package controller

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cloudnative-pg/machinery/pkg/log"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/cloudnative-pg/cloudnative-pg/internal/cnpi/plugin/repository"
	"github.com/cloudnative-pg/cloudnative-pg/internal/controller"
	webhookv1 "github.com/cloudnative-pg/cloudnative-pg/internal/webhook/v1"
	"github.com/cloudnative-pg/cloudnative-pg/pkg/certs"
	"github.com/cloudnative-pg/cloudnative-pg/pkg/utils"
)

var setupLog = log.WithName("setup")

const (
	// WebhookSecretName is the name of the secret where the certificates
	// for the webhook server are stored
	WebhookSecretName = "cnpg-webhook-cert" // #nosec

	// WebhookServiceName is the name of the service where the webhook server
	// is reachable
	WebhookServiceName = "cnpg-webhook-service" // #nosec

	// MutatingWebhookConfigurationName is the name of the mutating webhook configuration
	MutatingWebhookConfigurationName = "cnpg-mutating-webhook-configuration"

	// ValidatingWebhookConfigurationName is the name of the validating webhook configuration
	ValidatingWebhookConfigurationName = "cnpg-validating-webhook-configuration"

	// CaSecretName is the name of the secret which is hosting the Operator CA
	CaSecretName = "cnpg-ca-secret" // #nosec
)

// Config contains the configuration needed to add CloudNativePG controllers to a manager.
type Config struct {
	// OperatorNamespace is the namespace where the operator is installed
	OperatorNamespace string

	// PluginSocketDir is the directory where the plugin sockets are to be found.
	// If empty, plugins will not be loaded.
	PluginSocketDir string

	// DrainTaints is a list of taints the operator will watch and treat as Unschedule.
	// If nil or empty, default drain taints will be used.
	DrainTaints []string

	// WebhookCertDir is the directory where the certificates for the webhooks need to be written.
	// If set, PKI setup will be skipped (assuming OLM or external system manages certificates).
	// If empty, PKI infrastructure will be set up automatically.
	WebhookCertDir string
}

// AddToManager adds all CloudNativePG controllers and webhooks to the provided manager.
// This function follows the same setup pattern as internal/cmd/manager/controller/controller.go
// and allows adding CloudNativePG controllers to an external controller-runtime manager.
//
// Parameters:
//   - ctx: context.Context for the operation
//   - mgr: The external controller-runtime manager to add controllers and webhooks to
//   - conf: Configuration data containing operator settings (namespace, plugin socket dir, etc.)
//   - maxConcurrentReconciles: Maximum number of concurrent reconciles for controllers that support it
//
// Returns an error if any controller or webhook setup fails.
func AddToManager(ctx context.Context, mgr manager.Manager, conf Config, maxConcurrentReconciles int) error {
	setupLog.Info("Adding CloudNativePG controllers and webhooks to manager")

	// Get discovery client
	discoveryClient, err := utils.GetDiscoveryClient()
	if err != nil {
		setupLog.Error(err, "unable to get discovery client")
		return err
	}

	// Detect if we are running under a system that implements OpenShift Security Context Constraints
	if err = utils.DetectSecurityContextConstraints(discoveryClient); err != nil {
		setupLog.Error(err, "unable to detect OpenShift Security Context Constraints presence")
		return err
	}

	// Detect if we are running under a system that provides Volume Snapshots
	if err = utils.DetectVolumeSnapshotExist(discoveryClient); err != nil {
		setupLog.Error(err, "unable to detect if the cluster has the VolumeSnapshot CRD installed")
		return err
	}

	// Detect the available architectures
	if err = utils.DetectAvailableArchitectures(); err != nil {
		setupLog.Error(err, "unable to detect the available instance's architectures")
		return err
	}

	setupLog.Info("Kubernetes system metadata",
		"haveSCC", utils.HaveSecurityContextConstraints(),
		"haveVolumeSnapshot", utils.HaveVolumeSnapshot(),
		"availableArchitectures", utils.GetAvailableArchitectures(),
	)

	// Get webhook server if available
	var webhookServer *webhook.DefaultServer
	if ws := mgr.GetWebhookServer(); ws != nil {
		if ws, ok := ws.(*webhook.DefaultServer); ok {
			webhookServer = ws
		}
	}

	// Create kubeClient for PKI setup and configuration loading
	kubeClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		setupLog.Error(err, "unable to create Kubernetes client")
		return err
	}

	// Setup PKI infrastructure if webhook server is available and WebhookCertDir is not set
	if webhookServer != nil && conf.WebhookCertDir == "" {
		if err := ensurePKI(ctx, kubeClient, webhookServer.Options.CertDir, conf); err != nil {
			setupLog.Error(err, "unable to setup PKI infrastructure")
			return err
		}
	}

	// Create and register plugin repository
	pluginRepository := repository.New()
	if conf.PluginSocketDir != "" {
		if _, err := pluginRepository.RegisterUnixSocketPluginsInPath(
			conf.PluginSocketDir,
		); err != nil {
			setupLog.Error(err, "Unable to load sidecar CNPG-i plugins, skipping")
		}
	}

	// Use empty slice if DrainTaints is nil
	drainTaints := conf.DrainTaints
	if drainTaints == nil {
		drainTaints = []string{}
	}

	// Setup Cluster controller
	if err = controller.NewClusterReconciler(
		mgr,
		discoveryClient,
		pluginRepository,
		drainTaints,
	).SetupWithManager(ctx, mgr, maxConcurrentReconciles); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Cluster")
		return err
	}

	// Setup Backup controller
	if err = controller.NewBackupReconciler(
		mgr,
		discoveryClient,
		pluginRepository,
	).SetupWithManager(ctx, mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Backup")
		return err
	}

	// Setup Plugin controller
	if err = controller.NewPluginReconciler(mgr, conf.OperatorNamespace, pluginRepository).
		SetupWithManager(mgr, maxConcurrentReconciles); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Plugin")
		return err
	}

	// Setup ScheduledBackup controller
	if err = (&controller.ScheduledBackupReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("cloudnative-pg-scheduledbackup"),
	}).SetupWithManager(ctx, mgr, maxConcurrentReconciles); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ScheduledBackup")
		return err
	}

	// Setup Pooler controller
	if err = (&controller.PoolerReconciler{
		Client:          mgr.GetClient(),
		DiscoveryClient: discoveryClient,
		Scheme:          mgr.GetScheme(),
		Recorder:        mgr.GetEventRecorderFor("cloudnative-pg-pooler"),
	}).SetupWithManager(mgr, maxConcurrentReconciles); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pooler")
		return err
	}

	// Setup webhooks
	if err = webhookv1.SetupClusterWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "Cluster", "version", "v1")
		return err
	}

	if err = webhookv1.SetupBackupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "Backup", "version", "v1")
		return err
	}

	if err = webhookv1.SetupScheduledBackupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ScheduledBackup", "version", "v1")
		return err
	}

	if err = webhookv1.SetupPoolerWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "Pooler", "version", "v1")
		return err
	}

	if err = webhookv1.SetupDatabaseWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "Database", "version", "v1")
		return err
	}

	// Setup the handler used by the readiness and liveliness probe
	if webhookServer != nil {
		webhookServer.WebhookMux().HandleFunc("/readyz", readinessProbeHandler)
	}

	setupLog.Info("Successfully added all CloudNativePG controllers and webhooks to manager")
	return nil
}

// ensurePKI ensures that we have the required PKI infrastructure to make
// the operator and the clusters working
func ensurePKI(
	ctx context.Context,
	kubeClient client.Client,
	mgrCertDir string,
	conf Config,
) error {
	// We need to self-manage required PKI infrastructure and install the certificates into
	// the webhooks configuration
	pkiConfig := certs.PublicKeyInfrastructure{
		CaSecretName:                     CaSecretName,
		CertDir:                          mgrCertDir,
		SecretName:                       WebhookSecretName,
		ServiceName:                      WebhookServiceName,
		OperatorNamespace:                conf.OperatorNamespace,
		MutatingWebhookConfigurationName: MutatingWebhookConfigurationName,
		ValidatingWebhookConfigurationName: ValidatingWebhookConfigurationName,
		OperatorDeploymentLabelSelector:  "app.kubernetes.io/name=cloudnative-pg",
	}
	err := pkiConfig.Setup(ctx, kubeClient)
	if err != nil {
		setupLog.Error(err, "unable to setup PKI infrastructure")
	}
	return err
}

// readinessProbeHandler is used to implement the readiness probe handler
func readinessProbeHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = fmt.Fprint(w, "OK")
}

// readConfigMap reads the configMap and returns its content as map
func readConfigMap(
	ctx context.Context,
	kubeClient client.Client,
	namespace string,
	name string,
) (map[string]string, error) {
	if name == "" {
		return nil, nil
	}

	if namespace == "" {
		return nil, nil
	}

	setupLog.Info("Loading configuration from ConfigMap",
		"namespace", namespace,
		"name", name)

	configMap := &corev1.ConfigMap{}
	err := kubeClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, configMap)
	if apierrs.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return configMap.Data, nil
}

// readSecret reads the secret and returns its content as map
func readSecret(
	ctx context.Context,
	kubeClient client.Client,
	namespace,
	name string,
) (map[string]string, error) {
	if name == "" {
		return nil, nil
	}

	if namespace == "" {
		return nil, nil
	}

	setupLog.Info("Loading configuration from Secret",
		"namespace", namespace,
		"name", name)

	secret := &corev1.Secret{}
	err := kubeClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, secret)
	if apierrs.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	data := make(map[string]string)
	for k, v := range secret.Data {
		data[k] = string(v)
	}

	return data, nil
}