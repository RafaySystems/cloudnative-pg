package controller

import (
	"context"

	"github.com/cloudnative-pg/machinery/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/cloudnative-pg/cloudnative-pg/internal/cnpi/plugin/repository"
	"github.com/cloudnative-pg/cloudnative-pg/internal/configuration"
	"github.com/cloudnative-pg/cloudnative-pg/internal/controller"
	webhookv1 "github.com/cloudnative-pg/cloudnative-pg/internal/webhook/v1"
	"github.com/cloudnative-pg/cloudnative-pg/pkg/utils"
)

var setupLog = log.WithName("setup")

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
func AddToManager(ctx context.Context, mgr manager.Manager, conf *configuration.Data, maxConcurrentReconciles int) error {
	setupLog.Info("Adding CloudNativePG controllers and webhooks to manager")

	// Get discovery client
	discoveryClient, err := utils.GetDiscoveryClient()
	if err != nil {
		setupLog.Error(err, "unable to get discovery client")
		return err
	}

	// Create and register plugin repository
	pluginRepository := repository.New()
	if _, err := pluginRepository.RegisterUnixSocketPluginsInPath(
		conf.PluginSocketDir,
	); err != nil {
		setupLog.Error(err, "Unable to load sidecar CNPG-i plugins, skipping")
	}

	// Setup Cluster controller
	if err = controller.NewClusterReconciler(
		mgr,
		discoveryClient,
		pluginRepository,
		conf.DrainTaints,
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

	setupLog.Info("Successfully added all CloudNativePG controllers and webhooks to manager")
	return nil
}
