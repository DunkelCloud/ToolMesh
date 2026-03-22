// Command toolmesh starts the ToolMesh MCP server and Temporal worker.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/mcp"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/DunkelCloud/ToolMesh/internal/version"
	temporalclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Setup logger
	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: logLevel}
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	logger.Info("starting ToolMesh",
		"version", version.Version,
		"commit", version.Commit,
		"buildDate", version.BuildDate,
		"port", cfg.Port,
		"transport", cfg.Transport,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize credential store
	credStore := credentials.NewEmbeddedStore()

	// Initialize MCPAdapter (external MCP backends)
	mcpAdapter, err := backend.NewMCPAdapter(cfg.BackendsConfigPath, credStore, logger)
	if err != nil {
		logger.Error("failed to create MCP adapter", "error", err)
		os.Exit(1)
	}
	defer mcpAdapter.Close()

	// Connect to all configured MCP backends
	if err := mcpAdapter.Connect(ctx); err != nil {
		logger.Error("failed to connect backends", "error", err)
	}

	// Compose all backends: built-in echo + external MCP backends
	// MCPAdapter already prefixes tools (e.g. "everything:echo"),
	// so it's registered without a prefix in the composite.
	compositeBackend := backend.NewCompositeBackend(map[string]backend.ToolBackend{
		"echo": backend.NewEchoBackend(),
	})
	compositeBackend.AddPassthrough(mcpAdapter)

	// Initialize OpenFGA authorizer (optional — skip if no store ID configured)
	var auth *authz.Authorizer
	if cfg.OpenFGAStoreID != "" {
		auth, err = authz.NewAuthorizer(cfg.OpenFGAAPIURL, cfg.OpenFGAStoreID, logger)
		if err != nil {
			logger.Error("failed to create authorizer", "error", err)
			os.Exit(1)
		}
		logger.Info("OpenFGA authorizer initialized", "storeId", cfg.OpenFGAStoreID)
	} else {
		logger.Warn("OpenFGA store ID not configured, running without authorization")
	}

	// Initialize output gate
	outputGate, err := gate.New(cfg.PoliciesDir, logger)
	if err != nil {
		logger.Error("failed to create output gate", "error", err)
		os.Exit(1)
	}

	// Initialize executor
	exec := executor.New(auth, credStore, compositeBackend, outputGate, logger)

	// Initialize Temporal client and worker
	var temporalWorker worker.Worker
	tc, err := temporalclient.Dial(temporalclient.Options{
		HostPort:  cfg.TemporalAddress,
		Namespace: cfg.TemporalNamespace,
		Logger:    newTemporalLogger(logger),
		ContextPropagators: []workflow.ContextPropagator{
			&userctx.HeaderPropagator{},
		},
	})
	if err != nil {
		logger.Warn("failed to connect to Temporal, running without workflow durability", "error", err)
	} else {
		defer tc.Close()

		temporalWorker = worker.New(tc, cfg.TemporalTaskQueue, worker.Options{})
		temporalWorker.RegisterWorkflow(executor.ToolExecutionWorkflow)
		temporalWorker.RegisterActivity(exec.ExecuteToolActivity)

		go func() {
			if err := temporalWorker.Run(worker.InterruptCh()); err != nil {
				logger.Error("temporal worker failed", "error", err)
			}
		}()
		logger.Info("Temporal worker started", "taskQueue", cfg.TemporalTaskQueue)
	}

	// Initialize MCP handler and server
	mcpHandler := mcp.NewHandler(exec, compositeBackend, logger)
	mcpServer := mcp.NewServer(mcpHandler, cfg, logger)

	httpMux := http.NewServeMux()
	mcpServer.SetupRoutes(httpMux)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      httpMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		logger.Info("shutting down")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("http server shutdown error", "error", err)
		}

		if temporalWorker != nil {
			temporalWorker.Stop()
		}
	}()

	logger.Info("ToolMesh MCP server listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("http server error", "error", err)
		os.Exit(1)
	}

	logger.Info("ToolMesh stopped")
}

// temporalLogger adapts slog to Temporal's logger interface.
type temporalLogger struct {
	logger *slog.Logger
}

func newTemporalLogger(l *slog.Logger) *temporalLogger {
	return &temporalLogger{logger: l.With("component", "temporal")}
}

func (l *temporalLogger) Debug(msg string, keyvals ...any)  { l.logger.Debug(msg, keyvals...) }
func (l *temporalLogger) Info(msg string, keyvals ...any)   { l.logger.Info(msg, keyvals...) }
func (l *temporalLogger) Warn(msg string, keyvals ...any)   { l.logger.Warn(msg, keyvals...) }
func (l *temporalLogger) Error(msg string, keyvals ...any)  { l.logger.Error(msg, keyvals...) }
