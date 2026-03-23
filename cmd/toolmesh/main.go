// Copyright 2026 Dunkel Cloud GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command toolmesh starts the ToolMesh MCP server and Temporal worker.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/mcp"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
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

	// Initialize credential store via registry
	credStore, err := credentials.New(cfg.CredentialStore, nil)
	if err != nil {
		logger.Error("failed to create credential store", "type", cfg.CredentialStore, "error", err)
		os.Exit(1)
	}
	logger.Info("credential store initialized", "type", cfg.CredentialStore)

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

	// Load TypeScript tool definitions (canonical source)
	toolDefs, err := tsdef.LoadDir(cfg.ToolsDir)
	if err != nil {
		logger.Error("failed to load tool definitions", "dir", cfg.ToolsDir, "error", err)
		os.Exit(1)
	}
	rawTS, _ := tsdef.LoadRawTS(cfg.ToolsDir)

	// Create echo backend — use TS definitions if available, else fallback
	var echoBackend backend.ToolBackend
	if len(toolDefs) > 0 {
		var echoDescs []backend.ToolDescriptor
		for _, td := range toolDefs {
			echoDescs = append(echoDescs, td.ToToolDescriptor("builtin:echo"))
		}
		echoBackend = backend.NewEchoBackendWithDefs(echoDescs)
		logger.Info("loaded tool definitions from TypeScript", "count", len(toolDefs), "dir", cfg.ToolsDir)
	} else {
		echoBackend = backend.NewEchoBackend()
		logger.Info("using fallback tool definitions (no .ts files found)")
	}

	// Create type coercer for LLM tolerance
	coercer := tsdef.NewCoercer(toolDefs, logger)

	// Compose all backends: built-in echo + external MCP backends
	compositeBackend := backend.NewCompositeBackend(map[string]backend.ToolBackend{
		"echo": echoBackend,
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

	// Initialize output gate pipeline via registry
	var evaluators []gate.Evaluator
	for _, name := range strings.Split(cfg.GateEvaluators, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		evConfig := map[string]string{"policies_dir": cfg.PoliciesDir}
		ev, err := gate.NewEvaluator(name, evConfig)
		if err != nil {
			logger.Error("failed to create gate evaluator", "name", name, "error", err)
			os.Exit(1)
		}
		evaluators = append(evaluators, ev)
		logger.Info("gate evaluator initialized", "name", name)
	}
	gatePipeline := gate.NewPipeline(evaluators)

	// Initialize executor
	exec := executor.New(auth, credStore, compositeBackend, gatePipeline, logger)

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
	mcpHandler := mcp.NewHandler(exec, compositeBackend, coercer, rawTS, logger)
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
