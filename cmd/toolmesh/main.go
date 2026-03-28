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

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/debuglog"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/mcp"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/DunkelCloud/ToolMesh/internal/version"
	"github.com/redis/go-redis/v9"
	temporalclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"gopkg.in/yaml.v3"
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

	// Per-backend debug file logging
	debugBackends := cfg.DebugBackendsList()
	var debugFile *os.File
	var debugSet map[string]bool

	if len(debugBackends) > 0 && cfg.DebugFile != "" {
		var dfErr error
		debugFile, dfErr = debuglog.OpenDebugFile(cfg.DebugFile)
		if dfErr != nil {
			logger.Error("failed to open debug file, continuing without debug logging",
				"path", cfg.DebugFile, "error", dfErr)
		} else {
			defer func() { _ = debugFile.Close() }()
			debugSet = make(map[string]bool, len(debugBackends))
			for _, name := range debugBackends {
				debugSet[name] = true
			}
			logger.Info("debug file logging enabled",
				"file", cfg.DebugFile,
				"backends", debugBackends,
			)

			// Write startup banner to debug file
			dfLogger := slog.New(slog.NewJSONHandler(debugFile, &slog.HandlerOptions{Level: slog.LevelDebug}))
			dfLogger.Info("starting ToolMesh",
				"version", version.Version,
				"commit", version.Commit,
				"buildDate", version.BuildDate,
				"port", cfg.Port,
				"transport", cfg.Transport,
				"debugBackends", debugBackends,
			)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize credential store via registry
	credStore, err := credentials.New(cfg.CredentialStore, nil)
	if err != nil {
		logger.Error("failed to create credential store", "type", cfg.CredentialStore, "error", err)
		os.Exit(1) //nolint:gocritic // intentional in main
	}
	logger.Info("credential store initialized", "type", cfg.CredentialStore)

	// Initialize MCPAdapter (external MCP backends)
	// Use FilteredTeeHandler so only records with a matching "backend"
	// attribute are written to the debug file.
	mcpLogger := logger
	if debugFile != nil && debugSet != nil {
		filtered := debuglog.NewFilteredTeeHandler(handler, debugFile, debugSet)
		mcpLogger = slog.New(filtered)
	}
	mcpAdapter, err := backend.NewMCPAdapter(cfg.BackendsConfigPath, credStore, mcpLogger)
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
		echoDescs := make([]backend.ToolDescriptor, 0, len(toolDefs))
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

	// Initialize REST Proxy backends from DADL files
	loadRESTBackends(compositeBackend, cfg.BackendsConfigPath, credStore, logger, handler, debugFile, debugSet)

	// Initialize OpenFGA authorizer based on OPENFGA_MODE
	var authorizer *authz.Authorizer
	if cfg.OpenFGAMode == "restrict" {
		if cfg.OpenFGAStoreID == "" {
			logger.Error("OPENFGA_MODE=restrict requires OPENFGA_STORE_ID to be set")
			os.Exit(1)
		}
		authorizer, err = authz.NewAuthorizer(cfg.OpenFGAAPIURL, cfg.OpenFGAStoreID, logger)
		if err != nil {
			logger.Error("failed to create authorizer", "error", err)
			os.Exit(1)
		}
		logger.Info("OpenFGA authorizer initialized", "mode", "restrict", "storeId", cfg.OpenFGAStoreID)
	} else {
		logger.Warn("OpenFGA authorization bypassed", "mode", "bypass")
	}

	// Initialize gate pipeline via registry
	gateNames := strings.Split(cfg.GateEvaluators, ",")
	evaluators := make([]gate.Evaluator, 0, len(gateNames))
	for _, name := range gateNames {
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

	// Initialize Temporal client and worker based on TEMPORAL_MODE
	var temporalClient temporalclient.Client
	var temporalWorker worker.Worker

	if cfg.TemporalMode == "durable" {
		tc, err := temporalclient.Dial(temporalclient.Options{
			HostPort:  cfg.TemporalAddress,
			Namespace: cfg.TemporalNamespace,
			Logger:    newTemporalLogger(logger),
			ContextPropagators: []workflow.ContextPropagator{
				&userctx.HeaderPropagator{},
			},
		})
		if err != nil {
			logger.Error("TEMPORAL_MODE=durable but failed to connect to Temporal", "error", err)
			os.Exit(1)
		}
		defer tc.Close()
		temporalClient = tc

		temporalWorker = worker.New(tc, cfg.TemporalTaskQueue, worker.Options{})
		temporalWorker.RegisterWorkflow(executor.ToolExecutionWorkflow)
		// Activity is registered after executor creation below.

		logger.Info("Temporal worker started", "mode", "durable", "taskQueue", cfg.TemporalTaskQueue)
	} else {
		logger.Warn("Temporal durability bypassed — tool calls execute directly", "mode", "bypass")
	}

	// Initialize executor
	exec := executor.New(authorizer, credStore, compositeBackend, gatePipeline, temporalClient, cfg.TemporalTaskQueue, logger)

	// Register activity and start worker after executor is created
	if temporalWorker != nil {
		temporalWorker.RegisterActivity(exec.ExecuteToolActivity)

		go func() {
			if err := temporalWorker.Run(worker.InterruptCh()); err != nil {
				logger.Error("temporal worker failed", "error", err)
			}
		}()
	}

	// Initialize token store for auth state.
	// The file-based store always runs for persistence across restarts.
	// When Redis is available, a hybrid store writes to both and reads
	// from Redis with file-based fallback.
	fileStore, err := auth.NewFileTokenStore(cfg.DataDir)
	if err != nil {
		logger.Error("failed to create file token store", "error", err)
		os.Exit(1) //nolint:gocritic // intentional in main
	}
	go fileStore.Cleanup(ctx)
	logger.Info("file-based token store initialized", "dataDir", cfg.DataDir)

	var tokenStore auth.TokenStore = fileStore
	var rateLimiter *auth.DCRRateLimiter

	if cfg.RedisURL != "" && cfg.RedisURL != "none" {
		redisOpts, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			logger.Warn("failed to parse Redis URL, using file-only token store", "error", err)
		} else {
			rdb := redis.NewClient(redisOpts)
			defer func() { _ = rdb.Close() }()

			if err := rdb.Ping(ctx).Err(); err != nil {
				logger.Warn("Redis not reachable, using file-only token store", "error", err)
			} else {
				logger.Info("Redis connected, using hybrid token store")
				tokenStore = auth.NewHybridTokenStore(auth.NewRedisTokenStore(rdb), fileStore)
				rateLimiter = auth.NewDCRRateLimiter(rdb)
			}
		}
	}

	// Load user identity configs
	userStore, err := auth.NewUserStore(cfg.UsersConfigPath)
	if err != nil {
		logger.Error("failed to load users config", "error", err)
		os.Exit(1)
	}
	if userStore != nil {
		logger.Info("loaded users config", "path", cfg.UsersConfigPath)
	}

	apiKeyStore, err := auth.NewAPIKeyStore(cfg.APIKeysConfigPath)
	if err != nil {
		logger.Error("failed to load apikeys config", "error", err)
		os.Exit(1)
	}
	if apiKeyStore != nil {
		logger.Info("loaded apikeys config", "path", cfg.APIKeysConfigPath)
	}

	callerClasses, err := config.LoadCallerClasses(cfg.CallerClassesConfigPath)
	if err != nil {
		logger.Error("failed to load caller-classes config", "error", err)
		os.Exit(1)
	}
	if callerClasses != nil {
		logger.Info("loaded caller-classes config", "path", cfg.CallerClassesConfigPath)
	}

	// Initialize MCP handler and server
	mcpHandler := mcp.NewHandler(exec, compositeBackend, coercer, rawTS, logger)
	mcpServer := mcp.NewServer(mcpHandler, cfg, logger, tokenStore, userStore, apiKeyStore, rateLimiter, callerClasses)

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

// Debug implements the Temporal logger interface.
func (l *temporalLogger) Debug(msg string, keyvals ...any) { l.logger.Debug(msg, keyvals...) }

// Info implements the Temporal logger interface.
func (l *temporalLogger) Info(msg string, keyvals ...any) { l.logger.Info(msg, keyvals...) }

// Warn implements the Temporal logger interface.
func (l *temporalLogger) Warn(msg string, keyvals ...any) { l.logger.Warn(msg, keyvals...) }

// Error implements the Temporal logger interface.
func (l *temporalLogger) Error(msg string, keyvals ...any) { l.logger.Error(msg, keyvals...) }

// backendLogger returns a tee logger for debug-listed backends,
// or the global logger for all others.
func backendLogger(name string, globalLogger *slog.Logger, stdoutHandler slog.Handler, debugFile *os.File, debugSet map[string]bool) *slog.Logger {
	if debugSet[name] && debugFile != nil {
		tee := debuglog.NewTeeHandler(stdoutHandler, debugFile)
		return slog.New(tee)
	}
	return globalLogger
}

// loadRESTBackends scans the backends config for transport: rest entries,
// parses their DADL files, and adds them to the composite backend.
func loadRESTBackends(composite *backend.CompositeBackend, backendsConfigPath string, creds credentials.CredentialStore, logger *slog.Logger, stdoutHandler slog.Handler, debugFile *os.File, debugSet map[string]bool) {
	data, err := os.ReadFile(backendsConfigPath) //nolint:gosec // path from trusted config
	if err != nil {
		return // no config = no REST backends
	}

	var cfg backend.BackendConfig
	if err := backendsYAMLUnmarshal(data, &cfg); err != nil {
		logger.Error("failed to parse backends config for REST entries", "error", err)
		return
	}

	for _, entry := range cfg.Backends {
		if entry.Transport != "rest" {
			continue
		}
		if entry.DADL == "" {
			logger.Error("REST backend missing dadl path", "name", entry.Name)
			continue
		}

		spec, err := dadl.Parse(entry.DADL)
		if err != nil {
			logger.Error("failed to parse DADL file", "name", entry.Name, "path", entry.DADL, "error", err)
			continue
		}

		// Override base_url from backends.yaml if provided
		if entry.URL != "" {
			spec.Backend.BaseURL = entry.URL
		}

		// Override backend name from backends.yaml if it differs
		if entry.Name != "" && entry.Name != spec.Backend.Name {
			spec.Backend.Name = entry.Name
		}

		// Check scoping strategy
		if spec.Backend.Scoping != nil && spec.Backend.Scoping.Strategy != "" && spec.Backend.Scoping.Strategy != "static" {
			logger.Warn("scoping strategy not yet implemented, exposing all tools", "strategy", spec.Backend.Scoping.Strategy)
		}

		bl := backendLogger(spec.Backend.Name, logger, stdoutHandler, debugFile, debugSet)
		adapter, err := backend.NewRESTAdapter(spec, creds, bl)
		if err != nil {
			logger.Error("failed to create REST adapter", "name", entry.Name, "error", err)
			continue
		}

		composite.AddNamed(spec.Backend.Name, adapter)
		logger.Info("REST proxy backend loaded",
			"name", spec.Backend.Name,
			"tools", len(spec.Backend.Tools),
			"baseURL", spec.Backend.BaseURL,
		)
	}
}

// backendsYAMLUnmarshal unmarshals backends YAML config.
func backendsYAMLUnmarshal(data []byte, cfg *backend.BackendConfig) error {
	return yaml.Unmarshal(data, cfg)
}
