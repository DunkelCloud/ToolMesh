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

// Command toolmesh starts the ToolMesh MCP server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/debuglog"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/mcp"
	"github.com/DunkelCloud/ToolMesh/internal/telemetry"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
	"github.com/DunkelCloud/ToolMesh/internal/version"
	"github.com/redis/go-redis/v9"
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

	var baseHandler slog.Handler
	opts := &slog.HandlerOptions{Level: logLevel}
	if cfg.LogFormat == "json" {
		baseHandler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		baseHandler = slog.NewTextHandler(os.Stdout, opts)
	}
	// Wrap with ContextHandler so *Context log calls automatically
	// include trace_id from the request context.
	handler := mcp.NewContextHandler(baseHandler)
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

	// Initialize blob store for binary API responses
	blobBaseURL := strings.TrimRight(cfg.Issuer, "/")
	blobDir := filepath.Join(cfg.DataDir, "blobs")
	blobStore, err := blob.NewStore(blobDir, blobBaseURL, logger)
	if err != nil {
		logger.Error("failed to create blob store", "error", err)
		os.Exit(1)
	}
	logger.Info("blob store initialized", "dir", blobDir, "base_url", blobBaseURL)

	// Initialize telemetry collector
	tc := telemetry.New(cfg.DataDir, version.Version, logger)

	// Build backends from backends.yaml (MCP + REST via DADL)
	bldCfg := &buildBackendsConfig{
		cfg:         cfg,
		credStore:   credStore,
		blobStore:   blobStore,
		tc:          tc,
		logger:      logger,
		baseHandler: baseHandler,
		debugFile:   debugFile,
		debugSet:    debugSet,
	}
	res, err := buildBackends(ctx, bldCfg)
	if err != nil {
		logger.Error("failed to build backends", "error", err)
		os.Exit(1)
	}
	defer res.mcpAdapter.Close()

	// Compose all backends: built-in echo + external MCP + REST
	compositeBackend := backend.NewCompositeBackend(res.named)
	compositeBackend.AddNamed("echo", echoBackend)
	for _, p := range res.passthroughs {
		compositeBackend.AddPassthrough(p)
	}
	tc.SetMCPServerCount(res.mcpAdapter.BackendCount())

	// Watch backends.yaml for changes and hot-reload
	go watchBackendsConfig(ctx, cfg.BackendsConfigPath, 5*time.Second, func() {
		logger.Info("backends.yaml changed, reloading backends")
		newRes, reloadErr := buildBackends(ctx, bldCfg)
		if reloadErr != nil {
			logger.Error("hot-reload failed, keeping current backends", "error", reloadErr)
			return
		}
		// Merge echo backend (static) with reloaded backends
		newRes.named["echo"] = echoBackend
		compositeBackend.Swap(newRes.named, newRes.passthroughs)
		tc.SetMCPServerCount(newRes.mcpAdapter.BackendCount())
		logger.Info("backends hot-reloaded successfully")
	})

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
		logger.Warn("SECURITY: OpenFGA authorization is BYPASSED — all tool calls are allowed without permission checks. Set OPENFGA_MODE=restrict for production use.", "mode", "bypass")
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

	// Initialize audit store
	auditStore, err := audit.New(cfg.AuditStore, map[string]string{
		"data_dir":       cfg.DataDir,
		"retention_days": strconv.Itoa(cfg.AuditRetentionDays),
	})
	if err != nil {
		logger.Error("failed to create audit store", "type", cfg.AuditStore, "error", err)
		os.Exit(1)
	}
	logger.Info("audit store initialized", "type", cfg.AuditStore)

	// Initialize executor
	execTimeout := time.Duration(cfg.ExecTimeout) * time.Second
	exec := executor.New(authorizer, credStore, compositeBackend, gatePipeline, auditStore, execTimeout, logger, tc)

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
				redisStore := auth.NewRedisTokenStore(rdb)
				tokenStore = auth.NewHybridTokenStore(redisStore, fileStore)
				rateLimiter = auth.NewDCRRateLimiter(rdb)
				fileStore.WarmUp(ctx, redisStore)
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
	httpMux.Handle("/blobs/", blobStore)

	// Wrap with middleware: panic recovery (outermost) → security headers → request logging.
	httpHandler := mcp.PanicRecovery(logger)(mcp.SecurityHeaders(mcp.RequestLogging(logger)(httpMux)))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      httpHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start telemetry send loop (persists counters on ctx cancellation)
	go tc.Run(ctx)

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
	}()

	logger.Info("ToolMesh MCP server listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("http server error", "error", err)
		os.Exit(1)
	}

	logger.Info("ToolMesh stopped")
}

// buildBackendsConfig holds the dependencies needed by buildBackends.
// Grouped into a struct to keep the signature manageable and reusable
// from both startup and the hot-reload callback.
type buildBackendsConfig struct {
	cfg         *config.Config
	credStore   credentials.CredentialStore
	blobStore   *blob.Store
	tc          *telemetry.Collector
	logger      *slog.Logger
	baseHandler slog.Handler
	debugFile   *os.File
	debugSet    map[string]bool
}

// backendsResult holds the output of buildBackends — the named backend map,
// passthrough backends, and the MCPAdapter (for lifecycle management).
type backendsResult struct {
	named        map[string]backend.ToolBackend
	passthroughs []backend.ToolBackend
	mcpAdapter   *backend.MCPAdapter
}

// buildBackends creates all MCP and REST backends from backends.yaml and DADL
// files. This function is called at startup and on hot-reload. It returns the
// named map and passthroughs ready for CompositeBackend.Swap().
func buildBackends(ctx context.Context, bc *buildBackendsConfig) (*backendsResult, error) {
	// Initialize MCPAdapter (external MCP backends)
	mcpLogger := bc.logger
	if bc.debugFile != nil && bc.debugSet != nil {
		filtered := debuglog.NewFilteredTeeHandler(bc.baseHandler, bc.debugFile, bc.debugSet)
		mcpLogger = slog.New(mcp.NewContextHandler(filtered))
	}
	mcpAdapter, err := backend.NewMCPAdapter(bc.cfg.BackendsConfigPath, bc.credStore, mcpLogger)
	if err != nil {
		return nil, fmt.Errorf("create MCP adapter: %w", err)
	}

	if err := mcpAdapter.Connect(ctx); err != nil {
		bc.logger.Error("failed to connect MCP backends", "error", err)
	}

	// Build named REST backends from DADL files
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, bc.cfg.BackendsConfigPath, bc.cfg.DADLDir, bc.blobStore, bc.credStore, bc.tc, bc.logger, bc.baseHandler, bc.debugFile, bc.debugSet)

	return &backendsResult{
		named:        named,
		passthroughs: []backend.ToolBackend{mcpAdapter},
		mcpAdapter:   mcpAdapter,
	}, nil
}

// watchBackendsConfig polls the backends config file for changes and calls
// reload when a modification is detected. Uses stat-based polling to avoid
// adding an fsnotify dependency. The initial mtime is captured on first tick
// so startup does not trigger a spurious reload.
func watchBackendsConfig(ctx context.Context, path string, interval time.Duration, reload func()) {
	var lastMod time.Time
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			mod := info.ModTime()
			if !mod.Equal(lastMod) {
				if !lastMod.IsZero() {
					reload()
				}
				lastMod = mod
			}
		}
	}
}

// backendLogger returns a tee logger for debug-listed backends,
// or the global logger for all others.
func backendLogger(name string, globalLogger *slog.Logger, stdoutHandler slog.Handler, debugFile *os.File, debugSet map[string]bool) *slog.Logger {
	if debugSet[name] && debugFile != nil {
		tee := debuglog.NewTeeHandler(stdoutHandler, debugFile)
		return slog.New(mcp.NewContextHandler(tee))
	}
	return globalLogger
}

// loadRESTBackendsInto scans the backends config for transport: rest entries,
// parses their DADL files, and populates the named map.
func loadRESTBackendsInto(named map[string]backend.ToolBackend, backendsConfigPath, dadlDir string, blobStore *blob.Store, creds credentials.CredentialStore, tc *telemetry.Collector, logger *slog.Logger, stdoutHandler slog.Handler, debugFile *os.File, debugSet map[string]bool) {
	data, err := os.ReadFile(backendsConfigPath) //nolint:gosec // path from trusted config
	if err != nil {
		return // no config = no REST backends
	}

	var cfg backend.BackendConfig
	if err := backendsYAMLUnmarshal(data, &cfg); err != nil {
		logger.Error("failed to parse backends config for REST entries", "error", err)
		return
	}

	// Fetch remote spec manifest once (best-effort, non-blocking with 5s timeout)
	var specManifest *dadl.SpecManifest
	if m, fetchErr := dadl.FetchSpecManifest(context.Background()); fetchErr != nil {
		logger.Debug("could not fetch DADL spec manifest", "error", fetchErr)
	} else {
		specManifest = m
		logger.Debug("DADL spec manifest fetched", "latest", m.Latest, "supported", len(m.Supported))
	}

	for _, entry := range cfg.Backends {
		if entry.Transport != "rest" {
			continue
		}
		if entry.DADL == "" {
			logger.Error("REST backend missing dadl path", "name", entry.Name)
			continue
		}

		// Resolve relative DADL paths against TOOLMESH_DADL_DIR
		dadlPath := entry.DADL
		if !filepath.IsAbs(dadlPath) {
			dadlPath = filepath.Join(dadlDir, dadlPath)
		}

		spec, err := dadl.Parse(dadlPath)
		if err != nil {
			logger.Error("failed to parse DADL file", "name", entry.Name, "path", dadlPath, "error", err)
			continue
		}

		// Check if a newer DADL spec version is available
		if specManifest != nil {
			if warning, checkErr := dadl.CheckSpecVersion(spec.Spec, specManifest); checkErr != nil {
				logger.Debug("spec version check failed", "name", entry.Name, "error", checkErr)
			} else if warning != "" {
				logger.Warn(warning, "name", entry.Name)
			}
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

		// Resolve per-backend security options.
		// allow_private_url defaults to true — admin-configured backends are trusted.
		allowPrivate := true
		if entry.AllowPrivateURL != nil {
			allowPrivate = *entry.AllowPrivateURL
		}
		if allowPrivate {
			logger.Warn("SSRF base_url validation skipped (allow_private_url)", "name", entry.Name)
		}
		if entry.TLSSkipVerify {
			logger.Warn("TLS certificate validation disabled (tls_skip_verify)", "name", entry.Name)
		}

		bl := backendLogger(spec.Backend.Name, logger, stdoutHandler, debugFile, debugSet)
		adapter, err := backend.NewRESTAdapter(spec, creds, bl, backend.RESTAdapterOptions{
			AllowPrivateURL: allowPrivate,
			TLSSkipVerify:   entry.TLSSkipVerify,
		})
		if err != nil {
			logger.Error("failed to create REST adapter", "name", entry.Name, "error", err)
			continue
		}
		adapter.SetBlobStore(blobStore)
		if ttlStr, ok := entry.Options["blob_ttl"]; ok {
			if d, parseErr := time.ParseDuration(ttlStr); parseErr == nil {
				adapter.SetBlobTTL(d)
			} else {
				logger.Warn("invalid blob_ttl option, using default 1h", "name", entry.Name, "value", ttlStr)
			}
		}
		if timeoutStr, ok := entry.Options["timeout"]; ok {
			if d, parseErr := time.ParseDuration(timeoutStr); parseErr == nil {
				adapter.SetHTTPTimeout(d)
				logger.Info("REST backend timeout override", "name", entry.Name, "timeout", d)
			} else {
				logger.Warn("invalid timeout option, using default", "name", entry.Name, "value", timeoutStr)
			}
		}
		if timeoutStr, ok := entry.Options["streaming_timeout"]; ok {
			if d, parseErr := time.ParseDuration(timeoutStr); parseErr == nil {
				adapter.SetStreamingHTTPTimeout(d)
				logger.Info("REST backend streaming timeout override", "name", entry.Name, "streaming_timeout", d)
			} else {
				logger.Warn("invalid streaming_timeout option, using default", "name", entry.Name, "value", timeoutStr)
			}
		}

		named[spec.Backend.Name] = adapter
		if tc != nil {
			tc.RegisterBackend(spec.Backend.Name, spec.ContentHash)
		}
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
