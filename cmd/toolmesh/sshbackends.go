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

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/health"
	"github.com/DunkelCloud/ToolMesh/internal/sshcmd"
)

// loadSSHBackendsInto scans the backends config for transport: ssh entries,
// reads their command files and adds each backend to the named map. It
// returns the backends as health targets: the check of an SSH backend is to
// connect to its hosts and log in, and it runs unless the entry turns it
// off.
//
// An entry that cannot be loaded is logged and left out; the other backends
// keep running.
func loadSSHBackendsInto(named map[string]backend.ToolBackend, backendsConfigPath string, creds credentials.CredentialStore, logger *slog.Logger, stdoutHandler slog.Handler, debugFile *os.File, debugSet map[string]bool) []health.Target {
	data, err := os.ReadFile(backendsConfigPath) //nolint:gosec // path from trusted config
	if err != nil {
		return nil // no config = no SSH backends
	}
	var cfg backend.BackendConfig
	if err := backendsYAMLUnmarshal(data, &cfg); err != nil {
		// The REST loader reads the same file and has reported the error.
		return nil
	}

	var targets []health.Target
	for _, entry := range cfg.Backends {
		if entry.Transport != backend.TransportSSH {
			continue
		}
		if _, taken := named[entry.Name]; taken {
			logger.Error("SSH backend refused: another backend has the same name", "name", entry.Name)
			continue
		}
		bl := backendLogger(entry.Name, logger, stdoutHandler, debugFile, debugSet)
		adapter, err := newSSHBackend(entry, filepath.Dir(backendsConfigPath), creds, bl)
		if err != nil {
			logger.Error("SSH backend refused; the other backends keep running", "name", entry.Name, "error", err)
			continue
		}
		named[entry.Name] = adapter

		// A malformed health_check field costs that setting, not the backend.
		settings, hcErr := health.ParseSettings(entry.HealthCheck)
		if hcErr != nil {
			logger.Error("invalid health_check settings, using defaults for them", "name", entry.Name, "error", hcErr)
		}
		var pollInterval time.Duration
		if settings.Enabled {
			targets = append(targets, health.Target{Name: entry.Name, Checker: adapter, Policy: settings.Policy})
			pollInterval = settings.Policy.Interval
		}
		logger.Info("SSH backend loaded",
			"name", entry.Name,
			"tools", adapter.ToolCount(),
			"hosts", adapter.HostNames(),
			"user", entry.SSH.User,
			"commands", entry.Commands,
			"health_check", settings.Enabled,
			"health_poll_interval", pollInterval.String(),
		)
	}
	return targets
}

// newSSHBackend builds the backend of one transport: ssh entry. Relative
// paths of the entry start at baseDir, the directory of backends.yaml.
func newSSHBackend(entry backend.BackendEntry, baseDir string, creds credentials.CredentialStore, logger *slog.Logger) (*backend.SSHAdapter, error) {
	if entry.Name == "" {
		return nil, errors.New("the entry has no name; add name: to the backends.yaml entry")
	}
	if entry.Commands == "" {
		return nil, errors.New("commands is missing: the path of the command file with the commands this backend may run")
	}
	if entry.SSH == nil {
		return nil, errors.New("the ssh block is missing: user, hosts, known_hosts and the key")
	}
	// Refused, not ignored: each of these says the entry was meant to be
	// something else, or to behave in a way this transport does not offer.
	switch {
	case entry.DADL != "":
		return nil, errors.New("dadl is for transport: rest; an SSH backend takes its commands from commands")
	case entry.URL != "" || entry.Command != "":
		return nil, errors.New("url and command are for MCP backends; an SSH backend names its hosts in ssh.hosts")
	case len(entry.UserCredentials) > 0:
		return nil, errors.New("user_credentials is supported for transport: rest only; an SSH backend logs in with one key for all callers")
	}
	if len(entry.ExposeTools) > 0 {
		logger.Warn("expose_tools is not honored for transport ssh, ignoring it", "name", entry.Name)
	}

	spec, err := sshcmd.Parse(resolvePath(baseDir, entry.Commands))
	if err != nil {
		return nil, fmt.Errorf("command file %s: %w", entry.Commands, err)
	}

	sshCfg := *entry.SSH
	if sshCfg.KnownHosts != "" {
		sshCfg.KnownHosts = resolvePath(baseDir, sshCfg.KnownHosts)
	}
	if sshCfg.KeyFile != "" {
		sshCfg.KeyFile = resolvePath(baseDir, sshCfg.KeyFile)
	}

	backendCreds := creds
	if len(entry.Env) > 0 {
		backendCreds = credentials.NewRemappingStore(creds, entry.Env)
		logger.Info("credential env remapping active", "name", entry.Name, "mappings", len(entry.Env))
	}
	return backend.NewSSHAdapter(spec, backendCreds, logger, backend.SSHAdapterOptions{
		Name:            entry.Name,
		SSH:             sshCfg,
		Hint:            entry.Hint,
		HintRequiredFor: entry.HintRequiredFor,
		IncludeTools:    entry.IncludeTools,
	})
}

// resolvePath returns path as it is when absolute, and below baseDir
// otherwise.
func resolvePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}
