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

package authz

import (
	"cmp"
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed" // the authorization model is compiled in
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage"
	"github.com/openfga/openfga/pkg/storage/migrate"
	"github.com/openfga/openfga/pkg/storage/sqlcommon"
	"github.com/openfga/openfga/pkg/storage/sqlite"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// DBFileName is the SQLite file of the embedded engine in the data directory.
const DBFileName = "authz.db"

// MarkerFileName is written next to the database on the first start of the
// embedded engine and records the upgrade decision. It outlives the database:
// a data directory whose authz.db was deleted is not mistaken for an
// installation that ran without authorization, which would open every tool.
const MarkerFileName = ".authz-bootstrap"

const (
	storeName = "toolmesh"

	// objInstance is the one instance object; grants on it cover every tool.
	objInstance = "instance:toolmesh"

	relExecutor    = "executor"
	relBlocked     = "blocked"
	relInstance    = "instance"
	relBackend     = "backend"
	relAccessClass = "access_class"
	relMember      = "member"
	relSubscriber  = "subscriber"
	relAssignee    = "assignee"

	// writeChunk stays within OpenFGA's limit of tuples per write request.
	writeChunk = 100
	readPage   = 100

	// dbConns bounds the SQLite connections of the embedded engine. Checks
	// beyond it wait for a connection instead of opening the file again.
	dbConns = 16

	// Check cache. Only Apply writes to the store and it invalidates the
	// cache, so the TTL bounds memory, not staleness.
	cacheEntries = 10000
	cacheTTL     = 5 * time.Minute
)

// Keys of the toolmesh_authz_state table.
const (
	stateStoreID       = "store_id"
	stateModelID       = "model_id"
	stateModelHash     = "model_hash"
	stateUpgradePreset = "upgrade_preset"
	stateBootstrapped  = "bootstrapped_at"
)

//go:embed model.fga
var modelDSL string

// ModelHash identifies the compiled-in authorization model. A store whose
// recorded hash differs gets the model written again on start.
func ModelHash() string {
	sum := sha256.Sum256([]byte(modelDSL))
	return hex.EncodeToString(sum[:])
}

// tupleKey is a stored relationship: user has relation on object.
type tupleKey struct {
	User     string
	Relation string
	Object   string
}

func compareTuples(a, b tupleKey) int {
	return cmp.Or(cmp.Compare(a.Object, b.Object), cmp.Compare(a.Relation, b.Relation), cmp.Compare(a.User, b.User))
}

// EmbeddedOptions configures OpenEmbedded.
type EmbeddedOptions struct {
	// Path of the SQLite file; created with its directory when missing.
	Path string
	// Upgrade marks an installation that ran without authorization before.
	// On the first start of the engine it records PresetOpen as the upgrade
	// preset, so that its behavior does not change.
	Upgrade bool
	Logger  *slog.Logger
}

// Embedded runs OpenFGA inside the ToolMesh process on a SQLite file
// (TOOLMESH_AUTHZ_MODE=embedded). ToolMesh owns the store: it creates the
// store and the model on first start, writes the model again when it changes
// and keeps the stored grants equal to the policy given to Apply.
type Embedded struct {
	srv     *server.Server
	db      *sql.DB
	cache   *epochCache
	logger  *slog.Logger
	storeID string
	modelID string
	// upgradePreset is the preset recorded at the first start of an upgraded
	// installation, empty otherwise.
	upgradePreset string

	// toolGrants holds the tool objects that may have stored grants or denies
	// of their own. Every other tool is decided by its backend and access
	// class alone, which lets CheckBatch answer many tools with one check. It
	// must always be a superset of the tools that do have stored rules.
	toolGrants atomic.Pointer[map[string]bool]

	applyMu   sync.Mutex
	closeOnce sync.Once
}

// OpenEmbedded opens (or creates) the embedded engine at opts.Path: it runs
// the OpenFGA schema migrations, creates the store on first start, and writes
// the compiled-in model when the store does not have it yet. Grants are not
// touched; call Apply.
func OpenEmbedded(ctx context.Context, opts EmbeddedOptions) (*Embedded, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o750); err != nil {
		return nil, fmt.Errorf("create authz data directory: %w", err)
	}

	// Writes are rare (start, policy reload) and checks only read, so a
	// generous busy timeout costs nothing and keeps a reload from failing
	// while a long read holds the file. Temporary tables stay in memory: the
	// container image has no writable temp directory.
	uri := opts.Path + "?_pragma=busy_timeout(5000)&_pragma=temp_store(memory)"
	if err := migrate.RunMigrations(migrate.MigrationConfig{
		Engine:      "sqlite",
		URI:         uri,
		Timeout:     30 * time.Second,
		PingTimeout: 5 * time.Second,
	}); err != nil {
		return nil, fmt.Errorf("migrate authz database %s: %w", opts.Path, err)
	}

	dsn, err := sqlite.PrepareDSN(uri)
	if err != nil {
		return nil, fmt.Errorf("authz database dsn: %w", err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open authz database: %w", err)
	}
	// A check runs several reads in parallel. With database/sql's default of
	// two idle connections the others are closed after each read, and every
	// new SQLite connection opens the file and parses the schema again, which
	// costs more than the check itself. Keep the connections.
	db.SetMaxOpenConns(dbConns)
	db.SetMaxIdleConns(dbConns)
	ds, err := sqlite.NewWithDB(db, sqlcommon.NewConfig())
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open authz datastore: %w", err)
	}
	// Without a cache, every check runs about a dozen SQL queries, and parsing
	// them costs about a millisecond. The cache holds stored grants only: the
	// caller's identity comes in as contextual tuples, which OpenFGA merges in
	// above the cached reads, so an entry is never specific to one caller.
	lru, err := storage.NewInMemoryLRUCache([]storage.InMemoryLRUCacheOpt[any]{
		storage.WithMaxCacheSize[any](cacheEntries),
	}...)
	if err != nil {
		ds.Close()
		return nil, fmt.Errorf("create authz cache: %w", err)
	}
	cache := &epochCache{inner: lru}
	srv, err := server.NewServerWithOpts(
		server.WithDatastore(ds),
		server.WithCheckCache(cache),
		server.WithCheckIteratorCacheEnabled(true),
		server.WithCheckIteratorCacheTTL(cacheTTL),
	)
	if err != nil {
		cache.Stop()
		ds.Close()
		return nil, fmt.Errorf("start embedded openfga: %w", err)
	}

	e := &Embedded{srv: srv, db: db, cache: cache, logger: logger}
	if err := e.bootstrap(ctx, opts.Upgrade, filepath.Join(filepath.Dir(opts.Path), MarkerFileName)); err != nil {
		srv.Close() // closes the datastore and with it db
		return nil, err
	}
	return e, nil
}

// StoreID returns the id of the embedded store.
func (e *Embedded) StoreID() string { return e.storeID }

// ModelID returns the id of the model checks are evaluated against.
func (e *Embedded) ModelID() string { return e.modelID }

// UpgradePreset returns the preset recorded when an installation that ran
// without authorization was upgraded, or "" for any other installation.
func (e *Embedded) UpgradePreset() string { return e.upgradePreset }

// bootstrap creates what a first start needs and adopts what an earlier start
// left: the state table, the store, the model and the upgrade record.
func (e *Embedded) bootstrap(ctx context.Context, upgrade bool, markerPath string) error {
	if _, err := e.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS toolmesh_authz_state (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create authz state table: %w", err)
	}
	state, err := e.readState(ctx)
	if err != nil {
		return err
	}

	if e.storeID, err = e.ensureStore(ctx, state[stateStoreID]); err != nil {
		return err
	}
	if e.modelID, err = e.ensureModel(ctx, state[stateModelID], state[stateModelHash]); err != nil {
		return err
	}
	current, err := e.readTuples(ctx)
	if err != nil {
		return err
	}
	e.setToolGrants(current)

	update := map[string]string{
		stateStoreID:   e.storeID,
		stateModelID:   e.modelID,
		stateModelHash: ModelHash(),
	}
	m, markerFound, err := readMarker(markerPath)
	if err != nil {
		return err
	}
	if preset, recorded := state[stateUpgradePreset]; recorded {
		e.upgradePreset = preset
	} else {
		switch {
		case markerFound:
			// The database is new, the data directory is not: keep the
			// decision of its first start instead of taking the existing
			// data directory for an upgrade.
			e.upgradePreset = m.UpgradePreset
			e.logger.WarnContext(ctx, "authz database was created again; keeping the upgrade decision of the first start",
				"marker", markerPath, "upgrade_preset", m.UpgradePreset)
		case upgrade:
			// First start of the engine on this data directory: decide once
			// whether this is an upgrade, and keep the answer.
			e.upgradePreset = PresetOpen
		}
		update[stateUpgradePreset] = e.upgradePreset
		update[stateBootstrapped] = time.Now().UTC().Format(time.RFC3339)
	}
	if err := e.writeState(ctx, update); err != nil {
		return err
	}
	if !markerFound || m.UpgradePreset != e.upgradePreset {
		return writeMarker(markerPath, marker{UpgradePreset: e.upgradePreset, BootstrappedAt: time.Now().UTC().Format(time.RFC3339)})
	}
	return nil
}

// marker is the content of MarkerFileName.
type marker struct {
	UpgradePreset  string `json:"upgrade_preset"`
	BootstrappedAt string `json:"bootstrapped_at"`
}

func readMarker(path string) (marker, bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from the configured data directory
	if errors.Is(err, os.ErrNotExist) {
		return marker{}, false, nil
	}
	if err != nil {
		return marker{}, false, fmt.Errorf("read authz marker: %w", err)
	}
	var m marker
	if err := json.Unmarshal(data, &m); err != nil {
		return marker{}, false, fmt.Errorf("authz marker %s: %w", path, err)
	}
	if m.UpgradePreset != "" && !ValidPreset(m.UpgradePreset) {
		return marker{}, false, fmt.Errorf("authz marker %s: unknown upgrade preset %q", path, m.UpgradePreset)
	}
	return m, true, nil
}

func writeMarker(path string, m marker) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("write authz marker: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write authz marker: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write authz marker: %w", err)
	}
	return nil
}

func (e *Embedded) ensureStore(ctx context.Context, recorded string) (string, error) {
	if recorded != "" {
		if _, err := e.srv.GetStore(ctx, &openfgav1.GetStoreRequest{StoreId: recorded}); err == nil {
			return recorded, nil
		}
		e.logger.WarnContext(ctx, "authz store recorded in the state table is missing, creating a new one", "store_id", recorded)
	}
	// A start that created the store but died before recording it left the
	// store behind; adopt it instead of creating a second one.
	list, err := e.srv.ListStores(ctx, &openfgav1.ListStoresRequest{})
	if err != nil {
		return "", fmt.Errorf("list authz stores: %w", err)
	}
	for _, s := range list.GetStores() {
		if s.GetName() == storeName {
			return s.GetId(), nil
		}
	}
	resp, err := e.srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: storeName})
	if err != nil {
		return "", fmt.Errorf("create authz store: %w", err)
	}
	e.logger.InfoContext(ctx, "authorization store created", "store_id", resp.GetId())
	return resp.GetId(), nil
}

func (e *Embedded) ensureModel(ctx context.Context, recordedID, recordedHash string) (string, error) {
	if recordedID != "" && recordedHash == ModelHash() {
		_, err := e.srv.ReadAuthorizationModel(ctx, &openfgav1.ReadAuthorizationModelRequest{StoreId: e.storeID, Id: recordedID})
		if err == nil {
			return recordedID, nil
		}
	}
	model, err := transformer.TransformDSLToProto(modelDSL)
	if err != nil {
		return "", fmt.Errorf("parse authorization model: %w", err)
	}
	resp, err := e.srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         e.storeID,
		TypeDefinitions: model.GetTypeDefinitions(),
		SchemaVersion:   model.GetSchemaVersion(),
		Conditions:      model.GetConditions(),
	})
	if err != nil {
		return "", fmt.Errorf("write authorization model: %w", err)
	}
	if recordedID == "" {
		e.logger.InfoContext(ctx, "authorization model written", "model_id", resp.GetAuthorizationModelId())
	} else {
		e.logger.InfoContext(ctx, "authorization model upgraded", "model_id", resp.GetAuthorizationModelId(), "previous_model_id", recordedID)
	}
	return resp.GetAuthorizationModelId(), nil
}

func (e *Embedded) readState(ctx context.Context) (map[string]string, error) {
	rows, err := e.db.QueryContext(ctx, `SELECT key, value FROM toolmesh_authz_state`)
	if err != nil {
		return nil, fmt.Errorf("read authz state: %w", err)
	}
	defer func() { _ = rows.Close() }()
	state := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("read authz state: %w", err)
		}
		state[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read authz state: %w", err)
	}
	return state, nil
}

func (e *Embedded) writeState(ctx context.Context, values map[string]string) error {
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("write authz state: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for k, v := range values {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO toolmesh_authz_state (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			return fmt.Errorf("write authz state: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("write authz state: %w", err)
	}
	return nil
}

// Check reports whether the caller may execute the tool. The caller's
// identity and the tool's place (instance, backend, access classification)
// are passed as contextual tuples; the store contributes the grants.
func (e *Embedded) Check(ctx context.Context, req Request) (bool, error) {
	if req.UserID == "" || req.Tool == "" {
		return false, nil
	}
	user := "user:" + escapeID(req.UserID)
	tool := "tool:" + escapeID(req.Tool)

	ctxTuples := []*openfgav1.TupleKey{{User: objInstance, Relation: relInstance, Object: tool}}
	if req.Backend != "" {
		ctxTuples = append(ctxTuples, &openfgav1.TupleKey{User: "backend:" + escapeID(req.Backend), Relation: relBackend, Object: tool})
	}
	if req.Access != "" {
		ctxTuples = append(ctxTuples, &openfgav1.TupleKey{User: "access_class:" + escapeID(req.Access), Relation: relAccessClass, Object: tool})
	}
	if req.CompanyID != "" {
		ctxTuples = append(ctxTuples, &openfgav1.TupleKey{User: user, Relation: relMember, Object: "company:" + escapeID(req.CompanyID)})
	}
	if req.Plan != "" {
		ctxTuples = append(ctxTuples, &openfgav1.TupleKey{User: user, Relation: relSubscriber, Object: "plan:" + escapeID(req.Plan)})
	}
	seen := make(map[string]bool, len(req.Roles))
	for _, r := range req.Roles {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		ctxTuples = append(ctxTuples, &openfgav1.TupleKey{User: user, Relation: relAssignee, Object: "role:" + escapeID(r)})
	}

	resp, err := e.srv.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              e.storeID,
		AuthorizationModelId: e.modelID,
		TupleKey:             &openfgav1.CheckRequestTupleKey{User: user, Relation: relCanExecute, Object: tool},
		ContextualTuples:     &openfgav1.ContextualTupleKeys{TupleKeys: ctxTuples},
	})
	if err != nil {
		return false, fmt.Errorf("authz check for user=%s tool=%s: %w", req.UserID, req.Tool, err)
	}
	return resp.GetAllowed(), nil
}

// Healthy reports whether the datastore is ready.
func (e *Embedded) Healthy(ctx context.Context) error {
	ready, err := e.srv.IsReady(ctx)
	if err != nil {
		return fmt.Errorf("embedded authz health check: %w", err)
	}
	if !ready {
		return errors.New("embedded authz datastore is not ready")
	}
	return nil
}

// Close stops the engine and closes the SQLite file. Calls after the first
// do nothing; OpenFGA's own Close must not run twice.
func (e *Embedded) Close() error {
	e.closeOnce.Do(e.srv.Close)
	return nil
}

// ApplyResult summarizes what Apply changed.
type ApplyResult struct {
	// Tuples is the number of stored tuples the grants and denies amount to.
	Tuples  int
	Written int
	Deleted int
}

// Apply makes the stored rules equal to grants and denies: it writes the
// tuples that are missing and deletes those no rule asks for. The steps are
// ordered so that no state in between allows more than both the old and the
// new rules: new denies first, then removed grants, then new grants, removed
// denies last. Checks started after Apply returns see the new rules.
func (e *Embedded) Apply(ctx context.Context, grants, denies []Grant) (ApplyResult, error) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	// Also after a partial failure: whatever was written must take effect.
	defer e.cache.invalidate()

	desired := map[tupleKey]bool{}
	for _, set := range []struct {
		kind, relation string
		rules          []Grant
	}{{"grant", relExecutor, grants}, {"deny", relBlocked, denies}} {
		for i, g := range set.rules {
			if err := g.Validate(); err != nil {
				return ApplyResult{}, fmt.Errorf("%s %d: %w", set.kind, i+1, err)
			}
			for _, t := range g.tuples(set.relation) {
				desired[t] = true
			}
		}
	}

	current, err := e.readTuples(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	var writes, deletes []tupleKey
	for t := range desired {
		if !current[t] {
			writes = append(writes, t)
		}
	}
	for t := range current {
		if !desired[t] {
			deletes = append(deletes, t)
		}
	}
	slices.SortFunc(writes, compareTuples)
	slices.SortFunc(deletes, compareTuples)

	// While the store changes, and if the change fails halfway, any tool that
	// either side names may have grants of its own.
	union := maps.Clone(current)
	maps.Copy(union, desired)
	e.setToolGrants(union)

	isDeny := func(t tupleKey) bool { return t.Relation == relBlocked }
	isGrant := func(t tupleKey) bool { return !isDeny(t) }

	res := ApplyResult{Tuples: len(desired)}
	for _, step := range []struct {
		write bool
		pick  func(tupleKey) bool
	}{{true, isDeny}, {false, isGrant}, {true, isGrant}, {false, isDeny}} {
		var n int
		var err error
		if step.write {
			n, err = e.writeTuples(ctx, filterTuples(writes, step.pick))
			res.Written += n
		} else {
			n, err = e.deleteAll(ctx, filterTuples(deletes, step.pick))
			res.Deleted += n
		}
		if err != nil {
			return res, err
		}
	}
	// Exact again, including tuples deleteTuples had to leave behind.
	if after, err := e.readTuples(ctx); err == nil {
		e.setToolGrants(after)
	}
	return res, nil
}

func filterTuples(ts []tupleKey, keep func(tupleKey) bool) []tupleKey {
	var out []tupleKey
	for _, t := range ts {
		if keep(t) {
			out = append(out, t)
		}
	}
	return out
}

// writeTuples writes ts in chunks of at most writeChunk tuples.
func (e *Embedded) writeTuples(ctx context.Context, ts []tupleKey) (int, error) {
	written := 0
	for chunk := range slices.Chunk(ts, writeChunk) {
		keys := make([]*openfgav1.TupleKey, 0, len(chunk))
		for _, t := range chunk {
			keys = append(keys, &openfgav1.TupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
		}
		if _, err := e.srv.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              e.storeID,
			AuthorizationModelId: e.modelID,
			Writes:               &openfgav1.WriteRequestWrites{TupleKeys: keys},
		}); err != nil {
			return written, fmt.Errorf("write authz rules: %w", err)
		}
		written += len(chunk)
	}
	return written, nil
}

// deleteAll deletes ts in chunks of at most writeChunk tuples.
func (e *Embedded) deleteAll(ctx context.Context, ts []tupleKey) (int, error) {
	deleted := 0
	for chunk := range slices.Chunk(ts, writeChunk) {
		n, err := e.deleteTuples(ctx, chunk)
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

func (e *Embedded) setToolGrants(stored map[tupleKey]bool) {
	tools := map[string]bool{}
	for t := range stored {
		if strings.HasPrefix(t.Object, "tool:") {
			tools[t.Object] = true
		}
	}
	e.toolGrants.Store(&tools)
}

// CheckBatch answers many requests, typically one caller and many tools, as
// when a tool listing is filtered. A tool without grants of its own is decided
// by the caller, its backend and its access class alone, so all such tools
// that agree on these share one check. A request whose check fails is
// reported as not allowed; the errors are returned joined.
func (e *Embedded) CheckBatch(ctx context.Context, reqs []Request) ([]bool, error) {
	out := make([]bool, len(reqs))
	toolGrants := *e.toolGrants.Load()
	decided := map[string]bool{}
	var errs []error
	for i, r := range reqs {
		key := ""
		if !toolGrants["tool:"+escapeID(r.Tool)] {
			key = equivalenceKey(r)
			if allowed, ok := decided[key]; ok {
				out[i] = allowed
				continue
			}
		}
		allowed, err := e.Check(ctx, r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[i] = allowed
		if key != "" {
			decided[key] = allowed
		}
	}
	return out, errors.Join(errs...)
}

// equivalenceKey identifies everything a check depends on except the tool
// name. An empty tool name is kept apart: Check denies it without asking.
func equivalenceKey(r Request) string {
	roles := slices.Clone(r.Roles)
	slices.Sort(roles)
	roles = slices.Compact(roles)
	parts := append([]string{r.UserID, r.CompanyID, r.Plan, r.Backend, r.Access, strconv.FormatBool(r.Tool == "")}, roles...)
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return b.String()
}

// deleteTuples deletes a chunk in one request. When that fails it retries
// tuple by tuple: a tuple that the current model rejects (written by a newer
// ToolMesh before a rollback) cannot grant anything under this model, so it is
// logged and left behind instead of blocking the rest.
func (e *Embedded) deleteTuples(ctx context.Context, chunk []tupleKey) (int, error) {
	del := func(ts []tupleKey) error {
		keys := make([]*openfgav1.TupleKeyWithoutCondition, 0, len(ts))
		for _, t := range ts {
			keys = append(keys, &openfgav1.TupleKeyWithoutCondition{User: t.User, Relation: t.Relation, Object: t.Object})
		}
		_, err := e.srv.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              e.storeID,
			AuthorizationModelId: e.modelID,
			Deletes:              &openfgav1.WriteRequestDeletes{TupleKeys: keys},
		})
		return err
	}
	if err := del(chunk); err == nil {
		return len(chunk), nil
	}
	deleted := 0
	for _, t := range chunk {
		if err := ctx.Err(); err != nil {
			return deleted, fmt.Errorf("delete authz grants: %w", err)
		}
		if err := del([]tupleKey{t}); err != nil {
			e.logger.WarnContext(ctx, "authz grant could not be deleted, leaving it", "user", t.User, "relation", t.Relation, "object", t.Object, "error", err)
			continue
		}
		deleted++
	}
	return deleted, nil
}

func (e *Embedded) readTuples(ctx context.Context) (map[tupleKey]bool, error) {
	out := map[tupleKey]bool{}
	token := ""
	for {
		resp, err := e.srv.Read(ctx, &openfgav1.ReadRequest{
			StoreId:           e.storeID,
			PageSize:          wrapperspb.Int32(readPage),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("read authz grants: %w", err)
		}
		for _, t := range resp.GetTuples() {
			k := t.GetKey()
			out[tupleKey{User: k.GetUser(), Relation: k.GetRelation(), Object: k.GetObject()}] = true
		}
		token = resp.GetContinuationToken()
		if token == "" {
			return out, nil
		}
	}
}

// HasPriorState reports whether dataDir holds state of an earlier ToolMesh
// run, apart from the embedded authz database itself. Called before anything
// else writes to the directory, it tells an upgraded installation from a
// fresh one.
func HasPriorState(dataDir string) bool {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), DBFileName) {
			return true
		}
	}
	return false
}
