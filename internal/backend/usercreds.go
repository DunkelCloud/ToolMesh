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

package backend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Formats of a user credential (UserCredential.Format): how the credentials
// page asks for it and what it stores.
const (
	// UserCredentialFormatSecret asks for one secret and stores it as
	// entered. The default.
	UserCredentialFormatSecret = "secret"
	// UserCredentialFormatBasic asks for a user name and a password and
	// stores "Basic <base64(user:password)>", the value of an HTTP
	// Authorization header.
	UserCredentialFormatBasic = "basic"
)

// UserCredential is one entry of user_credentials in backends.yaml: a
// credential name of the backend's DADL that every user stores for
// themselves instead of the operator storing one for all. It is written
// either as the bare name or as a mapping with the texts the credentials
// page shows:
//
//	user_credentials:
//	  - mail_password
//	  - name: mail_login
//	    label: Mailbox login
//	    hint: Your mail address and an app password.
//	    format: basic
type UserCredential struct {
	// Name is the credential name as the DADL's auth block writes it.
	Name string
	// Label and Hint are shown on the credentials page; without a label
	// the page shows the name.
	Label string
	Hint  string
	// Format is UserCredentialFormatSecret (default) or
	// UserCredentialFormatBasic.
	Format string
}

// userCredentialFieldName is the key of a user_credentials mapping that
// carries the credential name.
const userCredentialFieldName = "name"

// userCredentialNameRe is the form of a credential name: letters, digits
// and "_", as in a DADL.
var userCredentialNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// Bounds of the texts the credentials page shows for a user credential.
const (
	maxUserCredentialLabelRunes = 80
	maxUserCredentialHintRunes  = 300
)

// UnmarshalYAML reads the bare name or the mapping form. Unknown keys of
// the mapping are errors, as everywhere in backends.yaml.
func (u *UserCredential) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		u.Name = node.Value
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, val := node.Content[i], node.Content[i+1]
			if val.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: user_credentials: %s must be a text", val.Line, key.Value)
			}
			switch key.Value {
			case userCredentialFieldName:
				u.Name = val.Value
			case "label":
				u.Label = val.Value
			case "hint":
				u.Hint = val.Value
			case "format":
				u.Format = val.Value
			default:
				return fmt.Errorf("line %d: user_credentials: field %s not found (use %s, label, hint, format)", key.Line, key.Value, userCredentialFieldName)
			}
		}
	default:
		return fmt.Errorf("line %d: user_credentials: an entry is a credential name or a mapping with name, label, hint, format", node.Line)
	}
	u.Name = strings.TrimSpace(u.Name)
	u.Label = strings.TrimSpace(u.Label)
	u.Hint = strings.TrimSpace(u.Hint)
	u.Format = strings.ToLower(strings.TrimSpace(u.Format))
	if u.Format == "" {
		u.Format = UserCredentialFormatSecret
	}
	return nil
}

// validate refuses an entry that names no credential or asks for an
// unknown format.
func (u UserCredential) validate() error {
	if !userCredentialNameRe.MatchString(u.Name) {
		return fmt.Errorf("user_credentials: %q is not a credential name: use letters, digits and _ only", u.Name)
	}
	if u.Format != UserCredentialFormatSecret && u.Format != UserCredentialFormatBasic {
		return fmt.Errorf("user_credentials: %s: format %q is not known (use %s or %s)", u.Name, u.Format, UserCredentialFormatSecret, UserCredentialFormatBasic)
	}
	if len([]rune(u.Label)) > maxUserCredentialLabelRunes {
		return fmt.Errorf("user_credentials: %s: label is longer than %d characters", u.Name, maxUserCredentialLabelRunes)
	}
	if len([]rune(u.Hint)) > maxUserCredentialHintRunes {
		return fmt.Errorf("user_credentials: %s: hint is longer than %d characters", u.Name, maxUserCredentialHintRunes)
	}
	return nil
}

// UserCredentialBinding makes credentials of a REST backend per user: the
// declared names are read from Store in the namespace of the calling user,
// never from the instance's credential store.
type UserCredentialBinding struct {
	// Credentials are the user_credentials of the backends.yaml entry.
	Credentials []UserCredential
	// Store holds what users stored. Without one a backend that declares
	// user credentials is refused.
	Store credentials.UserStore
	// EnrollURL is the address of the credentials page for the message of
	// a call that lacks its user's credential; "" when unknown.
	EnrollURL string
}

// errUserCredentialsNoStore explains how to turn the user credential store
// on.
var errUserCredentialsNoStore = errors.New("user_credentials needs the store for credentials of users, which is off: set TOOLMESH_USER_CREDENTIALS_KEY (32 random bytes, base64)")

// bindUserCredentials checks the user_credentials of a backend against its
// DADL and its entry and returns the credential store the backend reads
// through, with the declared names answered per user. A name the DADL's
// auth block does not read is an error, not a warning: with a mistyped
// name the DADL's real one would silently stay a credential of the
// instance, shared by every user.
func bindUserCredentials(spec *dadl.Spec, creds credentials.CredentialStore, b *UserCredentialBinding, env map[string]string) (credentials.CredentialStore, []UserCredential, error) {
	if b == nil || len(b.Credentials) == 0 {
		return creds, nil, nil
	}
	if b.Store == nil {
		return nil, nil, errUserCredentialsNoStore
	}
	used := map[string]bool{}
	for _, n := range spec.Backend.Auth.CredentialNames() {
		used[strings.ToUpper(strings.TrimSpace(n))] = true
	}
	remapped := map[string]bool{}
	for k := range env {
		if name, ok := strings.CutPrefix(credentials.CanonicalEnvKey(k), credentials.EnvKeyPrefix); ok {
			remapped[name] = true
		}
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(b.Credentials))
	bound := make([]UserCredential, 0, len(b.Credentials))
	for _, uc := range b.Credentials {
		if err := uc.validate(); err != nil {
			return nil, nil, err
		}
		key := strings.ToUpper(uc.Name)
		switch {
		case seen[key]:
			return nil, nil, fmt.Errorf("user_credentials: %s is listed twice", uc.Name)
		case !used[key]:
			return nil, nil, fmt.Errorf("user_credentials: the auth block of the DADL does not read a credential %q (it reads: %s)",
				uc.Name, strings.Join(spec.Backend.Auth.CredentialNames(), ", "))
		case remapped[key]:
			return nil, nil, fmt.Errorf("user_credentials: %s is also remapped by env: of the entry; a credential comes either from the users or from the instance", uc.Name)
		}
		seen[key] = true
		names = append(names, uc.Name)
		bound = append(bound, uc)
	}
	return credentials.NewUserScopedStore(creds, b.Store, spec.Backend.Name, names, b.EnrollURL), bound, nil
}

// userCredentialNote is added to the description of a backend with user
// credentials in the catalog.
const userCredentialNote = "Calls are made with the calling user's own stored account; " +
	"when the user has stored several, pass the label of one as \"account\"."

// accountParamDescription tells a caller what the account parameter is for.
const accountParamDescription = "Which of your stored accounts at this backend to use, by its label. " +
	"Leave it out when you have stored one account only. A call without it lists the labels when there are several."

// declareAccountParam adds the account parameter to every tool and
// composite of spec, so that schemas, descriptions and the argument check
// know it. A DADL that declares a parameter of that name itself is
// refused: one name cannot mean both.
func declareAccountParam(spec *dadl.Spec) error {
	def := dadl.GatewayParam(accountParamDescription)
	withAccount := func(kind, name string, params map[string]dadl.ParamDef) (map[string]dadl.ParamDef, error) {
		if existing, ok := params[credentials.AccountParam]; ok {
			if existing.Gateway() {
				return params, nil // added by an earlier adapter on the same spec
			}
			return nil, fmt.Errorf("user_credentials: %s %q declares a parameter %q, the name ToolMesh uses to select the user's account",
				kind, name, credentials.AccountParam)
		}
		out := make(map[string]dadl.ParamDef, len(params)+1)
		for k, v := range params {
			out[k] = v
		}
		out[credentials.AccountParam] = def
		return out, nil
	}
	for name, tool := range spec.Backend.Tools {
		params, err := withAccount("tool", name, tool.Params)
		if err != nil {
			return err
		}
		tool.Params = params
		spec.Backend.Tools[name] = tool
	}
	for name, comp := range spec.Backend.Composites {
		params, err := withAccount("composite", name, comp.Params)
		if err != nil {
			return err
		}
		comp.Params = params
		spec.Backend.Composites[name] = comp
	}
	return nil
}

// UserCredentialConfigError is returned by NewRESTAdapter for a backend
// whose user_credentials cannot be honored. The backend is refused: it
// would otherwise run with one credential for all callers.
type UserCredentialConfigError struct {
	Backend string
	Err     error
}

// Error implements error.
func (e *UserCredentialConfigError) Error() string {
	return fmt.Sprintf("REST backend %q: %v", e.Backend, e.Err)
}

// Unwrap returns the reason.
func (e *UserCredentialConfigError) Unwrap() error { return e.Err }

// CheckUserCredentialsYAML refuses a backends document in which an entry
// has the key user_credentials without a credential name under it: the key
// alone, an empty list, or an empty item. Syntax errors are left to the
// decoder of the document.
func CheckUserCredentialsYAML(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "backends" || root.Content[i+1].Kind != yaml.SequenceNode {
			continue
		}
		for _, entry := range root.Content[i+1].Content {
			if entry.Kind != yaml.MappingNode {
				continue
			}
			name := ""
			var declared *yaml.Node
			for j := 0; j+1 < len(entry.Content); j += 2 {
				switch entry.Content[j].Value {
				case userCredentialFieldName:
					name = entry.Content[j+1].Value
				case "user_credentials":
					declared = entry.Content[j+1]
				}
			}
			if declared == nil {
				continue
			}
			empty := declared.Kind != yaml.SequenceNode || len(declared.Content) == 0
			for _, item := range declared.Content {
				if item.Kind == yaml.ScalarNode && (item.Tag == "!!null" || strings.TrimSpace(item.Value) == "") {
					empty = true
				}
			}
			if empty {
				return fmt.Errorf("line %d: user_credentials of backend %q names no credential in one of its items, or none at all: name the credentials, or remove the key", declared.Line, name)
			}
		}
	}
	return nil
}

// normalizeAccountParam puts the account label of a call into its stored
// form: trimmed and lower-cased. A blank label counts as none and is taken
// out. A value that is no label is refused like any other wrong argument.
func normalizeAccountParam(toolName string, params map[string]any) (map[string]any, error) {
	raw, ok := params[credentials.AccountParam]
	if !ok {
		return params, nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		if k != credentials.AccountParam {
			out[k] = v
		}
	}
	if raw == nil {
		return out, nil
	}
	label, isString := raw.(string)
	if !isString {
		return nil, accountParamError(toolName, "must be a string, the label of one of your accounts")
	}
	if strings.TrimSpace(label) == "" {
		return out, nil
	}
	account, valid := credentials.NormalizeAccount(label)
	if !valid {
		return nil, accountParamError(toolName, "is not an account label: 1 to 100 letters, digits and @ . _ + -")
	}
	out[credentials.AccountParam] = account
	return out, nil
}

// accountParamError is the invalid_input error of an account argument.
func accountParamError(toolName, problem string) error {
	return &dadl.APIError{
		Code:       dadl.ErrCodeInvalidInput,
		HTTPStatus: http.StatusBadRequest,
		Message:    fmt.Sprintf("tool %q: parameter %q %s", toolName, credentials.AccountParam, problem),
	}
}

// selectAccount takes the account parameter out of the arguments of a call
// and puts the label into the context, where the auth layer reads it. The
// API never sees the parameter. A call without it keeps the account of its
// context: the child calls of a composite use the account the composite
// was called with.
func selectAccount(ctx context.Context, toolName string, params map[string]any) (context.Context, map[string]any, error) {
	params, err := normalizeAccountParam(toolName, params)
	if err != nil {
		return ctx, params, err
	}
	account, ok := params[credentials.AccountParam].(string)
	if !ok {
		return ctx, params, nil
	}
	rest := make(map[string]any, len(params))
	for k, v := range params {
		if k != credentials.AccountParam {
			rest[k] = v
		}
	}
	return credentials.WithAccount(ctx, account), rest, nil
}

// resolveAccount returns the account the call in ctx uses: the one it
// selected, or the calling user's only one.
func (a *RESTAdapter) resolveAccount(ctx context.Context) (string, error) {
	tenant := credentials.TenantInfo{Account: credentials.AccountFromContext(ctx)}
	if uc := userctx.FromContext(ctx); uc != nil && uc.Authenticated {
		tenant.UserID = uc.UserID
		tenant.CompanyID = uc.CompanyID
	}
	return a.userAccounts.ResolveAccount(ctx, tenant)
}

// withContextAccount returns params with the account of ctx added, for a
// backend with user credentials and arguments that name none. It is what
// the guard of a composite's child call checks.
func (a *RESTAdapter) withContextAccount(ctx context.Context, params map[string]any) map[string]any {
	account := credentials.AccountFromContext(ctx)
	if a.userAccounts == nil || account == "" {
		return params
	}
	if _, named := params[credentials.AccountParam]; named {
		return params
	}
	out := make(map[string]any, len(params)+1)
	for k, v := range params {
		out[k] = v
	}
	out[credentials.AccountParam] = account
	return out
}

// sentRequest returns the request a response answers when it is the one
// the adapter built, and nil after a redirect: the credentials of a
// redirected request may have been dropped on the way, so it does not tell
// which session was refused.
func sentRequest(resp *http.Response) *http.Request {
	if resp == nil || resp.Request == nil || resp.Request.Response != nil {
		return nil
	}
	return resp.Request
}

// UserCredentials returns the credentials every user of this backend stores
// for themselves, nil when the backend uses credentials of the instance
// only.
func (a *RESTAdapter) UserCredentials() []UserCredential {
	return a.userCredentials
}

// ForgetAccount drops the token, session and cookies the backend keeps for
// one account of userID, so that the account's next call authenticates
// with the credentials stored then. The user's other accounts keep their
// sessions. It does nothing for a backend without user credentials.
func (a *RESTAdapter) ForgetAccount(userID, account string) {
	a.auth.ForgetAccount(userID, account)
}

// Outcomes of a check of a user's credentials (UserCredentialCheck.Outcome).
const (
	// UserCheckAccepted: the API answered the check as a healthy backend
	// does.
	UserCheckAccepted = "accepted"
	// UserCheckRefused: the API did not accept the credentials (HTTP 401
	// or 403, or a refused login or token request).
	UserCheckRefused = "refused"
	// UserCheckUnknown: the check did not get far enough to tell, for
	// instance because the API was not reachable.
	UserCheckUnknown = "unknown"
	// UserCheckUnavailable: the backend's DADL declares no health check,
	// so there is nothing to check with.
	UserCheckUnavailable = "unavailable"
)

// UserCredentialCheck is the result of trying a user's stored credentials
// against the API.
type UserCredentialCheck struct {
	Outcome string
	// Detail says what happened in a few words. It never carries content
	// of a response.
	Detail string
}

// CheckUserCredentials sends the health check the backend's DADL declares
// with the credentials stored for one account of the user in ctx, once,
// and says whether the API accepted them. The token, session and cookies
// kept for that account are dropped first, so the check authenticates with
// what is stored now.
func (a *RESTAdapter) CheckUserCredentials(ctx context.Context, account string) UserCredentialCheck {
	tool, ok := a.spec.Backend.HealthToolDef()
	if !ok {
		return UserCredentialCheck{Outcome: UserCheckUnavailable, Detail: "the backend declares no health check"}
	}
	if uc := userctx.FromContext(ctx); uc != nil {
		a.auth.ForgetAccount(uc.UserID, account)
	}
	ctx = credentials.WithAccount(ctx, account)
	ctx, cancel := context.WithTimeout(ctx, a.spec.Backend.Health.CheckTimeout())
	defer cancel()

	at := a.healthAttempt(ctx, &tool)
	if at.err != nil {
		var exchange *dadl.AuthExchangeError
		if errors.As(at.err, &exchange) {
			detail := fmt.Sprintf("%s answered HTTP %d", exchange.What, exchange.Status)
			if exchange.Refused() {
				return UserCredentialCheck{Outcome: UserCheckRefused, Detail: detail}
			}
			return UserCredentialCheck{Outcome: UserCheckUnknown, Detail: detail}
		}
		var missing *credentials.UserCredentialError
		if errors.As(at.err, &missing) {
			return UserCredentialCheck{Outcome: UserCheckUnknown, Detail: "not all credentials of the backend are stored yet"}
		}
		if at.setup {
			return UserCredentialCheck{Outcome: UserCheckUnknown, Detail: "the check request could not be prepared"}
		}
		return UserCredentialCheck{Outcome: UserCheckUnknown, Detail: "no response (" + classifyTransportError(at.err) + ")"}
	}
	var res HealthResult
	a.evaluateHealth(&res, &tool, at)
	switch {
	case res.OK:
		return UserCredentialCheck{Outcome: UserCheckAccepted, Detail: fmt.Sprintf("HTTP %d", at.status)}
	case at.status == http.StatusUnauthorized || at.status == http.StatusForbidden:
		return UserCredentialCheck{Outcome: UserCheckRefused, Detail: fmt.Sprintf("the API answered HTTP %d", at.status)}
	}
	return UserCredentialCheck{Outcome: UserCheckUnknown, Detail: res.Reason}
}

// userCredentialResult turns the error of a call that lacks its user's
// credential into the tool result the caller gets: what is missing and
// where the user adds it. ok is false for any other error.
func userCredentialResult(err error) (*ToolResult, bool) {
	var uce *credentials.UserCredentialError
	if !errors.As(err, &uce) {
		return nil, false
	}
	return &ToolResult{
		Content: []any{textContent("Error: " + uce.Error())},
		IsError: true,
		Metadata: map[string]any{
			metadataKeyErrorCode:    "user_credential_" + uce.Reason,
			metadataKeyErrorMessage: uce.Error(),
			metadataKeyBackend:      uce.Backend,
		},
	}, true
}
