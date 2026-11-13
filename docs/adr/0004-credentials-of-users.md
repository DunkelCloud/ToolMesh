---
status: accepted
date: 2026-11-13
---

# Credentials of Users

## Context and Problem Statement

ToolMesh adds backend credentials to a request at call time. Until now every
credential belonged to the instance: one value per backend, stored by the
operator, used for every caller. That fits an API with one service account. It
does not fit an API where each person has an account of their own, such as a
mailbox, a calendar or a personal API token: with one stored value every caller
acts as the same account, and what a caller may see is decided by ToolMesh alone
instead of by the API.

Such backends need the credential of the calling user. Four questions follow.
Who decides that a credential is per user, the DADL or the operator? Where do
the values live, given that the built-in credential stores are read-only? How do
they get there without passing through a model? And what happens to a call whose
user has stored none?

## Decision Drivers

- A credential never passes through a model: no tool takes one as a parameter.
- A call without its user's credential fails. It is neither sent without
  authentication nor sent with a credential of the instance.
- The operator's configuration decides, not the DADL. A DADL may come from a
  public registry.
- Nothing kept between calls, a token, a session, a cookie, is shared between
  users.
- A person can have several accounts at one API.
- It works with the built-in credential stores, without an external secrets
  manager.

## Considered Options

1. **Fallback `user → tenant → global` for every credential**, as ADR-0001
   describes it. For a credential that is meant to be personal, the fallback is
   the failure: a user who has stored nothing would act under the shared value.
2. **Credentials as tool parameters.** No store and no page, but every secret
   passes through the model and into transcripts and audit entries.
3. **One `backends.yaml` entry per account.** Works with instance credentials,
   but the operator has to know every account of every user, each account
   multiplies the tool list, and every caller sees every account's tools.
4. **Operator-declared user credentials, an encrypted store written through a
   page, and an account chosen per call** (chosen).

## Decision Outcome

**Declaration.** A `backends.yaml` entry lists under `user_credentials` the
credential names of its DADL that every user stores for themselves. The DADL is
unchanged and does not know. A listed name that the DADL's auth block does not
read refuses the backend at load: with a mistyped name the real one would stay a
credential of the instance, silently. The same holds for an entry of a transport
that cannot honor the list (MCP over HTTP or stdio, the backends of a unit): it
is refused, not ignored.

**Resolution.** A declared name is read from the calling user's namespace and
from nowhere else. There is no fallback to the instance. This narrows ADR-0001
for declared names: resolution still lives in ToolMesh and not in the store, but
a personal credential has exactly one level. A call whose user has stored none
ends as an error result that says so and names the page; nothing is sent to the
API.

**Accounts.** A user stores several accounts per backend, each under a label,
such as a mail address. Every tool of such a backend
takes a parameter `account` besides its own. ToolMesh consumes it; the API never
sees it. With one stored account it may be left out. With several, a call that
names none fails and lists the labels. Labels are names, not secrets: they
appear in tool calls, in the audit trail, which names the account of every
call, and to policies, which see the label a call passes in its normalized
form and none when the call leaves it out. A DADL that declares a parameter
`account` itself cannot be used with user credentials.

**Isolation.** What ToolMesh keeps between calls, an OAuth2 access token, the
tokens of a session login and the cookies of that login, exists once per user
and account. The account is resolved before that state is chosen, so a state is
never used for a call that names another account. Logins of one identity are
serialized: calls that arrive while a login runs wait for it.

**Store.** The values live in a store of their own, written at run time: a file
in the data directory, each value sealed with AES-256-GCM under a key the
operator supplies (`TOOLMESH_USER_CREDENTIALS_KEY`). User, backend, account and
name are bound into each seal, so an entry copied to another place in the file
does not open. Without the key the store is off and a backend that declares
user credentials is refused. The key is the operator's to create because a key
that ToolMesh generated next to the file would protect nothing.

**Page.** Users store their accounts on a page of ToolMesh, signed in with
their ToolMesh password. The page runs no script, shows what is stored and
when, and never a value. It offers a backend to the users who may call a tool
of it, by the authorization of tool calls. After storing, ToolMesh sends the
health check the DADL declares with the new credentials; if the API refuses
them, the earlier state is restored. Every stored and removed account is an
audit entry without values.

**No call without authentication.** For a backend with instance credentials a
credential that is not set means the call goes out without a header, which
suits public endpoints. A backend with user credentials never does that,
whichever of its credentials is missing.

### Consequences

- Good: an API with personal accounts is called as the person the call is made
  for, and the API's own permissions apply.
- Good: a missing credential is a visible, recoverable error for the agent and
  never a silent downgrade.
- Good: one user's token, session or cookie cannot ride on another user's
  request.
- Cost: the operator keeps one more secret, and losing it loses every stored
  value. Changing the key makes stored values unreadable; users store them
  again.
- Cost: a backend with user credentials is not monitored in the background,
  because a background check has no user. Each user's check runs when they
  store an account and when they call `<backend>_health`.
- Cost: accounts belong to a user id and outlive the user. Nothing tells one
  holder of an id from the next, so an operator who reuses an id has to remove
  its accounts first. ToolMesh warns about accounts of users who cannot sign
  in.
- Limit: the page signs users in with a password. An installation that
  authenticates callers with API keys only cannot use it.
- Limit: the store is a file of one process. Instances behind a load balancer
  do not share it.
- Limit: cookies a tool response sets are not kept for the sessions of such a
  backend; only the cookies of the login are.

## More Information

Narrows [ADR-0001](0001-credential-override-resolution-in-toolmesh.md), and with
it the statement of
[ADR-0002](0002-per-user-settings-and-policy-resolution.md) that credential
resolution is a setting, for credentials declared per user. Restricting which
resources of an account a caller reaches, such as the folders of a mailbox, is
the subject of ADR-0002 and not decided here. Configuration:
[docs/configuration.md](../configuration.md#credentials-of-users).
