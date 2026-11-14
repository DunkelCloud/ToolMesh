---
status: accepted
date: 2026-11-14
---

# A Limit per Account, Enforced by the API

## Context and Problem Statement

With credentials of users ([ADR-0004](0004-credentials-of-users.md)) an agent
calls a backend as the account its user stored. The account's credentials open
everything the account can reach: every mailbox of a mail account, every
calendar, sending. A person who lets an agent work in their mailbox often wants
less than that: the inbox and one project folder, reading without sending.

Where does such a limit live, who writes it, and who enforces it? ToolMesh sees
a call as a tool name and parameters. For many calls the resource is not among
them: a message is fetched by its id, a thread by its id, and whether either
lies in a mailbox the user released is known to the API alone.

## Decision Drivers

- The limit is the user's, set where the user sets the credentials, and never
  within reach of an agent.
- A limit holds for every route of the API, also those that name a resource
  only by an id.
- No limit is never the result of a limit that could not be supplied.
- An operator can make the limit a condition instead of a choice.
- What a limit can express grows with the API, not with ToolMesh.

## Considered Options

1. **Enforcement in the gateway**: the DADL binds tool parameters to resource
   types, an authorization model holds the grants per user and resource, and
   ToolMesh checks parameters before a call and filters responses after it.
   Every route that names a resource by an id needs a lookup or a filter that
   repeats what the API knows, and every new route of the API is unprotected
   until the DADL binds it.
2. **One backend entry per limit**, each with fixed credentials and a fixed
   limit. The operator has to know every account and every limit, and each
   multiplies the tool list.
3. **A limit stored with the account, in the API's own form, handed to the API
   at login** (chosen). It needs an API whose login takes a limit.

## Decision Outcome

**The limit is one more credential of the user, and it is no secret.** An entry
of `user_credentials` with `format: acl` is a JSON object in the form the API
defines. The user enters it on the credentials page next to the account's
credentials. It is stored like them, sealed and bound to user, backend and
account. Unlike them it is shown on the page and named in the audit entry of a
change, so that the record says which limit applied from when on.

**ToolMesh does not read it.** It checks that the value is one JSON object and
hands it to the API as that object. What the properties mean, which names
match and what happens outside the limit is the API's business. A property
the API adds later works without a change to ToolMesh.

**The DADL says where it goes and that it may be absent.** The limit is a field
of the session login body, a credential reference like the others.
`auth.login.optional` lists the fields the login may go without: such a field
is left out when its credential has no value. This is a ToolMesh extension that
DADL spec v0.2 does not define. Because the limit travels with the login, it
needs a DADL with `auth.type: session`.

**The operator decides whether an account may go without one.** With
`optional: true` on the entry, an account without a limit is a whole account
and reaches what its credentials reach. Without it every account must hold a
limit, and one that does not fails its calls. A backend whose entry asks for
something its DADL cannot do is refused at load: an optional credential that
the DADL cannot leave out, a limit for a DADL without a login, an optional
credential that is no limit, an entry whose credentials are all optional.

**It fails closed.** A field is left out only when there is no value for it:
the account holds none and may go without one, or, for a credential of the
instance, the store has none. A limit that is stored and cannot be read, a
store that fails, an account that does not exist or a value that is no JSON
object fail the login, and nothing is sent. The same holds on the page: a save
is one write, so an account never exists with its secret and without the limit
entered next to it, and a save the API refuses is taken back whole. An entry
that could not be read before is in place after, still unreadable; the account
does not become one without a limit.

**The agent picks an account, nothing more.** The limit is not a tool
parameter. An agent names one of the user's accounts and gets what that
account's limit allows. Two accounts with the same credentials and different
limits give a user a wide and a narrow way in, chosen per call.

### Consequences

- Good: the limit covers every route, because the API applies it to the
  session, and the DADL binds nothing per tool.
- Good: one place holds the credentials and the limit of an account, and the
  session ToolMesh keeps per user and account is the unit the limit applies to.
  Storing or removing a limit ends that session, so the next call logs in with
  what is stored then.
- Good: the check that follows a save logs in with the limit, so a limit the
  API refuses at login, as malformed or as wider than the API allows this
  gateway, is reported at once and the earlier state is put back.
- Neutral: the check tells that the API took the login. Whether the API
  honors the limit is the API's and the DADL's business.
- Neutral: there is no central list of who released what. The audit trail
  records every change with its value.
- Bad: an operator who removes or renames the entry of a limit takes the
  limits of all accounts away, because the DADL's optional field is then read
  from the instance. ToolMesh warns in the log when users hold values under
  names a backend does not ask for; it does not refuse to load.
- Bad: it works only for APIs whose login takes a limit. For other APIs the
  account's credentials decide alone, as before.
- Bad: the limit binds agents that call through this backend entry. The
  account's credentials themselves open everything; whoever holds them is not
  bound.
- Bad: a user writes the object by hand. A name that matches nothing at the
  API is not an error at login; the account then reaches less than meant.

## More Information

- `docs/configuration.md`, section "Limiting what an account reaches".
- [ADR-0004](0004-credentials-of-users.md) for the accounts, the store and the
  page this builds on.
