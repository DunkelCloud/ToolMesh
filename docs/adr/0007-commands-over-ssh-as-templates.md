---
status: accepted
date: 2026-11-16
---

# Commands over SSH as Templates

## Context and Problem Statement

Agents that operate hosts need a few things there again and again: the state
of a service, the end of a log, a restart, a step of a deployment. The way to
a host is SSH. Handing an agent an SSH session hands it a shell, and with a
shell everything the account may do.

ToolMesh decides per tool whether a caller may call it, checks the parameters
of a call before it runs, and writes each call to the audit log. All of that
works on a tool name and its parameters. A tool `run(command)` has one name
and one parameter for everything: the permission says "may use the host" and
the parameter is a program text.

How does an agent run a command on a host so that the existing checks say
something about what is run?

## Decision Drivers

- A permission names what may be done on a host, not that the host may be
  reached.
- No second place that decides. Authorization, kits, policies and the audit
  log stay the ones that exist.
- The check holds whatever a parameter value contains.
- The key of the host account never reaches the agent.
- A host is not sent anything before it has shown the key that is known for
  it.
- The first step is small: what an operator needs to run a handful of
  commands, without a service of its own on the hosts.

## Considered Options

1. **A tool that takes a command line, with a filter** that allows or refuses
   it: a list of allowed programs, prefixes of the argument vector, regular
   expressions, or a shell parser.
2. **Commands as templates**: a file lists named commands with a fixed
   argument vector and typed parameters; the caller picks a command and fills
   in values.
3. **An existing MCP server for SSH** as a backend.
4. **Policy at the host only**: forced commands in `authorized_keys` or
   `sudoers` rules, behind a tool that takes a command line.

## Decision Outcome

Chosen option: **2**.

**A command is a tool.** A backend of transport `ssh` reads a command file.
Each command in it has a name, a description, an access class, an argument
vector with placeholders, and the parameters the placeholders stand for. The
command appears as the tool `<backend>_<command>`. Authorization by tool,
backend or access class, kits, hints, policies before and after the call and
the audit log apply to it as to any tool, without a change to them.

**The caller writes no shell text.** SSH has no argument vector: the command
goes to the host as one string, which the login shell of the account reads.
ToolMesh builds that string. Every item of the argument vector becomes one
word in single quotes, with quotes and backslashes written outside the
quoting, so that sh, bash, dash, zsh and fish read the same word. A value
therefore stays one argument whatever it contains.

**A parameter says which values exist.** A string parameter has a pattern,
which has to match the whole value, or a list of values; a file with a free
string is refused when it is loaded. A number has a lower bound of 0 unless
the file sets another. A string value that starts with `-` is refused, since
the program would read it as an option; the values the author wrote, a list
or a default, are exempt. The program itself is never a placeholder. The
checks run before the pre-execution gate, so a policy sees the values the
command line is built from.

**One command per connection.** A call connects, logs in, runs its command
without a terminal and disconnects. Nothing is kept between calls: no
connection, no working directory, no environment. The result carries the
command line as it was sent, the exit code and what the command wrote. An exit
code the command's author did not name as a result makes the call an error
with the same content.

**The key stays with ToolMesh.** The private key comes from the credential
store or from a file, its passphrase from the credential store. Both are read
for every connection.

**The host shows its key first.** The entry names a `known_hosts` file. A host
whose key the file does not list, or that presents another one, is not
connected to. There is no setting that turns the check off.

**A backend is a host or a group of hosts.** With several hosts a call names
one of them in the parameter `host`. Rights are per backend and tool, so hosts
that need different rights get entries of their own, which may share a command
file.

### Why not the others

- **A filter on a command line** checks a program text. The string runs
  through a shell, with `;`, `$(...)`, redirections and globs. With the
  argument vector split out, many plain programs still run other programs on
  request (`find -exec`, `tar --checkpoint-action`, `awk`, `git -c`,
  `docker run -v`), and embedded languages (`psql -c`, `bash -c`) are beyond
  any syntax check. A filter can spare an agent some questions; it is no
  boundary.
- **An existing MCP server for SSH** holds the key itself and brings its own
  rules and, in some cases, its own way to approve a call. That is a second
  place that decides, in another runtime than ToolMesh's own. The servers
  looked at check the command line with patterns or a parser, which is
  option 1.
- **Policy at the host only** leaves ToolMesh with one tool and one
  permission per host, and an audit entry that holds a program text. It
  remains worth having underneath: an account of its own, `restrict` in
  `authorized_keys` and exact `sudoers` entries bound what a template can do
  if its author was too generous.

### Consequences

- An operator writes the commands down before an agent can use them. What is
  not in the file cannot be run, including the one command needed during an
  incident.
- A template is as wide as its program. `[sh, -c, "{script}"]` is a shell
  again, and so is any program that runs others on request. The file is code
  the operator installs and is read as such.
- The login shell of the account has to read single quotes the way a POSIX
  shell does. csh, PowerShell and `cmd.exe` do not.
- No terminal and no input: programs that prompt do not work, `sudo` only
  with `-n` and a rule that needs no password.
- Without a terminal the host does not end a command when the connection
  goes away. At a timeout ToolMesh asks the host to end it and closes the
  connection; a program that ignores the request and writes nothing keeps
  running.
- A connection per call costs a handshake per call. It keeps the backend
  without state: a reload, a rotated key and a changed `known_hosts` take
  effect with the next call, and nothing has to be closed when a right is
  taken away.
- The key is a standing right at the host, the same for every caller of the
  backend. Keys issued per call and credentials of users are not part of this
  decision.
- The format is a file of its own in the shape of a DADL (`backend`, `tools`,
  `params`, `access`), not a new backend type of the DADL specification.
  Published versions of the specification stay as they are; should the
  specification take the type up later, the shape carries over.

### Not decided here

A free shell for debugging and for development work, and sessions that last
across calls. Both need another boundary than a command file: a grant for a
limited time, a restricted account, a machine without credentials. They are
left to a later decision and do not change this one.
