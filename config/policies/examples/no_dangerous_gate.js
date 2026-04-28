// No-Dangerous Gate Policy
//
// Permits read and write operations but blocks anything the DADL author
// classified as `admin` or `dangerous`. This is the pragmatic middle ground
// for production agents: the model can create issues, update configuration,
// and perform routine writes — but irreversible or destructive actions
// (delete repository, power-off device, drop database, …) are rejected
// before they reach the backend.
//
// To enable, copy this file into your active policies directory (the path
// configured via TOOLMESH_GATE_POLICIES_DIR or the default /app/policies).
//
// Tools without an explicit access tag are blocked under STRICT_MODE = true.
// Set STRICT_MODE = false to allow unclassified tools through; only the
// blocked levels listed below are then rejected.
//
// Customize `BLOCKED` to match your risk model — adding "write" turns this
// into a read-only policy (equivalent to readonly_gate.js).
//
// The policy runs only in the pre-execution phase so blocked calls never
// reach the backend.

var STRICT_MODE = true;
var BLOCKED = ["admin", "dangerous"];

if (ctx.phase === "pre") {
    var access = ctx.toolAccess || "";

    if (STRICT_MODE && access === "") {
        throw "no-dangerous mode: tool " + ctx.tool + " has no access classification";
    }

    for (var i = 0; i < BLOCKED.length; i++) {
        if (access === BLOCKED[i]) {
            throw "no-dangerous mode: tool " + ctx.tool + " requires '" + access + "' access, which is blocked";
        }
    }
}
