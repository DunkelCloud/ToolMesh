// Read-Only Gate Policy
//
// Restricts the AI to tools the DADL author has classified as access: read.
// This is the simplest way to enforce a read-only posture without standing
// up OpenFGA — the DADL declaration is the single source of truth, and the
// gate evaluates it on every pre-execution check.
//
// To enable, copy this file into your active policies directory (the path
// configured via TOOLMESH_GATE_POLICIES_DIR or the default /app/policies).
//
// Tools without an explicit access tag (e.g. those sourced from upstream
// MCP servers without classification) are blocked under STRICT_MODE = true.
// Set STRICT_MODE = false to allow unclassified tools through; only "write",
// "admin", "dangerous", and any other non-"read" value are then rejected.
//
// The policy runs only in the pre-execution phase so blocked calls never
// reach the backend.

var STRICT_MODE = true;

if (ctx.phase === "pre") {
    var access = ctx.toolAccess || "";

    if (STRICT_MODE && access === "") {
        throw "read-only mode: tool " + ctx.tool + " has no access classification";
    }

    if (access !== "" && access !== "read") {
        throw "read-only mode: tool " + ctx.tool + " requires '" + access + "' access";
    }
}
