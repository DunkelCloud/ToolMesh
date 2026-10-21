// prod-access-by-caller-class.js — Pre-gate policy for production: a tool
// call passes only when the caller's class may use the tool's access class.
//
// Two inputs decide every call:
//   ctx.user.callerClass  the caller's trust class, resolved from the verified
//                         caller ID through caller-classes.yaml
//                         (TOOLMESH_CALLER_CLASSES_CONFIG). A caller that
//                         matches no pattern is "untrusted"; so is an
//                         unauthenticated request.
//   ctx.toolAccess        the tool's DADL access classification: "read",
//                         "write", "admin", "dangerous" or a custom string.
//                         Empty for tools without an access field, for
//                         example tools of upstream MCP servers.
//
// The ALLOWED table says, per caller class, which access classes may be
// called. Everything else is denied before the backend is reached:
//   - a caller class that is not in the table,
//   - a tool whose access class is not listed for the caller's class
//     (custom access strings included, unless you add them to the table),
//   - a tool without an access classification, unless the caller's class
//     is listed in UNCLASSIFIED_ALLOWED_FOR.
// The error names the tool, the caller class and the reason; the caller sees
// it in the tool result and the audit entry records it with status "denied".
// ToolMesh appends the kits that would lift the refusal: a held kit replaces
// this policy, which does not declare enforce-with-kit. tell_me_my_rights
// reports a tool this policy refuses as escalatable through those kits, or
// as denied, before any call is made.
//
// To enable, copy this file into the active policies directory (the path in
// TOOLMESH_POLICIES_DIR, default /app/policies; docker-compose mounts
// ./config/policies there). Policies load at startup: the start log prints
// "loaded policy name=prod-access-by-caller-class.js". To roll back, remove
// the file and restart.
//
// This policy only denies, so it composes with other pre-gate policies (for
// example one that reserves a set of tools for a single caller ID): a call
// passes only when every loaded policy lets it through.
//
// A kit the caller holds that covers the tool replaces this policy: it
// carries no "toolmesh: enforce-with-kit" directive, so it is skipped for
// such a call and the approver's decision for the kit stands in for the
// table below. Denies in config/authz.yaml still apply. The audit entry of
// the call records the kit (kit_applied) and this policy as skipped
// (gate_skipped); the start log shows "pre_gate_with_kit=skipped" for it.
//
// The policy runs in the pre-execution phase only; it never touches responses.

// Allowed access classes per caller class. Edit this table to your risk
// model; the keys must match the class names in caller-classes.yaml.
var ALLOWED = {
    trusted:    ["read", "write", "admin", "dangerous"],
    standard:   ["read", "write"],
    restricted: ["read"],
    untrusted:  ["read"]
};

// Caller classes that may call tools WITHOUT an access classification.
// Empty by default: an unclassified tool is denied for everyone.
var UNCLASSIFIED_ALLOWED_FOR = [];

function deny(tool, callerClass, reason) {
    throw "tool " + tool + " denied for caller class \"" + callerClass + "\": " + reason;
}

if (ctx.phase === "pre") {
    var tool = ctx.tool;
    var callerClass = (ctx.user && ctx.user.callerClass) || "";
    var access = ctx.toolAccess || "";

    if (!Object.prototype.hasOwnProperty.call(ALLOWED, callerClass)) {
        deny(tool, callerClass, "caller class is not listed in this policy");
    }

    if (access === "") {
        if (UNCLASSIFIED_ALLOWED_FOR.indexOf(callerClass) === -1) {
            deny(tool, callerClass, "tool has no access classification");
        }
    } else if (ALLOWED[callerClass].indexOf(access) === -1) {
        deny(tool, callerClass, "access class \"" + access + "\" is not allowed for this caller class");
    }
}
