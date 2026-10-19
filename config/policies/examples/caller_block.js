// Caller Block Policy
// Blocks untrusted callers from accessing tools that return sensitive data.
// Tools matching certain patterns are restricted to trusted/standard callers only.
//
// Runs in the pre-execution phase only, so a blocked call never reaches the
// backend. A kit the caller holds that covers the tool replaces this policy:
// it carries no "toolmesh: enforce-with-kit" directive, so an approver's
// grant outranks the caller class.

var callerClass = (ctx.user && ctx.user.callerClass) || "untrusted";
var callerId = (ctx.user && ctx.user.callerId) || "unknown";

var blockedForUntrusted = [
    /customer/i,
    /credential/i,
    /secret/i,
    /admin/i,
];

if (ctx.phase === "pre" && callerClass === "untrusted") {
    for (var i = 0; i < blockedForUntrusted.length; i++) {
        if (blockedForUntrusted[i].test(ctx.tool)) {
            throw "Tool " + ctx.tool + " is not available for caller " + callerId + " (class: untrusted)";
        }
    }
}
