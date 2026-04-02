// Caller Block Policy
// Blocks untrusted callers from accessing tools that return sensitive data.
// Tools matching certain patterns are restricted to trusted/standard callers only.
//
// Note: callerClass is resolved from the verified callerId — for API keys this
// is admin-configured, for OAuth clients it is the opaque client_id (UUID).
// The self-reported callerName is available for logging but not used here.

var callerClass = (ctx.user && ctx.user.callerClass) || "untrusted";
var callerId = (ctx.user && ctx.user.callerId) || "unknown";

var blockedForUntrusted = [
    /customer/i,
    /credential/i,
    /secret/i,
    /admin/i,
];

if (callerClass === "untrusted") {
    for (var i = 0; i < blockedForUntrusted.length; i++) {
        if (blockedForUntrusted[i].test(ctx.tool)) {
            throw "Tool " + ctx.tool + " is not available for caller " + callerId + " (class: untrusted)";
        }
    }
}
