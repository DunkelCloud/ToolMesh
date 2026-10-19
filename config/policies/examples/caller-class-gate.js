// caller-class-gate.js — Example gate policy using caller origin.
// Restrict destructive tools for untrusted callers (pre-phase only).
//
// A kit the caller holds that covers the tool replaces this policy: it
// carries no "toolmesh: enforce-with-kit" directive, so an approver's grant
// of a destructive tool outranks the caller class, the rate limit below
// included. Put the rate limit into a policy of its own with the directive
// if it must hold for kit holders too.
if (ctx.phase === "pre") {
  if (ctx.user.callerClass === "untrusted" && ctx.tool.match(/_(delete|drop|remove)/i)) {
    throw new Error("Destructive operations not allowed for caller class: " + ctx.user.callerClass);
  }

  // Rate-limit untrusted callers more aggressively (20 req/hour vs default 100)
  if (ctx.user.callerClass === "untrusted" && ctx.rateLimitExceeded(20)) {
    throw new Error("Rate limit exceeded for untrusted caller: " + ctx.user.callerId);
  }
}
