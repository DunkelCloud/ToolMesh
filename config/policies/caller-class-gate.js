// caller-class-gate.js — Example gate policy using caller origin.
// Restrict destructive tools for untrusted callers (pre-phase only).
if (ctx.phase === "pre") {
  if (ctx.user.callerClass === "untrusted" && ctx.tool.match(/_(delete|drop|remove)/i)) {
    throw new Error("Destructive operations not allowed for caller class: " + ctx.user.callerClass);
  }

  // Rate-limit untrusted callers more aggressively (20 req/hour vs default 100)
  if (ctx.user.callerClass === "untrusted" && ctx.rateLimitExceeded(20)) {
    throw new Error("Rate limit exceeded for untrusted caller: " + ctx.user.callerId);
  }
}
