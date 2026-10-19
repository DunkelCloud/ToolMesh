// Default Policy
// Baseline for every call: the caller is authenticated and within the rate
// limit.
//
// toolmesh: enforce-with-kit
//
// The directive above keeps this policy in force for a call that a kit the
// caller holds covers; pre-execution policies without it are skipped for
// such a call (see docs/configuration.md, "Gate policies").

if (!ctx.user.authenticated) {
    throw new Error("Unauthenticated request");
}
if (ctx.rateLimitExceeded(100)) {
    throw new Error("Rate limit exceeded");
}
