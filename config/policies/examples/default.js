if (!ctx.user.authenticated) {
    throw new Error("Unauthenticated request");
}
if (ctx.rateLimitExceeded(100)) {
    throw new Error("Rate limit exceeded");
}
