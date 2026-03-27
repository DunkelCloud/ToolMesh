// Shelly Write Protection Policy
// Prevents turning off devices via Shelly Cloud tools.
// Active only in the pre-execution phase — blocks before the API call is made.
//
// Note: Tool names use the canonical backend prefix (e.g. "shelly-cloud_set_light"),
// not the sanitized JS name ("shelly_cloud_set_light"). The regex uses [_-] to
// match both forms defensively.

if (ctx.phase === "pre") {
    if (/^shelly[_-]cloud[_-]set[_-](switch|cover|light|groups)$/.test(ctx.tool)) {
        if (ctx.params && ctx.params.on === false) {
            throw "Turning off devices is not allowed by policy";
        }
    }
}
