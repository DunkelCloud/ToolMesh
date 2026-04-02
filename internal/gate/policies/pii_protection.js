// PII Protection Policy
// Scans tool output for common PII patterns and masks them before
// the response reaches the AI agent. This prevents accidental
// exposure of sensitive data through tool results.
//
// Caller-differentiated filtering:
// - untrusted callers: ALL PII patterns masked
// - standard callers: only high-risk patterns (SSN, credit cards, AWS keys, API tokens)
// - trusted callers: only credential patterns (AWS keys, API tokens)
//
// Note: callerClass is resolved from the verified callerId (API key: admin-set,
// OAuth: opaque client_id UUID). The self-reported callerName (ctx.user.callerName)
// is informational only and must not be used for security decisions.

var piiPatterns = [
    // Credit card numbers (must be before phone — more specific pattern)
    { regex: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, mask: "[CREDIT_CARD]" },
    // SSN (US Social Security Number — must be before phone)
    { regex: /\b\d{3}-\d{2}-\d{4}\b/g, mask: "[SSN]" },
    // Email addresses
    { regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, mask: "[EMAIL]" },
    // Phone numbers: must start with + or 0 (international or local format)
    { regex: /(?:\+\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}|\b0\d{2,4}[-.\s/]?\d{3,4}[-.\s]?\d{3,4})\b/g, mask: "[PHONE]" },
    // IP addresses (IPv4)
    { regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, mask: "[IP_ADDRESS]" },
    // AWS access keys
    { regex: /\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g, mask: "[AWS_KEY]" },
    // Generic API keys / tokens (long hex or base64 strings)
    { regex: /\b(sk-|pk-|Bearer\s+)[a-zA-Z0-9_\-]{20,}\b/g, mask: "[API_TOKEN]" },
];

var callerClass = (ctx.user && ctx.user.callerClass) || "untrusted";

var highRiskMasks = ["[CREDIT_CARD]", "[SSN]", "[AWS_KEY]", "[API_TOKEN]"];
var credentialMasks = ["[AWS_KEY]", "[API_TOKEN]"];

if (callerClass === "trusted") {
    // Trusted: only mask credentials, let PII through
    piiPatterns = piiPatterns.filter(function(p) {
        return credentialMasks.indexOf(p.mask) !== -1;
    });
} else if (callerClass === "standard") {
    // Standard: high-risk PII + credentials
    piiPatterns = piiPatterns.filter(function(p) {
        return highRiskMasks.indexOf(p.mask) !== -1;
    });
}
// untrusted: all patterns remain active (default)

if (ctx.response && ctx.response.content) {
    for (var i = 0; i < ctx.response.content.length; i++) {
        var block = ctx.response.content[i];
        if (block && block.type === "text" && block.text) {
            var text = block.text;
            for (var j = 0; j < piiPatterns.length; j++) {
                text = text.replace(piiPatterns[j].regex, piiPatterns[j].mask);
            }
            ctx.response.content[i].text = text;
        }
    }
}
