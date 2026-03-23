// Role-Based Field Filter Policy
// Restricts which fields in tool responses are visible based on the
// user's roles. Users without the required role see filtered content
// with a notice that fields were redacted.

// Field restriction rules: tool pattern -> required role -> restricted fields
var rules = [
    {
        // Database query results: hide raw SQL and connection info from non-admins
        toolPattern: /database|sql|query/i,
        requiredRole: "admin",
        restrictedFields: ["connectionString", "rawQuery", "internalId"],
    },
    {
        // User data tools: hide PII fields from non-compliance roles
        toolPattern: /user|profile|account/i,
        requiredRole: "compliance",
        restrictedFields: ["ssn", "dateOfBirth", "bankAccount", "salary"],
    },
    {
        // Infrastructure tools: hide secrets from non-ops roles
        toolPattern: /infra|deploy|config|secret/i,
        requiredRole: "ops",
        restrictedFields: ["password", "secret", "privateKey", "token", "apiKey"],
    },
];

function userHasRole(roles, required) {
    if (!roles) return false;
    for (var i = 0; i < roles.length; i++) {
        if (roles[i] === required || roles[i] === "admin") return true;
    }
    return false;
}

function filterObject(obj, restrictedFields) {
    if (typeof obj !== "object" || obj === null) return obj;
    var filtered = false;
    for (var key in obj) {
        for (var i = 0; i < restrictedFields.length; i++) {
            if (key.toLowerCase() === restrictedFields[i].toLowerCase()) {
                obj[key] = "[REDACTED]";
                filtered = true;
            }
        }
        if (typeof obj[key] === "object" && obj[key] !== null) {
            filterObject(obj[key], restrictedFields);
        }
    }
    return filtered;
}

if (ctx.response && ctx.response.content && ctx.tool) {
    for (var r = 0; r < rules.length; r++) {
        var rule = rules[r];
        if (rule.toolPattern.test(ctx.tool)) {
            if (!userHasRole(ctx.user.roles, rule.requiredRole)) {
                for (var i = 0; i < ctx.response.content.length; i++) {
                    var block = ctx.response.content[i];
                    if (block && block.type === "text" && block.text) {
                        // Try to parse as JSON and filter fields
                        try {
                            var parsed = JSON.parse(block.text);
                            if (filterObject(parsed, rule.restrictedFields)) {
                                ctx.response.content[i].text = JSON.stringify(parsed);
                            }
                        } catch (e) {
                            // Not JSON — check for key-value patterns in plain text
                            for (var f = 0; f < rule.restrictedFields.length; f++) {
                                var field = rule.restrictedFields[f];
                                var pattern = new RegExp(
                                    '("?' + field + '"?\\s*[:=]\\s*)("[^"]*"|\\S+)',
                                    "gi"
                                );
                                block.text = block.text.replace(pattern, "$1[REDACTED]");
                            }
                        }
                    }
                }
            }
        }
    }
}
