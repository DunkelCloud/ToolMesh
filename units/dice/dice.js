// Walking-skeleton unit-backend implementation.
//
// Exposes roll(n) which calls api.randombit.flip() n times and returns an
// aggregate of the outcomes. The MCP tool descriptors are derived from the
// top-level describe() function — no separate schema sidecar.

/* global api */

function describe() {
    return {
        tools: [
            {
                name: "roll",
                description: "Roll the bit n times and return per-outcome counts plus the raw sequence.",
                access: "read",
                params: {
                    n: {
                        type: "integer",
                        required: true,
                        description: "Number of flips (1..10000)"
                    }
                }
            }
        ]
    };
}

async function roll(args) {
    const n = Number(args && args.n);
    if (!Number.isInteger(n) || n < 1 || n > 10000) {
        throw new Error("n must be an integer in 1..10000");
    }

    const counts = { A: 0, B: 0 };
    const sequence = [];
    for (let i = 0; i < n; i++) {
        const result = await api.randombit.flip({});
        const text = extractText(result);
        if (text !== "A" && text !== "B") {
            throw new Error("randombit returned unexpected value: " + text);
        }
        counts[text]++;
        sequence.push(text);
    }

    return {
        content: [{
            type: "text",
            text: JSON.stringify({ n: n, counts: counts })
        }],
        _meta: {
            counts: counts,
            sequence: sequence
        }
    };
}

// extractText pulls the first text block out of an MCP tool result. The
// MCP adapter shape is { content: [{ type: "text", text: "..." }, ...] }.
function extractText(result) {
    if (!result || !Array.isArray(result.content)) {
        return null;
    }
    for (const block of result.content) {
        if (block && block.type === "text" && typeof block.text === "string") {
            return block.text;
        }
    }
    return null;
}
