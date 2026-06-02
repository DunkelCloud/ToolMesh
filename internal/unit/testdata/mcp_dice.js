// Test-only unit implementation: drives randombit-mcp via api.randombit.flip
// to validate the full sandbox → api.* → MCP stdio chain. The user-facing
// dice example in config/units/examples/dice uses Math.random() and has no
// sub-backends; this variant exists only so the integration test can prove
// the cross-backend path with a statistically meaningful signal.

/* global api */

function describe() {
    return {
        tools: [
            {
                name: "roll",
                description: "Roll the bit n times via api.randombit.flip and return per-outcome counts.",
                access: "read",
                params: {
                    n: { type: "integer", required: true }
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
    for (let i = 0; i < n; i++) {
        const result = await api.randombit.flip({});
        const text = extractText(result);
        if (text !== "A" && text !== "B") {
            throw new Error("randombit returned unexpected value: " + text);
        }
        counts[text]++;
    }

    return {
        content: [{ type: "text", text: JSON.stringify({ n: n, counts: counts }) }]
    };
}

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
