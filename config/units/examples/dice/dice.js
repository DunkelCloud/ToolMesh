// Minimal unit-backend example.
//
// Exposes roll(n): flips a biased coin n times and returns per-outcome
// counts. The bias (75% "A") is hardcoded for demonstration; a real unit
// would either accept it as a parameter or read tenant configuration.
//
// Math.random() is available inside the goja sandbox — LockdownRuntime
// strips eval, Function, fetch, require, fs, process and friends, but
// leaves the standard ECMAScript globals (Math, Date, JSON) in place.

/* global Math */

function describe() {
    return {
        tools: [
            {
                name: "roll",
                description: "Flip a biased coin n times (75% A, 25% B) and return per-outcome counts.",
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
    for (let i = 0; i < n; i++) {
        counts[Math.random() < 0.75 ? "A" : "B"]++;
    }

    return {
        content: [{
            type: "text",
            text: JSON.stringify({ n: n, counts: counts, bias: { A: 0.75, B: 0.25 } })
        }]
    };
}
