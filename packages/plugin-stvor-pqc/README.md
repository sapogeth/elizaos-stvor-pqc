# @elizaos/plugin-stvor-pqc

Post-quantum end-to-end encryption for elizaOS agent-to-agent messaging, powered by [Stvor](https://pqc.stvor.xyz).

## Installation

```bash
npm install plugin-stvor-pqc
```

## Setup

Add the plugin to your agent's plugin array in `elizos.config.ts` (or equivalent):

```ts
import { stvorPqcPlugin } from "plugin-stvor-pqc";

export default {
  plugins: [
    stvorPqcPlugin,
    // ... your other plugins
  ],
};
```

No additional configuration is required.

## How it works

When an agent starts up, the plugin generates a fresh ML-KEM-768 keypair using the Stvor WASM core. The first time two Stvor-enabled agents exchange a message, they automatically perform an in-band key handshake — each agent sends its public encapsulation key, and both sides derive a shared secret via ML-KEM-768 encapsulation/decapsulation. From that point on, every message between those two agents is wrapped in a Double Ratchet session (forward-secrecy, break-in recovery), providing NIST FIPS 203-compliant post-quantum E2EE with zero manual configuration. Agents that don't have the plugin installed receive messages unchanged, so deployment is fully backward-compatible.

## Cryptographic primitives

| Primitive | Standard | Purpose |
|---|---|---|
| ML-KEM-768 | NIST FIPS 203 | Key encapsulation / shared secret |
| Double Ratchet | Signal Protocol | Forward secrecy, break-in recovery |
| AES-256-GCM | NIST SP 800-38D | Message encryption |
| HKDF-SHA256 | RFC 5869 | Key derivation |

All cryptography is handled by the `@stvor/web3` Rust/WASM core — no custom crypto.

## Known limitations (v0.1.0)

- **Agent detection** relies on `content.source === "agent"` convention, not a typed enum. Graceful failure if a connector uses a different string — no crash, just no E2EE for that session.
- **No persistent session storage** — sessions reset on agent restart. Cross-restart persistence is planned for v0.2.0.
- **In-band handshake only** — no external key registry. For cross-org agent identity verification see [pqc.stvor.xyz](https://pqc.stvor.xyz).

## Security notes (v0.1.0)

- **[MEDIUM] No cryptographic binding between peer's `ik` and `agentId`** — the channel provides the only authentication for peer identity. An on-chain identity registry is planned for v0.2.0 (see [pqc.stvor.xyz](https://pqc.stvor.xyz)).
- **[MEDIUM] Handshake fields have no size bounds** — oversized inputs are passed to the WASM layer without validation. Field length guards will be added in v0.2.0.
- **[MEDIUM] Session map is unbounded** — a peer rotating `agentId` repeatedly can grow memory without limit. A cap of 1000 sessions with LRU eviction is planned for v0.2.0.

## Links

- Stvor SDK: [pqc.stvor.xyz](https://pqc.stvor.xyz)
- elizaOS: [github.com/elizaos/eliza](https://github.com/elizaos/eliza)
- Issues: open a ticket in this repository

## License

MIT
