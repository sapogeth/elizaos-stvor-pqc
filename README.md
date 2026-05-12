# elizaos-stvor-pqc

Post-quantum E2EE plugin for [elizaOS](https://github.com/elizaos/eliza) v3, powered by [Stvor](https://pqc.stvor.xyz).

## Package

| Package | Description |
|---|---|
| [`packages/plugin-stvor-pqc`](packages/plugin-stvor-pqc) | elizaOS plugin — ML-KEM-768 + Double Ratchet E2EE for agent-to-agent messaging |

## Quick start

```bash
npm install @elizaos/plugin-stvor-pqc
```

```ts
import { stvorPqcPlugin } from "@elizaos/plugin-stvor-pqc";

export default {
  plugins: [stvorPqcPlugin],
};
```

See [packages/plugin-stvor-pqc/README.md](packages/plugin-stvor-pqc/README.md) for full documentation.

## License

MIT
