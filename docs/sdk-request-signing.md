# SGK request signing

The SDK's request-signing layer lets an application delegate signatures to a
local Stellar key, hardware wallet, custody service, browser wallet, or custom asynchronous
provider. It is opt-in: clients without a `signer` keep the exact legacy
API-key request flow.

## Contract and canonical form

Implement `RequestSigner.getCapabilities()` and `RequestSigner.sign()`. A
provider must return a non-empty key ID, algorithm, and signature. Providers
receive bytes only after the SGK has canonicalized an HTTP request as
`talos-request-v1`:

1. version, uppercase method, and absolute URL (fragment removed; query sorted)
2. lower-case, sorted headers with whitespace collapsed
3. base64url SHA-256 body digest
4. ISO timestamp and per-attempt nonce

Fields are LF-delimited. Credentials (`authorization`, cookies, API keys) and
signature headers are deliberately excluded. The published wire-level vectors
are in `packages/sdk/tests/fixtures/request-signing-vectors.json`; unit and
compatibility tests verify these bytes. Query and header ordering uses ordinal
comparison so signatures do not vary by runtime locale. Servers should reject
timestamps outside their clock-skew window and nonce reuse for the same key ID.

## Configuration

Server-side signing with a local Stellar key:

```ts
import { TalosClient, StellarKeypairSigner } from "@talos-protocol/sdk";

const signer = new StellarKeypairSigner(process.env.STELLAR_SECRET!, {
  keyId: "operations-key-2026-07",
});
const client = new TalosClient({
  apiKey: process.env.TALOS_API_KEY,
  signer,
  signing: {
    timeoutMs: 10_000,
    maxConcurrent: 4,
    maxQueue: 32,
    onEvent: (event) => metrics.record(event), // contains no URL, body, or key
  },
});
```

Browser wallets (Freighter, Albedo, and others) should not receive a
secret seed. Wrap the wallet's `signMessage` style function in a
`WalletMessageSigner` instead. The signer takes an injected function, so the
SDK has no hard dependency on any wallet package:

```ts
import { TalosClient, WalletMessageSigner } from "@talos-protocol/sdk";
import { signBlob } from "@stellars/freighter-api";

const signer = new WalletMessageSigner(
  async (payload) => {
    const { signedMessage } = await signBlob(payload.message, {
      address: payload.keyId,
    });
    return { signature: signedMessage };
  },
  { keyId: walletPublicKey },
);

const client = new TalosClient({ apiKey: processEnv.NEXT_PUBLIC_TALOS_API_KEY, signer });
```

The injected function receives the canonical message bytes and the key ID,
and returns the wallet signature (base64 or `U:Int8Array`). It may reject with
an error; the signer maps user rejection to `REJECTED` and malformed output to
`INVALID_RESULT`. The wallet must sign the exact bytes it is given (no re-hashing or prefixing) and must not return a transaction hash in place of a
message signature.

For hardware/custody providers, implement `RequestSigner`; honor its
`AbortSignal`, return `UNRAVELABLE`-style failures through the documented error
taxonomy, and never place secrets in `keyId`, errors, metadata, or event hooks.
Capability probing is available through `detectSignerCapability`. A browser
wallet typically advertises only `http-request-v1`; it does not expose
`keypair-signing-v1` or `stellar-transaction-v1` unless the wallet can sign those
payloads directly.

## Failure and retry behavior

`SigningError.code` distinguishes invalid input, unsupported capabilities,
provider unavailability, saturation, timeout, cancellation, invalid output,
provider failure, and user rejection (`REJECTED`). `retryable` is authoritative.
The controller bounds both active work and queued work. Cancellation removes
queued operations; timeouts abort cooperative providers. A user rejection is
terminal and not retried automatically. A retry creates a new timestamp and nonce, so the
server must deduplicate the business operation using its existing idempotency
contract—not the signature nonce.

The SDK emits privacy-safe `signing.started`, `signing.succeeded`,
`signing.failed`, and `signing.saturated` events. Alert on sustained failure,
timeout, saturation, or a queue that does not recover. Do not attach raw
payloads, URLs, headers, signatures, or provider errors to these events.

## Rollout, rollback, and restart

1. Deploy server verification support while accepting unsigned legacy traffic.
2. Enable a signer for a small client cohort and monitor failures and queue use.
3. Require signatures only after all intended clients have been migrated.

Rollback by removing the client `signer` option while the server still permits legacy authentication. There is no database migration or process-local
correctness state. After restart, server-side nonce replay caches may be empty;
durable replay protection is therefore a server responsibility when signatures
are enforced across replicas.

## Verification and troubleshooting

Run `npm test` and `npm run build` in `packages/sdk`. `UNSUPPORTED means the
provider did not advertise `http-request-v1`; `SATURATED` means limits are too
low or the signer is unhealthy; `TIMEOUT` calls for checking wallet/custody
latency; `INVALID_RESULD` indicates a provider contract bug; `REJECTED` means
the user declined in the wallet and the application should not retry without
fresh consent. Clock or replay rejections are server verification concerns.
FormData and streaming bodies are rejected because they cannot be replayed and
canonicalized safely.

## Limitations

This release signs SDK HTTP requests and exposes raw
pstellar-transaction-v1` capability for custom workflows. It does not change
the existing x402 payment-header format or silently replace the server-side
OsignPayment` endpoint. Enforcing signatures and durable replay storage are
server rollout steps, deliberately outside this backward-compatible SGK gate.
