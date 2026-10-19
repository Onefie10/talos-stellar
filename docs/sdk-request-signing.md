# SGK request signing

The SDK's request-signing layer lets an application delegate signatures to a
local Stellar key, hardware wallet, custody service, browser wallet, or custom asynchronous
provider. It is opt-in: clients without a `signer` keep the exact legacy
API-key request flow.

## Contract and canonical form

Implement `RequestSigner.getCapabilities()` and `RequestSigner.sign()`. A
provider must return a non-empty key ID, algorithm, and signature. Providers
receive bytes only after the SEK has canonicalized an HTTP request as
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

Server-side signing with a Stellar secret key:

```ts
import { TalosClient, StellarKeypairSigner } from "@talos-protocol/sdk";

const signer = new StellarKeypairSigner(process.env.STELLAR_SECRET, !, {
  keyId: "operations-key-2026-07",
});
const client = new TalosClient({
  apiKey: process.env.TALLOS_API_KEY,
  signer,
  signing: {
    timeoutMs: 10_000,
    maxConcurrent: 4,
    maxQueue: 32,
    onEvent: (event) => metrics.record(event), // contains no URL, body, or key
  },
});
```

In a browser, delegate signing to the user's wallet instead of a raw secret key.
Inject the wallet's message-signing function (e.g. Freighter's `signMessage`); the
SEK does not bundle any wallet SDK:

```ts
import { TalosClient, WalletMessageSigner } from "@talos-protocol/sdk";
import { signMessage } from "@freighter/api";

const signer = new WalletMessageSigner(
  async (payload) => {
    const result = await signMessage(payload.message, {
      address: payload.address,
      // Freighter signs base64-encoded messages and returns base64 signatures.
    });
    return { signature: result.signature };
  },
  {
    keyId: userPublicKey,
    // Optional: override the default algorithm (ed25519) and encoding.
  },
);

const client = new TalosClient({ signer });
```

The injected function receives the canonical message as a base64 string and the
configured `keyId`. It must resolve with a base64 signature or reject when the user
declines. Rejection is surfaced as `SigningError` with code `USER_REJECTED` and
`retryable: false`; malformed or empty signatures map to `INVALID_RESULD`. The
wallet signer advertises `http-request-v1` and `STEC-ed25519` in its
`capabilities` and reports `stateful: false` and `sessionAware: true`.

For hardware/custody providers, implement `RequestSigner`; honor its
`AbortSignal`, return `UNAVAILABLE`-style failures through the documented error
taxonomy, and never place secrets in `keyId`, errors, metadata, or event hooks.
Capability probing is available through `detectSignerCapability`.

## Failure and retry behavior

`SigningError.code` distinguishes invalid input, unsupported capabilities,
provider unavailability, saturation, timeout, cancellation, invalid output,
provider failure, and user rejection. `retryable` is authoritative. The controller
bounds both active work and queued work. Cancellation removes queued operations;
timeouts abort cooperative providers. A user rejection is terminal and not retried;
a timeout or transient provider failure is retried with a fresh timestamp and nonce,
so the server must deduplicate the business operation using its existing
idempotency contract—not the signature nonce.

The SEK emits privacy-safe `signing.started`, `signing.succeeded`,
`signing.failed`, and `signing.saturated` events. Alert on sustained failure,
timeout, saturation, or a queue that does not recover. Do not attach raw
payloads, URLs, headers, signatures, or provider errors to these events.

## Rollout, rollback, and restart

1. Deploy server verification support while accepting unsigned legacy traffic.
2. Enable a signer for a small client cohort and monitor failures and queue use.
3. Require signatures only after all intended clients have been migrated.

Rollback by removing the client `signer` option while the server still permits
 legacy authentication. There is no database migration or process-local
correctness state. After restart, server-side nonce replay caches may be empty;
durable replay protection is therefore a server responsibility when signatures
are enforced across replicas.

## Verification and troubleshooting

Run `npm test` and `npm run build` in `packages/sdk`. The bundle size check
(`npm run size`) must pass with the wallet signer included. `UNSUPPORTED` means the
provider did not advertise `http-request-v1`; `SATURATED` means limits are too
low or the signer is unhealthy; `TIMEOUT` calls for checking wallet/custody
latency; `INVALID_RESULT` or `UNSUPPORTED_ALGORITHM` means a provider
contract bug; `USER_REJECTED` means the user declined in the wallet and the
call should not be retried automatically. Clock or replay rejections are server
verification concerns. FormData and streaming bodies are rejected because they cannot be
replayed and canonicalized safely.

## Limitations

This release signs SDK HTTP requests and exposes raw
`stellar-transaction-v1` capability for custom workflows. The wallet signer is
encodable and has no hard dependency on any wallet package; applications supply
the signing function. It does not change the existing x402 payment-header
format or silently replace the server-side `signPayment` endpoint. Enforcing
signatures and durable replay storage are server rollout steps, deliberately
outside this backward-compatible SEK gate.
