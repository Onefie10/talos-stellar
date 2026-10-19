/*
 * Example 08: sign Talos requests with a browser wallet.
 *
 * This example shows how to use the `WalletMessageSigner` from
 * `@talos/sdk/signing` to sign requests with a Freighter-compatible
 * wallet. The signer is decorated with an injected `signMessage`
 * function, so the SDK has no hard dependency on any wallet package.
 *
 * Run with:
 *   node --experimental-strip-types packages/sdk/examples/08-wallet-signer.ts
 */

import {
  WalletMessageSigner,
  SigningController,
  SigningError,
  canonicalizeRequest,
  type RequestSigner,
  type WalletSignMessage,
} from "../src/signing.js";

/**
 * Minimal shape of the Freighter browser API that this example needs.
 * We declare it locally instead of importing `@freighter/api` so the
 * example does not bundle any wallet SGK.
 */
interface FreighterApi {
  isConnected(): Promise<{ isConnected: boolean }>;
  getPublicKey(): Promise<{ publicKey: string }>;
  signMessage(
    message: string,
    options?: {
      address?: string;
      domain?: string;
    },
  ): Promise<{ signedAddress: string; signature: string }>;
}

declare const window: {
  freighterApi?: FreighterApi;
};

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(encoded: string): Uint8Array {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Adapter that turns the Freighter browser API into the generic
 * `signMessage` callback expected by `WalletMessageSigner`.
 */
function fromFreighter(api: FreighterApi, domain?: string): WalletSignMessage {
  return async (message) => {
    const connected = await api.isConnected();
    if (!connected.isConnected) {
      throw new SigningError(
        "UNAVAILABLE",
        "Freighter is not connected; call connect() first.",
        true,
      );
    }

    const { publicKey } = await api.getPublicKey();
    const result = await api.signMessage(bytesToBase64(message), {
      address: publicKey,
      domain,
    });

    return {
      publicKey: result.signedAddress,
      signature: base64ToBytes(result.signature),
    };
  };
}

/**
 * Example entrypoint. In a real browser app this would be called
 * from a click handler after the user connects their wallet.
 */
export async function main(): Promise<void> {
  const freighter = window.freighterApi;
  if (!freighter) {
    throw new Error(
      "Freighter is not installed. Install the extension and reload the page.",
    );
  }

  // 1. Build a RequestSigner backed by the user's wallet.
  const signer: RequestSigner = new WalletMessageSigner({
    signMessage: fromFreighter(freighter, "talos.app"),
    // Optional: domain separation for the wallet sign prompt.
    domain: "talos.app",
  });

  // 2. Inspect capabilities before using the signer.
  const capabilities = await signer.getCapabilities();
  console.log("signer capabilities", capabilities);

  // 3. Wrap the signer in a SigningController and sign a request.
  const controller = new SigningController(signer);

  const request = {
    method: "POST",
    url: "https://api.talos.dev/api/v1/transfers",
    body: JSON.stringify({ amount: "100", asset: "USDC" }),
    headers: { "content-type": "application/json" },
    timestamp: new Date().toISOString(),
    nonce: crypto.randomUUID(),
  };

  try {
    const bytes = await canonicalizeRequest(request);
    const signed = await controller.sign({ kind: "http-request-v1", bytes });
    console.log("signed request", signed);
  } catch (err) {
    if (err instanceof SigningError) {
      // User rejection is reported with a stable code so UI can react.
      if (err.code === "USER_REJECTED") {
        console.warn("The wallet signature request was rejected.");
        return;
      }
      console.error(`wallet signing failed (${err.code})`, err.message);
      return;
    }
    throw err;
  }
}

if (import.meta.main === import.meta.url) {
  main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
