/*
 * Example: sign Talos requests with a browser wallet.
 *
 * This file shows how to wire a Freighter-compatible wallet into the
 * `WalletMessageSigner` without adding a wallet package as a dependency.
 * The application injects its own `signMessage` function.
 *
 * Run: `tsx packages/sdk/examples/wallet-message-signer.ts`
 * (adjust the import path to your build output).
 */

import {
  WalletMessageSigner,
  SigningController,
  SigningError,
  canonicalizeRequest,
  type WalletSignMessage,
} from "../src/signing.js";

/**
 * Minimal shape of the Freighter browser API. We declare it locally so
 * this example does not depend on `@freighter/api`.
 */
interface FreighterApi {
  isConnected(): Promise<{ isConnected: boolean }>;
  getPublicKey(): Promise<{ address: string }>;
  signMessage(
    message: string,
    options?: { address?: string },
  ): Promise<{ signedMessage: string; signerAddress?: string }>;
}

declare const globalThis: typeof globalThis & {
  freighter?: FreighterApi;
};

function requireFreighter(): FreighterApi {
  const api = globalThis.freighter;
  if (!api) {
    throw new Error("Freighter is not installed in this browser");
  }
  return api;
}

/**
 * Adapter that turns Freighter's base64 signMessage into the shape
 * `WalletMessageSigner` knows how to normalize. The wallet signs the
 * canonical request bytes that the SDK hands it.
 */
export function createFreighterSignMessage(api: FreighterApi = requireFreighter()): WalletSignMessage {
  return async (input) => {
    const connected = await api.isConnected();
    if (!connected.isConnected) {
      throw new Error("Wallet is not connected");
    }
    const { address } = await api.getPublicKey();
    const result = await api.signMessage(input.message, { address: address });
    return {
      signature: result.signedMessage,
      publicKey: result.signerAddress ?? address,
    };
  };
}

export async function main(): Promise<void> {
  const signer = new WalletMessageSigner(createFreighterSignMessage());

  // In a real app you would pass this signer to `TalosClient`. Here we
  // demonstrate the flow directly through the controller.
  const controller = new SigningController(signer, {
    timeoutMs: 15_000,
    onEvent: (event) => {
      // Privacy-safe telemetry: no URL, body, or signature bytes.
      console.log(`[${event.name}] ${event.capability}`);
    },
  });

  const bytes = await canonicalizeRequest({
    method: "POST",
    url: "https://api.talos.protocol/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: "10.00", asset: "USDC" }),
    timestamp: new Date().toISOString(),
    nonce: globalThis.crypto.randomUUID(),
  });

  try {
    const result = await controller.sign({ kind: "http-request-v1", bytes });
    console.log(`Signed with ${result.algorithm} ${result.keyId}`);
  } catch (error) {
    if (error instanceof SigningError && error.code === "USER_REJECTED") {
      console.info("User cancelled the wallet prompt");
      return;
    }
    throw error;
  }
}

if (typeof import.meta !== "undefined" && import.meta.url === process.argv[1]) {
  void main();
}
