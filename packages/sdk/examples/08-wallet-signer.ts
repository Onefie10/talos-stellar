/*
 * Example: sign Talos requests with a browser wallet (Freighter-compatible).
 *
 * Run with `tsx packages/sdk/examples/08-wallet-signer.ts` in a browser-like
 * environment. The adapter below wraps the Freighter `signMessage` API and the
 * SDK never imports the wallet package itself.
 */
import {
  SigningController,
  SigningError,
  TalosClient,
  WalletMessageSigner,
  type WalletSignMessageParams,
  type WalletSignMessageResult,
} from "../src/index.js";

/**
 * Minimal shape of the Freighter global exposed by the browser extension.
 * This is declared here so the example does not depend on `@freighter/api`.
 */
interface FreighterApi {
  isConnected(): Promise<{ isConnected: boolean }>;
  getPublicKey(): Promise<{ address: string }>;
  signMessage(
    message: string,
    options?: { address?: string; prompt?: string },
  ): Promise<{ signedMessage: string } | { error: string }>;
}

declare const freighter: FreighterApi | undefined;

function requireFreighter(): FreighterApi {
  if (typeof freighter === "undefined") {
    throw new SigningError(
      "UNAVAILABLE",
      "Install the Freighter wallet extension to sign requests",
      false,
    );
  }
  return freighter;
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Adapts Freighter's string-oriented `signMessage` to the SDK's byte-oriented
 * wallet signer contract. The canonical message bytes are base64-encoded for
 * transport and the returned signature is passed through as a base64 string.
 */
async function signMessageWithFreighter(
  params: WalletSignMessageParams,
  options?: { signal?: AbortSignal },
): Promise<WalletSignMessageResult> {
  if (options?.signal?.aborted) {
    throw new SigningError("CANCELLED", "Signing was cancelled", false);
  }
  const api = requireFreighter();
  const connection = await api.isConnected();
  if (!connection.isConnected) {
    throw new SigningError("UNAVAILABLE", "Connect Freighter before signing", false);
  }
  const { address } = await api.getPublicKey();
  const result = await api.signMessage(base64(params.message), {
    address,
    prompt: params.prompt,
  });
  if ("error" in result) {
    throw new SigningError("SIGNING_FAILED", result.error, true);
  }
  return { signature: result.signedMessage, keyId: address };
}

export async function main(): Promise<void> {
  const api = requireFreighter();
  const { address } = await api.getPublicKey();

  const signer = new WalletMessageSigner(signMessageWithFreighter, {
    keyId: address,
    capabilities: ["http-request-v1"],
    prompt: "Sign Talos API request",
    maxConcurrent: 1,
  });

  const controller = new SigningController(signer, {
    timeoutMs: 60_000,
    onEvent: (event) => {
      // Privacy-safe: contains no URL, body, or signature bytes.
      console.debug("signing", event.name, event.capability);
    },
  });

  const client = new TalosClient({
    baseUrl: "https://api.talos.protocol",
    signer,
    signing: { timeoutMs: 60_000, maxConcurrent: 1, maxQueue: 4 },
  });

  try {
    const talos = await client.getTalos("1");
    console.log("Signed request returned:", talos);
  } catch (error) {
    if (error instanceof SigningError && error.code === "CANCELLED") {
      console.info("User rejected the wallet signature request");
      return;
    }
    throw error;
  } finally {
    // Signing controller is exposed for custom flows that need direct signing.
    void controller;
  }
}

if (typeof import.meta !== "undefined" && import.meta.url === `process.argv[1]`) {
  void main();
}
