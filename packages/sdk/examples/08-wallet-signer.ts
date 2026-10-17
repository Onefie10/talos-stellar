/**
 * Example: sign Talos requests with a browser wallet (Freighter-compatible).
 *
 * Run with `tsx packages/sdk/examples/08-wallet-signer.ts` in a browser-like
 * environment, or wire the same `signMessage` function into your app.
 */
import {
  SigningController,
  SigningError,
  WalletMessageSigner,
  canonicalizeRequest,
} from "../src/index.js";


/**
 * Typical Freighter `signMessage` shape. We declare it locally so this
 * example does not depend on any wallet SDK.
 */
declare const freighter: {
  signMessage: (
    message: string,
    options?: { address?: string },
  ) => Promise<{ signedMessage: string; signerAddress: string }>;
};

async function main(): Promise<void> {
  // 1. Adapter the wallet API to the injected `signMessage` contract.
  const signer = new WalletMessageSigner({
    keyId: "freighter-user",
    signMessage: async ({ message, address }) => {
      const result = await freighter.signMessage(message, { address });
      return {
        signature: result.signedMessage,
        publicKey: result.signerAddress,
      };
    },
  });

  // 2. Wrap it in a controller to bound concurrency and timeouts.
  const controller = new SigningController(signer, {
    timeoutMs: 30_000,
    maxConcurrent: 1,
    onEvent: (event) => {
      // Privacy-safe: contains no URL, body, or signature bytes.
      console.debug("[signing]", event.name, event.errorCode ?? "");
    },
  });

  // 3. Canonicalize a request and sign it with the wallet.
  const canonical = await canonicalizeRequest({
    method: "GET",
    url: "https://api.talos.example/v1/talos/1",
    timestamp: new Date().toISOString(),
    nonce: crypto.randomUUID(),
  });

  try {
    const signature = await controller.sign({
      kind: "http-request-v1",
      bytes: canonical,
    });
    console.log("Signed with", signature.keyId, "algorithm", signature.algorithm);
  } catch (error) {
    if (error instanceof SigningError && error.code === "USER_REJECTED") {
      console.info("User declined to sign the request");
      return;
    }
    throw error;
  }
}

void main();
