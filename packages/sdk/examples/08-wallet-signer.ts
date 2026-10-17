import {
  WalletMessageSigner,
  SigningError,
  type WalletSignMessage,
} from "../src/signing.js";

/**
 * Example: sign a Talos request with a browser wallet.
 *
 * This example shows how to adapt a Freighter-compatible wallet (any wallet
 * that exposes `signMessage`) to the `RequestSigner` abstraction without
 * bundling any wallet SDK. The wallet function is injected, so this code
 * runs in the browser and in Node (e.g. with a fake wallet in tests).
 */

export async function main(wallet: WalletSignMessage): Promise<void> {
  const signer = new WalletMessageSigner({
    signMessage: wallet,
    // The address the wallet will sign with. Required for capability
    // reporting and for verifying the signature against the expected key.
    address: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });

  const capabilities = signer.getCapabilities();
  console.log("Wallet signer capabilities:", capabilities);

  // A request payload that must be signed. The canonical encoding is
  // handled by the signer/controller; the wallet only sees the bytes.
  const request = {
    method: "POST" as const,
    path: "/v1/transfers",
    body: { amount: "100", asset: "XET" },
    timestamp: Date.now(),
  };

  try {
    const signature = await signer.signRequest(request);
    console.log("Signed request:", signature);
  } catch (err: unknown) {
    if (err instanceof SigningError && err.code === "USER_REJECTED") {
      // The user closed or rejected the wallet prompt. This is expected
      // and should be surfaced to the UI as a cancellation, not an error.
      console.warn("Signing cancelled by the user.");
      return;
    }
    throw err;
  }
}
