import {
  WalletMessageSigner,
  SigningError,
  type WalletSignMessage,
} from "../src/signing.js";

/**
 * Example: sign a Talos request with a browser wallet.
 *
 * This example shows how to adapt a wallet's `signMessage`-style API (e.g.
 * Freighter, Albedo) to the SDK's `RequestSigner` abstraction without
 * depending on any wallet package.
 */

// A typical wallet signMessage signature looks like this:
// (Freighter's `signMessage(message, options)` returns a signed message.)
type FreighterLikeWallet = {
  signMessage: (
    message: string,
    options?: { address?: string },
  ) => Promise<{ signedMessage: string } | string>;
};

/**
 * Adapter that normalizes a wallet's signMessage result into the
 * signature format expected by the SDK.
 */
function adaptWallet(wallet: FreighterLikeWallet): WalletSignMessage {
  return async (payload: string) => {
    const result = await wallet.signMessage(payload);
    if (typeof result === "string") {
      return result;
    }
    return result.signedMessage;
  };
}

async function main(): Promise<void> {
  // In a real browser app this would be the wallet connector from
  // `web/src/components/providers.tsx`. Here we use a minimal stand-in
  // that forwards to a signing function provided by the host app.
  const wallet: FreighterLikeWallet = {
    signMessage: async (message: string) => {
      // This is where the actual wallet call happens. The wallet
      // returns a base64-encoded signature over the provided message.
      // For this example we delegate to a signer function that the
      // host app would implement using the wallet's API.
      return signMessageWithWallet(message);
    },
  };

  const signer = new WalletMessageSigner({
    signMessage: adaptWallet(wallet),
    // The wallet address is used for capability reporting and
    // identifying the signer in requests signed by this instance.
    address: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });

  const capabilities = signer.getCapabilities();
  console.log("Wallet signer capabilities:", capabilities);

  // The SigningController uses the signer to sign canonical request
  // payloads. The signature is verified against the wallet address.
  try {
    const signature = await signer.signMessage('talos:request:v1:{"example":true}');
    console.log("Signature:", signature);
  } catch (err) {
    if (err instanceof SigningError && err.code === "USER_REJECTED") {
      console.log("The user rejected the signing request.");
      return;
    }
    throw err;
  }
}

/**
 * Placeholder for the host app's wallet adapter. In a real app this
 * would call `FreighterApi.signMessage` or the equivalent Albedo call.
 */
async function signMessageWithWallet(_message: string): Promise<string> {
  throw new Error(
    "Wire this to the host app's wallet adapter (e.g. FreighterApi.signMessage).",
  );
}

void main().catch((err) => {
  console.error(err);
  process.exitCode(1);
});
