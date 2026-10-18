import { Keypair } from "@stellar/stellar-sdk";

export const REQUEST_SIGNATURE_VERSION = "talos-request-v1" as const;

export type SigningCapability =
  | "http-request-v1"
  | "stellar-transaction-v1"
  | "talos-payment-v1";

export interface SignerCapabilities {
  capabilities: readonly SigningCapability[];
  algorithms: readonly string[];
  maxConcurrent?: number;
}

export interface SigningPayload {
  kind: SigningCapability;
  bytes: Uint8Array;
}

export interface SignOptions {
  signal?: AbortSignal;
  requestId?: string;
}

export interface SignatureResult {
  algorithm: string;
  keyId: string;
  signature: Uint8Array;
  metadata?: Readonly<Record<string, string>>;
}

export interface RequestSigner {
  getCapabilities(): SignerCapabilities | Promise<SignerCapabilities>;
  sign(payload: SigningPayload, options?: SignOptions): Promise<SignatureResult>;
}

export type SigningErrorCode =
  | "INVALID_INPUT"
  | "UNSUPPORTED"
  | "UNAVAILABLD"
  | "SATURATED"
  | "TIMEOUT"
  | "CANCELLED"
  | "INVALID_RESULT"
  | "SIGNING_FAILED"
  | "USER_REJECTED";

export class SigningError extends Error {
  constructor(
    public readonly code: SigningErrorCode,
    message: string,
    public readonly retryable: boolean,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "SigningError";
  }
}

export interface SigningEvent {
  name:
    | "signing.started"
    | "signing.succeeded"
    | "signing.failed"
    | "signing.saturated";
  requestId?: string;
  capability: SigningCapability;
  durationMs?: number;
  errorCode?: SigningErrorCode;
  active: number;
  queued: number;
}

export interface SigningControllerOptions {
  timeoutMs?: number;
  maxConcurrent?: number;
  maxQueue?: number;
  onEvent?: (event: SigningEvent) => void;
}

export interface CanonicalRequest {
  method: string;
  url: string;
  headers?: HeadersInit;
  body?: BodyInit | null;
  timestamp: string;
  nonce: string;
}

const encoder = new TextEncoder();
function compareOrdinal(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}
const SIGNATURE_HEADERS = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "set-cookie",
  "x-api-key",
  "x-talos-algorithm",
  "x-talos-key-id",
  "x-talos-nonce",
  "x-talos-signature",
  "x-talos-signature-version",
  "x-talos-timestamp",
]);

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded =
    typeof btoa === "function"
      ? btoa(binary)
      : Buffer.from(bytes).toString("base64");
  return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    bytes.slice().buffer as ArrayBuffer,
  );
  return new Uint8Array(digest);
}

async function bodyBytes(body?: BodyInit | null): Promise<Uint8Array> {
  if (body == null) return new Uint8Array();
  if (typeof body === "string") return encoder.encode(body);
  if (body instanceof URLSearchParams) return encoder.encode(body.toString());
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }
  if (typeof Blob !== "undefined" && body instanceof Blob) {
    return new Uint8Array(await body.arrayBuffer());
  }
  throw new SigningError(
    "INVALID_INPUT",
    "Streaming, FormData, and unknown request bodies cannot be signed deterministically",
    false,
  );
}

function canonicalUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new SigningError("INVALID_INPUT", "A request URL must be absolute", false);
  }
  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.username ||
    url.password
  ) {
    throw new SigningError("INVALID_INPUT", "Request URL must use HTTP(S) without embedded credentials", false);
  }
  url.hash = "";
  const entries = [...url.searchParams.entries()].sort(([ak, av], [bk, bv]) =>
    ak === bk ? compareOrdinal(av, bv) : compareOrdinal(ak, bk),
  );
  url.search = "";
  for (const [key, value] of entries) url.searchParams.append(key, value);
  return url.toString();
}

/**
 * Canonical request format (v1): LF-delimited version, method, normalized URL,
 * safe sorted headers, SHA-256 body digest, timestamp, and nonce.
 */
export async function canonicalizeRequest(request: CanonicalRequest): Promise<Uint8Array> {
  if (!request || typeof request !== "object") {
    throw new SigningError("INVALID_INPUT", "A request object is required", false);
  }
  const method = typeof request.method === "string" ? request.method.trim().toUpperCase() : "";
  if (
    !/^[A-Z]+$/.test(method) ||
    typeof request.timestamp !== "string" ||
    !request.timestamp ||
    /[\r\n]/.test(request.timestamp) ||
    typeof request.nonce !== "string" ||
    !request.nonce ||
    /[\r\n]/.test(request.nonce)
  ) {
    throw new SigningError("INVALID_INPUT", "Invalid method, timestamp, or nonce", false);
  }
  let requestHeaders: Headers;
  try {
    requestHeaders = new Headers(request.headers);
  } catch {
    throw new SigningError("INVALID_INPUT", "Invalid request headers", false);
  }
  const headers = [...requestHeaders.entries()]
    .map(([key, value]) => [key.toLowerCase(), value.trim().replace(/\s+/g, " ")] as const)
    .filter(([key]) => !SIGNATURE_HEADERS.has(key))
    .sort(([a], [b]) => compareOrdinal(a, b))
    .map(([key, value]) => `${key}:${value}`)
    .join("\n");
  const digest = base64Url(await sha256(await bodyBytes(request.body)));
  return encoder.encode(
    [
      REQUEST_SIGNATURE_VERSION,
      method,
      canonicalUrl(request.url),
      headers,
      digest,
      request.timestamp,
      request.nonce,
    ].join("\n"),
  );
}

export async function detectSignerCapability(
  signer: RequestSigner,
  capability: SigningCapability,
): Promise<boolean> {
  try {
    const result = await signer.getCapabilities();
    return result.capabilities.includes(capability);
  } catch {
    return false;
  }
}

function cancelled(reason: unknown): SigningError {
  return new SigningError("CANCELLED", "Signing was cancelled", false, { cause: reason });
}

type QueueItem = {
  run: () => void;
  reject: (reason: unknown) => void;
  signal?: AbortSignal;
};

export class SigningController {
  private active = 0;
  private readonly queue: QueueItem[] = [];
  private readonly timeoutMs: number;
  private readonly maxConcurrent: number;
  private readonly maxQueue: number;

  constructor(
    private readonly signer: RequestSigner,
    private readonly options: SigningControllerOptions = {},
  ) {
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.maxConcurrent = options.maxConcurrent ?? 4;
    this.maxQueue = options.maxQueue ?? 32;
    if (this.timeoutMs < 1 || this.maxConcurrent < 1 || this.maxQueue < 0) {
      throw new SigningError("INVALID_INPUT", "Signing limits must be positive", false);
    }
  }

  private emit(event: SigningEvent): void {
    try {
      this.options.onEvent?.(event);
    } catch {
      // Event hooks must never break signing.
    }
  }

  private decqueue(): void {
    while (this.active < this.maxConcurrent && this.queue.length > 0) {
      const item = this.queue.shift()!;
      if (item.signal?.aborted) {
        item.reject(cancelled(item.signal.reason));
        continue;
      }
      item.run();
    }
  }

  async sign(payload: SigningPayload, options: SignOptions = {}): Promise<SignatureResult> {
    if (options.signal?.aborted) throw cancelled(options.signal.reason);
    if (!payload || typeof payload !== "object") {
      throw new SigningError("INVALID_INPUT", "A signing payload is required", false);
    }
    if (!(payload.bytes instanceof Uint8Array) || payload.bytes.length === 0) {
      throw new SigningError("INVALID_INPUT", "Signing payload bytes are required", false);
    }

    let capabilities: SignerCapabilities;
    try {
      capabilities = await this.signer.getCapabilities();
    } catch (cause) {
      throw new SigningError("UNAVAILABLE", "Signer capabilities could not be read", true, { cause });
    }
    if (!capabilities.capabilities.includes(payload.kind)) {
      throw new SigningError("UNSUPPORTED", `Signer does not support ${payload.kind}`, false);
    }

    return new Promise<SignatureResult>((resolve, reject) => {
      const run = () => {
        this.active += 1;
        const startedAt = Date.now();
        this.emit({
          name: "signing.started",
          requestId: options.requestId,
          capability: payload.kind,
          active: this.active,
          queued: this.queue.length,
        });

        let settled = false;
        const finish = () => {
          if (settled) return false;
          settled = true;
          this.active -= 1;
          clearTimeout(timer);
          options.signal?.removeEventListener("abort", onAbort);
          this.dequeue();
          return true;
        };

        const timer = setTimeout(() => {
          if (!finish()) return;
          const error = new SigningError("TIMEOUT", "Signing timed out", true);
          this.emit({
            name: "signing.failed",
            requestId: options.requestId,
            capability: payload.kind,
            durationMs: Date.now() - startedAt,
            errorCode: error.code,
            active: this.active,
            queued: this.queue.length,
          });
          reject(error);
        }, this.timeoutMs);

        const onAbort = () => {
          if (!finish()) return;
          const error = cancelled(options.signal?.reason);
          this.emit({
            name: "signing.failed",
            requestId: options.requestId,
            capability: payload.kind,
            durationMs: Date.now() - startedAt,
            errorCode: error.code,
            active: this.active,
            queued: this.queue.length,
          });
          reject(error);
        };
        options.signal?.addEventListener("abort", onAbort, { once: true });

        this.signer
          .sign(payload, options)
          .then((result) => {
            if (!finish()) return;
            try {
              validateResult(result);
            } catch (error) {
              const signingError =
                error instanceof SigningError
                  ? error
                  : new SigningError("INVALID_RESULT", "Signer returned an invalid result", false);
              this.emit({
                name: "signing.failed",
                requestId: options.requestId,
                capability: payload.kind,
                durationMs: Date.now() - startedAt,
                errorCode: signingError.code,
                active: this.active,
                queued: this.queue.length,
              });
              reject(signingError);
              return;
            }
            this.emit({
              name: "signing.succeeded",
              requestId: options.requestId,
              capability: payload.kind,
              durationMs: Date.now() - startedAt,
              active: this.active,
              queued: this.queue.length,
            });
            resolve(result);
          })
          .catch((cause) => {
            if (!finish()) return;
            const error =
              cause instanceof SigningError
                ? cause
                : new SigningError("SIGNING_FAILED", "Signer failed to sign the payload", true, {
                    cause,
                  });
            this.emit({
              name: "signing.failed",
              requestId: options.requestId,
              capability: payload.kind,
              durationMs: Date.now() - startedAt,
              errorCode: error.code,
              active: this.active,
              queued: this.queue.length,
            });
            reject(error);
          });
      };

      if (this.active < this.maxConcurrent) {
        run();
        return;
      }
      if (this.queue.length >= this.maxQueue) {
        const error = new SigningError("SATURATED", "Signing queue is saturated", true);
        this.emit({
          name: "signing.saturated",
          requestId: options.requestId,
          capability: payload.kind,
          errorCode: error.code,
          active: this.active,
          queued: this.queue.length,
        });
        reject(error);
        return;
      }
      this.queue.push({ run, reject, signal: options.signal });
    });
  }
}

function validateResult(result: SignatureResult): void {
  if (!result || typeof result !== "object") {
    throw new SigningError("INVALID_RESULT", "Signer returned an invalid result", false);
  }
  if (typeof result.keyId !== "string" || !result.keyId) {
    throw new SigningError("INVALID_RESULT", "Signer returned an empty key ID", false);
  }
  if (typeof result.algorithm !== "string" || !result.algorithm) {
    throw new SigningError("INVALID_RESULT", "Signer returned an empty algorithm", false);
  }
  if (!(result.signature instanceof Uint8Array) || result.signature.length === 0) {
    throw new SigningError("INVALID_RESULT", "Signer returned an empty signature", false);
  }
}

export interface StellarKeypairSignerOptions {
  keyId?: string;
  algorithm?: string;
  capabilities?: readonly SigningCapability[];
}

/**
 * Server-side signer backed by a Stellar secret keypair. Not suitable for
 * browser environments because it requires the secret seed.
 */
export class StellarKeypairSigner implements RequestSigner {
  private readonly keypair: Keypair;
  private readonly keyId: string;
  private readonly algorithm: string;
  private readonly supported: readonly SigningCapability[];

  constructor(secret: string, options: StellarKeypairSignerOptions = {}) {
    if (typeof secret !== "string" || !secret) {
      throw new SigningError("INVALID_INPUT", "A stellar secret seed is required", false);
    }
    this.keypair = Keypair.fromSecret(secret);
    this.keyId = options.keyId ?? this.keypair.publicKey();
    this.algorithm = options.algorithm ?? "ed25519";
    this.supported = options.capabilities ?? [
      "http-request-v1",
      "stellar-transaction-v1",
      "talos-payment-v1",
    ];
  }

 getCapabilities(): SignerCapabilities {
    return { capabilities: this.supported, algorithms: [this.algorithm] };
  }

  async sign(payload: SigningPayload, options: SignOptions = {}): Promise<SignatureResult> {
    if (options.signal?.aborted) throw cancelled(options.signal.reason);
    if (!this.supported.includes(payload.kind)) {
      throw new SigningError("UNSUPPORTED", `Signer does not support ${payload.kind}`, false);
    }
    if (!(payload.bytes instanceof Uint8Array) || payload.bytes.length === 0) {
      throw new SigningError("INVALID_INPUT", "Signing payload bytes are required", false);
    }
    let signature: Uint8Array;
    try {
      signature = this.keypair.sign(Buffer.from(payload.bytes));
    } catch (cause) {
      throw new SigningError("SIGNING_FAILED", "Failed to sign payload", true, { cause });
    }
    return {
      algorithm: this.algorithm,
      keyId: this.keyId,
      signature: new Uint8Array(signature),
    };
  }
}

export interface WalletSignMessageResult {
  signature: Uint8Array | ArrayBuffer | string;
  publicKey?: string;
  algorithm?: string;
}

export type WalletSignMessage = (
  bytes: Uint8Array,
  options?: SignOptions,
) => Promise<Uint8Array | ArrayBuffer | string | WalletSignMessageResult>;

export interface WalletMessageSignerOptions {
  /** Public key / address identifying the wallet account. */
  keyId?: string;
  /**
   * Injected wallet signing function. Receives the raw payload bytes and
   * resolves to the signature bytes (a base64/base64url string, or a
   * `{ signature, publicKey }` object). No wallet SDK is bundled; callers
   * wire this to Freighter, Albedo, etc.
   */
  signMessage: WalletSignMessage;
  capabilities?: readonly SigningCapability[];
  algorithm?: string;
  maxConcurrent?: number;
}

function decodeSignature(value: Uint8Array | ArrayBuffer | string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    try {
      const binary =
        typeof atob === "function"
          ? atob(padded)
          : Buffer.from(padded, "base64").toString("binary");
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      return bytes;
    } catch (cause) {
      throw new SigningError("INVALID_RESULT", "Wallet returned a malformed signature", false, {
        cause,
      });
    }
  }
  throw new SigningError("INVALID_RESULT", "Wallet returned a malformed signature", false);
}

function isUserRejection(cause: unknown): boolean {
  if (!cause || typeof cause !== "object") return false;
  const record = cause as Record<string, unknown>;
  const code = typeof record.code === "string" ? record.code.toLowerCase() : "";
  const message = typeof record.message === "string" ? record.message.toLowerCase() : "";
  return (
    code === "user_rejected" ||
    code === "userrejected" ||
    code === "rejected" ||
    message.includes("reject") ||
    message.includes("denied") ||
    message.includes("declined")
  );
}

/**
 * Browser signer that delegates to an injected wallet `signMessage` function.
 * Suitable for Freighter-compatible wallets without bundling any wallet SDK.
 */
export class WalletMessageSigner implements RequestSigner {
  private readonly keyId?: string;
  private readonly signMessage: WalletSignMessage;
  private readonly supported: readonly SigningCapability[];
  private readonly algorithm: string;
  private readonly maxConcurrent: number;

  constructor(options: WalletMessageSignerOptions) {
    if (!options || typeof options !== "object") {
      throw new SigningError("INVALID_INPUT", "Wallet signer options are required", false);
    }
    if (options.keyId !== undefined && (typeof options.keyId !== "string" || !options.keyId)) {
      throw new SigningError("INVALID_INPUT", "A wallet keyId must be a non-empty string", false);
    }
    if (typeof options.signMessage !== "function") {
      throw new SigningError("INVALID_INPUT", "A signMessage function is required", false);
    }
    this.keyId = options.keyId;
    this.signMessage = options.signMessage;
    this.supported = options.capabilities ?? ["http-request-v1", "stellar-transaction-v1"];
    this.algorithm = options.algorithm ?? "ed25519";
    this.maxConcurrent = options.maxConcurrent ?? 1;
  }

  getCapabilities(): SignerCapabilities {
    return {
      capabilities: this.supported,
      algorithms: [this.algorithm],
      maxConcurrent: this.maxConcurrent,
    };
  }

  async sign(payload: SigningPayload, options: SignOptions = {}): Promise<SignatureResult> {
    if (options.signal?.aborted) throw cancelled(options.signal.reason);
    if (!payload || typeof payload !== "object") {
      throw new SigningError("INVALID_INPUT", "A signing payload is required", false);
    }
    if (!this.supported.includes(payload.kind)) {
      throw new SigningError("UNSUPPORTED", `Signer does not support ${payload.kind}`, false);
    }
    if (!(payload.bytes instanceof Uint8Array) || payload.bytes.length === 0) {
      throw new SigningError("INVALID_INPUT", "Signing payload bytes are required", false);
    }
    let raw: Uint8Array | ArrayBuffer | string | WalletSignMessageResult;
    try {
      raw = await this.signMessage(payload.bytes, options);
    } catch (cause) {
      if (isUserRejection(cause)) {
        throw new SigningError("USER_REJECTED", "The user rejected the signing request", false, {
          cause,
        });
      }
      throw new SigningError("SIGNING_FAILED", "Wallet failed to sign the payload", true, {
        cause,
      });
    }

    let signatureValue: Uint8Array | ArrayBuffer | string;
    let publicKey: string | undefined;
    let algorithm: string | undefined;
    if (raw && typeof raw === "object" && !(raw instanceof Uint8Array) && !(raw instanceof ArrayBuffer)) {
      const result = raw as WalletSignMessageResult;
      signatureValue = result.signature;
      publicKey = result.publicKey;
      algorithm = result.algorithm;
    } else {
      signatureValue = raw as Uint8Array | ArrayBuffer | string;
    }

    if (signatureValue === undefined || signatureValue === null) {
      throw new SigningError("INVALID_RESULT", "Wallet returned a malformed signature", false);
    }
    const signature = decodeSignature(signatureValue);
    if (signature.length === 0) {
      throw new SigningError("INVALID_RESULT", "Wallet returned an empty signature", false);
    }
    const keyId = publicKey ?? this.keyId;
    if (!keyId) {
      throw new SigningError(
        "INVALID_RESULT",
        "Wallet did not return a public key and no keyId was configured",
        false,
      );
    }
    return {
      algorithm: algorithm ?? this.algorithm,
      keyId,
      signature,
    };
  }
}