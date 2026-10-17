/**
 * Unit coverage for the governance effects applied when proposals resolve.
 *
 * The effects in `src/lib/governance/effects.ts` are written to converge and to
 * compensate safely, so these tests exercise every effect branch, idempotent
 * re-application, and failure rollback against a mocked transaction.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { mockDb, mockLoadAgent, mockCreateAgentKeypair, mockLogger } = vi.hoisted(() => {
  const mockDb = {
    select: vi.fn(),
    update: vi.fn(),
  };
  const mockLoadAgent = vi.fn();
  const mockCreateAgentKeypair = vi.fn();
  const mockLogger = { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() };
  return { mockDb, mockLoadAgent, mockCreateAgentKeypair, mockLogger };
});

vi.mock("@/db", () => ({ db: mockDb }));
vi.mock("@/lib/logger", () => ({ logger: mockLogger }));
vi.mock("@/lib/stellar", () => ({ createAgentKeypair: mockCreateAgentKeypair }));

// Schema table markers are only used as arguments to the mocked driver, so they
// can be stable objects.
vi.mock("@/db/schema", () => ({
  tlsTalos: { id: "tlt_talos.id", agentWalletId: "tlt_talos.agent_wallet_id" },
  tlsCommerceServices: {
    id: "tls_commerce_services.id",
    talosId: "tls_commerce_services.talos_id",
    stellarPublicKey: "tls_commerce_services.stellar_public_key",
  },
  tlsCommerceJobs: {
    talosId: "tls_commerce_jobs.talos_id",
    status: "tls_commerce_jobs.status",
  },
}));

// Drizzle condition builders are only passed through to the mocked driver.
vi.mock("drizzle-orm", () => ({
  and: (...args: unknown[]) => ({ op: "and", args }),
  eq: (col: unknown, value: unknown) => ({ op: "eq", col, value }),
  isNull: (col: unknown) => ({ op: "isNull", col }),
}));

type UpdateCall = { table: unknown; set: Record<unknown, unknown>; where: unknown };

function makeSelectChain() {
  const chain: Record<string, unknown> = {};
  chain.from = vi.fn(() => chain);
  chain.where = vi.fn(() => chain);
  chain.limit = vi.fn(() => chain);
  chain.then = (cb: (value: unknown[]) => unknown, _rej?: unknown) =>
    Promise.resolve(chain._rows as unknown[]).then(cb);
  return chain;
}

function makeUpdateChain(calls: UpdateCall[], table: unknown, set: Record<unknown, unknown>) {
  const chain: Record<string, unknown> = {};
  chain.where = vi.fn((where: unknown) => {
    calls.push({ table, set, where });
    return Promise.resolve(undefined);
  });
  return chain;
}

let updateCalls: UpdateCall[];
let selectQueue: unknown[][];

function queueSelect(rows: unknown[]) {
  selectQueue.push(rows);
}

beforeEach(() => {
  vi.clearAllMocks();
  updateCalls = [];
  selectQueue = [];
  mockDb.select.mockImplementation(() => {
    const chain = makeSelectChain();
    const rows = selectQueue.shift() ?? [];
    (chain as { _rows: unknown[] })._rows = rows;
    return chain;
  });
  mockDb.update.mockImplementation((table: unknown, set: Record<unknown, unknown>) =>
    makeUpdateChain(updateCalls, table, set),
  );
});

async function loadEffects() {
  // Import after mocks are installed.
  const mod = await import("@/lib/governance/effects");
  return mod.databaseEffects;
}

const context = {
  talosId: "talos-1",
  jobId: "job-1",
  outputs: {},
} as unknown as import("@/lib/governance/provisioning").StepContext;

describe("governance effects: createWallet", () => {
  it("throws when the agent is missing", async () => {
    const effects = await loadEffects();
    queueSelect([]);
    await expect(effects.createWallet(context)).rejects.toThrow("agent not found");
  });

  it("reuses an already allocated wallet without mutating", async () => {
    const effects = await loadEffects();
    queueSelect([{ agentWalletId: "GEXISTING", agentWalletAddress: "GEXISTING" }]);
    const result = await effects.createWallet(context);
    expect(result).toEqual({ walletPublicKey: "GEXISTING", reused: true });
    expect(updateCalls).length(0);
    expect(mockCreateAgentKeypair).not.toHaveBeenCalled();
  });

  it("mints and persists a new wallet when none exists", async () => {
    const effects = await loadEffects();
    mockCreateAgentKeypair.mockResolved({ publicKey: "NEWKEY" });
    // Load, re-read after CAS.
    queueSelect([{ agentWalletId: null }]);
    queueSelect([{ agentWalletId: "NEWKEY" }]);
    const result = await effects.createWallet(context);
    expect(result).toEqual({ walletPublicKey: "NEWKEY", reused: false });
    expect(mockCreateAgentKeypair).toHaveBeenCalledOnce();
    expect(updateCalls).length(1);
    expect(updateCalls[0].set).toMatchObject({ agentWalletId: "NEWKEY" });
  });

  it("returns the key of record when a concurrent attempt won the CAS", async () => {
    const effects = await loadEffects();
    mockCreateAgentKeypair.mockResolved({ publicKey: "LOSINGKEY" });
    queueSelect([{ agentWalletId: null }]);
    queueSelect([{ agentWalletId: "WINNERKEY" }]);
    const result = await effects.createWallet(context);
    expect(result).toEqual({ walletPublicKey: "WINNERKEY", reused: false });
  });

});

describe("governance effects: releaseWallet", () => {
  it("unlinks the wallet and logs for reconciliation", async () => {
    const effects = await loadEffects();
    await effects.releaseWallet(context);
    expect(updateCalls).length(1);
    expect(updateCalls[0].set).toMatchObject({ agentWalletId: null, agentWalletAddress: null });
    expect(mockLogger.info).toHaveBeenCalled();
  });

  it("is idempotent on re-application", async () => {
    const effects = await loadEffects();
    await effects.releaseWallet(context);
    await effects.releaseWallet(context);
    expect(updateCalls).length(2);
    for (const call of updateCalls) {
      expect(call.set).toMatchObject({ agentWalletId: null, agentWalletAddress: null });
    }
  });
});

describe("governance effects: issueCredentials", () => {
  it("throws when the agent is missing", async () => {
    const effects = await loadEffects();
    queueSelect([]);
    await expect(effects.issueCredentials(context)).rejects.toThrow("agent not found");
  });

  it("reuses an existing API key", async () => {
    const effects = await loadEffects();
    queueSelect([{ apiKey: "tak_existing" }]);
    const result = await effects.issueCredentials(context);
    expect(result).toEqual({ credentialIssued: true, reused: true });
    expect(updateCalls).length(0);
  });

  it("issues a new key when none exists", async () => {
    const effects = await loadEffects();
    queueSelect([{ apiKey: null }]);
    const result = await effects.issueCredentials(context);
    expect(result).toEqual({ credentialIssued: true, reused: false });
    expect(updateCalls).length(1);
    const apiKey = updateCalls[0].set.apiKey as string;
    expect(apiKey).toMatch(/^tak_[0-9a-f]{48}$/);
  });
});

describe("governance effects: revokeCredentials", () => {
  it("clears the API key", async () => {
    const effects = await loadEffects();
    await effects.revokeCredentials(context);
    expect(updateCalls).length(1);
    expect(updateCalls[0].set).toMatchObject({ apiKey: null });
  });

  it("is idempotent on re-application", async () => {
    const effects = await loadEffects();
    await effects.revokeCredentials(context);
    await effects.revokeCredentials(context);
    expect(updateCalls).length(2);
    for (const call of updateCalls) {
      expect(call.set).toMatchObject({ apiKey: null });
    }
  });
});

describe("governance effects: registerServices", () => {
  it("throws when the wallet output is missing", async () => {
    const effects = await loadEffects();
    await expect(effects.registerServices(context)).rejects.toThrow("wallet step produced no public key");
  });

  it("rewrites service keys and captures previous routing", async () => {
    const effects = await loadEffects();
    queueSelect([
      { id: "svc-1", stellarPublicKey: "OLD1-1" },
      { id: "svc-2", stellarPublicKey: "OLD-2" },
    ]);
    const result = await effects.registerServices({
      ...context,
      outputs: { wallet: { walletPublicKey: "NEWKEY" } },
    });
    expect(result).toEqual({
      serviceCount: 2,
      previousKeys: [
        { id: "svc-1", stellarPublicKey: "OLD-1" },
        { id: "svc-2", stellarPublicKey: "OLD-2" },
      ],
    });
    expect(updateCalls).length(1);
    expect(updateCalls[0].set).toMatchObject({ stellarPublicKey: "NEWKEY" });
  });

  it("is idempotent on re-application", async () => {
    const effects = await loadEffects();
    const ctx = {
      ...context,
      outputs: { wallet: { walletPublicKey: "NEWKEY" } },
    };
    queueSelect([]);
    await effects.registerServices(ctx);
    queueSelect([]);
    await effects.registerServices(ctx);
    expect(updateCalls).length(2);
    for (const call of updateCalls) {
      expect(call.set).toMatchObject({ stellarPublicKey: "NEWKEY" });
    }
  });
});

describe("governance effects: deregisterServices", () => {
  it("restores previous routing keys", async () => {
    const effects = await loadEffects();
    await effects.deregisterServices({
      ...context,
      outputs: {
        services: {
          previousKeys: [
            { id: "svc-1", stellarPublicKey: "OLD-1" },
            { id: "svc-2", stellarPublicKey: "OLD-2" },
          ],
        },
      },
    });
    expect(updateCalls).length(2);
    expect(updateCalls[0].set).toMatchObject({ stellarPublicKey: "OLD-1" });
    expect(updateCalls[1].set).toMatchObject({ stellarPublicKey: "OLD-2" });
  });

  it("is a no-op hen no previous keys were recorded", async () => {
    const effects = await loadEffects();
    await effects.deregisterServices(context);
    expect(updateCalls).length(0);
  });

  it("restores the same keys on re-application", async () => {
    const effects = await loadEffects();
    const ctx = {
      ...context,
      outputs: {
        services: { previousKeys: [{ id: "svc-1", stellarPublicKey: "OLD-1" }] },
      },
    };
    await effects.deregisterServices(ctx);
    await effects.deregisterServices(ctx);
    expect(updateCalls).length(2);
    for (const call of updateCalls) {
      expect(call.set).toMatchObject({ stellarPublicKey: "OLD-1" });
    }
  });
});

describe("governance effects: startRuntime", () => {
  it("brings the agent online", async () => {
    const effects = await loadEffects();
    const result = await effects.startRuntime(context);
    expect(result).toEqual({ online: true });
    expect(updateCalls).length(1);
    expect(updateCalls[0].set).toMatchObject({ status: "Active", agentOnline: true });
  });

  it("is idempotent on re-application", async () => {
    const effects = await loadEffects();
    await effects.startRuntime(context);
    await effects.startRuntime(context);
    expect(updateCalls).length(2);
    for (const call of updateCalls) {
      expect(call.set).toMatchObject({ status: "Active", agentOnline: true });
    }
  });
});

describe("governance effects: stopRuntime", () => {
  it("takes the agent offline and cancels pending jobs", async () => {
    const effects = await loadEffects();
    await effects.stopRuntime(context);
    expect(updateCalls).length(2);
    expect(updateCalls[0].set).toMatchObject({ agentOnline: false });
    expect(updateCalls[1].set).toMatchObject({
      status: "cancelled",
      leasedBy: null,
      leasedAt: null,
      leaseExpiresAt: null,
    });
  });

  it("is idempotent on re-application", async () => {
    const effects = await loadEffects();
    await effects.stopRuntime(context);
    await effects.stopRuntime(context);
    expect(updateCalls).length(4);
    expect(updateCalls[2].set).toMatchObject({ agentOnline: false });
    expect(updateCalls[3].set).toMatchObject({ status: "cancelled" });
  });
});

describe("governance effects: failure rollback", () => {
  it("rolls back a partial credential issue when the update fails", async () => {
    const effects = await loadEffects();
    queueSelect([{ apiKey: null }]);
    // First update (issue) succeeds, second (compensation) fails once.
    let calls = 0;
    mockDb.update.mockImplementation((table: unknown, set: Record<unknown, unknown>) => {
      calls += 1;
      if (calls === 2) throw new Error("tx aborted");
      return makeUpdateChain(updateCalls, table, set);
    });
    await effects.issueCredentials(context);
    await expect(effects.revokeCredentials(context)).rejects.toThrow("tx aborted");
    // Retry after the failure still converges.
    await effects.revokeCredentials(context);
    expect(updateCalls).length(2);
    expect(updateCalls[1].set).toMatchObject({ apiKey: null });
  });

  it("rolls back a partial service registration when a restore fails", async () => {
    const effects = await loadEffects();
    queueSelect([{ id: "svc-1", stellarPublicKey: "OLD-1" }]);
    const ctx = {
      ...context,
      outputs: {
        wallet: { walletPublicKey: "NEWKEY" },
        services: { previousKeys: [{ id: "svc-1", stellarPublicKey: "OLD-1" }] },
      },
    };
    await effects.registerServices(ctx);
    let calls = 0;
    mockDb.update.mockImplementation((table: unknown, set: Record<unknown, unknown>) => {
      calls += 1;
      if (calls === 1) throw new Error("tx aborted");
      return makeUpdateChain(updateCalls, table, set);
    });
    await expect(effects.deregisterServices(ctx)).rejects.toThrow("tx aborted");
    // Retry converges to the same previous key.
    await effects.deregisterServices(ctx);
    expect(updateCalls).length(2);
    expect(updateCalls[1].set).toMatchObject({ stellarPublicKey: "OLD-1" });
  });
});
