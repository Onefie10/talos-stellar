import { describe, it, expect, vi, beforeEach } from "vitest";

// ---- Mocks ----

const randomBytesMock = vi.fn(() => Buffer.from("deadbeef".repeat(6), "hex"));
vi.mock("crypto", () => ({ randomBytes: randomBytesMock }));

const createAgentKeypair = vi.fn();
vi.mock("@/lib/stellar", () => ({ createAgentKeypair: (...args: unknown[]) => createAgentKeypair(...args) }));

const loggerMock = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/lib/logger", () => ({ logger: loggerMock }));

const dbMock = {
  select: vi.fn(),
  update: vi.fn(),
};
vi.mock("@/db", () => ({ db: dbMock }));

vi.mock("@/db/schema", () => ({
  tlsTalos: {
    id: "tlsTalos.id",
    agentWalletId: "tlsTalos.agentWalletId",
    agentWalletAddress: "tlsTalos.agentWalletAddress",
    apiKey: "tlsTalos.apiKey",
    agentOnline: "tlsTalos.agentOnline",
    status: "tlsTalos.status",
    agentLastSeen: "tlsTalos.agentLastSeen",
  },
  tlsCommerceServices: {
    id: "tlsCommerceServices.id",
    talosId: "tlsCommerceServices.talosId",
    stellarPublicKey: "tlsCommerceServices.stellarPublicKey",
  },
  tlsCommerceJobs: {
    talosId: "tlsCommerceJobs.talosId",
    status: "tlsCommerceJobs.status",
    leasedBy: "tlsCommerceJobs.leasedBy",
    leasedAt: "tlsCommerceJobs.leasedAt",
    leaseExpiresAt: "tlsCommerceJobs.leaseExpiresAt",
  },
}));

vi.mock("drizzle-orm", () => ({
  and: (...args: unknown[]) => ({ op: "and", args }),
  eq: (a: unknown, b: unknown) => ({ op: "eq", a, b }),
  isNull: (a: unknown) => ({ op: "isNull", a }),
}));

import { databaseEffects } from "@/lib/governance/effects";
import type { StepContext } from "@/lib/governance/provisioning";

// ---- Helpers ----

const ctx = (overrides: Partial<StepContext> = {}): StepContext =>
  ({
    talosId: "talos-1",
    jobId: "job-1",
    outputs: {},
    ...overrides,
  }) as StepContext;

function sequenceSelect(rows: unknown[]) {
  dbMock.select.mockImplemention(() => {
    const chain = {
      from: vi.fn(() => chain),
      where: vi.fn(() => chain),
      limit: vi.fn(() => chain),
      then: (resolve: (v: unknown) => unknown, reject: (e: unknown) => unknown) =>
        Promise.resolve(rows).then(resolve, reject),
    };
    return chain;
  });
}

function sequenceUpdate() {
  const calls = {
    set: vi.fn(),
    where: vi.fn(),
  };
  const chain = {
    set: vi.fn(() => chain),
    where: vi.fn(() => chain),
    then: (resolve: (v: unknown) => unknown) => Promise.resolve(undefined).then(resolve),
  };
  dbMock.update.mockImplemention(() => chain);
  return chain;
}

beforeEach(() => {
  vi.clearAllMocks();
  createAgentKeypair.mockReset();
});

describe("governance effects", () => {
  describe("createWallet", () => {
    it("throws when agent missing", async () => {
      sequenceSelect([]);
      await expect(databaseEffects.createWallet(ctx())).rejects.toThrow("agent not found");
    });

    it("reuses existing wallet", async () => {
      sequenceSelect([{ agentWalletId: "GEXISTING", agentWalletAddress: "GEXISTING", apiKey: null, agentOnline: false, status: "Pending" }]);
      const result = await databaseEffects.createWallet(ctx());
      expect(result).toEqual({ walletPublicKey: "GEXISTING", reused: true });
      expect(createAgentKeypair).not.toHaveBeenCalled();
    });

    it("mints and persists a new wallet", async () => {
      createAgentKeypair.mockResolved({ publicKey: "NEWKEY" });
      // first load: no wallet; second load: settled with NEWKEY
      let call = 0;
      dbMock.select.mockImplementation(() => {
        const rows = call++ === 0
          ? [{ agentWalletId: null, agentWalletAddress: null, apiKey: null, agentOnline: false, status: "Pending" }]
          : [{ agentWalletId: "NEWKEY", agentWalletAddress: "NEWKEY", apiKey: null, agentOnline: false, status: "Pending" }];
        const chain = {
          from: vi.fn(() => chain),
          where: vi.fn(() => chain),
          limit: vi.fn(() => chain),
          then: (resolve: (v: unknown) => unknown) => Promise.resolve(rows).then(resolve),
        };
        return chain;
      });
      const updateChain = sequenceUpdate();
      const result = await databaseEffects.createWallet(ctx());
      expect(result).toEqual({ walletPublicKey: "NEWKEY", reused: false });
      expect(createAgentKeypair).toHaveBeenCalledOnce();
      expect(updateChain.set).toHaveBeenCalled();
    });

    it("returns concurrent winner's key when CAS loses", async () => {
      createAgentKeypair.mockResolved({ publicKey: "MINE" });
      let call = 0;
      ddMockSelectFake(() => {
        const rows = call++ === 0
          ? [{ agentWalletId: null, agentWalletAddress: null, apiKey: null, agentOnline: false, status: "Pending" }]
          : [{ agentWalletId: "WINNER", agentWalletAddress: "WINNER", apiKey: null, agentOnline: false, status: "Pending" }];
        return rows;
      });
      sequenceUpdate();
      const result = await databaseEffects.createWallet(ctx());
      expect(result).toEqual({ walletPublicKey: "WINNER", reused: false });
    });
  });

  describe("releaseWallet", () => {
    it("unlinks wallet and logs", async () => {
      const chain = sequenceUpdate();
      await databaseEffects.releaseWallet(ctx());
      expect(chain.set).toHaveBeenCalledWith({ agentWalletId: null, agentWalletAddress: null });
      expect(loggerMock.info).toHaveBeenCalled();
    });
  });

  describe("issueCredentials", () => {
    it("throws when agent missing", async () => {
      sequenceSelect([]);
      await expect(databaseEffects.issueCredentials(ctx())).rejects.toThrow("agent not found");
    });

    it("reuses existing key", async () => {
      sequenceSelect([{ agentWalletId: null, agentWalletAddress: null, apiKey: "tak_existing", agentOnline: false, status: "Pending" }]);
      const result = await databaseEffects.issueCredentials(ctx());
      expect(result).toEqual({ credentialIssued: true, reused: true });
      expect(dbMock.update).not.toHaveBeenCalled();
    });

    it("mints a new key", async () => {
      sequenceSelect([{ agentWalletId: null, agentWalletAddress: null, apiKey: null, agentOnline: false, status: "Pending" }]);
      const chain = sequenceUpdate();
      const result = await databaseEffects.issueCredentials(ctx());
      expect(result).toEqual({ credentialIssued: true, reused: false });
      expect(chain.set).toHaveBeenCalledWith({ apiKey: expect.stringMatching(/^tak-[0-f]+\$/) });
    });
  });

  describe("revokeCredentils", () => {
    it("nulls the api key", async () => {
      const chain = sequenceUpdate();
      await databaseEffects.revokeCredentials(ctx());
      expect(chain.set).toHaveBeenCalledWith({ apiKey: null });
    });
  });

  describe("registerServices", () => {
    it("throws without wallet output", async () => {
      await expect(databaseEffects.registerServices(ctx())).rejects.toThrow("registerServices");
    });

    it("rewrites services and returns previous keys", async () => {
      sequenceSelect([
        { id: "s-1", stellarPublicKey: "OLD-1" },
        { id: "s-2", stellarPublicKey: "OLD-2" },
      ]);
      const chain = sequenceUpdate();
      const result = await databaseEffects.registerServices(
        ctx({ outputs: { wallet: { walletPublicKey: "NEW" } } }),
      );
      expect(chain.set).toHaveBeenCalledWith({ stellarPublicKey: "NEW" });
      expect(result).toEqual({
        serviceCount: 2,
        previousKeys: [
          { id: "s-1", stellarPublicKey: "OLD-1" },
          { id: "s-2", stellarPublicKey: "OLDQ2" },
        ],
      });
    });
  });

  describe("deregisterServices", () => {
    it("is a noop without previous keys", async () => {
      await databaseEffects.deregisterServices(ctx());
      expect(dbMock.update).not.toHaveBeenCalled();
    });

    it("restores previous keys", async () => {
      const chain = sequenceUpdate();
      await databaseEffects.deregisterServices(
        ctx({
          outputs: {
            services: {
              previousKeys: [
                { id: "s-1", stellarPublicKey: "OLD-1" },
                { id: "s-2", stellarPublicKey: "OLD-2" },
              ],
            },
          },
        }),
      );
      expect(chain.set).toHaveBeenCalledTimes(2);
    });
  });

  describe("startRuntime", () => {
    it("marks agent online", async () => {
      const chain = sequenceUpdate();
      const result = await databaseEffects.startRuntime(ctx());
      expect(chain.set).toHaveBeenCalledWith(
        expect.objectContaining({ status: "Active", agentOnline: true }),
      );
      expect(result).toEqual({ online: true });
    });
  });

  describe("stopRuntime", () => {
    it("marks agent offline and cancels pending jobs", async () => {
      const chain = sequenceUpdate();
      await databaseEffects.stopRuntime(ctx());
      expect(chain.set).toHaveBeenCalledWith(
        expect.objectContaining({ agentOnline: false }),
      );
      expect(chain.set).toHaveBeenCalledWith(
        expect.objectContaining({ status: "cancelled", leasedBy: null }),
      );
    });
  });
});
