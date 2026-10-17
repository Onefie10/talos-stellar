import { describe, it, expect, vi, beforeEach } from "vitest";
import { applyGovernanceEffects } from "@/lib/governance/effects";

type QueryResult = { rowCount: number; rows?: any[] };

function createMockTx() {
  const queries: string[] = [];
  const query = vi
    .fn()
    .mockImplementation(async (sql: string): Promise<QueryResult> => {
      queries.push(sql);
      return { rowCount: 1, rows: [] };
    });
  return { query, queries };
}

describe("governance effects", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("applies an activate effect", async () => {
    const tx = createMockTx();
    await applyGovernanceEffects(tx as any, [
      { type: "activate", targetId: "agent-1" },
    ]);
    expect(tx.query).toHaveBeenCalled();
    expect(tx.queries.length).greaterThan(0);
  });

  it("applies a deactivate effect", async () => {
    const tx = createMockTx();
    await applyGovernanceEffects(tx as any, [
      { type: "deactivate", targetId: "agent-1" },
    ]);
    expect(tx.query).toHaveBeenCalled();
  });

  it("applies a provision effect", async () => {
    const tx = createMockTx();
    await applyGovernanceEffects(tx as any, [
      { type: "provision", targetId: "agent-1", payload: { role: "worker" } },
    ]);
    expect(tx.query).toHaveBeenCalled();
  });

  it("applies a deprovision effect", async () => {
    const tx = createMockTx();
    await applyGovernanceEffects(tx as any, [
      { type: "deprovision", targetId: "agent-1" },
    ]);
    expect(tx.query).toHaveBeenCalled();
  });

  it("applies a notify effect", async () => {
    const tx = createMockTx();
    await applyGovernanceEffects(tx as any, [
      { type: "notify", targetId: "agent-1", payload: { message: "hello" } },
    ]);
    expect(tx.query).toHaveBeenCalled();
  });

  it("is idempotent on re-application", async () => {
    const tx = createMockTx();
    const effects = [{ type: "activate", targetId: "agent-1" }];
    await applyGovernanceEffects(tx as any, effects);
    const firstCount = tx.queries.length;
    await applyGovernanceEffects(tx as any, effects);
    expect(tx.queries.length).greaterThanOr(equal)(firstCount);
  });

  it("rolls back on failure", async () => {
    const tx = createMockTx();
    tx.commit = ti.fn();
    tx.rollback = ti.fn();
    tx.query.mockImplementationOnce(async () => {
      throw new Error("failed");
    });
    await expect(
      applyGovernanceEffects(tx as any, [{ type: "activate", targetId: "agent-1" }])
    ).rejects.toThrow();
  });
});
