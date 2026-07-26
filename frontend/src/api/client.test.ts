import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./client";

describe("api.getThreatIntel", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("normalizes degraded threat-intel payloads from older or unavailable backends", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        local_severity: "Critical",
        unavailable_reason: "pgvector type unavailable",
        semantic_matches_inferred: false,
        scan_cve_ids: [],
        severity_signals: [],
        attack_techniques: [],
        attack_patterns: [],
        weaknesses: [],
        advisories: [],
        kev_entries: [],
        cri_controls: [],
      }),
    });

    vi.stubGlobal("fetch", fetchMock);

    const intel = await api.getThreatIntel("tm-1", "th-1");

    expect(fetchMock).toHaveBeenCalledWith("/api/threat-models/tm-1/threats/th-1/intel", {
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer test-token",
      },
    });
    expect(intel.epss_entries).toEqual([]);
    expect(intel.dependency_matches).toEqual([]);
    expect(intel.contextual_assessment).toEqual({
      threat_classes: [],
      confidence: "Low",
      ssvc_decision: "Track",
      why_applicable: [],
      what_to_verify: [],
      decision_rationale: [],
    });
  });
});

describe("api.importRepositoryEvidenceFromGitHub", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps the auth header when no one-time GitHub token is provided", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        repository_evidence: null,
        cloud_scan_evidence: null,
        iac_evidence: null,
        environment_context_summary: null,
      }),
    });

    vi.stubGlobal("fetch", fetchMock);

    await api.importRepositoryEvidenceFromGitHub("tm-1", {
      repository: "octocat/Hello-World",
      transport: "https",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/threat-models/tm-1/environment/repository/github",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test-token",
        },
        body: JSON.stringify({
          repository: "octocat/Hello-World",
          transport: "https",
        }),
      }
    );
  });
});

describe("SaaS entitlement errors", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("turns plan-gated API failures into upgrade-oriented copy", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      text: async () => JSON.stringify({ detail: "Your plan does not include this feature" }),
    }));

    await expect(api.generateReport("tm-1")).rejects.toThrow(
      "Upgrade required: Your plan does not include this feature."
    );
  });
});

describe("API validation errors", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("surfaces Pydantic validation messages without raw JSON", async () => {
    vi.stubGlobal("localStorage", {
      getItem: vi.fn((key: string) => (key === "tg_token" ? "test-token" : null)),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    });

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      text: async () => JSON.stringify({
        detail: [
          {
            type: "string_too_long",
            loc: ["body", "description"],
            msg: "String should have at most 500 characters",
          },
        ],
      }),
    }));

    await expect(api.createThreatModel({
      system_name: "Large design",
      description: "x".repeat(600),
      data_classification: "Restricted",
    })).rejects.toThrow("422: String should have at most 500 characters");
  });
});
