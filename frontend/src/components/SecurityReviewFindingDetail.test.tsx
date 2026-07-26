import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { SecurityReviewFinding } from "../types/api";
import { SecurityReviewFindingDetail } from "./SecurityReviewFindingDetail";

function makeFinding(
  overrides: Partial<SecurityReviewFinding> = {},
): SecurityReviewFinding {
  const finding: SecurityReviewFinding = {
    id: "finding-1",
    source_object_type: "application_review_finding",
    source_object_id: "surface:vendor-diagnostics",
    threat_id: null,
    display_id: null,
    wire_kind: "control_gap",
    display_kind: "control_gap",
    source_provenance: "app_review_projection",
    source_system: "threatgenix",
    title: "Code evidence found unprotected sensitive routes",
    priority: "p1_now",
    numeric_score: 88,
    wire_action_bucket: "engineer_now",
    queue_bucket: "fix_now",
    computed_queue_bucket: "fix_now",
    truth_status: "strongly_indicated",
    exploitability: "medium",
    urgency: "current_cycle",
    business_impact: "high",
    regulatory_pressure: "red_line",
    confidence: "high",
    is_real: true,
    is_urgent: true,
    is_exploitable_in_context: false,
    is_regulatory_or_control_relevant: true,
    needs_engineering_change: true,
    needs_evidence: false,
    why_now: "The route processes sensitive payment callback state without a clear guard.",
    impacted_assets: ["API Gateway"],
    entry_point: "API Gateway",
    evidence_refs: ["repository"],
    linked_threat_ids: [],
    linked_change_ids: [],
    linked_control_ids: [],
    owner: null,
    due_at: null,
    note: null,
    artifacts: [],
    review_status: "open",
    last_non_terminal_bucket: null,
    primary_mode: "compliance",
    noise_disposition: "focus",
    computed_recommendation_changed: false,
    systemic: true,
    next_best_action: "Create an engineering task with the affected route and missing control.",
    next_step: "Create an engineering task.",
    rationale_excerpt: "Externally reachable sensitive route.",
    code_links: [],
  };
  return Object.assign(finding, overrides);
}

describe("SecurityReviewFindingDetail", () => {
  it("renders duplicate surface code evidence without React key warnings", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <SecurityReviewFindingDetail
        finding={makeFinding({
          code_links: [
            {
              finding_key: "finding-1",
              surface_id: "surface-post-vendor-diagnostics-session",
              relationship: "confirms_missing_control",
              source_file: "api_gateway_vendor_callbacks.js",
              line_number: 4,
              surface_name: "POST /vendor/diagnostics/session",
              summary: "No auth guard is detected.",
              control_signal_ids: [],
              risk_signal_ids: [],
            },
            {
              finding_key: "finding-1",
              surface_id: "surface-post-vendor-diagnostics-session",
              relationship: "confirms_missing_control",
              source_file: "api_gateway_vendor_callbacks.js",
              line_number: 5,
              surface_name: "POST /callbacks/vendor/payment-status",
              summary: "Sensitive callback state is accepted without a guard.",
              control_signal_ids: [],
              risk_signal_ids: [],
            },
          ],
        })}
      />,
    );

    expect(screen.getByText("POST /vendor/diagnostics/session")).toBeInTheDocument();
    expect(screen.getByText("POST /callbacks/vendor/payment-status")).toBeInTheDocument();
    expect(consoleError).not.toHaveBeenCalledWith(
      expect.stringContaining("Encountered two children with the same key"),
      expect.anything(),
      expect.anything(),
    );

    consoleError.mockRestore();
  });
});
