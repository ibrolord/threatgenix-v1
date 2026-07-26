import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import { SecurityReviewReportPanel } from "./SecurityReviewReportPanel";
import type {
  SecurityReviewApplicationSummary,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";

vi.mock("../api/client", () => ({
  api: {
    getLatestScanRunbook: vi.fn(),
    getThreatModelAgentReleaseDecision: vi.fn(),
  },
}));

const model: ThreatModelResponse = {
  id: "tm-1",
  system_name: "Payments Platform",
  description: "Handles merchant payments.",
  data_classification: "Restricted",
  regulatory_scope: ["PCI DSS"],
  deployment_model: "cloud",
  repository_evidence: null,
  cloud_scan_evidence: null,
  iac_evidence: null,
  environment_context_summary: null,
  report_templates: [],
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const threat: ThreatResponse = {
  id: "threat-1",
  display_id: "T-001",
  description: "Caller auth missing on public payment API",
  stride_category: "Spoofing",
  threat_subtype: null,
  severity: "High",
  source: "Rules",
  status: "Open",
  dismiss_reason: null,
  rule_id: null,
  ai_enhanced: false,
  provider_managed: false,
  original_rule_threat_id: null,
  affected_node_ids: [],
  affected_edge_ids: [],
  relevance_rationale: null,
  mitigation_plan: null,
  mitigation_owner: null,
  due_date: null,
  mitigation_notes: null,
  control_effectiveness: "none",
  residual_risk_level: "High",
  closed_at: null,
  compliance_controls: [],
  qualification_score: null,
  qualification_label: null,
  qualification_note: null,
  auto_score: null,
  analyst_score: null,
  analyst_score_rationale: null,
  ai_likelihood_score: null,
  ai_likelihood_assessment: null,
  ai_likelihood_generated_at: null,
  cluster_id: null,
  false_positive_reason: null,
  qualification_completed_at: null,
  created_at: "2026-01-01T00:00:00Z",
};

const finding: SecurityReviewFinding = {
  id: "threat:threat-1",
  source_object_type: "threat",
  source_object_id: "threat-1",
  threat_id: "threat-1",
  display_id: "T-001",
  wire_kind: "threat",
  display_kind: "threat",
  source_provenance: "rules_engine",
  source_system: "threatgenix",
  title: "Caller auth missing on public payment API",
  priority: "p0_blocker",
  wire_action_bucket: "bright_red_line",
  queue_bucket: "fix_now",
  computed_queue_bucket: "fix_now",
  truth_status: "validated",
  numeric_score: 98,
  exploitability: "high",
  urgency: "immediate",
  business_impact: "severe",
  regulatory_pressure: "red_line",
  confidence: "high",
  is_real: true,
  is_urgent: true,
  is_exploitable_in_context: true,
  is_regulatory_or_control_relevant: true,
  needs_engineering_change: true,
  needs_evidence: false,
  why_now: "Public entry point reaches cardholder data processing.",
  impacted_assets: ["Payment API"],
  entry_point: "Public API Gateway",
  evidence_refs: ["dfd", "scan", "repository"],
  linked_threat_ids: ["threat-1"],
  linked_change_ids: [],
  linked_control_ids: [],
  code_links: [],
  owner: null,
  due_at: null,
  note: null,
  artifacts: [],
  review_status: "open",
  last_non_terminal_bucket: null,
  primary_mode: "findings",
  noise_disposition: "focus",
  computed_recommendation_changed: false,
  systemic: false,
  next_best_action:
    "Require authenticated caller identity before payment initiation.",
  next_step: "Block unauthenticated payment initiation.",
  rationale_excerpt:
    "Validated public entry point and restricted target asset.",
};

const summary: SecurityReviewApplicationSummary = {
  generated_at: "2026-04-24T12:00:00Z",
  system_name: "Payments Platform",
  overall_priority: "p0_blocker",
  overall_action_bucket: "bright_red_line",
  focus_statement:
    "Public payment initiation can reach restricted payment data without proof of caller identity.",
  rationale: [
    "A public entry point reaches a restricted payment workflow.",
    "The issue has direct PCI relevance and operational blast radius.",
  ],
  next_steps: [
    "Add caller authentication before payment creation.",
    "Attach scan and code evidence after remediation.",
  ],
  coverage: {
    total_findings: 1,
    threat_findings: 1,
    systemic_findings: 0,
    open_threats: 1,
    public_entry_points: 1,
    privileged_surfaces: 1,
    restricted_assets: 1,
    attack_paths: 1,
    attached_evidence_sources: 3,
    missing_evidence_sources: 1,
  },
  priority_counts: [{ key: "p0_blocker", label: "P0 blocker", count: 1 }],
  action_bucket_counts: [
    { key: "bright_red_line", label: "Bright red line", count: 1 },
  ],
  truth_status_counts: [{ key: "validated", label: "Validated", count: 1 }],
  noise_counts: [{ key: "focus", label: "Focus", count: 1 }],
  top_findings: [
    {
      finding_key: "threat:threat-1",
      threat_id: "threat-1",
      display_id: "T-001",
      finding_kind: "threat",
      title: "T-001 · Caller auth missing on public payment API",
      priority: "p0_blocker",
      action_bucket: "bright_red_line",
      truth_status: "validated",
      urgency: "immediate",
      noise_disposition: "focus",
      numeric_score: 98,
      entry_point: "Public API Gateway",
      target_asset: "Payment API",
      rationale_excerpt:
        "Validated public entry point and restricted target asset.",
      next_step: "Block unauthenticated payment initiation.",
      related_attack_path_count: 1,
      evidence_adjustment_count: 0,
      systemic: false,
    },
  ],
  blind_spots: [],
  attack_paths: [
    {
      path_id: "path-1",
      finding_keys: ["threat:threat-1"],
      finding_titles: ["Caller auth missing on public payment API"],
      chain_description:
        "Unauthenticated caller can initiate a payment workflow.",
      entry_point: "Public API Gateway",
      target_asset: "Payment API",
      hop_count: 2,
      support_count: 1,
      composite_exploitability: "high",
      composite_priority: "p0_blocker",
      path_nodes: ["Public API Gateway", "Payment API"],
      evidence_sources: ["dfd", "scan"],
      relationship_reasons: [
        "Public entry point reaches restricted payment workflow.",
      ],
      verification_steps: [
        "Confirm payment initiation rejects unauthenticated callers.",
      ],
    },
  ],
  risk_acceptance_summary: { active: 0, reopened: 0, expired: 0 },
  review_delta_summary: {
    new_findings: 1,
    resolved_findings: 0,
    reopened_findings: 0,
    escalated_findings: 1,
    deescalated_findings: 0,
  },
};

const findingsResponse: SecurityReviewFindingListResponse = {
  generated_at: "2026-04-24T12:00:00Z",
  system_name: "Payments Platform",
  queue_counts: [
    { key: "fix_now", label: "Fix Now", count: 1 },
    { key: "verify", label: "Verify", count: 0 },
    { key: "gather_evidence", label: "Gather Evidence", count: 0 },
    { key: "backlog", label: "Backlog", count: 0 },
  ],
  review_status_counts: [
    { key: "open", label: "Open", count: 1 },
    { key: "in_progress", label: "In Progress", count: 0 },
    { key: "mitigated", label: "Mitigated", count: 0 },
    { key: "accepted", label: "Accepted", count: 0 },
    { key: "dismissed", label: "Dismissed", count: 0 },
  ],
  default_finding_id: "threat:threat-1",
  findings: [finding],
};

describe("SecurityReviewReportPanel", () => {
  beforeEach(() => {
    vi.mocked(api.getLatestScanRunbook).mockRejectedValue(new Error("No scan"));
    vi.mocked(api.getThreatModelAgentReleaseDecision).mockResolvedValue({
      generated_at: "2026-04-24T12:00:00Z",
      system_name: "Payments Platform",
      decision: "block",
      decision_reason: "1 blocking finding is grounded enough to stop release.",
      pass_semantics:
        "Ship means no blocking finding based on currently connected evidence; it does not certify that the application is secure.",
      evidence_gaps: [],
      findings: [
        {
          decision: "block",
          finding_id: "threat:threat-1",
          source_object_type: "threat",
          source_object_id: "threat-1",
          title: "Caller auth missing on public payment API",
          priority: "p0_blocker",
          confidence: "high",
          risk_path: ["Public API Gateway", "Payment API"],
          evidence: [
            {
              type: "repository",
              reference: "repository",
              claim: "repository evidence supports this review finding.",
              validated: true,
            },
          ],
          fix_instructions: [
            "Require authenticated caller identity before payment initiation.",
          ],
          verification: {
            required: true,
            suggested_test:
              "Confirm payment initiation rejects unauthenticated callers.",
            evidence_needed: [],
          },
        },
      ],
    });
  });

  it("renders a full-picture stakeholder report from summary and finding data", () => {
    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    expect(screen.getByText("Stakeholder report")).toBeInTheDocument();
    expect(screen.getByText("Release blocker posture")).toBeInTheDocument();
    expect(screen.getByText("Executive Readout")).toBeInTheDocument();
    expect(screen.getByText("Quantified Risk Inventory")).toBeInTheDocument();
    expect(screen.getByText("Agent/API Release Decision")).toBeInTheDocument();
    expect(screen.getByText("Finding type")).toBeInTheDocument();
    expect(screen.getByText("Evidence confidence")).toBeInTheDocument();
    expect(screen.getByText("STRIDE shape")).toBeInTheDocument();
    expect(screen.getByText("Unowned high risk")).toBeInTheDocument();
    expect(screen.getByText("Review Progress")).toBeInTheDocument();
    expect(screen.getByText("Validation Coverage")).toBeInTheDocument();
    expect(screen.getByText("Attack Surface Shape")).toBeInTheDocument();
    expect(screen.getByText("Projected Attack Paths")).toBeInTheDocument();
    expect(screen.getByText("Supporting Analysis")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Hard counts from the current review findings and queue state.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Prioritized findings from review scoring and evidence context.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Modeled routes, not measured network distance."),
    ).toBeInTheDocument();

    const metricGrid = screen
      .getByText("P0 blockers")
      .closest(".security-review-report-metric-grid");
    expect(metricGrid).not.toBeNull();
    expect(
      within(metricGrid as HTMLElement).getAllByText("1").length,
    ).toBeGreaterThan(0);

    expect(screen.getByText("PCI DSS")).toBeInTheDocument();
    expect(screen.getAllByText("Runtime scan").length).toBeGreaterThan(0);
    expect(screen.getByText("Code evidence")).toBeInTheDocument();
  });

  it("renders deterministic validation runbook coverage when available", async () => {
    vi.mocked(api.getLatestScanRunbook).mockResolvedValue({
      coverage: {
        scan_job_id: "scan-1",
        scan_completed_at: "2026-04-25T00:00:00Z",
        tool_names: ["semgrep", "trivy"],
        target_binding: "mixed",
        finding_count: 4,
        deterministic_finding_count: 4,
        assisted_finding_count: 0,
        artifact_count: 2,
        mapped_threat_count: 2,
        validated_threat_count: 1,
        indicated_threat_count: 1,
        unbound_finding_count: 2,
        untested_threat_count: 5,
        confidence_counts: { validated: 1, indicated: 1, untested: 5 },
        validated_risk_score: 80,
        indicated_risk_score: 60,
        ai_assisted_risk_score: 0,
      },
      executive_summary: "Semgrep and Trivy produced deterministic validation evidence.",
      gaps: ["2 validation finding(s) are retained as evidence but not bound to a semantic threat."],
      mapped_threats: [],
      unbound_findings: [
        {
          finding_id: "finding-1",
          title: "JWT verification disabled",
          severity: "high",
          tool_name: "semgrep",
          target: "/repo",
          matched_at: "app/auth.py:42",
          cve_ids: [],
          tags: ["jwt"],
          confidence_label: "untested",
          evidence_scope: "unbound",
          proof_class: "deterministic",
          evidence_quality: "moderate",
          risk_score: 44,
          next_action: "Bind this finding to an affected DFD node or mark it not applicable.",
          explanation: "Finding was retained as deterministic evidence.",
        },
      ],
    });

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    expect(await screen.findByText("Semgrep and Trivy produced deterministic validation evidence.")).toBeInTheDocument();
    expect(screen.getByText("Validated threats")).toBeInTheDocument();
    expect(screen.getByText("Unbound findings")).toBeInTheDocument();
    expect(screen.getByText("JWT verification disabled · high")).toBeInTheDocument();
  });

  it("copies a stakeholder-safe report summary", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Copy report" }));

    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("# Payments Platform Security Review Report"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("P0 blockers: 1"),
    );
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("## Projected Attack Paths"),
    );
    expect(
      await screen.findByRole("button", { name: "Copied" }),
    ).toBeInTheDocument();
  });

  it("opens the deep-dive workspace from a top-risk row", async () => {
    const user = userEvent.setup();
    const onOpenFinding = vi.fn();
    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
        onOpenFinding={onOpenFinding}
      />,
    );

    await user.click(
      screen.getByRole("button", {
        name: /Caller auth missing on public payment API/i,
      }),
    );

    expect(onOpenFinding).toHaveBeenCalledWith(finding);
  });

  it("reveals attack path detail when more context is available", async () => {
    const user = userEvent.setup();
    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
      />,
    );

    expect(screen.queryByText("Modeled route")).not.toBeInTheDocument();

    await user.click(
      screen.getByRole("button", {
        name: /See more about Unauthenticated caller can initiate a payment workflow/i,
      }),
    );

    expect(screen.getByText("Modeled route")).toBeInTheDocument();
    expect(screen.getByText("Linked findings")).toBeInTheDocument();
    expect(screen.getByText("Why linked")).toBeInTheDocument();
    expect(screen.getByText("Verification")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Public entry point reaches restricted payment workflow.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Confirm payment initiation rejects unauthenticated callers.",
      ),
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", {
        name: /Show less for Unauthenticated caller can initiate a payment workflow/i,
      }),
    );

    expect(screen.queryByText("Modeled route")).not.toBeInTheDocument();
  });

  it("opens the deep-dive workspace from an attack path action", async () => {
    const user = userEvent.setup();
    const onOpenFinding = vi.fn();
    render(
      <SecurityReviewReportPanel
        model={model}
        threats={[threat]}
        summary={summary}
        findingsResponse={findingsResponse}
        onOpenFinding={onOpenFinding}
      />,
    );

    await user.click(
      screen.getByRole("button", {
        name: /Open finding for Unauthenticated caller can initiate a payment workflow/i,
      }),
    );

    expect(onOpenFinding).toHaveBeenCalledWith(finding);
  });
});
