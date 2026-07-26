import { useEffect, useState } from "react";

import { api } from "../api/client";
import type {
  AgentReleaseDecision,
  AgentSecurityReviewResponse,
  SecurityReviewApplicationSummary,
  SecurityReviewAttackPath,
  SecurityReviewBucketCount,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  SecurityReviewFindingSummary,
  ThreatModelResponse,
  ThreatResponse,
  ValidationRunbookResponse,
} from "../types/api";
import {
  reviewFindingKindLabel,
  reviewPriorityLabel,
  reviewPriorityTone,
  reviewQueueBucketLabel,
} from "./securityReviewWorkbenchUtils";

interface SecurityReviewReportPanelProps {
  model: ThreatModelResponse;
  threats: ThreatResponse[];
  summary: SecurityReviewApplicationSummary | null;
  findingsResponse: SecurityReviewFindingListResponse | null;
  onOpenFinding?: (finding: SecurityReviewFinding) => void;
}

interface DistributionSegment {
  key: string;
  label: string;
  count: number;
}

function bucketCount(counts: SecurityReviewBucketCount[], key: string): number {
  return counts.find((item) => item.key === key)?.count ?? 0;
}

function percent(part: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((part / total) * 100);
}

function formatGeneratedAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function evidenceSourceLabel(source: string): string {
  switch (source) {
    case "dfd":
      return "DFD";
    case "scan":
      return "Runtime scan";
    case "repository":
      return "Code evidence";
    case "compliance":
      return "Compliance framework";
    case "cloud":
      return "Cloud evidence";
    case "manual":
      return "Manual evidence";
    case "threat_intel":
      return "Threat intel";
    case "iac":
      return "IaC";
    case "sdlc":
      return "SDLC";
    default:
      return source
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
  }
}

function truthStatusLabel(status: string): string {
  switch (status) {
    case "validated":
      return "Validated";
    case "strongly_indicated":
      return "Strongly indicated";
    case "contextual":
      return "Contextual";
    case "theoretical":
      return "Theoretical";
    default:
      return status
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
  }
}

function agentDecisionLabel(decision: AgentReleaseDecision): string {
  switch (decision) {
    case "ship":
      return "Ship";
    case "block":
      return "Block";
    case "fix_now":
      return "Fix Now";
    case "verify":
      return "Verify";
    case "gather_evidence":
      return "Gather Evidence";
    case "accept_risk":
      return "Accept Risk";
  }
}

function agentDecisionTone(decision: AgentReleaseDecision): string {
  switch (decision) {
    case "block":
      return reviewPriorityTone("p0_blocker");
    case "fix_now":
      return reviewPriorityTone("p1_now");
    case "verify":
    case "gather_evidence":
      return reviewPriorityTone("p2_sprint");
    case "accept_risk":
      return reviewPriorityTone("p3_backlog");
    case "ship":
      return reviewPriorityTone("p4_monitor");
  }
}

function segmentToneClass(key: string, index: number): string {
  if (["p0_blocker", "validated", "Spoofing", "threat"].includes(key)) {
    return "security-review-report-segment-critical";
  }
  if (["p1_now", "strongly_indicated", "Tampering"].includes(key)) {
    return "security-review-report-segment-high";
  }
  if (["contextual", "Repudiation", "Information Disclosure"].includes(key)) {
    return "security-review-report-segment-medium";
  }
  if (
    ["theoretical", "Denial of Service", "Elevation of Privilege"].includes(key)
  ) {
    return "security-review-report-segment-muted";
  }
  return `security-review-report-segment-${(index % 4) + 1}`;
}

function countSegments(
  items: string[],
  labelForKey: (key: string) => string = (key) => key,
): DistributionSegment[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = item || "unknown";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, label: labelForKey(key), count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function reportFindingTitle(finding: SecurityReviewFindingSummary): string {
  if (!finding.display_id) return finding.title;
  const title = finding.title
    .replace(
      new RegExp(`^${escapeRegExp(finding.display_id)}\\s*[·:-]?\\s*`, "i"),
      "",
    )
    .trim();
  return `${finding.display_id} · ${title || finding.title}`;
}

function findMatchingFinding(
  summaryFinding: SecurityReviewFindingSummary,
  findings: SecurityReviewFinding[],
): SecurityReviewFinding | null {
  if (summaryFinding.threat_id) {
    const byThreat = findings.find(
      (finding) => finding.threat_id === summaryFinding.threat_id,
    );
    if (byThreat) return byThreat;
  }
  if (summaryFinding.finding_key) {
    const byKey = findings.find(
      (finding) =>
        finding.id === summaryFinding.finding_key ||
        finding.source_object_id === summaryFinding.finding_key,
    );
    if (byKey) return byKey;
  }
  return (
    findings.find(
      (finding) =>
        finding.display_id === summaryFinding.display_id &&
        finding.title === summaryFinding.title,
    ) ?? null
  );
}

function findAttackPathFinding(
  path: SecurityReviewAttackPath,
  findings: SecurityReviewFinding[],
): SecurityReviewFinding | null {
  const findingKeys = new Set(path.finding_keys ?? []);
  const findingTitles = new Set(path.finding_titles ?? []);

  return (
    findings.find(
      (finding) =>
        findingKeys.has(finding.id) ||
        findingKeys.has(finding.source_object_id) ||
        (finding.threat_id ? findingKeys.has(finding.threat_id) : false),
    ) ??
    findings.find(
      (finding) =>
        findingTitles.has(finding.title) ||
        (finding.display_id
          ? (path.finding_titles ?? []).some((title) =>
              title.startsWith(finding.display_id ?? ""),
            )
          : false),
    ) ??
    null
  );
}

function findingEvidenceSignalLabel(finding: SecurityReviewFindingSummary): string {
  if (finding.finding_kind === "evidence_gap") return "evidence missing";
  if (finding.finding_kind === "compliance_gap") return "compliance gap";
  if (finding.finding_kind === "control_gap") return "control gap";
  return finding.truth_status.replace(/_/g, " ");
}

function hasAttackPathDetails(path: SecurityReviewAttackPath): boolean {
  return (
    (path.path_nodes?.length ?? 0) > 0 ||
    path.finding_titles.length > 0 ||
    (path.relationship_reasons?.length ?? 0) > 0 ||
    (path.verification_steps?.length ?? 0) > 0
  );
}

function riskPostureLabel(
  p0Count: number,
  p1Count: number,
  evidenceGapCount: number,
): string {
  const evidenceQualifier = evidenceGapCount > 0 ? " · evidence-limited" : "";
  if (p0Count > 0) return `Release blocker posture${evidenceQualifier}`;
  if (p1Count > 0) return `Fix-before-confidence posture${evidenceQualifier}`;
  if (evidenceGapCount > 0) return "Evidence-limited posture";
  return "Monitor with normal governance";
}

function buildReportMarkdown({
  model,
  summary,
  p0Count,
  p1Count,
  fixNowCount,
  evidenceGapCount,
  unownedHighRiskCount,
  progressValue,
  validationRunbook,
}: {
  model: ThreatModelResponse;
  summary: SecurityReviewApplicationSummary;
  p0Count: number;
  p1Count: number;
  fixNowCount: number;
  evidenceGapCount: number;
  unownedHighRiskCount: number;
  progressValue: number;
  validationRunbook?: ValidationRunbookResponse | null;
}): string {
  const topRisks = summary.top_findings.slice(0, 5).map((finding, index) => {
    const target = finding.target_asset ? ` -> ${finding.target_asset}` : "";
    return `${index + 1}. ${reviewPriorityLabel(finding.priority)}: ${reportFindingTitle(finding)}${target}`;
  });
  const blindSpots = summary.blind_spots
    .slice(0, 4)
    .map((finding, index) => `${index + 1}. ${reportFindingTitle(finding)}`);
  const attackPaths = summary.attack_paths.slice(0, 4).map((path, index) => {
    const route =
      path.entry_point || path.target_asset
        ? ` (${path.entry_point ?? "unknown entry"} -> ${path.target_asset ?? "unknown target"})`
        : "";
    return `${index + 1}. ${reviewPriorityLabel(path.composite_priority)}: ${path.chain_description}${route}`;
  });
  const nextSteps = summary.next_steps
    .slice(0, 5)
    .map((item, index) => `${index + 1}. ${item}`);
  const validationCoverage = validationRunbook
    ? [
        `- Validated threats: ${validationRunbook.coverage.validated_threat_count}`,
        `- Indicated threats: ${validationRunbook.coverage.indicated_threat_count}`,
        `- Unbound findings: ${validationRunbook.coverage.unbound_finding_count}`,
        `- Untested threats: ${validationRunbook.coverage.untested_threat_count}`,
        `- Findings: ${validationRunbook.coverage.finding_count} total (${validationRunbook.coverage.deterministic_finding_count} deterministic, ${validationRunbook.coverage.assisted_finding_count} non-deterministic)`,
        `- Risk scores: ${validationRunbook.coverage.validated_risk_score} validated / ${validationRunbook.coverage.indicated_risk_score} indicated / ${validationRunbook.coverage.ai_assisted_risk_score} non-deterministic`,
        `- Target binding: ${validationRunbook.coverage.target_binding.replace(/_/g, " ")}`,
        ...validationRunbook.mapped_threats
          .filter((threat) => threat.confidence_label !== "validated")
          .slice(0, 5)
          .map((threat) => `- ${threat.threat_display_id}: ${threat.confidence_label}, risk ${threat.risk_score}, next action: ${threat.next_action}`),
      ]
    : ["No validation runbook attached."];

  return [
    `# ${model.system_name} Security Review Report`,
    "",
    `Verdict: ${reviewPriorityLabel(summary.overall_priority)} - ${summary.focus_statement}`,
    `Generated: ${formatGeneratedAt(summary.generated_at)}`,
    `Scope: ${model.data_classification} / ${model.deployment_model ?? "deployment unspecified"} / ${
      model.regulatory_scope.length > 0
        ? model.regulatory_scope.join(", ")
        : "no regulatory scope attached"
    }`,
    "",
    "## Key Counts",
    `- P0 blockers: ${p0Count}`,
    `- P1 now: ${p1Count}`,
    `- Fix Now queue: ${fixNowCount}`,
    `- Evidence gaps: ${evidenceGapCount}`,
    `- Unowned high-risk findings: ${unownedHighRiskCount}`,
    `- Resolved, accepted, or dismissed: ${progressValue}%`,
    "",
    "## Top Risks",
    ...(topRisks.length > 0 ? topRisks : ["No top risks attached."]),
    "",
    "## Blind Spots",
    ...(blindSpots.length > 0
      ? blindSpots
      : ["No blind spots currently flagged."]),
    "",
    "## Projected Attack Paths",
    ...(attackPaths.length > 0
      ? attackPaths
      : ["No aggregate attack paths attached."]),
    "",
    "## Validation Coverage",
    ...validationCoverage,
    "",
    "## Next Steps",
    ...(nextSteps.length > 0 ? nextSteps : ["No next steps attached."]),
  ].join("\n");
}

function DistributionBreakdown({
  title,
  subtitle,
  segments,
}: {
  title: string;
  subtitle: string;
  segments: DistributionSegment[];
}): JSX.Element {
  const total = segments.reduce((sum, segment) => sum + segment.count, 0);

  return (
    <article className="security-review-report-breakdown">
      <div>
        <strong>{title}</strong>
        <p>{subtitle}</p>
      </div>
      {total > 0 ? (
        <>
          <div className="security-review-report-stacked-bar">
            {segments.map((segment, index) => (
              <span
                key={segment.key}
                className={segmentToneClass(segment.key, index)}
                style={{
                  width: `${Math.max(percent(segment.count, total), 2)}%`,
                }}
                title={`${segment.label}: ${segment.count}`}
              />
            ))}
          </div>
          <div className="security-review-report-breakdown-legend">
            {segments.slice(0, 6).map((segment, index) => (
              <span key={segment.key}>
                <i className={segmentToneClass(segment.key, index)} />
                {segment.label}: {segment.count}
              </span>
            ))}
          </div>
        </>
      ) : (
        <p className="security-review-report-muted">
          No distribution data attached.
        </p>
      )}
    </article>
  );
}

function ActionableFindingRow({
  item,
  matchingFinding,
  onOpenFinding,
}: {
  item: SecurityReviewFindingSummary;
  matchingFinding: SecurityReviewFinding | null;
  onOpenFinding?: (finding: SecurityReviewFinding) => void;
}): JSX.Element {
  const content = (
    <>
      <span
        className={`application-review-priority-chip ${reviewPriorityTone(item.priority)}`}
      >
        {reviewPriorityLabel(item.priority)}
      </span>
      <strong>{reportFindingTitle(item)}</strong>
      <p>
        {item.rationale_excerpt ??
          item.next_step ??
          "No summary rationale attached yet."}
      </p>
      <span className="security-review-report-row-meta">
        {findingEvidenceSignalLabel(item)} ·{" "}
        {item.urgency.replace(/_/g, " ")}
        {item.entry_point ? ` · Entry: ${item.entry_point}` : ""}
        {item.target_asset ? ` · Target: ${item.target_asset}` : ""}
      </span>
    </>
  );

  if (matchingFinding && onOpenFinding) {
    return (
      <button
        type="button"
        className="security-review-report-finding-row security-review-report-finding-row-button"
        onClick={() => onOpenFinding(matchingFinding)}
      >
        {content}
      </button>
    );
  }

  return (
    <article className="security-review-report-finding-row">{content}</article>
  );
}

function AttackPathRow({
  path,
  matchingFinding,
  onOpenFinding,
  isExpanded,
  onToggleDetails,
}: {
  path: SecurityReviewAttackPath;
  matchingFinding: SecurityReviewFinding | null;
  onOpenFinding?: (finding: SecurityReviewFinding) => void;
  isExpanded: boolean;
  onToggleDetails: () => void;
}): JSX.Element {
  const supportCount = path.support_count ?? path.finding_titles.length;
  const modeledStepCount =
    path.path_nodes && path.path_nodes.length > 1
      ? path.path_nodes.length - 1
      : path.hop_count;
  const hasDetails = hasAttackPathDetails(path);

  return (
    <article className="security-review-report-path-row">
      <div>
        <strong>{path.chain_description}</strong>
        <p>
          {path.entry_point ?? "Unknown entry"} to{" "}
          {path.target_asset ?? "unknown target"} · {modeledStepCount} modeled{" "}
          {modeledStepCount === 1 ? "step" : "steps"} · {supportCount}{" "}
          supporting {supportCount === 1 ? "finding" : "findings"}
        </p>
      </div>
      <div className="security-review-report-chip-row">
        <span
          className={`application-review-priority-chip ${reviewPriorityTone(path.composite_priority)}`}
        >
          {reviewPriorityLabel(path.composite_priority)}
        </span>
        <span className="security-review-detail-tag">
          {path.composite_exploitability} exploitability
        </span>
        {(path.evidence_sources ?? []).slice(0, 3).map((source) => (
          <span key={source} className="security-review-detail-tag">
            {evidenceSourceLabel(source)}
          </span>
        ))}
        {hasDetails ? (
          <button
            type="button"
            className="security-review-report-path-action"
            aria-expanded={isExpanded}
            aria-label={`${isExpanded ? "Show less for" : "See more about"} ${path.chain_description}`}
            onClick={onToggleDetails}
          >
            {isExpanded ? "Show less" : "See more"}
          </button>
        ) : null}
        {matchingFinding && onOpenFinding ? (
          <button
            type="button"
            className="security-review-report-path-action security-review-report-path-action-primary"
            aria-label={`Open finding for ${path.chain_description}`}
            onClick={() => onOpenFinding(matchingFinding)}
          >
            Open finding
          </button>
        ) : null}
      </div>
      {isExpanded && hasDetails ? (
        <div className="security-review-report-path-details">
          {path.path_nodes && path.path_nodes.length > 0 ? (
            <div>
              <strong>Modeled route</strong>
              <div className="security-review-report-path-node-row">
                {path.path_nodes.map((node, index) => (
                  <span key={`${path.path_id}-node-${index}`}>
                    <span>{node}</span>
                    {index < (path.path_nodes?.length ?? 0) - 1 ? (
                      <i>-&gt;</i>
                    ) : null}
                  </span>
                ))}
              </div>
            </div>
          ) : null}
          {path.finding_titles.length > 0 ? (
            <div>
              <strong>Linked findings</strong>
              <ul>
                {path.finding_titles.map((title, index) => (
                  <li key={`${path.path_id}-finding-${index}`}>{title}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {path.relationship_reasons && path.relationship_reasons.length > 0 ? (
            <div>
              <strong>Why linked</strong>
              <ul>
                {path.relationship_reasons.map((reason, index) => (
                  <li key={`${path.path_id}-reason-${index}`}>{reason}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {path.verification_steps && path.verification_steps.length > 0 ? (
            <div>
              <strong>Verification</strong>
              <ul>
                {path.verification_steps.map((step, index) => (
                  <li key={`${path.path_id}-verification-${index}`}>{step}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}

export function SecurityReviewReportPanel({
  model,
  threats,
  summary,
  findingsResponse,
  onOpenFinding,
}: SecurityReviewReportPanelProps): JSX.Element {
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "failed">(
    "idle",
  );
  const [expandedAttackPathIds, setExpandedAttackPathIds] = useState<
    Set<string>
  >(() => new Set());
  const [validationRunbook, setValidationRunbook] =
    useState<ValidationRunbookResponse | null>(null);
  const [validationRunbookLoading, setValidationRunbookLoading] = useState(false);
  const [agentDecision, setAgentDecision] =
    useState<AgentSecurityReviewResponse | null>(null);
  const [agentDecisionLoading, setAgentDecisionLoading] = useState(false);

  useEffect(() => {
    let active = true;
    setValidationRunbookLoading(true);
    api
      .getLatestScanRunbook(model.id)
      .then((runbook) => {
        if (active) setValidationRunbook(runbook);
      })
      .catch(() => {
        if (active) setValidationRunbook(null);
      })
      .finally(() => {
        if (active) setValidationRunbookLoading(false);
      });
    return () => {
      active = false;
    };
  }, [model.id, summary?.generated_at]);

  useEffect(() => {
    let active = true;
    setAgentDecisionLoading(true);
    api
      .getThreatModelAgentReleaseDecision(model.id)
      .then((decision) => {
        if (active) setAgentDecision(decision);
      })
      .catch(() => {
        if (active) setAgentDecision(null);
      })
      .finally(() => {
        if (active) setAgentDecisionLoading(false);
      });
    return () => {
      active = false;
    };
  }, [model.id, summary?.generated_at, findingsResponse?.generated_at]);

  if (!summary || !findingsResponse) {
    return (
      <div className="application-review-panel-state">Loading report…</div>
    );
  }

  const findings = findingsResponse.findings;
  const p0Count = bucketCount(summary.priority_counts, "p0_blocker");
  const p1Count = bucketCount(summary.priority_counts, "p1_now");
  const fixNowCount = bucketCount(findingsResponse.queue_counts, "fix_now");
  const verifyCount = bucketCount(findingsResponse.queue_counts, "verify");
  const evidenceQueueCount = bucketCount(
    findingsResponse.queue_counts,
    "gather_evidence",
  );
  const backlogCount = bucketCount(findingsResponse.queue_counts, "backlog");
  const openCount = bucketCount(findingsResponse.review_status_counts, "open");
  const inProgressCount = bucketCount(
    findingsResponse.review_status_counts,
    "in_progress",
  );
  const mitigatedCount = bucketCount(
    findingsResponse.review_status_counts,
    "mitigated",
  );
  const acceptedCount = bucketCount(
    findingsResponse.review_status_counts,
    "accepted",
  );
  const dismissedCount = bucketCount(
    findingsResponse.review_status_counts,
    "dismissed",
  );
  const closedCount = mitigatedCount + acceptedCount + dismissedCount;
  const evidenceGapCount = findings.filter(
    (finding) => finding.needs_evidence,
  ).length;
  const engineeringChangeCount = findings.filter(
    (finding) => finding.needs_engineering_change,
  ).length;
  const activeThreatCount = threats.filter(
    (threat) => threat.status === "Open" || threat.status === "In Progress",
  ).length;
  const unownedHighRiskCount = findings.filter(
    (finding) =>
      (finding.priority === "p0_blocker" || finding.priority === "p1_now") &&
      (finding.review_status === "open" ||
        finding.review_status === "in_progress") &&
      !finding.owner,
  ).length;
  const uniqueEvidenceRefs = new Set(
    findings.flatMap((finding) => finding.evidence_refs),
  );
  const progressValue = percent(closedCount, findings.length);
  const posture = riskPostureLabel(p0Count, p1Count, evidenceGapCount);
  const findingKindSegments = countSegments(
    findings.map((finding) => finding.display_kind),
    (kind) =>
      reviewFindingKindLabel(kind as SecurityReviewFinding["display_kind"]),
  );
  const truthStatusSegments = summary.truth_status_counts
    .map((item) => ({
      key: item.key,
      label: truthStatusLabel(item.key),
      count: item.count,
    }))
    .filter((item) => item.count > 0);
  const strideSegments = countSegments(
    threats.map((threat) => threat.stride_category),
  );
  const clipboardReport = buildReportMarkdown({
    model,
    summary,
    p0Count,
    p1Count,
    fixNowCount,
    evidenceGapCount,
    unownedHighRiskCount,
    progressValue,
    validationRunbook,
  });

  async function handleCopyReport() {
    try {
      await navigator.clipboard.writeText(clipboardReport);
      setCopyStatus("copied");
      window.setTimeout(() => setCopyStatus("idle"), 1800);
    } catch {
      setCopyStatus("failed");
    }
  }

  function toggleAttackPathDetails(pathId: string) {
    setExpandedAttackPathIds((current) => {
      const next = new Set(current);
      if (next.has(pathId)) {
        next.delete(pathId);
      } else {
        next.add(pathId);
      }
      return next;
    });
  }

  const riskMetrics = [
    {
      label: "P0 blockers",
      value: p0Count,
      note: "must be resolved or explicitly accepted",
      tone: "critical",
    },
    {
      label: "P1 now",
      value: p1Count,
      note: "current-cycle engineering or verification",
      tone: "high",
    },
    {
      label: "Fix Now queue",
      value: fixNowCount,
      note: "active remediation demand",
      tone: "high",
    },
    {
      label: "Evidence gaps",
      value: evidenceGapCount,
      note: "review confidence limiters",
      tone: "medium",
    },
    {
      label: "Engineering changes",
      value: engineeringChangeCount,
      note: "findings needing code, config, or control work",
      tone: "neutral",
    },
    {
      label: "Unowned high risk",
      value: unownedHighRiskCount,
      note: "P0/P1 work without an assigned owner",
      tone: "critical",
    },
    {
      label: "Active threats",
      value: activeThreatCount,
      note: "open or in-progress threat records",
      tone: "neutral",
    },
  ];

  const attackSurfaceMetrics = [
    {
      label: "Public entry points",
      value: summary.coverage.public_entry_points,
    },
    {
      label: "Privileged surfaces",
      value: summary.coverage.privileged_surfaces,
    },
    { label: "Restricted assets", value: summary.coverage.restricted_assets },
    { label: "Projected attack paths", value: summary.coverage.attack_paths },
    { label: "Systemic findings", value: summary.coverage.systemic_findings },
    {
      label: "Evidence sources",
      value: summary.coverage.attached_evidence_sources,
    },
  ];

  return (
    <div className="security-review-report">
      <section
        className={`security-review-report-hero security-review-report-hero-${summary.overall_priority}`}
      >
        <div className="security-review-report-verdict-main">
          <span className="security-review-report-kicker">
            Stakeholder report
          </span>
          <span
            className={`security-review-report-verdict-chip ${reviewPriorityTone(summary.overall_priority)}`}
          >
            {reviewPriorityLabel(summary.overall_priority)}
          </span>
          <h4>{posture}</h4>
          <p>{summary.focus_statement}</p>
          <div className="security-review-report-meta-line">
            <span>{model.system_name}</span>
            <span>{model.data_classification}</span>
            <span>{model.deployment_model ?? "deployment unspecified"}</span>
            <span>
              {model.regulatory_scope.length > 0
                ? model.regulatory_scope.join(", ")
                : "No regulatory scope attached"}
            </span>
            <span>Generated {formatGeneratedAt(summary.generated_at)}</span>
          </div>
        </div>
        <button
          type="button"
          className="security-review-report-copy-btn"
          onClick={() => void handleCopyReport()}
        >
          {copyStatus === "copied"
            ? "Copied"
            : copyStatus === "failed"
              ? "Copy failed"
              : "Copy report"}
        </button>
      </section>

      <section className="security-review-report-exec">
        <div className="security-review-report-section-header">
          <div>
            <h5>Executive Readout</h5>
            <p>Why the posture matters and what needs to happen next.</p>
          </div>
          <span>Review engine</span>
        </div>
        <div className="security-review-report-two-column-list">
          <div>
            <strong>Why this matters</strong>
            <ul>
              {summary.rationale.slice(0, 3).map((item, index) => (
                <li key={`rationale-${index}`}>{item}</li>
              ))}
            </ul>
          </div>
          <div>
            <strong>Next steps</strong>
            <ul>
              {summary.next_steps.slice(0, 3).map((item, index) => (
                <li key={`next-${index}`}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Agent/API Release Decision</h5>
            <p>The machine-readable decision uses the same review findings and pass semantics as this report.</p>
          </div>
          <span>{agentDecisionLoading ? "loading" : "agent contract"}</span>
        </div>
        {agentDecision ? (
          <>
            <div className="security-review-report-chip-row">
              <span
                className={`application-review-priority-chip ${agentDecisionTone(agentDecision.decision)}`}
              >
                {agentDecisionLabel(agentDecision.decision)}
              </span>
              <span className="security-review-detail-tag">
                {agentDecision.findings.length} agent-visible findings
              </span>
              <span className="security-review-detail-tag">
                {agentDecision.evidence_gaps.length} evidence gaps
              </span>
            </div>
            <p className="security-review-report-muted">
              {agentDecision.decision_reason}
            </p>
            {agentDecision.findings.length > 0 ? (
              <div className="security-review-report-list">
                {agentDecision.findings.slice(0, 3).map((finding) => (
                  <article
                    key={finding.finding_id}
                    className="security-review-report-finding-row"
                  >
                    <span
                      className={`application-review-priority-chip ${agentDecisionTone(finding.decision)}`}
                    >
                      {agentDecisionLabel(finding.decision)}
                    </span>
                    <strong>{finding.title}</strong>
                    <p>
                      {finding.fix_instructions[0] ??
                        finding.verification.suggested_test ??
                        "No agent instruction attached yet."}
                    </p>
                    <span className="security-review-report-row-meta">
                      {finding.evidence.length} evidence refs ·{" "}
                      {finding.verification.required
                        ? "verification required"
                        : "no verification required"}
                    </span>
                  </article>
                ))}
              </div>
            ) : null}
          </>
        ) : (
          <p className="security-review-report-muted">
            {agentDecisionLoading
              ? "Loading agent release decision..."
              : "Agent release decision is not available for this review yet."}
          </p>
        )}
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Quantified Risk Inventory</h5>
            <p>Hard counts from the current review findings and queue state.</p>
          </div>
          <span>{findings.length} findings</span>
        </div>
        <div className="security-review-report-metric-grid">
          {riskMetrics.map((metric) => (
            <article
              key={metric.label}
              className={`security-review-report-metric security-review-report-metric-${metric.tone}`}
            >
              <strong>{metric.value}</strong>
              <span>{metric.label}</span>
              <p>{metric.note}</p>
            </article>
          ))}
        </div>
        <div className="security-review-report-breakdown-grid">
          <DistributionBreakdown
            title="Finding type"
            subtitle="What kind of security work is in the queue."
            segments={findingKindSegments}
          />
          <DistributionBreakdown
            title="Evidence confidence"
            subtitle="Validated versus contextual or theoretical signals."
            segments={truthStatusSegments}
          />
          <DistributionBreakdown
            title="STRIDE shape"
            subtitle="Threat categories represented in the current model."
            segments={strideSegments}
          />
        </div>
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Validation Coverage</h5>
            <p>Validation evidence mapped against semantic threats.</p>
          </div>
          <span>
            {validationRunbook
              ? validationRunbook.coverage.tool_names.join(", ") || "validation"
              : validationRunbookLoading
                ? "loading"
                : "no runbook"}
          </span>
        </div>
        {validationRunbook ? (
          <>
            <div className="security-review-report-metric-grid">
              <article className="security-review-report-metric security-review-report-metric-neutral">
                <strong>{validationRunbook.coverage.validated_threat_count}</strong>
                <span>Validated threats</span>
                <p>node-bound validation evidence</p>
              </article>
              <article className="security-review-report-metric security-review-report-metric-medium">
                <strong>{validationRunbook.coverage.indicated_threat_count}</strong>
                <span>Indicated threats</span>
                <p>evidence needs stronger binding</p>
              </article>
              <article className="security-review-report-metric security-review-report-metric-high">
                <strong>{validationRunbook.coverage.unbound_finding_count}</strong>
                <span>Unbound findings</span>
                <p>retained but not semantic validation</p>
              </article>
              <article className="security-review-report-metric security-review-report-metric-neutral">
                <strong>{validationRunbook.coverage.untested_threat_count}</strong>
                <span>Untested threats</span>
                <p>still need validation evidence</p>
              </article>
            </div>
            <p className="security-review-report-muted">
              {validationRunbook.executive_summary}
            </p>
            <div className="security-review-report-chip-row">
              <span className="security-review-detail-tag">
                {validationRunbook.coverage.target_binding.replace(/_/g, " ")}
              </span>
              <span className="security-review-detail-tag">
                {validationRunbook.coverage.deterministic_finding_count} deterministic findings
              </span>
              <span className="security-review-detail-tag">
                validated risk {validationRunbook.coverage.validated_risk_score}
              </span>
              <span className="security-review-detail-tag">
                indicated risk {validationRunbook.coverage.indicated_risk_score}
              </span>
              {validationRunbook.coverage.assisted_finding_count > 0 ? (
                <span className="security-review-detail-tag">
                  {validationRunbook.coverage.assisted_finding_count} non-deterministic findings · risk {validationRunbook.coverage.ai_assisted_risk_score}
                </span>
              ) : null}
              {validationRunbook.coverage.tool_names.map((toolName) => (
                <span key={toolName} className="security-review-detail-tag">
                  {toolName}
                </span>
              ))}
            </div>
            <div className="security-review-report-two-column-list security-review-report-validation-splits">
              <div>
                <strong>Validated and indicated threats</strong>
                <ul>
                  {validationRunbook.mapped_threats
                    .filter((threat) => threat.confidence_label !== "untested")
                    .slice(0, 5)
                    .map((threat) => (
                      <li key={threat.threat_id}>
                        {threat.threat_display_id} · {threat.confidence_label} · risk {threat.risk_score} · {threat.proof_class}
                      </li>
                    ))}
                  {validationRunbook.mapped_threats.every((threat) => threat.confidence_label === "untested") ? (
                    <li>No threat has validation evidence yet.</li>
                  ) : null}
                </ul>
              </div>
              <div>
                <strong>Unvalidated next actions</strong>
                <ul>
                  {validationRunbook.mapped_threats
                    .filter((threat) => threat.confidence_label === "untested")
                    .slice(0, 5)
                    .map((threat) => (
                      <li key={threat.threat_id}>
                        {threat.threat_display_id} · {threat.next_action}
                      </li>
                    ))}
                  {validationRunbook.mapped_threats.some((threat) => threat.confidence_label === "untested") ? null : (
                    <li>No mapped threat is currently untested in this runbook.</li>
                  )}
                </ul>
              </div>
            </div>
            <div className="security-review-report-two-column-list">
              <div>
                <strong>Coverage gaps</strong>
                <ul>
                  {validationRunbook.gaps.slice(0, 4).map((gap) => (
                    <li key={gap}>{gap}</li>
                  ))}
                </ul>
              </div>
              <div>
                <strong>Unbound evidence</strong>
                <ul>
                  {validationRunbook.unbound_findings.slice(0, 4).map((finding) => (
                    <li key={finding.finding_id}>
                      {finding.title} · {finding.severity}
                    </li>
                  ))}
                  {validationRunbook.unbound_findings.length === 0 ? (
                    <li>No unbound validation evidence.</li>
                  ) : null}
                </ul>
              </div>
            </div>
          </>
        ) : (
          <p className="security-review-report-muted">
            {validationRunbookLoading
              ? "Loading validation coverage..."
              : "No completed validation runbook is available yet."}
          </p>
        )}
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Review Progress</h5>
            <p>Lifecycle state across all normalized findings.</p>
          </div>
          <span>{progressValue}% resolved, accepted, or dismissed</span>
        </div>
        <div
          className="security-review-report-progress"
          aria-label="Review completion"
        >
          <span style={{ width: `${progressValue}%` }} />
        </div>
        <div className="security-review-report-chip-row">
          <span className="security-review-detail-tag">{openCount} open</span>
          <span className="security-review-detail-tag">
            {inProgressCount} in progress
          </span>
          <span className="security-review-detail-tag">
            {mitigatedCount} mitigated
          </span>
          <span className="security-review-detail-tag">
            {acceptedCount} accepted
          </span>
          <span className="security-review-detail-tag">
            {dismissedCount} dismissed
          </span>
        </div>
        <div className="security-review-report-chip-row">
          <span className="security-review-detail-tag">
            {reviewQueueBucketLabel("fix_now")}: {fixNowCount}
          </span>
          <span className="security-review-detail-tag">
            {reviewQueueBucketLabel("verify")}: {verifyCount}
          </span>
          <span className="security-review-detail-tag">
            {reviewQueueBucketLabel("gather_evidence")}: {evidenceQueueCount}
          </span>
          <span className="security-review-detail-tag">
            {reviewQueueBucketLabel("backlog")}: {backlogCount}
          </span>
        </div>
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Top Risks</h5>
            <p>Prioritized findings from review scoring and evidence context.</p>
          </div>
          <span>Review engine</span>
        </div>
        <div className="security-review-report-list">
          {summary.top_findings.slice(0, 8).map((item) => (
            <ActionableFindingRow
              key={`${item.finding_key ?? item.threat_id ?? item.title}-top`}
              item={item}
              matchingFinding={findMatchingFinding(item, findings)}
              onOpenFinding={onOpenFinding}
            />
          ))}
          {summary.top_findings.length === 0 ? (
            <p className="security-review-report-muted">
              No top findings are attached yet.
            </p>
          ) : null}
        </div>
      </section>

      <section className="security-review-report-section">
        <div className="security-review-report-section-header">
          <div>
            <h5>Projected Attack Paths</h5>
            <p>Modeled routes, not measured network distance.</p>
          </div>
          <span>Modeled paths</span>
        </div>
        <div className="security-review-report-path-list">
          {summary.attack_paths.slice(0, 5).map((path) => (
            <AttackPathRow
              key={path.path_id}
              path={path}
              matchingFinding={findAttackPathFinding(path, findings)}
              onOpenFinding={onOpenFinding}
              isExpanded={expandedAttackPathIds.has(path.path_id)}
              onToggleDetails={() => toggleAttackPathDetails(path.path_id)}
            />
          ))}
          {summary.attack_paths.length === 0 ? (
            <p className="security-review-report-muted">
              No aggregate attack path is attached yet.
            </p>
          ) : null}
        </div>
      </section>

      <section className="security-review-report-grid">
        <div className="security-review-report-section">
          <div className="security-review-report-section-header">
            <div>
              <h5>Blind Spots</h5>
              <p>Potential gaps identified by the review engine.</p>
            </div>
            <span>Review engine</span>
          </div>
          <div className="security-review-report-list">
            {summary.blind_spots.slice(0, 6).map((item) => (
              <ActionableFindingRow
                key={`${item.finding_key ?? item.threat_id ?? item.title}-blind`}
                item={item}
                matchingFinding={findMatchingFinding(item, findings)}
                onOpenFinding={onOpenFinding}
              />
            ))}
            {summary.blind_spots.length === 0 ? (
              <p className="security-review-report-muted">
                No blind spots are currently flagged.
              </p>
            ) : null}
          </div>
        </div>

        <div className="security-review-report-section">
          <div className="security-review-report-section-header">
            <div>
              <h5>Risk Acceptances</h5>
              <p>Accepted risk that still needs governance visibility.</p>
            </div>
            <span>Hard state counts</span>
          </div>
          <div className="security-review-report-delta-strip">
            <span>{summary.risk_acceptance_summary.active} active</span>
            <span>{summary.risk_acceptance_summary.reopened} reopened</span>
            <span>{summary.risk_acceptance_summary.expired} expired</span>
          </div>
        </div>
      </section>

      <details className="security-review-report-supporting">
        <summary>
          <span>Supporting Analysis</span>
          <strong>Attack surface, delta, and evidence coverage</strong>
        </summary>
        <div className="security-review-report-supporting-grid">
          <div className="security-review-report-section">
            <div className="security-review-report-section-header">
              <div>
                <h5>Attack Surface Shape</h5>
                <p>
                  Modeled exposure, privileged paths, restricted assets, and
                  evidence coverage.
                </p>
              </div>
              <span>Hard model counts</span>
            </div>
            <div className="security-review-report-surface-grid">
              {attackSurfaceMetrics.map((metric) => (
                <div
                  key={metric.label}
                  className="security-review-report-surface-item"
                >
                  <strong>{metric.value}</strong>
                  <span>{metric.label}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="security-review-report-section">
            <div className="security-review-report-section-header">
              <div>
                <h5>Delta Since Last Review</h5>
                <p>
                  Change pressure from the review engine's current delta
                  baseline.
                </p>
              </div>
              <span>Hard delta counts</span>
            </div>
            <div className="security-review-report-delta-strip">
              <span>+{summary.review_delta_summary.new_findings} new</span>
              <span>
                -{summary.review_delta_summary.resolved_findings} resolved
              </span>
              <span>
                {summary.review_delta_summary.reopened_findings} reopened
              </span>
              <span>
                {summary.review_delta_summary.escalated_findings} escalated
              </span>
              <span>
                {summary.review_delta_summary.deescalated_findings} de-escalated
              </span>
            </div>
          </div>

          <div className="security-review-report-section">
            <div className="security-review-report-section-header">
              <div>
                <h5>Evidence Coverage</h5>
                <p>How much proof is attached versus still missing.</p>
              </div>
              <span>{uniqueEvidenceRefs.size} referenced sources</span>
            </div>
            <div className="security-review-report-evidence">
              <strong>{summary.coverage.attached_evidence_sources}</strong>
              <span>attached source types</span>
              <p>
                {summary.coverage.missing_evidence_sources} source types still
                missing.
              </p>
            </div>
            <div className="security-review-report-chip-row">
              {[...uniqueEvidenceRefs].slice(0, 8).map((source) => (
                <span key={source} className="security-review-detail-tag">
                  {evidenceSourceLabel(source)}
                </span>
              ))}
            </div>
          </div>
        </div>
      </details>
    </div>
  );
}
