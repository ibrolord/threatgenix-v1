"""Agent-facing release decision projection for semantic security reviews."""

from __future__ import annotations

from collections import Counter

from app.schemas.security_review import (
    AgentEvidenceRef,
    AgentEvidenceType,
    AgentFindingVerification,
    AgentReleaseDecision,
    AgentSecurityReviewFinding,
    AgentSecurityReviewResponse,
    SecurityReviewApplicationSummary,
    SecurityReviewFinding,
    SecurityReviewFindingListResponse,
)

PASS_SEMANTICS = (
    "Ship means no blocking finding based on currently connected evidence; "
    "it does not certify that the application is secure."
)

_DECISION_RANK: dict[AgentReleaseDecision, int] = {
    "block": 0,
    "fix_now": 1,
    "verify": 2,
    "gather_evidence": 3,
    "accept_risk": 4,
    "ship": 5,
}
_EVIDENCE_TYPES: set[AgentEvidenceType] = {
    "code",
    "dfd",
    "scan",
    "cloud",
    "iac",
    "control",
    "threat_intel",
    "manual",
    "repository",
    "unknown",
}


def _active_for_release(finding: SecurityReviewFinding) -> bool:
    return finding.review_status in {"open", "in_progress", "accepted"}


def _is_grounded(finding: SecurityReviewFinding) -> bool:
    return bool(finding.evidence_refs or finding.code_links)


def _evidence_type(value: str) -> AgentEvidenceType:
    candidate = value.strip().casefold().replace("-", "_")
    if candidate in _EVIDENCE_TYPES:
        return candidate  # type: ignore[return-value]
    if candidate in {"repo", "git", "github"}:
        return "repository"
    if candidate in {"sast", "dast", "validation"}:
        return "scan"
    if candidate in {"threat_intelligence", "intel"}:
        return "threat_intel"
    return "unknown"


def _agent_decision_for_finding(
    finding: SecurityReviewFinding,
) -> AgentReleaseDecision:
    if finding.review_status == "accepted":
        return "accept_risk"

    proposed: AgentReleaseDecision
    if (
        finding.priority == "p0_blocker"
        or finding.wire_action_bucket == "bright_red_line"
    ):
        proposed = "block"
    elif (
        finding.queue_bucket == "fix_now"
        or finding.wire_action_bucket == "engineer_now"
        or (finding.needs_engineering_change and finding.priority == "p1_now")
    ):
        proposed = "fix_now"
    elif (
        finding.queue_bucket == "verify"
        or finding.wire_action_bucket == "verify_control"
    ):
        proposed = "verify"
    elif (
        finding.queue_bucket == "gather_evidence"
        or finding.wire_action_bucket == "fill_evidence_gap"
        or finding.needs_evidence
    ):
        proposed = "gather_evidence"
    else:
        proposed = "verify"

    if (
        proposed in {"block", "fix_now"}
        and not _is_grounded(finding)
        and finding.truth_status not in {"validated", "strongly_indicated"}
    ):
        return "gather_evidence"
    return proposed


def _risk_path(finding: SecurityReviewFinding) -> list[str]:
    path: list[str] = []
    if finding.entry_point:
        path.append(finding.entry_point)
    path.extend(asset for asset in finding.impacted_assets if asset not in path)
    if not path and finding.code_links:
        first_link = finding.code_links[0]
        path.append(first_link.surface_name or first_link.source_file)
    if finding.title not in path:
        path.append(finding.title)
    return path


def _evidence_refs(finding: SecurityReviewFinding) -> list[AgentEvidenceRef]:
    validated = finding.truth_status in {"validated", "strongly_indicated"}
    refs: list[AgentEvidenceRef] = []
    seen: set[tuple[str, str]] = set()

    for link in finding.code_links:
        reference = link.source_file
        if link.line_number:
            reference = f"{reference}:{link.line_number}"
        key = ("code", reference)
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            AgentEvidenceRef(
                type="code",
                reference=reference,
                claim=link.summary,
                validated=link.relationship
                in {"confirms_missing_control", "shows_compensating_control"},
            )
        )

    for raw_ref in finding.evidence_refs:
        evidence_type = _evidence_type(raw_ref)
        key = (evidence_type, raw_ref)
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            AgentEvidenceRef(
                type=evidence_type,
                reference=raw_ref,
                claim=f"{raw_ref.replace('_', ' ')} evidence supports this review finding.",
                validated=validated,
            )
        )

    return refs


def _fix_instructions(
    finding: SecurityReviewFinding, decision: AgentReleaseDecision
) -> list[str]:
    instructions: list[str] = []
    for candidate in (
        finding.next_best_action,
        finding.next_step,
        finding.rationale_excerpt,
    ):
        if candidate and candidate not in instructions:
            instructions.append(candidate)

    if finding.needs_engineering_change:
        instructions.append(
            "Patch the affected code, configuration, or control path and rerun the review."
        )
    if finding.needs_evidence or decision == "gather_evidence":
        instructions.append(
            "Attach repository, scan, DFD, cloud, or human evidence before promoting this as validated."
        )
    if not finding.owner and decision in {"block", "fix_now", "verify"}:
        instructions.append("Assign an owner for the next review action.")

    deduped: list[str] = []
    for item in instructions:
        normalized = item.strip()
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped


def _verification(
    finding: SecurityReviewFinding, decision: AgentReleaseDecision
) -> AgentFindingVerification:
    evidence_needed: list[str] = []
    if finding.needs_evidence or decision == "gather_evidence":
        evidence_needed.append("grounded evidence chain")
    if not finding.code_links and "repository" in finding.evidence_refs:
        evidence_needed.append("exact code reference")
    if not finding.evidence_refs:
        evidence_needed.append("at least one non-AI evidence reference")

    suggested_test = finding.next_step or finding.next_best_action
    if decision == "block":
        suggested_test = suggested_test or "Reproduce the blocked path, apply the fix, then rerun review."
    elif decision == "verify":
        suggested_test = suggested_test or "Collect proof that the compensating control is active."
    elif decision == "gather_evidence":
        suggested_test = suggested_test or "Attach the missing evidence, then rerun the review."

    return AgentFindingVerification(
        required=decision != "ship",
        suggested_test=suggested_test,
        evidence_needed=evidence_needed,
    )


def _overall_decision(
    summary: SecurityReviewApplicationSummary,
    decisions: list[AgentReleaseDecision],
) -> AgentReleaseDecision:
    if "block" in decisions:
        return "block"
    if "fix_now" in decisions:
        return "fix_now"
    if "verify" in decisions:
        return "verify"
    if "gather_evidence" in decisions:
        return "gather_evidence"
    if summary.coverage.missing_evidence_sources > 0:
        return "gather_evidence"
    if "accept_risk" in decisions:
        return "accept_risk"
    return "ship"


def _decision_reason(
    decision: AgentReleaseDecision,
    summary: SecurityReviewApplicationSummary,
    decisions: list[AgentReleaseDecision],
) -> str:
    counts = Counter(decisions)
    if decision == "ship":
        return PASS_SEMANTICS
    if decision == "block":
        return f"{counts['block']} blocking finding(s) are grounded enough to stop release."
    if decision == "fix_now":
        return f"{counts['fix_now']} finding(s) require current-cycle engineering work before confidence is defensible."
    if decision == "verify":
        return f"{counts['verify']} finding(s) need control or implementation verification before release confidence improves."
    if decision == "gather_evidence":
        gaps = counts["gather_evidence"] or summary.coverage.missing_evidence_sources
        return f"{gaps} evidence gap(s) prevent a strong pass or fix decision."
    return "Only accepted-risk items remain active in the release decision set."


def build_agent_security_review_response(
    summary: SecurityReviewApplicationSummary,
    findings_response: SecurityReviewFindingListResponse,
) -> AgentSecurityReviewResponse:
    agent_findings: list[AgentSecurityReviewFinding] = []
    evidence_gaps: list[str] = []

    active_findings = [
        finding for finding in findings_response.findings if _active_for_release(finding)
    ]
    for finding in sorted(
        active_findings,
        key=lambda item: (
            _DECISION_RANK[_agent_decision_for_finding(item)],
            -item.numeric_score,
            item.title,
        ),
    ):
        decision = _agent_decision_for_finding(finding)
        if decision == "gather_evidence":
            evidence_gaps.append(finding.title)
        agent_findings.append(
            AgentSecurityReviewFinding(
                decision=decision,
                finding_id=finding.id,
                source_object_type=finding.source_object_type,
                source_object_id=finding.source_object_id,
                title=finding.title,
                priority=finding.priority,
                confidence=finding.confidence,
                risk_path=_risk_path(finding),
                evidence=_evidence_refs(finding),
                fix_instructions=_fix_instructions(finding, decision),
                verification=_verification(finding, decision),
            )
        )

    decisions = [finding.decision for finding in agent_findings]
    overall = _overall_decision(summary, decisions)
    return AgentSecurityReviewResponse(
        generated_at=findings_response.generated_at,
        system_name=findings_response.system_name,
        decision=overall,
        decision_reason=_decision_reason(overall, summary, decisions),
        pass_semantics=PASS_SEMANTICS,
        findings=agent_findings,
        evidence_gaps=evidence_gaps,
    )
