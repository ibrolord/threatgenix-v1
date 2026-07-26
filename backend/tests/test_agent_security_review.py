from app.schemas.security_review import (
    SecurityReviewApplicationSummary,
    SecurityReviewCoverageSummary,
    SecurityReviewFinding,
    SecurityReviewFindingListResponse,
)
from app.services.agent_security_review import build_agent_security_review_response


def _summary(*, missing_evidence_sources: int = 0) -> SecurityReviewApplicationSummary:
    return SecurityReviewApplicationSummary(
        generated_at="2026-04-30T20:00:00Z",
        system_name="Payments",
        overall_priority="p1_now",
        overall_action_bucket="engineer_now",
        focus_statement="Review the release decision.",
        coverage=SecurityReviewCoverageSummary(
            total_findings=1,
            attached_evidence_sources=1,
            missing_evidence_sources=missing_evidence_sources,
        ),
    )


def _finding(**overrides) -> SecurityReviewFinding:
    data = {
        "id": "threat:finding-1",
        "source_object_type": "threat",
        "source_object_id": "finding-1",
        "threat_id": "finding-1",
        "display_id": "T-001",
        "wire_kind": "threat",
        "display_kind": "threat",
        "source_provenance": "rules_engine",
        "source_system": "threatgenix",
        "title": "Public route writes tenant data",
        "priority": "p0_blocker",
        "numeric_score": 92,
        "wire_action_bucket": "bright_red_line",
        "queue_bucket": "fix_now",
        "computed_queue_bucket": "fix_now",
        "truth_status": "validated",
        "exploitability": "high",
        "urgency": "immediate",
        "business_impact": "severe",
        "regulatory_pressure": "red_line",
        "confidence": "high",
        "is_real": True,
        "is_urgent": True,
        "is_exploitable_in_context": True,
        "is_regulatory_or_control_relevant": True,
        "needs_engineering_change": True,
        "needs_evidence": False,
        "why_now": "Public route reaches tenant data.",
        "impacted_assets": ["Tenant data"],
        "entry_point": "POST /api/share",
        "evidence_refs": ["repository", "dfd"],
        "linked_threat_ids": ["finding-1"],
        "linked_change_ids": [],
        "linked_control_ids": [],
        "code_links": [],
        "owner": None,
        "due_at": None,
        "note": None,
        "artifacts": [],
        "review_status": "open",
        "last_non_terminal_bucket": None,
        "primary_mode": "findings",
        "noise_disposition": "focus",
        "computed_recommendation_changed": False,
        "systemic": False,
        "next_best_action": "Require authentication and tenant ownership checks.",
        "next_step": "Add regression coverage for cross-tenant access.",
        "rationale_excerpt": "Validated public route reaches tenant data.",
    }
    data.update(overrides)
    return SecurityReviewFinding(**data)


def _findings_response(*findings: SecurityReviewFinding) -> SecurityReviewFindingListResponse:
    return SecurityReviewFindingListResponse(
        generated_at="2026-04-30T20:00:00Z",
        system_name="Payments",
        findings=list(findings),
    )


def test_agent_release_decision_blocks_only_when_grounded() -> None:
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(_finding()),
    )

    assert response.decision == "block"
    assert response.findings[0].decision == "block"
    assert response.findings[0].risk_path == [
        "POST /api/share",
        "Tenant data",
        "Public route writes tenant data",
    ]
    assert {item.type for item in response.findings[0].evidence} == {
        "repository",
        "dfd",
    }
    assert "does not certify" in response.pass_semantics


def test_agent_release_decision_downgrades_ungrounded_blockers_to_evidence_gap() -> None:
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(
            _finding(
                truth_status="theoretical",
                evidence_refs=[],
                code_links=[],
                confidence="low",
            )
        ),
    )

    assert response.decision == "gather_evidence"
    assert response.findings[0].decision == "gather_evidence"
    assert response.evidence_gaps == ["Public route writes tenant data"]
    assert response.findings[0].verification.required is True
    assert "at least one non-AI evidence reference" in response.findings[0].verification.evidence_needed


def test_agent_release_decision_uses_precise_ship_semantics() -> None:
    response = build_agent_security_review_response(
        _summary(),
        _findings_response(
            _finding(
                priority="p4_monitor",
                wire_action_bucket="monitor",
                queue_bucket=None,
                computed_queue_bucket="backlog",
                review_status="mitigated",
                needs_engineering_change=False,
                truth_status="validated",
            )
        ),
    )

    assert response.decision == "ship"
    assert response.findings == []
    assert response.decision_reason == response.pass_semantics
