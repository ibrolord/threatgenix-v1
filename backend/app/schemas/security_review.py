from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.environment_evidence import FindingCodeLink

FindingKind = Literal[
    "threat",
    "vulnerability",
    "drift",
    "compliance_gap",
    "control_gap",
    "evidence_gap",
    "hardening",
]
FindingSource = Literal[
    "dfd",
    "scan",
    "cloud",
    "iac",
    "repository",
    "compliance",
    "threat_intel",
    "sdlc",
    "manual",
]
SeverityLevel = Literal["Critical", "High", "Medium", "Low"]
ResidualRiskLevel = Literal["Critical", "High", "Medium", "Low", "Negligible"]
ControlEffectiveness = Literal["none", "partial", "substantial", "full"]
DataClassification = Literal["Restricted", "Confidential", "Internal", "Public"]
ScanStatus = Literal["confirmed", "mitigated", "unverifiable", "not_found"]
EvidenceStrength = Literal["strong", "partial", "weak", "missing"]
BusinessCriticality = Literal["mission_critical", "high", "moderate", "low"]
ChangeSurface = Literal["runtime", "deployment", "code", "design", "unknown"]

TruthStatus = Literal["validated", "strongly_indicated", "contextual", "theoretical"]
ExploitabilityRating = Literal["proven", "high", "medium", "low"]
ImpactRating = Literal["severe", "high", "moderate", "low"]
RegulatoryPressure = Literal["red_line", "high", "moderate", "low"]
UrgencyRating = Literal["immediate", "current_cycle", "planned", "defer"]
ActionBucket = Literal[
    "bright_red_line",
    "engineer_now",
    "verify_control",
    "fill_evidence_gap",
    "planned_hardening",
    "monitor",
]
PriorityBand = Literal["p0_blocker", "p1_now", "p2_sprint", "p3_backlog", "p4_monitor"]
NoiseDisposition = Literal["focus", "queue", "background", "suppress"]
EvidenceAdjustmentField = Literal[
    "truth_status",
    "exploitability",
    "business_impact",
    "regulatory_pressure",
    "action_bucket",
    "priority",
    "noise_disposition",
]
ReviewDeltaDisposition = Literal[
    "new", "resolved", "reopened", "escalated", "deescalated", "unchanged"
]
QueueBucket = Literal["fix_now", "verify", "gather_evidence", "backlog"]
ReviewStatus = Literal["open", "in_progress", "mitigated", "accepted", "dismissed"]
ReviewConfidence = Literal["high", "medium", "low"]
ReviewArtifactKind = Literal[
    "remediation_note", "verification_note", "evidence_request"
]
ReviewDisplayKind = Literal[
    "threat",
    "hardening",
    "misconfiguration",
    "compliance_gap",
    "control_gap",
    "evidence_gap",
    "pr_risk",
    "incident_signal",
]
ReviewPrimaryMode = Literal["review", "findings", "compliance", "model_health"]
ReviewSourceProvenance = Literal[
    "rules_engine",
    "framework_seed",
    "app_review_projection",
    "manual",
    "external_import",
]
ReviewSourceSystem = Literal["threatgenix", "external"]
ReviewSourceObjectType = Literal["threat", "application_review_finding", "manual"]
AgentReleaseDecision = Literal[
    "ship",
    "block",
    "fix_now",
    "verify",
    "gather_evidence",
    "accept_risk",
]
AgentEvidenceType = Literal[
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
]


class SecurityReviewEvidenceAdjustment(BaseModel):
    """Explicitly records how evidence changed a verdict.

    This is critical for auditability and to show users why compensating
    controls or environment evidence changed the final recommendation.
    """

    evidence_type: FindingSource
    evidence_value: str
    field_affected: EvidenceAdjustmentField
    original_value: str
    adjusted_value: str
    justification: str


class SecurityReviewAttackPath(BaseModel):
    """Rolls multiple findings into one path-level risk summary."""

    path_id: str
    finding_keys: list[str] = Field(default_factory=list)
    finding_titles: list[str] = Field(default_factory=list)
    chain_description: str
    entry_point: str | None = None
    target_asset: str | None = None
    hop_count: int = 0
    support_count: int = 0
    composite_exploitability: ExploitabilityRating
    composite_priority: PriorityBand
    path_nodes: list[str] = Field(default_factory=list)
    evidence_sources: list[FindingSource] = Field(default_factory=list)
    relationship_reasons: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)


class SecurityReviewRiskAcceptance(BaseModel):
    """Persistent acceptance state required for continuous review."""

    finding_title: str
    status: Literal["active", "expired", "reopened"]
    accepted_by: str | None = None
    accepted_at: str | None = None
    expires_at: str | None = None
    acceptance_rationale: str | None = None
    reopen_triggers: list[str] = Field(default_factory=list)


class SecurityReviewDelta(BaseModel):
    """What changed since the last review run."""

    disposition: ReviewDeltaDisposition = "unchanged"
    days_since_last_review: int | None = None
    new_findings_count: int = 0
    resolved_count: int = 0
    reopened_count: int = 0
    escalated_count: int = 0


class SecurityReviewContext(BaseModel):
    """Typed context for one review decision.

    This is intentionally broader than a threat record so the same decision layer
    can score threat findings, scan results, drift findings, compliance gaps, and
    evidence gaps without pretending they are all the same artifact.
    """

    finding_kind: FindingKind
    finding_key: str | None = None
    title: str
    description: str | None = None
    finding_sources: list[FindingSource] = Field(default_factory=list)
    affected_node_ids: list[str] = Field(default_factory=list)
    affected_edge_ids: list[str] = Field(default_factory=list)
    entry_point: str | None = None
    target_asset: str | None = None
    threat_severity: SeverityLevel | None = None
    residual_risk_level: ResidualRiskLevel | None = None
    control_effectiveness: ControlEffectiveness = "none"
    scan_status: ScanStatus | None = None
    has_known_exploited_vulnerability: bool = False
    has_exact_threat_intel: bool = False
    has_semantic_threat_intel: bool = False
    internet_facing: bool = False
    public_exposure: bool = False
    privileged_access: bool = False
    crosses_trust_boundary: bool = False
    control_plane_asset: bool = False
    crown_jewel: bool = False
    data_classification: DataClassification = "Internal"
    regulatory_scope: list[str] = Field(default_factory=list)
    business_criticality: BusinessCriticality = "moderate"
    business_capability: str | None = None
    evidence_strength: EvidenceStrength = "partial"
    change_surface: ChangeSurface = "unknown"
    active_change_window: bool = False
    compensating_controls_present: bool = False
    owner_known: bool = True
    remediation_exists: bool = False
    existing_risk_acceptance: SecurityReviewRiskAcceptance | None = None
    previous_priority: PriorityBand | None = None
    previous_truth_status: TruthStatus | None = None
    days_since_last_review: int | None = None
    code_links: list[FindingCodeLink] = Field(default_factory=list)

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("title must not be blank")
        return candidate

    @field_validator("regulatory_scope")
    @classmethod
    def _normalize_regulatory_scope(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        for item in value:
            candidate = item.strip()
            if not candidate:
                continue
            key = candidate.casefold()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(candidate)
        return normalized


class SecurityReviewScoreBreakdown(BaseModel):
    reality: int
    exploitability: int
    business_impact: int
    regulatory_pressure: int
    noise_penalty: int
    total: int


class SecurityReviewDecision(BaseModel):
    priority: PriorityBand
    action_bucket: ActionBucket
    truth_status: TruthStatus
    urgency: UrgencyRating
    exploitability: ExploitabilityRating
    business_impact: ImpactRating
    regulatory_pressure: RegulatoryPressure
    noise_disposition: NoiseDisposition
    numeric_score: int
    score_breakdown: SecurityReviewScoreBreakdown
    evidence_adjustments: list[SecurityReviewEvidenceAdjustment] = Field(
        default_factory=list
    )
    related_attack_paths: list[SecurityReviewAttackPath] = Field(default_factory=list)
    risk_acceptance: SecurityReviewRiskAcceptance | None = None
    review_delta: SecurityReviewDelta | None = None
    rationale: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class SecurityReviewBucketCount(BaseModel):
    key: str
    label: str
    count: int


class SecurityReviewFindingSummary(BaseModel):
    finding_key: str | None = None
    threat_id: str | None = None
    display_id: str | None = None
    finding_kind: FindingKind
    title: str
    priority: PriorityBand
    action_bucket: ActionBucket
    truth_status: TruthStatus
    urgency: UrgencyRating
    noise_disposition: NoiseDisposition
    numeric_score: int
    entry_point: str | None = None
    target_asset: str | None = None
    rationale_excerpt: str | None = None
    next_step: str | None = None
    related_attack_path_count: int = 0
    evidence_adjustment_count: int = 0
    systemic: bool = False


class SecurityReviewCoverageSummary(BaseModel):
    total_findings: int = 0
    threat_findings: int = 0
    systemic_findings: int = 0
    open_threats: int = 0
    public_entry_points: int = 0
    privileged_surfaces: int = 0
    restricted_assets: int = 0
    attack_paths: int = 0
    attached_evidence_sources: int = 0
    missing_evidence_sources: int = 0


class SecurityReviewRiskAcceptanceSummary(BaseModel):
    active: int = 0
    reopened: int = 0
    expired: int = 0


class SecurityReviewDeltaSummary(BaseModel):
    new_findings: int = 0
    resolved_findings: int = 0
    reopened_findings: int = 0
    escalated_findings: int = 0
    deescalated_findings: int = 0


class SecurityReviewApplicationSummary(BaseModel):
    generated_at: str
    system_name: str
    overall_priority: PriorityBand
    overall_action_bucket: ActionBucket
    focus_statement: str
    rationale: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    coverage: SecurityReviewCoverageSummary = Field(
        default_factory=SecurityReviewCoverageSummary
    )
    priority_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    action_bucket_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    truth_status_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    noise_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    top_findings: list[SecurityReviewFindingSummary] = Field(default_factory=list)
    blind_spots: list[SecurityReviewFindingSummary] = Field(default_factory=list)
    attack_paths: list[SecurityReviewAttackPath] = Field(default_factory=list)
    risk_acceptance_summary: SecurityReviewRiskAcceptanceSummary = Field(
        default_factory=SecurityReviewRiskAcceptanceSummary
    )
    review_delta_summary: SecurityReviewDeltaSummary = Field(
        default_factory=SecurityReviewDeltaSummary
    )


class SecurityReviewStateRecord(BaseModel):
    id: str
    source_object_type: ReviewSourceObjectType
    source_object_id: str
    queue_bucket: QueueBucket | None = None
    review_status: ReviewStatus | None = None
    last_non_terminal_bucket: QueueBucket | None = None
    owner: str | None = None
    due_at: str | None = None
    note: str | None = None
    artifacts: list["SecurityReviewArtifact"] = Field(default_factory=list)
    created_at: str
    updated_at: str


class SecurityReviewStateUpdate(BaseModel):
    queue_bucket: QueueBucket | None = None
    review_status: ReviewStatus | None = None
    last_non_terminal_bucket: QueueBucket | None = None
    owner: str | None = None
    due_at: str | None = None
    note: str | None = None
    artifacts: list["SecurityReviewArtifact"] | None = None


class SecurityReviewArtifact(BaseModel):
    id: str
    kind: ReviewArtifactKind
    title: str
    summary: str
    body: str
    created_at: str


class SecurityReviewArtifactCreate(BaseModel):
    kind: ReviewArtifactKind


class SecurityReviewFinding(BaseModel):
    id: str
    source_object_type: ReviewSourceObjectType
    source_object_id: str
    threat_id: str | None = None
    display_id: str | None = None
    wire_kind: FindingKind | Literal["pr_risk", "incident_signal"]
    display_kind: ReviewDisplayKind
    source_provenance: ReviewSourceProvenance
    source_system: ReviewSourceSystem = "threatgenix"
    title: str
    priority: PriorityBand
    numeric_score: int = 0
    wire_action_bucket: ActionBucket | None = None
    queue_bucket: QueueBucket | None = None
    computed_queue_bucket: QueueBucket | None = None
    truth_status: TruthStatus | None = None
    exploitability: ExploitabilityRating | None = None
    urgency: UrgencyRating | None = None
    business_impact: ImpactRating | None = None
    regulatory_pressure: RegulatoryPressure | None = None
    confidence: ReviewConfidence
    is_real: bool = False
    is_urgent: bool = False
    is_exploitable_in_context: bool = False
    is_regulatory_or_control_relevant: bool = False
    needs_engineering_change: bool = False
    needs_evidence: bool = False
    why_now: str
    impacted_assets: list[str] = Field(default_factory=list)
    entry_point: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    linked_threat_ids: list[str] = Field(default_factory=list)
    linked_change_ids: list[str] = Field(default_factory=list)
    linked_control_ids: list[str] = Field(default_factory=list)
    code_links: list[FindingCodeLink] = Field(default_factory=list)
    owner: str | None = None
    due_at: str | None = None
    note: str | None = None
    artifacts: list[SecurityReviewArtifact] = Field(default_factory=list)
    review_status: ReviewStatus
    last_non_terminal_bucket: QueueBucket | None = None
    primary_mode: ReviewPrimaryMode
    noise_disposition: NoiseDisposition
    computed_recommendation_changed: bool = False
    systemic: bool = False
    next_best_action: str | None = None
    next_step: str | None = None
    rationale_excerpt: str | None = None


class SecurityReviewFindingListResponse(BaseModel):
    generated_at: str
    system_name: str
    queue_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    review_status_counts: list[SecurityReviewBucketCount] = Field(default_factory=list)
    default_finding_id: str | None = None
    findings: list[SecurityReviewFinding] = Field(default_factory=list)


class AgentEvidenceRef(BaseModel):
    type: AgentEvidenceType = "unknown"
    reference: str
    claim: str
    validated: bool = False


class AgentFindingVerification(BaseModel):
    required: bool
    suggested_test: str | None = None
    evidence_needed: list[str] = Field(default_factory=list)


class AgentSecurityReviewFinding(BaseModel):
    decision: AgentReleaseDecision
    finding_id: str
    source_object_type: ReviewSourceObjectType
    source_object_id: str
    title: str
    priority: PriorityBand
    confidence: ReviewConfidence
    risk_path: list[str] = Field(default_factory=list)
    evidence: list[AgentEvidenceRef] = Field(default_factory=list)
    fix_instructions: list[str] = Field(default_factory=list)
    verification: AgentFindingVerification


class AgentSecurityReviewResponse(BaseModel):
    generated_at: str
    system_name: str
    decision: AgentReleaseDecision
    decision_reason: str
    pass_semantics: str
    findings: list[AgentSecurityReviewFinding] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)


SecurityReviewContext.model_rebuild()
SecurityReviewDecision.model_rebuild()
SecurityReviewApplicationSummary.model_rebuild()
