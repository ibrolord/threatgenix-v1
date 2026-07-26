from app.models.audit import ThreatAuditLog
from app.models.compliance import ComplianceMapping
from app.models.dfd import DFDEdge, DFDNode, TrustBoundary
from app.models.document import Document
from app.models.email_verification import EmailVerification
from app.models.evidence import (
    EvidenceEntity,
    EvidenceFinding,
    EvidenceFindingLink,
    EvidenceItem,
    EvidenceObservation,
    EvidenceRelationship,
    EvidenceSource,
)
from app.models.organization import Organization
from app.models.orchestration import (
    OrchestrationEvent,
    OrchestrationJob,
    OrchestrationTask,
)
from app.models.password_reset import PasswordResetToken
from app.models.scan import (
    ScanAuthorization,
    ScanExecutionArtifact,
    ScanCredential,
    ScanFinding,
    ScanJob,
    ScanTargetAuthorization,
    ScanThreatResult,
    ValidationCaseEvent,
    ValidationCaseState,
    ValidationSchedule,
    ValidationTargetBundle,
)
from app.models.threat import Threat
from app.models.threat_model import ThreatModel
from app.models.user import User
from app.models.user_provider_key import UserProviderKey

__all__ = [
    "ThreatModel",
    "Document",
    "DFDNode",
    "DFDEdge",
    "TrustBoundary",
    "Threat",
    "ThreatAuditLog",
    "ComplianceMapping",
    "EmailVerification",
    "EvidenceEntity",
    "EvidenceFinding",
    "EvidenceFindingLink",
    "EvidenceItem",
    "EvidenceObservation",
    "EvidenceRelationship",
    "EvidenceSource",
    "Organization",
    "OrchestrationEvent",
    "OrchestrationJob",
    "OrchestrationTask",
    "PasswordResetToken",
    "User",
    "UserProviderKey",
    "ScanAuthorization",
    "ScanExecutionArtifact",
    "ScanCredential",
    "ScanFinding",
    "ScanJob",
    "ScanTargetAuthorization",
    "ScanThreatResult",
    "ValidationCaseEvent",
    "ValidationCaseState",
    "ValidationSchedule",
    "ValidationTargetBundle",
]

# threat_intel models require pgvector PostgreSQL extension — import only if available
try:
    from app.models.threat_intel import (  # noqa: F401
        AttackPattern,
        AttackTechnique,
        CCSCAdvisory,
        CRIMapping,
        KEVEntry,
        ThreatIntelSync,
        WeaknessEntry,
    )

    __all__.extend(
        [
            "AttackTechnique",
            "AttackPattern",
            "WeaknessEntry",
            "CRIMapping",
            "KEVEntry",
            "CCSCAdvisory",
            "ThreatIntelSync",
        ]
    )
except ImportError:
    pass  # pgvector not installed — threat intel features unavailable
