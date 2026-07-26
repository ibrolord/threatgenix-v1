"""Tests for threats generate, list, filter, summary, and triage endpoints (Block B19 + B13 + F-11)."""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.schemas.rules import GeneratedThreat, RuleEngineOutput
from app.schemas.security_review import (
    SecurityReviewApplicationSummary,
    SecurityReviewArtifact,
    SecurityReviewCoverageSummary,
    SecurityReviewDecision,
    SecurityReviewFinding,
    SecurityReviewFindingListResponse,
    SecurityReviewScoreBreakdown,
)
from app.schemas.threat import ThreatIntelResponse
from app.services.auth import get_current_user
from app.api.threats import _require_owner, _require_read_access, _require_review_access, _security_review_intel_candidates

BASE_URL = "http://test"

FAKE_USER_ID = uuid.uuid4()


class FakeUser:
    id = FAKE_USER_ID
    email = "test@example.com"
    full_name = "Test User"
    role = "admin"
    is_active = True


async def override_get_db():
    yield AsyncMock()


async def override_get_current_user():
    return FakeUser()


async def override_require_owner(threat_model_id: uuid.UUID):
    return FakeUser()


async def override_require_read_access(threat_model_id: uuid.UUID):
    return FakeUser()


async def override_require_review_access(threat_model_id: uuid.UUID):
    return FakeUser()


app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user
app.dependency_overrides[_require_owner] = override_require_owner
app.dependency_overrides[_require_read_access] = override_require_read_access
app.dependency_overrides[_require_review_access] = override_require_review_access


def _generate_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/threats/generate"


def _list_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/threats"


def _summary_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/threats/summary"


def _residual_summary_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/threats/residual-summary"


def _triage_url(threat_model_id: uuid.UUID, threat_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/threats/{threat_id}/triage"


def _intel_url(threat_model_id: uuid.UUID, threat_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/threats/{threat_id}/intel"


def test_security_review_intel_candidates_prioritize_confirmed_scan_and_cap_work():
    confirmed_id = uuid.uuid4()
    dismissed_id = uuid.uuid4()
    threats = [
        SimpleNamespace(
            id=uuid.uuid4(),
            status="Open",
            severity="Medium",
            display_id="T-002",
        ),
        SimpleNamespace(
            id=confirmed_id,
            status="Open",
            severity="High",
            display_id="T-010",
        ),
        SimpleNamespace(
            id=uuid.uuid4(),
            status="Open",
            severity="Critical",
            display_id="T-001",
        ),
        SimpleNamespace(
            id=dismissed_id,
            status="Dismissed",
            severity="Critical",
            display_id="T-000",
        ),
    ]

    candidates = _security_review_intel_candidates(
        threats,
        {str(confirmed_id): "confirmed"},
        limit=2,
    )

    assert [item.id for item in candidates] == [confirmed_id, threats[2].id]
    assert dismissed_id not in {item.id for item in candidates}


def _review_url(threat_model_id: uuid.UUID, threat_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/threats/{threat_id}/review"


def _application_review_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/review"


def _review_findings_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/review-findings"


def _agent_release_decision_url(threat_model_id: uuid.UUID) -> str:
    return f"/api/threat-models/{threat_model_id}/agent/release-decision"


class FakeThreatModel:
    def __init__(self, id=None, owner_id=None):
        self.id = id or uuid.uuid4()
        self.system_name = "Test System"
        self.description = ""
        self.data_classification = "Internal"
        self.owner_id = owner_id or FAKE_USER_ID
        self.collaborators = None
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)


def _make_fake_nodes_edges_boundaries():
    """Create fake DFD data that the rules engine can process."""
    node_id_1 = uuid.uuid4()
    node_id_2 = uuid.uuid4()
    edge_id = uuid.uuid4()
    boundary_id = uuid.uuid4()

    class FakeNode:
        id = node_id_1
        node_type = "process"
        name = "API Gateway"
        position_x = 0.0
        position_y = 0.0
        trust_boundary_id = None
        properties = {}

    class FakeNode2:
        id = node_id_2
        node_type = "data_store"
        name = "User DB"
        position_x = 120.0
        position_y = 0.0
        trust_boundary_id = None
        properties = {}

    class FakeEdge:
        id = edge_id
        source_node_id = node_id_1
        target_node_id = node_id_2
        label = "query"
        properties = {}

    class FakeBoundary:
        id = boundary_id
        name = "DMZ"
        node_ids = [node_id_1]

    return [FakeNode(), FakeNode2()], [FakeEdge()], [FakeBoundary()]


def _make_rule_engine_output() -> RuleEngineOutput:
    return RuleEngineOutput(
        threats=[
            GeneratedThreat(
                rule_id="S-01",
                display_id="T-001",
                stride_category="Spoofing",
                threat_subtype="Identity Spoofing",
                severity="High",
                description="An attacker may spoof the API Gateway.",
                affected_node_ids=[str(uuid.uuid4())],
                affected_edge_ids=[str(uuid.uuid4())],
                source="Rules",
            ),
        ],
        execution_time_ms=1.5,
        rules_evaluated=10,
        rules_fired=1,
    )


def _mock_db_with_dfd(nodes, edges, boundaries):
    """Create a mock DB that returns DFD data across sequential execute calls."""
    call_count = 0

    async def mock_execute(stmt, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_scalars = MagicMock()
        if call_count == 1:
            mock_scalars.all.return_value = nodes
        elif call_count == 2:
            mock_scalars.all.return_value = edges
        else:
            mock_scalars.all.return_value = boundaries
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    mock_db.add = MagicMock()
    return mock_db


def _mock_db_empty():
    """Create a mock DB that returns empty results for nodes (first query)."""

    async def mock_execute(stmt):
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    return mock_db


# ─── POST /threats/generate Tests ──────────────────────────────────


@pytest.mark.asyncio
async def test_generate_threats_with_valid_dfd_returns_200():
    """POST generate with valid DFD -> 200, non-empty threats."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_output = _make_rule_engine_output()

    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_output),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_generate_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert len(body["threats"]) == 1
    assert body["threats"][0]["rule_id"] == "S-01"
    assert body["threats"][0]["display_id"] == "T-001"
    assert body["rules_evaluated"] == 10
    assert body["rules_fired"] == 1


@pytest.mark.asyncio
async def test_generate_threats_no_dfd_returns_400():
    """POST generate with no DFD -> 400."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    mock_db = _mock_db_empty()

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_generate_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 400
    assert "No DFD found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_generate_threats_rules_failure_does_not_persist_partial_work():
    """Rules-engine failures should fail before deleting or committing threats."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)
    added_objects = []
    mock_db.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", side_effect=RuntimeError("rule pack unavailable")),
    ):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_generate_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 500
    assert added_objects == []
    mock_db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_generate_threats_invalid_threat_model_returns_404():
    """POST generate with invalid threat_model_id -> 404."""
    tm_id = uuid.uuid4()

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=None
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_generate_url(tm_id))

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


@pytest.mark.asyncio
async def test_generate_threats_persists_to_db():
    """POST generate persists threats via db.add and db.commit."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_output = _make_rule_engine_output()

    mock_db = _mock_db_with_dfd(nodes, edges, boundaries)
    added_objects = []
    mock_db.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.evaluate_rules", return_value=fake_output),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(_generate_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    # One threat was generated, so one object should have been added
    assert len(added_objects) == 1
    assert added_objects[0].source == "Rules"
    assert added_objects[0].status == "Open"
    assert added_objects[0].rule_id == "S-01"
    mock_db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_generate_threats_idempotent():
    """POST generate twice -> idempotent (deletes old threats, same count)."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    nodes, edges, boundaries = _make_fake_nodes_edges_boundaries()
    fake_output = _make_rule_engine_output()

    # Run generate twice and verify delete is called each time
    for _ in range(2):
        mock_db = _mock_db_with_dfd(nodes, edges, boundaries)

        async def db_override():
            yield mock_db

        app.dependency_overrides[get_db] = db_override

        with (
            patch(
                "app.api.threats.get_threat_model",
                new_callable=AsyncMock,
                return_value=fake_tm,
            ),
            patch("app.api.threats.evaluate_rules", return_value=fake_output),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
                response = await client.post(_generate_url(tm_id))

        assert response.status_code == 200
        body = response.json()
        assert len(body["threats"]) == 1

    app.dependency_overrides[get_db] = override_get_db


# ─── GET /threats Tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_threats_empty_returns_200():
    """GET threats before generate -> empty list."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_list_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_threats_returns_persisted_threats():
    """GET threats after generate -> returns persisted threats."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    threat_id = uuid.uuid4()
    node_id = uuid.uuid4()
    now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)

    class FakeThreat:
        id = threat_id
        display_id = "T-001"
        description = "An attacker may spoof the API Gateway."
        stride_category = "Spoofing"
        severity = "High"
        source = "Rules"
        status = "Open"
        dismiss_reason = None
        rule_id = "S-01"
        ai_enhanced = False
        original_rule_threat_id = None
        affected_node_ids = [node_id]
        affected_edge_ids = []
        mitigation_plan = None
        mitigation_owner = None
        due_date = None
        mitigation_notes = None
        closed_at = None
        created_at = now

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [FakeThreat()]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_list_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["display_id"] == "T-001"
    assert body[0]["stride_category"] == "Spoofing"
    assert body[0]["source"] == "Rules"
    assert body[0]["status"] == "Open"
    assert body[0]["control_effectiveness"] == "none"
    assert body[0]["residual_risk_level"] == "High"
    assert body[0]["rule_id"] == "S-01"


@pytest.mark.asyncio
async def test_list_threats_includes_latest_scan_status():
    """GET threats includes the latest scan verdict used by the main table filters."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    threat_id = uuid.uuid4()
    now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)

    class FakeThreat:
        id = threat_id
        display_id = "T-001"
        description = "Partner callback spoofing."
        stride_category = "Spoofing"
        severity = "High"
        source = "Manual"
        status = "Open"
        dismiss_reason = None
        rule_id = None
        ai_enhanced = False
        original_rule_threat_id = None
        affected_node_ids = []
        affected_edge_ids = []
        mitigation_plan = None
        mitigation_owner = None
        due_date = None
        mitigation_notes = None
        closed_at = None
        created_at = now

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [FakeThreat()]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats._latest_scan_status_by_threat_id",
            new_callable=AsyncMock,
            return_value={str(threat_id): "confirmed"},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_list_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body[0]["display_id"] == "T-001"
    assert body[0]["scan_status"] == "confirmed"


@pytest.mark.asyncio
async def test_list_threats_invalid_threat_model_returns_404():
    """GET threats for non-existent threat model -> 404."""
    tm_id = uuid.uuid4()

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=None
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_list_url(tm_id))

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


# ─── B13: STRIDE filter + summary Tests ──────────────────────────────


def _make_fake_threats():
    """Create a list of fake threats with diverse STRIDE/severity/status values."""
    now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)

    class FakeThreat:
        def __init__(self, display_id, stride_category, severity, status):
            self.id = uuid.uuid4()
            self.display_id = display_id
            self.description = f"Threat {display_id}"
            self.stride_category = stride_category
            self.severity = severity
            self.source = "Rules"
            self.status = status
            self.dismiss_reason = None
            self.rule_id = "R-01"
            self.ai_enhanced = False
            self.original_rule_threat_id = None
            self.affected_node_ids = []
            self.affected_edge_ids = []
            self.mitigation_plan = None
            self.mitigation_owner = None
            self.due_date = None
            self.mitigation_notes = None
            self.control_effectiveness = "none"
            self.residual_risk_level = None
            self.provider_managed = False
            self.closed_at = None
            self.created_at = now

    return [
        FakeThreat("T-001", "Spoofing", "High", "Open"),
        FakeThreat("T-002", "Spoofing", "Medium", "Accepted"),
        FakeThreat("T-003", "Tampering", "Critical", "Open"),
        FakeThreat("T-004", "Denial of Service", "Low", "Dismissed"),
    ]


@pytest.mark.asyncio
async def test_list_threats_with_stride_filter_returns_filtered():
    """GET threats with stride_category=Spoofing returns only Spoofing threats."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    all_threats = _make_fake_threats()
    spoofing_threats = [t for t in all_threats if t.stride_category == "Spoofing"]

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = spoofing_threats
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(
                _list_url(tm_id), params={"stride_category": "Spoofing"}
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert all(t["stride_category"] == "Spoofing" for t in body)


@pytest.mark.asyncio
async def test_list_threats_without_filter_returns_all():
    """GET threats without stride_category returns all threats."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    all_threats = _make_fake_threats()

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = all_threats
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_list_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 4


@pytest.mark.asyncio
async def test_summary_returns_correct_counts():
    """GET summary returns correct by_stride, by_severity, by_status counts."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    all_threats = _make_fake_threats()

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = all_threats
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_summary_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 4
    assert body["by_stride"] == {"Spoofing": 2, "Tampering": 1, "Denial of Service": 1}
    assert body["by_severity"] == {"High": 1, "Medium": 1, "Critical": 1, "Low": 1}
    assert body["by_status"] == {"Open": 2, "Accepted": 1, "Dismissed": 1}


@pytest.mark.asyncio
async def test_summary_empty_threats_returns_zeros():
    """GET summary for empty threats returns total=0 and empty dicts."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_summary_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 0
    assert body["by_stride"] == {}
    assert body["by_severity"] == {}
    assert body["by_status"] == {}


@pytest.mark.asyncio
async def test_summary_invalid_threat_model_returns_404():
    """GET summary for non-existent threat model -> 404."""
    tm_id = uuid.uuid4()

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=None
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_summary_url(tm_id))

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


@pytest.mark.asyncio
async def test_residual_summary_returns_derived_counts():
    """GET residual summary derives risk levels from severity and control effectiveness."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    all_threats = _make_fake_threats()
    all_threats[0].control_effectiveness = "none"
    all_threats[0].residual_risk_level = None
    all_threats[1].control_effectiveness = "none"
    all_threats[1].residual_risk_level = None
    all_threats[2].control_effectiveness = "substantial"
    all_threats[2].residual_risk_level = "Low"

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = all_threats[:3]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_residual_summary_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["by_level"] == {
        "Critical": 0,
        "High": 1,
        "Medium": 1,
        "Low": 1,
        "Negligible": 0,
    }


# ─── PATCH /threats/{threat_id}/triage Tests (F-11) ─────────────────


def _make_single_fake_threat(threat_model_id: uuid.UUID, threat_id: uuid.UUID):
    """Create a mutable fake threat object for triage tests."""
    now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)

    class FakeThreat:
        def __init__(self):
            self.id = threat_id
            self.threat_model_id = threat_model_id
            self.display_id = "T-001"
            self.description = "An attacker may spoof the API Gateway."
            self.stride_category = "Spoofing"
            self.threat_subtype = None
            self.severity = "High"
            self.source = "Rules"
            self.status = "Open"
            self.dismiss_reason = None
            self.rule_id = "S-01"
            self.ai_enhanced = False
            self.original_rule_threat_id = None
            self.affected_node_ids = []
            self.affected_edge_ids = []
            self.mitigation_plan = None
            self.mitigation_owner = None
            self.due_date = None
            self.mitigation_notes = None
            self.control_effectiveness = "none"
            self.residual_risk_level = None
            self.provider_managed = False
            self.closed_at = None
            self.created_at = now
            self.updated_at = now

    return FakeThreat()


def _mock_db_for_triage(fake_threat):
    """Create a mock DB that returns a single threat from execute, supports refresh."""
    mock_db = AsyncMock()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = fake_threat
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.add = MagicMock()

    async def mock_refresh(obj):
        pass  # no-op; the object is already mutated in-place

    mock_db.refresh = mock_refresh

    return mock_db


def _mock_db_for_detail(fake_threat):
    """Create a mock DB that returns a single threat for detail/intel routes."""
    mock_db = AsyncMock()

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = fake_threat
    mock_db.execute = AsyncMock(return_value=mock_result)

    return mock_db


def _mock_db_for_review(fake_threats, nodes, edges, scan_rows):
    """Create a mock DB for threat review route sequencing."""

    call_count = 0

    async def mock_execute(stmt, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_scalars = MagicMock()
        if call_count == 1:
            mock_scalars.all.return_value = fake_threats
        elif call_count == 2:
            mock_scalars.all.return_value = nodes
        elif call_count == 3:
            mock_scalars.all.return_value = edges
        else:
            mock_scalars.all.return_value = scan_rows
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    return mock_db


def _mock_db_for_application_review(fake_threats, nodes, edges, boundaries, scan_rows):
    """Create a mock DB for application review route sequencing."""

    call_count = 0

    async def mock_execute(stmt, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_scalars = MagicMock()
        if call_count == 1:
            mock_scalars.all.return_value = fake_threats
        elif call_count == 2:
            mock_scalars.all.return_value = nodes
        elif call_count == 3:
            mock_scalars.all.return_value = edges
        elif call_count == 4:
            mock_scalars.all.return_value = boundaries
        else:
            mock_scalars.all.return_value = scan_rows
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        return mock_result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    return mock_db


@pytest.mark.asyncio
async def test_triage_accept_sets_status_and_clears_dismiss_reason():
    """PATCH triage accept -> status=Accepted, dismiss_reason=None."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    mock_db = _mock_db_for_triage(fake_threat)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.lookup_controls_batch",
            new_callable=AsyncMock,
            return_value={},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={"status": "Accepted"},
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "Accepted"
    assert body["dismiss_reason"] is None
    audit_entry = mock_db.add.call_args.args[0]
    assert audit_entry.action == "triaged"
    assert audit_entry.reason == "Status changed to Accepted"


@pytest.mark.asyncio
async def test_triage_dismiss_with_reason_sets_status_and_reason():
    """PATCH triage dismiss with reason -> status=Dismissed, dismiss_reason set."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    mock_db = _mock_db_for_triage(fake_threat)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.lookup_controls_batch",
            new_callable=AsyncMock,
            return_value={},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={"status": "Dismissed", "dismiss_reason": "False positive"},
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "Dismissed"
    assert body["dismiss_reason"] == "False positive"


@pytest.mark.asyncio
async def test_triage_dismiss_without_reason_returns_400():
    """PATCH triage dismiss without dismiss_reason -> 400."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    mock_db = _mock_db_for_triage(fake_threat)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.lookup_controls_batch",
            new_callable=AsyncMock,
            return_value={},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={"status": "Dismissed"},
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 400
    assert "dismiss_reason" in response.json()["detail"]


@pytest.mark.asyncio
async def test_triage_updates_control_effectiveness_and_derives_residual_risk():
    """PATCH triage with control effectiveness derives residual risk and persists both fields."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    fake_threat.control_effectiveness = "none"
    fake_threat.residual_risk_level = None
    mock_db = _mock_db_for_triage(fake_threat)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.lookup_controls_batch",
            new_callable=AsyncMock,
            return_value={},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={"status": "In Progress", "control_effectiveness": "partial"},
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "In Progress"
    assert body["control_effectiveness"] == "partial"
    assert body["residual_risk_level"] == "Medium"


@pytest.mark.asyncio
async def test_triage_updates_severity_and_recomputes_residual_risk():
    """PATCH triage with severity override persists it and recomputes residual risk."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    fake_threat.severity = "High"
    fake_threat.control_effectiveness = "partial"
    fake_threat.residual_risk_level = "Medium"
    mock_db = _mock_db_for_triage(fake_threat)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.lookup_controls_batch",
            new_callable=AsyncMock,
            return_value={},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={"status": "In Progress", "severity": "Critical"},
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["severity"] == "Critical"
    assert body["control_effectiveness"] == "partial"
    assert body["residual_risk_level"] == "High"
    assert fake_threat.severity == "Critical"


@pytest.mark.asyncio
async def test_triage_persists_audit_entries_for_real_review_changes():
    """Triage should keep status, owner, control, and severity changes audit-visible."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    fake_threat.severity = "High"
    fake_threat.control_effectiveness = "none"
    fake_threat.mitigation_owner = None
    mock_db = _mock_db_for_triage(fake_threat)
    added_objects = []
    mock_db.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.lookup_controls_batch",
            new_callable=AsyncMock,
            return_value={},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={
                    "status": "In Progress",
                    "severity": "Critical",
                    "mitigation_owner": "secops-oncall",
                    "control_effectiveness": "partial",
                },
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    actions = [item.action for item in added_objects]
    assert actions == [
        "triaged",
        "mitigation_assigned",
        "control_effectiveness_updated",
        "severity_updated",
    ]
    assert added_objects[0].old_status == "Open"
    assert added_objects[0].new_status == "In Progress"
    assert added_objects[0].reason == "Status changed to In Progress"
    assert added_objects[1].reason == "Assigned to: secops-oncall"
    assert added_objects[2].reason == "none -> partial"
    assert added_objects[3].old_status == "High"
    assert added_objects[3].new_status == "Critical"
    assert added_objects[3].reason == "High -> Critical"
    mock_db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_triage_honors_explicit_residual_risk_override():
    """PATCH triage honors an explicit residual_risk_level instead of recomputing it."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    fake_threat.control_effectiveness = "none"
    fake_threat.residual_risk_level = None
    mock_db = _mock_db_for_triage(fake_threat)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.lookup_controls_batch",
            new_callable=AsyncMock,
            return_value={},
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={
                    "status": "In Progress",
                    "control_effectiveness": "partial",
                    "residual_risk_level": "Low",
                },
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["control_effectiveness"] == "partial"
    assert body["residual_risk_level"] == "Low"


@pytest.mark.asyncio
async def test_triage_invalid_threat_model_returns_404():
    """PATCH triage with invalid threat_model_id -> 404."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=None
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={"status": "Accepted"},
            )

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat model not found"


@pytest.mark.asyncio
async def test_triage_invalid_threat_id_returns_404():
    """PATCH triage with invalid threat_id -> 404."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    # DB returns None for the threat query
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                _triage_url(tm_id, threat_id),
                json={"status": "Accepted"},
            )

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 404
    assert response.json()["detail"] == "Threat not found"


@pytest.mark.asyncio
async def test_get_threat_intel_returns_payload():
    """GET threat intel returns the structured enrichment payload."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    mock_db = _mock_db_for_detail(fake_threat)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    fake_intel = ThreatIntelResponse(
        local_severity="High",
        highest_external_severity="Medium",
        semantic_matches_inferred=True,
        scan_cve_ids=["CVE-2026-1000"],
        severity_signals=[],
        attack_techniques=[],
        attack_patterns=[],
        weaknesses=[],
        advisories=[],
        kev_entries=[],
        cri_controls=[],
    )

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.build_threat_intel_response",
            new_callable=AsyncMock,
            return_value=fake_intel,
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_intel_url(tm_id, threat_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["local_severity"] == "High"
    assert body["highest_external_severity"] == "Medium"
    assert body["scan_cve_ids"] == ["CVE-2026-1000"]


@pytest.mark.asyncio
async def test_get_threat_intel_gracefully_degrades_on_failure():
    """GET threat intel should degrade instead of 500ing when enrichment fails."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    mock_db = _mock_db_for_detail(fake_threat)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.build_threat_intel_response",
            new_callable=AsyncMock,
            side_effect=RuntimeError("vector unavailable"),
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_intel_url(tm_id, threat_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["local_severity"] == "High"
    assert body["unavailable_reason"] == "Threat intelligence temporarily unavailable."


@pytest.mark.asyncio
async def test_get_threat_review_returns_deterministic_decision():
    """GET threat review returns the deterministic review-engine payload."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    related_threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    fake_related_threat = _make_single_fake_threat(tm_id, related_threat_id)
    fake_related_threat.display_id = "T-002"
    fake_related_threat.description = "A related vault exposure exists."

    class FakeNode:
        def __init__(self, node_id: uuid.UUID, name: str, node_type: str):
            self.id = node_id
            self.name = name
            self.node_type = node_type
            self.properties = {}

    class FakeEdge:
        def __init__(
            self,
            edge_id: uuid.UUID,
            source_node_id: uuid.UUID,
            target_node_id: uuid.UUID,
        ):
            self.id = edge_id
            self.source_node_id = source_node_id
            self.target_node_id = target_node_id

    node_api = FakeNode(uuid.uuid4(), "Public API", "process")
    node_vault = FakeNode(uuid.uuid4(), "Token Vault", "data_store")
    edge = FakeEdge(uuid.uuid4(), node_api.id, node_vault.id)
    fake_threat.affected_node_ids = [node_api.id]
    fake_related_threat.affected_node_ids = [node_api.id, node_vault.id]
    fake_related_threat.affected_edge_ids = [edge.id]

    mock_db = _mock_db_for_review(
        [fake_threat, fake_related_threat],
        [node_api, node_vault],
        [edge],
        [],
    )

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    fake_decision = SecurityReviewDecision(
        priority="p1_now",
        action_bucket="engineer_now",
        truth_status="validated",
        urgency="current_cycle",
        exploitability="high",
        business_impact="high",
        regulatory_pressure="moderate",
        noise_disposition="focus",
        numeric_score=72,
        score_breakdown=SecurityReviewScoreBreakdown(
            reality=70,
            exploitability=68,
            business_impact=74,
            regulatory_pressure=36,
            noise_penalty=5,
            total=72,
        ),
        related_attack_paths=[],
        rationale=["The path is externally reachable."],
        next_steps=["Create a current-cycle engineering task."],
    )

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.build_threat_intel_response",
            new_callable=AsyncMock,
            return_value=ThreatIntelResponse(local_severity="High"),
        ),
        patch(
            "app.api.threats.evaluate_threat_security_reviews",
            return_value={
                str(threat_id): fake_decision,
                str(related_threat_id): fake_decision,
            },
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_review_url(tm_id, threat_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["priority"] == "p1_now"
    assert body["action_bucket"] == "engineer_now"
    assert body["numeric_score"] == 72


@pytest.mark.asyncio
async def test_get_threat_review_invalid_threat_returns_404():
    """GET threat review returns 404 when the threat is not in the model."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    mock_db = _mock_db_for_review([], [], [], [])

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_review_url(tm_id, threat_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 404
    assert response.json()["detail"] == "No threats found for this model"


@pytest.mark.asyncio
async def test_get_application_review_returns_summary():
    """GET application review returns the deterministic application summary."""
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.repository_evidence = None
    fake_tm.cloud_scan_evidence = None
    fake_tm.iac_evidence = None
    fake_tm.environment_context_summary = None
    fake_tm.regulatory_scope = ["PCI DSS"]
    fake_tm.deployment_model = "cloud"

    fake_threat = _make_single_fake_threat(tm_id, threat_id)
    mock_db = _mock_db_for_application_review([fake_threat], [], [], [], [])

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    fake_summary = SecurityReviewApplicationSummary(
        generated_at="2026-04-18T12:00:00Z",
        system_name="Test System",
        overall_priority="p1_now",
        overall_action_bucket="engineer_now",
        focus_statement="This application has immediate work in both active findings and systemic blind spots.",
        rationale=["The application review found high-signal work."],
        next_steps=["Assign an owner."],
        coverage=SecurityReviewCoverageSummary(
            total_findings=3,
            threat_findings=1,
            systemic_findings=2,
            open_threats=1,
            public_entry_points=0,
            privileged_surfaces=0,
            restricted_assets=0,
            attack_paths=0,
            attached_evidence_sources=0,
            missing_evidence_sources=4,
        ),
    )

    with (
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.build_application_security_review",
            return_value=fake_summary,
        ),
        patch(
            "app.api.threats.build_threat_intel_response",
            new_callable=AsyncMock,
            return_value=ThreatIntelResponse(local_severity="High"),
        ) as build_intel,
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_application_review_url(tm_id))

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200
    body = response.json()
    assert body["overall_priority"] == "p1_now"
    assert body["coverage"]["systemic_findings"] == 2
    assert body["focus_statement"].startswith("This application")
    build_intel.assert_awaited_once()
    assert build_intel.await_args.kwargs["include_semantic_retrieval"] is False


@pytest.mark.asyncio
async def test_get_review_findings_returns_workbench_payload():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.review_state = None
    fake_response = SecurityReviewFindingListResponse(
        generated_at="2026-04-22T01:00:00Z",
        system_name="Test System",
        queue_counts=[],
        review_status_counts=[],
        default_finding_id="threat:threat-1",
        findings=[
            SecurityReviewFinding(
                id="threat:threat-1",
                source_object_type="threat",
                source_object_id="threat-1",
                threat_id="threat-1",
                display_id="T-001",
                wire_kind="threat",
                display_kind="threat",
                source_provenance="rules_engine",
                source_system="threatgenix",
                title="Spoofed caller identity",
                priority="p1_now",
                wire_action_bucket="engineer_now",
                queue_bucket="fix_now",
                computed_queue_bucket="fix_now",
                truth_status="validated",
                confidence="high",
                why_now="Validated and urgent.",
                impacted_assets=[],
                entry_point="API Gateway",
                evidence_refs=["dfd"],
                linked_threat_ids=["threat-1"],
                linked_change_ids=[],
                linked_control_ids=[],
                review_status="open",
                primary_mode="findings",
                noise_disposition="focus",
            ),
        ],
    )

    with (
        patch(
            "app.api.threats._load_security_review_inputs",
            new_callable=AsyncMock,
            return_value=(fake_tm, [], [], [], [], {}, {}),
        ),
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.build_security_review_findings", return_value=fake_response
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_review_findings_url(tm_id))

    assert response.status_code == 200
    body = response.json()
    assert body["default_finding_id"] == "threat:threat-1"
    assert body["findings"][0]["queue_bucket"] == "fix_now"


@pytest.mark.asyncio
async def test_get_agent_release_decision_returns_agent_contract():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.review_state = None
    fake_summary = SecurityReviewApplicationSummary(
        generated_at="2026-04-22T01:00:00Z",
        system_name="Test System",
        overall_priority="p0_blocker",
        overall_action_bucket="bright_red_line",
        focus_statement="Public route reaches tenant data.",
        coverage=SecurityReviewCoverageSummary(
            total_findings=1,
            attached_evidence_sources=2,
            missing_evidence_sources=0,
        ),
    )
    fake_findings = SecurityReviewFindingListResponse(
        generated_at="2026-04-22T01:00:00Z",
        system_name="Test System",
        findings=[
            SecurityReviewFinding(
                id="threat:threat-1",
                source_object_type="threat",
                source_object_id="threat-1",
                threat_id="threat-1",
                display_id="T-001",
                wire_kind="threat",
                display_kind="threat",
                source_provenance="rules_engine",
                source_system="threatgenix",
                title="Public route writes tenant-scoped data",
                priority="p0_blocker",
                numeric_score=96,
                wire_action_bucket="bright_red_line",
                queue_bucket="fix_now",
                computed_queue_bucket="fix_now",
                truth_status="validated",
                confidence="high",
                is_real=True,
                is_urgent=True,
                is_exploitable_in_context=True,
                is_regulatory_or_control_relevant=True,
                needs_engineering_change=True,
                needs_evidence=False,
                why_now="Validated and urgent.",
                impacted_assets=["Tenant data"],
                entry_point="POST /api/share",
                evidence_refs=["repository", "dfd"],
                linked_threat_ids=["threat-1"],
                linked_change_ids=[],
                linked_control_ids=[],
                review_status="open",
                primary_mode="findings",
                noise_disposition="focus",
                next_step="Require session auth and tenant ownership checks.",
            ),
        ],
    )

    with (
        patch(
            "app.api.threats._load_security_review_inputs",
            new_callable=AsyncMock,
            return_value=(fake_tm, [], [], [], [], {}, {}),
        ),
        patch(
            "app.api.threats.build_application_security_review",
            return_value=fake_summary,
        ),
        patch(
            "app.api.threats.build_security_review_findings",
            return_value=fake_findings,
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(_agent_release_decision_url(tm_id))

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "block"
    assert "does not certify" in body["pass_semantics"]
    assert body["findings"][0]["decision"] == "block"
    assert body["findings"][0]["risk_path"] == [
        "POST /api/share",
        "Tenant data",
        "Public route writes tenant-scoped data",
    ]
    assert {item["type"] for item in body["findings"][0]["evidence"]} == {
        "repository",
        "dfd",
    }


@pytest.mark.asyncio
async def test_patch_review_finding_updates_application_review_state():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.review_state = None
    current = SecurityReviewFindingListResponse(
        generated_at="2026-04-22T01:00:00Z",
        system_name="Test System",
        queue_counts=[],
        review_status_counts=[],
        default_finding_id="application_review_finding:model:repository-evidence",
        findings=[
            SecurityReviewFinding(
                id="application_review_finding:model:repository-evidence",
                source_object_type="application_review_finding",
                source_object_id="model:repository-evidence",
                threat_id=None,
                display_id=None,
                wire_kind="evidence_gap",
                display_kind="evidence_gap",
                source_provenance="app_review_projection",
                source_system="threatgenix",
                title="Repository evidence is missing",
                priority="p2_sprint",
                wire_action_bucket="fill_evidence_gap",
                queue_bucket="gather_evidence",
                computed_queue_bucket="gather_evidence",
                truth_status="contextual",
                confidence="medium",
                why_now="The review needs repository evidence.",
                impacted_assets=[],
                entry_point=None,
                evidence_refs=["repository"],
                linked_threat_ids=[],
                linked_change_ids=[],
                linked_control_ids=[],
                review_status="open",
                primary_mode="compliance",
                noise_disposition="queue",
            ),
        ],
    )
    updated = current.model_copy(
        update={
            "findings": [
                current.findings[0].model_copy(
                    update={
                        "review_status": "accepted",
                        "queue_bucket": None,
                        "last_non_terminal_bucket": "gather_evidence",
                    }
                )
            ]
        }
    )

    with (
        patch(
            "app.api.threats._load_security_review_inputs",
            new_callable=AsyncMock,
            return_value=(fake_tm, [], [], [], [], {}, {}),
        ),
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch(
            "app.api.threats.build_security_review_findings",
            side_effect=[current, updated],
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                f"{_review_findings_url(tm_id)}/application_review_finding/model%3Arepository-evidence",
                json={"review_status": "accepted"},
            )

    assert response.status_code == 200
    body = response.json()
    assert body["review_status"] == "accepted"
    assert body["queue_bucket"] is None
    assert body["last_non_terminal_bucket"] == "gather_evidence"


@pytest.mark.asyncio
async def test_patch_review_finding_rejects_queue_change_for_terminal_item():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.review_state = None
    current = SecurityReviewFindingListResponse(
        generated_at="2026-04-22T01:00:00Z",
        system_name="Test System",
        queue_counts=[],
        review_status_counts=[],
        default_finding_id="application_review_finding:model:repository-evidence",
        findings=[
            SecurityReviewFinding(
                id="application_review_finding:model:repository-evidence",
                source_object_type="application_review_finding",
                source_object_id="model:repository-evidence",
                threat_id=None,
                display_id=None,
                wire_kind="evidence_gap",
                display_kind="evidence_gap",
                source_provenance="app_review_projection",
                source_system="threatgenix",
                title="Repository evidence is missing",
                priority="p2_sprint",
                wire_action_bucket="fill_evidence_gap",
                queue_bucket=None,
                computed_queue_bucket="gather_evidence",
                truth_status="contextual",
                confidence="medium",
                why_now="The review needs repository evidence.",
                impacted_assets=[],
                entry_point=None,
                evidence_refs=["repository"],
                linked_threat_ids=[],
                linked_change_ids=[],
                linked_control_ids=[],
                review_status="accepted",
                last_non_terminal_bucket="gather_evidence",
                primary_mode="compliance",
                noise_disposition="queue",
            ),
        ],
    )

    with (
        patch(
            "app.api.threats._load_security_review_inputs",
            new_callable=AsyncMock,
            return_value=(fake_tm, [], [], [], [], {}, {}),
        ),
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.build_security_review_findings", return_value=current),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                f"{_review_findings_url(tm_id)}/application_review_finding/model%3Arepository-evidence",
                json={"queue_bucket": "fix_now"},
            )

    assert response.status_code == 400
    assert "reopened before changing queue bucket" in response.json()["detail"]


@pytest.mark.asyncio
async def test_patch_review_finding_rejects_terminal_to_terminal_hop():
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.review_state = None
    current = SecurityReviewFindingListResponse(
        generated_at="2026-04-22T01:00:00Z",
        system_name="Test System",
        queue_counts=[],
        review_status_counts=[],
        default_finding_id="application_review_finding:model:repository-evidence",
        findings=[
            SecurityReviewFinding(
                id="application_review_finding:model:repository-evidence",
                source_object_type="application_review_finding",
                source_object_id="model:repository-evidence",
                threat_id=None,
                display_id=None,
                wire_kind="evidence_gap",
                display_kind="evidence_gap",
                source_provenance="app_review_projection",
                source_system="threatgenix",
                title="Repository evidence is missing",
                priority="p2_sprint",
                wire_action_bucket="fill_evidence_gap",
                queue_bucket=None,
                computed_queue_bucket="gather_evidence",
                truth_status="contextual",
                confidence="medium",
                why_now="The review needs repository evidence.",
                impacted_assets=[],
                entry_point=None,
                evidence_refs=["repository"],
                linked_threat_ids=[],
                linked_change_ids=[],
                linked_control_ids=[],
                review_status="accepted",
                last_non_terminal_bucket="gather_evidence",
                primary_mode="compliance",
                noise_disposition="queue",
            ),
        ],
    )

    with (
        patch(
            "app.api.threats._load_security_review_inputs",
            new_callable=AsyncMock,
            return_value=(fake_tm, [], [], [], [], {}, {}),
        ),
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats.build_security_review_findings", return_value=current),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.patch(
                f"{_review_findings_url(tm_id)}/application_review_finding/model%3Arepository-evidence",
                json={"review_status": "dismissed"},
            )

    assert response.status_code == 400
    assert "reopened before changing terminal state" in response.json()["detail"]


@pytest.mark.asyncio
async def test_create_review_artifact_persists_and_returns_updated_finding():
    tm_id = uuid.uuid4()
    threat_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)
    fake_tm.review_state = None
    current = SecurityReviewFindingListResponse(
        generated_at="2026-04-22T01:00:00Z",
        system_name="Test System",
        queue_counts=[],
        review_status_counts=[],
        default_finding_id=f"threat:{threat_id}",
        findings=[
            SecurityReviewFinding(
                id=f"threat:{threat_id}",
                source_object_type="threat",
                source_object_id=str(threat_id),
                threat_id=str(threat_id),
                display_id="T-001",
                wire_kind="threat",
                display_kind="threat",
                source_provenance="rules_engine",
                source_system="threatgenix",
                title="Spoofed caller identity",
                priority="p1_now",
                wire_action_bucket="engineer_now",
                queue_bucket="fix_now",
                computed_queue_bucket="fix_now",
                truth_status="validated",
                confidence="high",
                why_now="The boundary-crossing ingress is unauthenticated.",
                impacted_assets=["API Gateway"],
                entry_point="Public API",
                evidence_refs=["dfd"],
                linked_threat_ids=[str(threat_id)],
                linked_change_ids=[],
                linked_control_ids=[],
                artifacts=[],
                review_status="open",
                primary_mode="findings",
                noise_disposition="focus",
            ),
        ],
    )
    updated = current.model_copy(
        update={
            "findings": [
                current.findings[0].model_copy(
                    update={
                        "artifacts": [
                            SecurityReviewArtifact(
                                id="artifact-1",
                                kind="remediation_note",
                                title="Remediation note · Spoofed caller identity",
                                summary="Concrete engineering change.",
                                body="Objective\n- Reduce the risk.",
                                created_at="2026-04-23T12:00:00Z",
                            )
                        ]
                    }
                )
            ]
        }
    )

    with (
        patch(
            "app.api.threats._load_security_review_inputs",
            new_callable=AsyncMock,
            return_value=(
                fake_tm,
                [SimpleNamespace(id=threat_id)],
                [],
                [],
                [],
                {},
                {},
            ),
        ),
        patch(
            "app.api.threats.get_threat_model",
            new_callable=AsyncMock,
            return_value=fake_tm,
        ),
        patch("app.api.threats._hydrate_threat_response", return_value=None),
        patch(
            "app.api.threats.build_security_review_findings",
            side_effect=[current, updated],
        ),
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.post(
                f"{_review_findings_url(tm_id)}/threat/{threat_id}/artifacts",
                json={"kind": "remediation_note"},
            )

    assert response.status_code == 200
    body = response.json()
    assert len(body["artifacts"]) == 1
    assert body["artifacts"][0]["kind"] == "remediation_note"
    assert "Reduce the risk" in body["artifacts"][0]["body"]


# ---- S-09: pagination params on GET /threats ----

@pytest.mark.asyncio
async def test_list_threats_accepts_limit_offset_query_params():
    """S-09: limit and offset query params must be accepted without error."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    mock_db = AsyncMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute = AsyncMock(return_value=mock_result)

    async def db_override():
        yield mock_db

    app.dependency_overrides[get_db] = db_override

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            # limit + offset both present
            response = await client.get(f"{_list_url(tm_id)}?limit=50&offset=10")

    app.dependency_overrides[get_db] = override_get_db

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_list_threats_rejects_invalid_limit():
    """S-09: limit=0 must return 422 (ge=1 constraint)."""
    tm_id = uuid.uuid4()
    fake_tm = FakeThreatModel(id=tm_id)

    app.dependency_overrides[get_db] = override_get_db

    with patch(
        "app.api.threats.get_threat_model", new_callable=AsyncMock, return_value=fake_tm
    ):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=BASE_URL) as client:
            response = await client.get(f"{_list_url(tm_id)}?limit=0")

    assert response.status_code == 422
