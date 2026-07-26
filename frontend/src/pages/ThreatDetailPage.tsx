import { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";

import type {
  AssistantResponse,
  DFDNodeResponse,
  DFDEdgeResponse,
  ThreatAuditEntry,
  ThreatCatalogEntry,
  ThreatIntelResponse,
  ThreatResponse,
  ThreatScanCorrelationResponse,
} from "../types/api";
import { api } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { ThreatIntelPanel } from "../components/threats/ThreatIntelPanel";
import { ThreatTriageModal } from "../components/threats/ThreatTriageModal";

const CONTROL_EFFECTIVENESS_LABELS: Record<string, string> = {
  none: "None",
  partial: "Partial",
  substantial: "Substantial",
  full: "Full",
};

function severityTone(severity: string | null | undefined): string {
  switch (severity) {
    case "Critical":
      return "critical";
    case "High":
      return "high";
    case "Medium":
      return "medium";
    case "Low":
      return "low";
    default:
      return "muted";
  }
}

function statusTone(status: string | null | undefined): string {
  switch (status) {
    case "Open":
    case "In Progress":
      return "info";
    case "Mitigated":
    case "Accepted":
      return "success";
    case "Dismissed":
      return "muted";
    default:
      return "muted";
  }
}

function residualRiskTone(level: string | null | undefined): string {
  switch (level) {
    case "Critical":
      return "critical";
    case "High":
      return "high";
    case "Medium":
      return "medium";
    case "Low":
      return "info";
    case "Negligible":
      return "success";
    default:
      return "muted";
  }
}

function scanStatusTone(status: string | null | undefined): string {
  switch (status) {
    case "confirmed":
      return "critical";
    case "mitigated":
      return "success";
    case "not_found":
      return "muted";
    default:
      return "info";
  }
}

function scanStatusLabel(status: string | null | undefined): string {
  switch (status) {
    case "confirmed":
      return "Scan Confirmed";
    case "mitigated":
      return "Scan Validated as Mitigated";
    case "not_found":
      return "Not Found in Scan";
    default:
      return "Scan Unverifiable";
  }
}

function scanStatusCopy(status: string | null | undefined): string {
  switch (status) {
    case "confirmed":
      return "The latest attached scan found evidence that maps directly to this threat path.";
    case "mitigated":
      return "The target was checked and current controls prevented the vulnerable condition from being observed.";
    case "not_found":
      return "The target was scanned, but no matching evidence was found for this threat category.";
    default:
      return "Scan telemetry exists, but the current result cannot strongly confirm or disprove this threat.";
  }
}

function formatValidationToolName(toolName: string | null | undefined): string {
  if (!toolName) return "Unknown tool";
  if (toolName.toLowerCase() === "nuclei") return "Nuclei";
  return toolName;
}

function validationEvidenceSourceLabel(
  evidence: ThreatScanCorrelationResponse["evidence"][number]
): string {
  const toolName = formatValidationToolName(evidence.tool_name);
  return evidence.deterministic ? `${toolName} - deterministic` : toolName;
}

function toneClass(prefix: string, tone: string): string {
  return `${prefix} ${prefix}--${tone}`;
}

function formatDisplayDate(value: string): string {
  return new Date(value).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function formatDisplayDateTime(value: string): string {
  return new Date(value).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

/** Strip unresolved {placeholder} tokens left when catalog threats have no DFD context. */
function cleanDescription(text: string): string {
  const cleaned = text.replace(/\s*\{[a-z_]+\}\s*/g, " ").replace(/\s{2,}/g, " ").trim();
  return cleaned || "No description available.";
}

function ThreatDetailPage() {
  const { user } = useAuth();
  const { threatModelId, threatId } = useParams<{
    threatModelId: string;
    threatId: string;
  }>();

  const [threat, setThreat] = useState<ThreatResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [showTriageModal, setShowTriageModal] = useState(false);
  const [assistantPrompt, setAssistantPrompt] = useState(
    "Explain this threat, how it would likely be exploited, and what I should do next."
  );
  const [assistantLoading, setAssistantLoading] = useState(false);
  const [assistantError, setAssistantError] = useState<string | null>(null);
  const [assistantResponse, setAssistantResponse] = useState<AssistantResponse | null>(null);
  const [auditHistory, setAuditHistory] = useState<ThreatAuditEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelResponse | null>(null);
  const [threatIntelLoading, setThreatIntelLoading] = useState(false);
  const [threatIntelError, setThreatIntelError] = useState<string | null>(null);
  const [scanCorrelation, setScanCorrelation] =
    useState<ThreatScanCorrelationResponse | null>(null);
  const [dfdNodes, setDfdNodes] = useState<DFDNodeResponse[]>([]);
  const [dfdEdges, setDfdEdges] = useState<DFDEdgeResponse[]>([]);
  const [ruleDetail, setRuleDetail] = useState<ThreatCatalogEntry | null>(null);

  const fetchThreat = useCallback(async () => {
    if (!threatModelId || !threatId) return;
    try {
      const data = await api.getThreat(threatModelId, threatId);
      setThreat(data);
      setNotFound(false);
      setError(null);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "Failed to load threat";
      if (message.includes("404")) {
        setNotFound(true);
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  }, [threatId, threatModelId]);

  const fetchHistory = useCallback(async () => {
    if (!threatModelId || !threatId) return;
    setHistoryLoading(true);
    try {
      const entries = await api.getThreatHistory(threatModelId, threatId);
      setAuditHistory(entries);
    } catch {
      setAuditHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, [threatId, threatModelId]);

  useEffect(() => {
    void fetchThreat();
  }, [fetchThreat]);

  useEffect(() => {
    void fetchHistory();
  }, [fetchHistory]);

  useEffect(() => {
    if (!threatModelId) return;
    let cancelled = false;
    api.getDFD(threatModelId)
      .then((dfd) => {
        if (!cancelled) {
          setDfdNodes(dfd.nodes);
          setDfdEdges(dfd.edges);
        }
      })
      .catch(() => {
        // non-critical — UUID fallback is fine
      });
    return () => { cancelled = true; };
  }, [threatModelId]);

  useEffect(() => {
    if (!threat?.rule_id) {
      setRuleDetail(null);
      return;
    }
    let cancelled = false;
    api.getThreatCatalog(undefined, undefined).then((catalog) => {
      if (!cancelled) {
        const match = catalog.find((e) => e.rule_id === threat.rule_id);
        setRuleDetail(match ?? null);
      }
    }).catch(() => { /* non-critical */ });
    return () => { cancelled = true; };
  }, [threat?.rule_id]);

  useEffect(() => {
    // Deferred: only fetch intel after the primary threat data has loaded.
    // The /intel endpoint does a 4.6s pgvector search — loading it on mount
    // would block a visible section of the page before the threat content renders.
    if (!threatModelId || !threatId || !threat?.id) return;
    let cancelled = false;

    const fetchThreatIntel = async () => {
      setThreatIntelLoading(true);
      setThreatIntelError(null);
      try {
        const intel = await api.getThreatIntel(threatModelId, threatId);
        if (!cancelled) {
          setThreatIntel(intel);
        }
      } catch (caught) {
        if (!cancelled) {
          setThreatIntel(null);
          setThreatIntelError(
            caught instanceof Error ? caught.message : "Failed to load threat intelligence"
          );
        }
      } finally {
        if (!cancelled) {
          setThreatIntelLoading(false);
        }
      }
    };

    void fetchThreatIntel();

    return () => {
      cancelled = true;
    };
  }, [threatId, threatModelId, threat?.id]);

  useEffect(() => {
    if (!threat || !threatModelId) return;
    const fetchScanCorrelation = async () => {
      try {
        const result = await api.getLatestThreatScanCorrelation(threatModelId, threat.id);
        setScanCorrelation(result);
      } catch {
        setScanCorrelation(null);
      }
    };
    void fetchScanCorrelation();
  }, [threat, threatModelId]);

  const handleTriaged = useCallback(
    (updated: ThreatResponse) => {
      setThreat(updated);
      setThreatIntel((current) =>
        current ? { ...current, local_severity: updated.severity } : current
      );
      setShowTriageModal(false);
      void fetchHistory();
    },
    [fetchHistory]
  );

  const handleAskAboutThreat = useCallback(async () => {
    if (!threatModelId || !threat) return;
    setAssistantLoading(true);
    setAssistantError(null);
    try {
      const prompt = assistantPrompt.trim();
      const response = await api.assistantRespond(threatModelId, {
        message: prompt.startsWith("/") ? prompt : `/explain ${prompt}`,
        anchor: {
          kind: "threat",
          id: threat.id,
        },
        mode_hint: "explain",
      });
      setAssistantResponse(response);
    } catch (caught) {
      setAssistantError(
        caught instanceof Error ? caught.message : "Assistant request failed"
      );
    } finally {
      setAssistantLoading(false);
    }
  }, [assistantPrompt, threat, threatModelId]);

  if (loading) {
    return (
      <div className="page-loading">
        <div className="dfd-spinner" />
        <span>Loading threat...</span>
      </div>
    );
  }

  if (!threatModelId) {
    return null;
  }

  if (error) {
    return (
      <div className="td-page">
        <div className="td-shell td-shell-empty">
          <Link to={`/threat-models/${threatModelId}`} className="td-back">
            &larr; Back to Threat Model
          </Link>
          <section className="td-section td-section-empty">
            <p className="td-section-kicker">Load Error</p>
            <h1 className="td-section-title">Threat detail is unavailable.</h1>
            <p className="td-copy td-copy-muted">Failed to load threat: {error}</p>
          </section>
        </div>
      </div>
    );
  }

  if (notFound) {
    return (
      <div className="td-page">
        <div className="td-shell td-shell-empty">
          <Link to={`/threat-models/${threatModelId}`} className="td-back">
            &larr; Back to Threat Model
          </Link>
          <section className="td-section td-section-empty">
            <p className="td-section-kicker">Not Found</p>
            <h1 className="td-section-title">Threat record not found.</h1>
            <p className="td-copy td-copy-muted">
              The threat you are looking for does not exist or has been removed.
            </p>
          </section>
        </div>
      </div>
    );
  }

  if (!threat) return null;

  const controlsByFramework = threat.compliance_controls.reduce<
    Record<string, typeof threat.compliance_controls>
  >((groups, control) => {
    const framework = control.framework;
    if (!groups[framework]) groups[framework] = [];
    groups[framework].push(control);
    return groups;
  }, {});

  return (
    <div className="td-page">
      <div className="td-shell">
        <Link to={`/threat-models/${threatModelId}`} className="td-back">
          &larr; Back to Threat Model
        </Link>

        <header className="td-header">
          <div className="td-header-main">
            <p className="td-kicker">Threat Record</p>
            <h1 className="td-title">{threat.display_id}</h1>
            {threat.threat_subtype ? (
              <p className="td-subtitle">{threat.threat_subtype}</p>
            ) : null}
          </div>
          <div className="td-badge-row">
            <span className={toneClass("td-badge", severityTone(threat.severity))}>
              {threat.severity}
            </span>
            <span className={toneClass("td-badge", statusTone(threat.status))}>
              {threat.status}
            </span>
            {threat.residual_risk_level ? (
              <span className={toneClass("td-badge", residualRiskTone(threat.residual_risk_level))}>
                Residual {threat.residual_risk_level}
              </span>
            ) : null}
            <span className="td-badge td-badge--stride">{threat.stride_category}</span>
          </div>
        </header>

        <section className="td-saas-context" aria-label="SaaS workspace and validation context">
          <div>
            <span className="td-meta-label">Workspace</span>
            <strong>{user?.organization_name || "Personal pilot workspace"}</strong>
          </div>
          <div>
            <span className="td-meta-label">Reviewer Role</span>
            <strong>{user?.role || "User"}</strong>
          </div>
          <div>
            <span className="td-meta-label">Validation Boundary</span>
            <strong>Imported evidence and Try Sandbox are SaaS-safe; live tools require an isolated runner.</strong>
          </div>
        </section>

        <div className={`td-story-grid${threat.relevance_rationale ? "" : " td-story-grid-single"}`}>
          <section className="td-section">
            <p className="td-section-kicker">Threat Narrative</p>
            <h2 className="td-section-title">Description</h2>
            <p className="td-copy">{cleanDescription(threat.description)}</p>
          </section>

          {threat.relevance_rationale ? (
            <section className="td-section">
              <p className="td-section-kicker">Applicability</p>
              <h2 className="td-section-title">Why This Matters</h2>
              <p className="td-copy">{threat.relevance_rationale}</p>
            </section>
          ) : null}
        </div>

        <section className="td-section">
          <p className="td-section-kicker">Snapshot</p>
          <h2 className="td-section-title">Metadata</h2>
          <div className="td-meta-grid">
            <div className="td-meta-item">
              <span className="td-meta-label">Source</span>
              <span className="td-meta-value">{threat.source}</span>
            </div>
            {threat.threat_subtype ? (
              <div className="td-meta-item">
                <span className="td-meta-label">Threat Title</span>
                <span className="td-meta-value">{threat.threat_subtype}</span>
              </div>
            ) : null}
            {threat.rule_id ? (
              <div className="td-meta-item">
                <span className="td-meta-label">Rule ID</span>
                <span className="td-meta-value td-meta-value-mono">{threat.rule_id}</span>
              </div>
            ) : null}
            {ruleDetail ? (
              <div className="td-meta-item" style={{ gridColumn: "1 / -1" }}>
                <span className="td-meta-label">Rule Logic</span>
                <span className="td-meta-value" style={{ fontSize: "0.82rem", lineHeight: 1.5 }}>
                  <strong>{ruleDetail.threat_subtype}</strong>
                  <span className="td-copy-muted" style={{ display: "block", marginTop: 4 }}>
                    Condition: {ruleDetail.condition_type === "tuple"
                      ? "Fires when a matching source-edge-target tuple crosses a trust boundary"
                      : ruleDetail.condition_type === "standalone"
                        ? "Fires on individual nodes matching specific properties"
                        : ruleDetail.condition_type}
                  </span>
                  <span className="td-copy-muted" style={{ display: "block", marginTop: 2 }}>
                    Template: {ruleDetail.description_template.slice(0, 200)}{ruleDetail.description_template.length > 200 ? "..." : ""}
                  </span>
                </span>
              </div>
            ) : null}
            <div className="td-meta-item">
              <span className="td-meta-label">Created</span>
              <span className="td-meta-value">{formatDisplayDate(threat.created_at)}</span>
            </div>
            <div className="td-meta-item">
              <span className="td-meta-label">AI Enhanced</span>
              <span className="td-meta-value">{threat.ai_enhanced ? "Yes" : "No"}</span>
            </div>
            {threat.provider_managed ? (
              <div className="td-meta-item">
                <span className="td-meta-label">Responsibility</span>
                <span className="td-pill td-pill--info">Provider-managed</span>
              </div>
            ) : null}
          </div>
        </section>

        <section className="td-section">
          <p className="td-section-kicker">Signals</p>
          <h2 className="td-section-title">Threat Intel</h2>
          <ThreatIntelPanel
            intel={threatIntel}
            loading={threatIntelLoading}
            error={threatIntelError}
          />
        </section>

        {(threat.affected_node_ids.length > 0 ||
          threat.affected_edge_ids.length > 0 ||
          threat.compliance_controls.length > 0) && (
          <div className="td-support-grid">
            {(threat.affected_node_ids.length > 0 || threat.affected_edge_ids.length > 0) && (
              <section className="td-section">
                <p className="td-section-kicker">Blast Radius</p>
                <h2 className="td-section-title">Affected Components</h2>
                {threat.affected_node_ids.length > 0 ? (
                  <div className="td-stack">
                    <span className="td-meta-label">Nodes</span>
                    <ul className="td-mono-list">
                      {threat.affected_node_ids.map((nodeId) => {
                        const node = dfdNodes.find((n) => n.id === nodeId);
                        return (
                          <li key={nodeId}>
                            {node ? (
                              <><strong>{node.name}</strong> <span className="td-copy-muted">({node.node_type})</span></>
                            ) : (
                              nodeId
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ) : null}
                {threat.affected_edge_ids.length > 0 ? (
                  <div className="td-stack">
                    <span className="td-meta-label">Data Flows</span>
                    <ul className="td-mono-list">
                      {threat.affected_edge_ids.map((edgeId) => {
                        const edge = dfdEdges.find((e) => e.id === edgeId);
                        if (edge) {
                          const srcNode = dfdNodes.find((n) => n.id === edge.source_node_id);
                          const tgtNode = dfdNodes.find((n) => n.id === edge.target_node_id);
                          const srcName = srcNode?.name ?? edge.source_node_id;
                          const tgtName = tgtNode?.name ?? edge.target_node_id;
                          return (
                            <li key={edgeId}>
                              <strong>{srcName}</strong> &rarr; <strong>{tgtName}</strong>
                              {edge.label ? <span className="td-copy-muted"> ({edge.label})</span> : null}
                            </li>
                          );
                        }
                        return <li key={edgeId}>{edgeId}</li>;
                      })}
                    </ul>
                  </div>
                ) : null}
              </section>
            )}

            {threat.compliance_controls.length > 0 ? (
              <section className="td-section">
                <p className="td-section-kicker">Control Mapping</p>
                <h2 className="td-section-title">Compliance Controls</h2>
                <div className="td-stack">
                  {Object.entries(controlsByFramework).map(([framework, controls]) => (
                    <div key={framework} className="td-control-group">
                      <span className="td-control-framework">{framework}</span>
                      <ul className="td-control-list">
                        {controls.map((control) => (
                          <li key={`${control.framework}-${control.control_id}`}>
                            <strong>{control.control_id}</strong> {control.control_name}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </section>
            ) : null}
          </div>
        )}

        {(threat.mitigation_plan ||
          threat.mitigation_owner ||
          threat.due_date ||
          threat.mitigation_notes ||
          threat.dismiss_reason ||
          threat.closed_at ||
          threat.status !== "Open") && (
          <section className="td-section">
            <p className="td-section-kicker">Disposition</p>
            <h2 className="td-section-title">Mitigation and Workflow</h2>
            <div className="td-meta-grid">
              <div className="td-meta-item">
                <span className="td-meta-label">Workflow Status</span>
                <span className="td-meta-value">{threat.status}</span>
              </div>
              <div className="td-meta-item">
                <span className="td-meta-label">Control Effectiveness</span>
                <span className="td-meta-value">
                  {CONTROL_EFFECTIVENESS_LABELS[threat.control_effectiveness] ??
                    threat.control_effectiveness}
                </span>
              </div>
              {threat.residual_risk_level ? (
                <div className="td-meta-item">
                  <span className="td-meta-label">Residual Risk</span>
                  <span className="td-meta-value">{threat.residual_risk_level}</span>
                </div>
              ) : null}
              {threat.mitigation_owner ? (
                <div className="td-meta-item">
                  <span className="td-meta-label">Owner</span>
                  <span className="td-meta-value">{threat.mitigation_owner}</span>
                </div>
              ) : null}
              {threat.due_date ? (
                <div className="td-meta-item">
                  <span className="td-meta-label">Due Date</span>
                  <span className="td-meta-value">{threat.due_date}</span>
                </div>
              ) : null}
              {threat.closed_at ? (
                <div className="td-meta-item">
                  <span className="td-meta-label">Closed</span>
                  <span className="td-meta-value">{formatDisplayDate(threat.closed_at)}</span>
                </div>
              ) : null}
            </div>

            {threat.mitigation_plan ? (
              <div className="td-note-block">
                <span className="td-meta-label">Mitigation Plan</span>
                <p className="td-copy">{threat.mitigation_plan}</p>
              </div>
            ) : null}

            {threat.mitigation_notes ? (
              <div className="td-note-block">
                <span className="td-meta-label">Mitigation Notes</span>
                <p className="td-copy">{threat.mitigation_notes}</p>
              </div>
            ) : null}

            {threat.dismiss_reason ? (
              <div className="td-note-block">
                <span className="td-meta-label">Dismiss Reason</span>
                <p className="td-copy">{threat.dismiss_reason}</p>
              </div>
            ) : null}
          </section>
        )}

        <section className="td-section">
          <p className="td-section-kicker">Workflow</p>
          <h2 className="td-section-title">Triage Actions</h2>
          <div className="td-action-row">
            <button
              type="button"
              className="td-btn td-btn--primary"
              onClick={() => setShowTriageModal(true)}
              title="Open the triage workflow for this threat"
            >
              Update Status and Mitigation
            </button>
            <button
              type="button"
              className="td-btn td-btn--secondary"
              onClick={handleAskAboutThreat}
              disabled={assistantLoading}
              title="Ask the assistant to explain this threat and recommend next steps"
            >
              {assistantLoading ? "Asking AI..." : "Ask AI About This Threat"}
            </button>
          </div>
          <p className="td-copy td-copy-muted">
            Move the threat through triage, keep mitigation ownership current, and capture
            the rationale behind accepted or dismissed risk.
          </p>
        </section>

        <section className="td-section">
          <p className="td-section-kicker">Analysis</p>
          <h2 className="td-section-title">AI Guidance</h2>
          <div className="td-stack">
            <textarea
              className="td-textarea"
              value={assistantPrompt}
              onChange={(event) => setAssistantPrompt(event.target.value)}
              placeholder="Ask a focused question about this threat..."
              rows={4}
              title="Write a focused question for the assistant about this threat"
            />
            <div className="td-action-row">
              <button
                type="button"
                className="td-btn td-btn--secondary"
                onClick={handleAskAboutThreat}
                disabled={assistantLoading}
                title="Send the current question to the assistant"
              >
                {assistantLoading ? "Thinking..." : "Ask AI"}
              </button>
              {assistantResponse ? (
                <button
                  type="button"
                  className="td-btn td-btn--ghost"
                  onClick={() => {
                    setAssistantResponse(null);
                    setAssistantError(null);
                  }}
                  title="Clear the current assistant answer"
                >
                  Clear Answer
                </button>
              ) : null}
            </div>

            {assistantError ? <p className="td-inline-error">{assistantError}</p> : null}

            {assistantResponse ? (
              <div className="td-note-block">
                <span className="td-meta-label">AI Answer</span>
                <p className="td-copy td-copy-prewrap">{assistantResponse.answer}</p>
                {assistantResponse.degraded_reason ? (
                  <p className="td-copy td-copy-muted">{assistantResponse.degraded_reason}</p>
                ) : null}
                {assistantResponse.findings.length > 0 ? (
                  <div className="td-stack">
                    <span className="td-meta-label">Key Findings</span>
                    <ul className="td-control-list">
                      {assistantResponse.findings.map((finding, index) => (
                        <li key={`${finding.title}-${index}`}>
                          <strong>{finding.title}</strong> {finding.description}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </section>

        <section className="td-section">
          <p className="td-section-kicker">History</p>
          <h2 className="td-section-title">Audit Trail</h2>
          {historyLoading ? (
            <p className="td-copy td-copy-muted">Loading history...</p>
          ) : auditHistory.length === 0 ? (
            <p className="td-copy td-copy-muted">No history yet.</p>
          ) : (
            <ul className="td-timeline">
              {auditHistory.map((entry) => (
                <li key={entry.id} className="td-timeline-entry">
                  <span className="td-timeline-date">
                    {formatDisplayDateTime(entry.changed_at)} - {entry.changed_by}
                  </span>
                  <p className="td-copy td-copy-prewrap">
                    {entry.action}
                    {entry.old_status && entry.new_status
                      ? `: ${entry.old_status} -> ${entry.new_status}`
                      : entry.new_status
                        ? `: -> ${entry.new_status}`
                        : ""}
                  </p>
                  {entry.reason ? (
                    <p className="td-copy td-copy-muted">Reason: {entry.reason}</p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>

        {scanCorrelation ? (
          <section className={`td-section td-section-scan td-section-scan--${scanStatusTone(scanCorrelation.scan_status)}`}>
            <div className="td-section-header">
              <div>
                <p className="td-section-kicker">Validation</p>
                <h2 className="td-section-title">{scanStatusLabel(scanCorrelation.scan_status)}</h2>
              </div>
              <span className={toneClass("td-pill", scanStatusTone(scanCorrelation.scan_status))}>
                {scanCorrelation.scan_status.replace(/_/g, " ")}
              </span>
            </div>

            <p className="td-copy td-copy-muted">{scanStatusCopy(scanCorrelation.scan_status)}</p>

            <div className="td-scan-meta">
              <div className="td-scan-meta-item">
                <span className="td-meta-label">Latest completed scan</span>
                <span className="td-meta-value">
                  {scanCorrelation.scan_completed_at
                    ? formatDisplayDateTime(scanCorrelation.scan_completed_at)
                    : "Unknown"}
                </span>
              </div>
              {scanCorrelation.matched_targets.length > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Matched targets</span>
                  <span className="td-copy">{scanCorrelation.matched_targets.join(", ")}</span>
                </div>
              ) : null}
              {scanCorrelation.templates.length > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Templates</span>
                  <span className="td-copy">{scanCorrelation.templates.join(", ")}</span>
                </div>
              ) : null}
              {scanCorrelation.matched_node_labels.length > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Mapped DFD nodes</span>
                  <span className="td-copy">{scanCorrelation.matched_node_labels.join(", ")}</span>
                </div>
              ) : null}
              {scanCorrelation.finding_titles.length > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Finding trail</span>
                  <span className="td-copy">
                    {scanCorrelation.finding_titles.slice(0, 3).join(" | ")}
                  </span>
                </div>
              ) : null}
              {scanCorrelation.validation_tools?.length ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Evidence sources</span>
                  <span className="td-copy">
                    {scanCorrelation.validation_tools.map(formatValidationToolName).join(", ")}
                  </span>
                </div>
              ) : null}
              {(scanCorrelation.deterministic_evidence_count ?? 0) > 0 ? (
                <div className="td-scan-meta-item">
                  <span className="td-meta-label">Deterministic evidence</span>
                  <span className="td-meta-value">
                    {scanCorrelation.deterministic_evidence_count} finding
                    {scanCorrelation.deterministic_evidence_count === 1 ? "" : "s"}
                  </span>
                </div>
              ) : null}
            </div>

            {scanCorrelation.cve_ids.length > 0 ? (
              <div className="td-chip-group">
                {scanCorrelation.cve_ids.map((cveId) => (
                  <span key={cveId} className="td-chip">
                    {cveId}
                  </span>
                ))}
              </div>
            ) : null}

            {scanCorrelation.evidence.length > 0 ? (
              <div className="td-table-wrap">
                <table className="td-table">
                  <thead>
                    <tr>
                      <th>Template</th>
                      <th>Severity</th>
                      <th>Matched At</th>
                      <th>Evidence Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanCorrelation.evidence.map((evidence) => (
                      <tr key={evidence.finding_id}>
                        <td>{evidence.template_name}</td>
                        <td>
                          <span
                            className={toneClass(
                              "td-pill",
                              evidence.severity === "critical" || evidence.severity === "high"
                                ? "critical"
                                : evidence.severity === "medium"
                                  ? "medium"
                                  : "muted"
                            )}
                          >
                            {evidence.severity}
                          </span>
                        </td>
                        <td className="td-table-mono">
                          {evidence.matched_at.length > 60
                            ? `${evidence.matched_at.slice(0, 60)}...`
                            : evidence.matched_at}
                        </td>
                        <td>
                          {evidence.tool_name ? (
                            <span className="td-chip">
                              {validationEvidenceSourceLabel(evidence)}
                            </span>
                          ) : (
                            <span className="td-copy td-copy-muted">Legacy scan evidence</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : scanCorrelation.scan_status !== "unverifiable" ? (
              <p className="td-copy td-copy-muted">
                {scanCorrelation.scan_status === "mitigated"
                  ? "Security controls were verified during the scan and no vulnerable condition was found."
                  : "The target was scanned, but no matching findings were returned for this threat category."}
              </p>
            ) : null}
          </section>
        ) : null}

        {showTriageModal ? (
          <ThreatTriageModal
            threat={threat}
            threatModelId={threatModelId}
            onClose={() => setShowTriageModal(false)}
            onTriaged={handleTriaged}
            onAskAboutThreat={() => {
              setShowTriageModal(false);
              void handleAskAboutThreat();
            }}
          />
        ) : null}
      </div>
    </div>
  );
}

export default ThreatDetailPage;
