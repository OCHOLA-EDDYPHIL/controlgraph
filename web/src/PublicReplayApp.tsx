import { useEffect, useState, type ReactNode } from "react";

import {
  loadPublicReplay,
  type PublicReplayAdvisor,
  type PublicReplayEnvelope,
  type PublicReplayEvent,
  type PublicReplayEventEnvelope,
} from "./contracts/publicReplay";

type ReplayState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "invalid" }
  | { status: "ready"; replay: PublicReplayEnvelope };

const labels: Record<PublicReplayEvent["kind"], string> = {
  AUTHORITY_ADVANCED: "Approval was withdrawn",
  STALE_WORK_DENIED: "Stale promotion was blocked",
  TARGET_UNCHANGED: "Traffic stayed unchanged",
  ADVISOR_VALIDATED: "Advisor explained the evidence",
  RECOVERY_VERIFIED: "Recovery was verified",
  TIMELINE_COMMITTED: "Evidence chain was verified",
};

const advisorToolPresentation = {
  read_root_summary: {
    name: "Rollout root",
    role: "Approved rollout, current epoch, and fixed bounds",
  },
  read_target_summary: {
    name: "Target state",
    role: "Observed revisions and traffic allocation",
  },
  read_health_summary: {
    name: "Health evidence",
    role: "Deterministic health-window results",
  },
  read_receipt_summary: {
    name: "Execution receipt",
    role: "Request decision and denial result",
  },
  read_timeline_summary: {
    name: "Evidence timeline",
    role: "Ordered authority and execution facts",
  },
  read_verifier_summary: {
    name: "Independent verifier",
    role: "Target and data-path confirmation",
  },
} as const;

function record(value: unknown): Record<string, unknown> {
  return value as Record<string, unknown>;
}

function traffic(value: unknown): string {
  const item = record(value);
  return `${String(item.stable_percent)}% stable / ${String(item.candidate_percent)}% candidate`;
}

function modelName(modelId: PublicReplayAdvisor["model_id"]): string {
  return modelId === "gemini-3.5-flash" ? "Gemini 3.5 Flash" : modelId;
}

function eventLabel(event: PublicReplayEvent): string {
  if (event.kind === "TARGET_UNCHANGED") {
    const afterDenial = record(event.details.after_denial);
    return `Traffic stayed at ${String(afterDenial.stable_percent)}/${String(afterDenial.candidate_percent)}`;
  }
  if (event.kind === "RECOVERY_VERIFIED") {
    const recovered = record(event.details.traffic);
    return `Recovery reached ${String(recovered.stable_percent)}% stable`;
  }
  return labels[event.kind];
}

function ReplayTime({ value }: { readonly value: string }) {
  return <time dateTime={value}>{value}</time>;
}

function RawValue({ children }: { readonly children: ReactNode }) {
  return <code className="raw-value">{children}</code>;
}

function DetailRow({
  label,
  children,
}: {
  readonly label: string;
  readonly children: ReactNode;
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function EventFacts({ event }: { readonly event: PublicReplayEvent }) {
  const details = event.details;
  switch (event.kind) {
    case "AUTHORITY_ADVANCED":
      return (
        <p>
          Epoch <strong>{String(details.previous_epoch)}</strong> is N for this recorded run. An
          operator revocation advanced authority once to epoch{" "}
          <strong>{String(details.new_epoch)}</strong>, N+1; queued work remained bound to N and
          became stale.
        </p>
      );
    case "STALE_WORK_DENIED":
      return (
        <p>
          At the final check, authority at execution time was epoch{" "}
          {String(details.current_authority_epoch)} (N+1), not work epoch{" "}
          {String(details.work_epoch)} (N). The executor returned{" "}
          <strong>{String(details.outcome)} / {String(details.reason_code)}</strong> before calling
          the traffic mutation.
        </p>
      );
    case "TARGET_UNCHANGED":
      return (
        <p>
          Verified independent readback found {traffic(details.before_denial)} before the denial
          and {traffic(details.after_denial)} after it.
        </p>
      );
    case "ADVISOR_VALIDATED": {
      const advisor = details.advisor as unknown as PublicReplayAdvisor;
      return (
        <div>
          <p>
            {modelName(advisor.model_id)} on Vertex AI, coordinated by Google ADK, explained the
            already-recorded outcome through six fixed read-only tools. It could not approve work,
            override deterministic health decisions, dispatch recovery, or change traffic.
          </p>
          <p className="advisor-boundary">
            Recorded boundary: <strong>the advisor had no authority</strong>
          </p>
        </div>
      );
    }
    case "RECOVERY_VERIFIED":
      return (
        <p>
          Separately authorized recovery was <strong>{String(details.outcome)}</strong> at{" "}
          {traffic(details.traffic)}.
        </p>
      );
    case "TIMELINE_COMMITTED": {
      const timeline = record(details.timeline);
      const entries = timeline.entries as readonly unknown[];
      return (
        <p>
          {entries.length} relevant public commitments were linked in order through timeline
          sequence {String(timeline.head_sequence)}.
        </p>
      );
    }
  }
}

function OutcomeCard({
  label,
  value,
  detail,
  tone,
}: {
  readonly label: string;
  readonly value: string;
  readonly detail: string;
  readonly tone: "blocked" | "held" | "recovered";
}) {
  return (
    <article className={`outcome-card outcome-card--${tone}`}>
      <p className="outcome-label">{label}</p>
      <p className="outcome-value">{value}</p>
      <p className="outcome-detail">{detail}</p>
    </article>
  );
}

function AcceptedRunProvenance({ replay }: { readonly replay: PublicReplayEnvelope }) {
  const { payload } = replay;
  return (
    <section className="run-provenance" aria-labelledby="run-provenance-title">
      <div>
        <p className="eyebrow">Run provenance</p>
        <h2 id="run-provenance-title">Accepted stale-authority run</h2>
        <p>
          The acceptance time and source revision belong to this accepted hosted run. The current
          replay viewer is separate and may be newer; displaying the artifact does not extend its
          evidence to the viewer revision. The exact accepted source revision remains available in
          Verification gates.
        </p>
      </div>
      <dl className="run-provenance-values">
        <DetailRow label="Hosted acceptance">
          {payload.acceptance_status === "PASSED" ? "Passed" : payload.acceptance_status}
        </DetailRow>
        <DetailRow label="Accepted at"><ReplayTime value={payload.accepted_at} /></DetailRow>
      </dl>
    </section>
  );
}

function AdvisorOverview({ advisor }: { readonly advisor: PublicReplayAdvisor }) {
  const replayExplanation = advisor.replayed_without_model_call
    ? "The accepted record confirms this page replayed the stored advisor result without a new model call. Loading the replay did not send another request to Gemini."
    : (
        "The accepted record does not confirm that the stored advisor result was replayed " +
        "without a new model call."
      );
  return (
    <section className="advisor-overview" aria-labelledby="advisor-overview-title">
      <div className="section-heading">
        <p className="eyebrow">Advisory stack · no authority</p>
        <h2 id="advisor-overview-title">{modelName(advisor.model_id)} explains; code decides</h2>
        <p>
          The accepted run used {modelName(advisor.model_id)} on Vertex AI, coordinated by Google
          ADK. The model and its tools had no authority to approve work, decide health, dispatch an
          action, authorize recovery, or mutate traffic. Deterministic ControlGraph code retained
          those decisions.
        </p>
      </div>

      <div className="advisor-tool-panel">
        <h3>Six fixed read-only tools</h3>
        <ol className="advisor-tools">
          {advisor.tool_calls.map((call, index) => {
            const toolId = String(call.tool_id);
            const presentation = advisorToolPresentation[
              toolId as keyof typeof advisorToolPresentation
            ];
            return (
              <li key={`${toolId}-${index}`}>
                <strong>{presentation.name}</strong>
                <span>{presentation.role}</span>
              </li>
            );
          })}
        </ol>
      </div>

      <div className="advisor-replay-note">
        <p className="advisor-boundary">
          Recorded boundary: <strong>no advisor or tool authority</strong>
        </p>
        <p>{replayExplanation}</p>
      </div>
    </section>
  );
}

function AdvisorVerification({ advisor }: { readonly advisor: PublicReplayAdvisor }) {
  return (
    <div className="event-technical-block">
      <h4>Advisor record</h4>
      <dl className="verification-list">
        <DetailRow label="Schema"><RawValue>{advisor.schema_version}</RawValue></DetailRow>
        <DetailRow label="Model"><RawValue>{advisor.model_id}</RawValue></DetailRow>
        <DetailRow label="Model location"><RawValue>{advisor.model_location}</RawValue></DetailRow>
        <DetailRow label="Prompt version"><RawValue>{advisor.prompt_version}</RawValue></DetailRow>
        <DetailRow label="Validation"><RawValue>{advisor.validation}</RawValue></DetailRow>
        <DetailRow label="Authority effect"><RawValue>{advisor.authority_effect}</RawValue></DetailRow>
        <DetailRow label="Health override">
          <RawValue>{String(advisor.deterministic_health_override)}</RawValue>
        </DetailRow>
        <DetailRow label="Operator review required">
          <RawValue>{String(advisor.operator_review_required)}</RawValue>
        </DetailRow>
        <DetailRow label="Requested operator action">
          <RawValue>{advisor.requested_operator_action}</RawValue>
        </DetailRow>
        <DetailRow label="Confidence basis points">
          <RawValue>{String(advisor.confidence_basis_points)}</RawValue>
        </DetailRow>
        <DetailRow label="Replayed without model call">
          <RawValue>{String(advisor.replayed_without_model_call)}</RawValue>
        </DetailRow>
        <DetailRow label="Response SHA-256"><RawValue>{advisor.response_sha256}</RawValue></DetailRow>
        <DetailRow label="Audit SHA-256"><RawValue>{advisor.audit_sha256}</RawValue></DetailRow>
        <DetailRow label="Registry SHA-256"><RawValue>{advisor.registry_sha256}</RawValue></DetailRow>
        <DetailRow label="Snapshot SHA-256"><RawValue>{advisor.snapshot_sha256}</RawValue></DetailRow>
        <DetailRow label="Structured output SHA-256">
          <RawValue>{advisor.structured_output_sha256}</RawValue>
        </DetailRow>
      </dl>

      <h4>Exact findings and citations</h4>
      <ol className="verification-records">
        {advisor.findings.map((finding, findingIndex) => (
          <li key={`${findingIndex}-${finding.statement}`}>
            <p className="server-finding">{finding.statement}</p>
            <p className="schema-line">
              Finding schema: <RawValue>{finding.schema_version}</RawValue>
            </p>
            <ul className="citation-records">
              {finding.citations.map((citation, citationIndex) => (
                <li key={`${citation.evidence_kind}-${citation.evidence_id}-${citationIndex}`}>
                  <dl className="verification-list">
                    <DetailRow label="Citation schema">
                      <RawValue>{citation.schema_version}</RawValue>
                    </DetailRow>
                    <DetailRow label="Evidence kind">
                      <RawValue>{citation.evidence_kind}</RawValue>
                    </DetailRow>
                    <DetailRow label="Evidence ID">
                      <RawValue>{citation.evidence_id}</RawValue>
                    </DetailRow>
                    <DetailRow label="Source SHA-256">
                      <RawValue>{citation.source_sha256}</RawValue>
                    </DetailRow>
                  </dl>
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ol>

      <h4>Exact tool calls</h4>
      <ol className="tool-records">
        {advisor.tool_calls.map((call, index) => (
          <li key={`${String(call.tool_id)}-${index}`}>
            <dl className="verification-list">
              <DetailRow label="Sequence"><RawValue>{String(call.sequence)}</RawValue></DetailRow>
              <DetailRow label="Tool"><RawValue>{String(call.tool_id)}</RawValue></DetailRow>
              <DetailRow label="Status"><RawValue>{String(call.status)}</RawValue></DetailRow>
              <DetailRow label="Schema"><RawValue>{String(call.schema_version)}</RawValue></DetailRow>
              <DetailRow label="Input SHA-256">
                <RawValue>{String(call.input_sha256)}</RawValue>
              </DetailRow>
              <DetailRow label="Output SHA-256">
                <RawValue>{String(call.output_sha256)}</RawValue>
              </DetailRow>
            </dl>
          </li>
        ))}
      </ol>
    </div>
  );
}

function EventTechnicalDetails({
  envelope,
}: {
  readonly envelope: PublicReplayEventEnvelope;
}) {
  const { event, event_sha256: eventSha256 } = envelope;
  const details = event.details;

  return (
    <li className="verification-record">
      <h3>
        {String(event.sequence).padStart(2, "0")} · {eventLabel(event)}
      </h3>
      <dl className="verification-list">
        <DetailRow label="Envelope schema"><RawValue>{envelope.schema_version}</RawValue></DetailRow>
        <DetailRow label="Event schema"><RawValue>{event.schema_version}</RawValue></DetailRow>
        <DetailRow label="Event kind"><RawValue>{event.kind}</RawValue></DetailRow>
        <DetailRow label="Occurred at"><ReplayTime value={event.occurred_at} /></DetailRow>
        <DetailRow label="Event SHA-256"><RawValue>{eventSha256}</RawValue></DetailRow>
        <DetailRow label="Previous event SHA-256">
          <RawValue>{event.previous_event_sha256 ?? "null"}</RawValue>
        </DetailRow>
      </dl>

      {event.kind === "AUTHORITY_ADVANCED" && (
        <dl className="verification-list event-detail-list">
          <DetailRow label="Detail schema"><RawValue>{String(details.schema_version)}</RawValue></DetailRow>
          <DetailRow label="Cause"><RawValue>{String(details.cause)}</RawValue></DetailRow>
          <DetailRow label="Previous epoch"><RawValue>{String(details.previous_epoch)}</RawValue></DetailRow>
          <DetailRow label="New epoch"><RawValue>{String(details.new_epoch)}</RawValue></DetailRow>
          <DetailRow label="Transition SHA-256"><RawValue>{String(details.transition_sha256)}</RawValue></DetailRow>
        </dl>
      )}

      {event.kind === "STALE_WORK_DENIED" && (
        <dl className="verification-list event-detail-list">
          <DetailRow label="Detail schema"><RawValue>{String(details.schema_version)}</RawValue></DetailRow>
          <DetailRow label="Work epoch"><RawValue>{String(details.work_epoch)}</RawValue></DetailRow>
          <DetailRow label="Current authority epoch">
            <RawValue>{String(details.current_authority_epoch)}</RawValue>
          </DetailRow>
          <DetailRow label="Outcome"><RawValue>{String(details.outcome)}</RawValue></DetailRow>
          <DetailRow label="Reason code"><RawValue>{String(details.reason_code)}</RawValue></DetailRow>
          <DetailRow label="Receipt SHA-256"><RawValue>{String(details.receipt_sha256)}</RawValue></DetailRow>
        </dl>
      )}

      {event.kind === "TARGET_UNCHANGED" && (
        <div className="event-technical-block">
          <p className="schema-line">
            Detail schema: <RawValue>{String(details.schema_version)}</RawValue>
          </p>
          {(["before_denial", "after_denial"] as const).map((key) => {
            const state = record(details[key]);
            return (
              <div key={key} className="traffic-record">
                <h4>{key === "before_denial" ? "Before denial" : "After denial"}</h4>
                <dl className="verification-list">
                  <DetailRow label="Schema"><RawValue>{String(state.schema_version)}</RawValue></DetailRow>
                  <DetailRow label="Stable percent"><RawValue>{String(state.stable_percent)}</RawValue></DetailRow>
                  <DetailRow label="Candidate percent"><RawValue>{String(state.candidate_percent)}</RawValue></DetailRow>
                  <DetailRow label="Target configuration SHA-256">
                    <RawValue>{String(state.target_configuration_sha256)}</RawValue>
                  </DetailRow>
                </dl>
              </div>
            );
          })}
        </div>
      )}

      {event.kind === "ADVISOR_VALIDATED" && (
        <div className="event-technical-block">
          <p className="schema-line">
            Detail schema: <RawValue>{String(details.schema_version)}</RawValue>
          </p>
          <AdvisorVerification advisor={details.advisor as unknown as PublicReplayAdvisor} />
        </div>
      )}

      {event.kind === "RECOVERY_VERIFIED" && (() => {
        const state = record(details.traffic);
        return (
          <div className="event-technical-block">
            <dl className="verification-list event-detail-list">
              <DetailRow label="Detail schema"><RawValue>{String(details.schema_version)}</RawValue></DetailRow>
              <DetailRow label="Outcome"><RawValue>{String(details.outcome)}</RawValue></DetailRow>
              <DetailRow label="Receipt SHA-256"><RawValue>{String(details.receipt_sha256)}</RawValue></DetailRow>
              <DetailRow label="Traffic schema"><RawValue>{String(state.schema_version)}</RawValue></DetailRow>
              <DetailRow label="Stable percent"><RawValue>{String(state.stable_percent)}</RawValue></DetailRow>
              <DetailRow label="Candidate percent"><RawValue>{String(state.candidate_percent)}</RawValue></DetailRow>
              <DetailRow label="Target configuration SHA-256">
                <RawValue>{String(state.target_configuration_sha256)}</RawValue>
              </DetailRow>
            </dl>
          </div>
        );
      })()}

      {event.kind === "TIMELINE_COMMITTED" && (() => {
        const timeline = record(details.timeline);
        const entries = timeline.entries as readonly Record<string, unknown>[];
        return (
          <div className="event-technical-block">
            <dl className="verification-list event-detail-list">
              <DetailRow label="Detail schema"><RawValue>{String(details.schema_version)}</RawValue></DetailRow>
              <DetailRow label="Timeline schema"><RawValue>{String(timeline.schema_version)}</RawValue></DetailRow>
              <DetailRow label="Head sequence"><RawValue>{String(timeline.head_sequence)}</RawValue></DetailRow>
              <DetailRow label="Head entry SHA-256"><RawValue>{String(timeline.head_entry_sha256)}</RawValue></DetailRow>
              <DetailRow label="Entry count"><RawValue>{String(timeline.entry_count)}</RawValue></DetailRow>
              <DetailRow label="Page count"><RawValue>{String(timeline.page_count)}</RawValue></DetailRow>
              <DetailRow label="Page set SHA-256"><RawValue>{String(timeline.page_set_sha256)}</RawValue></DetailRow>
            </dl>
            <h4>Timeline entries</h4>
            <ol className="tool-records">
              {entries.map((entry, index) => (
                <li key={`${String(entry.entry_sha256)}-${index}`}>
                  <dl className="verification-list">
                    <DetailRow label="Schema"><RawValue>{String(entry.schema_version)}</RawValue></DetailRow>
                    <DetailRow label="Sequence"><RawValue>{String(entry.sequence)}</RawValue></DetailRow>
                    <DetailRow label="Event type"><RawValue>{String(entry.event_type)}</RawValue></DetailRow>
                    <DetailRow label="Occurred at">
                      <ReplayTime value={String(entry.occurred_at)} />
                    </DetailRow>
                    <DetailRow label="Verification status">
                      <RawValue>{String(entry.verification_status)}</RawValue>
                    </DetailRow>
                    <DetailRow label="Entry SHA-256"><RawValue>{String(entry.entry_sha256)}</RawValue></DetailRow>
                  </dl>
                </li>
              ))}
            </ol>
          </div>
        );
      })()}
    </li>
  );
}

function VerificationDetails({ replay }: { readonly replay: PublicReplayEnvelope }) {
  const { payload } = replay;
  return (
    <details className="verification-details">
      <summary>
        <span>Verification gates</span>
        <small aria-hidden="true">Exact evidence, identifiers, and digests</small>
      </summary>
      <div className="verification-content">
        <section aria-labelledby="artifact-details-title">
          <h2 id="artifact-details-title">Accepted artifact</h2>
          <dl className="verification-list">
            <DetailRow label="Envelope schema"><RawValue>{replay.schema_version}</RawValue></DetailRow>
            <DetailRow label="Payload schema"><RawValue>{payload.schema_version}</RawValue></DetailRow>
            <DetailRow label="Replay payload SHA-256"><RawValue>{replay.payload_sha256}</RawValue></DetailRow>
            <DetailRow label="Accepted run source commit">
              <RawValue>{payload.source_commit}</RawValue>
            </DetailRow>
            <DetailRow label="Acceptance manifest SHA-256">
              <RawValue>{payload.acceptance_manifest_sha256}</RawValue>
            </DetailRow>
            <DetailRow label="Acceptance run"><RawValue>{payload.acceptance_run_id}</RawValue></DetailRow>
            <DetailRow label="Acceptance status"><RawValue>{payload.acceptance_status}</RawValue></DetailRow>
            <DetailRow label="Evidence binding complete">
              <RawValue>{String(payload.evidence_binding_complete)}</RawValue>
            </DetailRow>
            <DetailRow label="Accepted at"><ReplayTime value={payload.accepted_at} /></DetailRow>
            <DetailRow label="Event chain head SHA-256">
              <RawValue>{payload.event_chain_head_sha256}</RawValue>
            </DetailRow>
          </dl>
        </section>

        <section aria-labelledby="case-details-title">
          <h2 id="case-details-title">Accepted cases</h2>
          <ol className="compact-records">
            {payload.cases.map((replayCase) => (
              <li key={replayCase.case_sha256}>
                <strong>{String(replayCase.sequence).padStart(2, "0")}</strong>
                <span>
                  <RawValue>{replayCase.kind}</RawValue>
                  <small>Schema: <RawValue>{replayCase.schema_version}</RawValue></small>
                  <small>Case SHA-256: <RawValue>{replayCase.case_sha256}</RawValue></small>
                </span>
              </li>
            ))}
          </ol>
        </section>

        <section aria-labelledby="event-details-title">
          <h2 id="event-details-title">Event records</h2>
          <ol className="verification-events">
            {payload.events.map((envelope) => (
              <EventTechnicalDetails key={envelope.event_sha256} envelope={envelope} />
            ))}
          </ol>
        </section>

        <section aria-labelledby="image-details-title">
          <h2 id="image-details-title">Immutable images</h2>
          <ul className="image-records">
            {payload.images.map((image) => {
              const imageDigest = image.reference.split("@sha256:")[1];
              return (
                <li key={image.component}>
                  <strong>{image.component}</strong>
                  <span>Schema: <RawValue>{image.schema_version}</RawValue></span>
                  <span>Image SHA-256: <RawValue>{imageDigest}</RawValue></span>
                  <span>Reference: <RawValue>{image.reference}</RawValue></span>
                </li>
              );
            })}
          </ul>
        </section>
      </div>
    </details>
  );
}

function ReplayStatus({
  status,
  heading,
  message,
  action,
}: {
  readonly status: "loading" | "unavailable" | "invalid";
  readonly heading: string;
  readonly message: string;
  readonly action?: string;
}) {
  const loading = status === "loading";
  const invalid = status === "invalid";
  return (
    <main className="replay-shell replay-status" aria-busy={loading}>
      <section
        className={`replay-status-card replay-status-card--${status}`}
        role={invalid ? "alert" : "status"}
        aria-live={invalid ? "assertive" : "polite"}
      >
        <span className="status-mark" aria-hidden="true" />
        <p className="eyebrow">ControlGraph public replay</p>
        <h1>{heading}</h1>
        <p>{message}</p>
        {action !== undefined && (
          <a className="status-action" href="/replay">{action}</a>
        )}
      </section>
    </main>
  );
}

export function PublicReplayApp() {
  const [state, setState] = useState<ReplayState>({ status: "loading" });

  useEffect(() => {
    let active = true;
    void loadPublicReplay()
      .then((replay) => {
        if (active) {
          setState(replay === null ? { status: "unavailable" } : { status: "ready", replay });
        }
      })
      .catch(() => {
        if (active) {
          setState({ status: "invalid" });
        }
      });
    return () => {
      active = false;
    };
  }, []);

  if (state.status === "loading") {
    return (
      <ReplayStatus
        status="loading"
        heading="Verifying public replay"
        message="Checking the artifact, closed schema, case bindings, and event chain before showing evidence."
      />
    );
  }
  if (state.status === "unavailable") {
    return (
      <ReplayStatus
        status="unavailable"
        heading="No public replay available"
        message="No accepted replay is currently published. Nothing has been inferred or substituted."
        action="Check again"
      />
    );
  }
  if (state.status === "invalid") {
    return (
      <ReplayStatus
        status="invalid"
        heading="Replay could not be verified"
        message="The replay could not be loaded and verified, so it remains hidden. No evidence has been inferred or rendered."
        action="Retry replay"
      />
    );
  }

  const { payload } = state.replay;
  const authority = payload.events[0].event.details;
  const denial = payload.events[1].event.details;
  const unchanged = record(payload.events[2].event.details.before_denial);
  const advisor = record(payload.events[3].event.details).advisor as PublicReplayAdvisor;
  const recoveryDetails = payload.events[4].event.details;
  const recovery = record(payload.events[4].event.details.traffic);

  return (
    <main className="replay-shell">
      <header className="replay-header">
        <p className="eyebrow">Recorded demo replay · accepted hosted run · credential-free</p>
        <h1>Stale promotion blocked</h1>
        <p className="lede">
          Approval advanced from epoch {String(authority.previous_epoch)} (N) to epoch{" "}
          {String(authority.new_epoch)} (N+1). At the final gate, authority at execution time no
          longer matched queued epoch {String(denial.work_epoch)}, so the promotion ended{" "}
          {String(denial.outcome)} / {String(denial.reason_code)} before any target change.
          Independent readback confirmed {traffic(unchanged)} unchanged, and current-epoch recovery
          was {String(recoveryDetails.outcome)} at {traffic(recovery)}.
        </p>

        <section className="outcome-summary" aria-labelledby="outcome-summary-title">
          <h2 id="outcome-summary-title" className="visually-hidden">Outcome summary</h2>
          <OutcomeCard
            label="Queued promotion"
            value="Blocked"
            detail={`${String(denial.outcome)} / ${String(denial.reason_code)}`}
            tone="blocked"
          />
          <OutcomeCard
            label="Traffic after denial"
            value={`${String(unchanged.stable_percent)} / ${String(unchanged.candidate_percent)}`}
            detail="Stable / candidate · unchanged"
            tone="held"
          />
          <OutcomeCard
            label="Verified recovery"
            value={`${String(recovery.stable_percent)}% stable`}
            detail={`${String(recovery.candidate_percent)}% candidate`}
            tone="recovered"
          />
        </section>
      </header>

      <section className="replay-verification" aria-label="Replay verification" role="status" aria-live="polite">
        <span className="verification-mark" aria-hidden="true">✓</span>
        <div>
          <strong>Browser verification passed</strong>
          <span>Artifact hash · closed schema · payload digest · case bindings · event chain</span>
        </div>
      </section>

      <AcceptedRunProvenance replay={state.replay} />

      <section className="replay-sequence" aria-labelledby="replay-sequence-title">
        <div className="section-heading">
          <p className="eyebrow">What happened</p>
          <h2 id="replay-sequence-title">From revoked approval to stable recovery</h2>
        </div>
        <ol className="replay-events" role="list">
          {payload.events.map(({ event, event_sha256: eventSha256 }) => {
            const headingId = `replay-event-${event.sequence}`;
            return (
              <li key={eventSha256} className="replay-event">
                <div className="event-index" aria-hidden="true">
                  {String(event.sequence).padStart(2, "0")}
                </div>
                <article aria-labelledby={headingId}>
                  <p className="event-time"><ReplayTime value={event.occurred_at} /></p>
                  <h3 id={headingId}>{eventLabel(event)}</h3>
                  <EventFacts event={event} />
                </article>
              </li>
            );
          })}
        </ol>
      </section>

      <AdvisorOverview advisor={advisor} />

      <VerificationDetails replay={state.replay} />

      <footer>
        This replay is evidence only. It has no sign-in, protected API access, or mutation action.
      </footer>
    </main>
  );
}
