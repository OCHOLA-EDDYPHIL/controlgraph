import { useEffect, useMemo, useRef, useState, type RefObject } from "react";

import {
  OperatorApiError,
  createBrowserOperatorApi,
  newAdvisorIdentity,
  newRevocationIdentity,
  type OperatorApi,
  type RevocationResult,
} from "./api/operator";
import type { AdvisorOperatorResult } from "./contracts/modelAssistance";
import type { TargetBinding, TimelineEntry } from "./contracts/timeline";
import {
  displayField,
  eventPresentation,
  formatTimestamp,
  hasPartialEvidence,
  healthSummary,
  outcomeSummary,
  shortDigest,
  trafficSummary,
} from "./timelinePresentation";
import {
  useOperatorConsole,
  type ConsolePhase,
  type ReviewedAuthority,
  type RevocationResolution,
} from "./useOperatorConsole";

interface AppProps {
  readonly api?: OperatorApi;
  readonly pollIntervalMs?: number;
}

type RevocationStatus =
  | "IDLE"
  | "PREPARING"
  | "REVIEWING"
  | "SUBMITTING"
  | "COMMITTED"
  | "TIMELINE_CONFIRMED"
  | "SUPERSEDED"
  | "STALE"
  | "AMBIGUOUS"
  | "DENIED"
  | "FAILED";

type AdvisorStatus = "IDLE" | "RUNNING" | "COMPLETE" | "STALE" | "FAILED";

interface EligibleDenial {
  readonly entry: TimelineEntry;
  readonly target: TargetBinding;
  readonly currentEpoch: number;
}

interface AdvisorBinding {
  readonly entrySha256: string;
  readonly rootSha256: string;
  readonly currentEpoch: number;
  readonly headSequence: number;
  readonly headEntrySha256: string | null;
}

// Reserve the final 60 seconds of the backend's 300-second evidence lifetime for
// the bounded model call and response validation.
const ADVISOR_REQUEST_WINDOW_MS = 240_000;

function uniqueCorrelation(
  entry: TimelineEntry,
  kind: "EVIDENCE" | "REQUEST",
): string | null {
  const matches = entry.correlations.filter((correlation) => correlation.kind === kind);
  return matches.length === 1 ? matches[0]!.correlationId : null;
}

function isCorrelatedOperatorRevocation(
  entry: TimelineEntry,
  transition: TimelineEntry,
  denialSequence: number,
): boolean {
  const evidenceId = uniqueCorrelation(transition, "EVIDENCE");
  const requestId = uniqueCorrelation(transition, "REQUEST");
  return (
    evidenceId !== null &&
    requestId !== null &&
    entry.rootId === transition.rootId &&
    entry.rootSha256 === transition.rootSha256 &&
    entry.epoch === transition.epoch &&
    entry.sequence < denialSequence &&
    entry.occurredAt === transition.occurredAt &&
    entry.eventType === "OPERATOR_ACTION_RECORDED" &&
    entry.actorRole === "OPERATOR" &&
    entry.signature === null &&
    entry.verificationStatus === "NOT_APPLICABLE" &&
    entry.displayFields.some(
      (field) => field.name === "ACTION" && field.value === "REVOKE_EPOCH",
    ) &&
    uniqueCorrelation(entry, "EVIDENCE") === evidenceId &&
    uniqueCorrelation(entry, "REQUEST") === requestId
  );
}

function eligibleEpochMismatchDenial(
  phase: ConsolePhase,
  target: TargetBinding | null,
  authority: ReviewedAuthority | null | {
    readonly rootId: string;
    readonly rootSha256: string;
    readonly epoch: number;
  },
  entries: readonly TimelineEntry[],
  nowMs: number,
): EligibleDenial | null {
  if (phase !== "LIVE" || target === null || authority === null) {
    return null;
  }
  const latestReceipt = [...entries]
    .reverse()
    .find(
      (entry) =>
        entry.rootId === authority.rootId &&
        entry.rootSha256 === authority.rootSha256 &&
        entry.eventType.startsWith("MUTATION_"),
    );
  if (latestReceipt === undefined || latestReceipt.eventType !== "MUTATION_DENIED") {
    return null;
  }
  const reason = latestReceipt.displayFields.find(
    (field) => field.name === "REASON_CODE",
  )?.value;
  const outcome = latestReceipt.displayFields.find(
    (field) => field.name === "OUTCOME",
  )?.value;
  const authorityTransition = [...entries]
    .reverse()
    .find(
      (entry) =>
        entry.rootId === authority.rootId &&
        entry.rootSha256 === authority.rootSha256 &&
        entry.eventType === "AUTHORITY_EPOCH_ADVANCED" &&
        entry.actorRole === "OPERATOR" &&
        entry.epoch === authority.epoch &&
        entry.sequence < latestReceipt.sequence &&
        entry.signature !== null &&
        entry.signature.purpose === "EVIDENCE" &&
        entry.verificationStatus === "VERIFIED" &&
        entries.some((candidate) =>
          isCorrelatedOperatorRevocation(candidate, entry, latestReceipt.sequence),
        ),
    );
  const occurredAtMs = new Date(latestReceipt.occurredAt).valueOf();
  const ageMs = nowMs - occurredAtMs;
  if (
    reason !== "EPOCH_MISMATCH" ||
    outcome !== "DENIED" ||
    latestReceipt.epoch + 1 !== authority.epoch ||
    authorityTransition === undefined ||
    !Number.isFinite(occurredAtMs) ||
    ageMs < 0 ||
    ageMs >= ADVISOR_REQUEST_WINDOW_MS
  ) {
    return null;
  }
  return { entry: latestReceipt, target, currentEpoch: authority.epoch };
}

function advisorResultMatchesView(
  binding: AdvisorBinding | null,
  result: AdvisorOperatorResult | null,
  eligible: EligibleDenial | null,
  entries: readonly TimelineEntry[],
  head: { readonly afterSequence: number; readonly afterEntrySha256: string | null },
): boolean {
  if (binding === null || result === null || eligible === null) {
    return false;
  }
  if (
    eligible.entry.entrySha256 !== binding.entrySha256 ||
    eligible.entry.rootSha256 !== binding.rootSha256 ||
    eligible.currentEpoch !== binding.currentEpoch
  ) {
    return false;
  }
  if (
    head.afterSequence === binding.headSequence &&
    head.afterEntrySha256 === binding.headEntrySha256
  ) {
    return true;
  }
  const laterEntries = entries.filter(
    (entry) => entry.sequence > binding.headSequence,
  );
  return (
    laterEntries.length > 0 &&
    laterEntries.at(-1)?.sequence === head.afterSequence &&
    laterEntries.at(-1)?.entrySha256 === head.afterEntrySha256 &&
    laterEntries.every(
      (entry) =>
        entry.eventType === "MODEL_ASSISTANCE_RECORDED" &&
        entry.correlations.some(
          (correlation) =>
            correlation.kind === "MODEL" &&
            correlation.correlationId === result.interaction_id,
        ),
    )
  );
}

function actionLabel(value: string): string {
  return value.replaceAll("_", " ");
}

function advisorActionLabel(value: string): string {
  switch (value) {
    case "wait":
      return "Wait for more evidence";
    case "collect_approved_diagnostics":
      return "Collect approved diagnostics";
    case "request_revocation":
      return "Review epoch revocation";
    case "request_captured_stable_recovery":
      return "Review recovery to the captured stable revision";
    case "request_new_operator_approved_rollout":
      return "Review a new operator-approved rollout";
    case "manual_review":
      return "Continue with manual review";
    default:
      return actionLabel(value);
  }
}

function AdvisorInvestigation({
  eligible,
  status,
  result,
  run,
}: {
  readonly eligible: EligibleDenial | null;
  readonly status: AdvisorStatus;
  readonly result: AdvisorOperatorResult | null;
  readonly run: () => Promise<void>;
}) {
  if (eligible === null && status !== "STALE") {
    return null;
  }
  const recommendation = result?.response.recommendation ?? null;
  return (
    <section className="advisor-investigation" aria-labelledby="advisor-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Denied work · optional explanation</p>
          <h2 id="advisor-title">Why the queued action was denied</h2>
        </div>
        <p>
          The denial comes from deterministic checks. The advisor cannot approve work or change
          traffic.
        </p>
      </div>

      {eligible !== null && (
        <article className="denial-proof">
          <div>
            <span className="proof-kicker">Decision made before advisor analysis</span>
            <strong>Queued work was denied</strong>
            <p>
              This work was approved for epoch {eligible.entry.epoch}, but the root is now at epoch{" "}
              {eligible.currentEpoch}. The authority check blocked it before any provider change.
            </p>
            <code className="decision-code">DENIED · EPOCH_MISMATCH</code>
          </div>
          <dl>
            <div>
              <dt>Issued authority</dt>
              <dd>Epoch {eligible.entry.epoch}</dd>
            </div>
            <div>
              <dt>Current authority</dt>
              <dd>Epoch {eligible.currentEpoch}</dd>
            </div>
          </dl>
        </article>
      )}

      {status === "STALE" && (
        <div className="advisor-state advisor-state--warning" role="status">
          The authority or latest mutation receipt changed. The prior analysis was hidden.
        </div>
      )}
      {status === "FAILED" && eligible !== null && (
        <div className="advisor-state advisor-state--warning" role="alert">
          Evidence analysis was unavailable. The deterministic denial remains unchanged.
        </div>
      )}

      {eligible !== null && result === null && status !== "STALE" && (
        <div className="advisor-launch">
          <div>
            <strong>Ask the read-only advisor for an explanation</strong>
            <p>
              It summarizes named evidence and validates every citation. Its answer cannot
              change this decision.
            </p>
          </div>
          <button
            className="button button--advisory"
            type="button"
            disabled={status === "RUNNING"}
            onClick={asyncAction(run)}
          >
            {status === "RUNNING" ? "Analyzing evidence…" : "Analyze evidence"}
          </button>
        </div>
      )}

      {result !== null && recommendation === null && (
        <div className="advisor-state advisor-state--warning" role="status">
          <strong>No model recommendation was accepted.</strong>
          <span>
            Safe fallback: {actionLabel(result.response.audit.fallback_code ?? "unknown")}.
            Review the named deterministic evidence instead.
          </span>
        </div>
      )}

      {result !== null && recommendation !== null && (
        <article className="advisor-result" aria-label="Validated Gemini evidence analysis">
          <header>
            <div>
              <span className="proof-kicker">Validated advisory · operator review required</span>
              <h3>{advisorActionLabel(recommendation.requested_operator_action)}</h3>
            </div>
            <strong>{(recommendation.confidence_basis_points / 100).toFixed(2)}% confidence</strong>
          </header>

          <div className="advisor-boundary">
            Advice only. It cannot approve work, override deterministic health decisions, or
            change the target.
            <span>
              Authority effect: <strong>{recommendation.authority_effect}</strong> · deterministic
              health override:{" "}
              <strong>{String(recommendation.deterministic_health_override)}</strong>
            </span>
          </div>

          <div className="advisor-columns">
            <section aria-labelledby="advisor-findings">
              <h4 id="advisor-findings">Causal findings</h4>
              <ol className="advisor-findings">
                {recommendation.findings.map((finding, index) => (
                  <li key={`${index}:${finding.statement}`}>
                    <p>{finding.statement}</p>
                    <ul aria-label={`Citations for finding ${index + 1}`}>
                      {finding.citations.map((citation) => (
                        <li key={`${citation.evidence_kind}:${citation.evidence_id}`}>
                          <span>{citation.evidence_kind}</span>{" "}
                          <code>{citation.evidence_id}</code>
                        </li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ol>
            </section>
            <section aria-labelledby="advisor-uncertainties">
              <h4 id="advisor-uncertainties">Uncertainty retained</h4>
              <ul className="advisor-uncertainties">
                {recommendation.uncertainties.map((uncertainty) => (
                  <li key={uncertainty}>{uncertainty}</li>
                ))}
              </ul>
              {recommendation.manual_review_reason !== null && (
                <p className="manual-review-reason">{recommendation.manual_review_reason}</p>
              )}
            </section>
          </div>

          <details className="advisor-audit">
            <summary>Technical model and tool details</summary>
            <dl>
              <div><dt>Model</dt><dd>{result.response.audit.model_id}</dd></div>
              <div><dt>Prompt</dt><dd>{result.response.audit.prompt_version}</dd></div>
              <div><dt>Interaction</dt><dd><code>{result.interaction_id}</code></dd></div>
              <div><dt>Replay</dt><dd>{result.replayed ? "exact idempotent replay" : "fresh invocation"}</dd></div>
              <div><dt>Authority effect</dt><dd>{recommendation.authority_effect}</dd></div>
              <div><dt>Health override</dt><dd>{String(recommendation.deterministic_health_override)}</dd></div>
              {recommendation.findings.flatMap((finding, findingIndex) =>
                finding.citations.map((citation, citationIndex) => (
                  <div key={`${findingIndex}:${citationIndex}:${citation.evidence_id}`}>
                    <dt>{citation.evidence_kind} citation</dt>
                    <dd>
                      <code>{citation.evidence_id}</code>{" "}
                      <code>{shortDigest(citation.source_sha256)}</code>
                    </dd>
                  </div>
                )),
              )}
            </dl>
            <ol>
              {result.response.audit.tool_calls.map((tool) => (
                <li key={tool.sequence}>
                  <strong>{tool.sequence}. {tool.tool_id}</strong>
                  <span>{tool.status}</span>
                  <code>in {shortDigest(tool.input_sha256)}</code>
                  {tool.output_sha256 !== null && (
                    <code>out {shortDigest(tool.output_sha256)}</code>
                  )}
                </li>
              ))}
            </ol>
          </details>
        </article>
      )}
    </section>
  );
}

function asyncAction(action: () => Promise<unknown>): () => void {
  return () => {
    void action().catch(() => undefined);
  };
}

function phaseNotice(phase: ConsolePhase): {
  readonly heading: string;
  readonly message: string;
} | null {
  switch (phase) {
    case "AUTHENTICATING":
      return {
        heading: "Checking operator identity",
        message: "Verifying access before requesting target evidence.",
      };
    case "LOADING":
      return {
        heading: "Loading verified evidence",
        message: "Reading and validating the signed operator timeline.",
      };
    case "RECONNECTING":
      return {
        heading: "Connection interrupted",
        message: "The next read will continue from the last verified timeline position.",
      };
    case "EMPTY":
      return {
        heading: "No rollout evidence yet",
        message: "The verified timeline is empty. Authority actions become available after a rollout root is recorded.",
      };
    case "STALE":
      return {
        heading: "Timeline reload required",
        message: "This view is stale. Authority actions are blocked until the timeline is reloaded from its first entry.",
      };
    case "PARTIAL":
      return {
        heading: "Evidence could not be fully verified",
        message: "Timeline evidence is partial or failed validation. No authority action is available from this view.",
      };
    case "DENIED":
      return {
        heading: "Access denied",
        message: "An authenticated operator identity is required for this target.",
      };
    case "FAILED":
      return {
        heading: "Console unavailable",
        message: "The operator API is unavailable. Existing evidence has not been replaced or inferred.",
      };
    case "LIVE":
      return null;
  }
}

function ConnectionNotice({
  phase,
  stableCode,
  reconnect,
  reload,
}: {
  readonly phase: ConsolePhase;
  readonly stableCode: string | null;
  readonly reconnect: () => Promise<void>;
  readonly reload: () => Promise<void>;
}) {
  const notice = phaseNotice(phase);
  if (notice === null) {
    return null;
  }
  const isBusy = phase === "AUTHENTICATING" || phase === "LOADING";
  const isAlert = ["STALE", "PARTIAL", "DENIED", "FAILED"].includes(phase);
  return (
    <section
      className={`connection-notice connection-notice--${phase.toLowerCase()}`}
      role={isAlert ? "alert" : "status"}
      aria-live={isAlert ? "assertive" : "polite"}
    >
      <span className="connection-notice__signal" aria-hidden="true" />
      <div>
        <h2>{notice.heading}</h2>
        <p>{notice.message}</p>
        {stableCode !== null && <code>{stableCode}</code>}
      </div>
      {!isBusy && phase === "RECONNECTING" && (
        <button className="button button--quiet" type="button" onClick={asyncAction(reconnect)}>
          Reconnect
        </button>
      )}
      {!isBusy && phase !== "RECONNECTING" && (
        <button className="button button--quiet" type="button" onClick={asyncAction(reload)}>
          {phase === "DENIED"
            ? "Retry authentication"
            : phase === "EMPTY"
              ? "Check again"
              : "Reload timeline"}
        </button>
      )}
    </section>
  );
}

function SummaryCard({ label, value, detail }: {
  readonly label: string;
  readonly value: string;
  readonly detail: string;
}) {
  return (
    <article className="summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

function EventBindings({ entry }: { readonly entry: TimelineEntry }) {
  return (
    <details className="event-bindings">
      <summary>Technical details</summary>
      <dl>
        <div>
          <dt>Epoch</dt>
          <dd>{entry.epoch}</dd>
        </div>
        <div>
          <dt>Verification</dt>
          <dd>{entry.verificationStatus.toLowerCase().replaceAll("_", " ")}</dd>
        </div>
        <div>
          <dt>Signature metadata</dt>
          <dd>
            {entry.signature === null
              ? "Not present"
              : `Signed ${entry.signature.purpose.toLowerCase().replaceAll("_", " ")}`}
          </dd>
        </div>
        <div>
          <dt>Terminal classification</dt>
          <dd>{entry.terminalClassification.toLowerCase().replaceAll("_", " ")}</dd>
        </div>
        <div>
          <dt>Entry</dt>
          <dd><code>{shortDigest(entry.entrySha256)}</code></dd>
        </div>
        <div>
          <dt>Payload</dt>
          <dd><code>{shortDigest(entry.payloadSha256)}</code></dd>
        </div>
        <div>
          <dt>Actor</dt>
          <dd>{entry.actorRole.toLowerCase().replaceAll("_", " ")}</dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd>{entry.sourceSchemaVersion}</dd>
        </div>
      </dl>
      {entry.displayFields.length > 0 && (
        <dl className="display-fields" aria-label="Server-provided evidence fields">
          {entry.displayFields.map((field) => (
            <div key={field.name}>
              <dt>{field.name.toLowerCase().replaceAll("_", " ")}</dt>
              <dd>{field.value}</dd>
            </div>
          ))}
        </dl>
      )}
      {entry.correlations.length > 0 && (
        <div className="correlations" aria-label="Event correlations">
          {entry.correlations.map((correlation) => (
            <span key={`${correlation.kind}:${correlation.correlationId}`}>
              {correlation.kind.toLowerCase()}: {correlation.correlationId}
            </span>
          ))}
        </div>
      )}
    </details>
  );
}

function TimelineEvent({
  entry,
  entries,
}: {
  readonly entry: TimelineEntry;
  readonly entries: readonly TimelineEntry[];
}) {
  const presentation = eventPresentation(entry, entries);
  const decisiveOutcome = displayField(entry, "OUTCOME");
  const decisiveReason = displayField(entry, "REASON_CODE");
  const summary =
    entry.eventType === "VERIFICATION_RECORDED"
      ? displayField(entry, "OBSERVATION") ?? displayField(entry, "SUMMARY")
      : displayField(entry, "SUMMARY") ??
        displayField(entry, "OBSERVATION") ??
        displayField(entry, "OUTCOME");
  return (
    <li className={`timeline-event timeline-event--${presentation.tone.toLowerCase()}`}>
      <div className="timeline-event__rail" aria-hidden="true">
        <span>{String(entry.sequence).padStart(2, "0")}</span>
      </div>
      <article aria-labelledby={`event-${entry.sequence}`}>
        <div className="timeline-event__heading">
          <div>
            <p>{presentation.category}</p>
            <h3 id={`event-${entry.sequence}`}>{presentation.title}</h3>
          </div>
          <time dateTime={entry.occurredAt}>{formatTimestamp(entry.occurredAt)} UTC</time>
        </div>
        {summary !== null && <p className="timeline-event__summary">{summary}</p>}
        <div
          className="timeline-event__facts"
          role="group"
          aria-label="Decisive event outcome"
        >
          <span>Epoch {entry.epoch}</span>
          <span>
            Record {entry.verificationStatus.toLowerCase().replaceAll("_", " ")}
          </span>
          {decisiveOutcome !== null && (
            <span>Outcome {decisiveOutcome.replaceAll("_", " ")}</span>
          )}
          {decisiveReason !== null && (
            <span>Reason {decisiveReason.replaceAll("_", " ")}</span>
          )}
          {entry.terminalClassification !== "NONE" && (
            <span>{entry.terminalClassification.toLowerCase().replaceAll("_", " ")}</span>
          )}
        </div>
        {presentation.advisory && (
          <p className="advisory-boundary">
            Advisory only. This event cannot authorize, classify, enqueue, or mutate a rollout.
          </p>
        )}
        <EventBindings entry={entry} />
      </article>
    </li>
  );
}

function RevocationOutcome({
  status,
  result,
  resolution,
  checkTimeline,
  outcomeRef,
}: {
  readonly status: RevocationStatus;
  readonly result: RevocationResult | null;
  readonly resolution: RevocationResolution | null;
  readonly checkTimeline: () => Promise<void>;
  readonly outcomeRef: RefObject<HTMLElement>;
}) {
  if (status === "COMMITTED" && result !== null) {
    return (
      <section
        ref={outcomeRef}
        className="action-result action-result--success"
        role="status"
        aria-live="polite"
        tabIndex={-1}
      >
        <span aria-hidden="true">✓</span>
        <div>
          <strong>Authority revoked at epoch {result.newEpoch}</strong>
          <p>
            The committed evidence identifier is <code>{result.evidenceId}</code>. Timeline
            admission may follow this direct response.
          </p>
        </div>
      </section>
    );
  }
  if (status === "AMBIGUOUS") {
    return (
      <section
        ref={outcomeRef}
        className="action-result action-result--danger"
        role="alert"
        tabIndex={-1}
      >
        <span aria-hidden="true">!</span>
        <div>
          <strong>Revocation outcome is unknown</strong>
          <p>
            The request may have committed. It will not be retried blindly; reconnect the
            timeline and inspect the authority epoch first.
          </p>
          <button className="button button--quiet" type="button" onClick={asyncAction(checkTimeline)}>
            Check timeline
          </button>
        </div>
      </section>
    );
  }
  if (status === "TIMELINE_CONFIRMED" && resolution?.status === "CONFIRMED") {
    return (
      <section
        ref={outcomeRef}
        className="action-result action-result--success"
        role="status"
        aria-live="polite"
        tabIndex={-1}
      >
        <span aria-hidden="true">✓</span>
        <div>
          <strong>Revocation confirmed by timeline at epoch {resolution.epoch}</strong>
          <p>
            {resolution.evidenceId === null
              ? "The correlated operator action is admitted in the target history."
              : <>Correlated evidence: <code>{resolution.evidenceId}</code>.</>}
          </p>
        </div>
      </section>
    );
  }
  if (status === "SUPERSEDED") {
    return (
      <section
        ref={outcomeRef}
        className="action-result action-result--warning"
        role="alert"
        tabIndex={-1}
      >
        <span aria-hidden="true">!</span>
        <div>
          <strong>Authority advanced without a matching request</strong>
          <p>The ambiguous request was not correlated. Review the newer root and epoch before another action.</p>
        </div>
      </section>
    );
  }
  if (status === "STALE") {
    return (
      <section
        ref={outcomeRef}
        className="action-result action-result--warning"
        role="alert"
        tabIndex={-1}
      >
        <span aria-hidden="true">!</span>
        <div>
          <strong>Revocation review expired</strong>
          <p>The root or epoch changed before submission. No stale command was sent.</p>
        </div>
      </section>
    );
  }
  if (status === "DENIED" || status === "FAILED") {
    return (
      <section
        ref={outcomeRef}
        className="action-result action-result--danger"
        role="alert"
        tabIndex={-1}
      >
        <span aria-hidden="true">!</span>
        <div>
          <strong>{status === "DENIED" ? "Revocation denied" : "Revocation failed safely"}</strong>
          <p>
            {status === "DENIED"
              ? "The authenticated identity is not permitted to revoke this root."
              : "No successful authority transition was accepted by this console."}
          </p>
        </div>
      </section>
    );
  }
  return null;
}

function RevocationDialog({
  reviewed,
  reason,
  confirmed,
  submitting,
  setReason,
  setConfirmed,
  close,
  submit,
}: {
  readonly reviewed: ReviewedAuthority;
  readonly reason: string;
  readonly confirmed: boolean;
  readonly submitting: boolean;
  readonly setReason: (value: string) => void;
  readonly setConfirmed: (value: boolean) => void;
  readonly close: () => void;
  readonly submit: () => Promise<void>;
}) {
  const dialogRef = useRef<HTMLElement>(null);
  const reasonIsValid =
    reason.length >= 12 && reason.length <= 512 && reason === reason.trim();
  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog === null) {
      return undefined;
    }
    const handleKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape" && !submitting) {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "Tab") {
        return;
      }
      const focusable = [...dialog.querySelectorAll<HTMLElement>(
        'button:not([disabled]), textarea:not([disabled]), input:not([disabled])',
      )];
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0]!;
      const last = focusable.at(-1)!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    dialog.addEventListener("keydown", handleKeyDown);
    return () => dialog.removeEventListener("keydown", handleKeyDown);
  }, [close, submitting]);
  return (
    <div className="dialog-backdrop">
      <section
        ref={dialogRef}
        className="revocation-dialog"
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="revocation-title"
        aria-describedby="revocation-description"
      >
        <div className="dialog-heading">
          <div>
            <p className="eyebrow">Authority change</p>
            <h2 id="revocation-title">Review epoch revocation</h2>
          </div>
          <button className="icon-button" type="button" onClick={close} disabled={submitting}>
            <span aria-hidden="true">×</span>
            <span className="sr-only">Close revocation review</span>
          </button>
        </div>
        <p id="revocation-description" className="dialog-intro">
          Revoking moves this root from epoch {reviewed.epoch} to {reviewed.epoch + 1}. Any queued
          work approved for epoch {reviewed.epoch} will be rejected at its next authority check.
          Revocation does not change traffic itself. Work that has already passed its final
          authority check may still complete.
        </p>
        <dl className="review-grid">
          <div className="review-grid__target">
            <dt>Target under review</dt>
            <dd>
              <strong>{reviewed.target.service_name}</strong>
              <span>
                {reviewed.target.project_id} · {reviewed.target.region} ·{" "}
                {reviewed.target.environment}
              </span>
            </dd>
          </div>
          <div>
            <dt>Root under review</dt>
            <dd><code>{reviewed.rootId}</code></dd>
          </div>
          <div>
            <dt>Expected epoch</dt>
            <dd><strong>{reviewed.epoch}</strong> → {reviewed.epoch + 1}</dd>
          </div>
        </dl>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void submit();
          }}
        >
          <label htmlFor="revocation-reason">Reason for revocation</label>
          <textarea
            id="revocation-reason"
            autoFocus
            rows={4}
            minLength={12}
            maxLength={512}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            aria-describedby="reason-help"
            disabled={submitting}
            required
          />
          <div className="field-help" id="reason-help">
            <span>Use 12–512 characters with no leading or trailing whitespace.</span>
            <span>{reason.length}/512</span>
          </div>
          <label className="confirmation" htmlFor="revocation-confirmation">
            <input
              id="revocation-confirmation"
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
              disabled={submitting}
            />
            <span>
              I reviewed root <code>{shortDigest(reviewed.rootSha256)}</code> and understand that
              revoking epoch {reviewed.epoch} advances authority to epoch {reviewed.epoch + 1}
              and makes work approved for epoch {reviewed.epoch} stale.
            </span>
          </label>
          <div className="dialog-actions">
            <button className="button button--quiet" type="button" onClick={close} disabled={submitting}>
              Cancel
            </button>
            <button
              className="button button--danger"
              type="submit"
              disabled={!reasonIsValid || !confirmed || submitting}
            >
              {submitting
                ? "Checking fresh epoch…"
                : `Revoke and advance to epoch ${reviewed.epoch + 1}`}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

export function App({ api, pollIntervalMs = 10_000 }: AppProps) {
  const operatorApi = useMemo(() => api ?? createBrowserOperatorApi(), [api]);
  const controller = useOperatorConsole(operatorApi, pollIntervalMs);
  const { view } = controller;
  const [revocationStatus, setRevocationStatus] = useState<RevocationStatus>("IDLE");
  const [reviewed, setReviewed] = useState<ReviewedAuthority | null>(null);
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [requestIdentity, setRequestIdentity] = useState<ReturnType<
    typeof newRevocationIdentity
  > | null>(null);
  const [revocationResult, setRevocationResult] = useState<RevocationResult | null>(null);
  const [revocationResolution, setRevocationResolution] =
    useState<RevocationResolution | null>(null);
  const [advisorStatus, setAdvisorStatus] = useState<AdvisorStatus>("IDLE");
  const [advisorResult, setAdvisorResult] = useState<AdvisorOperatorResult | null>(null);
  const [advisorBinding, setAdvisorBinding] = useState<AdvisorBinding | null>(null);
  const reviewButtonRef = useRef<HTMLButtonElement>(null);
  const revocationOutcomeRef = useRef<HTMLElement>(null);
  const consoleContentRef = useRef<HTMLDivElement>(null);
  const dialogWasOpen = useRef(false);
  const previousRevocationStatus = useRef<RevocationStatus>("IDLE");

  const dialogOpen =
    reviewed !== null &&
    (revocationStatus === "REVIEWING" || revocationStatus === "SUBMITTING");

  const eligibleDenial = useMemo(
    () =>
      eligibleEpochMismatchDenial(
        view.phase,
        view.target,
        view.authority,
        view.entries,
        Date.now(),
      ),
    [view.authority, view.entries, view.phase, view.target],
  );
  const advisorResultIsCurrent = useMemo(
    () =>
      advisorResultMatchesView(
        advisorBinding,
        advisorResult,
        eligibleDenial,
        view.entries,
        view.head,
      ),
    [advisorBinding, advisorResult, eligibleDenial, view.entries, view.head],
  );

  useEffect(() => {
    if (advisorResult !== null && !advisorResultIsCurrent) {
      setAdvisorResult(null);
      setAdvisorStatus("STALE");
    }
  }, [advisorResult, advisorResultIsCurrent]);

  useEffect(() => {
    const content = consoleContentRef.current;
    if (content !== null) {
      content.inert = dialogOpen;
      content.setAttribute("aria-hidden", dialogOpen ? "true" : "false");
    }
    if (!dialogOpen && previousRevocationStatus.current !== revocationStatus) {
      if (
        ["COMMITTED", "TIMELINE_CONFIRMED", "SUPERSEDED", "STALE", "AMBIGUOUS", "DENIED", "FAILED"].includes(
          revocationStatus,
        )
      ) {
        revocationOutcomeRef.current?.focus();
      } else if (dialogWasOpen.current) {
        reviewButtonRef.current?.focus();
      }
    } else if (dialogWasOpen.current && !dialogOpen) {
      reviewButtonRef.current?.focus();
    }
    dialogWasOpen.current = dialogOpen;
    previousRevocationStatus.current = revocationStatus;
    return () => {
      if (content !== null) {
        content.inert = false;
        content.removeAttribute("aria-hidden");
      }
    };
  }, [dialogOpen, revocationStatus]);

  const canRevoke =
    view.phase === "LIVE" &&
    view.authority !== null &&
    revocationStatus !== "AMBIGUOUS" &&
    revocationStatus !== "PREPARING" &&
    revocationStatus !== "SUBMITTING" &&
    !(
      revocationStatus === "COMMITTED" &&
      revocationResult !== null &&
      view.authority.epoch < revocationResult.newEpoch
    ) &&
    !(
      revocationStatus === "TIMELINE_CONFIRMED" &&
      revocationResolution?.epoch !== null &&
      revocationResolution?.epoch !== undefined &&
      view.authority.epoch < revocationResolution.epoch
    );

  const openRevocationReview = async (): Promise<void> => {
    setRevocationStatus("PREPARING");
    setRevocationResult(null);
    setRevocationResolution(null);
    try {
      const fresh = await controller.reviewAuthority();
      setReviewed(fresh);
      setRequestIdentity(newRevocationIdentity());
      setReason("");
      setConfirmed(false);
      setRevocationStatus("REVIEWING");
    } catch {
      setRevocationStatus("FAILED");
    }
  };

  const submitRevocation = async (): Promise<void> => {
    if (
      reviewed === null ||
      requestIdentity === null ||
      reason.length < 12 ||
      reason.length > 512 ||
      reason !== reason.trim() ||
      !confirmed
    ) {
      return;
    }
    setRevocationStatus("SUBMITTING");
    try {
      const result = await controller.revokeReviewed(reviewed, {
        ...requestIdentity,
        reason,
      });
      setRevocationResult(result);
      setReviewed(null);
      setRevocationStatus("COMMITTED");
      void controller.reconnect().catch(() => undefined);
    } catch (error) {
      let keepForReconciliation = true;
      if (error instanceof OperatorApiError) {
        if (error.kind === "STALE_AUTHORITY" || error.kind === "CONFLICT") {
          setRevocationStatus("STALE");
          keepForReconciliation = false;
        } else if (
          error.kind === "AUTHENTICATION_REQUIRED" ||
          error.kind === "ACCESS_DENIED"
        ) {
          setRevocationStatus("DENIED");
          keepForReconciliation = false;
        } else if (error.kind === "UNAVAILABLE") {
          setRevocationStatus("AMBIGUOUS");
        } else {
          setRevocationStatus("AMBIGUOUS");
        }
      } else {
        setRevocationStatus("AMBIGUOUS");
      }
      if (!keepForReconciliation) {
        setReviewed(null);
      }
    }
  };

  const checkAmbiguousRevocation = async (): Promise<void> => {
    if (reviewed === null || requestIdentity === null) {
      return;
    }
    try {
      const resolution = await controller.resolveRevocation(
        reviewed,
        requestIdentity.requestId,
      );
      setRevocationResolution(resolution);
      if (resolution.status === "CONFIRMED") {
        setRevocationStatus("TIMELINE_CONFIRMED");
        setReviewed(null);
      } else if (resolution.status === "SUPERSEDED") {
        setRevocationStatus("SUPERSEDED");
        setReviewed(null);
      }
    } catch {
      setRevocationStatus("AMBIGUOUS");
    }
  };

  const runAdvisorInvestigation = async (): Promise<void> => {
    if (eligibleDenial === null || advisorStatus === "RUNNING") {
      return;
    }
    const binding = {
      entrySha256: eligibleDenial.entry.entrySha256,
      rootSha256: eligibleDenial.entry.rootSha256,
      currentEpoch: eligibleDenial.currentEpoch,
      headSequence: view.head.afterSequence,
      headEntrySha256: view.head.afterEntrySha256,
    };
    setAdvisorStatus("RUNNING");
    setAdvisorResult(null);
    setAdvisorBinding(binding);
    try {
      const identity = newAdvisorIdentity();
      const requestedAt = new Date(Math.floor(Date.now() / 1_000) * 1_000)
        .toISOString()
        .replace(".000Z", "Z");
      const result = await operatorApi.advise({
        rootId: eligibleDenial.entry.rootId,
        rootSha256: eligibleDenial.entry.rootSha256,
        expectedEpoch: eligibleDenial.currentEpoch,
        requestId: identity.requestId,
        idempotencyKey: identity.idempotencyKey,
        requestedAt,
        expectedTarget: eligibleDenial.target,
      });
      const citationKinds = new Set(
        result.response.recommendation?.findings.flatMap((finding) =>
          finding.citations.map((citation) => citation.evidence_kind),
        ) ?? [],
      );
      if (
        result.response.audit.prompt_version !==
          "controlgraph.rollout-advisor-prompt/v2" ||
        (result.response.recommendation !== null &&
          (!citationKinds.has("receipt") ||
            !citationKinds.has("timeline") ||
            (!citationKinds.has("target") && !citationKinds.has("verifier"))))
      ) {
        throw new OperatorApiError(
          "RESPONSE_INVALID",
          "ADVISOR_CAUSAL_EVIDENCE_INVALID",
        );
      }
      await controller.reloadFromStart();
      setAdvisorResult(result);
      setAdvisorStatus("COMPLETE");
    } catch {
      setAdvisorResult(null);
      setAdvisorStatus("FAILED");
    }
  };

  const phaseBusy = view.phase === "AUTHENTICATING" || view.phase === "LOADING";
  return (
    <div className="shell">
      <div className="console-content" ref={consoleContentRef}>
      <header className="masthead">
        <a className="brand" href="#timeline" aria-label="ControlGraph Canary timeline">
          <span className="brand__mark" aria-hidden="true">CG</span>
          <span>
            <strong>ControlGraph</strong>
            <small>Operator evidence console</small>
          </span>
        </a>
        <div className="operator-identity">
          <span className={`live-dot live-dot--${view.phase.toLowerCase()}`} aria-hidden="true" />
          <span>
            <small>{view.phase === "LIVE" ? "Authenticated operator" : "Console state"}</small>
            <strong>{view.identity?.principal ?? view.phase.toLowerCase().replaceAll("_", " ")}</strong>
          </span>
        </div>
      </header>

      <main id="top" aria-busy={phaseBusy}>
        <section className="console-hero" aria-labelledby="page-title">
          <div>
            <p className="eyebrow">Signed history · exact epoch</p>
            <h1 id="page-title">Authority you can inspect.</h1>
            <p className="lede">
              Follow one target from rollout root to independent verification. Ambiguity stays
              visible, stale authority stays denied, and model output stays advisory.
            </p>
          </div>
        </section>

        <ConnectionNotice
          phase={view.phase}
          stableCode={view.stableCode}
          reconnect={controller.reconnect}
          reload={controller.reloadFromStart}
        />

        {hasPartialEvidence(view.entries) && view.phase === "LIVE" && (
          <section className="partial-notice" role="status">
            <strong>Partial or contradictory evidence is present.</strong>
            <span>The console will not infer a successful outcome from incomplete signals.</span>
          </section>
        )}

        {view.target !== null && view.authority !== null && (
          <section className="rollout-overview" aria-labelledby="overview-title">
            <div className="section-heading">
              <div>
                <p className="eyebrow">
                  {view.phase === "LIVE" ? "Live authority overview" : "Latest admitted evidence"}
                </p>
                <h2 id="overview-title">{view.target.service_name}</h2>
              </div>
              <details className="section-disclosure">
                <summary>Target details</summary>
                <p>{view.target.project_id} · {view.target.region} · {view.target.environment}</p>
              </details>
            </div>
            <div className="summary-grid">
              <SummaryCard
                label="Authority"
                value={`Epoch ${view.authority.epoch}`}
                detail="Target-scoped rollout root"
              />
              <SummaryCard
                label="Traffic"
                value={trafficSummary(view.entries)}
                detail="Derived from admitted mutation evidence"
              />
              <SummaryCard
                label="Health"
                value={healthSummary(view.entries)}
                detail="Deterministic policy windows"
              />
              <SummaryCard
                label="Outcome"
                value={outcomeSummary(view.entries)}
                detail={`Timeline head ${view.head.afterSequence}`}
              />
            </div>
            {view.phase === "LIVE" && (
              <div className="authority-action">
                <div>
                  <span className="proof-kicker">Manual authority action</span>
                  <strong>Revoke authority for epoch {view.authority.epoch}</strong>
                  <p>
                    Revoking advances this root to epoch {view.authority.epoch + 1}. Queued work
                    approved for epoch {view.authority.epoch} will be denied at its next authority
                    check. Revocation does not change traffic itself.
                  </p>
                </div>
                <button
                  ref={reviewButtonRef}
                  className="button button--quiet"
                  type="button"
                  onClick={asyncAction(openRevocationReview)}
                  disabled={!canRevoke}
                >
                  {revocationStatus === "PREPARING"
                    ? "Refreshing authority…"
                    : "Review revocation"}
                </button>
              </div>
            )}
          </section>
        )}

        <RevocationOutcome
          status={revocationStatus}
          result={revocationResult}
          resolution={revocationResolution}
          checkTimeline={checkAmbiguousRevocation}
          outcomeRef={revocationOutcomeRef}
        />

        <AdvisorInvestigation
          eligible={eligibleDenial}
          status={
            advisorResult !== null && !advisorResultIsCurrent
              ? "STALE"
              : advisorStatus
          }
          result={advisorResultIsCurrent ? advisorResult : null}
          run={runAdvisorInvestigation}
        />

        <section className="timeline-section" id="timeline" aria-labelledby="timeline-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Append-only target history</p>
              <h2 id="timeline-title">Operator timeline</h2>
            </div>
            <details className="section-disclosure">
              <summary>Timeline connection details</summary>
              <p>
                Reconnects continue from sequence {view.cursor.afterSequence}. Raw records,
                capabilities, and credentials are never exposed here.
              </p>
            </details>
          </div>
          {view.entries.length === 0 && view.target !== null && view.phase === "EMPTY" ? (
            <div className="empty-timeline" role="status">
              <span aria-hidden="true">○</span>
              <p>No target-scoped evidence is available yet.</p>
            </div>
          ) : view.entries.length > 0 ? (
            <ol className="timeline-list">
              {view.entries.map((entry) => (
                <TimelineEvent entry={entry} entries={view.entries} key={entry.entryId} />
              ))}
            </ol>
          ) : null}
        </section>
      </main>

      <footer>
        <span>ControlGraph Canary</span>
        <span>Operator projection · no generic cloud controls</span>
      </footer>
      </div>

      {reviewed !== null &&
        (revocationStatus === "REVIEWING" || revocationStatus === "SUBMITTING") && (
          <RevocationDialog
            reviewed={reviewed}
            reason={reason}
            confirmed={confirmed}
            submitting={revocationStatus === "SUBMITTING"}
            setReason={setReason}
            setConfirmed={setConfirmed}
            close={() => {
              setReviewed(null);
              setRevocationStatus("IDLE");
            }}
            submit={submitRevocation}
          />
        )}
    </div>
  );
}
