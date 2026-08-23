import { useEffect, useMemo, useRef, useState } from "react";

import {
  OperatorApiError,
  createBrowserOperatorApi,
  newRevocationIdentity,
  type OperatorApi,
  type RevocationResult,
} from "./api/operator";
import type { TimelineEntry } from "./contracts/timeline";
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

function asyncAction(action: () => Promise<unknown>): () => void {
  return () => {
    void action().catch(() => undefined);
  };
}

function phaseMessage(phase: ConsolePhase): string | null {
  switch (phase) {
    case "AUTHENTICATING":
      return "Authenticating operator identity…";
    case "LOADING":
      return "Loading the signed operator timeline…";
    case "RECONNECTING":
      return "Connection interrupted. The next read will continue from the last verified cursor.";
    case "STALE":
      return "This view is stale. Authority actions are blocked until the timeline is reloaded from its first entry.";
    case "PARTIAL":
      return "Timeline evidence is partial or failed validation. No authority action is available from this view.";
    case "DENIED":
      return "Access denied. An authenticated operator identity is required for this target.";
    case "FAILED":
      return "The operator API is unavailable. Existing evidence has not been replaced or inferred.";
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
  const message = phaseMessage(phase);
  if (message === null) {
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
        <strong>{isBusy ? "Establishing trusted view" : "Operator attention required"}</strong>
        <p>{message}</p>
        {stableCode !== null && <code>{stableCode}</code>}
      </div>
      {!isBusy && phase === "RECONNECTING" && (
        <button className="button button--quiet" type="button" onClick={asyncAction(reconnect)}>
          Reconnect
        </button>
      )}
      {!isBusy && phase !== "RECONNECTING" && (
        <button className="button button--quiet" type="button" onClick={asyncAction(reload)}>
          {phase === "DENIED" ? "Retry authentication" : "Reload timeline"}
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
      <summary>Evidence bindings</summary>
      <dl>
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
  const summary =
    displayField(entry, "SUMMARY") ??
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
        <div className="timeline-event__facts">
          <span>Epoch {entry.epoch}</span>
          <span>{entry.verificationStatus.toLowerCase().replaceAll("_", " ")}</span>
          <span>
            {entry.signature === null
              ? "No signature metadata"
              : `Signed ${entry.signature.purpose.toLowerCase().replaceAll("_", " ")} metadata`}
          </span>
          {entry.terminalClassification !== "NONE" && (
            <span>{entry.terminalClassification.toLowerCase().replaceAll("_", " ")}</span>
          )}
        </div>
        {entry.displayFields.length > 0 && (
          <dl className="display-fields">
            {entry.displayFields.map((field) => (
              <div key={field.name}>
                <dt>{field.name.toLowerCase().replaceAll("_", " ")}</dt>
                <dd>{field.value}</dd>
              </div>
            ))}
          </dl>
        )}
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
}: {
  readonly status: RevocationStatus;
  readonly result: RevocationResult | null;
  readonly resolution: RevocationResolution | null;
  readonly checkTimeline: () => Promise<void>;
}) {
  if (status === "COMMITTED" && result !== null) {
    return (
      <section className="action-result action-result--success" role="status" aria-live="polite">
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
      <section className="action-result action-result--danger" role="alert">
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
      <section className="action-result action-result--success" role="status" aria-live="polite">
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
      <section className="action-result action-result--warning" role="alert">
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
      <section className="action-result action-result--warning" role="alert">
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
      <section className="action-result action-result--danger" role="alert">
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
            <p className="eyebrow">Human authority action</p>
            <h2 id="revocation-title">Review epoch revocation</h2>
          </div>
          <button className="icon-button" type="button" onClick={close} disabled={submitting}>
            <span aria-hidden="true">×</span>
            <span className="sr-only">Close revocation review</span>
          </button>
        </div>
        <p id="revocation-description" className="dialog-intro">
          Revocation advances authority by one epoch. It does not select traffic or invoke a
          cloud control plane.
        </p>
        <dl className="review-grid">
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
              I reviewed root <code>{shortDigest(reviewed.rootSha256)}</code> and confirm
              revocation of expected epoch {reviewed.epoch}.
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
              {submitting ? "Checking fresh epoch…" : `Revoke epoch ${reviewed.epoch}`}
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
  const reviewButtonRef = useRef<HTMLButtonElement>(null);
  const consoleContentRef = useRef<HTMLDivElement>(null);
  const dialogWasOpen = useRef(false);

  const dialogOpen =
    reviewed !== null &&
    (revocationStatus === "REVIEWING" || revocationStatus === "SUBMITTING");

  useEffect(() => {
    const content = consoleContentRef.current;
    if (content !== null) {
      content.inert = dialogOpen;
      content.setAttribute("aria-hidden", dialogOpen ? "true" : "false");
    }
    if (dialogWasOpen.current && !dialogOpen) {
      reviewButtonRef.current?.focus();
    }
    dialogWasOpen.current = dialogOpen;
    return () => {
      if (content !== null) {
        content.inert = false;
        content.removeAttribute("aria-hidden");
      }
    };
  }, [dialogOpen]);

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
          <div className="hero-actions">
            <button
              ref={reviewButtonRef}
              className="button button--danger"
              type="button"
              onClick={asyncAction(openRevocationReview)}
              disabled={!canRevoke}
            >
              {revocationStatus === "PREPARING" ? "Refreshing authority…" : "Review revocation"}
            </button>
            <small>Only epoch revocation is available here. Traffic controls are intentionally absent.</small>
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

        <RevocationOutcome
          status={revocationStatus}
          result={revocationResult}
          resolution={revocationResolution}
          checkTimeline={checkAmbiguousRevocation}
        />

        {view.target !== null && view.authority !== null && (
          <section className="rollout-overview" aria-labelledby="overview-title">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Current evidence view</p>
                <h2 id="overview-title">{view.target.service_name}</h2>
              </div>
              <p>
                {view.target.project_id} · {view.target.region} · {view.target.environment}
              </p>
            </div>
            <div className="summary-grid">
              <SummaryCard
                label="Authority"
                value={`Epoch ${view.authority.epoch}`}
                detail={`Root ${shortDigest(view.authority.rootSha256)}`}
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
          </section>
        )}

        <section className="timeline-section" id="timeline" aria-labelledby="timeline-title">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Append-only target history</p>
              <h2 id="timeline-title">Operator timeline</h2>
            </div>
            <p>
              Reconnects continue from sequence {view.cursor.afterSequence}. Raw records,
              capabilities, and credentials are never exposed here.
            </p>
          </div>
          {view.entries.length === 0 ? (
            <div className="empty-timeline" role="status">
              <span aria-hidden="true">○</span>
              <p>No target-scoped evidence is available yet.</p>
            </div>
          ) : (
            <ol className="timeline-list">
              {view.entries.map((entry) => (
                <TimelineEvent entry={entry} entries={view.entries} key={entry.entryId} />
              ))}
            </ol>
          )}
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
