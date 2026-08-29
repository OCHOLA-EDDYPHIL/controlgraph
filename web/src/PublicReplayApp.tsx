import { useEffect, useState } from "react";

import {
  loadPublicReplay,
  type PublicReplayEnvelope,
  type PublicReplayEvent,
} from "./contracts/publicReplay";

type ReplayState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "invalid" }
  | { status: "ready"; replay: PublicReplayEnvelope };

const labels: Record<PublicReplayEvent["kind"], string> = {
  AUTHORITY_ADVANCED: "Authority advanced",
  STALE_WORK_DENIED: "Queued work denied",
  TARGET_UNCHANGED: "Target stayed unchanged",
  ADVISOR_VALIDATED: "Advisory analysis validated",
  RECOVERY_VERIFIED: "Captured stable restored",
  TIMELINE_COMMITTED: "Timeline commitments verified",
};

function shortDigest(value: unknown): string {
  return typeof value === "string" && value.length === 64
    ? `${value.slice(0, 12)}…${value.slice(-8)}`
    : "invalid";
}

function traffic(value: unknown): string {
  const item = value as Record<string, unknown>;
  return `${String(item.stable_percent)}% stable / ${String(item.candidate_percent)}% candidate`;
}

function EventFacts({ event }: { readonly event: PublicReplayEvent }) {
  const details = event.details;
  switch (event.kind) {
    case "AUTHORITY_ADVANCED":
      return (
        <p>
          Epoch <strong>{String(details.previous_epoch)}</strong> advanced to{" "}
          <strong>{String(details.new_epoch)}</strong> by operator revocation.
        </p>
      );
    case "STALE_WORK_DENIED":
      return (
        <p>
          Epoch-{String(details.work_epoch)} work finished as <strong>DENIED</strong> with{" "}
          <strong>EPOCH_MISMATCH</strong> against current epoch{" "}
          {String(details.current_authority_epoch)}.
        </p>
      );
    case "TARGET_UNCHANGED": {
      const before = details.before_denial as Record<string, unknown>;
      const after = details.after_denial as Record<string, unknown>;
      return (
        <div>
          <p>{traffic(before)} before and after the denial.</p>
          <p className="digest">Configuration {shortDigest(after.target_configuration_sha256)}</p>
        </div>
      );
    }
    case "ADVISOR_VALIDATED": {
      const advisor = details.advisor as Record<string, unknown>;
      const findings = advisor.findings as readonly Record<string, unknown>[];
      const toolCalls = advisor.tool_calls as readonly unknown[];
      return (
        <div>
          <p>
            <strong>{String(advisor.model_id)}</strong> returned an accepted, advisory-only result;
            {toolCalls.length === 6 ? " 6 / 6 read-only tools succeeded; " : ""}
            exact replay used no second model call.
          </p>
          <ul className="findings">
            {findings.map((finding, index) => {
              const citations = finding.citations as readonly Record<string, unknown>[];
              return (
                <li key={`${index}-${String(finding.statement)}`}>
                  {String(finding.statement)}
                  <span className="citations">
                    {citations.map((citation) => String(citation.evidence_kind)).join(" · ")}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      );
    }
    case "RECOVERY_VERIFIED": {
      const state = details.traffic as Record<string, unknown>;
      return (
        <p>
          Recovery was <strong>VERIFIED</strong> at {traffic(state)}.
        </p>
      );
    }
    case "TIMELINE_COMMITTED": {
      const timeline = details.timeline as Record<string, unknown>;
      const entries = timeline.entries as readonly unknown[];
      return (
        <p>
          {entries.length} relevant public commitments are anchored to timeline head{" "}
          {String(timeline.head_sequence)} ({shortDigest(timeline.head_entry_sha256)}).
        </p>
      );
    }
  }
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
    return <main className="replay-shell"><p>Verifying immutable replay…</p></main>;
  }
  if (state.status === "unavailable") {
    return (
      <main className="replay-shell">
        <h1>Public replay</h1>
        <p>No accepted replay is currently published.</p>
      </main>
    );
  }
  if (state.status === "invalid") {
    return (
      <main className="replay-shell replay-error" role="alert">
        <h1>Replay verification failed</h1>
        <p>The replay was not rendered because its immutable validation did not pass.</p>
      </main>
    );
  }

  const { payload } = state.replay;
  return (
    <main className="replay-shell">
      <header className="replay-header">
        <p className="eyebrow">Credential-free · immutable · self-verifying</p>
        <h1>Stale-authority replay</h1>
        <p className="lede">
          A queued promotion lost authority at execution time, was denied without changing the
          90/10 target, received read-only cited analysis, and recovered to 100/0.
        </p>
        <dl className="replay-meta">
          <div><dt>Source</dt><dd>{payload.source_commit}</dd></div>
          <div><dt>Manifest</dt><dd>{shortDigest(payload.acceptance_manifest_sha256)}</dd></div>
          <div><dt>Acceptance</dt><dd>Cases: {payload.cases.length} / 8 passed</dd></div>
          <div><dt>Chain head</dt><dd>{shortDigest(payload.event_chain_head_sha256)}</dd></div>
          <div><dt>Accepted</dt><dd>{payload.accepted_at}</dd></div>
        </dl>
      </header>

      <section className="replay-verification" aria-label="Replay verification">
        <strong>Recorded hosted evidence — no live connection or credentials.</strong>
        <span>artifact hash · closed schema · payload digest · event chain</span>
      </section>

      <ol className="replay-events">
        {payload.events.map(({ event, event_sha256 }) => (
          <li key={event_sha256} className="replay-event">
            <div className="event-index">{String(event.sequence).padStart(2, "0")}</div>
            <article>
              <p className="event-time">{event.occurred_at}</p>
              <h2>{labels[event.kind]}</h2>
              <EventFacts event={event} />
              <p className="digest">Event {shortDigest(event_sha256)}</p>
            </article>
          </li>
        ))}
      </ol>

      <section className="image-bindings">
        <h2>Immutable images</h2>
        <ul>
          {payload.images.map((image) => (
            <li key={image.component}>
              <span>{image.component}</span>
              <code>{image.reference.split("@sha256:")[1]}</code>
            </li>
          ))}
        </ul>
      </section>

      <footer>
        This replay is evidence only. It has no sign-in, protected API access, or mutation action.
      </footer>
    </main>
  );
}
