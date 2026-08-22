import { useCallback, useEffect, useRef, useState } from "react";

import {
  DEFAULT_TIMELINE_QUERY,
  OperatorApiError,
  type OperatorApi,
  type OperatorIdentity,
  type RevocationCommand,
  type RevocationResult,
} from "./api/operator";
import {
  INITIAL_TIMELINE_CURSOR,
  targetEquals,
  type TargetBinding,
  type TimelineCursor,
  type TimelineEntry,
} from "./contracts/timeline";

const MAX_PAGE_READS = 100;
const MAX_VISIBLE_ENTRIES = 2_500;

export type ConsolePhase =
  | "AUTHENTICATING"
  | "LOADING"
  | "LIVE"
  | "RECONNECTING"
  | "STALE"
  | "PARTIAL"
  | "DENIED"
  | "FAILED";

export interface AuthoritySnapshot {
  readonly rootId: string;
  readonly rootSha256: string;
  readonly epoch: number;
  readonly sequence: number;
}

export interface ReviewedAuthority extends AuthoritySnapshot {
  readonly target: TargetBinding;
  readonly operatorPrincipal: string;
  readonly operatorSubject: string;
}

export interface RevocationResolution {
  readonly status: "CONFIRMED" | "SUPERSEDED" | "PENDING";
  readonly epoch: number | null;
  readonly evidenceId: string | null;
}

export interface OperatorConsoleView {
  readonly phase: ConsolePhase;
  readonly identity: OperatorIdentity | null;
  readonly target: TargetBinding | null;
  readonly entries: readonly TimelineEntry[];
  readonly cursor: TimelineCursor;
  readonly head: TimelineCursor;
  readonly authority: AuthoritySnapshot | null;
  readonly stableCode: string | null;
  readonly lastConnectedAt: Date | null;
}

interface PageBatch {
  readonly target: TargetBinding | null;
  readonly entries: readonly TimelineEntry[];
  readonly cursor: TimelineCursor;
  readonly head: TimelineCursor;
}

const initialView: OperatorConsoleView = {
  phase: "AUTHENTICATING",
  identity: null,
  target: null,
  entries: [],
  cursor: INITIAL_TIMELINE_CURSOR,
  head: INITIAL_TIMELINE_CURSOR,
  authority: null,
  stableCode: null,
  lastConnectedAt: null,
};

function sameCursor(left: TimelineCursor, right: TimelineCursor): boolean {
  return (
    left.afterSequence === right.afterSequence &&
    left.afterEntrySha256 === right.afterEntrySha256
  );
}

export function deriveAuthority(
  entries: readonly TimelineEntry[],
): AuthoritySnapshot | null {
  const latest = [...entries]
    .reverse()
    .find(
      (entry) =>
        entry.eventType === "AUTHORITY_ROOT_CREATED" ||
        entry.eventType === "AUTHORITY_EPOCH_ADVANCED",
    );
  if (latest === undefined) {
    return null;
  }
  return {
    rootId: latest.rootId,
    rootSha256: latest.rootSha256,
    epoch: latest.epoch,
    sequence: latest.sequence,
  };
}

async function readToHead(
  api: OperatorApi,
  start: TimelineCursor,
  expectedTarget: TargetBinding | null,
  expectedHead: TimelineCursor,
  existingEntryCount: number,
  signal?: AbortSignal,
): Promise<PageBatch> {
  let cursor = start;
  let head = expectedHead;
  let target = expectedTarget;
  const entries: TimelineEntry[] = [];
  for (let pageNumber = 0; pageNumber < MAX_PAGE_READS; pageNumber += 1) {
    const page = await api.readTimeline(
      {
        ...DEFAULT_TIMELINE_QUERY,
        afterSequence: cursor.afterSequence,
        afterEntrySha256: cursor.afterEntrySha256,
      },
      signal,
    );
    if (target !== null && !targetEquals(target, page.target)) {
      throw new OperatorApiError("RESPONSE_INVALID", "TIMELINE_TARGET_CHANGED");
    }
    target = page.target;
    if (
      page.head.afterSequence < head.afterSequence ||
      (page.head.afterSequence === head.afterSequence &&
        page.head.afterEntrySha256 !== head.afterEntrySha256)
    ) {
      throw new OperatorApiError("RESPONSE_INVALID", "TIMELINE_HEAD_REGRESSED");
    }
    if (
      existingEntryCount + entries.length + page.entries.length >
      MAX_VISIBLE_ENTRIES
    ) {
      throw new OperatorApiError("RESPONSE_INVALID", "TIMELINE_VIEW_BOUND_EXCEEDED");
    }
    entries.push(...page.entries);
    cursor = page.nextCursor;
    head = page.head;
    if (!page.hasMore) {
      if (!sameCursor(cursor, head)) {
        throw new OperatorApiError("RESPONSE_INVALID", "TIMELINE_HEAD_MISMATCH");
      }
      return { target, entries, cursor, head };
    }
  }
  throw new OperatorApiError("RESPONSE_INVALID", "TIMELINE_PAGE_BOUND_EXCEEDED");
}

function errorPhase(error: unknown, hasEvidence: boolean): ConsolePhase {
  if (!(error instanceof OperatorApiError)) {
    return hasEvidence ? "RECONNECTING" : "FAILED";
  }
  switch (error.kind) {
    case "AUTHENTICATION_REQUIRED":
    case "ACCESS_DENIED":
      return "DENIED";
    case "CURSOR_INVALID":
    case "STALE_AUTHORITY":
      return "STALE";
    case "RESPONSE_INVALID":
      return "PARTIAL";
    case "CONFLICT":
      return "STALE";
    case "UNAVAILABLE":
      return hasEvidence ? "RECONNECTING" : "FAILED";
  }
}

function errorCode(error: unknown): string | null {
  return error instanceof OperatorApiError ? (error.stableCode ?? null) : null;
}

export interface OperatorConsoleController {
  readonly view: OperatorConsoleView;
  reconnect(): Promise<void>;
  reloadFromStart(): Promise<void>;
  reviewAuthority(): Promise<ReviewedAuthority>;
  revokeReviewed(
    reviewed: ReviewedAuthority,
    command: Pick<RevocationCommand, "reason" | "requestId" | "idempotencyKey">,
  ): Promise<RevocationResult>;
  resolveRevocation(
    reviewed: ReviewedAuthority,
    requestId: string,
  ): Promise<RevocationResolution>;
}

export function useOperatorConsole(
  api: OperatorApi,
  pollIntervalMs = 10_000,
): OperatorConsoleController {
  const [view, setView] = useState<OperatorConsoleView>(initialView);
  const viewRef = useRef(view);
  const lifetime = useRef<AbortController | null>(null);
  const refreshInFlight = useRef<Promise<AuthoritySnapshot | null> | null>(null);
  const refreshInFlightIsFresh = useRef(false);

  const commitView = useCallback((next: OperatorConsoleView): void => {
    viewRef.current = next;
    setView(next);
  }, []);

  const commitBatch = useCallback(
    (
      batch: PageBatch,
      identity: OperatorIdentity,
      replace: boolean,
    ): AuthoritySnapshot | null => {
      const previous = viewRef.current;
      const entries = replace
        ? [...batch.entries]
        : [...previous.entries, ...batch.entries];
      if (entries.length > MAX_VISIBLE_ENTRIES) {
        throw new OperatorApiError("RESPONSE_INVALID", "TIMELINE_VIEW_BOUND_EXCEEDED");
      }
      const authority = deriveAuthority(entries);
      const next: OperatorConsoleView = {
        phase: entries.length === 0 ? "PARTIAL" : "LIVE",
        identity,
        target: batch.target,
        entries,
        cursor: batch.cursor,
        head: batch.head,
        authority,
        stableCode: null,
        lastConnectedAt: new Date(),
      };
      commitView(next);
      return authority;
    },
    [commitView],
  );

  const handleError = useCallback(
    (error: unknown): void => {
      if (error instanceof DOMException && error.name === "AbortError") {
        return;
      }
      const previous = viewRef.current;
      commitView({
        ...previous,
        phase: errorPhase(error, previous.entries.length > 0),
        stableCode: errorCode(error),
      });
    },
    [commitView],
  );

  const refresh = useCallback(
    async (freshIdentity: boolean): Promise<AuthoritySnapshot | null> => {
      if (refreshInFlight.current !== null) {
        const existing = refreshInFlight.current;
        if (!freshIdentity || refreshInFlightIsFresh.current) {
          return existing;
        }
        try {
          await existing;
        } catch {
          // A deliberate review still performs its own fresh read below.
        }
        return refresh(true);
      }
      const operation = (async (): Promise<AuthoritySnapshot | null> => {
        try {
          const signal = lifetime.current?.signal;
          const identity = await api.authenticate({ fresh: freshIdentity, signal });
          const current = viewRef.current;
          const batch = await readToHead(
            api,
            current.cursor,
            current.target,
            current.head,
            current.entries.length,
            signal,
          );
          return commitBatch(batch, identity, false);
        } catch (error) {
          handleError(error);
          throw error;
        }
      })();
      refreshInFlight.current = operation;
      refreshInFlightIsFresh.current = freshIdentity;
      try {
        return await operation;
      } finally {
        if (refreshInFlight.current === operation) {
          refreshInFlight.current = null;
          refreshInFlightIsFresh.current = false;
        }
      }
    },
    [api, commitBatch, handleError],
  );

  const reloadFromStart = useCallback(async (): Promise<void> => {
    const previous = viewRef.current;
    commitView({
      ...previous,
      phase: previous.identity === null ? "AUTHENTICATING" : "LOADING",
      stableCode: null,
    });
    try {
      const signal = lifetime.current?.signal;
      const identity = await api.authenticate({ fresh: true, signal });
      const batch = await readToHead(
        api,
        INITIAL_TIMELINE_CURSOR,
        null,
        INITIAL_TIMELINE_CURSOR,
        0,
        signal,
      );
      commitBatch(batch, identity, true);
    } catch (error) {
      handleError(error);
      throw error;
    }
  }, [api, commitBatch, commitView, handleError]);

  const reconnect = useCallback(async (): Promise<void> => {
    const previous = viewRef.current;
    commitView({ ...previous, phase: "RECONNECTING", stableCode: null });
    await refresh(false);
  }, [commitView, refresh]);

  const reviewAuthority = useCallback(async (): Promise<ReviewedAuthority> => {
    const authority = await refresh(true);
    const current = viewRef.current;
    if (authority === null || current.identity === null || current.target === null) {
      const error = new OperatorApiError(
        "RESPONSE_INVALID",
        "TIMELINE_AUTHORITY_MISSING",
      );
      handleError(error);
      throw error;
    }
    return {
      ...authority,
      target: current.target,
      operatorPrincipal: current.identity.principal,
      operatorSubject: current.identity.subject,
    };
  }, [handleError, refresh]);

  const revokeReviewed = useCallback(
    async (
      reviewed: ReviewedAuthority,
      command: Pick<RevocationCommand, "reason" | "requestId" | "idempotencyKey">,
    ): Promise<RevocationResult> => {
      const fresh = await reviewAuthority();
      if (
        fresh.rootId !== reviewed.rootId ||
        fresh.rootSha256 !== reviewed.rootSha256 ||
        fresh.epoch !== reviewed.epoch
        || fresh.operatorPrincipal !== reviewed.operatorPrincipal
        || fresh.operatorSubject !== reviewed.operatorSubject
        || !targetEquals(fresh.target, reviewed.target)
      ) {
        const error = new OperatorApiError(
          "STALE_AUTHORITY",
          "REVOCATION_REVIEW_STALE",
        );
        handleError(error);
        throw error;
      }
      try {
        const result = await api.revoke(
          {
            ...command,
            rootId: reviewed.rootId,
            rootSha256: reviewed.rootSha256,
            expectedEpoch: reviewed.epoch,
            expectedTarget: reviewed.target,
            operatorPrincipal: reviewed.operatorPrincipal,
            operatorSubject: reviewed.operatorSubject,
          },
          lifetime.current?.signal,
        );
        return result;
      } catch (error) {
        if (
          error instanceof OperatorApiError &&
          (error.kind === "STALE_AUTHORITY" || error.kind === "CONFLICT")
        ) {
          handleError(error);
        }
        throw error;
      }
    },
    [api, handleError, reviewAuthority],
  );

  const resolveRevocation = useCallback(
    async (
      reviewed: ReviewedAuthority,
      requestId: string,
    ): Promise<RevocationResolution> => {
      await refresh(true);
      const current = viewRef.current;
      const matching = current.entries.find(
        (entry) =>
          entry.rootId === reviewed.rootId &&
          entry.rootSha256 === reviewed.rootSha256 &&
          entry.epoch === reviewed.epoch + 1 &&
          entry.correlations.some(
            (correlation) =>
              correlation.kind === "REQUEST" && correlation.correlationId === requestId,
          ) &&
          ((entry.eventType === "OPERATOR_ACTION_RECORDED" &&
            entry.displayFields.some(
              (field) => field.name === "ACTION" && field.value === "REVOKE_EPOCH",
            )) ||
            (entry.eventType === "TERMINAL_CLASSIFIED" &&
              entry.terminalClassification === "REVOKED")),
      );
      if (matching !== undefined) {
        return {
          status: "CONFIRMED",
          epoch: matching.epoch,
          evidenceId:
            matching.correlations.find((correlation) => correlation.kind === "EVIDENCE")
              ?.correlationId ?? null,
        };
      }
      const authority = current.authority;
      if (
        authority !== null &&
        (authority.rootId !== reviewed.rootId ||
          authority.rootSha256 !== reviewed.rootSha256 ||
          authority.epoch > reviewed.epoch)
      ) {
        return {
          status: "SUPERSEDED",
          epoch: authority.epoch,
          evidenceId: null,
        };
      }
      return { status: "PENDING", epoch: null, evidenceId: null };
    },
    [refresh],
  );

  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    commitView(initialView);
    void (async () => {
      try {
        const identity = await api.authenticate({ signal: controller.signal });
        if (controller.signal.aborted) {
          return;
        }
        commitView({ ...initialView, phase: "LOADING", identity });
        const batch = await readToHead(
          api,
          INITIAL_TIMELINE_CURSOR,
          null,
          INITIAL_TIMELINE_CURSOR,
          0,
          controller.signal,
        );
        if (!controller.signal.aborted) {
          commitBatch(batch, identity, true);
        }
      } catch (error) {
        handleError(error);
      }
    })();
    return () => {
      controller.abort();
      lifetime.current = null;
      refreshInFlight.current = null;
      refreshInFlightIsFresh.current = false;
    };
  }, [api, commitBatch, commitView, handleError]);

  useEffect(() => {
    if (view.phase !== "LIVE" || pollIntervalMs <= 0) {
      return undefined;
    }
    const timer = window.setTimeout(() => {
      void refresh(false).catch(() => undefined);
    }, pollIntervalMs);
    return () => window.clearTimeout(timer);
  }, [pollIntervalMs, refresh, view.cursor, view.phase]);

  return {
    view,
    reconnect,
    reloadFromStart,
    reviewAuthority,
    revokeReviewed,
    resolveRevocation,
  };
}
