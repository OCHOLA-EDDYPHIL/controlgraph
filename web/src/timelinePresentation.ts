import type {
  TimelineDisplayFieldName,
  TimelineEntry,
} from "./contracts/timeline";

export type EventTone = "NEUTRAL" | "ACTIVE" | "GOOD" | "WARNING" | "DANGER" | "ADVISORY";

export interface EventPresentation {
  readonly title: string;
  readonly category: string;
  readonly tone: EventTone;
  readonly advisory: boolean;
}

export function displayField(
  entry: TimelineEntry,
  name: TimelineDisplayFieldName,
): string | null {
  return entry.displayFields.find((field) => field.name === name)?.value ?? null;
}

function correlatedAction(
  entry: TimelineEntry,
  entries: readonly TimelineEntry[],
): string {
  const requests = new Set(
    entry.correlations
      .filter((correlation) => correlation.kind === "REQUEST")
      .map((correlation) => correlation.correlationId),
  );
  const related = [...entries]
    .reverse()
    .find(
      (candidate) =>
        candidate.sequence <= entry.sequence &&
        candidate.rootId === entry.rootId &&
        candidate.rootSha256 === entry.rootSha256 &&
        candidate.correlations.some(
          (correlation) =>
            correlation.kind === "REQUEST" && requests.has(correlation.correlationId),
        ) &&
        displayField(candidate, "ACTION") !== null,
    );
  return (displayField(entry, "ACTION") ??
    (related === undefined ? null : displayField(related, "ACTION")) ??
    "").toUpperCase();
}

function mutationTitle(
  entry: TimelineEntry,
  entries: readonly TimelineEntry[],
): EventPresentation {
  const action = correlatedAction(entry, entries);
  const outcome = displayField(entry, "OUTCOME")?.toUpperCase();
  const status =
    outcome === "VERIFIED"
      ? "VERIFIED"
      : outcome === "APPLIED"
        ? "AWAITING_VERIFICATION"
        : "RECORDED";
  if (action.includes("APPLY") || action.includes("CANARY")) {
    return {
      title:
        status === "VERIFIED"
          ? "90/10 canary verified"
          : status === "AWAITING_VERIFICATION"
            ? "90/10 canary accepted; verification pending"
            : "90/10 canary update recorded",
      category: "Traffic",
      tone: status === "VERIFIED" ? "GOOD" : "ACTIVE",
      advisory: false,
    };
  }
  if (action.includes("PROMOT")) {
    return {
      title:
        status === "VERIFIED"
          ? "Candidate promotion verified"
          : status === "AWAITING_VERIFICATION"
            ? "Candidate promotion accepted; verification pending"
            : "Candidate promotion recorded",
      category: "Promotion",
      tone: status === "VERIFIED" ? "GOOD" : "ACTIVE",
      advisory: false,
    };
  }
  if (action.includes("RECOVER") || action.includes("RESTORE")) {
    return {
      title:
        status === "VERIFIED"
          ? "Captured stable revision restored"
          : status === "AWAITING_VERIFICATION"
            ? "Stable recovery accepted; verification pending"
            : "Stable recovery recorded",
      category: "Recovery",
      tone: status === "VERIFIED" ? "GOOD" : "ACTIVE",
      advisory: false,
    };
  }
  return {
    title:
      status === "VERIFIED"
        ? "Target mutation verified"
        : status === "AWAITING_VERIFICATION"
          ? "Target mutation accepted; verification pending"
          : "Target mutation recorded",
    category: "Mutation",
    tone: status === "VERIFIED" ? "GOOD" : "ACTIVE",
    advisory: false,
  };
}

export function eventPresentation(
  entry: TimelineEntry,
  entries: readonly TimelineEntry[] = [entry],
): EventPresentation {
  switch (entry.eventType) {
    case "AUTHORITY_ROOT_CREATED":
      return {
        title: "Rollout root established",
        category: "Authority",
        tone: "ACTIVE",
        advisory: false,
      };
    case "AUTHORITY_EPOCH_ADVANCED":
      return {
        title: "Authority epoch advanced",
        category: "Revocation",
        tone: "WARNING",
        advisory: false,
      };
    case "CAPABILITY_ISSUED":
      return {
        title: "Bounded capability issued",
        category: "Authority",
        tone: "NEUTRAL",
        advisory: false,
      };
    case "TASK_CREATED": {
      const action = correlatedAction(entry, entries);
      return {
        title: action.includes("PROMOT")
          ? "Promotion task created"
          : action.includes("CANARY") || action.includes("APPLY")
            ? "Canary task created"
            : "Addressed task created",
        category: action.includes("PROMOT") ? "Promotion" : "Delivery",
        tone: "NEUTRAL",
        advisory: false,
      };
    }
    case "TASK_DELIVERED":
      return {
        title: "Task delivery authenticated",
        category: "Delivery",
        tone: "ACTIVE",
        advisory: false,
      };
    case "HEALTH_OBSERVED":
      return {
        title: `Health window ${displayField(entry, "WINDOW") ?? "observed"}`,
        category: "Health",
        tone: "NEUTRAL",
        advisory: false,
      };
    case "HEALTH_DECIDED": {
      const state = (
        displayField(entry, "STATE") ?? displayField(entry, "OUTCOME") ?? ""
      ).toUpperCase();
      return {
        title: state.includes("UNHEALTHY")
          ? "Health policy: unhealthy"
          : state.includes("HEALTHY")
            ? "Health policy: healthy"
            : "Health policy evaluated",
        category: "Health",
        tone: state.includes("UNHEALTHY") ? "DANGER" : "GOOD",
        advisory: false,
      };
    }
    case "MUTATION_REQUESTED":
      return {
        title: "Target mutation requested",
        category: "Mutation",
        tone: "ACTIVE",
        advisory: false,
      };
    case "MUTATION_APPLIED":
      return mutationTitle(entry, entries);
    case "MUTATION_DENIED": {
      const reason = displayField(entry, "REASON_CODE")?.toUpperCase() ?? "";
      return {
        title:
          reason.includes("STALE") || reason.includes("EPOCH")
            ? "Stale authority denied"
            : "Mutation denied",
        category: "Denial",
        tone: "WARNING",
        advisory: false,
      };
    }
    case "MUTATION_AMBIGUOUS":
      return {
        title: "Mutation outcome ambiguous",
        category: "Ambiguity",
        tone: "DANGER",
        advisory: false,
      };
    case "RECOVERY_INTENT_CREATED":
      return {
        title: "Stable-only recovery selected",
        category: "Recovery",
        tone: "WARNING",
        advisory: false,
      };
    case "RECOVERY_TASK_CREATED":
      return {
        title: "Recovery task created",
        category: "Recovery",
        tone: "WARNING",
        advisory: false,
      };
    case "RECOVERY_APPLIED":
      return {
        title: "Captured stable revision restored",
        category: "Recovery",
        tone: "GOOD",
        advisory: false,
      };
    case "VERIFICATION_RECORDED": {
      const verdict = displayField(entry, "OUTCOME")?.toUpperCase();
      if (verdict === "MATCH") {
        return {
          title: "Independent verification matched",
          category: "Verification",
          tone: "GOOD",
          advisory: false,
        };
      }
      if (verdict === "MISMATCH") {
        return {
          title: "Independent verification found a mismatch",
          category: "Verification",
          tone: "DANGER",
          advisory: false,
        };
      }
      if (verdict === "UNAVAILABLE") {
        return {
          title: "Independent verification unavailable",
          category: "Verification",
          tone: "WARNING",
          advisory: false,
        };
      }
      if (verdict === "INCONCLUSIVE") {
        return {
          title: "Independent verification inconclusive",
          category: "Verification",
          tone: "WARNING",
          advisory: false,
        };
      }
      return {
        title:
          entry.verificationStatus === "FAILED"
            ? "Independent verification record failed checks"
            : entry.verificationStatus === "AMBIGUOUS"
              ? "Independent verification record ambiguous"
              : "Independent verification recorded",
        category: "Verification",
        tone:
          entry.verificationStatus === "FAILED"
            ? "DANGER"
            : entry.verificationStatus === "AMBIGUOUS" ||
                entry.verificationStatus === "UNVERIFIED"
              ? "WARNING"
              : "NEUTRAL",
        advisory: false,
      };
    }
    case "TERMINAL_CLASSIFIED":
      return {
        title: `Outcome classified: ${entry.terminalClassification
          .toLowerCase()
          .replace("_", " ")}`,
        category: "Outcome",
        tone:
          entry.terminalClassification === "AMBIGUOUS"
            ? "DANGER"
            : entry.terminalClassification === "DENIED" ||
                entry.terminalClassification === "FAILED_SAFE"
              ? "WARNING"
              : "GOOD",
        advisory: false,
      };
    case "MODEL_ASSISTANCE_RECORDED":
      return {
        title: "Model advisory recorded",
        category: "Advisory only",
        tone: "ADVISORY",
        advisory: true,
      };
    case "OPERATOR_ACTION_RECORDED":
      return {
        title: "Operator action recorded",
        category: "Operator",
        tone: "ACTIVE",
        advisory: false,
      };
  }
}

export function trafficSummary(entries: readonly TimelineEntry[]): string {
  for (const entry of [...entries].reverse()) {
    const values = `${correlatedAction(entry, entries)} ${entry.displayFields
      .map((field) => field.value)
      .join(" ")}`.toUpperCase();
    if (
      entry.eventType === "TERMINAL_CLASSIFIED" &&
      entry.terminalClassification === "RECOVERED"
    ) {
      return "100% captured stable";
    }
    if (
      entry.eventType === "TERMINAL_CLASSIFIED" &&
      entry.terminalClassification === "PROMOTED"
    ) {
      return "100% candidate";
    }
    if (entry.eventType === "RECOVERY_APPLIED") {
      return "100% captured stable";
    }
    if (entry.eventType === "MUTATION_APPLIED") {
      const verificationPending =
        displayField(entry, "OUTCOME")?.toUpperCase() !== "VERIFIED";
      if (values.includes("PROMOT") || values.includes("100% CANDIDATE")) {
        return verificationPending
          ? "100% candidate · verification pending"
          : "100% candidate";
      }
      if (
        values.includes("APPLY") ||
        values.includes("90/10") ||
        values.includes("90% STABLE")
      ) {
        return verificationPending
          ? "90% stable · 10% candidate · verification pending"
          : "90% stable · 10% candidate";
      }
    }
  }
  return "Awaiting traffic evidence";
}

export function healthSummary(entries: readonly TimelineEntry[]): string {
  const entry = [...entries]
    .reverse()
    .find(
      (item) =>
        item.eventType === "HEALTH_OBSERVED" || item.eventType === "HEALTH_DECIDED",
    );
  if (entry === undefined) {
    return "No health window yet";
  }
  return (
    displayField(entry, "STATE") ??
    displayField(entry, "OUTCOME") ??
    displayField(entry, "SUMMARY") ??
    "Window recorded"
  );
}

export function outcomeSummary(entries: readonly TimelineEntry[]): string {
  const terminal = [...entries]
    .reverse()
    .find((entry) => entry.terminalClassification !== "NONE");
  return terminal === undefined
    ? "In progress"
    : terminal.terminalClassification.toLowerCase().replace("_", " ");
}

export function hasPartialEvidence(entries: readonly TimelineEntry[]): boolean {
  return entries.some(
    (entry) => {
      const independentVerdict =
        entry.eventType === "VERIFICATION_RECORDED"
          ? displayField(entry, "OUTCOME")?.toUpperCase()
          : null;
      return (
        entry.eventType === "MUTATION_AMBIGUOUS" ||
        independentVerdict === "MISMATCH" ||
        independentVerdict === "UNAVAILABLE" ||
        independentVerdict === "INCONCLUSIVE" ||
        entry.verificationStatus === "UNVERIFIED" ||
        entry.verificationStatus === "FAILED" ||
        entry.verificationStatus === "AMBIGUOUS" ||
        entry.terminalClassification === "AMBIGUOUS"
      );
    },
  );
}

export function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value));
}

export function shortDigest(value: string): string {
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}
