import { readFile, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { extname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

const MAX_REQUEST_BYTES = 65_536;
const MAX_RESPONSE_BYTES = 65_536;
export const MAX_PUBLIC_REPLAY_JSON_BYTES = 65_536;
export const MAX_PUBLIC_REPLAY_GZIP_BYTES = 18_432;
export const MAX_PUBLIC_REPLAY_BASE64_BYTES = 24_576;
const TIMELINE_TIMEOUT_MS = 12_000;
const COMMAND_TIMEOUT_MS = 60_000;
const oauthClientAudience =
  /^[0-9]{6,32}(?:-[a-z0-9]{6,128})?\.apps\.googleusercontent\.com$/;
const consoleOriginPattern =
  /^https:\/\/controlgraph-console-[1-9][0-9]{5,31}\.us-central1\.run\.app$/;
const apiOriginPattern =
  /^https:\/\/controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$/;
const bearer = /^Bearer ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;
const sha256Digest = /^[0-9a-f]{64}$/;
const canonicalBase64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const canonicalObjectKey = /^[a-z][a-z0-9_]*$/;
const replayCommit = /^[0-9a-f]{40}$/;
const replayIdentifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const replayTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const replayImageReference =
  /^us-central1-docker\.pkg\.dev\/(controlgraph-canary-[a-z0-9]{6,10})\/controlgraph-canary\/([a-z][a-z0-9-]*)@sha256:([0-9a-f]{64})$/;
const replayImageComponents = Object.freeze([
  "controller",
  "advisor",
  "console",
  "reference-stable",
  "reference-candidate",
]);
const replayCaseKinds = Object.freeze([
  "TARGET_RESET",
  "HEALTHY_PROMOTION",
  "UNHEALTHY_STABLE_RECOVERY",
  "REVOCATION_STALE_DENIAL",
  "INDEPENDENT_VERIFIER_PROBE",
  "AMBIGUITY_CLASSIFICATION",
  "TIMELINE_CONSOLE_READ",
  "BOUNDED_ADVISOR",
]);
const replayEventKinds = Object.freeze([
  "AUTHORITY_ADVANCED",
  "STALE_WORK_DENIED",
  "TARGET_UNCHANGED",
  "ADVISOR_VALIDATED",
  "RECOVERY_VERIFIED",
  "TIMELINE_COMMITTED",
]);
const replayTimelineEventTypes = Object.freeze([
  "AUTHORITY_EPOCH_ADVANCED",
  "MUTATION_APPLIED",
  "MUTATION_DENIED",
  "MODEL_ASSISTANCE_RECORDED",
]);
const replayToolIds = Object.freeze([
  "read_root_summary",
  "read_target_summary",
  "read_health_summary",
  "read_receipt_summary",
  "read_timeline_summary",
  "read_verifier_summary",
]);
const replayRequestedActions = Object.freeze([
  "wait",
  "collect_approved_diagnostics",
  "request_revocation",
  "request_captured_stable_recovery",
  "request_new_operator_approved_rollout",
  "manual_review",
]);
const safeErrorCodes = new Set([
  "CONSOLE_BODY_TOO_LARGE",
  "CONSOLE_BROWSER_ENVELOPE_INVALID",
  "CONSOLE_CONFIGURATION_INVALID",
  "CONSOLE_CONTENT_TYPE_INVALID",
  "CONSOLE_COOKIE_DENIED",
  "CONSOLE_IDENTITY_ENVELOPE_INVALID",
  "CONSOLE_METHOD_DENIED",
  "CONSOLE_PUBLIC_REPLAY_NOT_FOUND",
  "CONSOLE_ROUTE_DENIED",
  "CONSOLE_UPSTREAM_RESPONSE_INVALID",
]);

const securityHeaders = Object.freeze({
  "Cache-Control": "no-store",
  "Content-Security-Policy": [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self' https://accounts.google.com/gsi/",
    "font-src 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "frame-src https://accounts.google.com/gsi/",
    "img-src 'self' data: https://*.googleusercontent.com",
    "object-src 'none'",
    "script-src 'self' https://accounts.google.com/gsi/client",
    "style-src 'self'",
  ].join("; "),
  "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
});

const publicReplayHeaders = Object.freeze({
  "Content-Security-Policy": [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
  ].join("; "),
});

function fail(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function assertReplayJson(value, depth = 0) {
  if (depth > 12) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  if (value === null || typeof value === "boolean") {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    return;
  }
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw fail("CONSOLE_CONFIGURATION_INVALID");
        }
        index += 1;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw fail("CONSOLE_CONFIGURATION_INVALID");
      }
    }
    if (value.normalize("NFC") !== value) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 64) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    value.forEach((item) => assertReplayJson(item, depth + 1));
    return;
  }
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  const entries = Object.entries(value);
  if (entries.length > 64) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  for (const [key, item] of entries) {
    if (!canonicalObjectKey.test(key)) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    assertReplayJson(item, depth + 1);
  }
}

function orderedReplayJson(value) {
  if (Array.isArray(value)) {
    return value.map(orderedReplayJson);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, orderedReplayJson(value[key])]),
    );
  }
  return value;
}

function assertExactReplayKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const orderedExpected = [...expected].sort();
  if (
    actual.length !== orderedExpected.length ||
    actual.some((key, index) => key !== orderedExpected[index])
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
}

function replayContractSha256(schemaVersion, value) {
  return createHash("sha256")
    .update("controlgraph.contract-sha256/v1\0", "utf8")
    .update(schemaVersion, "utf8")
    .update("\0", "utf8")
    .update(JSON.stringify(orderedReplayJson(value)), "utf8")
    .digest("hex");
}

function replayRecord(value) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return value;
}

function replayString(value, pattern) {
  if (typeof value !== "string" || (pattern !== undefined && !pattern.test(value))) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return value;
}

function replayInteger(value, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return value;
}

function replayTimestampValue(value) {
  const text = replayString(value, replayTimestamp);
  const parsed = new Date(text);
  if (
    Number(text.slice(0, 4)) < 1 ||
    Number.isNaN(parsed.valueOf()) ||
    parsed.toISOString().replace(".000Z", "Z") !== text
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return text;
}

function replayArray(value, minimum, maximum) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return value;
}

function replayOneOf(value, allowed) {
  const text = replayString(value);
  if (!allowed.includes(text)) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return text;
}

function validateReplayTraffic(value) {
  const traffic = replayRecord(value);
  assertExactReplayKeys(traffic, [
    "candidate_percent",
    "schema_version",
    "stable_percent",
    "target_configuration_sha256",
  ]);
  const stable = replayInteger(traffic.stable_percent, 0, 100);
  const candidate = replayInteger(traffic.candidate_percent, 0, 100);
  if (
    traffic.schema_version !== "controlgraph.public-replay-traffic/v1" ||
    stable + candidate !== 100 ||
    !sha256Digest.test(replayString(traffic.target_configuration_sha256))
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return traffic;
}

function validateReplayAdvisor(value) {
  const outer = replayRecord(value);
  assertExactReplayKeys(outer, ["advisor", "schema_version"]);
  const advisor = replayRecord(outer.advisor);
  assertExactReplayKeys(advisor, [
    "audit_sha256",
    "authority_effect",
    "confidence_basis_points",
    "deterministic_health_override",
    "findings",
    "model_id",
    "model_location",
    "operator_review_required",
    "prompt_version",
    "registry_sha256",
    "replayed_without_model_call",
    "requested_operator_action",
    "response_sha256",
    "schema_version",
    "snapshot_sha256",
    "structured_output_sha256",
    "tool_calls",
    "validation",
  ]);
  if (
    outer.schema_version !== "controlgraph.public-replay-advisor-validated/v1" ||
    advisor.schema_version !== "controlgraph.public-replay-advisor/v1" ||
    advisor.model_id !== "gemini-3.5-flash" ||
    advisor.model_location !== "global" ||
    advisor.prompt_version !== "controlgraph.rollout-advisor-prompt/v2" ||
    advisor.validation !== "accepted" ||
    advisor.authority_effect !== "none" ||
    advisor.deterministic_health_override !== false ||
    advisor.operator_review_required !== true ||
    advisor.replayed_without_model_call !== true
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  for (const key of [
    "audit_sha256",
    "registry_sha256",
    "response_sha256",
    "snapshot_sha256",
    "structured_output_sha256",
  ]) {
    replayString(advisor[key], sha256Digest);
  }
  replayOneOf(advisor.requested_operator_action, replayRequestedActions);
  replayInteger(advisor.confidence_basis_points, 0, 10_000);
  const citationKinds = new Set();
  replayArray(advisor.findings, 1, 8).forEach((value) => {
    const finding = replayRecord(value);
    assertExactReplayKeys(finding, ["citations", "schema_version", "statement"]);
    const statement = replayString(finding.statement);
    if (
      finding.schema_version !== "controlgraph.public-replay-finding/v1" ||
      Array.from(statement).length < 1 ||
      Array.from(statement).length > 512 ||
      /[\p{C}\p{Zl}\p{Zp}]/u.test(statement)
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    const citationKeys = new Set();
    replayArray(finding.citations, 1, 8).forEach((citationValue) => {
      const citation = replayRecord(citationValue);
      assertExactReplayKeys(citation, [
        "evidence_id",
        "evidence_kind",
        "schema_version",
        "source_sha256",
      ]);
      const kind = replayOneOf(
        citation.evidence_kind,
        ["root", "target", "health", "receipt", "timeline", "verifier"],
      );
      const evidenceId = replayString(citation.evidence_id, replayIdentifier);
      const sourceSha256 = replayString(citation.source_sha256, sha256Digest);
      if (citation.schema_version !== "controlgraph.public-replay-citation/v1") {
        throw fail("CONSOLE_CONFIGURATION_INVALID");
      }
      citationKinds.add(kind);
      citationKeys.add(`${kind}\0${evidenceId}\0${sourceSha256}`);
    });
    if (citationKeys.size !== finding.citations.length) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
  });
  if (
    !citationKinds.has("receipt") ||
    !citationKinds.has("timeline") ||
    (!citationKinds.has("target") && !citationKinds.has("verifier"))
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  const observedTools = new Set();
  replayArray(advisor.tool_calls, 6, 6).forEach((callValue, index) => {
    const call = replayRecord(callValue);
    assertExactReplayKeys(call, [
      "input_sha256",
      "output_sha256",
      "schema_version",
      "sequence",
      "status",
      "tool_id",
    ]);
    const toolId = replayOneOf(call.tool_id, replayToolIds);
    if (
      call.schema_version !== "controlgraph.public-replay-tool-call/v1" ||
      call.sequence !== index + 1 ||
      call.status !== "succeeded"
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    replayString(call.input_sha256, sha256Digest);
    replayString(call.output_sha256, sha256Digest);
    observedTools.add(toolId);
  });
  if (observedTools.size !== replayToolIds.length) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
}

function validateReplayTimeline(value) {
  const outer = replayRecord(value);
  assertExactReplayKeys(outer, ["schema_version", "timeline"]);
  const timeline = replayRecord(outer.timeline);
  assertExactReplayKeys(timeline, [
    "entries",
    "entry_count",
    "head_entry_sha256",
    "head_sequence",
    "page_count",
    "page_set_sha256",
    "schema_version",
  ]);
  const head = replayInteger(timeline.head_sequence, 1);
  const count = replayInteger(timeline.entry_count, 1, head);
  replayInteger(timeline.page_count, 1);
  replayString(timeline.head_entry_sha256, sha256Digest);
  replayString(timeline.page_set_sha256, sha256Digest);
  if (
    outer.schema_version !== "controlgraph.public-replay-timeline-committed/v1" ||
    timeline.schema_version !== "controlgraph.public-replay-timeline/v1"
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  let previousSequence = 0;
  const eventTypes = new Set();
  const entryDigests = new Set();
  const entries = replayArray(timeline.entries, 4, 8);
  entries.forEach((entryValue) => {
    const entry = replayRecord(entryValue);
    assertExactReplayKeys(entry, [
      "entry_sha256",
      "event_type",
      "occurred_at",
      "schema_version",
      "sequence",
      "verification_status",
    ]);
    const sequence = replayInteger(entry.sequence, previousSequence + 1, head);
    replayTimestampValue(entry.occurred_at);
    if (
      entry.schema_version !== "controlgraph.public-replay-timeline-entry/v1" ||
      sequence <= previousSequence
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    previousSequence = sequence;
    entryDigests.add(replayString(entry.entry_sha256, sha256Digest));
    eventTypes.add(replayOneOf(entry.event_type, replayTimelineEventTypes));
    replayOneOf(entry.verification_status, ["NOT_APPLICABLE", "VERIFIED"]);
  });
  if (
    entries.length > count ||
    entryDigests.size !== entries.length ||
    eventTypes.size !== replayTimelineEventTypes.length
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
}

function validateReplayDetails(kind, value) {
  const details = replayRecord(value);
  if (kind === "AUTHORITY_ADVANCED") {
    assertExactReplayKeys(details, [
      "cause",
      "new_epoch",
      "previous_epoch",
      "schema_version",
      "transition_sha256",
    ]);
    const previous = replayInteger(details.previous_epoch, 1);
    if (
      details.schema_version !== "controlgraph.public-replay-authority-advanced/v1" ||
      details.cause !== "OPERATOR_REVOCATION" ||
      replayInteger(details.new_epoch, 1) !== previous + 1
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    replayString(details.transition_sha256, sha256Digest);
  } else if (kind === "STALE_WORK_DENIED") {
    assertExactReplayKeys(details, [
      "current_authority_epoch",
      "outcome",
      "reason_code",
      "receipt_sha256",
      "schema_version",
      "work_epoch",
    ]);
    const workEpoch = replayInteger(details.work_epoch, 1);
    if (
      details.schema_version !== "controlgraph.public-replay-stale-denial/v1" ||
      details.outcome !== "DENIED" ||
      details.reason_code !== "EPOCH_MISMATCH" ||
      replayInteger(details.current_authority_epoch, 1) !== workEpoch + 1
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    replayString(details.receipt_sha256, sha256Digest);
  } else if (kind === "TARGET_UNCHANGED") {
    assertExactReplayKeys(details, ["after_denial", "before_denial", "schema_version"]);
    const before = validateReplayTraffic(details.before_denial);
    const after = validateReplayTraffic(details.after_denial);
    if (
      details.schema_version !== "controlgraph.public-replay-target-unchanged/v1" ||
      before.stable_percent !== 90 ||
      before.candidate_percent !== 10 ||
      JSON.stringify(before) !== JSON.stringify(after)
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
  } else if (kind === "ADVISOR_VALIDATED") {
    validateReplayAdvisor(details);
  } else if (kind === "RECOVERY_VERIFIED") {
    assertExactReplayKeys(details, ["outcome", "receipt_sha256", "schema_version", "traffic"]);
    const traffic = validateReplayTraffic(details.traffic);
    if (
      details.schema_version !== "controlgraph.public-replay-recovery-verified/v1" ||
      details.outcome !== "VERIFIED" ||
      traffic.stable_percent !== 100 ||
      traffic.candidate_percent !== 0
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    replayString(details.receipt_sha256, sha256Digest);
  } else if (kind === "TIMELINE_COMMITTED") {
    validateReplayTimeline(details);
  } else {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return details;
}

function validateReplayJson(body) {
  let text;
  let value;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
    value = JSON.parse(text);
  } catch {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  assertReplayJson(value);
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    JSON.stringify(orderedReplayJson(value)) !== text
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  assertExactReplayKeys(value, ["payload", "payload_sha256", "schema_version"]);
  const payload = value.payload;
  if (
    value.schema_version !== "controlgraph.public-replay-envelope/v1" ||
    typeof value.payload_sha256 !== "string" ||
    !sha256Digest.test(value.payload_sha256) ||
    payload === null ||
    Array.isArray(payload) ||
    typeof payload !== "object"
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  assertExactReplayKeys(payload, [
    "acceptance_manifest_sha256",
    "acceptance_run_id",
    "acceptance_status",
    "accepted_at",
    "cases",
    "event_chain_head_sha256",
    "events",
    "evidence_binding_complete",
    "images",
    "schema_version",
    "source_commit",
  ]);
  if (
    payload.schema_version !== "controlgraph.public-replay-payload/v1" ||
    payload.acceptance_status !== "PASSED" ||
    payload.evidence_binding_complete !== true ||
    typeof payload.source_commit !== "string" ||
    !replayCommit.test(payload.source_commit) ||
    typeof payload.acceptance_manifest_sha256 !== "string" ||
    !sha256Digest.test(payload.acceptance_manifest_sha256) ||
    typeof payload.acceptance_run_id !== "string" ||
    !replayIdentifier.test(payload.acceptance_run_id) ||
    typeof payload.accepted_at !== "string" ||
    typeof payload.event_chain_head_sha256 !== "string" ||
    !sha256Digest.test(payload.event_chain_head_sha256) ||
    !Array.isArray(payload.images) ||
    payload.images.length !== replayImageComponents.length ||
    !Array.isArray(payload.cases) ||
    payload.cases.length !== replayCaseKinds.length ||
    !Array.isArray(payload.events) ||
    payload.events.length !== replayEventKinds.length
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  const acceptedAt = replayTimestampValue(payload.accepted_at);
  const imageProjects = new Set();
  const imageDigests = new Set();
  const imageReferences = new Set();
  payload.images.forEach((image, index) => {
    if (image === null || Array.isArray(image) || typeof image !== "object") {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    assertExactReplayKeys(image, ["component", "reference", "schema_version"]);
    const reference = replayString(image.reference);
    const match = replayImageReference.exec(reference);
    if (
      image.schema_version !== "controlgraph.public-replay-image/v1" ||
      image.component !== replayImageComponents[index] ||
      match === null ||
      match[2] !== image.component
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    imageProjects.add(match[1]);
    imageDigests.add(match[3]);
    imageReferences.add(reference);
  });
  if (
    imageProjects.size !== 1 ||
    imageDigests.size !== replayImageComponents.length ||
    imageReferences.size !== replayImageComponents.length
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  const caseDigests = new Set();
  payload.cases.forEach((replayCase, index) => {
    if (replayCase === null || Array.isArray(replayCase) || typeof replayCase !== "object") {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    assertExactReplayKeys(replayCase, ["case_sha256", "kind", "schema_version", "sequence"]);
    if (
      replayCase.schema_version !== "controlgraph.public-replay-case/v1" ||
      replayCase.sequence !== index + 1 ||
      replayCase.kind !== replayCaseKinds[index] ||
      typeof replayCase.case_sha256 !== "string" ||
      !sha256Digest.test(replayCase.case_sha256)
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    caseDigests.add(replayCase.case_sha256);
  });
  if (caseDigests.size !== replayCaseKinds.length) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  let predecessor = null;
  let previousOccurredAt = "";
  payload.events.forEach((envelope, index) => {
    if (envelope === null || Array.isArray(envelope) || typeof envelope !== "object") {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    assertExactReplayKeys(envelope, ["event", "event_sha256", "schema_version"]);
    const event = envelope.event;
    if (event === null || Array.isArray(event) || typeof event !== "object") {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    assertExactReplayKeys(event, [
      "details",
      "kind",
      "occurred_at",
      "previous_event_sha256",
      "schema_version",
      "sequence",
    ]);
    const occurredAt = replayTimestampValue(event.occurred_at);
    const observed = replayContractSha256("controlgraph.public-replay-event/v1", event);
    if (
      envelope.schema_version !== "controlgraph.public-replay-event-envelope/v1" ||
      envelope.event_sha256 !== observed ||
      event.schema_version !== "controlgraph.public-replay-event/v1" ||
      event.sequence !== index + 1 ||
      event.kind !== replayEventKinds[index] ||
      event.previous_event_sha256 !== predecessor ||
      (previousOccurredAt !== "" && occurredAt < previousOccurredAt) ||
      occurredAt > acceptedAt
    ) {
      throw fail("CONSOLE_CONFIGURATION_INVALID");
    }
    validateReplayDetails(event.kind, event.details);
    predecessor = observed;
    previousOccurredAt = occurredAt;
  });
  const authority = replayRecord(payload.events[0].event.details);
  const denial = replayRecord(payload.events[1].event.details);
  if (
    predecessor !== payload.event_chain_head_sha256 ||
    authority.previous_epoch !== denial.work_epoch ||
    authority.new_epoch !== denial.current_authority_epoch ||
    replayContractSha256(payload.schema_version, payload) !== value.payload_sha256
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
}

export function publicReplayFromEnvironment(environment) {
  const encoded = environment.CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64 ?? "";
  const expectedSha256 = environment.CONTROLGRAPH_PUBLIC_REPLAY_SHA256 ?? "";
  if (typeof encoded !== "string" || typeof expectedSha256 !== "string") {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  if (encoded === "" && expectedSha256 === "") {
    return undefined;
  }
  if (
    encoded === "" ||
    expectedSha256 === "" ||
    encoded.length > MAX_PUBLIC_REPLAY_BASE64_BYTES ||
    encoded.length % 4 !== 0 ||
    !canonicalBase64.test(encoded) ||
    !sha256Digest.test(expectedSha256)
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  const compressed = Buffer.from(encoded, "base64");
  if (
    compressed.length === 0 ||
    compressed.length > MAX_PUBLIC_REPLAY_GZIP_BYTES ||
    compressed.toString("base64") !== encoded
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  let body;
  try {
    body = gunzipSync(compressed, { maxOutputLength: MAX_PUBLIC_REPLAY_JSON_BYTES });
  } catch {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  if (body.length === 0 || body.length > MAX_PUBLIC_REPLAY_JSON_BYTES) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  const observedSha256 = createHash("sha256").update(body).digest("hex");
  if (observedSha256 !== expectedSha256) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  validateReplayJson(body);
  return Object.freeze({ body, sha256: observedSha256 });
}

export function publicReplayConfigScript(publicReplay) {
  const value = publicReplay === undefined
    ? { available: false, sha256: null }
    : { available: true, sha256: publicReplay.sha256 };
  return `window.controlGraphPublicReplayConfig=Object.freeze(${JSON.stringify(value)});\n`;
}

function headerValues(rawHeaders, expectedName) {
  const result = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index]?.toLowerCase() === expectedName.toLowerCase()) {
      result.push(rawHeaders[index + 1] ?? "");
    }
  }
  return result;
}

export function operatorProxyHeaders(rawHeaders, method) {
  if (method !== "GET" && method !== "POST") {
    throw fail("CONSOLE_METHOD_DENIED");
  }
  if (headerValues(rawHeaders, "authorization").length !== 0) {
    throw fail("CONSOLE_IDENTITY_ENVELOPE_INVALID");
  }
  if (headerValues(rawHeaders, "cookie").length !== 0) {
    throw fail("CONSOLE_COOKIE_DENIED");
  }
  const controlgraph = headerValues(rawHeaders, "x-controlgraph-authorization");
  const serverless = headerValues(rawHeaders, "x-serverless-authorization");
  if (controlgraph.length !== 1 || serverless.length !== 1) {
    throw fail("CONSOLE_IDENTITY_ENVELOPE_INVALID");
  }
  const full = bearer.exec(controlgraph[0]);
  if (full === null || controlgraph[0].length > 8_192) {
    throw fail("CONSOLE_IDENTITY_ENVELOPE_INVALID");
  }
  const exact = serverless[0] === controlgraph[0];
  const rewritten = serverless[0] ===
    `bearer ${full[1]}.${full[2]}.SIGNATURE_REMOVED_BY_GOOGLE`;
  if (!exact && !rewritten) {
    throw fail("CONSOLE_IDENTITY_ENVELOPE_INVALID");
  }

  const forwarded = new Headers({
    Accept: "application/json",
    "X-ControlGraph-Authorization": controlgraph[0],
    "X-Serverless-Authorization": controlgraph[0],
  });
  for (const name of [
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
  ]) {
    const values = headerValues(rawHeaders, name);
    if (values.length > 1) {
      throw fail("CONSOLE_BROWSER_ENVELOPE_INVALID");
    }
    if (values.length === 1) {
      forwarded.set(name, values[0]);
    }
  }
  const csrf = headerValues(rawHeaders, "x-controlgraph-csrf");
  if (csrf.length > 1) {
    throw fail("CONSOLE_BROWSER_ENVELOPE_INVALID");
  }
  if (csrf.length === 1) {
    forwarded.set("X-ControlGraph-CSRF", csrf[0]);
  }
  if (method === "POST") {
    const contentTypes = headerValues(rawHeaders, "content-type");
    if (contentTypes.length !== 1 || contentTypes[0] !== "application/json") {
      throw fail("CONSOLE_CONTENT_TYPE_INVALID");
    }
    forwarded.set("Content-Type", "application/json");
  }
  return forwarded;
}

export function operatorProxyTarget(apiOrigin, requestUrl, method) {
  if (!apiOriginPattern.test(apiOrigin)) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  const parsed = new URL(requestUrl, "https://console.invalid");
  const allowed = method === "GET"
    ? parsed.pathname === "/v1/operator/timeline"
    : method === "POST" && parsed.pathname === "/v1/operator/commands";
  if (!allowed || parsed.hash !== "" || parsed.username !== "" || parsed.password !== "") {
    throw fail("CONSOLE_ROUTE_DENIED");
  }
  return `${apiOrigin}${parsed.pathname}${parsed.search}`;
}

export function operatorConfigScript(clientId) {
  if (!oauthClientAudience.test(clientId)) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return `window.controlGraphOperatorConfig=Object.freeze({oauthClientAudience:${JSON.stringify(clientId)}});\n`;
}

async function boundedBody(stream, maximum) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > maximum) {
      throw fail("CONSOLE_BODY_TOO_LARGE");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, size);
}

function respond(response, status, contentType, body, extraHeaders = {}) {
  response.writeHead(status, {
    ...securityHeaders,
    ...extraHeaders,
    "Content-Length": body.length,
    "Content-Type": contentType,
  });
  response.end(body);
}

function deny(response, status, code) {
  respond(
    response,
    status,
    "application/json",
    Buffer.from(`${JSON.stringify({ code })}\n`, "utf8"),
  );
}

function contentType(path) {
  switch (extname(path)) {
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    default:
      return "application/octet-stream";
  }
}

async function staticAsset(distDirectory, pathname) {
  const relative = pathname === "/" || pathname === "/index.html"
    ? "index.html"
    : pathname === "/replay" || pathname === "/replay/" || pathname === "/replay.html"
      ? "replay.html"
      : pathname.startsWith("/assets/") && /^\/assets\/[A-Za-z0-9._-]+$/.test(pathname)
        ? pathname.slice(1)
        : null;
  if (relative === null) {
    throw fail("CONSOLE_ROUTE_DENIED");
  }
  const root = await realpath(distDirectory);
  const path = await realpath(resolve(join(root, relative)));
  if (
    path !== join(root, "index.html") &&
    path !== join(root, "replay.html") &&
    !path.startsWith(`${join(root, "assets")}/`)
  ) {
    throw fail("CONSOLE_ROUTE_DENIED");
  }
  return {
    body: await readFile(path),
    contentType: relative.endsWith(".html") ? "text/html; charset=utf-8" : contentType(path),
  };
}

export function createConsoleServer(configuration, dependencies = {}) {
  const {
    apiOrigin,
    consoleOrigin,
    oauthClientId,
    distDirectory,
    publicReplay,
  } = configuration;
  if (
    !apiOriginPattern.test(apiOrigin) ||
    !consoleOriginPattern.test(consoleOrigin) ||
    !oauthClientAudience.test(oauthClientId) ||
    typeof distDirectory !== "string" ||
    distDirectory.length === 0 ||
    (
      publicReplay !== undefined &&
      (
        publicReplay === null ||
        !Buffer.isBuffer(publicReplay.body) ||
        !sha256Digest.test(publicReplay.sha256) ||
        createHash("sha256").update(publicReplay.body).digest("hex") !== publicReplay.sha256
      )
    )
  ) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  const fetcher = dependencies.fetcher ?? globalThis.fetch;
  return createServer(async (request, response) => {
    const method = request.method ?? "";
    const requestUrl = request.url ?? "";
    try {
      if (method === "GET" && requestUrl === "/healthz") {
        respond(
          response,
          200,
          "application/json",
          Buffer.from('{"status":"ok"}\n', "utf8"),
        );
        return;
      }
      if (method === "GET" && requestUrl === "/operator-config.js") {
        respond(
          response,
          200,
          "text/javascript; charset=utf-8",
          Buffer.from(operatorConfigScript(oauthClientId), "utf8"),
        );
        return;
      }
      if (method === "GET" && requestUrl === "/replay-config.js") {
        respond(
          response,
          200,
          "text/javascript; charset=utf-8",
          Buffer.from(publicReplayConfigScript(publicReplay), "utf8"),
          publicReplayHeaders,
        );
        return;
      }
      const parsed = new URL(requestUrl, consoleOrigin);
      const pathname = parsed.pathname;
      const replayMatch = /^\/replays\/([0-9a-f]{64})\.json$/.exec(pathname);
      if (replayMatch !== null) {
        if (
          method !== "GET" ||
          parsed.search !== "" ||
          publicReplay === undefined ||
          replayMatch[1] !== publicReplay.sha256
        ) {
          deny(response, 404, "CONSOLE_PUBLIC_REPLAY_NOT_FOUND");
          return;
        }
        respond(
          response,
          200,
          "application/json",
          publicReplay.body,
          {
            ...publicReplayHeaders,
            "Cache-Control": "public, max-age=31536000, immutable",
          },
        );
        return;
      }
      if (!pathname.startsWith("/v1/operator/")) {
        if (method !== "GET") {
          throw fail("CONSOLE_METHOD_DENIED");
        }
        const asset = await staticAsset(distDirectory, pathname);
        const replayPage = ["/replay", "/replay/", "/replay.html"].includes(pathname);
        respond(
          response,
          200,
          asset.contentType,
          asset.body,
          replayPage ? publicReplayHeaders : {},
        );
        return;
      }

      const target = operatorProxyTarget(apiOrigin, requestUrl, method);
      const headers = operatorProxyHeaders(request.rawHeaders, method);
      const body = method === "POST"
        ? await boundedBody(request, MAX_REQUEST_BYTES)
        : undefined;
      const upstream = await fetcher(target, {
        method,
        headers,
        body,
        redirect: "error",
        signal: AbortSignal.timeout(
          method === "POST" ? COMMAND_TIMEOUT_MS : TIMELINE_TIMEOUT_MS,
        ),
      });
      const responseBody = upstream.body === null
        ? Buffer.alloc(0)
        : await boundedBody(upstream.body, MAX_RESPONSE_BYTES);
      const upstreamContentType = upstream.headers.get("content-type");
      if (upstreamContentType?.split(";", 1)[0]?.trim() !== "application/json") {
        if (upstream.status === 401 || upstream.status === 403) {
          deny(response, upstream.status, "AUTH_CLOUD_RUN_DENIED");
          return;
        }
        throw fail("CONSOLE_UPSTREAM_RESPONSE_INVALID");
      }
      const correlation = upstream.headers.get("x-controlgraph-correlation-id");
      respond(
        response,
        upstream.status,
        "application/json",
        responseBody,
        correlation === null ? {} : { "X-ControlGraph-Correlation-Id": correlation },
      );
    } catch (error) {
      const candidate = typeof error === "object" && error !== null &&
        typeof error.code === "string"
        ? error.code
        : "";
      const code = safeErrorCodes.has(candidate)
        ? candidate
        : "CONSOLE_UPSTREAM_UNAVAILABLE";
      const clientFailure = code.startsWith("CONSOLE_") &&
        !code.startsWith("CONSOLE_UPSTREAM_");
      deny(response, clientFailure ? 400 : 502, code);
    }
  });
}

function runtimeConfiguration() {
  const portText = process.env.PORT ?? "8080";
  if (!/^[1-9][0-9]{1,4}$/.test(portText) || Number(portText) > 65_535) {
    throw fail("CONSOLE_CONFIGURATION_INVALID");
  }
  return {
    port: Number(portText),
    apiOrigin: process.env.CONTROLGRAPH_OPERATOR_API_ORIGIN ?? "",
    consoleOrigin: process.env.CONTROLGRAPH_CONSOLE_ORIGIN ?? "",
    oauthClientId: process.env.CONTROLGRAPH_OPERATOR_OAUTH_CLIENT_AUDIENCE ?? "",
    distDirectory: resolve(fileURLToPath(new URL("./dist", import.meta.url))),
    publicReplay: publicReplayFromEnvironment(process.env),
  };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const configuration = runtimeConfiguration();
  createConsoleServer(configuration).listen(configuration.port, "0.0.0.0");
}
