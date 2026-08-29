// @vitest-environment node

import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

import {
  createConsoleServer,
  operatorConfigScript,
  operatorProxyHeaders,
  operatorProxyTarget,
  publicReplayConfigScript,
  publicReplayFromEnvironment,
} from "./host.mjs";

const API = "https://controlgraph-api-123456789012.us-central1.run.app";
const FULL = "Bearer header.payload.synthetic-signature";
const REWRITTEN = "bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE";

function replayEnvironment(mutator = () => {}) {
  const ordered = (value) => {
    if (Array.isArray(value)) {
      return value.map(ordered);
    }
    if (value !== null && typeof value === "object") {
      return Object.fromEntries(
        Object.keys(value).sort().map((key) => [key, ordered(value[key])]),
      );
    }
    return value;
  };
  const canonical = (value) => JSON.stringify(ordered(value));
  const sha = (value) => value.toString(16).padStart(2, "0").repeat(32);
  const contractSha256 = (schemaVersion, value) => createHash("sha256")
    .update("controlgraph.contract-sha256/v1\0", "utf8")
    .update(schemaVersion, "utf8")
    .update("\0", "utf8")
    .update(canonical(value), "utf8")
    .digest("hex");
  const imageComponents = [
    "controller",
    "advisor",
    "console",
    "reference-stable",
    "reference-candidate",
  ];
  const caseKinds = [
    "TARGET_RESET",
    "HEALTHY_PROMOTION",
    "UNHEALTHY_STABLE_RECOVERY",
    "REVOCATION_STALE_DENIAL",
    "INDEPENDENT_VERIFIER_PROBE",
    "AMBIGUITY_CLASSIFICATION",
    "TIMELINE_CONSOLE_READ",
    "BOUNDED_ADVISOR",
  ];
  const eventKinds = [
    "AUTHORITY_ADVANCED",
    "STALE_WORK_DENIED",
    "TARGET_UNCHANGED",
    "ADVISOR_VALIDATED",
    "RECOVERY_VERIFIED",
    "TIMELINE_COMMITTED",
  ];
  const traffic90 = {
    candidate_percent: 10,
    schema_version: "controlgraph.public-replay-traffic/v1",
    stable_percent: 90,
    target_configuration_sha256: sha(20),
  };
  const detailValues = [
    {
      cause: "OPERATOR_REVOCATION",
      new_epoch: 2,
      previous_epoch: 1,
      schema_version: "controlgraph.public-replay-authority-advanced/v1",
      transition_sha256: sha(21),
    },
    {
      current_authority_epoch: 2,
      outcome: "DENIED",
      reason_code: "EPOCH_MISMATCH",
      receipt_sha256: sha(22),
      schema_version: "controlgraph.public-replay-stale-denial/v1",
      work_epoch: 1,
    },
    {
      after_denial: traffic90,
      before_denial: traffic90,
      schema_version: "controlgraph.public-replay-target-unchanged/v1",
    },
    {
      advisor: {
        audit_sha256: sha(23),
        authority_effect: "none",
        confidence_basis_points: 8500,
        deterministic_health_override: false,
        findings: [{
          citations: ["receipt", "timeline", "target"].map((evidenceKind, index) => ({
            evidence_id: `evidence-${evidenceKind}`,
            evidence_kind: evidenceKind,
            schema_version: "controlgraph.public-replay-citation/v1",
            source_sha256: sha(30 + index),
          })),
          schema_version: "controlgraph.public-replay-finding/v1",
          statement: "Stale work was denied and the target remained unchanged.",
        }],
        model_id: "gemini-3.5-flash",
        model_location: "global",
        operator_review_required: true,
        prompt_version: "controlgraph.rollout-advisor-prompt/v2",
        registry_sha256: sha(24),
        replayed_without_model_call: true,
        requested_operator_action: "wait",
        response_sha256: sha(25),
        schema_version: "controlgraph.public-replay-advisor/v1",
        snapshot_sha256: sha(26),
        structured_output_sha256: sha(27),
        tool_calls: [
          "read_root_summary",
          "read_target_summary",
          "read_health_summary",
          "read_receipt_summary",
          "read_timeline_summary",
          "read_verifier_summary",
        ].map((toolId, index) => ({
          input_sha256: sha(40 + index),
          output_sha256: sha(50 + index),
          schema_version: "controlgraph.public-replay-tool-call/v1",
          sequence: index + 1,
          status: "succeeded",
          tool_id: toolId,
        })),
        validation: "accepted",
      },
      schema_version: "controlgraph.public-replay-advisor-validated/v1",
    },
    {
      outcome: "VERIFIED",
      receipt_sha256: sha(28),
      schema_version: "controlgraph.public-replay-recovery-verified/v1",
      traffic: {
        candidate_percent: 0,
        schema_version: "controlgraph.public-replay-traffic/v1",
        stable_percent: 100,
        target_configuration_sha256: sha(29),
      },
    },
    {
      schema_version: "controlgraph.public-replay-timeline-committed/v1",
      timeline: {
        entries: [
          "AUTHORITY_EPOCH_ADVANCED",
          "MUTATION_DENIED",
          "MUTATION_APPLIED",
          "MODEL_ASSISTANCE_RECORDED",
        ].map((eventType, index) => ({
          entry_sha256: sha(60 + index),
          event_type: eventType,
          occurred_at: `2026-08-24T00:00:0${index}Z`,
          schema_version: "controlgraph.public-replay-timeline-entry/v1",
          sequence: index + 1,
          verification_status: index === 0 ? "NOT_APPLICABLE" : "VERIFIED",
        })),
        entry_count: 4,
        head_entry_sha256: sha(63),
        head_sequence: 4,
        page_count: 1,
        page_set_sha256: sha(64),
        schema_version: "controlgraph.public-replay-timeline/v1",
      },
    },
  ];
  let predecessor = null;
  const events = eventKinds.map((kind, index) => {
    const event = {
      details: detailValues[index],
      kind,
      occurred_at: `2026-08-24T00:00:0${index}Z`,
      previous_event_sha256: predecessor,
      schema_version: "controlgraph.public-replay-event/v1",
      sequence: index + 1,
    };
    predecessor = contractSha256(event.schema_version, event);
    return {
      event,
      event_sha256: predecessor,
      schema_version: "controlgraph.public-replay-event-envelope/v1",
    };
  });
  const payload = {
    acceptance_manifest_sha256: "a".repeat(64),
    acceptance_run_id: `cgacceptance:${"b".repeat(64)}`,
    acceptance_status: "PASSED",
    accepted_at: "2026-08-24T00:00:06Z",
    cases: caseKinds.map((kind, index) => ({
      case_sha256: sha(index + 1),
      kind,
      schema_version: "controlgraph.public-replay-case/v1",
      sequence: index + 1,
    })),
    event_chain_head_sha256: predecessor,
    events,
    evidence_binding_complete: true,
    images: imageComponents.map((component, index) => ({
      component,
      reference: `us-central1-docker.pkg.dev/controlgraph-canary-abc123/controlgraph-canary/${component}@sha256:${sha(10 + index)}`,
      schema_version: "controlgraph.public-replay-image/v1",
    })),
    schema_version: "controlgraph.public-replay-payload/v1",
    source_commit: "c".repeat(40),
  };
  mutator(payload);
  predecessor = null;
  payload.events.forEach((envelope) => {
    envelope.event.previous_event_sha256 = predecessor;
    predecessor = contractSha256(envelope.event.schema_version, envelope.event);
    envelope.event_sha256 = predecessor;
  });
  payload.event_chain_head_sha256 = predecessor;
  const envelope = {
    payload,
    payload_sha256: contractSha256(payload.schema_version, payload),
    schema_version: "controlgraph.public-replay-envelope/v1",
  };
  const body = Buffer.from(canonical(envelope), "utf8");
  return {
    body,
    environment: {
      CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64: gzipSync(body, { mtime: 0 }).toString("base64"),
      CONTROLGRAPH_PUBLIC_REPLAY_SHA256: createHash("sha256").update(body).digest("hex"),
    },
  };
}

function raw(serverless = FULL) {
  return [
    "X-ControlGraph-Authorization",
    FULL,
    "X-Serverless-Authorization",
    serverless,
    "Origin",
    "https://controlgraph-console-123456789012.us-central1.run.app",
    "Sec-Fetch-Site",
    "same-origin",
    "Sec-Fetch-Mode",
    "cors",
    "Sec-Fetch-Dest",
    "empty",
    "X-ControlGraph-CSRF",
    "a".repeat(43),
    "Content-Type",
    "application/json",
  ];
}

describe("operator console host boundary", () => {
  it("makes the host entrypoint readable by the unprivileged runtime user", () => {
    const dockerfile = readFileSync(new URL("./Dockerfile", import.meta.url), "utf8");

    expect(dockerfile).toContain("COPY --chown=node:node --chmod=0444 host.mjs ./host.mjs");
    expect(dockerfile).toContain("FROM node:22-alpine3.22@sha256:");
    expect(dockerfile).toContain(
      "RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx",
    );
  });

  it("restores the untouched credential after Cloud Run removes its proxy signature", () => {
    for (const serverless of [FULL, REWRITTEN]) {
      const headers = operatorProxyHeaders(raw(serverless), "POST");

      expect(headers.get("X-ControlGraph-Authorization")).toBe(FULL);
      expect(headers.get("X-Serverless-Authorization")).toBe(FULL);
      expect(headers.get("Origin")).toBe(
        "https://controlgraph-console-123456789012.us-central1.run.app",
      );
      expect(headers.get("X-ControlGraph-CSRF")).toBe("a".repeat(43));
      expect(headers.get("Cookie")).toBeNull();
    }
  });

  it("rejects duplicate, substituted, ambient, and cookie identity envelopes", () => {
    const cases = [
      [...raw(), "X-ControlGraph-Authorization", FULL],
      raw("Bearer other.payload.synthetic-signature"),
      [...raw(), "Authorization", FULL],
      [...raw(), "Cookie", "session=ambient"],
    ];

    for (const headers of cases) {
      expect(() => operatorProxyHeaders(headers, "POST")).toThrow(
        /^CONSOLE_(?:IDENTITY_ENVELOPE_INVALID|COOKIE_DENIED)$/,
      );
    }
  });

  it("relays only exact operator API routes to the fixed private origin", () => {
    expect(
      operatorProxyTarget(API, "/v1/operator/timeline?after_sequence=0", "GET"),
    ).toBe(`${API}/v1/operator/timeline?after_sequence=0`);
    expect(operatorProxyTarget(API, "/v1/operator/commands", "POST")).toBe(
      `${API}/v1/operator/commands`,
    );
    expect(() => operatorProxyTarget(API, "/v1/operator/commands", "GET")).toThrow(
      "CONSOLE_ROUTE_DENIED",
    );
    expect(() => operatorProxyTarget(API, "/v1/operator/timeline/raw-export", "GET"))
      .toThrow("CONSOLE_ROUTE_DENIED");
    expect(() => operatorProxyTarget("https://attacker.example", "/v1/operator/timeline", "GET"))
      .toThrow("CONSOLE_CONFIGURATION_INVALID");
  });

  it("renders only a validated non-secret OAuth audience into runtime configuration", () => {
    const script = operatorConfigScript("32555940559.apps.googleusercontent.com");
    expect(script).toBe(
      'window.controlGraphOperatorConfig=Object.freeze({oauthClientAudience:"32555940559.apps.googleusercontent.com"});\n',
    );
    expect(() => operatorConfigScript('</script><script>alert("x")</script>')).toThrow(
      "CONSOLE_CONFIGURATION_INVALID",
    );
  });

  it("loads an optional bounded replay only from a complete hash-matching pair", () => {
    const fixture = replayEnvironment();
    const replay = publicReplayFromEnvironment(fixture.environment);

    expect(replay?.body).toEqual(fixture.body);
    expect(replay?.sha256).toBe(fixture.environment.CONTROLGRAPH_PUBLIC_REPLAY_SHA256);
    expect(publicReplayFromEnvironment({})).toBeUndefined();
    expect(publicReplayConfigScript(replay)).toContain(
      `{"available":true,"sha256":"${replay?.sha256}"}`,
    );
    expect(() => publicReplayFromEnvironment({
      CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64:
        fixture.environment.CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64,
    })).toThrow("CONSOLE_CONFIGURATION_INVALID");
    expect(() => publicReplayFromEnvironment({
      ...fixture.environment,
      CONTROLGRAPH_PUBLIC_REPLAY_SHA256: "0".repeat(64),
    })).toThrow("CONSOLE_CONFIGURATION_INVALID");
    expect(() => publicReplayFromEnvironment({
      ...fixture.environment,
      CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64: "A".repeat(24_576),
    })).toThrow("CONSOLE_CONFIGURATION_INVALID");
    const incomplete = Buffer.from(
      '{"payload":{"schema_version":"controlgraph.public-replay-payload/v1"},' +
        `"payload_sha256":"${"1".repeat(64)}",` +
        '"schema_version":"controlgraph.public-replay-envelope/v1"}',
      "utf8",
    );
    expect(() => publicReplayFromEnvironment({
      CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64: gzipSync(incomplete).toString("base64"),
      CONTROLGRAPH_PUBLIC_REPLAY_SHA256: createHash("sha256").update(incomplete).digest("hex"),
    })).toThrow("CONSOLE_CONFIGURATION_INVALID");
    const overflow = Buffer.alloc(65_537, 0x20);
    expect(() => publicReplayFromEnvironment({
      CONTROLGRAPH_PUBLIC_REPLAY_GZIP_BASE64: gzipSync(overflow).toString("base64"),
      CONTROLGRAPH_PUBLIC_REPLAY_SHA256: createHash("sha256").update(overflow).digest("hex"),
    })).toThrow("CONSOLE_CONFIGURATION_INVALID");
    const yearZero = replayEnvironment((payload) => {
      payload.accepted_at = "0000-08-24T00:00:06Z";
    });
    expect(() => publicReplayFromEnvironment(yearZero.environment)).toThrow(
      "CONSOLE_CONFIGURATION_INVALID",
    );
  });

  it("allows append-ordered timeline replay with an earlier source timestamp", () => {
    const fixture = replayEnvironment((payload) => {
      const timeline = payload.events[5].event.details.timeline;
      const entries = timeline.entries;
      entries.push({
        ...entries[2],
        entry_sha256: "e".repeat(64),
        occurred_at: "2026-08-24T00:00:04Z",
        sequence: 5,
      });
      entries.push({
        ...entries[3],
        entry_sha256: "f".repeat(64),
        occurred_at: "2026-08-24T00:00:03Z",
        sequence: 6,
      });
      timeline.entry_count = 6;
      timeline.head_entry_sha256 = "f".repeat(64);
      timeline.head_sequence = 6;
    });

    expect(publicReplayFromEnvironment(fixture.environment)?.body).toEqual(fixture.body);
  });

  it("serves the public replay without an identity envelope or protected API call", async () => {
    const fixture = replayEnvironment();
    const replay = publicReplayFromEnvironment(fixture.environment);
    const distDirectory = mkdtempSync(join(tmpdir(), "controlgraph-replay-"));
    writeFileSync(join(distDirectory, "replay.html"), "<!doctype html><p>replay</p>");
    const server = createConsoleServer({
      apiOrigin: API,
      consoleOrigin: "https://controlgraph-console-123456789012.us-central1.run.app",
      oauthClientId: "32555940559.apps.googleusercontent.com",
      distDirectory,
      publicReplay: replay,
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string" || replay === undefined) {
        throw new Error("test server address unavailable");
      }
      const origin = `http://127.0.0.1:${address.port}`;
      const page = await fetch(`${origin}/replay`);
      const config = await fetch(`${origin}/replay-config.js`);
      const artifact = await fetch(`${origin}/replays/${replay.sha256}.json`);

      expect(page.status).toBe(200);
      expect(page.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(page.headers.get("content-security-policy")).not.toContain("accounts.google.com");
      expect(await config.text()).toBe(publicReplayConfigScript(replay));
      expect(artifact.status).toBe(200);
      expect(artifact.headers.get("cache-control")).toBe(
        "public, max-age=31536000, immutable",
      );
      expect(Buffer.from(await artifact.arrayBuffer())).toEqual(fixture.body);
      expect((await fetch(`${origin}/replays/${"0".repeat(64)}.json`)).status).toBe(404);
    } finally {
      await new Promise((resolve, reject) => {
        server.close((error) => error === undefined ? resolve() : reject(error));
      });
      rmSync(distDirectory, { recursive: true, force: true });
    }
  });

  it("never reflects relay exception details, credentials, or CSRF state", async () => {
    const secretCsrf = "z".repeat(43);
    const server = createConsoleServer(
      {
        apiOrigin: API,
        consoleOrigin:
          "https://controlgraph-console-123456789012.us-central1.run.app",
        oauthClientId: "32555940559.apps.googleusercontent.com",
        distDirectory: "/unused-for-api-route",
      },
      {
        fetcher: async () => {
          const error = new Error(`provider rejected ${FULL} ${secretCsrf}`);
          error.code = `CONSOLE_${secretCsrf}`;
          throw error;
        },
      },
    );
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("test server address unavailable");
      }
      const response = await fetch(
        `http://127.0.0.1:${address.port}/v1/operator/commands`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Origin": "https://controlgraph-console-123456789012.us-central1.run.app",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "X-ControlGraph-Authorization": FULL,
            "X-ControlGraph-CSRF": secretCsrf,
            "X-Serverless-Authorization": FULL,
          },
          body: "{}",
        },
      );
      const responseBody = await response.text();

      expect(response.status).toBe(502);
      expect(responseBody).toContain("CONSOLE_UPSTREAM_UNAVAILABLE");
      expect(responseBody).not.toContain(FULL);
      expect(responseBody).not.toContain(secretCsrf);
    } finally {
      await new Promise((resolve, reject) => {
        server.close((error) => error === undefined ? resolve() : reject(error));
      });
    }
  });
});
