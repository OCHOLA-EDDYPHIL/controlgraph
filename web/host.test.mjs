// @vitest-environment node

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  createConsoleServer,
  operatorConfigScript,
  operatorProxyHeaders,
  operatorProxyTarget,
} from "./host.mjs";

const API = "https://controlgraph-api-123456789012.us-central1.run.app";
const FULL = "Bearer header.payload.synthetic-signature";
const REWRITTEN = "bearer header.payload.SIGNATURE_REMOVED_BY_GOOGLE";

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
