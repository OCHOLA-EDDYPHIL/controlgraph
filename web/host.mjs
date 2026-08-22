import { readFile, realpath } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const MAX_REQUEST_BYTES = 65_536;
const MAX_RESPONSE_BYTES = 65_536;
const TIMELINE_TIMEOUT_MS = 12_000;
const COMMAND_TIMEOUT_MS = 60_000;
const oauthClientAudience =
  /^[0-9]{6,32}(?:-[a-z0-9]{6,128})?\.apps\.googleusercontent\.com$/;
const consoleOriginPattern =
  /^https:\/\/controlgraph-console-[1-9][0-9]{5,31}\.us-central1\.run\.app$/;
const apiOriginPattern =
  /^https:\/\/controlgraph-api-[1-9][0-9]{5,31}\.us-central1\.run\.app$/;
const bearer = /^Bearer ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;
const safeErrorCodes = new Set([
  "CONSOLE_BODY_TOO_LARGE",
  "CONSOLE_BROWSER_ENVELOPE_INVALID",
  "CONSOLE_CONFIGURATION_INVALID",
  "CONSOLE_CONTENT_TYPE_INVALID",
  "CONSOLE_COOKIE_DENIED",
  "CONSOLE_IDENTITY_ENVELOPE_INVALID",
  "CONSOLE_METHOD_DENIED",
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

function fail(code) {
  const error = new Error(code);
  error.code = code;
  return error;
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
    : pathname.startsWith("/assets/") && /^\/assets\/[A-Za-z0-9._-]+$/.test(pathname)
      ? pathname.slice(1)
      : null;
  if (relative === null) {
    throw fail("CONSOLE_ROUTE_DENIED");
  }
  const root = await realpath(distDirectory);
  const path = await realpath(resolve(join(root, relative)));
  if (path !== join(root, "index.html") && !path.startsWith(`${join(root, "assets")}/`)) {
    throw fail("CONSOLE_ROUTE_DENIED");
  }
  return {
    body: await readFile(path),
    contentType: relative === "index.html" ? "text/html; charset=utf-8" : contentType(path),
  };
}

export function createConsoleServer(configuration, dependencies = {}) {
  const {
    apiOrigin,
    consoleOrigin,
    oauthClientId,
    distDirectory,
  } = configuration;
  if (
    !apiOriginPattern.test(apiOrigin) ||
    !consoleOriginPattern.test(consoleOrigin) ||
    !oauthClientAudience.test(oauthClientId) ||
    typeof distDirectory !== "string" ||
    distDirectory.length === 0
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
      const pathname = new URL(requestUrl, consoleOrigin).pathname;
      if (!pathname.startsWith("/v1/operator/")) {
        const asset = await staticAsset(distDirectory, pathname);
        respond(response, 200, asset.contentType, asset.body);
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
  };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const configuration = runtimeConfiguration();
  createConsoleServer(configuration).listen(configuration.port, "0.0.0.0");
}
