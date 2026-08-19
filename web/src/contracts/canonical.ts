export const CANONICAL_ENCODING = "controlgraph.canonical-json/v1";
export const DIGEST_DOMAIN = "controlgraph.contract-sha256/v1\0";
export const MAX_CONTRACT_BYTES = 65_536;
export const MAX_JSON_DEPTH = 12;
export const MAX_JSON_ITEMS = 64;

const objectKey = /^[a-z][a-z0-9_]*$/;
const base64Url = /^[A-Za-z0-9_-]*$/;
const utcSecond =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

export class ContractCodecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContractCodecError";
  }
}

function assertUnicodeScalars(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new ContractCodecError("text contains an unpaired surrogate");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new ContractCodecError("text contains an unpaired surrogate");
    }
  }
}

function assertNfc(value: string): void {
  assertUnicodeScalars(value);
  if (value.normalize("NFC") !== value) {
    throw new ContractCodecError("text must use NFC normalization");
  }
}

function assertRestricted(value: unknown, depth = 0): void {
  if (depth > MAX_JSON_DEPTH) {
    throw new ContractCodecError("JSON nesting is too deep");
  }
  if (value === null || typeof value === "boolean") {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ContractCodecError("number is not a safe integer");
    }
    return;
  }
  if (typeof value === "string") {
    assertNfc(value);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_JSON_ITEMS) {
      throw new ContractCodecError("JSON array has too many items");
    }
    value.forEach((item) => assertRestricted(item, depth + 1));
    return;
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new ContractCodecError("JSON object has an invalid prototype");
    }
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > MAX_JSON_ITEMS) {
      throw new ContractCodecError("JSON object has too many fields");
    }
    for (const [key, item] of entries) {
      if (!objectKey.test(key)) {
        throw new ContractCodecError("JSON object key is not canonical");
      }
      assertRestricted(item, depth + 1);
    }
    return;
  }
  throw new ContractCodecError("value is not part of restricted JSON");
}

function ordered(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(ordered);
  }
  if (value !== null && typeof value === "object") {
    const source = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(source)
        .sort()
        .map((key) => [key, ordered(source[key])]),
    );
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  assertRestricted(value);
  const text = JSON.stringify(ordered(value));
  if (text === undefined) {
    throw new ContractCodecError("canonical JSON encoding failed");
  }
  const bytes = new TextEncoder().encode(text);
  if (bytes.length === 0 || bytes.length > MAX_CONTRACT_BYTES) {
    throw new ContractCodecError("canonical JSON is outside its byte bounds");
  }
  return text;
}

export function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

export function decodeCanonicalJson(text: string): Record<string, unknown> {
  if (typeof text !== "string") {
    throw new TypeError("contract text must be a string");
  }
  const bytes = new TextEncoder().encode(text);
  if (bytes.length === 0 || bytes.length > MAX_CONTRACT_BYTES) {
    throw new ContractCodecError("contract is outside its byte bounds");
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ContractCodecError("contract is not valid JSON");
  }
  assertRestricted(value);
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    canonicalJson(value) !== text
  ) {
    throw new ContractCodecError("contract is not a canonical JSON object");
  }
  return value as Record<string, unknown>;
}

export function decodeVersionedCanonicalJson(
  text: string,
  expectedVersion: string,
): Record<string, unknown> {
  const value = decodeCanonicalJson(text);
  if (typeof value.schema_version !== "string") {
    throw new ContractCodecError("schema_version is required");
  }
  if (value.schema_version !== expectedVersion) {
    throw new ContractCodecError("schema_version is unsupported");
  }
  return value;
}

function concatenate(...parts: readonly Uint8Array[]): Uint8Array {
  const size = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export async function canonicalSha256(
  schemaVersion: string,
  value: unknown,
): Promise<string> {
  assertNfc(schemaVersion);
  const encoder = new TextEncoder();
  const material = concatenate(
    encoder.encode(DIGEST_DOMAIN),
    encoder.encode(schemaVersion),
    new Uint8Array([0]),
    canonicalJsonBytes(value),
  );
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", material));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function encodeBase64Url(value: Uint8Array): string {
  let binary = "";
  value.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function decodeBase64Url(value: string, maximumBytes = 16_384): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length > maximumBytes * 2 ||
    !base64Url.test(value)
  ) {
    throw new ContractCodecError("base64url value is invalid");
  }
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  } catch {
    throw new ContractCodecError("base64url value is invalid");
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (decoded.length > maximumBytes || encodeBase64Url(decoded) !== value) {
    throw new ContractCodecError("base64url value is not canonical");
  }
  return decoded;
}

export function assertUtcSecondTimestamp(value: string): void {
  const match = utcSecond.exec(value);
  if (match === null || Number(match[1]) < 1) {
    throw new ContractCodecError("timestamp must use a valid UTC-second encoding");
  }
  const parsed = new Date(value);
  if (
    Number.isNaN(parsed.valueOf()) ||
    parsed.toISOString().replace(".000Z", "Z") !== value
  ) {
    throw new ContractCodecError("timestamp must use a valid UTC-second encoding");
  }
}
