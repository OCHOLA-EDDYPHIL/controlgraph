import { describe, expect, it } from "vitest";

import golden from "../../../contract-fixtures/v1/golden.json";
import malformed from "../../../contract-fixtures/v1/malformed.json";
import {
  assertUtcSecondTimestamp,
  canonicalJson,
  canonicalSha256,
  decodeBase64Url,
  decodeVersionedCanonicalJson,
  encodeBase64Url,
} from "./canonical";

describe("restricted canonical contracts", () => {
  it("matches every Python golden byte and digest", async () => {
    for (const vector of golden.vectors) {
      const value = decodeVersionedCanonicalJson(
        vector.canonical,
        vector.schema_version,
      );

      expect(canonicalJson(value)).toBe(vector.canonical);
      await expect(canonicalSha256(vector.schema_version, value)).resolves.toBe(
        vector.sha256,
      );
    }
  });

  it("rejects every shared ambiguous or malformed encoding", () => {
    for (const fixture of malformed.cases) {
      expect(() =>
        decodeVersionedCanonicalJson(
          fixture.text,
          "controlgraph.target-binding/v1",
        ),
      ).toThrow();
    }
  });

  it("rejects floats, unsafe integers, deep values, and non-NFC strings", () => {
    expect(() => canonicalJson({ value: 1.5 })).toThrow();
    expect(() => canonicalJson({ value: Number.MAX_SAFE_INTEGER + 1 })).toThrow();
    expect(() => canonicalJson({ value: "Cafe\u0301" })).toThrow();

    let value: unknown = true;
    for (let depth = 0; depth < 14; depth += 1) {
      value = [value];
    }
    expect(() => canonicalJson(value)).toThrow();
  });

  it("uses one unpadded base64url spelling", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const encoded = encodeBase64Url(bytes);

    expect(encoded).not.toMatch(/[=+/]/);
    expect(decodeBase64Url(encoded)).toEqual(bytes);
    expect(() => decodeBase64Url("A=")).toThrow();
    expect(() => decodeBase64Url("A")).toThrow();
  });

  it("accepts only exact valid UTC-second timestamps", () => {
    expect(() => assertUtcSecondTimestamp("2026-08-19T12:00:00Z")).not.toThrow();
    expect(() => assertUtcSecondTimestamp("2026-02-30T12:00:00Z")).toThrow();
    expect(() => assertUtcSecondTimestamp("2026-08-19T12:00:00.000Z")).toThrow();
    expect(() => assertUtcSecondTimestamp("2026-08-19T12:00:00+00:00")).toThrow();
  });
});
