import { describe, expect, it } from "vitest";

import manifest from "../../../contract-fixtures/manifest.json";

describe("shared contract fixtures", () => {
  it("uses the expected versioned manifest", () => {
    expect(manifest).toEqual({
      canonical_encoding: "controlgraph.canonical-json/v1",
      fixture_version: "controlgraph.contract-fixtures/v1",
      fixture_sets: [{ manifest: "v1/manifest.json", name: "v1" }],
    });
  });
});
