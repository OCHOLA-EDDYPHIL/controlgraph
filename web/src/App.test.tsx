import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { App } from "./App";

describe("App", () => {
  it("makes the safety posture visible", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", { name: "One active controller. Every epoch." }),
    ).toBeTruthy();
    expect(screen.getAllByText("Held safe")).toHaveLength(2);
    expect(
      screen.getByText("Nothing here deploys or mutates a cloud resource."),
    ).toBeTruthy();
  });
});
