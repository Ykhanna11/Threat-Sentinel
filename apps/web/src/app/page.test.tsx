import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import HomePage from "./page";

describe("home page", () => {
  it("introduces ThreatSentinel and makes its development status clear", () => {
    const markup = renderToStaticMarkup(createElement(HomePage));

    expect(markup).toContain("Security intelligence,");
    expect(markup).toContain("A Meta Infinium platform");
    expect(markup).toContain("Core product capabilities are planned and are not yet available.");
  });
});
