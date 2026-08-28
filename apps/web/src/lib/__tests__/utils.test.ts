import { describe, expect, it } from "vitest";
import { highlightMatch } from "../utils";

describe("highlightMatch", () => {
  it("escapes text before returning HTML", () => {
    expect(highlightMatch("<script>alert(1)</script>", "")).toBe("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("escapes highlighted matches", () => {
    expect(highlightMatch("<img>", "<img>")).toBe('<span class="match">&lt;img&gt;</span>');
  });

  it("does not insert markup inside escaped entities", () => {
    expect(highlightMatch("R&D", "amp")).toBe("R&amp;D");
  });

  it("escapes regex metacharacters in the query", () => {
    expect(highlightMatch("C++ runtime", "C++")).toBe('<span class="match">C++</span> runtime');
  });
});
