import { cleanup, render, screen, within } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";
import Page from "./+page.svelte";

afterEach(() => cleanup());

describe("Patch8 shell", () => {
  it("states that data capabilities are planned rather than implemented", () => {
    render(Page);

    expect(screen.getByRole("heading", { level: 1, name: "Know what needs patching." })).toBeInTheDocument();
    expect(
      screen.getByText(/Exact CVE lookup and CISA Known Exploited Vulnerabilities context are planned/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Lookup planned" })).toBeDisabled();
    expect(screen.getByLabelText("CVE identifier")).toBeDisabled();
  });

  it("keeps conditional sources visibly disabled", () => {
    render(Page);
    const epss = screen.getByRole("heading", { level: 3, name: "EPSS and OSV" }).closest("article");

    expect(epss).not.toBeNull();
    expect(within(epss as HTMLElement).getByText("Disabled")).toBeInTheDocument();
    expect(within(epss as HTMLElement).getByText(/EPSS awaits a direct-display policy update/)).toBeInTheDocument();
  });
});
