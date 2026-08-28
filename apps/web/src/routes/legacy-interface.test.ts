import { cleanup, render, screen, waitFor } from "@testing-library/svelte";
import { afterEach, describe, expect, it } from "vitest";
import Page from "./+page.svelte";

afterEach(() => cleanup());

describe("legacy Patch8 dashboard", () => {
  it("preserves the legacy identity, search, and dashboard sections", async () => {
    render(Page);

    expect(screen.getByRole("heading", { level: 1, name: "patch8" })).toBeInTheDocument();
    expect(screen.getByText("Vulnerability intelligence, prioritised")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Search CVE IDs, descriptions, or packages…")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Recent KEV Vulnerabilities" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Critical CVEs" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "High EPSS Risk" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Patch Tuesday" })).toBeInTheDocument();

    await waitFor(() => expect(screen.getByText("Stats temporarily unavailable")).toBeInTheDocument());
    expect(screen.getByText("KEV data unavailable in this static release")).toBeInTheDocument();
    expect(screen.getByText("CVE data unavailable in this static release")).toBeInTheDocument();
    expect(screen.getByText("EPSS data unavailable in this static release")).toBeInTheDocument();
    expect(screen.getByText("Patch Tuesday data unavailable in this static release")).toBeInTheDocument();
  });
});
