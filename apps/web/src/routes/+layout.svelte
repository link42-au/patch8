<script lang="ts">
  import { base } from "$app/paths";
  import "../theme.css";

  let { children } = $props();
  let dark = $state(false);

  const toggleTheme = (): void => {
    dark = document.documentElement.dataset.theme !== "dark";
    const next = dark ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("patch8-theme", next);
    } catch {
      // Theme selection still works for this page when storage is unavailable.
    }
  };
</script>

<svelte:head>
  <title>Patch8 — vulnerability intelligence</title>
  <meta
    name="description"
    content="Patch8 is a planned, public, browser-direct vulnerability intelligence explorer."
  />
</svelte:head>

<a class="skip-link" href="#main">Skip to content</a>
<header class="site-header">
  <a class="brand" href={`${base}/`} aria-label="Patch8 home">
    <span class="brand-mark" aria-hidden="true">P8</span>
    <span>Patch8</span>
  </a>
  <nav aria-label="Primary navigation">
    <a href="#capabilities">Capabilities</a>
    <a href="#sources">Sources</a>
    <a href="https://github.com/link42-au/patch8">Source code</a>
  </nav>
  <button class="theme-toggle" type="button" aria-label="Toggle colour theme" onclick={toggleTheme}>
    <span aria-hidden="true">◐</span>
  </button>
</header>

{@render children()}

<footer>
  <p>Patch8 is free software licensed under AGPL-3.0-or-later.</p>
  <p>No account, paid feature, application server, or hosted database.</p>
</footer>
