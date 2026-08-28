<script lang="ts">
import "@link42/tokens";
import { onMount } from "svelte";
import { goto } from "$app/navigation";
import { base } from "$app/paths";
import { page } from "$app/state";
import "../brand.css";
import "@link42/ui/patterns.css";
import "@link42/ui/components.css";
import { PlatformBar, Header, Footer, Toast, theme } from "@link42/ui";

let { children } = $props();

const navItems = [
  { href: `${base}/search`, label: "Search" },
  { href: `${base}/software`, label: "Software" },
  { href: `${base}/packages`, label: "Packages" },
  { href: `${base}/reports/patch-tuesday`, label: "Reports" },
  { href: `${base}/feeds`, label: "Feeds" },
];

onMount(() => {
  theme.init();
});
</script>

<a href="#main-content" class="skip-link">Skip to content</a>

<PlatformBar
  currentApp="patch8"
  currentHref={`${base}/`}
  theme={theme.value}
  onToggleTheme={() => theme.toggle()}
/>

<Header
  navItems={navItems}
  activePath={page.url.pathname}
  search={{ placeholder: "Search CVEs...", onSubmit: (q) => { goto(q ? `${base}/search?q=${encodeURIComponent(q)}` : `${base}/search`); } }}
/>

<main id="main-content">
  {@render children()}
</main>

<Footer appName="patch8" excludeApps={["login2", "peer6"]} />

<Toast />

<style>
   .skip-link {
      position: absolute;
      top: -100%;
      left: 0;
      background: var(--accent);
      color: white;
      padding: 0.5rem 1rem;
      z-index: 100;
      text-decoration: none;
      font-size: 13px;
      border-radius: 0 0 6px 0;
   }
   .skip-link:focus {
      top: 0;
   }
   main {
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px 20px;
      min-height: calc(100vh - 50px - 60px);
   }
 </style>
