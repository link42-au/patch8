import adapter from "@sveltejs/adapter-static";

const config = {
  kit: {
    adapter: adapter({ fallback: "404.html" }),
    paths: { base: process.env.BASE_PATH ?? "" },
    prerender: { crawl: true, handleUnseenRoutes: "ignore" },
  },
};

export default config;
