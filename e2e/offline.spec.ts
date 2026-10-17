// No network at runtime (app ADR section 5): every request the browser
// makes is routed through the test. The page is one file, so loading it is
// one request to its own origin; after the load a full tour of the app
// makes no http(s) request at all, to any origin.
import { expect, test } from "@playwright/test";
import { tour } from "./helpers";

test("after load, a full tour of the app makes no request at all", async ({ page, context, baseURL }) => {
  const origin = new URL(baseURL as string).origin;
  const atLoad: string[] = [];
  const routed: string[] = [];
  const seen: string[] = [];
  let loaded = false;
  await context.route("**/*", (route) => {
    const url = route.request().url();
    (loaded ? routed : atLoad).push(url);
    return new URL(url).origin === origin && !loaded ? route.continue() : route.abort();
  });
  // what a route might not see (a service worker's fetch, a socket) is recorded too
  page.on("request", (r) => {
    if (loaded && /^(https?|wss?):/.test(r.url())) seen.push(r.url());
  });
  page.on("websocket", (ws) => seen.push(ws.url()));

  await page.goto("/", { waitUntil: "load" });
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Qayd");
  loaded = true;

  await tour(page, null);

  expect(atLoad).toEqual([`${origin}/`]);
  expect(routed).toEqual([]);
  expect(seen).toEqual([]);

  // the recorders are not blind: a request made now is seen (and refused)
  await page.evaluate(() => fetch("https://example.invalid/probe").catch(() => null));
  expect(routed).toEqual(["https://example.invalid/probe"]);
  expect(seen).toEqual(["https://example.invalid/probe"]);
});

test("the tour works with every request but the page itself refused", async ({ page, context, baseURL }) => {
  const origin = new URL(baseURL as string).origin;
  const refused: string[] = [];
  await context.route("**/*", (route) => {
    const req = route.request();
    if (req.isNavigationRequest() && req.url() === `${origin}/`) return route.continue();
    refused.push(req.url());
    return route.abort("internetdisconnected");
  });
  await tour(page);
  expect(refused).toEqual([]);
});
