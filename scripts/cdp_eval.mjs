#!/usr/bin/env node
// Run JavaScript in a shodan.io tab of a Chrome window started with --remote-debugging-port, and print the result.
// For agents with a shell but no browser tool, without turning on "Allow JavaScript from Apple Events".
// Works with node 22+ or bun (both have fetch and WebSocket built in). Start the window once:
//
//   P=~/.local/state/shodan-cert-report/chrome-profile
//   open -na "Google Chrome" --args --user-data-dir="$P" --remote-debugging-port=9333 --no-first-run https://account.shodan.io/login
//
// The user logs in to Shodan in that window; the profile keeps the login for later sessions. Then:
//
//   node scripts/cdp_eval.mjs scripts/shodan-batch.js
//   node scripts/cdp_eval.mjs 'window.__run(["country:SE \"Tridium\""]); "started"'
//   node scripts/cdp_eval.mjs 'window.__done ? JSON.stringify(window.__res) : "false"'
//
// The value of the last expression is printed (strings as they are, anything else as JSON); promises are awaited.
// Port: $CDP_PORT, default 9333. While the window is open, any program on this Mac can control it through the port.
import { existsSync, readFileSync } from "node:fs";

const arg = process.argv[2];
if (!arg) {
  console.error("usage: cdp_eval.mjs FILE-or-CODE");
  process.exit(2);
}
const code = existsSync(arg) ? readFileSync(arg, "utf8") : arg;
const port = process.env.CDP_PORT || "9333";

let tabs;
try {
  tabs = await (await fetch(`http://localhost:${port}/json`)).json();
} catch {
  console.error(`no Chrome with --remote-debugging-port=${port}; start it as shown at the top of this file`);
  process.exit(2);
}
const tab = tabs.find((t) => t.type === "page" && /^https:\/\/(www\.)?shodan\.io\//.test(t.url));
if (!tab) {
  console.error("no shodan.io tab in that window; open https://www.shodan.io there first");
  process.exit(2);
}

const ws = new WebSocket(tab.webSocketDebuggerUrl);
ws.onerror = () => {
  console.error("could not reach the tab");
  process.exit(2);
};
ws.onopen = () =>
  ws.send(JSON.stringify({
    id: 1,
    method: "Runtime.evaluate",
    params: { expression: code, awaitPromise: true, returnByValue: true },
  }));
ws.onmessage = (m) => {
  const d = JSON.parse(String(m.data));
  if (d.id !== 1) return;
  const ex = d.result?.exceptionDetails;
  if (ex) {
    console.error(ex.exception?.description || ex.text);
    process.exit(1);
  }
  const v = d.result?.result?.value;
  console.log(typeof v === "string" ? v : JSON.stringify(v));
  ws.close();
  process.exit(0);
};
