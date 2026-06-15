#!/usr/bin/env node
import http from "node:http";
import { URL } from "node:url";
import { readRailwayVariables } from "./lib/readRailwayVariables.mjs";

const DEFAULT_BASE_URL = "https://securl-app-production.up.railway.app";
const DEFAULT_PORT = 8790;

function send(response, status, body, headers = {}) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(body);
}

const vars = process.env.TELEMETRY_TOKEN ? {} : readRailwayVariables();
const telemetryToken = process.env.TELEMETRY_TOKEN || vars.TELEMETRY_TOKEN || vars.ADMIN_TELEMETRY_TOKEN || "";
const baseUrl = String(process.env.TELEMETRY_BASE_URL || vars.PUBLIC_API_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
const port = Number(process.env.PORT || DEFAULT_PORT);

if (!telemetryToken) {
  const railwayHint = vars.__railwayReadError ? ` Railway variable lookup failed: ${vars.__railwayReadError}` : "";
  console.error(`No TELEMETRY_TOKEN found.${railwayHint} Run \`railway login\`, or export TELEMETRY_TOKEN in this shell.`);
  process.exit(1);
}

const html = String.raw`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SecURL Telemetry</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #040c08;
      --panel: rgba(255,255,255,.045);
      --panel-strong: rgba(8,18,13,.92);
      --line: rgba(255,255,255,.1);
      --muted: #8b9a93;
      --text: #f6fff9;
      --teal: #2dd4bf;
      --blue: #7dd3fc;
      --amber: #fbbf24;
      --rose: #fb7185;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(ellipse 75% 50% at 15% -10%, rgba(16,185,129,.34), transparent 55%),
        radial-gradient(ellipse 45% 35% at 85% 5%, rgba(14,165,233,.16), transparent 52%),
        linear-gradient(180deg, #040c08 0%, #07110c 100%);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0; }
    .hero {
      border: 1px solid rgba(16,185,129,.2);
      background: var(--panel-strong);
      border-radius: 32px;
      padding: 30px;
      box-shadow: 0 48px 120px -40px rgba(0,0,0,.8), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .hero-row { display: flex; gap: 24px; justify-content: space-between; align-items: end; flex-wrap: wrap; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid rgba(45,212,191,.2);
      background: rgba(45,212,191,.1);
      color: #b8fff2;
      border-radius: 999px;
      padding: 6px 12px;
      text-transform: uppercase;
      letter-spacing: .18em;
      font-size: 12px;
      font-weight: 800;
    }
    h1 { margin: 20px 0 0; font-size: clamp(42px, 8vw, 76px); line-height: .9; letter-spacing: -.07em; }
    .sub { max-width: 720px; margin: 18px 0 0; color: #b8c6bf; font-size: 16px; line-height: 1.7; }
    button {
      appearance: none;
      border: 0;
      border-radius: 16px;
      background: var(--teal);
      color: #03110d;
      padding: 13px 18px;
      font-weight: 900;
      cursor: pointer;
      box-shadow: 0 18px 40px -24px rgba(45,212,191,.8);
    }
    button:disabled { cursor: wait; opacity: .7; }
    .meta { margin-top: 18px; color: var(--muted); font-size: 13px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-top: 24px; }
    .two { display: grid; grid-template-columns: 1.05fr .95fr; gap: 20px; margin-top: 20px; }
    .three { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 20px; margin-top: 20px; }
    .card {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 26px;
      padding: 22px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.05);
    }
    .kicker { color: var(--muted); text-transform: uppercase; letter-spacing: .22em; font-size: 11px; font-weight: 900; }
    .value { margin-top: 18px; font-size: 42px; line-height: 1; letter-spacing: -.06em; font-weight: 950; }
    .detail { margin-top: 10px; color: #9aaaa2; line-height: 1.55; font-size: 14px; }
    .split { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 18px; }
    .split-box { border: 1px solid var(--line); background: rgba(0,0,0,.18); border-radius: 18px; padding: 14px; }
    .split-label { color: var(--muted); text-transform: uppercase; letter-spacing: .18em; font-size: 10px; font-weight: 900; }
    .split-value { margin-top: 8px; font-size: 34px; line-height: 1; letter-spacing: -.055em; font-weight: 950; }
    h2 { margin: 8px 0 0; font-size: 26px; line-height: 1.05; letter-spacing: -.04em; }
    .row { display: flex; justify-content: space-between; gap: 16px; align-items: center; border: 1px solid var(--line); background: rgba(0,0,0,.2); border-radius: 18px; padding: 14px; margin-top: 10px; }
    .event { border: 1px solid var(--line); background: rgba(0,0,0,.2); border-radius: 18px; padding: 14px; margin-top: 10px; }
    .event strong { display: block; color: var(--paper); }
    .event small { display: block; margin-top: 8px; color: var(--muted); line-height: 1.45; }
    .bar { height: 8px; overflow: hidden; border-radius: 999px; background: rgba(255,255,255,.1); margin-top: 12px; }
    .fill { height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--teal), var(--blue)); }
    .warn { color: var(--amber); }
    .bad { color: var(--rose); }
    .good { color: var(--teal); }
    pre { white-space: pre-wrap; color: #b8c6bf; }
    @media (max-width: 900px) { .grid, .two, .three { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="hero-row">
        <div>
          <div class="pill">SecURL telemetry</div>
          <h1>Traffic and<br />scan pulse.</h1>
          <p class="sub">Local-only dashboard for live Railway telemetry. The token stays in this local Node process and is never sent to the browser.</p>
          <p class="meta" id="meta">Loading...</p>
        </div>
        <button id="refresh">Refresh</button>
      </div>
    </section>
    <section id="content"></section>
  </main>
  <script>
    const fmt = (n) => Number(n || 0).toLocaleString();
    const ms = (n) => fmt(Math.round(n || 0)) + "ms";
    const date = (s) => s ? new Date(s).toLocaleString() : "Unknown";
    const entries = (o) => Object.entries(o || {}).sort((a, b) => b[1] - a[1]);
    const sourceLabel = (s) => s.replaceAll("_", " ");
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
    const card = (label, value, detail, cls = "") => '<div class="card"><div class="kicker">' + label + '</div><div class="value ' + cls + '">' + value + '</div><div class="detail">' + detail + '</div></div>';
    const splitCard = (label, total, today, detail, cls = "") => '<div class="card"><div class="kicker">' + label + '</div><div class="split"><div class="split-box"><div class="split-label">Total</div><div class="split-value ' + cls + '">' + total + '</div></div><div class="split-box"><div class="split-label">Today</div><div class="split-value ' + cls + '">' + today + '</div></div></div><div class="detail">' + detail + '</div></div>';
    const row = (label, value) => '<div class="row"><span>' + label + '</span><strong>' + value + '</strong></div>';
    const event = (item) => '<div class="event"><strong>' + esc(item.class || "failure") + '</strong><small>' + esc(item.target || "Unknown target") + '</small><small>' + esc(item.message || "No message recorded.") + '</small><small>' + date(item.occurredAt) + (item.source ? " · " + esc(item.source) : "") + '</small></div>';

    async function load() {
      const button = document.getElementById("refresh");
      const content = document.getElementById("content");
      const meta = document.getElementById("meta");
      button.disabled = true;
      try {
        const res = await fetch("/api/telemetry");
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Request failed");
        meta.textContent = "Backend started " + date(data.startedAt) + " · storage: " + data.persistence;
        const failureTotal = (data.failures?.authRejected || 0) + (data.failures?.requesterRateLimited || 0) + (data.failures?.targetRateLimited || 0) + entries(data.failures?.classes).reduce((s, e) => s + e[1], 0);
        const sources = entries(data.trafficSources?.pageLoads);
        const todaySources = entries(data.trafficSources?.today);
        const funnelEvents = entries(data.funnel?.events);
        const funnelSources = entries(Object.fromEntries(entries(data.funnel?.bySource).map(([source, events]) => [source, Object.values(events || {}).reduce((sum, count) => sum + Number(count || 0), 0)])));
        const limitedKinds = entries(data.scans?.limitedReadKinds);
        const scanSources = entries(data.scans?.engagement?.sources);
        const scanChannels = entries(data.scans?.engagement?.channels);
        const repeatTargets = Array.isArray(data.scans?.engagement?.repeatTargets) ? data.scans.engagement.repeatTargets.slice(0, 8) : [];
        const failureClasses = entries(data.failures?.classes);
        const recentFailures = Array.isArray(data.failures?.recent) ? data.failures.recent.slice(0, 8) : [];
        content.innerHTML =
          '<div class="grid">' +
            splitCard("Page loads", fmt(data.pageLoads), fmt(data.visitors?.today?.pageLoads), "Total is all persisted page-load telemetry; today is the current UTC day.") +
            splitCard("Unique visitors", fmt(data.visitors?.unique), fmt(data.visitors?.today?.uniqueVisitors), "Unique count is based on the hashed IP and user-agent visitor key.", "good") +
            card("Scans completed", fmt(data.scans?.completed) + "/" + fmt(data.scans?.requested), fmt(data.scans?.fullReads) + " full reads, " + fmt(data.scans?.limitedReads) + " limited reads.", "good") +
            card("Scan uniqueness", fmt(data.scans?.engagement?.uniqueRequesters) + " / " + fmt(data.scans?.engagement?.uniqueTargets), fmt(data.scans?.engagement?.uniqueClients) + " unique scan clients. Requesters / targets separates repeat testing from wider use.", "good") +
            card("Failures", fmt(failureTotal), fmt(data.failures?.requesterRateLimited) + " requester limits, " + fmt(data.failures?.targetRateLimited) + " target limits.", failureTotal ? "bad" : "warn") +
          '</div>' +
          '<div class="two">' +
            '<div class="card"><div class="kicker">Traffic sources</div><h2>Where visits came from</h2>' +
              (sources.length ? sources.map(([source, count]) => '<div class="row"><span style="text-transform:capitalize">' + sourceLabel(source) + '</span><strong>' + fmt(count) + '</strong></div><div class="bar"><div class="fill" style="width:' + Math.max(6, data.pageLoads ? count / data.pageLoads * 100 : 0) + '%"></div></div>').join("") : '<p class="detail">No traffic source data yet.</p>') +
            '</div>' +
            '<div class="card"><div class="kicker">Funnel events</div><h2>What visitors did next</h2>' +
              (funnelEvents.length ? funnelEvents.map(([event, count]) => row(event, fmt(count))).join("") : '<p class="detail">No funnel events recorded yet.</p>') +
              (funnelSources.length ? '<div class="detail">Top sources</div>' + funnelSources.slice(0, 5).map(([source, count]) => row(sourceLabel(source), fmt(count))).join("") : '') +
            '</div>' +
          '</div>' +
          '<div class="two">' +
            '<div class="card"><div class="kicker">Scan timings</div><h2>How the engine is behaving</h2>' +
              row("Average total", ms(data.scans?.timing?.total?.averageMs)) +
              row("95% finished under", ms(data.scans?.timing?.total?.p95Ms)) +
              row("Core average", ms(data.scans?.timing?.core?.averageMs)) +
              row("Enrichment average", ms(data.scans?.timing?.enrichment?.averageMs)) +
            '</div>' +
            '<div class="card"><div class="kicker">Scan engagement</div><h2>Who is actually using scans</h2>' +
              (scanChannels.length ? '<div class="detail">Channels</div>' + scanChannels.map(([k, v]) => row(sourceLabel(k), fmt(v))).join("") : '<p class="detail">No scan channel data yet.</p>') +
              (scanSources.length ? '<div class="detail">Sources</div>' + scanSources.slice(0, 6).map(([k, v]) => row(sourceLabel(k), fmt(v))).join("") : '') +
            '</div>' +
          '</div>' +
          '<div class="three">' +
            '<div class="card"><div class="kicker">Today</div><h2>' + (data.visitors?.today?.date || "Today") + '</h2>' + (todaySources.length ? todaySources.map(([k, v]) => row(sourceLabel(k), fmt(v))).join("") : '<p class="detail">No visits today.</p>') + '</div>' +
            '<div class="card"><div class="kicker">Limited reads</div><h2>' + fmt(data.scans?.limitedReads) + ' total</h2>' + (limitedKinds.length ? limitedKinds.map(([k, v]) => row(k, fmt(v))).join("") : '<p class="detail">No limited-read buckets recorded.</p>') + '</div>' +
            '<div class="card"><div class="kicker">Failure classes</div><h2>' + fmt(failureClasses.reduce((s, e) => s + e[1], 0)) + ' classified</h2>' + (failureClasses.length ? failureClasses.map(([k, v]) => row(k, fmt(v))).join("") : '<p class="detail">No classified failures recorded.</p>') + '</div>' +
          '</div>' +
          '<div class="card" style="margin-top:22px"><div class="kicker">Repeat scan targets</div><h2>Concentration check</h2>' +
            (repeatTargets.length ? repeatTargets.map((item) => row(item.target, fmt(item.count))).join("") : '<p class="detail">No target concentration data yet.</p>') +
          '</div>' +
          '<div class="card" style="margin-top:22px"><div class="kicker">Recent failures</div><h2>What needs explaining</h2>' +
            (recentFailures.length ? recentFailures.map(event).join("") : '<p class="detail">No recent failure details recorded yet. New failures will include target, class, and a sanitized reason.</p>') +
          '</div>';
      } catch (err) {
        content.innerHTML = '<div class="card" style="margin-top:24px"><div class="kicker bad">Error</div><pre>' + (err?.message || String(err)) + '</pre></div>';
      } finally {
        button.disabled = false;
      }
    }
    document.getElementById("refresh").addEventListener("click", load);
    load();
  </script>
</body>
</html>`;

const server = http.createServer(async (request, response) => {
  const requestUrl = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

  if (requestUrl.pathname === "/" || requestUrl.pathname === "/telemetry") {
    send(response, 200, html, { "Content-Type": "text/html; charset=utf-8" });
    return;
  }

  if (requestUrl.pathname === "/api/telemetry") {
    try {
      const telemetryResponse = await fetch(`${baseUrl}/api/telemetry`, {
        headers: { Authorization: `Bearer ${telemetryToken}` },
      });
      const body = await telemetryResponse.text();
      send(response, telemetryResponse.status, body, { "Content-Type": "application/json; charset=utf-8" });
    } catch (error) {
      send(response, 502, JSON.stringify({ error: error instanceof Error ? error.message : "Telemetry request failed." }), {
        "Content-Type": "application/json; charset=utf-8",
      });
    }
    return;
  }

  send(response, 404, "Not found", { "Content-Type": "text/plain; charset=utf-8" });
});

server.on("error", (error) => {
  if (error?.code === "EADDRINUSE") {
    console.error(`Port ${port} is already in use. Stop the existing dashboard, or run PORT=8791 npm run telemetry:web`);
    process.exit(1);
  }

  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

server.listen(port, "127.0.0.1", () => {
  const url = `http://127.0.0.1:${port}/`;
  console.log(`SecURL telemetry dashboard: ${url}`);
  console.log("Press Ctrl+C to stop.");
});
