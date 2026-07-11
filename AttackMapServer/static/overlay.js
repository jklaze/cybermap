// Dashboard overlay: Preact + htm + signals via CDN (no build step).
// Subscribes to the "attack" / "ws-status" CustomEvents dispatched by map.js.

import { h, render } from "https://esm.sh/preact@10.24.3";
import { useState } from "https://esm.sh/preact@10.24.3/hooks";
import { signal } from "https://esm.sh/@preact/signals@1.3.0?deps=preact@10.24.3";
import htm from "https://esm.sh/htm@3.1.1";

const html = htm.bind(h);

const FEED_LIMIT = 50;
const RANK_LIMIT = 8;

// map.js mirrors the socket state on window.wsState, so a connection that
// opened before this module finished loading is still seen here.
const connected = signal(window.wsState === "open");
const stats = signal({ events: 0, ips: 0, countries: 0 });
const feed = signal([]);
const countries = signal([]);
const sources = signal([]);

// The full services legend comes from the server's SERVICE_RGB map (injected
// via the index.html template) rather than being inferred from seen events.
const services = signal(
    Object.entries(window.SERVICE_RGB || {}).map(([name, color]) => ({ name, color }))
);

let eventSeq = 0;

// Rankings arrive pre-sorted from the server's throttled Stats message;
// the client only clips to RANK_LIMIT and derives the bar widths.
function rank(rows) {
    const entries = (rows || []).slice(0, RANK_LIMIT);
    const max = entries.length ? entries[0].count : 1;
    return entries.map((row) => ({ ...row, share: row.count / max }));
}

window.addEventListener("ws-status", (e) => {
    connected.value = e.detail === "open";
});

function applyStats(msg) {
    stats.value = {
        events: msg.event_count || 0,
        ips: msg.unique_ips || 0,
        countries: msg.unique_countries || 0,
    };
    countries.value = rank(msg.top_countries);
    sources.value = rank(msg.top_sources);
}

window.addEventListener("stats", (e) => applyStats(e.detail));

// map.js mirrors the latest Stats snapshot, so a message that arrived before
// this module finished loading still seeds the panels.
if (window.lastStats) {
    applyStats(window.lastStats);
}

window.addEventListener("attack", (e) => {
    const msg = e.detail;

    feed.value = [
        {
            key: ++eventSeq,
            time: (msg.event_time || "").split(" ")[1] || msg.event_time,
            ip: msg.src_ip,
            code: msg.iso_code,
            country: msg.country,
            city: msg.city,
            protocol: msg.protocol || "OTHER",
            color: msg.color || "#888888",
        },
        ...feed.value,
    ].slice(0, FEED_LIMIT);
});

function Flag({ code }) {
    const [broken, setBroken] = useState(false);
    if (!code || broken) {
        return html`<span class="flag flag-missing">${code || "?"}</span>`;
    }
    return html`<img
        class="flag"
        src="/flags/${code}.png"
        alt=${code}
        loading="lazy"
        onError=${() => setBroken(true)}
    />`;
}

// Tag tinting lives in index.css (with a fallback for browsers without
// color-mix support); the service color only travels as a custom property.
function tagStyle(color) {
    return { "--tag-color": color };
}

function Stat({ label, value }) {
    return html`<div class="panel stat">
        <span class="stat-label">${label}</span>
        <span class="stat-value">${value.toLocaleString()}</span>
    </div>`;
}

function StatsBar() {
    return html`<header class="hud-top">
        <div class="panel brand ${connected.value ? "" : "off"}">
            <span class="status-dot ${connected.value ? "on" : "off"}"></span>
            <span class="brand-name">cybermap</span>
            <span class="brand-state">${connected.value ? "live" : "offline"}</span>
        </div>
        <${Stat} label="events" value=${stats.value.events} />
        <${Stat} label="unique ips" value=${stats.value.ips} />
        <${Stat} label="countries" value=${stats.value.countries} />
    </header>`;
}

function LiveFeed() {
    return html`<section class="panel feed">
        <h2 class="panel-title">live attacks</h2>
        <ul class="feed-list">
            ${feed.value.map(
                (row) => html`<li class="feed-row" key=${row.key}>
                    <span class="feed-time">${row.time}</span>
                    <${Flag} code=${row.code} />
                    <span class="feed-ip" title="${row.city ? row.city + ", " : ""}${row.country || ""}">${row.ip}</span>
                    <span class="tag" style=${tagStyle(row.color)}>${row.protocol}</span>
                </li>`
            )}
            ${feed.value.length === 0 &&
            html`<li class="feed-empty">waiting for events…</li>`}
        </ul>
    </section>`;
}

function RankPanel({ title, rows, mono }) {
    return html`<section class="panel rank">
        <h2 class="panel-title">${title}</h2>
        <ul class="rank-list">
            ${rows.map(
                (row) => html`<li key=${row.label}>
                    <div class="rank-row ${mono ? "mono" : ""}">
                        <${Flag} code=${row.code} />
                        <span class="rank-label">${row.label}</span>
                        <span class="rank-count">${row.count.toLocaleString()}</span>
                    </div>
                    <div class="bar"><div class="bar-fill" style=${{ width: `${Math.round(row.share * 100)}%` }}></div></div>
                </li>`
            )}
            ${rows.length === 0 && html`<li class="feed-empty">no data yet</li>`}
        </ul>
    </section>`;
}

function Legend() {
    return html`<section class="panel legend">
        <h2 class="panel-title">services</h2>
        <div class="legend-chips">
            ${services.value.map(
                (s) => html`<span class="legend-chip" key=${s.name}>
                    <span class="legend-dot" style=${{ background: s.color }}></span>${s.name}
                </span>`
            )}
            ${services.value.length === 0 && html`<span class="feed-empty">none seen yet</span>`}
        </div>
    </section>`;
}

function App() {
    return html`
        <${StatsBar} />
        <${LiveFeed} />
        <aside class="rail">
            <${RankPanel} title="top countries" rows=${countries.value} />
            <${RankPanel} title="top sources" rows=${sources.value} mono=${true} />
            <${Legend} />
        </aside>
    `;
}

render(html`<${App} />`, document.getElementById("overlay"));
