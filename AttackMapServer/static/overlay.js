// Dashboard overlay: Preact + htm + signals via CDN (no build step).
// Subscribes to the "attack" / "ws-status" CustomEvents dispatched by map.js.

import { h, render } from "https://esm.sh/preact@10.24.3";
import { useLayoutEffect, useRef, useState } from "https://esm.sh/preact@10.24.3/hooks";
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
const scans = signal({ recent: [], count: 0, ips: new Set() });
const scansOpen = signal(false);
// Hovered/focused label: { info, el }. One tooltip lives at the overlay root
// because panels use backdrop-filter, which would trap a fixed-position child.
const tip = signal(null);
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

// Port-scan probes are most of the traffic and would bury real attacks, so
// they skip the feed and roll up into a one-line, expandable scans bar at the
// top of the panel. The map still draws every scan.
const SCAN_PROTOCOL = "SCAN";

window.addEventListener("attack", (e) => {
    const msg = e.detail;
    const row = {
        key: ++eventSeq,
        time: (msg.event_time || "").split(" ")[1] || msg.event_time,
        ip: msg.src_ip,
        code: msg.iso_code,
        country: msg.country,
        city: msg.city,
        protocol: msg.protocol || "OTHER",
        color: msg.color || "#888888",
        // tooltip: built server-side from parsed fields only, never raw log lines
        summary: msg.summary,
        port: msg.dst_port,
        service: msg.service,
        evidence: msg.evidence,
    };

    if (row.protocol === SCAN_PROTOCOL) {
        const { recent, count, ips } = scans.value;
        ips.add(row.ip);
        scans.value = { recent: [row, ...recent].slice(0, FEED_LIMIT), count: count + 1, ips };
        return;
    }
    feed.value = [row, ...feed.value].slice(0, FEED_LIMIT);
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

// A service label that explains itself on hover, keyboard focus, or tap.
// `hoverOnly` is for labels inside another control (the scans bar button),
// where focus and clicks belong to that control.
function Tag({ info, hoverOnly = false }) {
    const show = (e) => (tip.value = { info, el: e.currentTarget });
    const hide = () => (tip.value = null);
    return html`<span
        class="tag tag-tip"
        tabindex=${hoverOnly ? undefined : "0"}
        style=${tagStyle(info.color)}
        onMouseEnter=${show}
        onMouseLeave=${hide}
        onFocus=${hoverOnly ? undefined : show}
        onBlur=${hoverOnly ? undefined : hide}
        onClick=${hoverOnly ? undefined : (e) => (tip.value?.info === info ? hide() : show(e))}
    >${info.label || info.protocol}</span>`;
}

const GAP = 10;
const EDGE = 8;

function Tooltip() {
    const ref = useRef(null);
    const current = tip.value;
    // Re-render (and re-measure) when the lists change: a new attack shifts
    // the hovered row down, and a row can drop off the end of the list.
    feed.value;
    scans.value;

    // Place beside the label (the feed sits bottom-left, so the right side is
    // usually free); fall back to above/below on narrow screens. Measured after
    // render so the real size is used, then clamped into the viewport.
    useLayoutEffect(() => {
        const el = ref.current;
        if (!el || !current) return;
        if (!current.el.isConnected) {
            tip.value = null; // label scrolled off the list while hovered
            return;
        }
        const rect = current.el.getBoundingClientRect();
        const w = el.offsetWidth;
        const hgt = el.offsetHeight;
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        let left;
        let top;
        if (vw - rect.right >= w + GAP + EDGE) {
            left = rect.right + GAP;
            top = rect.top + rect.height / 2 - hgt / 2;
        } else {
            left = rect.right - w;
            top = rect.top - hgt - GAP >= EDGE ? rect.top - hgt - GAP : rect.bottom + GAP;
        }
        el.style.left = `${Math.max(EDGE, Math.min(left, vw - w - EDGE))}px`;
        el.style.top = `${Math.max(EDGE, Math.min(top, vh - hgt - EDGE))}px`;
        el.style.visibility = "visible";
    });

    if (!current) return null;
    const { info } = current;
    const port =
        info.port && info.port !== "0" ? `port ${info.port} · ${info.service || "no known service"}` : info.service;
    return html`<div class="tooltip" ref=${ref} role="tooltip" style=${{ visibility: "hidden" }}>
        <div class="tooltip-head">
            <span class="tag" style=${tagStyle(info.color)}>${info.label || info.protocol}</span>
            ${port && html`<span class="tooltip-port">${port}</span>`}
        </div>
        <p class="tooltip-summary">${info.summary || "No details recorded for this event."}</p>
        ${info.evidence && html`<code class="tooltip-evidence">${info.evidence}</code>`}
    </div>`;
}

function FeedRow({ row }) {
    return html`<li class="feed-row">
        <span class="feed-time">${row.time}</span>
        <${Flag} code=${row.code} />
        <span class="feed-ip" title="${row.city ? row.city + ", " : ""}${row.country || ""}">${row.ip}</span>
        <${Tag} info=${row} />
    </li>`;
}

const SCAN_INFO = {
    protocol: SCAN_PROTOCOL,
    summary:
        "Port scans: probes to ports with no service behind them, blocked by the firewall. " +
        "Expand to see the latest ones; hover a scan's label for its log line.",
};

function ScanBar() {
    const { recent, count, ips } = scans.value;
    const latest = recent[0];
    const open = scansOpen.value && count > 0;
    const color = (window.SERVICE_RGB || {})[SCAN_PROTOCOL] || "#888888";
    return html`<div class="scans ${open ? "open" : ""}">
        <button
            class="scan-bar"
            type="button"
            disabled=${count === 0}
            aria-expanded=${open}
            onClick=${() => (scansOpen.value = !scansOpen.value)}
        >
            <span class="scan-chevron">${open ? "▾" : "▸"}</span>
            <${Tag} info=${{ ...SCAN_INFO, color }} hoverOnly=${true} />
            <span class="scan-summary">
                ${count === 0
                    ? "no port scans yet"
                    : `${count.toLocaleString()} probes · ${ips.size.toLocaleString()} ${ips.size === 1 ? "ip" : "ips"}`}
            </span>
            ${latest && html`<span class="feed-time">${latest.time}</span>`}
        </button>
        ${open &&
        html`<ul class="feed-list scan-list">
            ${recent.map((row) => html`<${FeedRow} key=${row.key} row=${row} />`)}
        </ul>`}
    </div>`;
}

function LiveFeed() {
    return html`<section class="panel feed">
        <h2 class="panel-title">live attacks</h2>
        <${ScanBar} />
        <ul class="feed-list">
            ${feed.value.map((row) => html`<${FeedRow} key=${row.key} row=${row} />`)}
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
        <${Tooltip} />
    `;
}

render(html`<${App} />`, document.getElementById("overlay"));
