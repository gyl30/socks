#include "trace_web_dashboard_page.h"

namespace relay
{

std::string build_trace_dashboard_page_body()
{
    return R"HTML(<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Trace Dashboard</title>
  <style>
    :root {
      --bg: #f3efe6;
      --surface: rgba(255, 252, 246, 0.9);
      --surface-strong: #fffaf0;
      --line: rgba(40, 34, 20, 0.14);
      --text: #261d14;
      --muted: #6b5a48;
      --accent: #bb5a2a;
      --accent-soft: rgba(187, 90, 42, 0.12);
      --ok: #1f7a45;
      --fail: #a63d40;
      --running: #22577a;
      --timeout: #8b5e34;
      --shadow: 0 24px 60px rgba(38, 29, 20, 0.12);
      --mono: "Iosevka", "SFMono-Regular", "Consolas", monospace;
      --sans: "IBM Plex Sans", "Segoe UI", sans-serif;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(187, 90, 42, 0.18), transparent 28%),
        radial-gradient(circle at top right, rgba(34, 87, 122, 0.16), transparent 24%),
        linear-gradient(180deg, #f7f1e7 0%, #f1eadf 42%, #ebe4d8 100%);
      min-height: 100vh;
    }

    .shell {
      width: min(1500px, calc(100vw - 32px));
      margin: 20px auto 40px;
    }

    .hero {
      background: linear-gradient(135deg, rgba(255, 250, 240, 0.96), rgba(249, 238, 219, 0.94));
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
      padding: 20px 22px;
      position: relative;
      overflow: hidden;
    }

    .hero::after {
      content: "";
      position: absolute;
      inset: auto -40px -40px auto;
      width: 220px;
      height: 220px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(187, 90, 42, 0.18), transparent 70%);
    }

    .eyebrow {
      font-size: 12px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 10px;
    }

    h1 {
      margin: 0;
      font-size: clamp(34px, 5vw, 56px);
      line-height: 0.96;
      letter-spacing: -0.05em;
    }

    .traffic-chart-shell {
      border: 1px solid rgba(40, 34, 20, 0.09);
      border-radius: 22px;
      background: rgba(255,255,255,0.5);
      padding: 12px 14px 8px;
      min-height: 278px;
      display: flex;
      align-items: stretch;
    }

    .traffic-chart {
      width: 100%;
      height: 260px;
      display: block;
      overflow: visible;
    }

    .chart-grid-line {
      stroke: rgba(40, 34, 20, 0.16);
      stroke-dasharray: 4 6;
      stroke-width: 1;
    }

    .chart-axis-label {
      fill: var(--muted);
      font-size: 12px;
      font-family: var(--mono);
    }

    .chart-axis-line {
      stroke: rgba(40, 34, 20, 0.22);
      stroke-width: 1;
    }

    .chart-line-rx {
      fill: none;
      stroke: var(--running);
      stroke-width: 3;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .chart-line-tx {
      fill: none;
      stroke: var(--accent);
      stroke-width: 3;
      stroke-linecap: round;
      stroke-linejoin: round;
    }

    .chart-dot-rx {
      fill: var(--running);
    }

    .chart-dot-tx {
      fill: var(--accent);
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 18px;
      margin-top: 18px;
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
      padding: 20px;
      backdrop-filter: blur(14px);
      min-width: 0;
    }

    .card h2, .card h3 {
      margin: 0 0 14px;
      font-size: 15px;
      letter-spacing: 0.02em;
    }

    .span-12 { grid-column: span 12; }
    .span-8 { grid-column: span 8; }
    .span-7 { grid-column: span 7; }
    .span-6 { grid-column: span 6; }
    .span-5 { grid-column: span 5; }
    .span-4 { grid-column: span 4; }

    .stats {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 12px;
    }

    .stat-box {
      border: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(255,255,255,0.72), rgba(255,255,255,0.46));
      border-radius: 18px;
      padding: 14px;
      min-height: 92px;
    }

    .stat-label {
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }

    .stat-value {
      margin-top: 10px;
      font-size: 30px;
      line-height: 1;
      letter-spacing: -0.05em;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    th, td {
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid rgba(40, 34, 20, 0.09);
      vertical-align: top;
    }

    th {
      color: var(--muted);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }

    tbody tr {
      transition: background 120ms ease;
    }

    tbody tr.is-active {
      background: rgba(34, 87, 122, 0.1);
    }

    .status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }

    .status-running { background: rgba(34, 87, 122, 0.12); color: var(--running); }
    .status-success { background: rgba(31, 122, 69, 0.12); color: var(--ok); }
    .status-failed { background: rgba(166, 61, 64, 0.12); color: var(--fail); }
    .status-timeout { background: rgba(139, 94, 52, 0.12); color: var(--timeout); }

    .mono {
      font-family: var(--mono);
      word-break: break-all;
    }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 10px;
    }

    .summary-item {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255,255,255,0.68);
      padding: 12px;
    }

    .summary-item .k {
      display: block;
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 6px;
    }

    .summary-item .v {
      font-family: var(--mono);
      font-size: 13px;
      line-height: 1.5;
    }

    .timeline {
      display: flex;
      flex-direction: column;
      gap: 10px;
      max-height: 760px;
      overflow: auto;
      padding-right: 4px;
    }

    .timeline-item {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255,255,255,0.74);
      padding: 12px;
    }

    .timeline-head {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: baseline;
      flex-wrap: wrap;
      margin-bottom: 8px;
    }

    .timeline-stage {
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .timeline-meta {
      color: var(--muted);
      font-size: 11px;
      font-family: var(--mono);
    }

    .timeline-body {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
      font-size: 12px;
    }

    .field {
      min-width: 0;
    }

    .field .k {
      display: block;
      color: var(--muted);
      margin-bottom: 4px;
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.08em;
    }

    .field .v {
      font-family: var(--mono);
      line-height: 1.45;
      word-break: break-word;
    }

    .toolbar {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }

    .toolbar small {
      color: var(--muted);
    }

    .filter-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }

    .query-panel {
      border: 1px solid var(--line);
      border-radius: 20px;
      background: rgba(255,255,255,0.56);
      padding: 16px;
    }

    .control-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 10px;
    }

    .control {
      display: flex;
      flex-direction: column;
      gap: 4px;
      min-width: 0;
    }

    .control span {
      color: var(--muted);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .control input,
    .control select {
      width: 100%;
      min-width: 0;
      border: 1px solid rgba(40, 34, 20, 0.14);
      border-radius: 10px;
      background: rgba(255,255,255,0.86);
      color: var(--text);
      padding: 8px 10px;
      font: inherit;
    }

    .control input::placeholder {
      color: rgba(107, 90, 72, 0.72);
    }

    .query-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 10px;
    }

    .button {
      border: 0;
      border-radius: 999px;
      background: var(--accent);
      color: white;
      padding: 8px 12px;
      font: inherit;
      cursor: pointer;
      box-shadow: 0 10px 20px rgba(187, 90, 42, 0.22);
    }

    .button-secondary {
      background: rgba(38, 29, 20, 0.08);
      color: var(--text);
      box-shadow: none;
      border: 1px solid var(--line);
    }

    .trace-table-wrap {
      border: 1px solid rgba(40, 34, 20, 0.09);
      border-radius: 18px;
      background: rgba(255,255,255,0.42);
      overflow: auto;
      max-height: 760px;
    }

    .trace-table-wrap table {
      min-width: 760px;
    }

    .trace-row-toggle {
      padding: 7px 12px;
      font-size: 12px;
      box-shadow: none;
      white-space: nowrap;
    }

    .trace-target {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .trace-target-real {
      color: var(--muted);
      font-size: 11px;
    }

    body.modal-open {
      overflow: hidden;
    }

    .trace-modal {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 20px;
      z-index: 60;
    }

    .trace-modal.is-open {
      display: flex;
    }

    .trace-modal-backdrop {
      position: absolute;
      inset: 0;
      background: rgba(38, 29, 20, 0.38);
      backdrop-filter: blur(6px);
    }

    .trace-modal-dialog {
      position: relative;
      width: min(1180px, calc(100vw - 32px));
      max-height: calc(100vh - 32px);
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 24px;
      background: rgba(255, 250, 240, 0.96);
      box-shadow: var(--shadow);
      padding: 20px;
    }

    .trace-modal-actions {
      display: inline-flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .trace-modal-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }

    .trace-modal-head h3 {
      margin-bottom: 0;
    }

    .trace-modal-meta {
      color: var(--muted);
      font-size: 12px;
      font-family: var(--mono);
    }

    .detail-stack {
      display: flex;
      flex-direction: column;
      gap: 14px;
      min-width: 0;
    }

    .detail-block {
      min-width: 0;
    }

    .trace-summary {
      max-height: 210px;
      overflow: auto;
      padding-right: 4px;
    }

    .trace-summary.summary-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }

    .trace-modal-dialog .summary-item {
      display: grid;
      grid-template-columns: 76px minmax(0, 1fr);
      gap: 8px;
      align-items: start;
      padding: 10px 12px;
    }

    .trace-modal-dialog .summary-item .k {
      margin-bottom: 0;
      padding-top: 2px;
      font-size: 10px;
      line-height: 1.2;
    }

    .trace-modal-dialog .summary-item .v {
      font-size: 12px;
      line-height: 1.35;
    }

    .detail-block-timeline {
      display: flex;
      flex-direction: column;
      min-width: 0;
      min-height: 0;
    }

    .detail-block-timeline > .toolbar {
      flex-shrink: 0;
      margin-bottom: 8px;
    }

    .trace-timeline {
      min-height: 240px;
      max-height: 420px;
    }

    .top-card {
      margin-bottom: 18px;
    }

    .empty {
      color: var(--muted);
      font-size: 13px;
      padding: 18px 0;
    }

    @media (max-width: 1100px) {
      .span-8, .span-7, .span-6, .span-5, .span-4 {
        grid-column: span 12;
      }

      .traffic-chart-shell {
        min-height: 250px;
      }

      .traffic-chart {
        height: 224px;
      }

      .stats {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .timeline-body {
        grid-template-columns: 1fr;
      }

      .trace-summary {
        max-height: none;
        overflow: visible;
        padding-right: 0;
      }

      .trace-modal-dialog .summary-grid {
        grid-template-columns: 1fr;
      }

      .trace-timeline {
        min-height: 300px;
      }

      .trace-modal {
        padding: 12px;
      }

      .trace-modal-dialog {
        width: min(100vw - 24px, 100%);
        max-height: calc(100vh - 24px);
        padding: 16px;
      }
    }

    @media (max-width: 640px) {
      .shell {
        width: min(100vw - 16px, 100%);
        margin-top: 12px;
      }

      .hero,
      .card {
        border-radius: 20px;
        padding: 16px;
      }

      .stats {
        grid-template-columns: 1fr;
      }

      th:nth-child(4),
      td:nth-child(4),
      th:nth-child(5),
      td:nth-child(5) {
        display: none;
      }
    }
  </style>
</head>
<body id="trace-dashboard">
  <div class="shell">
    <section class="card top-card">
      <h2>运行状态</h2>
      <div class="stats" id="stats-grid"></div>
    </section>

    <section class="hero">
      <div class="traffic-chart-shell">
        <svg id="traffic-chart" class="traffic-chart" viewBox="0 0 760 260" preserveAspectRatio="none" aria-label="实时流量折线图"></svg>
      </div>
    </section>

    <div class="grid">
      <section class="card span-12">
        <div class="toolbar">
          <h2>筛选与搜索</h2>
        </div>
        <div class="filter-grid">
          <form class="query-panel" id="trace-query-form">
            <div class="control-grid">
              <label class="control">
                <span>status</span>
                <select name="status">
                  <option value="">全部</option>
                  <option value="running">running</option>
                  <option value="success">success</option>
                  <option value="failed">failed</option>
                  <option value="timeout">timeout</option>
                </select>
              </label>
              <label class="control">
                <span>target_host</span>
                <input name="target_host" type="text" placeholder="精确匹配目标 host">
              </label>
              <label class="control">
                <span>inbound_tag</span>
                <input name="inbound_tag" type="text" placeholder="例如 socks-in">
              </label>
              <label class="control">
                <span>outbound_tag</span>
                <input name="outbound_tag" type="text" placeholder="例如 direct">
              </label>
              <label class="control">
                <span>route_type</span>
                <input name="route_type" type="text" placeholder="例如 direct">
              </label>
              <label class="control">
                <span>match_type</span>
                <input name="match_type" type="text" placeholder="例如 inbound">
              </label>
              <label class="control">
                <span>limit</span>
                <select name="limit">
                  <option value="12">12</option>
                  <option value="24" selected>24</option>
                  <option value="50">50</option>
                  <option value="100">100</option>
                </select>
              </label>
            </div>
            <div class="query-actions">
              <button class="button" type="submit">应用链路筛选</button>
              <button class="button button-secondary" data-reset-target="traces" type="button">重置</button>
            </div>
          </form>
        </div>
      </section>

      <section class="card span-12">
        <div class="toolbar">
          <h2>最近链路</h2>
          <small id="trace-list-meta"></small>
        </div>
        <div class="trace-table-wrap">
          <table>
            <thead>
              <tr>
                <th>trace</th>
                <th>status</th>
                <th>inbound</th>
                <th>target</th>
                <th>route</th>
                <th>bytes</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="trace-table"></tbody>
          </table>
        </div>
      </section>

    </div>
  </div>

  <div class="trace-modal" id="trace-modal" aria-hidden="true">
    <div class="trace-modal-backdrop" data-modal-close="true"></div>
    <div class="trace-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="trace-modal-title">
      <div class="trace-modal-head">
        <div>
          <h3 id="trace-modal-title">链路详情</h3>
          <small class="trace-modal-meta" id="trace-modal-meta">未选择链路</small>
        </div>
        <div class="trace-modal-actions">
          <button class="button button-secondary" data-modal-close="true" type="button">关闭</button>
        </div>
      </div>
      <div class="detail-stack">
        <section class="detail-block">
          <div class="toolbar">
            <h3>摘要</h3>
          </div>
          <div id="trace-summary" class="summary-grid trace-summary"></div>
        </section>
        <section class="detail-block detail-block-timeline">
          <div class="toolbar">
            <h3>链路时间线</h3>
            <small id="timeline-meta"></small>
          </div>
          <div class="timeline trace-timeline" id="trace-timeline"></div>
        </section>
      </div>
    </div>
  </div>

  <script>
    const refreshIntervalMs = 3000;
    const trafficWindowMinutes = 30;
    const trafficWindowMs = trafficWindowMinutes * 60 * 1000;

    const traceQueryDefaults = {
      status: "",
      target_host: "",
      inbound_tag: "",
      outbound_tag: "",
      route_type: "",
      match_type: "",
      limit: "24",
    };

    const state = {
      selectedTraceId: "",
      refreshTimer: 0,
      tracesQuery: Object.assign({}, traceQueryDefaults),
      tracesPage: null,
    };

    function numberText(value) {
      return new Intl.NumberFormat("zh-CN").format(Number(value || 0));
    }

    function formatBytes(value) {
      let number = Number(value || 0);
      const units = ["B", "KB", "MB", "GB", "TB"];
      let unitIndex = 0;
      while (number >= 1024 && unitIndex < units.length - 1) {
        number /= 1024;
        unitIndex += 1;
      }
      const digits = number >= 100 || unitIndex === 0 ? 0 : (number >= 10 ? 1 : 2);
      const text = number.toFixed(digits).replace(/\.0+$/, "").replace(/(\.\d*[1-9])0+$/, "$1");
      return text + " " + units[unitIndex];
    }

    function formatRate(value) {
      return formatBytes(value) + "/s";
    }

    function formatDurationAgo(ms) {
      const value = Math.max(0, Number(ms || 0));
      if (value < 1000) {
        return "刚刚";
      }
      if (value < 60 * 1000) {
        return Math.round(value / 1000) + " 秒前";
      }
      return Math.round(value / (60 * 1000)) + " 分钟前";
    }

    function formatStatus(status) {
      const text = String(status || "running");
      return text;
    }

    function statusClass(status) {
      return "status status-" + String(status || "running");
    }

    function formatDateTime(value) {
      const number = Number(value || 0);
      return number ? new Date(number).toLocaleString("zh-CN") : "-";
    }

    function formatEndpoint(host, port) {
      return String(host || "-") + ":" + Number(port || 0);
    }

    function formatResolvedTarget(item) {
      return item && item.resolved_target_host ? formatEndpoint(item.resolved_target_host, item.resolved_target_port) : "-";
    }

    function renderTargetCell(item, size) {
      const targetText = formatEndpoint(item && item.target_host, item && item.target_port);
      const resolvedText = formatResolvedTarget(item);
      if (resolvedText === "-" || resolvedText === targetText) {
        return '<div class="trace-target"><div>' + ellipsis(targetText, size) + "</div></div>";
      }
      return '<div class="trace-target"><div>' + ellipsis(targetText, size) + '</div><div class="trace-target-real">real ' +
        ellipsis(resolvedText, size) + "</div></div>";
    }

    function ellipsis(value, size) {
      const text = String(value || "");
      if (text.length <= size) {
        return text;
      }
      return text.slice(0, size - 1) + "…";
    }

    function emptyNode(message) {
      const node = document.createElement("div");
      node.className = "empty";
      node.textContent = message;
      return node;
    }

    function cleanValue(value) {
      return String(value == null ? "" : value).trim();
    }

    function queryText(params) {
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(params || {})) {
        const text = cleanValue(value);
        if (!text) {
          continue;
        }
        query.set(key, text);
      }
      return query.toString();
    }

    function queryPath(path, params) {
      const text = queryText(params);
      return text ? path + "?" + text : path;
    }

    function describeQuery(params, fallback) {
      const text = queryText(params);
      return text ? text : fallback;
    }

    function readFormState(formId) {
      const form = document.getElementById(formId);
      const next = {};
      const formData = new FormData(form);
      for (const [key, value] of formData.entries()) {
        next[key] = cleanValue(value);
      }
      return next;
    }

    function setTraceModalOpen(open) {
      const modal = document.getElementById("trace-modal");
      modal.classList.toggle("is-open", open);
      modal.setAttribute("aria-hidden", open ? "false" : "true");
      document.body.classList.toggle("modal-open", open);
    }

    function clearTraceDetailView(message) {
      document.getElementById("trace-modal-title").textContent = "链路详情";
      document.getElementById("trace-modal-meta").textContent = message || "未选择链路";
      renderTraceSummary(null);
      renderEventTimeline("trace-timeline", [], "未选择链路");
      document.getElementById("timeline-meta").textContent = "";
    }

    function renderTraceLoading(traceId) {
      document.getElementById("trace-modal-title").textContent = "链路详情";
      document.getElementById("trace-modal-meta").textContent = "trace " + traceId + " · 加载中";
      document.getElementById("trace-summary").replaceChildren(emptyNode("加载中"));
      renderEventTimeline("trace-timeline", [], "加载中");
      document.getElementById("timeline-meta").textContent = "";
    }

    function closeTraceModal() {
      state.selectedTraceId = "";
      setTraceModalOpen(false);
      clearTraceDetailView();
      if (state.tracesPage) {
        renderTraceList(state.tracesPage);
      }
    }

    function chartX(sampleTs, windowStart, chartLayout) {
      const spanMs = Math.max(1, chartLayout.windowMs || 1);
      const clamped = Math.min(Math.max(sampleTs - windowStart, 0), spanMs);
      return chartLayout.left + (chartLayout.plotWidth * clamped) / spanMs;
    }

    function chartPath(samples, accessor, maxValue, windowStart, chartLayout) {
      return samples
        .map((sample, index) => {
          const x = chartX(Number(sample.ts || 0), windowStart, chartLayout);
          const y = chartLayout.top + chartLayout.plotHeight - (chartLayout.plotHeight * accessor(sample)) / maxValue;
          return (index === 0 ? "M " : "L ") + x.toFixed(2) + " " + y.toFixed(2);
        })
        .join(" ");
    }

    function chartPoint(samples, accessor, maxValue, windowStart, chartLayout) {
      const last = samples[samples.length - 1];
      const x = chartX(Number(last.ts || 0), windowStart, chartLayout);
      const y = chartLayout.top + chartLayout.plotHeight - (chartLayout.plotHeight * accessor(last)) / maxValue;
      return { x, y };
    }

    function normalizeTrafficSamples(samples) {
      const ordered = Array.isArray(samples) ? samples.slice().sort((lhs, rhs) => Number(lhs.ts_unix_ms || 0) - Number(rhs.ts_unix_ms || 0)) : [];
      const normalized = [];
      let previous = null;
      for (const sample of ordered) {
        const ts = Number(sample.ts_unix_ms || 0);
        const totalTxBytes = Number(sample.total_tx_bytes || 0);
        const totalRxBytes = Number(sample.total_rx_bytes || 0);
        let txRate = 0;
        let rxRate = 0;
        if (previous && totalTxBytes >= previous.totalTxBytes && totalRxBytes >= previous.totalRxBytes && ts > previous.ts) {
          const elapsedSeconds = Math.max((ts - previous.ts) / 1000, 0.5);
          txRate = (totalTxBytes - previous.totalTxBytes) / elapsedSeconds;
          rxRate = (totalRxBytes - previous.totalRxBytes) / elapsedSeconds;
        }
        normalized.push({ ts, totalTxBytes, totalRxBytes, txRate, rxRate });
        previous = { ts, totalTxBytes, totalRxBytes };
      }
      return normalized;
    }

    function trimTrafficSamples(samples) {
      if (!samples.length) {
        return { samples: [], windowMs: trafficWindowMs };
      }
      const lastTs = Number(samples[samples.length - 1].ts || 0);
      const cutoff = Math.max(0, lastTs - trafficWindowMs);
      const trimmed = samples.filter((sample) => Number(sample.ts || 0) >= cutoff);
      if (!trimmed.length) {
        return { samples: [samples[samples.length - 1]], windowMs: trafficWindowMs };
      }
      const firstTs = Number(trimmed[0].ts || lastTs);
      const actualWindowMs = Math.max(lastTs - firstTs, 0);
      return {
        samples: trimmed,
        windowMs: Math.min(Math.max(actualWindowMs, 1), trafficWindowMs),
      };
    }

    function renderTrafficChart(history) {
      const chart = document.getElementById("traffic-chart");
      const normalizedSamples = normalizeTrafficSamples(history);
      const trimmed = trimTrafficSamples(normalizedSamples);
      const samples = trimmed.samples;
      if (!samples.length) {
        chart.innerHTML = "";
        return;
      }

      const svgWidth = 760;
      const svgHeight = 260;
      const left = 82;
      const right = 18;
      const top = 18;
      const bottom = 28;
      const plotWidth = svgWidth - left - right;
      const plotHeight = svgHeight - top - bottom;
      const windowMs = trimmed.windowMs;
      const windowStart = Number(samples[samples.length - 1].ts || 0) - windowMs;
      const chartLayout = { left, top, plotWidth, plotHeight, windowMs };
      const maxRate = Math.max(1, ...samples.map((sample) => Math.max(sample.txRate, sample.rxRate)));
      const xLabels = `
        <text class="chart-axis-label" x="${left}" y="${(svgHeight - 6).toFixed(2)}" text-anchor="start">${formatDurationAgo(windowMs)}</text>
        <text class="chart-axis-label" x="${(left + plotWidth / 2).toFixed(2)}" y="${(svgHeight - 6).toFixed(2)}" text-anchor="middle">${formatDurationAgo(windowMs / 2)}</text>
        <text class="chart-axis-label" x="${(svgWidth - right).toFixed(2)}" y="${(svgHeight - 6).toFixed(2)}" text-anchor="end">现在</text>
      `;
      const tickValues = [maxRate, maxRate * 0.5, 0];
      const grid = tickValues
        .map((value) => {
          const y = top + plotHeight - (plotHeight * value) / maxRate;
          return `
            <line class="chart-grid-line" x1="${left}" y1="${y.toFixed(2)}" x2="${svgWidth - right}" y2="${y.toFixed(2)}"></line>
            <text class="chart-axis-label" x="${left - 10}" y="${(y + 4).toFixed(2)}" text-anchor="end">${formatRate(value)}</text>
          `;
        })
        .join("");

      const rxPath = samples.length > 1 ? chartPath(samples, (sample) => sample.rxRate, maxRate, windowStart, chartLayout) : "";
      const txPath = samples.length > 1 ? chartPath(samples, (sample) => sample.txRate, maxRate, windowStart, chartLayout) : "";
      const rxDot = chartPoint(samples, (sample) => sample.rxRate, maxRate, windowStart, chartLayout);
      const txDot = chartPoint(samples, (sample) => sample.txRate, maxRate, windowStart, chartLayout);
      chart.innerHTML = `
        ${grid}
        <line class="chart-axis-line" x1="${left}" y1="${(svgHeight - bottom).toFixed(2)}" x2="${svgWidth - right}" y2="${(svgHeight - bottom).toFixed(2)}"></line>
        ${xLabels}
        ${rxPath ? `<path class="chart-line-rx" d="${rxPath}"></path>` : ""}
        ${txPath ? `<path class="chart-line-tx" d="${txPath}"></path>` : ""}
        <circle class="chart-dot-rx" cx="${rxDot.x.toFixed(2)}" cy="${rxDot.y.toFixed(2)}" r="4"></circle>
        <circle class="chart-dot-tx" cx="${txDot.x.toFixed(2)}" cy="${txDot.y.toFixed(2)}" r="4"></circle>
      `;
    }

    function renderStats(snapshot) {
      const stats = snapshot.stats || {};
      const grid = document.getElementById("stats-grid");
      grid.replaceChildren();
      const items = [
        ["total sessions", stats.total_sessions],
        ["running", stats.running_sessions],
        ["success", stats.success_sessions],
        ["failed", stats.failed_sessions],
        ["timeout", stats.timeout_sessions],
      ];
      for (const [label, value] of items) {
        const box = document.createElement("div");
        box.className = "stat-box";
        box.innerHTML = '<div class="stat-label"></div><div class="stat-value"></div>';
        box.querySelector(".stat-label").textContent = label;
        box.querySelector(".stat-value").textContent = numberText(value);
        grid.appendChild(box);
      }
      renderTrafficChart(snapshot.traffic_history || []);
    }

    function renderTraceList(page) {
      state.tracesPage = page;
      const tbody = document.getElementById("trace-table");
      tbody.replaceChildren();
      const items = page.items || [];
      if (!items.some((item) => item.trace_id === state.selectedTraceId)) {
        state.selectedTraceId = "";
        setTraceModalOpen(false);
        clearTraceDetailView();
      }
      document.getElementById("trace-list-meta").textContent =
        "count " + numberText(page.count || 0) + " · " + describeQuery(state.tracesQuery, "默认参数");
      if (!items.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 7;
        cell.appendChild(emptyNode("暂无链路"));
        row.appendChild(cell);
        tbody.appendChild(row);
        return;
      }

      for (const item of items) {
        const traceId = item.trace_id || "";
        const expanded = traceId && traceId === state.selectedTraceId;
        const row = document.createElement("tr");
        if (traceId && traceId === state.selectedTraceId) {
          row.classList.add("is-active");
        }
        row.innerHTML = `
          <td class="mono">${traceId || "-"}</td>
          <td><span class="${statusClass(item.status)}">${formatStatus(item.status)}</span></td>
          <td>${ellipsis(item.inbound_tag || item.inbound_type || "-", 20)}</td>
          <td class="mono">${renderTargetCell(item, 28)}</td>
          <td class="mono">${ellipsis(item.route_type || "-", 14)}</td>
          <td class="mono">${numberText(item.total_tx_bytes || 0)} / ${numberText(item.total_rx_bytes || 0)}</td>
          <td><button class="button button-secondary trace-row-toggle" data-trace-toggle="${traceId}" type="button">${expanded ? "收起" : "详情"}</button></td>
        `;
        row.querySelector("[data-trace-toggle]").addEventListener("click", (event) => {
          event.stopPropagation();
          if (!traceId) {
            return;
          }
          if (expanded) {
            closeTraceModal();
            return;
          }
          state.selectedTraceId = traceId;
          renderTraceList(page);
          setTraceModalOpen(true);
          renderTraceLoading(traceId);
          refreshSelectedTrace().catch(showError);
        });
        tbody.appendChild(row);
      }
    }

    function summaryItem(label, value) {
      const node = document.createElement("div");
      node.className = "summary-item";
      node.innerHTML = '<span class="k"></span><div class="v"></div>';
      node.querySelector(".k").textContent = label;
      node.querySelector(".v").textContent = value;
      return node;
    }

    function renderTraceSummary(detail) {
      const root = document.getElementById("trace-summary");
      root.replaceChildren();
      const summary = detail && detail.summary ? detail.summary : null;
      if (!summary) {
        root.appendChild(emptyNode("未选择链路"));
        return;
      }

      const items = [
        ["trace", summary.trace_id || "-"],
        ["status", summary.status || "-"],
        ["inbound", (summary.inbound_tag || "-") + " / " + (summary.inbound_type || "-")],
        ["outbound", (summary.outbound_tag || "-") + " / " + (summary.outbound_type || "-")],
        ["target", formatEndpoint(summary.target_host, summary.target_port)],
        ["resolved", formatResolvedTarget(summary)],
        ["route", (summary.route_type || "-") + " / " + (summary.match_type || "-")],
        ["bytes", numberText(summary.total_tx_bytes || 0) + " / " + numberText(summary.total_rx_bytes || 0)],
        ["duration", numberText(summary.duration_ms || 0) + " ms"],
      ];
      for (const [label, value] of items) {
        root.appendChild(summaryItem(label, String(value)));
      }
    }

    function renderEventTimeline(containerId, items, emptyText) {
      const root = document.getElementById(containerId);
      root.replaceChildren();
      if (!items || !items.length) {
        root.appendChild(emptyNode(emptyText));
        return;
      }

      for (const item of items) {
        const node = document.createElement("div");
        node.className = "timeline-item";
        const remoteText = formatEndpoint(item.remote_host, item.remote_port);
        const localText = formatEndpoint(item.local_host, item.local_port);
        const targetText = formatEndpoint(item.target_host, item.target_port);
        const resolvedText = formatResolvedTarget(item);
        node.innerHTML = `
          <div class="timeline-head">
            <div class="timeline-stage">${item.stage || "-"}</div>
            <div class="timeline-meta">${item.trace_id || "-"} · event ${item.event_id || 0}</div>
          </div>
          <div class="timeline-body">
            <div class="field"><span class="k">result</span><div class="v">${item.result || "-"}</div></div>
            <div class="field"><span class="k">target</span><div class="v">${targetText}</div></div>
            <div class="field"><span class="k">resolved</span><div class="v">${resolvedText}</div></div>
            <div class="field"><span class="k">route</span><div class="v">${item.route_type || "-"}</div></div>
            <div class="field"><span class="k">inbound</span><div class="v">${item.inbound_tag || item.inbound_type || "-"}</div></div>
            <div class="field"><span class="k">outbound</span><div class="v">${item.outbound_tag || item.outbound_type || "-"}</div></div>
            <div class="field"><span class="k">match</span><div class="v">${item.match_type || "-"} ${item.match_value || ""}</div></div>
            <div class="field"><span class="k">remote</span><div class="v">${remoteText}</div></div>
            <div class="field"><span class="k">local</span><div class="v">${localText}</div></div>
            <div class="field"><span class="k">bytes</span><div class="v">${numberText(item.bytes_tx || 0)} / ${numberText(item.bytes_rx || 0)}</div></div>
            <div class="field"><span class="k">latency</span><div class="v">${numberText(item.latency_ms || 0)} ms</div></div>
            <div class="field"><span class="k">error</span><div class="v">${item.error_code || 0} ${item.error_message || ""}</div></div>
            <div class="field"><span class="k">time</span><div class="v">${formatDateTime(item.ts_unix_ms)}</div></div>
          </div>
        `;
        root.appendChild(node);
      }
    }

    async function fetchJson(path) {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) {
        throw new Error(path + " " + response.status);
      }
      return response.json();
    }

    async function refreshSelectedTrace() {
      const traceId = state.selectedTraceId;
      if (!traceId) {
        return;
      }

      const [detail, events] = await Promise.all([
        fetchJson("/api/traces/" + traceId),
        fetchJson("/api/traces/" + traceId + "/events?sort_order=asc&limit=300"),
      ]);
      if (traceId !== state.selectedTraceId) {
        return;
      }
      const summary = detail && detail.summary ? detail.summary : null;
      document.getElementById("trace-modal-title").textContent = "链路详情";
      document.getElementById("trace-modal-meta").textContent = summary
        ? "trace " + (summary.trace_id || traceId) + " · " + formatStatus(summary.status) + " · " + ((summary.target_host || "-") + ":" + Number(summary.target_port || 0))
        : "trace " + traceId;
      renderTraceSummary(detail);
      renderEventTimeline("trace-timeline", events.events || [], "链路没有事件");
      document.getElementById("timeline-meta").textContent = "trace " + traceId + " · total " + numberText(events.total || 0);
    }

    async function refreshAll() {
      const [dashboard, traces] = await Promise.all([
        fetchJson("/api/traces/dashboard"),
        fetchJson(queryPath("/api/traces", state.tracesQuery)),
      ]);
      renderStats(dashboard);
      renderTraceList(traces);
      await refreshSelectedTrace();
    }

    function bindQueryForms() {
      document.getElementById("trace-query-form").addEventListener("submit", (event) => {
        event.preventDefault();
        state.tracesQuery = readFormState("trace-query-form");
        refreshAll().catch(showError);
      });
      for (const button of document.querySelectorAll("[data-reset-target]")) {
        button.addEventListener("click", () => {
          document.getElementById("trace-query-form").reset();
          state.tracesQuery = readFormState("trace-query-form");
          refreshAll().catch(showError);
        });
      }
    }

    function bindTraceModal() {
      for (const button of document.querySelectorAll("[data-modal-close]")) {
        button.addEventListener("click", closeTraceModal);
      }
      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && state.selectedTraceId) {
          closeTraceModal();
        }
      });
    }

    async function boot() {
      state.tracesQuery = readFormState("trace-query-form");
      clearTraceDetailView();
      bindTraceModal();
      bindQueryForms();
      await refreshAll();
      state.refreshTimer = window.setInterval(() => {
        refreshAll().catch(showError);
      }, refreshIntervalMs);
    }

    function showError(error) {
      console.error(error);
      document.getElementById("timeline-meta").textContent = "refresh failed: " + error.message;
      if (state.selectedTraceId) {
        document.getElementById("trace-modal-meta").textContent = "trace " + state.selectedTraceId + " · refresh failed";
      }
    }

    boot().catch(showError);
  </script>
</body>
</html>)HTML";
}

}    // namespace relay
