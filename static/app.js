/* Proxmox & Docker Security Dashboard – logika GUI (vanilla JS). */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const TYPE_LABELS = {
  local: "LOCAL", ssh: "SSH", lxc: "LXC", "ssh-lxc": "LXC", qemu: "VM",
  "ssh-qemu": "VM", "api-qemu": "VM", "api-lxc": "LXC",
  "docker-container": "DOCKER", "docker-image": "DOCKER",
};
const SCAN_TYPES = new Set(["local", "ssh", "lxc", "ssh-lxc", "qemu", "ssh-qemu",
                            "api-qemu", "docker-container", "docker-image"]);

let HOSTS = [];
let TASKS = [];
let CURRENT = null;          // targetId w modalu szczegółów
let DETAIL = null;           // pełny wynik skanu
let DETAIL_FILTER = "ALL";
let LOGGED_TOKEN = localStorage.getItem("dash_token") || "";

/* ---------------- helpers ---------------- */

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g,
    (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
}

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (LOGGED_TOKEN) headers["X-Dash-Token"] = LOGGED_TOKEN;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {...opts, headers});
  if (res.status === 401) {
    const tok = prompt("Panel jest chroniony tokenem (DASH_TOKEN). Podaj token:");
    if (tok !== null) {
      LOGGED_TOKEN = tok.trim();
      localStorage.setItem("dash_token", LOGGED_TOKEN);
      return api(path, opts);
    }
    throw new Error("Wymagany token dostępu");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return data;
}

function toast(msg, type = "info", ttl = 4000) {
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), ttl);
}

function fmtTime(ts) {
  if (!ts) return "–";
  const d = new Date(ts * 1000);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return "przed chwilą";
  if (diff < 3600) return `${Math.floor(diff / 60)} min temu`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h temu`;
  return d.toLocaleString("pl-PL", {dateStyle: "short", timeStyle: "short"});
}

function modalOpen(id) { $(id).classList.remove("hidden"); }
function modalClose(id) { $(id).classList.add("hidden"); }

$$("[data-close]").forEach((b) =>
  b.addEventListener("click", () => b.closest(".modal").classList.add("hidden")));
$$(".modal").forEach((m) =>
  m.addEventListener("click", (e) => { if (e.target === m) m.classList.add("hidden"); }));

/* ---------------- render: podsumowanie ---------------- */

function renderSummary() {
  const agg = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0};
  HOSTS.forEach((h) => {
    const s = h.result && h.result.summary;
    if (s) SEVS.forEach((sev) => (agg[sev] += s[sev] || 0));
  });
  $("#s-hosts").textContent = HOSTS.length;
  $("#s-crit").textContent = agg.CRITICAL;
  $("#s-high").textContent = agg.HIGH;
  $("#s-med").textContent = agg.MEDIUM;
  $("#s-low").textContent = agg.LOW;
  $("#s-tasks").textContent = TASKS.filter((t) => t.status === "running").length;
}

/* ---------------- render: zasoby ---------------- */

function typeBadge(type) {
  return `<span class="type-badge tb-${esc(type)}">${esc(TYPE_LABELS[type] || type)}</span>`;
}

function sevBadges(summary) {
  if (!summary) return `<span class="text-slate-600 text-xs">brak skanu</span>`;
  const total = SEVS.reduce((a, s) => a + (summary[s] || 0), 0);
  if (!total) return `<span class="text-emerald-400 text-xs">czysto</span>`;
  return SEVS.map((s) => summary[s]
    ? `<span class="sev sev-${s}" title="${s}">${summary[s]}</span>` : "").join(" ")
    + `<span class="text-slate-500 text-xs ml-1">(${total})</span>`;
}

function scannerChips(h) {
  const sc = h.scanners;
  if (h.type === "docker-image") {
    return `<span class="chip chip-ok" title="Skaner uruchamiany na hoście panelu">host</span>`;
  }
  if (!sc) return `<span class="chip chip-wait">sprawdzam…</span>`;
  const chip = (name, ver) => ver
    ? `<span class="chip chip-ok" title="${name} v${ver}">${name} v${ver}</span>`
    : `<button class="chip chip-no" onclick="installScanner('${esc(h.id)}','${name}')"
        title="Kliknij, aby zainstalować ${name}">${name} brak – zainstaluj</button>`;
  return chip("trivy", sc.trivy) + " " + chip("grype", sc.grype);
}

function statusDot(h) {
  const st = h.status || "unknown";
  const map = {online: "dot-online", offline: "dot-offline", stopped: "dot-stopped",
               unknown: "dot-unknown"};
  const label = {online: "online", offline: "offline", stopped: "zatrzymany",
                 unknown: "nieznany"}[st] || st;
  return `<span class="inline-flex items-center gap-1.5"><span class="dot ${map[st] || "dot-unknown"}"></span>
          <span class="text-xs text-slate-400">${label}</span></span>`;
}

function renderHosts() {
  const q = ($("#search").value || "").toLowerCase().trim();
  const rows = HOSTS.filter((h) =>
    !q || `${h.name} ${h.id} ${h.desc} ${h.type}`.toLowerCase().includes(q));
  const tbody = $("#hosts-body");
  tbody.innerHTML = rows.map((h) => {
    const canScan = SCAN_TYPES.has(h.type);
    const res = h.result;
    const fixable = res && res.fixable;
    const busy = TASKS.some((t) => t.status === "running" && t.target === h.id);
    const busyBadge = busy ? `<span class="chip chip-wait ml-1">praca…</span>` : "";
    return `<tr>
      <td>${typeBadge(h.type)}${busyBadge}</td>
      <td><div class="font-medium">${esc(h.name)}</div>
          <div class="text-xs text-slate-500">${esc(h.desc || h.id)}</div></td>
      <td>${statusDot(h)}</td>
      <td>${scannerChips(h)}</td>
      <td>${sevBadges(res && res.summary)}</td>
      <td class="text-xs text-slate-400">${res ? fmtTime(res.time) : "–"}</td>
      <td class="text-right pr-4 whitespace-nowrap">
        ${canScan ? `<button class="btn btn-ghost btn-xs" onclick="scanTarget('${esc(h.id)}')">Skanuj</button>` : ""}
        ${h.type !== "docker-image" ? `<button class="btn btn-ghost btn-xs" onclick="testHost('${esc(h.id)}')">Test</button>` : ""}
        ${res ? `<button class="btn btn-ghost btn-xs" onclick="openDetails('${esc(h.id)}')">Szczegóły</button>` : ""}
        ${res && fixable && h.type !== "docker-image"
          ? `<button class="btn btn-primary btn-xs" onclick="fixAll('${esc(h.id)}', ${fixable})"
             title="Aktualizacja ${fixable} podatnych pakietów">Napraw pakiety</button>` : ""}
        ${h.type === "ssh" ? `<button class="btn btn-danger btn-xs" onclick="removeSsh('${esc(h.id)}')">Usuń</button>` : ""}
      </td>
    </tr>`;
  }).join("");
  $("#hosts-empty").classList.toggle("hidden", HOSTS.length > 0);
  $("#hosts-count").textContent = `(${HOSTS.length})`;
}

/* ---------------- render: zadania ---------------- */

function renderTasks() {
  const running = TASKS.filter((t) => t.status === "running");
  const recent = TASKS.filter((t) => t.status !== "running").slice(0, 6);
  const panel = $("#tasks-panel");
  if (!running.length && !recent.length) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  panel.innerHTML = [...running, ...recent].map((t) => {
    const cls = t.status === "running" ? "task-running" :
                t.status === "failed" ? "task-failed" : "task-done";
    const icon = t.status === "running" ? "&#9203;" :
                 t.status === "failed" ? "&#10060;" : "&#9989;";
    const dur = t.finished
      ? `${Math.max(1, Math.round((t.finished - t.started)))} s` : "";
    return `<div class="task-row ${cls}">
      <div class="flex items-center justify-between gap-2">
        <span>${icon} ${esc(t.label)}</span>
        <span class="text-slate-500">${dur}</span>
      </div>
      ${t.message ? `<div class="text-slate-400 mt-0.5 break-words">${esc(t.message)}</div>` : ""}
    </div>`;
  }).join("");
}

/* ---------------- render: dziennik ---------------- */

function renderLogs(logs) {
  $("#logs-list").innerHTML = (logs || []).map((l) => {
    const cls = l.level === "error" ? "log-error" : l.level === "warn" ? "log-warn" : "";
    const t = new Date(l.ts * 1000).toLocaleTimeString("pl-PL");
    return `<li class="${cls}">${t} – ${esc(l.msg)}</li>`;
  }).join("");
}

/* ---------------- akcje ---------------- */

async function loadHosts() {
  try {
    const data = await api("/api/hosts");
    HOSTS = data.hosts || [];
    if (data.env) {
      $("#env-line").textContent =
        `${data.env.hostname || ""} · v${data.env.version}`;
      $("#env-pve").classList.toggle("hidden", !data.env.pve_node);
      $("#env-docker").classList.toggle("hidden", !data.env.docker);
      $("#ver").textContent = data.env.version;
    }
    renderSummary();
    renderHosts();
  } catch (e) {
    toast(`Nie udało się pobrać zasobów: ${e.message}`, "err");
  }
}

async function loadTasks() {
  try {
    const data = await api("/api/tasks");
    const prevRunning = TASKS.filter((t) => t.status === "running").map((t) => t.id);
    TASKS = data.tasks || [];
    TASKS.filter((t) => t.status === "failed" && prevRunning.includes(t.id))
      .forEach((t) => toast(`Zadanie nie powiodło się: ${t.message}`, "err", 7000));
    TASKS.filter((t) => t.status === "done" && prevRunning.includes(t.id))
      .forEach((t) => toast(`Gotowe: ${t.label}`, "ok"));
    renderTasks();
    renderSummary();
    if (TASKS.some((t) => t.status === "running")) renderHosts();
  } catch (e) { /* cicho */ }
}

async function loadLogs() {
  try {
    const data = await api("/api/logs");
    renderLogs(data.logs);
  } catch (e) { /* cicho */ }
}

async function scanTarget(id) {
  try {
    await api(`/api/hosts/${id}/scan`, {method: "POST"});
    toast("Skanowanie rozpoczęte w tle", "info");
    setTimeout(loadTasks, 400);
  } catch (e) { toast(e.message, "err"); }
}

async function testHost(id) {
  try {
    await api(`/api/hosts/${id}/test`, {method: "POST"});
    toast("Test połączenia rozpoczęty", "info");
    setTimeout(loadTasks, 400);
  } catch (e) { toast(e.message, "err"); }
}

async function installScanner(id, name) {
  try {
    await api(`/api/hosts/${id}/install-scanner`,
              {method: "POST", body: JSON.stringify({name})});
    toast(`Instalacja ${name} rozpoczęta`, "info");
    setTimeout(loadTasks, 400);
  } catch (e) { toast(e.message, "err"); }
}

function fixAll(id, count) {
  if (!confirm(`Zaktualizować wszystkie podatne pakiety (${count}) na tym celu?\n` +
               "Dla Debian/Ubuntu: apt-get install --only-upgrade; Alpine: apk add --upgrade.")) return;
  api(`/api/hosts/${id}/remediate-all`, {method: "POST"})
    .then(() => { toast("Naprawa pakietów rozpoczęta", "info"); setTimeout(loadTasks, 400); })
    .catch((e) => toast(e.message, "err"));
}

function fixPackage(id, pkg) {
  if (!confirm(`Zaktualizować pakiet "${pkg}"?`)) return;
  api(`/api/hosts/${id}/remediate`,
      {method: "POST", body: JSON.stringify({packages: [pkg]})})
    .then(() => { toast(`Aktualizacja "${pkg}" rozpoczęta`, "info"); setTimeout(loadTasks, 400); })
    .catch((e) => toast(e.message, "err"));
}

async function removeSsh(id) {
  if (!confirm("Usunąć ten host SSH? Wyniki jego skanów pozostaną zarchiwizowane.")) return;
  try {
    await api(`/api/hosts/ssh/${id}`, {method: "DELETE"});
    toast("Host usunięty", "ok");
    loadHosts();
  } catch (e) { toast(e.message, "err"); }
}

/* ---------------- szczegóły skanu ---------------- */

async function openDetails(id) {
  CURRENT = id;
  try {
    DETAIL = await api(`/api/hosts/${id}/vulns`);
  } catch (e) {
    toast(e.message, "err");
    return;
  }
  const host = HOSTS.find((h) => h.id === id) || {};
  $("#det-title").textContent = `Podatności: ${host.name || id}`;
  const s = DETAIL.summary || {};
  const os = (DETAIL.os && DETAIL.os.PRETTY_NAME) || "";
  $("#det-meta").textContent =
    `silniki: ${(DETAIL.engines || []).join(", ")} · skan: ${fmtTime(DETAIL.time)}` +
    (os ? ` · system: ${os}` : "") +
    (DETAIL.fixable != null ? ` · naprawialne: ${DETAIL.fixable}` : "");
  const warn = $("#det-warn");
  warn.classList.toggle("hidden", !DETAIL.truncated);
  if (DETAIL.truncated) {
    warn.textContent = "Wyjście mogło zostać ucięte przez QEMU Guest Agent – " +
      "dodaj tę maszynę przez SSH (zakładka „+ Host SSH”), aby wynik był pełny.";
  }
  DETAIL_FILTER = "ALL";
  renderFilters();
  renderDetails();
  modalOpen("#modal-details");
}

function renderFilters() {
  const s = DETAIL.summary || {};
  const counts = {ALL: SEVS.reduce((a, x) => a + (s[x] || 0), 0),
                  ...Object.fromEntries(SEVS.map((x) => [x, s[x] || 0]))};
  $("#det-filters").innerHTML = ["ALL", ...SEVS].map((f) =>
    `<button class="sev ${f === "ALL" ? "sev-UNKNOWN" : `sev-${f}`}"
      style="${DETAIL_FILTER === f ? "outline:2px solid #34d399" : ""}"
      onclick="setFilter('${f}')">${f === "ALL" ? "WSZYSTKIE" : f} (${counts[f]})</button>`).join("");
}

function setFilter(f) { DETAIL_FILTER = f; renderFilters(); renderDetails(); }

function renderDetails() {
  const rows = (DETAIL.vulns || []).filter((v) =>
    DETAIL_FILTER === "ALL" || v.severity === DETAIL_FILTER);
  const body = $("#det-body");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="5" class="text-center text-slate-500 py-6">
      Brak podatności w tym filtrze</td></tr>`;
    return;
  }
  body.innerHTML = rows.slice(0, 500).map((v) => {
    const link = v.url
      ? `<a href="${esc(v.url)}" target="_blank" rel="noopener"
            class="text-emerald-400 hover:underline">${esc(v.id)}</a>`
      : esc(v.id);
    const fixBtn = v.fixed && CURRENT !== "test"
      ? `<button class="btn btn-primary btn-xs"
           onclick="fixPackage('${esc(CURRENT)}','${esc(v.pkg)}')"
           title="apt-get install --only-upgrade / apk add --upgrade">Zaktualizuj ten pakiet</button>`
      : `<span class="text-slate-600 text-xs">brak poprawki</span>`;
    const ver = v.fixed
      ? `${esc(v.installed)} <span class="text-slate-500">-></span> <span class="text-emerald-400">${esc(v.fixed)}</span>`
      : esc(v.installed);
    const title = v.title ? `<div class="text-xs text-slate-500 max-w-md truncate"
      title="${esc(v.desc || v.title)}">${esc(v.title)}</div>` : "";
    return `<tr>
      <td><span class="sev sev-${esc(v.severity)}">${esc(v.severity)}</span></td>
      <td>${link}${title}</td>
      <td class="font-medium">${esc(v.pkg)}</td>
      <td class="text-xs whitespace-nowrap">${ver}</td>
      <td class="text-right pr-3">${fixBtn}</td>
    </tr>`;
  }).join("");
  if (rows.length > 500) {
    body.insertAdjacentHTML("beforeend",
      `<tr><td colspan="5" class="text-center text-slate-500 py-2">
       … pokazano pierwsze 500 z ${rows.length}</td></tr>`);
  }
}

$("#btn-rescan").addEventListener("click", () => {
  if (!CURRENT) return;
  modalClose("#modal-details");
  scanTarget(CURRENT);
});

$("#btn-fix-all").addEventListener("click", () => {
  if (!CURRENT) return;
  const n = (DETAIL.vulns || []).filter((v) => v.fixed).length;
  fixAll(CURRENT, n);
});

/* ---------------- ustawienia ---------------- */

function setVal(id, v) { $(id).value = v == null ? "" : v; }
function setChk(id, v) { $(id).checked = !!v; }

async function loadSettings() {
  const {settings: s} = await api("/api/settings");
  $("#set-engine").value = s.scan_engine || "trivy";
  $("#set-minsev").value = s.min_notify_severity || "HIGH";
  setVal("#set-interval", s.scan_interval_hours);
  setChk("#set-upddb", s.update_db_before_scan);
  setChk("#set-autoinst", s.auto_install_scanner);
  setChk("#set-allimg", s.scan_docker_all_images);
  const pve = s.proxmox_api || {};
  setChk("#set-pve-on", pve.enabled); setVal("#set-pve-url", pve.url);
  setVal("#set-pve-token", pve.token); setVal("#set-pve-user", pve.user);
  setVal("#set-pve-pass", pve.password); setChk("#set-pve-ssl", pve.verify_ssl);
  const ntfy = s.ntfy || {};
  setChk("#set-ntfy-on", ntfy.enabled); setVal("#set-ntfy-url", ntfy.url);
  setVal("#set-ntfy-token", ntfy.token);
  const gotify = s.gotify || {};
  setChk("#set-gotify-on", gotify.enabled); setVal("#set-gotify-url", gotify.url);
  setVal("#set-gotify-token", gotify.token);
  const ha = s.homeassistant || {};
  setChk("#set-ha-on", ha.enabled); setVal("#set-ha-url", ha.url);
  setVal("#set-ha-token", ha.token); setVal("#set-ha-sensor", ha.sensor);
  setVal("#set-ha-notify", ha.notify_service);
  const disc = s.discord || {};
  setChk("#set-discord-on", disc.enabled); setVal("#set-discord-url", disc.webhook_url);
  const tg = s.telegram || {};
  setChk("#set-tg-on", tg.enabled); setVal("#set-tg-token", tg.bot_token);
  setVal("#set-tg-chat", tg.chat_id);
}

function collectSettings() {
  return {
    scan_engine: $("#set-engine").value,
    min_notify_severity: $("#set-minsev").value,
    scan_interval_hours: Math.max(0, parseInt($("#set-interval").value || "0", 10)),
    update_db_before_scan: $("#set-upddb").checked,
    auto_install_scanner: $("#set-autoinst").checked,
    scan_docker_all_images: $("#set-allimg").checked,
    proxmox_api: {enabled: $("#set-pve-on").checked, url: $("#set-pve-url").value.trim(),
                  token: $("#set-pve-token").value.trim(), user: $("#set-pve-user").value.trim(),
                  password: $("#set-pve-pass").value, verify_ssl: $("#set-pve-ssl").checked},
    ntfy: {enabled: $("#set-ntfy-on").checked, url: $("#set-ntfy-url").value.trim(),
           token: $("#set-ntfy-token").value.trim()},
    gotify: {enabled: $("#set-gotify-on").checked, url: $("#set-gotify-url").value.trim(),
             token: $("#set-gotify-token").value.trim()},
    homeassistant: {enabled: $("#set-ha-on").checked, url: $("#set-ha-url").value.trim(),
                    token: $("#set-ha-token").value.trim(),
                    sensor: $("#set-ha-sensor").value.trim() || "sensor.security_dashboard",
                    notify_service: $("#set-ha-notify").value.trim()},
    discord: {enabled: $("#set-discord-on").checked,
              webhook_url: $("#set-discord-url").value.trim()},
    telegram: {enabled: $("#set-tg-on").checked, bot_token: $("#set-tg-token").value.trim(),
               chat_id: $("#set-tg-chat").value.trim()},
  };
}

$("#btn-settings").addEventListener("click", async () => {
  try {
    await loadSettings();
    modalOpen("#modal-settings");
  } catch (e) { toast(e.message, "err"); }
});

$("#btn-save-settings").addEventListener("click", async () => {
  try {
    await api("/api/settings", {method: "POST", body: JSON.stringify(collectSettings())});
    toast("Ustawienia zapisane", "ok");
    modalClose("#modal-settings");
    loadHosts();
  } catch (e) { toast(e.message, "err"); }
});

$("#btn-test-notify").addEventListener("click", async () => {
  const btn = $("#btn-test-notify");
  btn.disabled = true;
  try {
    // najpierw zapisz aktualne pola formularza, żeby test używał bieżącej konfiguracji
    await api("/api/settings", {method: "POST", body: JSON.stringify(collectSettings())});
    const data = await api("/api/settings/test-notify", {method: "POST"});
    const rows = Object.entries(data.results || {})
      .map(([k, v]) => `${k}: ${v}`).join("\n") || "Żaden kanał nie jest włączony";
    alert(`Wynik testu powiadomień:\n${rows}`);
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
  }
});

/* ---------------- dodawanie hosta SSH ---------------- */

$("#btn-add-ssh").addEventListener("click", () => modalOpen("#modal-ssh"));
$("#ssh-auth").addEventListener("change", () => {
  const isKey = $("#ssh-auth").value === "key";
  $("#ssh-pass-wrap").classList.toggle("hidden", isKey);
  $("#ssh-key-wrap").classList.toggle("hidden", !isKey);
  $("#ssh-keypass-wrap").classList.toggle("hidden", !isKey);
});

$("#btn-ssh-save").addEventListener("click", async () => {
  const btn = $("#btn-ssh-save");
  btn.disabled = true;
  try {
    const payload = {
      host: $("#ssh-host").value.trim(),
      port: parseInt($("#ssh-port").value || "22", 10),
      username: $("#ssh-user").value.trim() || "root",
      auth_type: $("#ssh-auth").value,
      password: $("#ssh-pass").value,
      private_key: $("#ssh-key").value,
      key_password: $("#ssh-keypass").value,
      pve: $("#ssh-pve").checked,
      test: $("#ssh-test").checked,
      name: $("#ssh-name").value.trim(),
    };
    if (!payload.host) throw new Error("Podaj adres hosta");
    if (payload.auth_type === "key" && !payload.private_key.trim()) {
      throw new Error("Wklej klucz prywatny");
    }
    const data = await api("/api/hosts/ssh",
                           {method: "POST", body: JSON.stringify(payload)});
    toast(`Host dodany${data.info ? ": " + data.info.split("\n")[0] : ""}`, "ok");
    modalClose("#modal-ssh");
    loadHosts();
  } catch (e) {
    toast(e.message, "err", 8000);
  } finally {
    btn.disabled = false;
  }
});

/* ---------------- nagłówek ---------------- */

$("#btn-refresh").addEventListener("click", async () => {
  try {
    await api("/api/discover", {method: "POST"});
    toast("Wykrywanie zasobów odświeżone", "ok");
    loadHosts();
  } catch (e) { toast(e.message, "err"); }
});

$("#btn-scan-all").addEventListener("click", async () => {
  try {
    await api("/api/scan-all", {method: "POST"});
    toast("Skan wszystkich celów rozpoczęty", "info");
    setTimeout(loadTasks, 400);
  } catch (e) { toast(e.message, "err"); }
});

$("#btn-clear-tasks").addEventListener("click", async () => {
  try {
    await api("/api/tasks/clear", {method: "POST"});
    loadTasks();
  } catch (e) { toast(e.message, "err"); }
});

/* ---------------- pętla odświeżania ---------------- */

$("#search").addEventListener("input", renderHosts);
setInterval(() => { loadHosts(); loadTasks(); }, 2500);
setInterval(loadLogs, 8000);
loadHosts();
loadTasks();
loadLogs();
