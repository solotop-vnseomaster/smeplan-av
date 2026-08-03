// UI tang hien thi/nhan thao tac (modules/02-kien-truc.md muc 1: "UI ... chi
// hien thi va nhan thao tac, khong tu xu ly logic phat hien"). Moi quyet
// dinh nghiep vu nam o service .NET, UI chi goi API va ve lai ket qua.

const API = ""; // cung origin voi service (loopback), xem Program.cs

// [SUA LOI NGHIEM TRONG] API truoc day khong xac thuc — gio moi request
// phai kem token doc tu query string luc mo trang (Shell native doc token
// tu file tren dia va mo URL kem ?token=..., xem Security/ApiTokenProvider.cs
// va MainWindow.xaml.cs). Neu thieu token, moi cuoc goi /api/* se bi 401.
//
// [UX FIX] Uu tien token tu URL (?token=...); neu khong co (vi du nguoi
// dung refresh trang hoac mo lai tab da luu), fallback ve token da nho tu
// lan truoc trong localStorage — tranh phai luon dan lai URL day du token.
// Token ban than da on dinh qua cac lan service restart (xem
// ApiTokenProvider.cs), nen cach nho nay an toan va it phien nhat.
const AV_TOKEN = (() => {
  const fromUrl = new URLSearchParams(location.search).get("token");
  if (fromUrl) {
    localStorage.setItem("av_token", fromUrl);
    return fromUrl;
  }
  return localStorage.getItem("av_token") || "";
})();

// ---------- Helpers ----------
function $(sel) { return document.querySelector(sel); }
function $all(sel) { return Array.from(document.querySelectorAll(sel)); }

// Chong XSS: escape truoc khi noi chuoi dong vao innerHTML (xem cac ham
// renderRules/renderQuarantine/renderDownloads/renderFlaggedItems/...).
function esc(value) {
  const s = value === null || value === undefined ? "" : String(value);
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function api(path, opts) {
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json", "X-Av-Token": AV_TOKEN },
    ...opts,
  });
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

function fmtTime(unixMs) {
  if (!unixMs) return "—";
  const d = new Date(unixMs);
  return d.toLocaleTimeString("vi-VN", { hour12: false });
}

function shortHash(h) {
  if (!h) return "(không có)";
  return h.length > 16 ? h.slice(0, 10) + "…" + h.slice(-6) : h;
}

// Tach ten file khoi duong dan thu muc de hien thi gon trong danh sach
// "File bị gắn cờ" luc dang quet — thu muc rut gon (chi giu vai cap dau)
// hien mo, ten file hien ro dam, tranh duong dan WinSxS/System32 rat dai
// lam tran man hinh (nguoi dung bao cao). Duong dan DAY DU van xem duoc
// qua title attribute (di chuot vao) hoac modal chi tiet khi bam vao dong.
function splitPathForDisplay(fullPath) {
  const idx = Math.max(fullPath.lastIndexOf("\\"), fullPath.lastIndexOf("/"));
  if (idx < 0) return { dir: "", name: fullPath };
  const name = fullPath.slice(idx + 1);
  let dir = fullPath.slice(0, idx + 1);
  // Rut gon thu muc qua dai: chi giu ~40 ky tu dau + "…\"
  if (dir.length > 40) dir = dir.slice(0, 37) + "…\\";
  return { dir, name };
}

function verdictClass(v) {
  return { Clean: "verdict-clean", Malicious: "verdict-malicious", Suspicious: "verdict-suspicious", ScanError: "verdict-scanerror" }[v] || "";
}

// Dang terminal log (tu tai lieu thiet ke UI futuristic): moi dong bat dau
// bang timestamp [HH:mm:ss] + nhan muc do [INFO]/[WARN]/[CRIT]. "level"
// nhan mot trong ba gia tri "info"|"warn"|"crit" — CRIT dung mau do DOC
// QUYEN (--danger), khong dung cho bat ky the loai nao khac ngoai threat
// that/hanh dong da thuc hien tu dong (vi du auto-rollback ransomware).
function logLevelMeta(level) {
  return {
    info: { cls: "log-info", label: "INFO" },
    warn: { cls: "log-warn", label: "WARN" },
    crit: { cls: "log-crit", label: "CRIT" },
  }[level] || { cls: "log-info", label: "INFO" };
}

// Suy ra muc do tu noi dung audit summary (Nhat ky/dashboard mini-log
// khong co truong severity rieng, chi co chuoi mo ta) — dung lai dung
// pattern da co trong pollAuditForToasts.
function logLevelFromSummary(summary) {
  if (/MALICIOUS/i.test(summary)) return "crit";
  if (/SUSPICIOUS/i.test(summary)) return "warn";
  return "info";
}

// Render mot dong <li> dang terminal log dung chung cho moi danh sach
// su kien (Nhat ky, beacon, ransomware, USB, webcam/mic, Alert Center).
function renderLogLi(ul, { timeMs, level, bodyHtml }) {
  const meta = logLevelMeta(level);
  const li = document.createElement("li");
  if (meta.cls === "log-crit") li.classList.add("log-row-crit");
  li.innerHTML = `<span class="audit-time">${esc(fmtTime(timeMs))}</span><span class="log-level ${meta.cls}">${meta.label}</span><span>${bodyHtml}</span>`;
  ul.appendChild(li);
  return li;
}

function toast(title, body, kind = "") {
  const el = document.createElement("div");
  el.className = "toast" + (kind ? " " + kind : "");
  el.innerHTML = `<b>${esc(title)}</b>${esc(body)}`;
  $("#toastStack").appendChild(el);
  setTimeout(() => el.remove(), 7000);
}

// ---------- Navigation ----------
// currentView theo doi tab dang xem — dung o vong lap polling ben duoi de
// chi render lai cac bang "nang" (quarantine/rules/downloads/flagged) khi
// nguoi dung THUC SU dang xem tab do, thay vi lam moi ca 4 bang mac dinh
// moi 1.5s bat ke dang o tab nao (xem ghi chu o tick()).
let currentView = "dashboard";
$all(".nav-item").forEach(btn => {
  btn.addEventListener("click", () => {
    $all(".nav-item").forEach(b => b.classList.remove("active"));
    $all(".view").forEach(v => v.classList.remove("active"));
    btn.classList.add("active");
    $("#view-" + btn.dataset.view).classList.add("active");
    currentView = btn.dataset.view;
  });
});

// ---------- Connection indicator ----------
let connected = false;
function setConnected(ok) {
  if (ok === connected) return;
  connected = ok;
  $("#connDot").className = "conn-dot " + (ok ? "ok" : "bad");
  $("#connLabel").textContent = ok ? "Đã kết nối service" : "Mất kết nối service…";
}

// ---------- Dashboard ----------
async function refreshStatus() {
  const status = await api("/api/status");
  setConnected(true);

  const upd = status.updateStatus;
  $("#statSigVersion").textContent = "v" + (upd?.currentVersion ?? 0);
  $("#updCurrentVersion").textContent = "v" + (upd?.currentVersion ?? 0);
  $("#updLastChecked").textContent = upd?.lastCheckedAt ? new Date(upd.lastCheckedAt).toLocaleString("vi-VN") : "—";
  $("#updLastResult").textContent = upd?.lastResult ?? "—";
}

async function refreshQuarantineSummary() {
  const list = await api("/api/quarantine");
  const active = list.filter(r => r.status === "Quarantined" || r.status === "PendingManualConfirmation");
  $("#statQuarantined").textContent = active.length;
  return list;
}

async function refreshRulesSummary() {
  const rules = await api("/api/rules");
  $("#statRules").textContent = rules.length;
  return rules;
}

// [UX] "ngau" hon ban list phang truoc day: tile thong ke theo tung loai
// hoat dong (mau + icon rieng), phia duoi van giu feed gan nhat.
const CATEGORY_META = {
  scan: { icon: "🔍", label: "Quét file", color: "var(--cyan)" },
  quarantine: { icon: "🗂", label: "Quarantine", color: "var(--danger)" },
  "process-trust": { icon: "🛡", label: "Process Trust", color: "var(--ok)" },
  update: { icon: "🔄", label: "Cập nhật CSDL", color: "var(--warn)" },
  system: { icon: "🖥", label: "Hệ thống", color: "var(--violet)" },
};

async function refreshDashboardLog() {
  // Lay mot lo lon hon de tinh thong ke theo category, khong chi 8 dong gan nhat.
  const events = await api("/api/audit?limit=300");
  $("#statsTotalEvents").textContent = `${events.length.toLocaleString("vi-VN")} sự kiện gần đây`;

  const counts = {};
  events.forEach(e => { counts[e.category] = (counts[e.category] || 0) + 1; });

  const statsEl = $("#activityStats");
  statsEl.innerHTML = Object.keys(CATEGORY_META).map(cat => {
    const meta = CATEGORY_META[cat];
    const count = counts[cat] || 0;
    return `
      <div class="as-tile" style="--as-color:${meta.color}">
        <span class="as-icon">${meta.icon}</span>
        <div class="as-count">${count}</div>
        <div class="as-label">${esc(meta.label)}</div>
      </div>`;
  }).join("");

  const ul = $("#dashboardLog");
  ul.innerHTML = "";
  events.slice(0, 8).forEach(e => {
    const meta = CATEGORY_META[e.category] || { icon: "•" };
    renderLogLi(ul, {
      timeMs: e.timestampUnixMs,
      level: logLevelFromSummary(e.summary),
      bodyHtml: `<b>${esc(meta.icon)} ${esc(e.category)}</b> — ${esc(e.summary)}`,
    });
  });
}

// ---------- Quick scan ----------
$("#quickScanBtn").addEventListener("click", async () => {
  const path = $("#quickScanPath").value.trim();
  if (!path) return;
  $("#quickScanResult").innerHTML = "Đang quét…";
  try {
    const r = await api("/api/scan/file", { method: "POST", body: JSON.stringify({ path }) });
    $("#quickScanResult").innerHTML =
      `<span class="verdict ${esc(verdictClass(r.verdict))}">${esc(r.verdict)}</span>` +
      `<span class="mono">stage=${esc(r.stage)} · sha256=${esc(shortHash(r.sha256Hex))}</span><br>` +
      `<span class="muted small">${esc(r.reason)}</span>`;
  } catch (e) {
    $("#quickScanResult").innerHTML = `<span class="muted small">Lỗi: ${esc(e.message)}</span>`;
  }
});

// ---------- Cache full scan: nut bat/tat (theo yeu cau nguoi dung) ----------
let cacheToggleState = null;

async function refreshCacheToggle() {
  const s = await api("/api/settings");
  if (cacheToggleState === s.fullScanCacheEnabled) return; // tranh ve lai khi khong doi (giu animation muot khi bam)
  cacheToggleState = s.fullScanCacheEnabled;
  const btn = $("#cacheToggle");
  btn.classList.toggle("on", cacheToggleState);
  btn.setAttribute("aria-pressed", String(cacheToggleState));
}

$("#cacheToggle").addEventListener("click", async () => {
  const next = !cacheToggleState;
  cacheToggleState = next;
  $("#cacheToggle").classList.toggle("on", next);
  $("#cacheToggle").setAttribute("aria-pressed", String(next));
  try {
    await api("/api/settings/full-scan-cache", { method: "POST", body: JSON.stringify({ enabled: next }) });
    toast(next ? "Đã bật cache full scan" : "Đã tắt cache full scan",
      next ? "Lần quét sau sẽ bỏ qua file không đổi." : "Lần quét sau sẽ quét lại toàn bộ, không dùng cache.");
  } catch (e) {
    toast("Không đổi được cài đặt cache", e.message, "danger");
    cacheToggleState = !next; // rollback UI neu goi API that bai
    $("#cacheToggle").classList.toggle("on", cacheToggleState);
  }
});

// ---------- Full scan (UI-02) ----------
$("#scanStartBtn").addEventListener("click", async () => {
  $("#scanStartBtn").disabled = true;
  try {
    await api("/api/scan/full/start", { method: "POST", body: JSON.stringify({ volumeRoot: $("#scanVolume").value.trim() }) });
  } catch (e) {
    toast("Không khởi động được scan", e.message.includes("400") ? "Đã có scan đang chạy rồi." : e.message, "warn");
  }
});
$("#scanPauseBtn").addEventListener("click", () => api("/api/scan/full/pause", { method: "POST" }));
$("#scanResumeBtn").addEventListener("click", () => api("/api/scan/full/resume", { method: "POST" }));
$("#scanCancelBtn").addEventListener("click", () => api("/api/scan/full/cancel", { method: "POST" }));

let lastScanStatus = null;

function fmtDuration(startIso, endIso) {
  if (!startIso || !endIso) return "";
  const ms = new Date(endIso) - new Date(startIso);
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s} giây` : `${Math.floor(s / 60)} phút ${s % 60} giây`;
}

async function refreshScanProgress() {
  const p = await api("/api/scan/full/status");
  const statusLabel = { Idle: "Chưa chạy", Running: "Đang quét", Paused: "Tạm dừng", Completed: "Hoàn tất", Error: "Lỗi" }[p.status] || p.status;
  $("#scanStatusText").textContent = statusLabel;
  $("#scanCurrentFile").textContent = p.currentFile || "";
  $("#scanFiles").textContent = p.filesScanned;
  $("#scanCached").textContent = p.cachedCount || 0;
  $("#scanMalicious").textContent = p.maliciousCount;
  $("#scanSuspicious").textContent = p.suspiciousCount;
  $("#scanErrors").textContent = p.errorCount;

  const pct = p.status === "Completed" ? 100 : Math.min(98, p.filesScanned > 0 ? (p.filesScanned % 500) / 5 : 0);
  $("#scanProgressFill").style.width = (p.status === "Idle" ? 0 : pct) + "%";

  // Nut "Bat dau" tu disable khi da co scan chay — tranh bam 2 lan gay hieu
  // lam la loi (UX fix theo yeu cau nguoi dung).
  $("#scanStartBtn").disabled = (p.status === "Running" || p.status === "Paused");

  // ----- Bao cao khi scan hoan tat (UI-02 mo rong theo yeu cau nguoi dung) -----
  if (p.status === "Completed") {
    $("#scanReportCard").style.display = "block";
    $("#scanReportMeta").textContent = fmtDuration(p.startedAt, p.finishedAt);
    const totalFlagged = p.maliciousCount + p.suspiciousCount;
    // [GIẢI THÍCH THEO YÊU CẦU NGƯỜI DÙNG] "chạy xong lâu quá dù có mở
    // cache, ko biết cache ko load hay bị xoá giữa các lần" — cache chỉ
    // dùng được khi CÙNG phiên bản CSDL với lần quét trước; CSDL tự kiểm
    // tra cập nhật mỗi ~2 giờ và MỖI LẦN cập nhật (kể cả bản vá nhỏ) đều
    // xoá sạch cache để đảm bảo an toàn (không bỏ sót file mà CSDL mới vừa
    // nhận diện được). Với một lần quét kéo dài nhiều giờ, CSDL rất có thể
    // đã cập nhật ngay trong lúc quét — hiện rõ lý do thay vì để im lặng.
    let cacheHint = "";
    if (cacheToggleState && p.cachedCount === 0) {
      cacheHint = `Cache đang bật nhưng lần này không dùng được file nào từ cache — bình thường nếu đây là lần quét đầu tiên (cache còn trống), hoặc do CSDL virus đã cập nhật kể từ lần quét trước (cache tự xoá mỗi khi CSDL đổi phiên bản, kể cả bản vá nhỏ). Từ lần quét kế tiếp (nếu CSDL không đổi) cache sẽ có tác dụng.\n`;
    }
    $("#scanReportSummary").textContent =
      `Đã quét ${p.filesScanned.toLocaleString("vi-VN")} file trên ${p.volume}.\n` +
      `Phát hiện: ${p.maliciousCount} Malicious, ${p.suspiciousCount} Suspicious, ${p.errorCount} lỗi đọc file.\n` +
      (p.cachedCount > 0 ? `Bỏ qua ${p.cachedCount.toLocaleString("vi-VN")} file nhờ cache (không đổi từ lần quét trước).\n` : "") +
      cacheHint +
      (totalFlagged > 0
        ? `Xem danh sách "File bị gắn cờ" bên dưới để biết chi tiết từng file.`
        : `Không phát hiện gì đáng ngờ trong lần quét này.`);
  } else if (p.status !== lastScanStatus) {
    $("#scanReportCard").style.display = "none";
  }
  lastScanStatus = p.status;
}

// ----- Danh sach file bi gan co (cap nhat song song luc dang quet) -----
// [UX FIX] Truoc day ve chung Malicious/Suspicious/ScanError trong CUNG
// mot danh sach — voi mot lan full scan that (~1 trieu file tren C:\),
// so luong ScanError (file he thong dang bi khoa/thieu quyen) co the len
// toi vai nghin, "chon lap" hoan toan cac phat hien Malicious/Suspicious
// thuc su quan trong, khien nguoi dung khong the tim thay chung. Them bo
// loc + phan tich nguyen nhan loi theo ma [CODE] (xem pipeline.cpp
// CopyClassifiedIoError va FullScanService.ScanWithTimeout).
let flaggedItemsCache = [];
let flaggedFilter = "important"; // mac dinh: chi hien Malicious+Suspicious
function verdictIcon(v) { return { Malicious: "☠", Suspicious: "⚠", ScanError: "❌" }[v] || "•"; }

const ERROR_CODE_INFO = {
  SHARING_VIOLATION: "File đang bị một tiến trình khác khóa (đang chạy/đang được dùng) — bình thường khi quét hệ thống đang hoạt động.",
  ACCESS_DENIED: "Thiếu quyền đọc — thường là file hệ thống được TrustedInstaller/Windows Resource Protection bảo vệ.",
  NOT_FOUND: "File đã bị xóa hoặc di chuyển giữa lúc liệt kê và lúc quét thực tế.",
  PATH_TOO_LONG: "Đường dẫn vượt giới hạn hệ thống ngay cả sau khi đã hỗ trợ long-path.",
  TIMEOUT: "Quá thời gian quét cho phép (20s) — có thể là socket/pipe/cache đang ghi liên tục.",
  EXCEPTION: "Lỗi phần mềm không mong đợi trong lúc quét file này.",
  WIN32: "Lỗi Windows khác — xem chi tiết từng dòng để biết mã lỗi cụ thể.",
  UNKNOWN: "Không xác định được nguyên nhân cụ thể.",
  CORRUPT_ARCHIVE: "File nén (.zip) có cấu trúc bên trong bị hỏng hoặc không hợp lệ.",
  OTHER: "Không phân loại được (định dạng lý do cũ hoặc không khớp mẫu).",
};

function parseErrorCode(reason) {
  const m = /^\[([A-Z_]+)\]/.exec(reason || "");
  return m ? m[1] : "OTHER";
}

function matchesFilter(item, filter) {
  if (filter === "all") return true;
  if (filter === "important") return item.verdict === "Malicious" || item.verdict === "Suspicious";
  return item.verdict === filter;
}

$all(".filter-chip").forEach(chip => {
  chip.addEventListener("click", () => {
    flaggedFilter = chip.dataset.filter;
    $all(".filter-chip").forEach(c => c.classList.remove("active"));
    chip.classList.add("active");
    renderFlaggedList();
  });
});

async function renderFlaggedItems() {
  flaggedItemsCache = await api("/api/scan/full/flagged");

  const counts = { Malicious: 0, Suspicious: 0, ScanError: 0 };
  flaggedItemsCache.forEach(i => { counts[i.verdict] = (counts[i.verdict] || 0) + 1; });
  $("#fcMalicious").textContent = counts.Malicious;
  $("#fcSuspicious").textContent = counts.Suspicious;
  $("#fcError").textContent = counts.ScanError;
  $("#fcImportant").textContent = counts.Malicious + counts.Suspicious;
  $("#fcAll").textContent = flaggedItemsCache.length;

  renderFlaggedList();
}

function renderFlaggedList() {
  const items = flaggedItemsCache.filter(i => matchesFilter(i, flaggedFilter));
  const ul = $("#flaggedList");
  $("#flaggedEmpty").style.display = items.length ? "none" : "block";

  // Phan tich nguyen nhan loi — chi hien khi dang loc rieng "Loi doc file".
  const breakdownEl = $("#errorBreakdown");
  if (flaggedFilter === "ScanError") {
    const byCode = {};
    items.forEach(i => {
      const code = parseErrorCode(i.reason);
      byCode[code] = (byCode[code] || 0) + 1;
    });
    const sorted = Object.entries(byCode).sort((a, b) => b[1] - a[1]);
    breakdownEl.innerHTML = sorted.map(([code, count]) => `
      <div class="eb-item">
        <div class="eb-code">${esc(code)}</div>
        <div class="eb-count">${count.toLocaleString("vi-VN")}</div>
        <div class="eb-desc">${esc(ERROR_CODE_INFO[code] || ERROR_CODE_INFO.OTHER)}</div>
      </div>`).join("");
    breakdownEl.style.display = sorted.length ? "grid" : "none";
  } else {
    breakdownEl.style.display = "none";
  }

  // Gioi han hien thi 500 dong gan nhat de tranh render qua nang neu so
  // luong loi len toi hang nghin — nguoi dung van xem duoc tong so qua chip.
  const MAX_RENDER = 500;
  const toRender = items.slice().reverse().slice(0, MAX_RENDER);

  ul.innerHTML = "";
  toRender.forEach(item => {
    const li = document.createElement("li");
    li.className = "flagged-item " + item.verdict.toLowerCase();
    // [SUA THEO YEU CAU NGUOI DUNG] Duong dan day du (co the rat dai, vi du
    // WinSxS) tran man hinh trong luc dang quet — chi can biet TEN FILE
    // ngay tuc thi, duong dan day du van xem duoc khi bam vao xem chi tiet
    // (showFlaggedDetail) hoac di chuot vao (title attribute).
    const { dir, name } = splitPathForDisplay(item.filePath);
    li.innerHTML = `
      <span>${esc(verdictIcon(item.verdict))} <b>${esc(item.verdict)}</b></span>
      <span class="fi-path" title="${esc(item.filePath)}">${dir ? `<span class="fp-dir">${esc(dir)}</span>` : ""}${esc(name)}</span>
      <span class="fi-time">${esc(fmtTime(item.flaggedAtUnixMs))}</span>`;
    li.addEventListener("click", () => showFlaggedDetail(item));
    ul.appendChild(li);
  });

  if (items.length > MAX_RENDER) {
    const li = document.createElement("li");
    li.className = "flagged-item";
    li.style.cursor = "default";
    li.innerHTML = `<span class="muted small">… và ${(items.length - MAX_RENDER).toLocaleString("vi-VN")} mục khác (dùng bộ lọc để thu hẹp).</span>`;
    ul.appendChild(li);
  }
}

function showFlaggedDetail(item) {
  $("#fdIcon").textContent = verdictIcon(item.verdict);
  $("#fdVerdict").textContent = item.verdict;
  $("#fdPath").textContent = item.filePath;
  $("#fdStage").textContent = item.stage;
  $("#fdHash").textContent = item.sha256Hex || "(không có)";
  $("#fdTime").textContent = new Date(item.flaggedAtUnixMs).toLocaleString("vi-VN");
  $("#fdReason").textContent = item.reason;
  $("#flaggedDetailModal").classList.add("show");
}
$("#fdClose").addEventListener("click", () => $("#flaggedDetailModal").classList.remove("show"));

// ---------- Quarantine (UI-03) ----------
async function renderQuarantine() {
  const list = await refreshQuarantineSummary();
  const tbody = $("#quarantineTable tbody");
  tbody.innerHTML = "";
  $("#quarantineEmpty").style.display = list.length ? "none" : "block";

  list.forEach(r => {
    const tr = document.createElement("tr");
    const statusLabel = { Active: "Chưa xử lý", PendingManualConfirmation: "Chờ xác nhận thủ công", Quarantined: "Đã cách ly", Restored: "Đã khôi phục" }[r.status] || r.status;
    tr.innerHTML = `
      <td>${esc(r.originalFilename)}<br><span class="muted small">${esc(r.originalPath)}</span></td>
      <td class="mono">${esc(shortHash(r.sha256Hash))}</td>
      <td class="muted small">${esc(r.detectionReason)}</td>
      <td><span class="pill ${r.status === "Quarantined" ? "pill-ok" : r.status === "PendingManualConfirmation" ? "pill-warn" : ""}">${esc(statusLabel)}</span></td>
      <td class="muted small">${esc(new Date(r.quarantinedAt * 1000).toLocaleString("vi-VN"))}</td>
      <td></td>`;
    const actionsTd = tr.lastElementChild;
    if (r.status === "Quarantined") {
      const btn = document.createElement("button");
      btn.className = "btn btn-ghost btn-sm";
      btn.textContent = "Khôi phục";
      btn.onclick = () => api(`/api/quarantine/${r.quarantineId}/restore`, { method: "POST" }).then(renderQuarantine).catch(e => toast("Khôi phục thất bại", e.message, "danger"));
      actionsTd.appendChild(btn);
    } else if (r.status === "PendingManualConfirmation") {
      const btn = document.createElement("button");
      btn.className = "btn btn-danger btn-sm";
      btn.textContent = "Xác nhận cách ly";
      btn.onclick = () => api(`/api/quarantine/${r.quarantineId}/confirm`, { method: "POST" }).then(renderQuarantine)
        .catch(e => toast("Xác nhận thất bại", e.message, "danger"));
      actionsTd.appendChild(btn);
    }

    // [TINH NANG THEO YEU CAU NGUOI DUNG] "Quarantine co xoa duoc khong" —
    // xoa VINH VIEN (khac Khoi phuc, khong the hoan tac).
    const delBtn = document.createElement("button");
    delBtn.className = "btn btn-danger btn-sm";
    delBtn.textContent = "Xoá vĩnh viễn";
    delBtn.style.marginLeft = "6px";
    delBtn.onclick = () => {
      const msg = r.status === "PendingManualConfirmation"
        ? "File gốc VẪN CÒN nguyên vị trí (chưa từng bị cách ly) — thao tác này chỉ xoá mục theo dõi này, không đụng tới file. Tiếp tục?"
        : "Xoá vĩnh viễn file đã cách ly này, KHÔNG THỂ khôi phục lại sau đó. Tiếp tục?";
      if (!confirm(msg)) return;
      api(`/api/quarantine/${r.quarantineId}`, { method: "DELETE" })
        .then(renderQuarantine)
        .catch(e => toast("Xoá thất bại", e.message, "danger"));
    };
    actionsTd.appendChild(delBtn);

    tbody.appendChild(tr);
  });
}

// ---------- Rules (UI-04) ----------
$("#ruleAddBtn").addEventListener("click", async () => {
  const rule = {
    sha256Hash: $("#ruleHash").value.trim() || "(trống)",
    publisherThumbprint: $("#rulePublisher").value.trim() || null,
    filePath: $("#rulePath").value.trim() || "(không rõ)",
    action: $("#ruleAction").value,
    scope: $("#ruleScope").value,
    createdBy: "User",
  };
  await api("/api/rules", { method: "POST", body: JSON.stringify(rule) });
  $("#ruleHash").value = ""; $("#rulePublisher").value = ""; $("#rulePath").value = "";
  renderRules();
});

async function renderRules() {
  const rules = await refreshRulesSummary();
  const tbody = $("#rulesTable tbody");
  tbody.innerHTML = "";
  rules.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(r.id)}</td>
      <td class="mono">${esc(shortHash(r.sha256Hash))}</td>
      <td class="mono">${r.publisherThumbprint ? esc(shortHash(r.publisherThumbprint)) : "—"}</td>
      <td class="muted small">${esc(r.filePath)}</td>
      <td><span class="pill ${r.action === "Allow" ? "pill-ok" : "pill-danger"}">${esc(r.action)}</span></td>
      <td>${esc(r.scope)}</td>
      <td class="muted small">${esc(r.createdBy)}</td>
      <td></td>`;
    const btn = document.createElement("button");
    btn.className = "btn btn-ghost btn-sm";
    btn.textContent = "Xoá";
    btn.onclick = () => api(`/api/rules/${r.id}`, { method: "DELETE" }).then(renderRules)
      .catch(e => toast("Xoá thất bại", e.message, "danger"));
    tr.lastElementChild.appendChild(btn);
    tbody.appendChild(tr);
  });
}

// ---------- Downloads pending (UI-06) ----------
async function renderDownloads() {
  const list = await api("/api/downloads/pending");
  const ul = $("#downloadsList");
  ul.innerHTML = "";
  $("#downloadsEmpty").style.display = list.length ? "none" : "block";
  list.forEach(item => {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="pending-info">
        <span class="path">${esc(item.filePath)}</span>
        <span class="muted small">${esc(item.reason)}</span>
      </div>
      <div class="pending-actions"></div>`;
    const actions = li.querySelector(".pending-actions");
    [["Xoá", "delete", "btn-danger"], ["Cách ly", "quarantine", "btn-primary"], ["Bỏ qua", "ignore", "btn-ghost"]].forEach(([label, action, cls]) => {
      const b = document.createElement("button");
      b.className = `btn btn-sm ${cls}`;
      b.textContent = label;
      b.onclick = () => api(`/api/downloads/${item.itemId}/action`, { method: "POST", body: JSON.stringify({ action }) }).then(renderDownloads)
        .catch(e => toast("Thao tác thất bại", e.message, "danger"));
      actions.appendChild(b);
    });
    ul.appendChild(li);
  });
}

// ---------- Audit (UI-07) ----------
async function renderAudit() {
  const events = await api("/api/audit?limit=200");
  const ul = $("#auditList");
  ul.innerHTML = "";
  events.forEach(e => {
    renderLogLi(ul, {
      timeMs: e.timestampUnixMs,
      level: logLevelFromSummary(e.summary),
      bodyHtml: `<b>${esc(e.category)}</b> — ${esc(e.summary)}`,
    });
  });

  const { sizeBytes } = await api("/api/audit/file-size");
  $("#auditFileSize").textContent = `File nhật ký trên đĩa: ${(sizeBytes / (1024 * 1024)).toFixed(2)} MB (tự động dọn khi vượt 20MB)`;
}

// [TINH NANG THEO YEU CAU NGUOI DUNG] "co co che nao xoa log tu dong va
// thu cong khong" — hai nut thu cong, co che tu dong xem AuditLogMaintenanceService.
$("#auditPruneBtn").addEventListener("click", async () => {
  try {
    const r = await api("/api/audit/prune", { method: "POST" });
    toast("Đã dọn nhật ký", `Xoá ${r.removed.toLocaleString("vi-VN")} dòng cũ, giữ lại 20.000 dòng gần nhất.`);
    renderAudit();
  } catch (e) {
    toast("Dọn nhật ký thất bại", e.message, "danger");
  }
});
$("#auditClearBtn").addEventListener("click", async () => {
  if (!confirm("Xoá TOÀN BỘ nhật ký hoạt động, không thể hoàn tác. Tiếp tục?")) return;
  try {
    await api("/api/audit", { method: "DELETE" });
    toast("Đã xoá toàn bộ nhật ký", "");
    renderAudit();
  } catch (e) {
    toast("Xoá nhật ký thất bại", e.message, "danger");
  }
});

// ---------- Update (UI-08) ----------
$("#updCheckBtn").addEventListener("click", async () => {
  $("#updCheckBtn").disabled = true;
  try {
    await api("/api/update/check-now", { method: "POST" });
    await refreshStatus();
  } finally {
    $("#updCheckBtn").disabled = false;
  }
});

// ---------- Permission modal (SEC-02/03): hop thoai xin quyen ----------
// Nut "Cho phep luon" KHONG duoc focus san va co tre toi thieu 0.5s truoc
// khi nhan input, chong malware tu dong gui phim Enter/click gia lap.
let currentPermissionRequest = null;

function showPermissionModal(req) {
  currentPermissionRequest = req;
  $("#pmPath").textContent = req.processPath;
  $("#pmPublisher").textContent = req.publisherName || "Không xác định";
  $("#pmHash").textContent = shortHash(req.sha256Hex);
  $("#permissionModal").classList.add("show");

  const allowBtn = $("#pmAllow");
  allowBtn.disabled = true;
  allowBtn.blur();
  setTimeout(() => { if (currentPermissionRequest === req) allowBtn.disabled = false; }, 500);
}

function hidePermissionModal() {
  currentPermissionRequest = null;
  $("#permissionModal").classList.remove("show");
}

async function respondPermission(choice) {
  if (!currentPermissionRequest) return;
  const id = currentPermissionRequest.requestId;
  hidePermissionModal();
  await api(`/api/permission-requests/${id}/respond`, { method: "POST", body: JSON.stringify({ choice }) });
}

$("#pmAllow").addEventListener("click", () => respondPermission("AllowAlways"));
$("#pmOnce").addEventListener("click", () => respondPermission("AllowOnce"));
$("#pmBlock").addEventListener("click", () => respondPermission("Block"));

async function pollPermissionRequests() {
  const pending = await api("/api/permission-requests");
  if (pending.length > 0 && !currentPermissionRequest) {
    showPermissionModal(pending[0]);
  } else if (pending.length === 0 && currentPermissionRequest) {
    hidePermissionModal();
  }
}

// ---------- Toast on new malicious/suspicious audit events ----------
let lastSeenAuditEventId = null;
async function pollAuditForToasts() {
  const events = await api("/api/audit?limit=5");
  if (!events.length) return;
  if (lastSeenAuditEventId === null) { lastSeenAuditEventId = events[0].eventId; return; }
  const newOnes = [];
  for (const e of events) {
    if (e.eventId === lastSeenAuditEventId) break;
    newOnes.push(e);
  }
  lastSeenAuditEventId = events[0].eventId;
  newOnes.reverse().forEach(e => {
    if (/MALICIOUS/i.test(e.summary)) toast("Phát hiện mã độc", e.summary, "danger");
    else if (/SUSPICIOUS/i.test(e.summary)) toast("Cảnh báo nghi ngờ", e.summary, "warn");
  });
}

// ---------- Risk score tong hop (EXT-RISK-01/02) ----------
const RISK_LABEL_META = {
  "An toan": { text: "An toàn", ring: "risk-safe" },
  "Can chu y": { text: "Cần chú ý", ring: "risk-warn" },
  "Rui ro cao": { text: "Rủi ro cao", ring: "risk-danger" },
};
const RING_CIRCUMFERENCE = 326.7; // 2 * PI * 52, khop voi r=52 cua vong tron SVG

async function refreshRiskScore() {
  const r = await api("/api/risk-score");
  const meta = RISK_LABEL_META[r.label] || { text: r.label, ring: "risk-warn" };

  const ring = $("#riskRing");
  ring.style.strokeDashoffset = String(RING_CIRCUMFERENCE * (1 - r.score / 100));
  ring.classList.remove("risk-safe", "risk-warn", "risk-danger");
  ring.classList.add(meta.ring);

  $("#riskScoreNum").textContent = r.score;
  $("#riskScoreLabel").textContent = meta.text;

  const deducted = r.components.filter(c => c.pointsDeducted > 0);
  $("#riskComponents").innerHTML = deducted.length
    ? deducted.map(c => `<div class="meta-row"><span>${esc(c.name)}</span><b class="pill pill-warn">-${esc(c.pointsDeducted)} · ${esc(c.detail)}</b></div>`).join("")
    : `<div class="meta-row"><span class="muted small">Không có mục nào đang trừ điểm — mọi lớp bảo vệ đều ổn.</span></div>`;
}

// ---------- Gaming mode + Task scheduler (dashboard + Nang cao) ----------
async function refreshGamingAndScheduler() {
  const gaming = await api("/api/gaming-mode");
  $("#gamingModeStatus").textContent = gaming.active ? "Đang bật" : "Tắt";
  $("#gamingModeStatus").className = "pill " + (gaming.active ? "pill-warn" : "pill-ok");

  const idle = await api("/api/scheduler/idle");
  const idleLabel = idle.idle ? "Idle" : "Đang bận";
  const idleCls = "pill " + (idle.idle ? "pill-ok" : "pill-warn");
  $("#schedulerIdleStatus").textContent = idleLabel;
  $("#schedulerIdleStatus").className = idleCls;
  $("#advSchedulerIdle").textContent = idleLabel;
  $("#advSchedulerIdle").className = idleCls;

  const regs = await api("/api/scheduler/registrations");
  $("#schedulerTaskCount").textContent = regs.length;
  $("#schedulerTable tbody").innerHTML = regs.map(reg => `
    <tr>
      <td class="mono">${esc(reg.taskId)}</td>
      <td>${esc(reg.resourceClass)}</td>
      <td>${esc(reg.priority)}</td>
      <td>${reg.requiresIdle ? "Có" : "Không"}</td>
      <td class="muted small">${esc(reg.maxDurationBeforeYield)}</td>
    </tr>`).join("");
}

// ---------- Firewall (EXT-FW) ----------
async function renderFirewall() {
  const rules = await api("/api/firewall/rules");
  const tbody = $("#fwRulesTable tbody");
  tbody.innerHTML = "";
  rules.forEach(r => {
    const tr = document.createElement("tr");
    const portLabel = r.remotePortStart != null
      ? `${r.remotePortStart}${r.remotePortEnd && r.remotePortEnd !== r.remotePortStart ? "-" + r.remotePortEnd : ""}`
      : "Bất kỳ";
    tr.innerHTML = `
      <td>${esc(r.id)}</td>
      <td class="mono">${esc(shortHash(r.appSha256))}</td>
      <td>${esc(r.direction)}</td>
      <td>${esc(r.protocol)}</td>
      <td>${esc(portLabel)}</td>
      <td><span class="pill ${r.action === "Allow" ? "pill-ok" : "pill-danger"}">${esc(r.action)}</span></td>
      <td>${esc(r.priority)}</td>
      <td></td>`;
    const btn = document.createElement("button");
    btn.className = "btn btn-ghost btn-sm";
    btn.textContent = "Xoá";
    btn.onclick = () => api(`/api/firewall/rules/${r.id}`, { method: "DELETE" }).then(renderFirewall)
      .catch(e => toast("Xoá thất bại", e.message, "danger"));
    tr.lastElementChild.appendChild(btn);
    tbody.appendChild(tr);
  });

  const suspicions = await api("/api/firewall/beacon-suspicions");
  const ul = $("#beaconList");
  ul.innerHTML = "";
  $("#beaconEmpty").style.display = suspicions.length ? "none" : "block";
  suspicions.slice().reverse().forEach(s => {
    // Beacon suspicion luon la tin hieu tham khao, KHONG tu chan (theo dung
    // tai lieu) — dat co dinh muc WARN, khong bao gio CRIT.
    renderLogLi(ul, {
      timeMs: s.detectedAtUnixMs,
      level: "warn",
      bodyHtml: `<b>PID ${esc(s.pid)}</b> ${esc(s.processPath)} → ${esc(s.remoteAddress)}${s.resolvedHostname ? " (" + esc(s.resolvedHostname) + ")" : ""} — ${esc(s.reason)}`,
    });
  });
}

$("#fwAddBtn").addEventListener("click", async () => {
  const rule = {
    appSha256: $("#fwSha256").value.trim() || "(trống)",
    direction: $("#fwDirection").value,
    protocol: $("#fwProtocol").value,
    remotePortStart: $("#fwPortStart").value.trim() ? Number($("#fwPortStart").value.trim()) : null,
    remotePortEnd: $("#fwPortEnd").value.trim() ? Number($("#fwPortEnd").value.trim()) : null,
    action: $("#fwAction").value,
    priority: Number($("#fwPriority").value.trim() || "100"),
    createdBy: "User",
  };
  await api("/api/firewall/rules", { method: "POST", body: JSON.stringify(rule) });
  $("#fwSha256").value = ""; $("#fwPortStart").value = ""; $("#fwPortEnd").value = "";
  renderFirewall();
});

// ---------- Ransomware (EXT-RW) ----------
async function renderRansomware() {
  const folders = await api("/api/ransomware/protected-folders");
  $("#rwProtectedFolders").innerHTML = folders.map(f => `<div>${esc(f)}</div>`).join("") || "Không có thư mục nào.";

  const alerts = await api("/api/ransomware/alerts");
  const ul = $("#rwAlertsList");
  ul.innerHTML = "";
  $("#rwAlertsEmpty").style.display = alerts.length ? "none" : "block";
  alerts.slice().reverse().forEach(a => {
    const signalCount = a.writeRateSignal + a.entropyJumpSignal + a.extensionBurstSignal;
    const level = a.autoRolledBack ? "crit" : (signalCount >= 2 ? "warn" : "info");
    renderLogLi(ul, {
      timeMs: a.detectedAtUnixMs,
      level,
      bodyHtml: `<b>${a.autoRolledBack ? "ĐÃ ROLLBACK" : "THEO DÕI"}</b> ${esc(a.affectedPaths.length)} file, đuôi "${esc(a.commonNewExtension)}" (tín hiệu: ghi=${a.writeRateSignal} entropy=${a.entropyJumpSignal} đổi-đuôi=${a.extensionBurstSignal})`,
    });
  });

  const versions = await api("/api/ransomware/version-store");
  const tbody = $("#rwVersionTable tbody");
  tbody.innerHTML = "";
  versions.forEach(v => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(v.originalPath)}</td>
      <td class="muted small">${esc(fmtTime(v.versionTimestampUnixMs))}</td>
      <td class="muted small">${(v.fileSize / 1024).toFixed(1)} KB</td>
      <td></td>`;
    const btn = document.createElement("button");
    btn.className = "btn btn-primary btn-sm";
    btn.textContent = "Khôi phục";
    btn.onclick = () => api("/api/ransomware/restore", { method: "POST", body: JSON.stringify({ path: v.originalPath }) })
      .then(() => toast("Đã khôi phục", v.originalPath))
      .catch(e => toast("Khôi phục thất bại", e.message, "danger"));
    tr.lastElementChild.appendChild(btn);
    tbody.appendChild(tr);
  });
}

// ---------- USB (EXT-USB) ----------
async function renderUsb() {
  const rules = await api("/api/usb/rules");
  const tbody = $("#usbRulesTable tbody");
  tbody.innerHTML = "";
  rules.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(r.id)}</td>
      <td class="mono">${esc(r.vendorId)}</td>
      <td class="mono">${esc(r.productId)}</td>
      <td class="mono">${r.serialNumber ? esc(r.serialNumber) : "(mọi thiết bị)"}</td>
      <td><span class="pill ${r.action === "Allow" ? "pill-ok" : r.action === "Block" ? "pill-danger" : "pill-warn"}">${esc(r.action)}</span></td>
      <td>${r.autoScan ? "Có" : "Không"}</td>
      <td></td>`;
    const btn = document.createElement("button");
    btn.className = "btn btn-ghost btn-sm";
    btn.textContent = "Xoá";
    btn.onclick = () => api(`/api/usb/rules/${r.id}`, { method: "DELETE" }).then(renderUsb)
      .catch(e => toast("Xoá thất bại", e.message, "danger"));
    tr.lastElementChild.appendChild(btn);
    tbody.appendChild(tr);
  });

  const arrivals = await api("/api/usb/devices");
  const ul = $("#usbArrivalsList");
  ul.innerHTML = "";
  $("#usbArrivalsEmpty").style.display = arrivals.length ? "none" : "block";
  arrivals.slice().reverse().forEach(a => {
    const level = a.resolvedAction === "Block" ? "crit" : (a.resolvedAction === "Ask" ? "warn" : "info");
    renderLogLi(ul, {
      timeMs: a.detectedAtUnixMs,
      level,
      bodyHtml: `<b>${esc(a.driveLetter)}</b> VID=${esc(a.vendorId)} PID=${esc(a.productId)} — chính sách: ${esc(a.resolvedAction)}${a.autoScanTriggered ? " (đã tự động quét)" : ""}`,
    });
  });
}

$("#usbAddBtn").addEventListener("click", async () => {
  const rule = {
    vendorId: $("#usbVid").value.trim().toUpperCase(),
    productId: $("#usbPid").value.trim().toUpperCase(),
    serialNumber: $("#usbSerial").value.trim() || null,
    action: $("#usbAction").value,
    autoScan: $("#usbAutoScan").checked,
  };
  if (!rule.vendorId || !rule.productId) { toast("Thiếu VID/PID", "Cần nhập cả Vendor ID và Product ID.", "warn"); return; }
  await api("/api/usb/rules", { method: "POST", body: JSON.stringify(rule) });
  $("#usbVid").value = ""; $("#usbPid").value = ""; $("#usbSerial").value = "";
  renderUsb();
});

// ---------- Vulnerability scan (EXT-VULN) ----------
async function renderVuln() {
  const findings = await api("/api/vulnerabilities");
  $("#vulnMeta").textContent = `${findings.length} lỗ hổng (demo)`;
  const tbody = $("#vulnTable tbody");
  tbody.innerHTML = "";
  $("#vulnEmpty").style.display = findings.length ? "none" : "block";
  findings.forEach(f => {
    const tr = document.createElement("tr");
    const sevCls = f.severityScore >= 9 ? "pill-danger" : f.severityScore >= 7 ? "pill-warn" : "pill-ok";
    tr.innerHTML = `
      <td>${esc(f.softwareName)}</td>
      <td class="mono">${esc(f.installedVersion)}</td>
      <td class="mono">${esc(f.cveId)}</td>
      <td><span class="pill ${sevCls}">${esc(f.severityScore)}</span></td>
      <td class="muted small">Cập nhật lên ${esc(f.fixAvailableVersion)}</td>`;
    tbody.appendChild(tr);
  });
}

$("#vulnScanBtn").addEventListener("click", async () => {
  $("#vulnScanBtn").disabled = true;
  try { await api("/api/vulnerabilities/scan-now", { method: "POST" }); await renderVuln(); }
  finally { $("#vulnScanBtn").disabled = false; }
});

// ---------- Webcam/Mic (EXT-CAM) ----------
async function renderPrivacy() {
  const whitelist = await api("/api/cam-mic/whitelist");
  const tbody = $("#camWhitelistTable tbody");
  tbody.innerHTML = "";
  whitelist.forEach(w => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(w.id)}</td><td class="mono">${esc(w.processIdentity)}</td><td class="muted small">${esc(w.addedBy)}</td><td></td>`;
    const btn = document.createElement("button");
    btn.className = "btn btn-ghost btn-sm";
    btn.textContent = "Xoá";
    btn.onclick = () => api(`/api/cam-mic/whitelist/${w.id}`, { method: "DELETE" }).then(renderPrivacy)
      .catch(e => toast("Xoá thất bại", e.message, "danger"));
    tr.lastElementChild.appendChild(btn);
    tbody.appendChild(tr);
  });

  const accesses = await api("/api/cam-mic/accesses");
  const ul = $("#camAccessList");
  ul.innerHTML = "";
  $("#camAccessEmpty").style.display = accesses.length ? "none" : "block";
  accesses.slice().reverse().forEach(a => {
    // Chua whitelist -> CANH BAO (warn), khong phai CRIT — module nay chi
    // canh bao, khong bao gio tu dong chan (dung tinh than tai lieu goc).
    renderLogLi(ul, {
      timeMs: a.detectedAtUnixMs,
      level: a.whitelisted ? "info" : "warn",
      bodyHtml: `<b>${esc(a.deviceType)}</b> ${esc(a.processIdentity)}${a.whitelisted ? " (đã whitelist)" : " — CHƯA whitelist"}`,
    });
  });
}

$("#camWhitelistAddBtn").addEventListener("click", async () => {
  const identity = $("#camWhitelistPath").value.trim();
  if (!identity) return;
  await api("/api/cam-mic/whitelist", { method: "POST", body: JSON.stringify({ processIdentity: identity }) });
  $("#camWhitelistPath").value = "";
  renderPrivacy();
});

// ---------- Home network (EXT-NET) ----------
async function renderNetwork() {
  const devices = await api("/api/home-network/devices");
  const tbody = $("#netDevicesTable tbody");
  tbody.innerHTML = "";
  $("#netDevicesEmpty").style.display = devices.length ? "none" : "block";
  devices.forEach(d => {
    const tr = document.createElement("tr");
    const sources = [d.seenViaArp && "ARP", d.seenViaMdns && "mDNS", d.seenViaSsdp && "SSDP"].filter(Boolean).join(", ") || "—";
    tr.innerHTML = `
      <td>${esc(d.discoveredName || d.vendor)}${d.isNewDevice ? ' <span class="sev-badge sev-med">MỚI</span>' : ""}</td>
      <td class="mono">${esc(d.ipAddress)}</td>
      <td class="mono">${esc(d.macAddress || "—")}</td>
      <td>${esc(d.vendor)}</td>
      <td class="muted small">${esc(sources)}</td>
      <td>${d.openAdminPorts && d.openAdminPorts.length ? `<span class="pill pill-warn">${esc(d.openAdminPorts.join(", "))}</span>` : "—"}</td>`;
    tbody.appendChild(tr);
  });
}

// ---------- Alert Center (EXT-EVT) ----------
async function renderAlertCenter() {
  const alerts = await api("/api/alerts");
  const ul = $("#alertCenterList");
  ul.innerHTML = "";
  $("#alertCenterEmpty").style.display = alerts.length ? "none" : "block";
  alerts.forEach(a => {
    const level = a.maxSeverity >= 70 ? "crit" : a.maxSeverity >= 35 ? "warn" : "info";
    const lastLine = a.summaryLines[a.summaryLines.length - 1] || "";
    renderLogLi(ul, {
      timeMs: a.lastUpdateUnixMs,
      level,
      bodyHtml: `<b>[${esc(a.maxSeverity)}] ${esc(a.sourceEngines.join(" + "))}</b> — ${esc(lastLine)}`,
    });
  });
}

// ---------- Nang cao: Cloud intel / Sandbox / Phishing / Scheduler ----------
$("#cloudLookupBtn").addEventListener("click", async () => {
  const sha256 = $("#cloudHashInput").value.trim();
  if (!sha256) return;
  $("#cloudLookupResult").textContent = "Đang tra cứu…";
  try {
    const r = await api("/api/cloud-intel/lookup", { method: "POST", body: JSON.stringify({ sha256 }) });
    $("#cloudLookupResult").innerHTML =
      `Verdict: <b>${esc(r.verdict)}</b> · Prevalence: <b>${esc(r.prevalence)}</b>` +
      (r.prevalence === 0 ? ' <span class="sev-badge sev-med">CHƯA TỪNG THẤY</span>' : "");
  } catch (e) {
    $("#cloudLookupResult").textContent = "Lỗi: " + e.message;
  }
});

const SANDBOX_DEMOS = {
  injection: [
    { apiName: "WriteProcessMemory", category: "ProcessInjection", timestampMs: 1000 },
    { apiName: "CreateRemoteThread", category: "ProcessInjection", timestampMs: 1050 },
  ],
  autorun: [
    { apiName: "RegSetValueExW", category: "RegistryAutorun", timestampMs: 1000, detail: "HKCU\\...\\Run" },
  ],
  network: Array.from({ length: 6 }, (_, i) => ({ apiName: "connect", category: "Network", timestampMs: 1000 + i * 500 })),
  benign: [
    { apiName: "WriteFile", category: "FileWrite", timestampMs: 1000 },
  ],
};

$all("[data-sandbox-demo]").forEach(btn => {
  btn.addEventListener("click", async () => {
    const calls = SANDBOX_DEMOS[btn.dataset.sandboxDemo];
    const r = await api("/api/sandbox/evaluate", { method: "POST", body: JSON.stringify(calls) });
    const cls = r.verdict === "Malicious" ? "verdict-malicious" : r.verdict === "Suspicious" ? "verdict-suspicious" : "verdict-clean";
    $("#sandboxResult").innerHTML =
      `<span class="verdict ${cls}">${esc(r.verdict)}</span><span class="mono">score=${esc(r.score)}</span>` +
      (r.noBehaviorObserved ? '<br><span class="muted small">(không quan sát được hành vi đáng chú ý trong thời gian detonation)</span>' : "") +
      "<br>" + r.reasons.map(x => "• " + esc(x)).join("<br>");
  });
});

$("#phishCheckBtn").addEventListener("click", async () => {
  const url = $("#phishUrlInput").value.trim();
  if (!url) return;
  const r = await api("/api/phishing/check-url", { method: "POST", body: JSON.stringify({ url }) });
  $("#phishCheckResult").innerHTML = r.malicious
    ? `<span class="verdict verdict-malicious">CHẶN</span> khớp ${esc(r.matchedOn)}: ${esc(r.matchedValue)}`
    : `<span class="verdict verdict-clean">AN TOÀN</span> không khớp danh sách phishing hiện có`;
});

async function refreshPhishStats() {
  const s = await api("/api/phishing/stats");
  $("#phishStatsMeta").textContent = `v${s.version} — ${s.domains} domain, ${s.ips} IP`;
}

$("#phishUpdateBtn").addEventListener("click", async () => {
  $("#phishUpdateBtn").disabled = true;
  try {
    const r = await api("/api/phishing/update-now", { method: "POST" });
    toast(r.success ? "Đã kiểm tra cập nhật" : "Cập nhật thất bại", "Xem chi tiết trong Nhật ký.", r.success ? "" : "warn");
    await refreshPhishStats();
  } finally {
    $("#phishUpdateBtn").disabled = false;
  }
});

// ---------- Polling loop ----------
// [SUA LOI HIEU NANG] TRUOC DAY tick() luon lam moi VA VE LAI TOAN BO 4
// bang "nang" (quarantine/rules/downloads/flagged — moi bang xoa het
// innerHTML roi dung lai tu dau) MOI 1.5 GIAY, BAT KE nguoi dung dang xem
// tab nao (vi du dang o tab "Firewall", 4 bang tren van bi ve lai lien tuc
// trong khi khong ai nhin thay) VA bat ke ca trinh duyet/WebView2 co dang
// o foreground hay khong. Sua theo 2 huong, dung nguyen tac da co san o
// VIEW_RENDERERS ben duoi (cac view "nang" khac da chi render khi nguoi
// dung bam vao xem):
//   1. document.hidden (Page Visibility API): bo qua CA vong tick neu tab/
//      cua so dang o nen (khong ai nhin thay ket qua polling luc do).
//   2. currentView: 4 bang tren CHI duoc lam moi khi dung la tab dang xem,
//      thay vi luon luon ca 4 bat ke dang o dau.
async function tick() {
  if (document.hidden) return;
  try {
    const tasks = [
      refreshStatus(),
      refreshDashboardLog(),
      refreshScanProgress(),
      refreshCacheToggle(),
      pollPermissionRequests(),
      pollAuditForToasts(),
      refreshRiskScore(),
      refreshGamingAndScheduler(),
      refreshPhishStats(),
    ];
    if (currentView === "quarantine") tasks.push(renderQuarantine());
    if (currentView === "rules") tasks.push(renderRules());
    if (currentView === "downloads") tasks.push(renderDownloads());
    if (currentView === "scan") tasks.push(renderFlaggedItems());
    await Promise.all(tasks);
  } catch (e) {
    setConnected(false);
  }
}

// Cac view "nang" (bang du lieu nhieu module moi) chi render khi nguoi
// dung thuc su mo xem, tranh polling lang phi cho du lieu it thay doi.
const VIEW_RENDERERS = {
  audit: renderAudit,
  firewall: renderFirewall,
  ransomware: renderRansomware,
  usb: renderUsb,
  vuln: renderVuln,
  privacy: renderPrivacy,
  network: renderNetwork,
  alerts: renderAlertCenter,
  // [SUA LOI HIEU NANG] Them 4 view nay vao day de render NGAY khi nguoi
  // dung bam chuyen tab (giong het cac view khac o tren) — tranh do tre
  // toi da 1.5s (mot chu ky tick) truoc khi noi dung xuat hien, vi tick()
  // gio chi lam moi 4 bang nay khi currentView da khop (xem tick() o tren).
  quarantine: renderQuarantine,
  rules: renderRules,
  downloads: renderDownloads,
  scan: renderFlaggedItems,
};
$all(".nav-item").forEach(btn => {
  const renderFn = VIEW_RENDERERS[btn.dataset.view];
  if (renderFn) btn.addEventListener("click", renderFn);
});

tick();
setInterval(tick, 1500);
