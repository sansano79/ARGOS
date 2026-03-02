import { useState, useEffect, useCallback, useRef } from "react";

// ─── Config ──────────────────────────────────────────────────────────────────
const API_BASE = "/api";

// ─── Auth helpers ────────────────────────────────────────────────────────────
const getToken = () => localStorage.getItem("occ_token");
const setToken = (t) => localStorage.setItem("occ_token", t);
const clearToken = () => { localStorage.removeItem("occ_token"); localStorage.removeItem("occ_user"); };
const getUser = () => { try { return JSON.parse(localStorage.getItem("occ_user")); } catch { return null; } };
const setUser = (u) => localStorage.setItem("occ_user", JSON.stringify(u));
const getResetTokenFromPath = () => {
  const m = window.location.pathname.match(/^\/reset-password\/([^/]+)$/);
  return m?.[1] ? decodeURIComponent(m[1]) : "";
};

const apiFetch = async (url, opts = {}) => {
  const token = getToken();
  const headers = { ...opts.headers };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (opts.body && typeof opts.body === "string") headers["Content-Type"] = "application/json";
  const res = await fetch(`${API_BASE}${url}`, { ...opts, headers });
  if (res.status === 401) { clearToken(); window.location.reload(); throw new Error("Unauthorized"); }
  return res;
};
const BACKFILL_ENDPOINTS = [
  "/vulnerabilities/nvd/backfill/lastmodified",
  "/vulnerability-collector/nvd/backfill/lastmodified",
];
const readResponsePayload = async (res) => {
  const raw = await res.text();
  if (!raw) return { raw: "", json: {} };
  try { return { raw, json: JSON.parse(raw) }; } catch { return { raw, json: {} }; }
};
const callBackfillApi = async (suffix, opts = {}) => {
  let lastErr = "";
  for (const base of BACKFILL_ENDPOINTS) {
    const path = `${base}${suffix}`;
    try {
      const res = await apiFetch(path, opts);
      const payload = await readResponsePayload(res);
      if (!res.ok) {
        const msg = payload.json?.message || payload.json?.error || payload.raw || `HTTP ${res.status}`;
        if (res.status === 404 || res.status === 405) {
          lastErr = `${path} no disponible (${res.status})`;
          continue;
        }
        throw new Error(`${msg} [${res.status}]`);
      }
      return payload.json;
    } catch (e) {
      lastErr = String(e?.message || e || "Error desconocido");
    }
  }
  throw new Error(lastErr || "No se pudo contactar con el endpoint de backfill");
};

// ─── SEIDOR Brand Colors ─────────────────────────────────────────────────────
const C = {
  navy: "#1B2A4A", navyDark: "#0F1B33", navyDeep: "#0A1628", navyLight: "#2A3F6A",
  blue: "#3B6CB5", blueLight: "#5A8FD4", bluePale: "#E8EFF8", accent: "#4ECDC4",
  white: "#FFFFFF", gray50: "#F8FAFB", gray100: "#EFF2F5", gray200: "#DDE2E8",
  gray300: "#C4CCD6", gray400: "#8E99A8", gray500: "#6B7688", gray600: "#4A5568",
  gray700: "#2D3748", text: "#1A202C",
  critical: "#DC2626", criticalBg: "#FEF2F2", high: "#EA580C", highBg: "#FFF7ED",
  medium: "#CA8A04", mediumBg: "#FEFCE8", low: "#16A34A", lowBg: "#F0FDF4",
  info: "#2563EB", infoBg: "#EFF6FF",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
const sevColor = (s) => ({ CRITICAL: C.critical, HIGH: C.high, MEDIUM: C.medium, LOW: C.low }[s] || C.gray500);
const sevBg = (s) => ({ CRITICAL: C.criticalBg, HIGH: C.highBg, MEDIUM: C.mediumBg, LOW: C.lowBg }[s] || C.gray100);
const timeAgo = (d) => { if (!d) return "-"; const s = Math.floor((Date.now() - new Date(d).getTime()) / 1000); if (s < 60) return `${s}s`; if (s < 3600) return `${Math.floor(s / 60)}m`; if (s < 86400) return `${Math.floor(s / 3600)}h`; return `${Math.floor(s / 86400)}d`; };
const fmtDate = (d) => d ? new Date(d).toLocaleString("es-ES", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "-";
const fmtEpss = (e) => e != null ? `${(parseFloat(e) * 100).toFixed(1)}%` : "-";
const fmtScore = (s) => s != null ? parseFloat(s).toFixed(1) : "-";
const fmtMs = (ms) => ms ? `${(ms / 1000).toFixed(1)}s` : "-";
const parseMaybeJsonObject = (value) => {
  if (!value) return {};
  if (typeof value === "object") return value;
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch { return {}; }
  }
  return {};
};

// ─── SVG Icons ───────────────────────────────────────────────────────────────
const I = ({ name, size = 18, color = "currentColor" }) => {
  const d = {
    shield: <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />,
    alert: <><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" fill="none" stroke={color} strokeWidth="1.5" /><line x1="12" y1="9" x2="12" y2="13" stroke={color} strokeWidth="1.5" /><circle cx="12" cy="17" r="0.5" fill={color} /></>,
    activity: <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />,
    download: <><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></>,
    refresh: <><polyline points="23 4 23 10 17 10" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></>,
    clock: <><circle cx="12" cy="12" r="10" fill="none" stroke={color} strokeWidth="1.5" /><polyline points="12 6 12 12 16 14" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" /></>,
    bug: <><path d="M8 2l1.88 1.88M14.12 3.88L16 2M9 7.13v-1a3 3 0 116 0v1M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 014-4h4a4 4 0 014 4v3c0 3.3-2.7 6-6 6zM12 20v-9M6.53 9C4.6 8.8 3 7.1 3 5M6 13H2M6 17H3M17.47 9C19.4 8.8 21 7.1 21 5M18 13h4M18 17h3" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></>,
    file: <><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" fill="none" stroke={color} strokeWidth="1.5" /><polyline points="14 2 14 8 20 8" fill="none" stroke={color} strokeWidth="1.5" /></>,
    check: <polyline points="20 6 9 17 4 12" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />,
    x: <><line x1="18" y1="6" x2="6" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" /><line x1="6" y1="6" x2="18" y2="18" stroke={color} strokeWidth="2" strokeLinecap="round" /></>,
    zap: <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />,
    server: <><rect x="2" y="2" width="20" height="8" rx="2" fill="none" stroke={color} strokeWidth="1.5" /><rect x="2" y="14" width="20" height="8" rx="2" fill="none" stroke={color} strokeWidth="1.5" /><circle cx="6" cy="6" r="0.5" fill={color} /><circle cx="6" cy="18" r="0.5" fill={color} /></>,
    search: <><circle cx="11" cy="11" r="8" fill="none" stroke={color} strokeWidth="1.5" /><line x1="21" y1="21" x2="16.65" y2="16.65" stroke={color} strokeWidth="1.5" strokeLinecap="round" /></>,
    users: <><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" fill="none" stroke={color} strokeWidth="1.5" /><circle cx="9" cy="7" r="4" fill="none" stroke={color} strokeWidth="1.5" /><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" fill="none" stroke={color} strokeWidth="1.5" /></>,
    mail: <><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" fill="none" stroke={color} strokeWidth="1.5" /><polyline points="22 6 12 13 2 6" fill="none" stroke={color} strokeWidth="1.5" /></>,
    brain: <><path d="M12 2a4 4 0 014 4v1a3 3 0 013 3 3 3 0 01-1 5.83V17a4 4 0 01-4 4h-4a4 4 0 01-4-4v-1.17A3 3 0 015 10a3 3 0 013-3V6a4 4 0 014-4z" fill="none" stroke={color} strokeWidth="1.5" /><path d="M12 2v20M8 6h8" fill="none" stroke={color} strokeWidth="1" strokeLinecap="round" opacity="0.4" /></>,
    link: <><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" /><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" /></>,
    edit: <><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" fill="none" stroke={color} strokeWidth="1.5" /><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" fill="none" stroke={color} strokeWidth="1.5" /></>,
    plus: <><line x1="12" y1="5" x2="12" y2="19" stroke={color} strokeWidth="2" strokeLinecap="round" /><line x1="5" y1="12" x2="19" y2="12" stroke={color} strokeWidth="2" strokeLinecap="round" /></>,
    trash: <><polyline points="3 6 5 6 21 6" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" fill="none" stroke={color} strokeWidth="1.5" /></>,
    send: <><line x1="22" y1="2" x2="11" y2="13" stroke={color} strokeWidth="1.5" /><polygon points="22 2 15 22 11 13 2 9 22 2" fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" /></>,
    chevDown: <polyline points="6 9 12 15 18 9" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />,
    arrowRight: <><line x1="5" y1="12" x2="19" y2="12" stroke={color} strokeWidth="1.5" strokeLinecap="round" /><polyline points="12 5 19 12 12 19" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></>,
    settings: <><circle cx="12" cy="12" r="3" fill="none" stroke={color} strokeWidth="1.5" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z" fill="none" stroke={color} strokeWidth="1.5" /></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" style={{ flexShrink: 0, display: "inline-block", verticalAlign: "middle" }}>{d[name]}</svg>;
};

// ─── Sub-Components ──────────────────────────────────────────────────────────
const SevBadge = ({ s, small }) => (
  <span style={{ display: "inline-flex", padding: small ? "1px 6px" : "2px 10px", borderRadius: 3, fontSize: small ? 9 : 10, fontWeight: 700, background: sevColor(s), color: "#fff", letterSpacing: "0.5px", fontFamily: "'JetBrains Mono', monospace" }}>{s}</span>
);

const Metric = ({ icon, label, value, sub, color = C.navy }) => (
  <div style={{ background: "#fff", borderRadius: 8, padding: "18px 20px", border: `1px solid ${C.gray200}`, position: "relative", overflow: "hidden" }}>
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: color }} />
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 2 }}>
      <span style={{ fontSize: 11, fontWeight: 600, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.8px" }}>{label}</span>
      <I name={icon} size={15} color={C.gray400} />
    </div>
    <div style={{ fontSize: 30, fontWeight: 800, color: C.text, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "-1px" }}>{value}</div>
    {sub && <div style={{ fontSize: 11, color: C.gray500, marginTop: 2 }}>{sub}</div>}
  </div>
);

const Bar = ({ label, count, total, color }) => {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 0" }}>
      <span style={{ width: 65, fontSize: 10, fontWeight: 700, color: C.gray600, textTransform: "uppercase" }}>{label}</span>
      <div style={{ flex: 1, height: 20, background: C.gray100, borderRadius: 3, overflow: "hidden", position: "relative" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: color, borderRadius: 3, transition: "width 0.6s ease", minWidth: count > 0 ? 2 : 0 }} />
      </div>
      <span style={{ width: 32, textAlign: "right", fontSize: 11, fontWeight: 700, color: C.gray700, fontFamily: "monospace" }}>{count}</span>
    </div>
  );
};

const Btn = ({ children, onClick, primary, danger, small, disabled, style: s = {} }) => (
  <button onClick={onClick} disabled={disabled} style={{
    display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6,
    padding: small ? "5px 10px" : "9px 18px", fontSize: small ? 11 : 13, fontWeight: 600,
    borderRadius: 6, border: primary || danger ? "none" : `1px solid ${C.gray300}`,
    background: disabled ? C.gray300 : primary ? C.navy : danger ? C.critical : "#fff",
    color: primary || danger ? "#fff" : C.gray700,
    cursor: disabled ? "not-allowed" : "pointer", transition: "all 0.15s", ...s,
  }}>{children}</button>
);

const Input = ({ value, onChange, placeholder, icon, style: s = {} }) => (
  <div style={{ position: "relative", ...s }}>
    {icon && <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }}><I name={icon} size={16} color={C.gray400} /></span>}
    <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={{
      width: "100%", padding: icon ? "10px 12px 10px 38px" : "10px 12px", fontSize: 13,
      border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff", color: C.text,
      outline: "none", transition: "border 0.15s", boxSizing: "border-box",
    }} onFocus={e => e.target.style.borderColor = C.blue} onBlur={e => e.target.style.borderColor = C.gray200} />
  </div>
);

const Card = ({ title, icon, action, children, noPad, style: s = {} }) => (
  <div style={{ background: "#fff", borderRadius: 8, border: `1px solid ${C.gray200}`, overflow: "hidden", ...s }}>
    {title && (
      <div style={{ padding: "14px 20px", borderBottom: `1px solid ${C.gray100}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {icon && <I name={icon} size={16} color={C.navy} />}
          <span style={{ fontSize: 14, fontWeight: 700, color: C.text }}>{title}</span>
        </div>
        {action}
      </div>
    )}
    {noPad ? children : <div style={{ padding: 20 }}>{children}</div>}
  </div>
);

// ─── Main Component ──────────────────────────────────────────────────────────
export default function VulnDashboard() {
  const initialResetToken = getResetTokenFromPath();

  // Auth state
  const [isLoggedIn, setIsLoggedIn] = useState(!!getToken());
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [loginErr, setLoginErr] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [authMode, setAuthMode] = useState(initialResetToken ? "reset" : "login");
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotErr, setForgotErr] = useState("");
  const [forgotMsg, setForgotMsg] = useState("");
  const [forgotLoading, setForgotLoading] = useState(false);
  const [resetToken, setResetToken] = useState(initialResetToken);
  const [tokenCheckLoading, setTokenCheckLoading] = useState(initialResetToken.length > 0);
  const [tokenValid, setTokenValid] = useState(false);
  const [resetPass, setResetPass] = useState("");
  const [resetConfirm, setResetConfirm] = useState("");
  const [resetErr, setResetErr] = useState("");
  const [resetMsg, setResetMsg] = useState("");
  const [resetLoading, setResetLoading] = useState(false);

  // Navigation
  const [view, setView] = useState("overview");
  const [collapsed, setCollapsed] = useState(false);

  // Data from API
  const [dash, setDash] = useState({ totalAll: 0, today: [], week: [], topExploited: [], lastRun: null });
  const [vulns, setVulns] = useState([]);
  const [vulnsTotal, setVulnsTotal] = useState(0);
  const [runs, setRuns] = useState([]);
  const [contacts, setContacts] = useState([]);
  const [reports, setReports] = useState([]);
  const [users, setUsers] = useState([]);
  const [subscriptionCatalog, setSubscriptionCatalog] = useState([]);
  const [subscriberVendors, setSubscriberVendors] = useState([]);
  const [activeVendor, setActiveVendor] = useState("");
  const [tags, setTags] = useState([]);
  const [notifHistory, setNotifHistory] = useState([]);
  const [notifDetail, setNotifDetail] = useState(null);
  const [templateConfig, setTemplateConfig] = useState({
    headerImageUrl: "",
    introMessage: "",
    showExploitProbability: true,
    showExploitExists: true,
    showAffectedSoftware: true,
    showDescription: true,
    showReferences: true,
    showPatchLink: true,
  });
  const [templateName, setTemplateName] = useState("Plantilla CVE");
  const [templateList, setTemplateList] = useState([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState("");
  const [templateLoading, setTemplateLoading] = useState(false);
  const [templateSaving, setTemplateSaving] = useState(false);
  const [previewVulnId, setPreviewVulnId] = useState("");
  const [templatePreviewHtml, setTemplatePreviewHtml] = useState("");
  const [templatePreviewMeta, setTemplatePreviewMeta] = useState({ cveId: "", manufacturer: "" });
  const [templatePreviewLoading, setTemplatePreviewLoading] = useState(false);
  const [manufacturers, setManufacturers] = useState([]);
  const [selectedManufacturer, setSelectedManufacturer] = useState("");
  const [newManufacturerName, setNewManufacturerName] = useState("");
  const [newProductForm, setNewProductForm] = useState({ vendor: "", product: "", versions: "" });
  const [mergeForm, setMergeForm] = useState({ targetName: "", sourceNames: [] });
  const [manufacturersLoading, setManufacturersLoading] = useState(false);

  // Filters & search
  const [searchQ, setSearchQ] = useState("");
  const [searchType, setSearchType] = useState("all");
  const [searchTagId, setSearchTagId] = useState("");
  const [searchPublishedFrom, setSearchPublishedFrom] = useState("");
  const [searchPublishedTo, setSearchPublishedTo] = useState("");
  const [searchMinScore, setSearchMinScore] = useState("");
  const [searchExploit, setSearchExploit] = useState("all");
  const [searchSeverity, setSearchSeverity] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [selectedVuln, setSelectedVuln] = useState(null);

  // Contacts CRUD
  const [editContact, setEditContact] = useState(null);
  const [showContactForm, setShowContactForm] = useState(false);

  // Users CRUD
  const [editUser, setEditUser] = useState(null);
  const [showUserForm, setShowUserForm] = useState(false);

  // Tags CRUD (moved below)

  // Collector & Reports
  const [collecting, setCollecting] = useState(false);
  const [backfillJobId, setBackfillJobId] = useState(() => localStorage.getItem("occ_backfill_job_id") || "");
  const [backfillBusy, setBackfillBusy] = useState(false);
  const [backfillStatus, setBackfillStatus] = useState(null);
  const [backfillMsg, setBackfillMsg] = useState(null);
  const [generating, setGenerating] = useState(false);
  const [reportResult, setReportResult] = useState(null);
  const [reportHours, setReportHours] = useState("24");
  const [reportSev, setReportSev] = useState("MEDIUM");

  // AI
  const [aiQuery, setAiQuery] = useState("");
  const [aiMessages, setAiMessages] = useState([]);
  const [aiLoading, setAiLoading] = useState(false);

  // Settings
  const [settingsTab, setSettingsTab] = useState("smtp");
  const [now, setNow] = useState(Date.now());
  const [smtpConfig, setSmtpConfig] = useState({ host: "", port: "", user: "", pass: "", secure: false, from: "" });
  const [smtpLoading, setSmtpLoading] = useState(false);
  const [smtpSaving, setSmtpSaving] = useState(false);
  const [testEmail, setTestEmail] = useState("");
  const [testSending, setTestSending] = useState(false);
  const DEFAULT_AI_MODEL = "krith/qwen2.5-32b-instruct:IQ1_M";
  const [aiConfig, setAiConfig] = useState({ provider: "ollama", baseUrl: "", model: DEFAULT_AI_MODEL, source: "env" });
  const [aiModels, setAiModels] = useState([]);
  const [aiConfigLoading, setAiConfigLoading] = useState(false);
  const [aiConfigSaving, setAiConfigSaving] = useState(false);
  const [smtpMsg, setSmtpMsg] = useState(null);
  const aiEndRef = useRef(null);
  const validatedTokenRef = useRef("");

  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 30000); return () => clearInterval(t); }, []);
  useEffect(() => { aiEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [aiMessages]);

  // Auto-login if bypass is active in backend
  useEffect(() => {
    const checkBypass = async () => {
      try {
        const res = await fetch(`${API_BASE}/health`);
        if (!res.ok) return;
        const data = await res.json();
        if (data.bypassAuth && !getToken()) {
          setUser({ id: 1, email: "admin@servicios-occ.local", role: "ADMIN", name: "Modo Desarrollo" });
          setIsLoggedIn(true);
        }
      } catch (e) {
        console.error("Health check error:", e);
      }
    };
    if (!isLoggedIn) checkBypass();
  }, [isLoggedIn]);

  useEffect(() => {
    if (view !== "collector") return undefined;
    if (!backfillJobId) return undefined;
    if ((backfillStatus?.job?.status || "").toUpperCase() !== "RUNNING") return undefined;
    const t = setInterval(() => {
      const jobId = String(backfillJobId || "").trim();
      if (!jobId) return;
      callBackfillApi(`/status/${encodeURIComponent(jobId)}`)
        .then((data) => {
          if (data && !data.error) setBackfillStatus(data);
        })
        .catch(() => undefined);
    }, 6000);
    return () => clearInterval(t);
  }, [view, backfillJobId, backfillStatus?.job?.status]);

  // Login handler
  const handleLogin = async (e) => {
    e.preventDefault(); setLoginErr(""); setLoginLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: loginEmail, password: loginPass }) });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        if (res.status === 502) throw new Error("API no disponible (502 Bad Gateway). Revisa el servicio occ-api.");
        throw new Error(d.message || "Login failed");
      }
      const data = await res.json();
      setToken(data.access_token); setUser(data.user); setIsLoggedIn(true);
    } catch (e) {
      const msg = String(e?.message || "");
      if (msg.toLowerCase().includes("failed to fetch")) {
        setLoginErr("No se pudo conectar con la API. Verifica que backend/proxy estén levantados.");
      } else {
        setLoginErr(msg || "Error de autenticación");
      }
    }
    setLoginLoading(false);
  };
  const handleLogout = () => { clearToken(); setIsLoggedIn(false); };

  const validateResetToken = useCallback(async (token) => {
    if (!token) {
      setTokenValid(false);
      setTokenCheckLoading(false);
      return;
    }
    setTokenCheckLoading(true);
    setResetErr("");
    setResetMsg("");
    try {
      const res = await fetch(`${API_BASE}/auth/reset-password/${encodeURIComponent(token)}`);
      if (!res.ok) throw new Error("No se pudo validar el enlace");
      const data = await res.json();
      setTokenValid(!!data?.valid);
      if (data?.email) setLoginEmail(String(data.email));
      if (!data?.valid) setResetErr("El enlace de recuperación es inválido o ha expirado.");
    } catch {
      setTokenValid(false);
      setResetErr("No se pudo validar el enlace. Intenta solicitar uno nuevo.");
    } finally {
      setTokenCheckLoading(false);
    }
  }, []);

  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setForgotErr("");
    setForgotMsg("");
    setForgotLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: forgotEmail.trim().toLowerCase() }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.message || "No se pudo procesar la solicitud");
      setForgotMsg(data?.message || "Si el correo está registrado, recibirás un enlace de recuperación en breve.");
    } catch (e) {
      setForgotErr(e.message || "Error solicitando recuperación");
    } finally {
      setForgotLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setResetErr("");
    setResetMsg("");

    if (resetPass !== resetConfirm) {
      setResetErr("Las contraseñas no coinciden.");
      return;
    }
    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(resetPass)) {
      setResetErr("La contraseña debe tener mínimo 8 caracteres, mayúscula, minúscula y número.");
      return;
    }

    setResetLoading(true);
    try {
      const res = await fetch(`${API_BASE}/auth/update-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: resetToken, password: resetPass }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.message || "No se pudo actualizar la contraseña");
      setResetMsg(data?.message || "La contraseña se actualizó correctamente.");
      setResetPass("");
      setResetConfirm("");
      setTokenValid(false);
      window.history.replaceState({}, "", "/");
      setTimeout(() => {
        setAuthMode("login");
      }, 1200);
    } catch (e) {
      setResetErr(e.message || "Error al actualizar la contraseña");
    } finally {
      setResetLoading(false);
    }
  };

  useEffect(() => {
    if (isLoggedIn || authMode !== "reset" || !resetToken) return;
    if (validatedTokenRef.current === resetToken) return;
    validatedTokenRef.current = resetToken;
    validateResetToken(resetToken);
  }, [authMode, isLoggedIn, resetToken, validateResetToken]);

  // Load data when view changes
  const loadData = useCallback(async (v) => {
    try {
      if (v === "overview") {
        const r = await apiFetch("/vulnerabilities/dashboard"); setDash(await r.json());
      } else if (v === "vulns" || v === "exploited") {
        const q = v === "exploited" ? "?exploited=true&limit=100" : `?dashboardDefault=true&limit=100${sevFilter ? `&severity=${sevFilter}` : ''}`;
        const r = await apiFetch(`/vulnerabilities${q}`); const d = await r.json(); setVulns(d.data || []); setVulnsTotal(d.total || 0);
      } else if (v === "contacts") {
        const r = await apiFetch("/users"); const allUsers = await r.json();
        setContacts((Array.isArray(allUsers) ? allUsers : []).filter(u => u.isSubscriber));
      } else if (v === "search") {
        const [vulnsR, tagsR] = await Promise.all([
          apiFetch("/vulnerabilities?limit=1000"),
          apiFetch("/tags"),
        ]);
        const vulnData = await vulnsR.json();
        setVulns(Array.isArray(vulnData?.data) ? vulnData.data : []);
        setVulnsTotal(vulnData?.total || 0);
        const tagsData = await tagsR.json();
        setTags(Array.isArray(tagsData) ? tagsData : []);
      } else if (v === "reports") {
        const r = await apiFetch("/vulnerabilities/reports"); const d = await r.json(); setReports(d.data || []);
      } else if (v === "collector") {
        const [runsR, dashR] = await Promise.all([
          apiFetch("/vulnerabilities/runs?limit=30"),
          apiFetch("/vulnerabilities/dashboard"),
        ]);
        const runsData = await runsR.json();
        const dashData = await dashR.json();
        setRuns(Array.isArray(runsData) ? runsData : (Array.isArray(runsData?.data) ? runsData.data : []));
        setDash(dashData || { totalAll: 0, today: [], week: [], topExploited: [], lastRun: null });
        if (backfillJobId) {
          try {
            const statusData = await callBackfillApi(`/status/${encodeURIComponent(backfillJobId)}`);
            if (!statusData?.error) {
              setBackfillStatus(statusData);
            } else {
              setBackfillStatus(null);
            }
          } catch {
            setBackfillStatus(null);
          }
        }
      } else if (v === "manufacturers") {
        setManufacturersLoading(true);
        const r = await apiFetch("/manufacturers");
        const data = await r.json();
        const list = Array.isArray(data) ? data : [];
        setManufacturers(list);
        if (!selectedManufacturer && list.length > 0) {
          setSelectedManufacturer(list[0].name);
          setMergeForm({ targetName: list[0].name, sourceNames: [list[0].name] });
        }
        setManufacturersLoading(false);
      } else if (v === "settings") {
        setSmtpLoading(true);
        try {
          const smtpR = await apiFetch("/notifications/config");
          const smtpD = await smtpR.json();
          if (smtpD) setSmtpConfig({ ...smtpD, pass: "" });
        } finally {
          setSmtpLoading(false);
        }

        const [usersRes, tagsRes, catalogRes] = await Promise.allSettled([
          apiFetch("/users").then(r => r.json()),
          apiFetch("/tags").then(r => r.json()),
          apiFetch("/users/subscription-catalog").then(r => r.json()),
        ]);

        if (usersRes.status === "fulfilled") {
          setUsers(Array.isArray(usersRes.value) ? usersRes.value : []);
        }
        if (tagsRes.status === "fulfilled") {
          setTags(Array.isArray(tagsRes.value) ? tagsRes.value : []);
        }
        if (catalogRes.status === "fulfilled") {
          setSubscriptionCatalog(Array.isArray(catalogRes.value) ? catalogRes.value : []);
        }

        setAiConfigLoading(true);
        const [aiConfigRes, aiModelsRes] = await Promise.allSettled([
          apiFetch("/ai/config").then(r => r.json()),
          apiFetch("/ai/models").then(r => r.json()),
        ]);
        if (aiConfigRes.status === "fulfilled" && aiConfigRes.value) {
          setAiConfig({
            provider: aiConfigRes.value.provider || "ollama",
            baseUrl: aiConfigRes.value.baseUrl || "",
            model: aiConfigRes.value.model || DEFAULT_AI_MODEL,
            source: aiConfigRes.value.source || "env",
          });
        }
        if (aiModelsRes.status === "fulfilled") {
          const models = Array.isArray(aiModelsRes.value?.models) ? aiModelsRes.value.models : [];
          setAiModels(models);
        }
        setAiConfigLoading(false);
      } else if (v === "notifications") {
        setTemplateLoading(true);
        const [historyRes, templateRes, templatesRes, vulnsRes] = await Promise.allSettled([
          apiFetch("/notifications/history").then(r => r.json()),
          apiFetch("/notifications/template-config").then(r => r.json()),
          apiFetch("/notifications/template-configs").then(r => r.json()),
          apiFetch("/vulnerabilities?limit=300").then(r => r.json()),
        ]);
        if (historyRes.status === "fulfilled") {
          setNotifHistory(historyRes.value?.data || []);
        }
        if (templateRes.status === "fulfilled" && templateRes.value) {
          setTemplateConfig(prev => ({ ...prev, ...templateRes.value }));
          setTemplateName(templateRes.value?.name || "Plantilla CVE");
        }
        if (templatesRes.status === "fulfilled") {
          const list = Array.isArray(templatesRes.value) ? templatesRes.value : [];
          setTemplateList(list);
          const active = list.find(t => t.isActive);
          setSelectedTemplateId(active ? String(active.id) : "");
        }
        if (vulnsRes.status === "fulfilled") {
          setVulns(Array.isArray(vulnsRes.value?.data) ? vulnsRes.value.data : []);
        }
        setTemplateLoading(false);
      }
    } catch (e) {
      setSmtpLoading(false);
      setAiConfigLoading(false);
      setTemplateLoading(false);
      setManufacturersLoading(false);
      console.error("Load error:", e.message);
    }
  }, [sevFilter, backfillJobId]);

  useEffect(() => { if (isLoggedIn) loadData(view); }, [view, isLoggedIn, loadData]);

  const handleCreateTest = async () => {
    if (!testEmail) return;
    setTestSending(true);
    try {
      const res = await apiFetch("/notifications/test", { method: "POST", body: JSON.stringify({ email: testEmail }) });
      if (res.ok) setSmtpMsg({ type: "success", text: "Email de prueba enviado correctamente" });
      else throw new Error("Error enviando email");
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error enviando email de prueba" });
    }
    setTestSending(false);
    setTimeout(() => setSmtpMsg(null), 3000);
  };

  const saveAiConfig = async () => {
    setAiConfigSaving(true);
    try {
      const res = await apiFetch("/ai/config", {
        method: "POST",
        body: JSON.stringify({
          provider: aiConfig.provider || "ollama",
          baseUrl: aiConfig.baseUrl || "",
          model: aiConfig.model || "",
        }),
      });
      if (!res.ok) throw new Error("No se pudo guardar la configuración IA");
      const data = await res.json();
      setAiConfig({
        provider: data.provider || "ollama",
        baseUrl: data.baseUrl || "",
        model: data.model || DEFAULT_AI_MODEL,
        source: data.source || "db",
      });
      setSmtpMsg({ type: "success", text: "Configuración IA guardada correctamente" });
      const modelsRes = await apiFetch("/ai/models");
      const modelsData = await modelsRes.json();
      setAiModels(Array.isArray(modelsData?.models) ? modelsData.models : []);
    } catch (e) {
      setSmtpMsg({ type: "error", text: e.message || "Error guardando configuración IA" });
    } finally {
      setAiConfigSaving(false);
      setTimeout(() => setSmtpMsg(null), 3000);
    }
  };

  const refreshAiModels = async () => {
    try {
      const modelsRes = await apiFetch("/ai/models");
      const modelsData = await modelsRes.json();
      setAiModels(Array.isArray(modelsData?.models) ? modelsData.models : []);
    } catch {
      setAiModels([]);
    }
  };

  const handleSaveSmtp = async () => {
    setSmtpSaving(true);
    try {
      const res = await apiFetch("/notifications/config", { method: "POST", body: JSON.stringify(smtpConfig) });
      if (res.ok) setSmtpMsg({ type: "success", text: "Configuración guardada correctamente" });
      else throw new Error("Error guardando configuración");
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error guardando configuración" });
    }
    setSmtpSaving(false);
    setTimeout(() => setSmtpMsg(null), 3000);
  };

  const todayT = (dash?.today || []).reduce((s, c) => s + (c?._count || 0), 0);
  const weekT = (dash?.week || []).reduce((s, c) => s + (c?._count || 0), 0);
  const gc = (arr, sev) => (arr || []).find(c => c?.cvssV31Severity === sev)?._count || 0;
  const nextRun = () => { if (!dash?.lastRun?.finishedAt) return "-"; return Math.max(0, Math.floor((new Date(dash?.lastRun?.finishedAt).getTime() + 1800000 - now) / 60000)) + "m"; };

  // Search logic (live filtering)
  const hasSearchCriteria = (
    searchQ.trim().length > 0 ||
    searchTagId !== "" ||
    searchPublishedFrom !== "" ||
    searchPublishedTo !== "" ||
    searchMinScore !== "" ||
    searchExploit !== "all" ||
    searchSeverity !== ""
  );

  const searchResults = vulns.filter(v => {
    const q = searchQ.trim().toLowerCase();
    let textMatch = true;
    if (q) {
      if (searchType === "cve") {
        textMatch = v.cveId.toLowerCase().includes(q);
      } else if (searchType === "product") {
        textMatch = (v.affectedProducts || []).some(
          p => `${p.vendor}/${p.product}`.toLowerCase().includes(q) ||
            p.vendor?.toLowerCase().includes(q) ||
            p.product?.toLowerCase().includes(q),
        );
      } else {
        textMatch =
          v.cveId.toLowerCase().includes(q) ||
          (v.description || "").toLowerCase().includes(q) ||
          (v.affectedProducts || []).some(p => `${p.vendor} ${p.product}`.toLowerCase().includes(q));
      }
    }

    const tagMatch = searchTagId === "" || (v.tags || []).some(t => String(t.id) === String(searchTagId));
    const severityMatch = searchSeverity === "" || v.cvssV31Severity === searchSeverity;

    const minScore = parseFloat(searchMinScore);
    const scoreMatch = Number.isNaN(minScore) || (Number(v.cvssV31Score || 0) >= minScore);

    const publishedAt = v.publishedAt ? new Date(v.publishedAt) : null;
    const fromMatch = !searchPublishedFrom || (publishedAt && publishedAt >= new Date(`${searchPublishedFrom}T00:00:00`));
    const toMatch = !searchPublishedTo || (publishedAt && publishedAt <= new Date(`${searchPublishedTo}T23:59:59`));

    let exploitMatch = true;
    if (searchExploit === "known") exploitMatch = !!v.isKnownExploited;
    else if (searchExploit === "public") exploitMatch = !!v.hasPublicExploit;
    else if (searchExploit === "any") exploitMatch = !!v.isKnownExploited || !!v.hasPublicExploit;
    else if (searchExploit === "none") exploitMatch = !v.isKnownExploited && !v.hasPublicExploit;

    return textMatch && tagMatch && severityMatch && scoreMatch && fromMatch && toMatch && exploitMatch;
  });

  // Find contacts (subscribers) affected by a CVE
  const getAffectedContacts = (vuln) => {
    if (!vuln) return [];
    const prods = (vuln.affectedProducts || []).map(p => `${p.vendor}/${p.product}`.toLowerCase());
    return contacts.filter(c => (c.subscriptions || []).some(s => prods.includes(`${s.vendor}/${s.product}`.toLowerCase())));
  };

  // AI Chat handler
  const handleAiSend = async (messageOverride = null) => {
    const prompt = (typeof messageOverride === "string" ? messageOverride : aiQuery).trim();
    if (!prompt) return;
    const userMsg = prompt;
    setAiMessages(prev => [...prev, { role: "user", content: userMsg }]);
    if (messageOverride == null) setAiQuery("");
    setAiLoading(true);

    const context = `Eres el asistente de IA de la Oficina de Ciberseguridad Corporativa (OCC) de SEIDOR. Tu rol es analizar vulnerabilidades (CVEs), evaluar impacto en la infraestructura corporativa, y recomendar acciones de remediación.

Base de datos actual: ${dash.totalAll || vulns.length} CVEs indexados.
Top CVEs con explotación activa: ${(dash.topExploited || []).map(v => v.cveId).join(", ")}.

Responde siempre en español, con rigor técnico. Incluye CVE IDs específicos cuando sea relevante.
Usa únicamente datos técnicos de vulnerabilidades y no incluyas datos de usuarios/contactos.`;

    try {
      const res = await apiFetch("/ai/chat", {
        method: "POST",
        body: JSON.stringify({
          messages: [
            { role: "system", content: context },
            ...aiMessages.map(m => ({ role: m.role, content: m.content })),
            { role: "user", content: userMsg },
          ],
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiMessages(prev => [...prev, { role: "assistant", content: data?.content || "Sin respuesta del modelo." }]);
      } else {
        throw new Error("AI API error");
      }
    } catch (e) {
      setAiMessages(prev => [...prev, {
        role: "assistant",
        content: `No se pudo obtener respuesta del asistente IA. Verifica la configuración de Ollama en el backend.\n\nDetalle: ${e?.message || "Error desconocido"}`,
      }]);
    }
    setAiLoading(false);
  };

  const analyzeVulnerabilityWithAi = async (v) => {
    if (!v) return;
    const prompt = `Analiza el impacto de ${v.cveId} en nuestra infraestructura.
Productos afectados: ${(v.affectedProducts || []).map(p => `${p.vendor}/${p.product}`).join(", ") || "No informado"}.
CVSS: ${v.cvssV31Score ?? "N/A"} (${v.cvssV31Severity || "N/A"}).
EPSS: ${fmtEpss(v.epssScore)}.
Indica prioridad, acciones inmediatas y plan de mitigación.`;
    setView("ai");
    setVulnDetail(null);
    setAiQuery(prompt);
    await handleAiSend(prompt);
  };

  const generateSimulatedResponse = (q) => {
    const ql = q.toLowerCase();
    if (ql.includes("cve-2025-21298") || ql.includes("windows ole")) return `**CVE-2025-21298 — Windows OLE RCE**\n\n**Severidad:** CRITICAL (CVSS 9.8) | **EPSS:** 94.3% probabilidad de explotación\n**Estado:** ⚠️ Explotación activa confirmada (CISA KEV)\n\n**Impacto en infraestructura OCC:**\n- Afecta a microsoft/windows_11 y windows_server_2022\n- **Equipo afectado:** Infraestructura Windows (infra-windows@corp.local)\n- Ventana de parcheo configurada: domingos 02:00-06:00\n\n**Recomendación:**\nDada la explotación activa, recomiendo solicitar parcheo de emergencia fuera de la ventana habitual. El vector de ataque es via documentos manipulados (OLE), lo que implica riesgo directo por phishing.\n\n**Acciones inmediatas:**\n1. Notificar a Pedro Gómez (infra-windows) para parcheo urgente\n2. Bloquear adjuntos OLE en el gateway de correo temporalmente\n3. Verificar detecciones en EDR para intentos de explotación`;
    if (ql.includes("fortinet") || ql.includes("fortigate") || ql.includes("fortios")) return `**Análisis FortiOS — CVE-2024-55591**\n\n**Severidad:** CRITICAL (CVSS 9.8) | Authentication Bypass\n**Estado:** Explotación activa confirmada\n\n**Detalle técnico:**\nBypass de autenticación via Node.js websocket en FortiOS permite a un atacante no autenticado obtener privilegios de super-admin mediante requests CSF proxy manipulados.\n\n**Impacto en OCC:**\n- **Equipo afectado:** Redes y Firewalls (redes-fw@corp.local)\n- FortiOS configurado en HA activo-pasivo según notas del equipo\n- Requiere CAB approval excepto P1 — esta vulnerabilidad califica como P1\n\n**Remediación:**\n1. Actualizar a FortiOS ≥7.0.17 inmediatamente\n2. Verificar logs de admin para accesos no autorizados\n3. Revisar reglas CSF proxy y deshabilitar si no se usa\n4. Contactar a Laura Martín para coordinar`;
    if (ql.includes("resumen") || ql.includes("estado") || ql.includes("informe")) return `**Resumen ejecutivo — Estado de vulnerabilidades**\n\n📊 **Últimas 24h:** ${todayT} CVEs procesados\n- 🔴 Critical: ${gc(dash.today, "CRITICAL")} | 🟠 High: ${gc(dash.today, "HIGH")} | 🟡 Medium: ${gc(dash.today, "MEDIUM")}\n\n⚡ **Explotación activa:** ${dash.topExploited.length} CVEs confirmados en CISA KEV\n\n**Top prioridades:**\n1. **CVE-2025-21298** (Windows OLE) — CVSS 9.8, EPSS 94.3% → Equipo Infra Windows\n2. **CVE-2024-55591** (FortiOS) — CVSS 9.8, EPSS 87.6% → Equipo Redes\n3. **CVE-2025-0282** (Ivanti CS) — CVSS 9.0, EPSS 89.1% → Equipo VPN\n\n**Recomendación:** Convocar reunión de emergencia con los 3 equipos afectados para coordinar parcheo prioritario de las 3 CVEs con explotación activa y CVSS ≥9.0.`;
    if (ql.includes("ivanti")) return `**Análisis Ivanti — Múltiples CVEs activas**\n\n**CVE-2025-0282** (Connect Secure) — CVSS 9.0\nBuffer overflow en stack permite RCE sin autenticación. Exploit público disponible.\n\n**CVE-2024-8963** (CSA) — CVSS 9.4\nPath traversal permite acceso no autenticado a funcionalidad restringida.\n\n**Impacto OCC:**\n- **Equipo VPN y Acceso Remoto** (vpn-team@corp.local)\n- 2 appliances en producción (Madrid y Barcelona)\n- Contacto: Carlos Ruiz\n\n**Acciones:**\n1. Verificar versión actual de Connect Secure (vulnerable si <22.7R2.5)\n2. Aplicar parche fuera de horario laboral según protocolo del equipo\n3. Ejecutar Integrity Checker Tool de Ivanti post-parcheo\n4. Revisar logs de acceso VPN de las últimas 2 semanas`;
    return `Procesando consulta: "${q}"\n\n**Análisis basado en la base de datos OCC:**\n\nActualmente hay ${dash.totalAll || vulns.length} CVEs indexados.\n\nLos equipos IT con mayor exposición son:\n${contacts.map(c => `- **${c.name}**: ${(c.products || []).length} productos monitorizados`).join("\n")}\n\n¿Necesitas un análisis más específico? Puedo detallar:\n- Impacto de un CVE concreto en la infraestructura\n- Vulnerabilidades que afectan a un producto/vendor\n- Priorización de parcheo recomendada\n- Draft de comunicación a un equipo IT`;
  };

  const handleCollect = async () => {
    setCollecting(true);
    try { await apiFetch("/vulnerabilities/collect", { method: "POST" }); await loadData("overview"); } catch (e) { console.error(e); }
    setCollecting(false);
  };

  const setStoredBackfillJobId = (jobId) => {
    const value = String(jobId || "").trim();
    setBackfillJobId(value);
    if (value) localStorage.setItem("occ_backfill_job_id", value);
    else localStorage.removeItem("occ_backfill_job_id");
  };

  const refreshBackfillStatus = async (jobIdOverride) => {
    const jobId = String(jobIdOverride || backfillJobId || "").trim();
    if (!jobId) {
      setBackfillMsg({ type: "error", text: "No hay jobId de backfill para consultar." });
      return;
    }
    try {
      const data = await callBackfillApi(`/status/${encodeURIComponent(jobId)}`);
      if (data?.error) throw new Error(data.error);
      setBackfillStatus(data);
      if (data?.job?.jobId) {
        setStoredBackfillJobId(data.job.jobId);
      }
      setBackfillMsg({ type: "success", text: `Estado cargado (${data?.job?.status || "N/A"})` });
    } catch (e) {
      setBackfillMsg({ type: "error", text: e?.message || "No se pudo consultar el estado del backfill" });
    }
  };

  const startBackfill = async () => {
    setBackfillBusy(true);
    setBackfillMsg(null);
    try {
      const data = await callBackfillApi("/start", { method: "POST" });
      if (!data?.jobId) throw new Error("Respuesta inválida al iniciar/reanudar backfill");
      setStoredBackfillJobId(data.jobId);
      setBackfillMsg({
        type: "success",
        text: data?.resumed ? `Backfill reanudado (${data.jobId})` : `Backfill iniciado (${data.jobId})`,
      });
      await refreshBackfillStatus(data.jobId);
    } catch (e) {
      setBackfillMsg({ type: "error", text: e?.message || "No se pudo iniciar/reanudar el backfill" });
    }
    setBackfillBusy(false);
  };

  const runBackfillToCompletion = async () => {
    const jobId = String(backfillJobId || "").trim();
    if (!jobId) {
      setBackfillMsg({ type: "error", text: "Primero inicia/reanuda un backfill para obtener jobId." });
      return;
    }
    setBackfillBusy(true);
    setBackfillMsg(null);
    try {
      const data = await callBackfillApi(`/run/${encodeURIComponent(jobId)}`, { method: "POST" });
      setBackfillMsg({
        type: "success",
        text: data?.alreadyRunning
          ? "Backfill ya estaba ejecutándose en segundo plano."
          : "Backfill lanzado en segundo plano. Usa Estado para seguimiento.",
      });
      await refreshBackfillStatus(jobId);
      await loadData("collector");
    } catch (e) {
      setBackfillMsg({ type: "error", text: e?.message || "Fallo al ejecutar el backfill" });
    }
    setBackfillBusy(false);
  };

  const handleReport = async () => {
    setGenerating(true); setReportResult(null);
    try {
      const r = await apiFetch(`/vulnerabilities/report?hours=${reportHours}&minSeverity=${reportSev}`, { method: "POST" });
      const d = await r.json(); setReportResult(d); await loadData("reports");
    } catch (e) { console.error(e); } setGenerating(false);
  };

  const saveContact = async (c) => {
    try {
      // Build User-compatible payload
      const payload = {
        name: c.name,
        email: c.email,
        isSubscriber: true,
        canLogin: false,
        notificationEmail: c.email,
        contactPerson: c.contactPerson || null,
        department: c.department || null,
        phone: c.phone || null,
        notes: c.notes || null,
        subscriptions: (c.products || []).map(p => {
          if (typeof p === 'string') {
            const parts = p.split('/');
            return parts.length >= 2
              ? { vendor: parts[0].trim().toLowerCase(), product: parts.slice(1).join('/').trim().toLowerCase(), versions: [] }
              : null;
          }
          if (p && typeof p === 'object') return { vendor: (p.vendor || '').toLowerCase(), product: (p.product || '').toLowerCase(), versions: p.versions || [] };
          return null;
        }).filter(Boolean),
      };
      if (c.id) { await apiFetch(`/users/${c.id}`, { method: "PUT", body: JSON.stringify(payload) }); }
      else { await apiFetch("/users", { method: "POST", body: JSON.stringify(payload) }); }
      await loadData("contacts");
    } catch (e) { console.error(e); }
    setEditContact(null); setShowContactForm(false);
  };
  const deleteContact = async (id) => { try { await apiFetch(`/users/${id}`, { method: "DELETE" }); await loadData("contacts"); } catch (e) { console.error(e); } };

  // Users CRUD
  const buildUserFormState = (u = {}) => ({
    id: u.id || null,
    name: u.name || "",
    email: u.email || "",
    password: "",
    role: u.role || "USER",
    canLogin: u.canLogin !== false,
    isSubscriber: u.isSubscriber === true,
    notificationEmail: u.notificationEmail || u.email || "",
    subscriptions: Array.isArray(u.subscriptions) ? u.subscriptions.map(s => ({
      vendor: String(s.vendor || "").toLowerCase(),
      product: String(s.product || "").toLowerCase(),
      versions: Array.isArray(s.versions) ? s.versions : [],
    })) : [],
    isActive: u.isActive !== false,
  });

  const openUserForm = (u = null) => {
    const state = buildUserFormState(u || {});
    setEditUser(state);
    const vendors = [...new Set((state.subscriptions || []).map(s => s.vendor))];
    setSubscriberVendors(vendors);
    const firstVendor = vendors[0] || (subscriptionCatalog[0]?.vendor || "");
    setActiveVendor(firstVendor);
    setShowUserForm(true);
  };

  const setSubscriberEnabled = (enabled) => {
    const next = { ...editUser, isSubscriber: enabled };
    if (!enabled) {
      next.subscriptions = [];
      next.notificationEmail = "";
      setSubscriberVendors([]);
      setActiveVendor("");
    } else {
      next.notificationEmail = next.notificationEmail || next.email || "";
      if (next.canLogin && !["ADMIN", "VIEWER"].includes((next.role || "").toUpperCase())) {
        next.role = "";
      }
    }
    setEditUser(next);
  };

  const toggleVendorSelection = (vendor, checked) => {
    const normalizedVendor = String(vendor || "").toLowerCase();
    if (checked) {
      setSubscriberVendors(prev => prev.includes(normalizedVendor) ? prev : [...prev, normalizedVendor]);
      setActiveVendor(normalizedVendor);
      return;
    }

    setSubscriberVendors(prev => {
      const next = prev.filter(v => v !== normalizedVendor);
      if (activeVendor === normalizedVendor) setActiveVendor(next[0] || "");
      return next;
    });
    setEditUser(prev => ({
      ...prev,
      subscriptions: (prev.subscriptions || []).filter(s => s.vendor !== normalizedVendor),
    }));
  };

  const toggleProductSubscription = (vendor, product, checked) => {
    const normalizedVendor = String(vendor || "").toLowerCase();
    const normalizedProduct = String(product || "").toLowerCase();
    setEditUser(prev => {
      const current = Array.isArray(prev.subscriptions) ? prev.subscriptions : [];
      const exists = current.find(s => s.vendor === normalizedVendor && s.product === normalizedProduct);
      let nextSubs = current;

      if (checked && !exists) {
        nextSubs = [...current, { vendor: normalizedVendor, product: normalizedProduct, versions: [] }];
      } else if (!checked && exists) {
        nextSubs = current.filter(s => !(s.vendor === normalizedVendor && s.product === normalizedProduct));
      }

      return { ...prev, subscriptions: nextSubs };
    });
    if (checked) {
      setSubscriberVendors(prev => prev.includes(normalizedVendor) ? prev : [...prev, normalizedVendor]);
      setActiveVendor(normalizedVendor);
    }
  };

  const toggleSubscriptionVersion = (vendor, product, version, checked) => {
    const normalizedVendor = String(vendor || "").toLowerCase();
    const normalizedProduct = String(product || "").toLowerCase();
    const ver = String(version || "").trim();
    if (!ver) return;

    setEditUser(prev => ({
      ...prev,
      subscriptions: (prev.subscriptions || []).map(s => {
        if (s.vendor !== normalizedVendor || s.product !== normalizedProduct) return s;
        const currentVersions = Array.isArray(s.versions) ? s.versions : [];
        const nextVersions = checked
          ? [...new Set([...currentVersions, ver])]
          : currentVersions.filter(v => v !== ver);
        return { ...s, versions: nextVersions };
      }),
    }));
  };

  const saveUser = async (u) => {
    const subscriberWithLogin = !!u.isSubscriber && !!u.canLogin;
    if (subscriberWithLogin && !["ADMIN", "VIEWER"].includes((u.role || "").toUpperCase())) {
      alert('Para suscriptores con inicio de sesión, debes seleccionar rol "Administrador" o "Viewer".');
      return;
    }

    try {
      const payload = {
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.canLogin ? (u.role || "USER") : "SUBSCRIBER",
        canLogin: !!u.canLogin,
        isSubscriber: !!u.isSubscriber,
        notificationEmail: u.isSubscriber ? (u.notificationEmail || u.email) : null,
        subscriptions: u.isSubscriber ? (u.subscriptions || []) : [],
        isActive: u.isActive !== false,
      };
      if (u.password && u.password.trim().length > 0) payload.password = u.password;

      if (payload.id) { await apiFetch(`/users/${payload.id}`, { method: "PUT", body: JSON.stringify(payload) }); }
      else { await apiFetch("/users", { method: "POST", body: JSON.stringify(payload) }); }
      await loadData("settings");
    } catch (e) { console.error(e); }
    setEditUser(null); setShowUserForm(false);
    setSubscriberVendors([]);
    setActiveVendor("");
  };
  const deleteUser = async (id) => { try { await apiFetch(`/users/${id}`, { method: "DELETE" }); await loadData("settings"); } catch (e) { console.error(e); } };

  // Tags CRUD
  const [newTagName, setNewTagName] = useState("");
  const [newTagColor, setNewTagColor] = useState("#3B6CB5");

  // Vulnerability Detail & Actions
  const [vulnDetail, setVulnDetail] = useState(null);
  const [vulnLoading, setVulnLoading] = useState(false);
  const [notifSending, setNotifSending] = useState(false);
  const [showNotifModal, setShowNotifModal] = useState(false);
  const [notifContactsLoading, setNotifContactsLoading] = useState(false);

  // Load full detail
  const loadVulnDetail = async (id) => {
    setVulnLoading(true);
    try {
      const r = await apiFetch(`/vulnerabilities/${id}`);
      setVulnDetail(await r.json());
    } catch (e) { console.error(e); }
    setVulnLoading(false);
  };

  const openVulnerabilityDetail = (v) => {
    const id = v?.id || vulns.find(x => x.cveId === v?.cveId)?.id;
    if (!id) return;
    setSelectedVuln(v);
    setView("vulns");
    loadVulnDetail(id);
  };

  const openNotifyModal = async () => {
    setShowNotifModal(true);
    if (contacts.length > 0) return;
    setNotifContactsLoading(true);
    try {
      const r = await apiFetch("/users");
      const data = await r.json();
      const subscribers = (Array.isArray(data) ? data : []).filter(u => u.isSubscriber);
      setContacts(subscribers);
    } catch (e) {
      console.error(e);
    } finally {
      setNotifContactsLoading(false);
    }
  };

  // Send notification
  const handleNotifyContact = async (contactId) => {
    if (!vulnDetail) return;
    const parsedContactId = Number(contactId);
    if (!Number.isInteger(parsedContactId) || parsedContactId <= 0) {
      alert("Contacto inválido");
      return;
    }
    setNotifSending(true);
    try {
      const res = await apiFetch(`/vulnerabilities/${vulnDetail.id}/notify`, {
        method: "POST",
        body: JSON.stringify({ contactId: parsedContactId })
      });
      if (res.ok) {
        await loadVulnDetail(vulnDetail.id); // Reload to see history
        setShowNotifModal(false);
        alert("Notificación enviada correctamente");
      } else {
        throw new Error("Error enviando notificación");
      }
    } catch (e) { alert(e.message); }
    setNotifSending(false);
  };

  // Manage tags on vuln
  const handleVulnTags = async (newTags) => {
    if (!vulnDetail) return;
    try {
      const tagIds = newTags.map(t => t.id);
      await apiFetch(`/vulnerabilities/${vulnDetail.id}/tags`, {
        method: "POST",
        body: JSON.stringify({ tagIds })
      });
      setVulnDetail({ ...vulnDetail, tags: newTags });
      // Update list view too if possible
      setVulns(vulns.map(v => v.id === vulnDetail.id ? { ...v, tags: newTags } : v));
    } catch (e) { console.error(e); }
  };

  const addTag = async () => {
    if (!newTagName.trim()) return;
    try { await apiFetch("/tags", { method: "POST", body: JSON.stringify({ name: newTagName, color: newTagColor }) }); setNewTagName(""); await loadData("settings"); } catch (e) { console.error(e); }
  };
  const deleteTag = async (id) => { try { await apiFetch(`/tags/${id}`, { method: "DELETE" }); await loadData("settings"); } catch (e) { console.error(e); } };

  const createManufacturer = async () => {
    const name = newManufacturerName.trim().toLowerCase();
    if (!name) return;
    try {
      const res = await apiFetch("/manufacturers", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      if (!res.ok) throw new Error("No se pudo crear fabricante");
      setNewManufacturerName("");
      await loadData("manufacturers");
      await loadData("settings");
      setSelectedManufacturer(name);
      setMergeForm({ targetName: name, sourceNames: [name] });
    } catch (e) {
      alert(e.message);
    }
  };

  const createManufacturerProduct = async () => {
    const vendor = String(newProductForm.vendor || "").trim().toLowerCase();
    const product = String(newProductForm.product || "").trim().toLowerCase();
    if (!vendor || !product) return;

    const versions = String(newProductForm.versions || "")
      .split(",")
      .map(v => v.trim())
      .filter(Boolean);

    try {
      const res = await apiFetch("/manufacturers/products", {
        method: "POST",
        body: JSON.stringify({ vendor, product, versions }),
      });
      if (!res.ok) throw new Error("No se pudo crear producto");
      setNewProductForm({ vendor, product: "", versions: "" });
      await loadData("manufacturers");
      await loadData("settings");
      setSelectedManufacturer(vendor);
    } catch (e) {
      alert(e.message);
    }
  };

  const toggleMergeSource = (name, checked) => {
    setMergeForm(prev => ({
      ...prev,
      sourceNames: checked
        ? [...new Set([...(prev.sourceNames || []), name])]
        : (prev.sourceNames || []).filter(v => v !== name),
    }));
  };

  const applyManufacturerMerge = async () => {
    const targetName = String(mergeForm.targetName || "").trim().toLowerCase();
    const sourceNames = [...new Set((mergeForm.sourceNames || []).map(v => String(v || "").trim().toLowerCase()).filter(Boolean))];
    if (!targetName || sourceNames.length === 0) return;

    try {
      const res = await apiFetch("/manufacturers/merge", {
        method: "POST",
        body: JSON.stringify({ targetName, sourceNames }),
      });
      if (!res.ok) throw new Error("No se pudo armonizar fabricantes");
      await loadData("manufacturers");
      await loadData("settings");
      setSelectedManufacturer(targetName);
      setMergeForm({ targetName, sourceNames: [targetName] });
      alert("Fabricantes armonizados correctamente");
    } catch (e) {
      alert(e.message);
    }
  };

  // Notification detail
  const viewNotification = async (id) => {
    try { const r = await apiFetch(`/notifications/history/${id}`); setNotifDetail(await r.json()); } catch (e) { console.error(e); }
  };

  const saveTemplateConfig = async () => {
    setTemplateSaving(true);
    try {
      const res = await apiFetch("/notifications/template-config", {
        method: "POST",
        body: JSON.stringify({
          ...templateConfig,
          name: templateName,
          templateId: selectedTemplateId ? Number(selectedTemplateId) : undefined,
        }),
      });
      if (!res.ok) throw new Error("Error guardando plantilla");
      setSmtpMsg({ type: "success", text: "Plantilla guardada correctamente" });
      await loadData("notifications");
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error guardando plantilla" });
    } finally {
      setTemplateSaving(false);
      setTimeout(() => setSmtpMsg(null), 3000);
    }
  };

  const loadTemplateById = async (id) => {
    if (!id) return;
    setTemplateLoading(true);
    try {
      const res = await apiFetch(`/notifications/template-config/${id}`);
      if (!res.ok) throw new Error("Error cargando plantilla");
      const data = await res.json();
      setTemplateConfig(prev => ({ ...prev, ...data }));
      setTemplateName(data?.name || "Plantilla CVE");
      setSelectedTemplateId(String(id));
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error cargando plantilla" });
      setTimeout(() => setSmtpMsg(null), 3000);
    } finally {
      setTemplateLoading(false);
    }
  };

  const activateTemplate = async () => {
    if (!selectedTemplateId) return;
    try {
      const res = await apiFetch(`/notifications/template-config/${selectedTemplateId}/activate`, {
        method: "POST",
      });
      if (!res.ok) throw new Error("Error activando plantilla");
      setSmtpMsg({ type: "success", text: "Plantilla activada" });
      await loadData("notifications");
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error activando plantilla" });
    } finally {
      setTimeout(() => setSmtpMsg(null), 3000);
    }
  };

  const onTemplateHeaderUpload = (file) => {
    if (!file) return;
    if (file.size > 1.5 * 1024 * 1024) {
      setSmtpMsg({ type: "error", text: "La imagen de cabecera es demasiado grande (máx. 1.5MB)" });
      setTimeout(() => setSmtpMsg(null), 3500);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setTemplateConfig(prev => ({ ...prev, headerImageUrl: String(reader.result || "") }));
    };
    reader.readAsDataURL(file);
  };

  const generateTemplatePreview = async () => {
    if (!previewVulnId) return;
    setTemplatePreviewLoading(true);
    try {
      const res = await apiFetch("/notifications/template-preview", {
        method: "POST",
        body: JSON.stringify({
          vulnerabilityId: Number(previewVulnId),
          config: templateConfig,
        }),
      });
      if (!res.ok) throw new Error("Error generando vista previa");
      const data = await res.json();
      setTemplatePreviewHtml(data.html || "");
      setTemplatePreviewMeta({
        cveId: data.cveId || "",
        manufacturer: data.manufacturer || "",
      });
    } catch {
      setSmtpMsg({ type: "error", text: "Error generando vista previa" });
      setTimeout(() => setSmtpMsg(null), 3000);
    } finally {
      setTemplatePreviewLoading(false);
    }
  };

  const sw = collapsed ? 58 : 230;
  const currentUser = getUser();
  const allNav = [
    { id: "overview", label: "Visión General", icon: "shield" },
    { id: "vulns", label: "Vulnerabilidades", icon: "bug" },
    { id: "search", label: "Búsqueda", icon: "search" },
    { id: "exploited", label: "Explotación Activa", icon: "zap" },
    { id: "manufacturers", label: "Fabricantes", icon: "server" },
    { id: "notifications", label: "Comunicaciones", icon: "mail" },
    { id: "reports", label: "Informes", icon: "file" },
    { id: "ai", label: "Asistente IA", icon: "brain" },
    { id: "collector", label: "Collector", icon: "server" },
    { id: "settings", label: "Configuración", icon: "settings" },
  ];
  const isViewer = (currentUser?.role || "").toUpperCase() === "VIEWER";
  const viewerAllowedViews = ["overview", "vulns", "search", "exploited", "ai"];
  const nav = isViewer
    ? allNav.filter((n) => viewerAllowedViews.includes(n.id))
    : allNav;
  const backfillMetrics = parseMaybeJsonObject(backfillStatus?.job?.metrics);

  useEffect(() => {
    if (!isViewer) return;
    if (!viewerAllowedViews.includes(view)) {
      setView("overview");
    }
  }, [isViewer, view]);

  // Login screen
  if (!isLoggedIn) return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: `linear-gradient(135deg, ${C.navyDeep} 0%, ${C.navy} 50%, ${C.blue} 100%)`, fontFamily: "'Inter', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');`}</style>
      <div style={{ background: "#fff", borderRadius: 16, padding: "40px 36px", width: 380, boxShadow: "0 25px 60px rgba(0,0,0,0.3)" }}>
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{ width: 56, height: 56, background: C.navy, borderRadius: 14, display: "inline-flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 900, fontSize: 16, fontFamily: "'JetBrains Mono', monospace", marginBottom: 12 }}>OCC</div>
          <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 4px" }}>Servicios OCC</h1>
          <p style={{ fontSize: 11, color: C.gray500, margin: 0, letterSpacing: 1, textTransform: "uppercase" }}>Oficina de Ciberseguridad Corporativa</p>
        </div>
        {authMode === "login" && (
          <>
            <form onSubmit={handleLogin}>
              <div style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email</label>
                <input value={loginEmail} onChange={e => setLoginEmail(e.target.value)} type="email" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
              </div>
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contraseña</label>
                <input value={loginPass} onChange={e => setLoginPass(e.target.value)} type="password" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
              </div>
              <div style={{ textAlign: "right", marginBottom: 16 }}>
                <button type="button" onClick={() => { setAuthMode("forgot"); setForgotEmail(loginEmail); setLoginErr(""); }} style={{ background: "none", border: "none", color: C.blue, fontSize: 12, fontWeight: 600, cursor: "pointer", padding: 0 }}>
                  ¿Olvidaste tu contraseña?
                </button>
              </div>
              {loginErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{loginErr}</div>}
              <button type="submit" disabled={loginLoading} style={{ width: "100%", padding: "12px", fontSize: 14, fontWeight: 700, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer" }}>{loginLoading ? "Accediendo..." : "Iniciar Sesión"}</button>
            </form>
          </>
        )}

        {authMode === "forgot" && (
          <>
            <div style={{ fontSize: 12, color: C.gray600, marginBottom: 14 }}>
              Ingresa tu correo y te enviaremos un enlace de recuperación.
            </div>
            <form onSubmit={handleForgotPassword}>
              <div style={{ marginBottom: 14 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email</label>
                <input value={forgotEmail} onChange={e => setForgotEmail(e.target.value)} type="email" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
              </div>
              {forgotErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{forgotErr}</div>}
              {forgotMsg && <div style={{ background: C.infoBg, color: C.info, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{forgotMsg}</div>}
              <button type="submit" disabled={forgotLoading} style={{ width: "100%", padding: "12px", fontSize: 14, fontWeight: 700, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", marginBottom: 10 }}>{forgotLoading ? "Enviando..." : "Enviar enlace"}</button>
              <button type="button" onClick={() => { setAuthMode("login"); setForgotErr(""); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: "#fff", color: C.gray700, border: `1px solid ${C.gray300}`, borderRadius: 8, cursor: "pointer" }}>Volver al login</button>
            </form>
          </>
        )}

        {authMode === "reset" && (
          <>
            {tokenCheckLoading && <div style={{ background: C.infoBg, color: C.info, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>Validando enlace de recuperación...</div>}
            {!tokenCheckLoading && !tokenValid && (
              <>
                {resetErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{resetErr}</div>}
                <button type="button" onClick={() => { window.history.replaceState({}, "", "/"); setAuthMode("forgot"); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", marginBottom: 10 }}>Solicitar nuevo enlace</button>
                <button type="button" onClick={() => { window.history.replaceState({}, "", "/"); setAuthMode("login"); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: "#fff", color: C.gray700, border: `1px solid ${C.gray300}`, borderRadius: 8, cursor: "pointer" }}>Volver al login</button>
              </>
            )}

            {!tokenCheckLoading && tokenValid && (
              <form onSubmit={handleResetPassword}>
                <div style={{ fontSize: 12, color: C.gray600, marginBottom: 14 }}>
                  Define tu nueva contraseña para la cuenta <strong>{loginEmail || ""}</strong>.
                </div>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Nueva contraseña</label>
                  <input value={resetPass} onChange={e => setResetPass(e.target.value)} type="password" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
                </div>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Confirmar contraseña</label>
                  <input value={resetConfirm} onChange={e => setResetConfirm(e.target.value)} type="password" required style={{ width: "100%", padding: "11px 14px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 8, boxSizing: "border-box", outline: "none" }} />
                </div>
                {resetErr && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{resetErr}</div>}
                {resetMsg && <div style={{ background: C.infoBg, color: C.info, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 14, fontWeight: 500 }}>{resetMsg}</div>}
                <button type="submit" disabled={resetLoading} style={{ width: "100%", padding: "12px", fontSize: 14, fontWeight: 700, background: C.navy, color: "#fff", border: "none", borderRadius: 8, cursor: "pointer", marginBottom: 10 }}>{resetLoading ? "Actualizando..." : "Actualizar contraseña"}</button>
                <button type="button" onClick={() => { window.history.replaceState({}, "", "/"); setAuthMode("login"); }} style={{ width: "100%", padding: "11px", fontSize: 13, fontWeight: 700, background: "#fff", color: C.gray700, border: `1px solid ${C.gray300}`, borderRadius: 8, cursor: "pointer" }}>Volver al login</button>
              </form>
            )}
          </>
        )}
      </div>
    </div>
  );

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: C.gray50, fontFamily: "'Inter', -apple-system, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap');
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { to{transform:rotate(360deg)} }
        .fade { animation: fadeIn 0.35s ease both; }
        .rh:hover { background: ${C.gray50} !important; }
        .bh:hover { filter: brightness(0.93); }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-thumb { background: ${C.gray300}; border-radius: 3px; }
        textarea:focus, select:focus { outline: none; border-color: ${C.blue} !important; }
      `}</style>

      {/* ── SIDEBAR ── */}
      <nav style={{ width: sw, background: `linear-gradient(180deg, ${C.navyDeep} 0%, ${C.navyDark} 100%)`, color: "#fff", position: "fixed", top: 0, left: 0, height: "100vh", zIndex: 100, transition: "width 0.2s ease", display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ padding: collapsed ? "16px 12px" : "16px 18px", borderBottom: "1px solid rgba(255,255,255,0.07)", display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 32, height: 32, background: C.blue, borderRadius: 7, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 10, flexShrink: 0, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.5px" }}>OCC</div>
          {!collapsed && <div><div style={{ fontSize: 13, fontWeight: 700 }}>Servicios OCC</div><div style={{ fontSize: 8, color: C.gray500, letterSpacing: "1.5px", textTransform: "uppercase" }}>Oficina Ciberseguridad</div></div>}
        </div>
        <div style={{ flex: 1, padding: "12px 0", overflowY: "auto" }}>
          {!collapsed && <div style={{ padding: "4px 18px 8px", fontSize: 8, fontWeight: 700, color: C.gray500, letterSpacing: "2px", textTransform: "uppercase" }}>Módulos</div>}
          {nav.map(n => (
            <div key={n.id} onClick={() => setView(n.id)} style={{ display: "flex", alignItems: "center", gap: 10, padding: collapsed ? "10px 18px" : "9px 18px", cursor: "pointer", color: view === n.id ? "#fff" : C.gray500, background: view === n.id ? "rgba(59,108,181,0.15)" : "transparent", borderLeft: view === n.id ? `3px solid ${C.blue}` : "3px solid transparent", transition: "all 0.12s" }} onMouseEnter={e => { if (view !== n.id) e.currentTarget.style.background = "rgba(255,255,255,0.03)"; }} onMouseLeave={e => { if (view !== n.id) e.currentTarget.style.background = "transparent"; }}>
              <I name={n.icon} size={17} color={view === n.id ? C.blueLight : C.gray500} />
              {!collapsed && <span style={{ fontSize: 12, fontWeight: view === n.id ? 600 : 400 }}>{n.label}</span>}
            </div>
          ))}
        </div>
        <div style={{ padding: "10px 14px", borderTop: "1px solid rgba(255,255,255,0.06)", fontSize: 10 }}>
          <div onClick={() => setCollapsed(!collapsed)} style={{ cursor: "pointer", color: C.gray500, display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ transform: collapsed ? "rotate(180deg)" : "none", transition: "transform 0.2s", display: "inline-block" }}>◀</span>
            {!collapsed && "Colapsar"}
          </div>
        </div>
      </nav>

      {/* ── MAIN ── */}
      <main style={{ flex: 1, marginLeft: sw, transition: "margin-left 0.2s ease", minHeight: "100vh", display: "flex", flexDirection: "column" }}>
        {/* Header */}
        <header style={{ height: 52, background: "#fff", borderBottom: `1px solid ${C.gray200}`, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 22px", position: "sticky", top: 0, zIndex: 50 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: C.gray500 }}>
            <span>OCC</span><span style={{ color: C.gray300 }}>/</span>
            <span style={{ color: C.text, fontWeight: 600 }}>{nav.find(n => n.id === view)?.label}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <span style={{ fontSize: 10, color: C.gray400, fontFamily: "monospace" }}>
              Próx. scan: {nextRun()}
            </span>
            {currentUser && <span style={{ fontSize: 11, color: C.gray600 }}>{currentUser.name || currentUser.email}</span>}
            <div style={{ width: 30, height: 30, borderRadius: "50%", background: C.navy, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 700, fontSize: 11, cursor: "pointer" }} title="Cerrar Sesión" onClick={handleLogout}>{(currentUser?.name || "A")[0].toUpperCase()}</div>
          </div>
        </header>

        <div style={{ padding: 22, flex: 1 }} className="fade" key={view}>

          {/* ═══ OVERVIEW ═══ */}
          {view === "overview" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 4px" }}>Panel de Vulnerabilidades</h1>
            <p style={{ color: C.gray500, fontSize: 12, marginBottom: 20 }}>Última actualización: {fmtDate(dash?.lastRun?.finishedAt)}</p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 20 }}>
              <Metric icon="bug" label="Total CVEs" value={dash?.totalAll ?? 0} sub="En base de datos" color={C.navy} />
              <Metric icon="alert" label="Últimas 24h" value={todayT} sub={`${gc(dash?.today, "CRITICAL")} críticas`} color={C.critical} />
              <Metric icon="zap" label="Explotación activa" value={(dash?.topExploited || []).length} sub="CISA KEV confirmadas" color="#B91C1C" />
              <Metric icon="activity" label="Semana" value={weekT} sub={`${gc(dash?.week, "HIGH")} altas`} color={C.high} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <Card title="Severidad (24h)" icon="shield">
                <Bar label="Critical" count={gc(dash?.today, "CRITICAL")} total={todayT} color={C.critical} />
                <Bar label="High" count={gc(dash?.today, "HIGH")} total={todayT} color={C.high} />
                <Bar label="Medium" count={gc(dash?.today, "MEDIUM")} total={todayT} color={C.medium} />
                <Bar label="Low" count={gc(dash?.today, "LOW")} total={todayT} color={C.low} />
              </Card>
              <Card title="Estado Collector" icon="server">
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
                  {[["CVEs", dash?.lastRun?.cvesFetched ?? 0], ["Nuevos", dash?.lastRun?.cvesNew ?? 0], ["Duración", fmtMs(dash?.lastRun?.durationMs ?? 0)]].map(([l, v]) => (
                    <div key={l} style={{ background: C.gray50, borderRadius: 6, padding: "8px 10px", textAlign: "center" }}>
                      <div style={{ fontSize: 9, color: C.gray500, fontWeight: 600, textTransform: "uppercase" }}>{l}</div>
                      <div style={{ fontSize: 20, fontWeight: 800, color: C.text, fontFamily: "monospace" }}>{v}</div>
                    </div>
                  ))}
                </div>
                <Btn primary onClick={handleCollect} disabled={collecting} style={{ width: "100%" }}>
                  {collecting ? <><span style={{ animation: "spin 1s linear infinite", display: "inline-block" }}>⟳</span> Recolectando...</> : <><I name="refresh" size={14} color="#fff" /> Recolección manual</>}
                </Btn>
              </Card>
            </div>

            <Card title="Explotación Activa — Acción Inmediata" icon="zap" noPad style={{ marginTop: 16 }} action={<span onClick={() => setView("exploited")} style={{ fontSize: 11, color: C.blue, cursor: "pointer", fontWeight: 600 }}>Ver todas →</span>}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr style={{ background: C.gray50 }}>
                  {["CVE", "CVSS", "EPSS", "Producto", "Equipo IT", "Hace"].map(h => (
                    <th key={h} style={{ padding: "9px 14px", textAlign: "left", fontSize: 9, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.8px", borderBottom: `1px solid ${C.gray200}` }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{(dash?.topExploited || []).map(v => {
                  const aff = getAffectedContacts(v);
                  return (
                    <tr key={v.cveId} className="rh" style={{ cursor: "pointer" }} onClick={() => openVulnerabilityDetail(v)}>
                      <td style={{ padding: "10px 14px", fontWeight: 700, fontSize: 12, fontFamily: "monospace", color: C.critical }}>{v.cveId}</td>
                      <td style={{ padding: "10px 14px" }}><SevBadge s={v.cvssV31Severity} small /> <span style={{ fontFamily: "monospace", fontSize: 12, fontWeight: 700, marginLeft: 4 }}>{fmtScore(v.cvssV31Score)}</span></td>
                      <td style={{ padding: "10px 14px", fontFamily: "monospace", fontSize: 12, fontWeight: 600 }}>{fmtEpss(v.epssScore)}</td>
                      <td style={{ padding: "10px 14px" }}>{(v.affectedProducts || []).map((p, i) => <span key={i} style={{ display: "inline-block", background: C.bluePale, color: C.navy, padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600, marginRight: 3 }}>{p.vendor}/{p.product}</span>)}</td>
                      <td style={{ padding: "10px 14px" }}>{aff.map(c => <span key={c.id} style={{ display: "inline-block", background: "#F0F0F0", padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600, marginRight: 3, color: C.gray700 }}>{c.name.split(" ").slice(1, 3).join(" ")}</span>)}</td>
                      <td style={{ padding: "10px 14px", fontSize: 10, color: C.gray500, fontFamily: "monospace" }}>{timeAgo(v.firstSeenAt)}</td>
                    </tr>
                  );
                })}</tbody>
              </table>
            </Card>
          </>}

          {/* ═══ VULNERABILITIES ═══ */}
          {
            view === "vulns" && <>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: 0 }}>Vulnerabilidades</h1>
                <div style={{ display: "flex", gap: 6 }}>
                  {["", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
                    <button key={s} onClick={() => setSevFilter(s)} className="bh" style={{ padding: "5px 12px", borderRadius: 5, fontSize: 10, fontWeight: 600, border: sevFilter === s ? "none" : `1px solid ${C.gray200}`, background: sevFilter === s ? (s ? sevColor(s) : C.navy) : "#fff", color: sevFilter === s ? "#fff" : C.gray600, cursor: "pointer", transition: "all 0.12s" }}>{s || "Todas"}</button>
                  ))}
                </div>
              </div>

              <Card noPad>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr style={{ background: C.gray50 }}>
                    {["CVE", "Sev", "CVSS", "EPSS", "KEV", "Exploit", "Productos", "Tags", "Publicada"].map(h => (
                      <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontSize: 9, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", borderBottom: `2px solid ${C.gray200}`, whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>{vulns.filter(v => !sevFilter || v.cvssV31Severity === sevFilter).map(v => (
                    <tr key={v.cveId} className="rh" onClick={() => openVulnerabilityDetail(v)} style={{ cursor: "pointer", background: v.isKnownExploited ? C.criticalBg : "#fff", borderLeft: v.isKnownExploited ? `3px solid ${C.critical}` : "3px solid transparent", transition: "background 0.1s" }}>
                      <td style={{ padding: "10px 12px", fontWeight: 700, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>{v.cveId}</td>
                      <td style={{ padding: "10px 12px" }}><SevBadge s={v.cvssV31Severity} small /></td>
                      <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 11, fontWeight: 700 }}>{fmtScore(v.cvssV31Score)}</td>
                      <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 11, color: (v.epssScore || 0) > 0.1 ? C.high : C.text }}>{fmtEpss(v.epssScore)}</td>
                      <td style={{ padding: "10px 12px" }}>{v.isKnownExploited ? <span style={{ fontSize: 14 }}>⚡</span> : <span style={{ color: C.gray300 }}>-</span>}</td>
                      <td style={{ padding: "10px 12px" }}>{v.hasPublicExploit ? <I name="bug" size={14} color={C.critical} /> : <span style={{ color: C.gray300 }}>-</span>}</td>
                      <td style={{ padding: "10px 12px" }}>{(v.affectedProducts || []).slice(0, 2).map((p, i) => <span key={i} style={{ display: "inline-block", background: C.bluePale, color: C.navy, padding: "1px 5px", borderRadius: 3, fontSize: 9, fontWeight: 600, marginRight: 3, marginBottom: 2 }}>{p.vendor}/{p.product}</span>)} {(v.affectedProducts || []).length > 2 && <span style={{ fontSize: 9, color: C.gray500 }}>+{v.affectedProducts.length - 2}</span>}</td>
                      <td style={{ padding: "10px 12px" }}>{(v.tags || []).map(t => <span key={t.id} style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: t.color, marginRight: 2 }} title={t.name} />)}</td>
                      <td style={{ padding: "10px 12px", fontSize: 10, color: C.gray500, fontFamily: "monospace" }}>{fmtDate(v.publishedAt).split(",")[0]}</td>
                    </tr>
                  ))}</tbody>
                </table>
                {vulns.length === 0 && <div style={{ padding: 40, textAlign: "center", color: C.gray400, fontSize: 13 }}>No hay vulnerabilidades que mostrar</div>}
              </Card>

              {/* VULN DETAIL OVERLAY */}
              {vulnDetail && (
                <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.5)", zIndex: 110, display: "flex", justifyContent: "flex-end" }} onClick={() => setVulnDetail(null)}>
                  <div style={{ width: 800, background: "#fff", height: "100%", overflowY: "auto", padding: 32, boxShadow: "-10px 0 40px rgba(0,0,0,0.2)" }} onClick={e => e.stopPropagation()}>
                    {vulnLoading ? <div style={{ padding: 40, textAlign: "center" }}>Cargando...</div> : <>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
                            <h2 style={{ fontSize: 28, fontWeight: 800, margin: 0, fontFamily: "'JetBrains Mono', monospace", color: C.navy }}>{vulnDetail.cveId}</h2>
                            <SevBadge s={vulnDetail.cvssV31Severity} />
                            {vulnDetail.isKnownExploited && <span style={{ background: C.criticalBg, color: C.critical, padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, border: `1px solid ${C.critical}` }}>⚡ KEV: EXPLOTACIÓN ACTIVA</span>}
                          </div>
                          <div style={{ fontSize: 11, color: C.gray500, fontFamily: "monospace" }}>Publicado: {fmtDate(vulnDetail.publishedAt)} · Actualizado: {fmtDate(vulnDetail.lastModifiedAt)}</div>
                        </div>
                        <button onClick={() => setVulnDetail(null)} style={{ border: "none", background: "transparent", cursor: "pointer" }}><I name="x" size={24} color={C.gray400} /></button>
                      </div>

                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 24 }}>
                        <Metric icon="shield" label="CVSS Score" value={fmtScore(vulnDetail.cvssV31Score)} sub={vulnDetail.cvssV31Vector} color={sevColor(vulnDetail.cvssV31Severity)} />
                        <Metric icon="activity" label="EPSS Prob." value={fmtEpss(vulnDetail.epssScore)} sub={`Percentile: ${((vulnDetail.epssPercentile || 0) * 100).toFixed(0)}%`} color={C.blue} />
                        <Metric icon="bug" label="Exploit Público" value={vulnDetail.hasPublicExploit ? "SÍ" : "NO"} sub={vulnDetail.hasPublicExploit ? `${(vulnDetail.exploitReferences?.length || 0)} referencias` : "No detectado"} color={vulnDetail.hasPublicExploit ? C.critical : C.low} />
                      </div>

                      <div style={{ marginBottom: 24 }}>
                        <h3 style={{ fontSize: 14, fontWeight: 700, color: C.gray700, marginBottom: 8, textTransform: "uppercase" }}>Descripción</h3>
                        <p style={{ fontSize: 13, lineHeight: 1.6, color: C.gray700, background: C.gray50, padding: 16, borderRadius: 8, border: `1px solid ${C.gray200}` }}>
                          {vulnDetail.description}
                        </p>
                      </div>

                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 24 }}>
                        <div>
                          <h3 style={{ fontSize: 14, fontWeight: 700, color: C.gray700, marginBottom: 12, textTransform: "uppercase" }}>Etiquetas</h3>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
                            {vulnDetail.tags.map(t => (
                              <span key={t.id} style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 12, background: `${t.color}15`, color: t.color, fontSize: 11, fontWeight: 600, border: `1px solid ${t.color}30` }}>
                                {t.name}
                                <span style={{ cursor: "pointer", opacity: 0.6 }} onClick={() => handleVulnTags(vulnDetail.tags.filter(x => x.id !== t.id))}>×</span>
                              </span>
                            ))}
                            <div style={{ position: "relative" }}>
                              <button onClick={() => document.getElementById("tag-dropdown").style.display = "block"} style={{ background: C.gray100, border: "none", borderRadius: 12, width: 24, height: 24, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}><I name="plus" size={14} color={C.gray600} /></button>
                              <div id="tag-dropdown" style={{ display: "none", position: "absolute", top: 30, left: 0, background: "#fff", border: `1px solid ${C.gray200}`, boxShadow: "0 10px 20px rgba(0,0,0,0.1)", borderRadius: 8, padding: 8, width: 200, zIndex: 120 }}>
                                {tags.filter(t => !vulnDetail.tags.find(vt => vt.id === t.id)).map(t => (
                                  <div key={t.id} onClick={() => { handleVulnTags([...vulnDetail.tags, t]); document.getElementById("tag-dropdown").style.display = "none"; }} style={{ padding: "6px 10px", fontSize: 12, cursor: "pointer", borderRadius: 4 }} className="rh">
                                    <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: t.color, marginRight: 8 }} />
                                    {t.name}
                                  </div>
                                ))}
                                {tags.length === 0 && <div style={{ fontSize: 11, color: C.gray500, padding: 8 }}>No hay tags disponibles. Créalos en Configuración.</div>}
                                <div style={{ borderTop: `1px solid ${C.gray100}`, marginTop: 4, paddingTop: 4, textAlign: "center", fontSize: 10, color: C.blue, cursor: "pointer" }} onClick={() => document.getElementById("tag-dropdown").style.display = "none"}>Cerrar</div>
                              </div>
                            </div>
                          </div>
                        </div>
                        <div>
                          <h3 style={{ fontSize: 14, fontWeight: 700, color: C.gray700, marginBottom: 12, textTransform: "uppercase" }}>Software Afectado ({((vulnDetail.affectedProducts || []).length)})</h3>
                          <div style={{ maxHeight: 150, overflowY: "auto", border: `1px solid ${C.gray200}`, borderRadius: 6 }}>
                            {(vulnDetail.affectedProducts || []).map((p, i) => (
                              <div key={i} style={{ padding: "6px 10px", borderBottom: `1px solid ${C.gray100}`, fontSize: 11 }}>
                                <span style={{ fontWeight: 700, color: C.navy }}>{p.vendor}</span> / {p.product} <span style={{ color: C.gray500 }}>{p.versionRange || ""}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      <div style={{ marginBottom: 24 }}>
                        <h3 style={{ fontSize: 14, fontWeight: 700, color: C.gray700, marginBottom: 12, textTransform: "uppercase" }}>Referencias Oficiales & Parches</h3>
                        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                          <a href={`https://nvd.nist.gov/vuln/detail/${vulnDetail.cveId}`} target="_blank" rel="noreferrer" style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 14px", background: "#fff", border: `1px solid ${C.gray300}`, borderRadius: 6, textDecoration: "none", color: C.navy, fontSize: 12, fontWeight: 600 }}>
                            <img src="https://nvd.nist.gov/site-media/images/NIST_logo_bw_64.png" height="14" alt="" /> NVD NIST <I name="link" size={12} />
                          </a>
                          {vulnDetail.remediationInfo?.patchAvailable && (vulnDetail.remediationInfo.patchUrls || []).map((url, i) => (
                            <a key={i} href={url} target="_blank" rel="noreferrer" style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 14px", background: C.lowBg, border: `1px solid ${C.low}`, borderRadius: 6, textDecoration: "none", color: C.low, fontSize: 12, fontWeight: 600 }}>
                              <I name="check" size={12} /> Patch / Advisor <I name="link" size={12} />
                            </a>
                          ))}
                          {(vulnDetail.references || []).slice(0, 3).map((ref, i) => (
                            <a key={i} href={ref.url} target="_blank" rel="noreferrer" style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 14px", background: C.gray50, border: `1px solid ${C.gray200}`, borderRadius: 6, textDecoration: "none", color: C.gray600, fontSize: 12 }}>
                              Reference {i + 1} <I name="link" size={12} />
                            </a>
                          ))}
                        </div>
                      </div>

                      <div style={{ background: C.gray50, borderRadius: 8, padding: 20, border: `1px solid ${C.gray200}` }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                          <h3 style={{ fontSize: 14, fontWeight: 700, color: C.navy, margin: 0, display: "flex", alignItems: "center", gap: 8 }}><I name="mail" size={16} /> Notificaciones y Alertas</h3>
                          <Btn small primary onClick={openNotifyModal}><I name="send" size={12} /> Notificar a contacto</Btn>
                        </div>

                        {showNotifModal && (
                          <div style={{ marginBottom: 16, background: "#fff", padding: 16, borderRadius: 6, border: `1px solid ${C.blue}`, animation: "fadeIn 0.2s" }}>
                            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>Selecciona un contacto para enviar alerta sobre {vulnDetail.cveId}:</div>
                            <div style={{ display: "flex", gap: 8 }}>
                              <select id="contact-select" disabled={notifContactsLoading || contacts.length === 0} style={{ flex: 1, padding: 8, borderRadius: 4, border: `1px solid ${C.gray300}` }}>
                                {notifContactsLoading && <option value="">Cargando contactos...</option>}
                                {!notifContactsLoading && contacts.length === 0 && <option value="">No hay contactos disponibles</option>}
                                {!notifContactsLoading && contacts.map(c => <option key={c.id} value={c.id}>{c.name} ({c.email})</option>)}
                              </select>
                              <Btn small primary disabled={notifSending || notifContactsLoading || contacts.length === 0} onClick={() => handleNotifyContact(document.getElementById("contact-select").value)}>
                                {notifSending ? "Enviando..." : "Enviar Email"}
                              </Btn>
                              <Btn small onClick={() => setShowNotifModal(false)}>Cancelar</Btn>
                            </div>
                          </div>
                        )}

                        <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff", borderRadius: 6, overflow: "hidden" }}>
                          <thead><tr style={{ background: C.gray100, borderBottom: `1px solid ${C.gray200}` }}>
                            {["Fecha", "Destinatario", "Estado"].map(h => <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 10, color: C.gray600 }}>{h}</th>)}
                          </tr></thead>
                          <tbody>
                            {(vulnDetail.notifications || []).length === 0 ? (
                              <tr><td colSpan={3} style={{ padding: 12, textAlign: "center", fontSize: 11, color: C.gray500 }}>Sin notificaciones enviadas</td></tr>
                            ) : vulnDetail.notifications.map(n => (
                              <tr key={n.id} style={{ borderBottom: `1px solid ${C.gray100}` }}>
                                <td style={{ padding: "8px 12px", fontSize: 11, fontFamily: "monospace" }}>{fmtDate(n.sentAt)}</td>
                                <td style={{ padding: "8px 12px", fontSize: 11 }}>{n.recipientName} ({n.recipientEmail})</td>
                                <td style={{ padding: "8px 12px", fontSize: 10, fontWeight: 700, color: n.status === "sent" ? C.low : C.critical }}>{n.status.toUpperCase()}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      <div style={{ marginTop: 24, textAlign: "right" }}>
                        <Btn onClick={() => analyzeVulnerabilityWithAi(vulnDetail)} style={{ marginRight: 12 }}><I name="brain" size={14} /> Analizar con IA</Btn>
                        <Btn onClick={() => setVulnDetail(null)}>Cerrar</Btn>
                      </div>

                    </>}
                  </div>
                </div>
              )}
            </>
          }

          {/* ═══ SEARCH ═══ */}
          {view === "search" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 16px" }}>Búsqueda de Vulnerabilidades</h1>
            <Card>
              <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
                <div style={{ flex: 1 }}>
                  <Input value={searchQ} onChange={setSearchQ} placeholder="Buscar por CVE, producto, vendor, descripción..." icon="search" />
                </div>
                <select value={searchType} onChange={e => setSearchType(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff", minWidth: 140 }}>
                  <option value="all">Todo</option>
                  <option value="cve">CVE ID</option>
                  <option value="product">Producto / Vendor</option>
                </select>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, minmax(120px, 1fr))", gap: 10, marginBottom: 12 }}>
                <select value={searchTagId} onChange={e => setSearchTagId(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff" }}>
                  <option value="">Etiqueta (todas)</option>
                  {tags.map(t => <option key={t.id} value={String(t.id)}>{t.name}</option>)}
                </select>
                <select value={searchSeverity} onChange={e => setSearchSeverity(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff" }}>
                  <option value="">Criticidad (todas)</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
                <select value={searchExploit} onChange={e => setSearchExploit(e.target.value)} style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff" }}>
                  <option value="all">Exploit (todos)</option>
                  <option value="known">KEV (explotación activa)</option>
                  <option value="public">Exploit público</option>
                  <option value="any">Cualquier explotación</option>
                  <option value="none">Sin explotación</option>
                </select>
                <input
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  value={searchMinScore}
                  onChange={e => setSearchMinScore(e.target.value)}
                  placeholder="CVSS mínimo (ej. 7.5)"
                  style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff", boxSizing: "border-box" }}
                />
                <Btn onClick={() => { setSearchQ(""); setSearchType("all"); setSearchTagId(""); setSearchPublishedFrom(""); setSearchPublishedTo(""); setSearchMinScore(""); setSearchExploit("all"); setSearchSeverity(""); }}>Limpiar filtros</Btn>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 14 }}>
                <input
                  type="date"
                  value={searchPublishedFrom}
                  onChange={e => setSearchPublishedFrom(e.target.value)}
                  style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff", boxSizing: "border-box" }}
                />
                <input
                  type="date"
                  value={searchPublishedTo}
                  onChange={e => setSearchPublishedTo(e.target.value)}
                  style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff", boxSizing: "border-box" }}
                />
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
                <span style={{ fontSize: 11, color: C.gray500, lineHeight: "26px" }}>Búsquedas rápidas:</span>
                {["fortinet", "microsoft", "ivanti", "cisco", "CVE-2025", "sonicwall", "apple"].map(q => (
                  <span key={q} onClick={() => { setSearchQ(q); setSearchType(q.startsWith("CVE") ? "cve" : "product"); }} style={{ padding: "3px 10px", background: C.bluePale, color: C.navy, borderRadius: 4, fontSize: 11, fontWeight: 600, cursor: "pointer", transition: "all 0.1s" }}>{q}</span>
                ))}
              </div>
            </Card>

            {hasSearchCriteria && (
              <div className="fade" style={{ marginTop: 14 }}>
                <div style={{ fontSize: 12, color: C.gray500, marginBottom: 10 }}>
                  {searchResults.length} resultado{searchResults.length !== 1 ? "s" : ""}
                </div>
                {searchResults.map(v => {
                  const aff = getAffectedContacts(v);
                  return (
                    <Card key={v.cveId} style={{ marginBottom: 10, borderLeft: `3px solid ${sevColor(v.cvssV31Severity)}` }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                            <span style={{ fontSize: 15, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace" }}>{v.cveId}</span>
                            <SevBadge s={v.cvssV31Severity} small />
                            <span style={{ fontFamily: "monospace", fontWeight: 700, fontSize: 13 }}>{fmtScore(v.cvssV31Score)}</span>
                            {v.isKnownExploited && <span style={{ background: C.critical, color: "#fff", padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 700 }}>KEV</span>}
                            {v.hasPublicExploit && <span style={{ background: C.high, color: "#fff", padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 700 }}>EXPLOIT</span>}
                          </div>
                          <p style={{ color: C.gray600, fontSize: 11, lineHeight: 1.5, margin: "0 0 8px" }}>{v.description}</p>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                            {(v.affectedProducts || []).map((p, i) => <span key={i} style={{ background: C.bluePale, color: C.navy, padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600 }}>{p.vendor}/{p.product} {p.versionRange ? `(${p.versionRange})` : ""}</span>)}
                          </div>
                          {aff.length > 0 && (
                            <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap" }}>
                              <I name="users" size={12} color={C.gray400} />
                              {aff.map(c => <span key={c.id} style={{ fontSize: 10, color: C.gray600 }}>{c.name} ({c.email})</span>)}
                            </div>
                          )}
                        </div>
                        <div style={{ textAlign: "right", flexShrink: 0, marginLeft: 12 }}>
                          <div style={{ fontSize: 10, color: C.gray400 }}>EPSS {fmtEpss(v.epssScore)}</div>
                          <div style={{ fontSize: 10, color: C.gray400 }}>{fmtDate(v.publishedAt)}</div>
                          <Btn small style={{ marginTop: 6 }} onClick={() => openVulnerabilityDetail(v)}>Detalle →</Btn>
                        </div>
                      </div>
                    </Card>
                  );
                })}
                {searchResults.length === 0 && <Card><div style={{ textAlign: "center", padding: 20, color: C.gray500 }}>Sin resultados con los filtros actuales</div></Card>}
              </div>
            )}
          </>}

          {/* ═══ EXPLOITED ═══ */}
          {view === "exploited" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 14px" }}>Explotación Activa</h1>
            <div style={{ background: C.critical, color: "#fff", borderRadius: 8, padding: "14px 18px", marginBottom: 16, display: "flex", alignItems: "center", gap: 10 }}>
              <I name="alert" size={20} color="#fff" />
              <div><div style={{ fontWeight: 700, fontSize: 13 }}>{vulns.filter(v => v.isKnownExploited).length} vulnerabilidades con explotación activa</div><div style={{ fontSize: 11, opacity: 0.85 }}>Parcheo prioritario según CISA BOD 22-01</div></div>
            </div>
            {vulns.filter(v => v.isKnownExploited).map(v => {
              const aff = getAffectedContacts(v);
              return (
                <Card key={v.cveId} style={{ marginBottom: 10, borderLeft: `4px solid ${C.critical}` }}>
                  <div
                    onClick={() => openVulnerabilityDetail(v)}
                    style={{ cursor: "pointer" }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ fontSize: 16, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace" }}>{v.cveId}</span>
                        <SevBadge s={v.cvssV31Severity} /><span style={{ fontFamily: "monospace", fontWeight: 800, fontSize: 14 }}>{fmtScore(v.cvssV31Score)}</span>
                      </div>
                      <span style={{ fontSize: 10, color: C.gray500 }}>EPSS {fmtEpss(v.epssScore)}</span>
                    </div>
                    <p style={{ color: C.gray600, fontSize: 11, lineHeight: 1.5, marginBottom: 10 }}>{v.description}</p>
                    <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginBottom: 8 }}>
                      {(v.affectedProducts || []).map((p, i) => <span key={i} style={{ background: C.bluePale, color: C.navy, padding: "2px 8px", borderRadius: 3, fontSize: 10, fontWeight: 600 }}>{p.vendor}/{p.product}</span>)}
                    </div>
                    {aff.length > 0 && (
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                        {aff.map(c => (
                          <div key={c.id} style={{ display: "flex", alignItems: "center", gap: 6, background: C.gray50, padding: "4px 10px", borderRadius: 4, fontSize: 10 }}>
                            <I name="mail" size={12} color={C.blue} />
                            <strong>{c.name.split(" ").slice(1, 3).join(" ")}</strong>
                            <span style={{ color: C.gray500 }}>{c.email}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    <div style={{ padding: "8px 10px", borderRadius: 4, background: v.remediationInfo?.patchAvailable ? C.lowBg : C.highBg, fontSize: 11, borderLeft: `3px solid ${v.remediationInfo?.patchAvailable ? C.low : C.high}` }}>
                      <strong>{v.remediationInfo?.patchAvailable ? "✅ Parche disponible" : "❌ Sin parche"}</strong>
                    </div>
                  </div>
                </Card>
              );
            })}
          </>}

          {/* ═══ MANUFACTURERS ═══ */}
          {view === "manufacturers" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 4px" }}>Fabricantes</h1>
            <p style={{ color: C.gray500, fontSize: 12, marginBottom: 16 }}>Gestión avanzada de fabricantes y software para suscripciones automáticas.</p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
              <Card title="Nuevo Fabricante" icon="plus">
                <div style={{ display: "flex", gap: 8 }}>
                  <Input value={newManufacturerName} onChange={setNewManufacturerName} placeholder="ej: adobe" style={{ flex: 1 }} />
                  <Btn primary onClick={createManufacturer}>Crear</Btn>
                </div>
              </Card>
              <Card title="Nuevo Producto" icon="plus">
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
                  <select
                    value={newProductForm.vendor}
                    onChange={e => setNewProductForm({ ...newProductForm, vendor: e.target.value })}
                    style={{ padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff", fontSize: 12 }}
                  >
                    <option value="">Selecciona fabricante</option>
                    {manufacturers.map(m => <option key={m.name} value={m.name}>{m.name}</option>)}
                  </select>
                  <Input value={newProductForm.product} onChange={v => setNewProductForm({ ...newProductForm, product: v })} placeholder="producto" />
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <Input value={newProductForm.versions} onChange={v => setNewProductForm({ ...newProductForm, versions: v })} placeholder="versiones (coma separadas)" style={{ flex: 1 }} />
                  <Btn primary onClick={createManufacturerProduct}>Crear</Btn>
                </div>
              </Card>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 12 }}>
              <Card title="Listado de Fabricantes" icon="server">
                {manufacturersLoading && <div style={{ fontSize: 12, color: C.gray500 }}>Cargando...</div>}
                {!manufacturersLoading && manufacturers.length === 0 && <div style={{ fontSize: 12, color: C.gray500 }}>No hay fabricantes todavía.</div>}
                {!manufacturersLoading && manufacturers.map(m => (
                  <div
                    key={m.name}
                    onClick={() => {
                      setSelectedManufacturer(m.name);
                      setNewProductForm(prev => ({ ...prev, vendor: m.name }));
                      setMergeForm({ targetName: m.name, sourceNames: [m.name] });
                    }}
                    style={{
                      padding: "8px 10px",
                      borderRadius: 6,
                      border: `1px solid ${selectedManufacturer === m.name ? C.blue : C.gray200}`,
                      background: selectedManufacturer === m.name ? C.bluePale : "#fff",
                      cursor: "pointer",
                      marginBottom: 6,
                    }}
                  >
                    <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{m.name}</div>
                    <div style={{ fontSize: 10, color: C.gray500 }}>{m.productsCount} productos</div>
                  </div>
                ))}
              </Card>

              <Card
                title={selectedManufacturer ? `Software vinculado a ${selectedManufacturer}` : "Software vinculado"}
                icon="edit"
              >
                {selectedManufacturer && (
                  <>
                    <div style={{ marginBottom: 14 }}>
                      {((manufacturers.find(m => m.name === selectedManufacturer)?.products) || []).map(p => (
                        <div key={`${p.id}-${p.product}`} style={{ padding: "8px 10px", border: `1px solid ${C.gray200}`, borderRadius: 6, background: C.gray50, marginBottom: 6 }}>
                          <div style={{ fontSize: 12, fontWeight: 700 }}>{p.product}</div>
                          <div style={{ fontSize: 10, color: C.gray500 }}>
                            {(p.versions || []).length > 0 ? `Versiones: ${p.versions.join(", ")}` : "Versiones: todas"}
                          </div>
                        </div>
                      ))}
                      {((manufacturers.find(m => m.name === selectedManufacturer)?.products) || []).length === 0 && (
                        <div style={{ fontSize: 12, color: C.gray500 }}>No hay productos vinculados a este fabricante.</div>
                      )}
                    </div>

                    <div style={{ borderTop: `1px solid ${C.gray200}`, paddingTop: 12 }}>
                      <h3 style={{ fontSize: 13, fontWeight: 700, margin: "0 0 8px" }}>Armonizar / unir fabricantes</h3>
                      <div style={{ marginBottom: 8 }}>
                        <label style={{ fontSize: 11, color: C.gray600, display: "block", marginBottom: 4 }}>Nombre final del fabricante</label>
                        <Input value={mergeForm.targetName} onChange={v => setMergeForm({ ...mergeForm, targetName: v })} placeholder="fabricante objetivo" />
                      </div>
                      <div style={{ maxHeight: 140, overflow: "auto", border: `1px solid ${C.gray200}`, borderRadius: 6, padding: 8, background: "#fff" }}>
                        {manufacturers.map(m => {
                          const checked = (mergeForm.sourceNames || []).includes(m.name);
                          return (
                            <label key={`merge-${m.name}`} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 2px", fontSize: 12 }}>
                              <input type="checkbox" checked={checked} onChange={e => toggleMergeSource(m.name, e.target.checked)} />
                              <span>{m.name}</span>
                            </label>
                          );
                        })}
                      </div>
                      <div style={{ marginTop: 8 }}>
                        <Btn primary onClick={applyManufacturerMerge}>Aplicar armonización</Btn>
                      </div>
                    </div>
                  </>
                )}
                {!selectedManufacturer && <div style={{ fontSize: 12, color: C.gray500 }}>Selecciona un fabricante de la lista para ver su software.</div>}
              </Card>
            </div>
          </>}

          {/* ═══ CONTACTS ═══ */}
          {view === "contacts" && <>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div>
                <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: 0 }}>Servicios IT</h1>
                <p style={{ color: C.gray500, fontSize: 12, marginTop: 2 }}>Directorio de equipos IT para comunicación de vulnerabilidades</p>
              </div>
              <Btn primary onClick={() => { setEditContact({ id: null, name: "", email: "", products: [], notes: "", contactPerson: "", phone: "", department: "" }); setShowContactForm(true); }}><I name="plus" size={14} color="#fff" /> Nuevo servicio</Btn>
            </div>

            {showContactForm && editContact && (
              <Card title={editContact.id ? "Editar servicio IT" : "Nuevo servicio IT"} icon="edit" style={{ marginBottom: 16 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Nombre del equipo</label>
                    <Input value={editContact.name} onChange={v => setEditContact({ ...editContact, name: v })} placeholder="Ej: Equipo Infraestructura Windows" />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email de contacto</label>
                    <Input value={editContact.email} onChange={v => setEditContact({ ...editContact, email: v })} placeholder="equipo@corp.local" icon="mail" />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Persona de contacto</label>
                    <Input value={editContact.contactPerson} onChange={v => setEditContact({ ...editContact, contactPerson: v })} placeholder="Nombre y apellido" />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Teléfono</label>
                    <Input value={editContact.phone} onChange={v => setEditContact({ ...editContact, phone: v })} placeholder="+34 6XX XXX XXX" />
                  </div>
                </div>
                <div style={{ marginTop: 12 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Productos asignados (vendor/product, separados por coma)</label>
                  <Input value={(editContact.products || []).join(", ")} onChange={v => setEditContact({ ...editContact, products: v.split(",").map(x => x.trim()).filter(Boolean) })} placeholder="microsoft/windows_11, fortinet/fortios" />
                </div>
                <div style={{ marginTop: 12 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Notas / Observaciones</label>
                  <textarea value={editContact.notes} onChange={e => setEditContact({ ...editContact, notes: e.target.value })} placeholder="Ventana de parcheo, restricciones, observaciones..." rows={3} style={{ width: "100%", padding: "10px 12px", fontSize: 12, border: `1px solid ${C.gray200}`, borderRadius: 6, resize: "vertical", fontFamily: "inherit", boxSizing: "border-box" }} />
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 14, justifyContent: "flex-end" }}>
                  <Btn onClick={() => { setShowContactForm(false); setEditContact(null); }}>Cancelar</Btn>
                  <Btn primary onClick={() => saveContact(editContact)}>Guardar</Btn>
                </div>
              </Card>
            )}

            {contacts.map(c => {
              const contactProds = (c.subscriptions || []).map(s => `${s.vendor}/${s.product}`.toLowerCase());
              const affectedVulns = vulns.filter(v => (v.affectedProducts || []).some(p => contactProds.includes(`${p.vendor}/${p.product}`.toLowerCase())));
              const critCount = affectedVulns.filter(v => v.cvssV31Severity === "CRITICAL").length;
              const exploitedCount = affectedVulns.filter(v => v.isKnownExploited).length;
              return (
                <Card key={c.id} style={{ marginBottom: 10, borderLeft: exploitedCount > 0 ? `4px solid ${C.critical}` : critCount > 0 ? `4px solid ${C.high}` : `4px solid ${C.gray200}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 15, fontWeight: 800, color: C.text }}>{c.name}</span>
                        {exploitedCount > 0 && <span style={{ background: C.criticalBg, color: C.critical, padding: "1px 8px", borderRadius: 3, fontSize: 9, fontWeight: 700 }}>⚠ {exploitedCount} explotadas</span>}
                        {critCount > 0 && <span style={{ background: C.highBg, color: C.high, padding: "1px 8px", borderRadius: 3, fontSize: 9, fontWeight: 700 }}>{critCount} críticas</span>}
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 14, fontSize: 12, color: C.gray600, marginBottom: 6 }}>
                        <span style={{ display: "flex", alignItems: "center", gap: 4 }}><I name="mail" size={13} color={C.blue} /> {c.email}</span>
                        <span>{c.contactPerson}</span>
                        {c.phone && <span style={{ color: C.gray400 }}>{c.phone}</span>}
                      </div>
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                        {(c.subscriptions || []).map(s => <span key={`${s.vendor}/${s.product}`} style={{ background: C.bluePale, color: C.navy, padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600 }}>{s.vendor}/{s.product}</span>)}
                      </div>
                      {c.notes && <div style={{ fontSize: 11, color: C.gray500, background: C.gray50, padding: "6px 10px", borderRadius: 4, borderLeft: `2px solid ${C.gray300}`, lineHeight: 1.5 }}>{c.notes}</div>}
                    </div>
                    <div style={{ display: "flex", gap: 6, flexShrink: 0, marginLeft: 12 }}>
                      <Btn small onClick={() => { setEditContact({ ...c, products: (c.subscriptions || []).map(s => `${s.vendor}/${s.product}`) }); setShowContactForm(true); }}><I name="edit" size={12} /></Btn>
                    </div>
                  </div>
                  {affectedVulns.length > 0 && (
                    <div style={{ marginTop: 10, padding: "8px 10px", background: C.gray50, borderRadius: 4 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: C.gray500, marginBottom: 4, textTransform: "uppercase" }}>CVEs que afectan a este equipo ({affectedVulns.length})</div>
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                        {affectedVulns.map(v => (
                          <span key={v.cveId} onClick={() => openVulnerabilityDetail(v)} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 8px", background: sevBg(v.cvssV31Severity), border: `1px solid ${sevColor(v.cvssV31Severity)}30`, borderRadius: 3, fontSize: 9, fontWeight: 700, fontFamily: "monospace", cursor: "pointer", color: sevColor(v.cvssV31Severity) }}>
                            {v.cveId} {v.isKnownExploited && "🔴"}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </Card>
              );
            })}
          </>}

          {/* ═══ NOTIFICATIONS HISTORY ═══ */}
          {view === "notifications" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 16px" }}>Comunicaciones</h1>
            <Card title="Plantilla de Notificación de Vulnerabilidades" icon="mail" style={{ marginBottom: 16 }}>
              {templateLoading ? (
                <div style={{ padding: 20, textAlign: "center", color: C.gray500 }}>Cargando plantilla...</div>
              ) : (
                <>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto auto", gap: 8, alignItems: "end", marginBottom: 12 }}>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Plantillas guardadas</label>
                      <select value={selectedTemplateId} onChange={e => loadTemplateById(e.target.value)} style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff" }}>
                        <option value="">(Nueva plantilla)</option>
                        {templateList.map(t => (
                          <option key={t.id} value={String(t.id)}>
                            {t.name}{t.isActive ? " (activa)" : ""}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Nombre de plantilla</label>
                      <Input value={templateName} onChange={setTemplateName} placeholder="Ej: Comunicados críticos" />
                    </div>
                    <Btn onClick={() => {
                      setSelectedTemplateId("");
                      setTemplateName("Plantilla CVE");
                      setTemplateConfig({
                        headerImageUrl: "",
                        introMessage: "La Oficina de Ciberseguridad Corporativa informa de la publicación de nuevas Vulnerabilidades del Fabricante {{fabricante}} en los siguientes CVE con una estimación de Impacto CVSS superior a 7.5 sobre 10.\n\nSe recomienda proceder a la identificación de los activos afectados y ejecutar las correspondientes tareas de mitigación y actuación recomendadas por el fabricante.\n\nImportante: La lista de versiones afectadas que aparecen en este comunicado ha sido simplificada, por favor, consulte la lista Oficial del fabricante en los enlaces que aparecen en el apartado de referencias.",
                        showExploitProbability: true,
                        showExploitExists: true,
                        showAffectedSoftware: true,
                        showDescription: true,
                        showReferences: true,
                        showPatchLink: true,
                      });
                    }}>Nueva</Btn>
                    <Btn onClick={activateTemplate} disabled={!selectedTemplateId}>Activar</Btn>
                  </div>

                  <div style={{ marginBottom: 12 }}>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Encabezado (imagen)</label>
                    <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                      <input
                        type="file"
                        accept="image/*"
                        onChange={e => onTemplateHeaderUpload(e.target.files?.[0])}
                        style={{ fontSize: 12 }}
                      />
                      {templateConfig.headerImageUrl && (
                        <Btn small onClick={() => setTemplateConfig({ ...templateConfig, headerImageUrl: "" })}>Quitar imagen</Btn>
                      )}
                    </div>
                    {templateConfig.headerImageUrl && (
                      <img src={templateConfig.headerImageUrl} alt="Cabecera plantilla" style={{ maxWidth: "100%", maxHeight: 130, marginTop: 8, borderRadius: 6, border: `1px solid ${C.gray200}` }} />
                    )}
                  </div>

                  <div style={{ background: C.gray50, border: `1px solid ${C.gray200}`, borderRadius: 6, padding: "10px 12px", fontSize: 11, color: C.gray600, marginBottom: 12 }}>
                    El fabricante se incorpora automáticamente desde la vulnerabilidad (vendor detectado en software afectado). Puedes usar <code>{"{{fabricante}}"}</code> en el mensaje.
                  </div>

                  <div style={{ marginBottom: 12 }}>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Mensaje inicial</label>
                    <textarea
                      value={templateConfig.introMessage}
                      onChange={e => setTemplateConfig({ ...templateConfig, introMessage: e.target.value })}
                      rows={6}
                      style={{ width: "100%", padding: "10px 12px", fontSize: 12, border: `1px solid ${C.gray200}`, borderRadius: 6, resize: "vertical", fontFamily: "inherit", boxSizing: "border-box" }}
                    />
                  </div>

                  <div style={{ marginBottom: 14 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: C.gray600, marginBottom: 6 }}>Bloques por vulnerabilidad</div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
                      {[
                        ["showExploitProbability", "Posibilidad de explotación"],
                        ["showExploitExists", "Existencia de exploit (sí/no)"],
                        ["showAffectedSoftware", "Listado de software afectado"],
                        ["showDescription", "Descripción de la vulnerabilidad"],
                        ["showReferences", "Enlaces de información"],
                        ["showPatchLink", "Enlace del parche"],
                      ].map(([key, label]) => (
                        <label key={key} style={{ fontSize: 12, color: C.gray700, display: "flex", alignItems: "center", gap: 6 }}>
                          <input
                            type="checkbox"
                            checked={!!templateConfig[key]}
                            onChange={e => setTemplateConfig({ ...templateConfig, [key]: e.target.checked })}
                          />
                          {label}
                        </label>
                      ))}
                    </div>
                  </div>

                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                    <Btn onClick={() => loadData("notifications")}>Recargar</Btn>
                    <Btn primary onClick={saveTemplateConfig} disabled={templateSaving}>
                      {templateSaving ? "Guardando..." : "Guardar plantilla"}
                    </Btn>
                  </div>

                  <div style={{ marginTop: 16, paddingTop: 12, borderTop: `1px solid ${C.gray100}` }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8, alignItems: "end", marginBottom: 10 }}>
                      <div>
                        <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 6 }}>Vulnerabilidad para vista previa</label>
                        <select value={previewVulnId} onChange={e => setPreviewVulnId(e.target.value)} style={{ width: "100%", padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, background: "#fff" }}>
                          <option value="">Selecciona un CVE...</option>
                          {vulns.map(v => (
                            <option key={v.id} value={String(v.id)}>{v.cveId} ({v.cvssV31Severity || "N/A"})</option>
                          ))}
                        </select>
                      </div>
                      <Btn primary onClick={generateTemplatePreview} disabled={!previewVulnId || templatePreviewLoading}>
                        {templatePreviewLoading ? "Generando..." : "Generar vista previa"}
                      </Btn>
                    </div>
                    {templatePreviewMeta.cveId && (
                      <div style={{ fontSize: 11, color: C.gray600, marginBottom: 8 }}>
                        Vista previa para <strong>{templatePreviewMeta.cveId}</strong> · Fabricante detectado: <strong>{templatePreviewMeta.manufacturer || "N/D"}</strong>
                      </div>
                    )}
                    <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 6, overflow: "hidden", background: "#fff" }}>
                      {templatePreviewHtml ? (
                        <iframe title="Preview plantilla" srcDoc={templatePreviewHtml} style={{ width: "100%", height: 520, border: 0 }} />
                      ) : (
                        <div style={{ padding: 16, fontSize: 12, color: C.gray500 }}>Genera una vista previa para revisar la plantilla antes de enviar.</div>
                      )}
                    </div>
                  </div>
                </>
              )}
            </Card>
            <Card title="Historial de Notificaciones" icon="mail" noPad>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr style={{ background: C.gray50 }}>
                  {["Fecha", "Destinatario", "Asunto", "Template", "Estado"].map(h => (
                    <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontSize: 9, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", borderBottom: `2px solid ${C.gray200}` }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{notifHistory.length === 0 ? (
                  <tr><td colSpan={5} style={{ padding: 30, textAlign: "center", color: C.gray400, fontSize: 12 }}>No hay notificaciones enviadas aún</td></tr>
                ) : notifHistory.map(n => (
                  <tr key={n.id} className="rh" style={{ cursor: "pointer" }} onClick={() => viewNotification(n.id)}>
                    <td style={{ padding: "8px 12px", fontSize: 10, fontFamily: "monospace" }}>{fmtDate(n.sentAt)}</td>
                    <td style={{ padding: "8px 12px", fontSize: 11 }}>{n.to}</td>
                    <td style={{ padding: "8px 12px", fontSize: 11, fontWeight: 500 }}>{n.subject}</td>
                    <td style={{ padding: "8px 12px" }}><span style={{ padding: "2px 8px", borderRadius: 3, fontSize: 9, fontWeight: 600, background: C.bluePale, color: C.blue }}>{n.template || "custom"}</span></td>
                    <td style={{ padding: "8px 12px" }}><span style={{ color: n.status === "sent" ? C.low : C.critical, fontWeight: 600, fontSize: 10 }}>{n.status === "sent" ? "✓ Enviado" : "✗ Error"}</span></td>
                  </tr>
                ))}</tbody>
              </table>
            </Card>
            {notifDetail && (
              <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.4)", zIndex: 200, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={() => setNotifDetail(null)}>
                <div style={{ background: "#fff", borderRadius: 12, padding: 28, width: 560, maxHeight: "80vh", overflow: "auto" }} onClick={e => e.stopPropagation()}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                    <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Detalle de Notificación</h3>
                    <span style={{ cursor: "pointer" }} onClick={() => setNotifDetail(null)}><I name="x" size={18} /></span>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
                    <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>DESTINATARIO</span><div style={{ fontSize: 12 }}>{notifDetail.to}</div></div>
                    <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>FECHA</span><div style={{ fontSize: 12 }}>{fmtDate(notifDetail.sentAt)}</div></div>
                    <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>ASUNTO</span><div style={{ fontSize: 12 }}>{notifDetail.subject}</div></div>
                    <div><span style={{ fontSize: 10, fontWeight: 600, color: C.gray500 }}>ESTADO</span><div style={{ fontSize: 12, color: notifDetail.status === "sent" ? C.low : C.critical, fontWeight: 600 }}>{notifDetail.status}</div></div>
                  </div>
                  {notifDetail.error && <div style={{ background: C.criticalBg, color: C.critical, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 12 }}>Error: {notifDetail.error}</div>}
                </div>
              </div>
            )}
          </>}

          {/* ═══ REPORTS ═══ */}
          {view === "reports" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 16px" }}>Informes</h1>
            <Card title="Módulo en construcción" icon="file">
              <div style={{ textAlign: "center", padding: "22px 10px" }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: C.gray700, marginBottom: 8 }}>
                  Esta sección estará disponible próximamente.
                </div>
                <div style={{ fontSize: 12, color: C.gray500, marginBottom: 14 }}>
                  Estamos preparando el nuevo módulo de generación y gestión de informes.
                </div>
                <Btn onClick={() => setView("overview")}>Volver a Visión General</Btn>
              </div>
            </Card>
          </>}

          {/* ═══ AI ASSISTANT ═══ */}
          {view === "ai" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 4px" }}>Asistente IA — Oficina de Ciberseguridad</h1>
            <p style={{ color: C.gray500, fontSize: 12, marginBottom: 14 }}>Análisis de impacto, recomendaciones de parcheo, correlación con infraestructura. Conectado a Ollama.</p>

            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
              {[
                "Dame un resumen del estado actual de vulnerabilidades",
                "Analiza el impacto de CVE-2025-21298",
                "¿Qué vulnerabilidades afectan a Fortinet?",
                "¿Qué equipos IT necesitan actuar urgentemente?",
                "Draft de comunicación para el equipo de Ivanti",
              ].map(q => (
                <span key={q} onClick={() => { setAiQuery(q); }} style={{ padding: "4px 10px", background: C.bluePale, color: C.navy, borderRadius: 4, fontSize: 10, fontWeight: 600, cursor: "pointer" }}>{q}</span>
              ))}
            </div>

            <Card noPad style={{ height: "calc(100vh - 280px)", display: "flex", flexDirection: "column" }}>
              <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
                {aiMessages.length === 0 && (
                  <div style={{ textAlign: "center", padding: "60px 20px", color: C.gray400 }}>
                    <I name="brain" size={40} color={C.gray300} />
                    <div style={{ fontSize: 14, fontWeight: 600, marginTop: 12 }}>Asistente IA OCC</div>
                    <div style={{ fontSize: 12, marginTop: 4 }}>Consulta sobre CVEs, impacto en infraestructura, o solicita análisis y recomendaciones</div>
                  </div>
                )}
                {aiMessages.map((m, i) => (
                  <div key={i} className="fade" style={{ display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start", marginBottom: 10 }}>
                    <div style={{
                      maxWidth: "80%", padding: "10px 14px", borderRadius: 10,
                      background: m.role === "user" ? C.navy : C.gray50,
                      color: m.role === "user" ? "#fff" : C.text,
                      fontSize: 12, lineHeight: 1.7, whiteSpace: "pre-wrap",
                      borderTopRightRadius: m.role === "user" ? 2 : 10,
                      borderTopLeftRadius: m.role === "user" ? 10 : 2,
                    }}>
                      {m.content.split(/(\*\*.*?\*\*)/).map((part, j) =>
                        part.startsWith("**") && part.endsWith("**")
                          ? <strong key={j}>{part.slice(2, -2)}</strong>
                          : <span key={j}>{part}</span>
                      )}
                    </div>
                  </div>
                ))}
                {aiLoading && (
                  <div style={{ display: "flex", gap: 4, padding: "8px 14px" }}>
                    {[0, 1, 2].map(i => <div key={i} style={{ width: 8, height: 8, borderRadius: "50%", background: C.gray300, animation: `pulse 1.2s ${i * 0.2}s infinite` }} />)}
                  </div>
                )}
                <div ref={aiEndRef} />
              </div>
              <div style={{ padding: "10px 14px", borderTop: `1px solid ${C.gray200}`, display: "flex", gap: 8 }}>
                <input
                  value={aiQuery}
                  onChange={e => setAiQuery(e.target.value)}
                  onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleAiSend(); } }}
                  placeholder="Pregunta sobre vulnerabilidades, impacto, recomendaciones..."
                  style={{ flex: 1, padding: "10px 12px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12, outline: "none" }}
                />
                <Btn primary onClick={handleAiSend} disabled={aiLoading || !aiQuery.trim()}><I name="send" size={14} color="#fff" /></Btn>
              </div>
            </Card>
          </>}

          {/* ═══ SETTINGS ═══ */}
          {view === "settings" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 16px" }}>Configuración</h1>
            <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
              {[{ id: "smtp", label: "SMTP" }, { id: "ia", label: "IA" }, { id: "users", label: "Usuarios" }, { id: "tags", label: "Etiquetas" }].map(t => (
                <div key={t.id} onClick={() => setSettingsTab(t.id)} style={{ padding: "8px 18px", borderRadius: 6, cursor: "pointer", fontSize: 12, fontWeight: 600, background: settingsTab === t.id ? C.navy : C.gray100, color: settingsTab === t.id ? "#fff" : C.gray600, transition: "all 0.15s" }}>{t.label}</div>
              ))}
            </div>

            {/* SMTP Tab */}
            {settingsTab === "smtp" && <Card title="Configuración SMTP" icon="settings">
              {smtpLoading ? (
                <div style={{ padding: 20, textAlign: "center", color: C.gray500 }}>Cargando configuración...</div>
              ) : (
                <>
                  <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 16 }}>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Servidor SMTP (Host)</label>
                      <Input value={smtpConfig.host} onChange={v => setSmtpConfig({ ...smtpConfig, host: v })} placeholder="smtp.example.com" />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Puerto</label>
                      <Input value={smtpConfig.port} onChange={v => setSmtpConfig({ ...smtpConfig, port: v })} placeholder="587" />
                    </div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Usuario</label>
                      <Input value={smtpConfig.user} onChange={v => setSmtpConfig({ ...smtpConfig, user: v })} placeholder="user@example.com" />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contraseña</label>
                      <Input value={smtpConfig.pass} onChange={v => setSmtpConfig({ ...smtpConfig, pass: v })} placeholder="••••••••" />
                    </div>
                  </div>
                  <div style={{ marginBottom: 16 }}>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Remitente (From)</label>
                    <Input value={smtpConfig.from} onChange={v => setSmtpConfig({ ...smtpConfig, from: v })} placeholder="noreply@example.com" />
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 20 }}>
                    <input type="checkbox" checked={smtpConfig.secure} onChange={e => setSmtpConfig({ ...smtpConfig, secure: e.target.checked })} id="secureCheck" />
                    <label htmlFor="secureCheck" style={{ fontSize: 12, color: C.text }}>Usar conexión segura (SSL/TLS)</label>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", borderTop: `1px solid ${C.gray100}`, paddingTop: 16 }}>
                    <div style={{ display: "flex", gap: 8 }}>
                      <Input value={testEmail} onChange={setTestEmail} placeholder="Email de prueba" style={{ width: 250 }} />
                      <Btn onClick={handleCreateTest} disabled={testSending || !testEmail}>{testSending ? "Enviando..." : "Probar"}</Btn>
                    </div>
                    <Btn primary onClick={handleSaveSmtp} disabled={smtpSaving}>{smtpSaving ? "Guardando..." : "Guardar Configuración"}</Btn>
                  </div>
                  {smtpMsg && (
                    <div className="fade" style={{ marginTop: 12, padding: "10px 12px", borderRadius: 4, fontSize: 12, fontWeight: 600, background: smtpMsg.type === "success" ? C.lowBg : C.criticalBg, color: smtpMsg.type === "success" ? C.low : C.critical, borderLeft: `3px solid ${smtpMsg.type === "success" ? C.low : C.critical}` }}>
                      {smtpMsg.text}
                    </div>
                  )}
                </>
              )}
            </Card>}

            {/* IA Tab */}
            {settingsTab === "ia" && <Card title="Configuración IA (Ollama)" icon="brain">
              {aiConfigLoading ? (
                <div style={{ padding: 20, textAlign: "center", color: C.gray500 }}>Cargando configuración IA...</div>
              ) : (
                <>
                  <div style={{ marginBottom: 12, background: C.gray50, border: `1px solid ${C.gray200}`, borderRadius: 6, padding: "10px 12px", fontSize: 11, color: C.gray600 }}>
                    Fuente actual: <strong>{aiConfig.source === "db" ? "Base de datos" : ".env"}</strong>. Si guardas aquí, pasará a usar configuración en base de datos.
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Proveedor</label>
                      <select
                        value={aiConfig.provider || "ollama"}
                        onChange={e => setAiConfig({ ...aiConfig, provider: e.target.value })}
                        style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}
                      >
                        <option value="ollama">Ollama</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Base URL Ollama</label>
                      <Input value={aiConfig.baseUrl || ""} onChange={v => setAiConfig({ ...aiConfig, baseUrl: v })} placeholder="http://192.168.1.30:11434" />
                    </div>
                  </div>

                  <div style={{ marginBottom: 14 }}>
                    <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Modelo</label>
                    <select
                      value={aiConfig.model || ""}
                      onChange={e => setAiConfig({ ...aiConfig, model: e.target.value })}
                      style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}
                    >
                      <option value="">Selecciona modelo...</option>
                      {[...new Set([DEFAULT_AI_MODEL, "sylink/sylink:8b", ...(aiModels || [])])].map(m => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                    <div style={{ marginTop: 8 }}>
                      <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Modelo manual (opcional)</label>
                      <Input
                        value={aiConfig.model || ""}
                        onChange={v => setAiConfig({ ...aiConfig, model: v })}
                        placeholder={`Ej: ${DEFAULT_AI_MODEL} o sylink/sylink:8b`}
                      />
                    </div>
                    {(aiModels || []).length === 0 && (
                      <div style={{ fontSize: 11, color: C.gray500, marginTop: 6 }}>
                        No se pudieron listar modelos automáticamente. Puedes escribir el modelo manualmente en `.env` o revisar conectividad con Ollama.
                      </div>
                    )}
                  </div>

                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                    <Btn onClick={refreshAiModels}>Recargar modelos</Btn>
                    <Btn onClick={() => loadData("settings")}>Recargar</Btn>
                    <Btn primary onClick={saveAiConfig} disabled={aiConfigSaving}>
                      {aiConfigSaving ? "Guardando..." : "Guardar Configuración IA"}
                    </Btn>
                  </div>
                </>
              )}
            </Card>}

            {/* Users Tab */}
            {settingsTab === "users" && <>
              <Card title="Gestión de Usuarios" icon="users" action={<Btn small primary onClick={() => openUserForm()}><I name="plus" size={14} /> Nuevo</Btn>}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr style={{ background: C.gray50 }}>
                    {["Nombre", "Email", "Rol", "Estado", "Último acceso", "Acciones"].map(h => (
                      <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 9, fontWeight: 700, color: C.gray500, textTransform: "uppercase", borderBottom: `2px solid ${C.gray200}` }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>{users.map(u => (
                    <tr key={u.id} className="rh">
                      <td style={{ padding: "8px 12px", fontWeight: 600, fontSize: 12 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          <span>{u.name}</span>
                          {u.isSubscriber && <span style={{ padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 700, background: C.infoBg, color: C.info }}>SUSCRIPTOR</span>}
                        </div>
                      </td>
                      <td style={{ padding: "8px 12px", fontSize: 11, fontFamily: "monospace" }}>{u.email}</td>
                      <td style={{ padding: "8px 12px" }}><span style={{ padding: "2px 8px", borderRadius: 3, fontSize: 9, fontWeight: 700, background: u.role === "ADMIN" ? C.bluePale : C.gray100, color: u.role === "ADMIN" ? C.blue : C.gray600 }}>{u.role}</span></td>
                      <td style={{ padding: "8px 12px" }}><span style={{ color: u.isActive ? C.low : C.critical, fontWeight: 600, fontSize: 10 }}>{u.isActive ? "● Activo" : "○ Inactivo"}</span></td>
                      <td style={{ padding: "8px 12px", fontSize: 10, color: C.gray400 }}>{fmtDate(u.lastLoginAt)}</td>
                      <td style={{ padding: "8px 12px" }}>
                        <span style={{ cursor: "pointer", marginRight: 8 }} onClick={() => openUserForm(u)}><I name="edit" size={14} color={C.blue} /></span>
                        <span style={{ cursor: "pointer" }} onClick={() => deleteUser(u.id)}><I name="trash" size={14} color={C.critical} /></span>
                      </td>
                    </tr>
                  ))}</tbody>
                </table>
              </Card>
              {showUserForm && editUser && (
                <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.4)", zIndex: 200, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={() => setShowUserForm(false)}>
                  <div style={{ background: "#fff", borderRadius: 12, padding: 28, width: 980, maxHeight: "92vh", overflow: "auto" }} onClick={e => e.stopPropagation()}>
                    <h3 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 16px" }}>{editUser?.id ? "Editar Usuario" : "Nuevo Usuario"}</h3>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                      {[{ k: "name", l: "Nombre" }, { k: "email", l: "Email" }].map(f => (
                        <div key={f.k} style={{ marginBottom: 12 }}>
                          <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>{f.l}</label>
                          <Input value={editUser[f.k] || ""} onChange={v => setEditUser({ ...editUser, [f.k]: v })} placeholder={f.l} />
                        </div>
                      ))}
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <input type="checkbox" checked={!!editUser.canLogin} onChange={e => setEditUser({
                          ...editUser,
                          canLogin: e.target.checked,
                          role: e.target.checked
                            ? (editUser.isSubscriber
                              ? (["ADMIN", "VIEWER"].includes((editUser.role || "").toUpperCase()) ? editUser.role : "")
                              : (editUser.role === "SUBSCRIBER" ? "USER" : editUser.role || "USER"))
                            : "SUBSCRIBER",
                        })} />
                        <span style={{ fontSize: 12, color: C.text }}>Permitir inicio de sesión</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <input type="checkbox" checked={!!editUser.isSubscriber} onChange={e => setSubscriberEnabled(e.target.checked)} />
                        <span style={{ fontSize: 12, color: C.text }}>Usuario suscriptor de alertas</span>
                      </div>
                    </div>

                    {editUser.canLogin && (
                      <>
                        <div style={{ marginBottom: 12 }}>
                          <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Rol de acceso</label>
                          <select value={editUser.role || ""} onChange={e => setEditUser({ ...editUser, role: e.target.value })} style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff" }}>
                            <option value="" disabled>Seleccionar rol...</option>
                            {editUser.isSubscriber ? (
                              <>
                                <option value="VIEWER">Viewer</option>
                                <option value="ADMIN">Administrador</option>
                              </>
                            ) : (
                              <>
                                <option value="USER">Usuario</option>
                                <option value="VIEWER">Viewer</option>
                                <option value="ADMIN">Administrador</option>
                              </>
                            )}
                          </select>
                        </div>
                        <div style={{ marginBottom: 12 }}>
                          <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Contraseña {editUser.id ? "(opcional)" : "(obligatoria)"}</label>
                          <input
                            type="password"
                            value={editUser.password || ""}
                            onChange={e => setEditUser({ ...editUser, password: e.target.value })}
                            placeholder="Mínimo 8 caracteres"
                            style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${C.gray200}`, borderRadius: 6, boxSizing: "border-box" }}
                          />
                        </div>
                      </>
                    )}

                    {editUser.isSubscriber && (
                      <div style={{ marginTop: 6, border: `1px solid ${C.gray200}`, borderRadius: 8, padding: 14, background: C.gray50 }}>
                        <div style={{ marginBottom: 10 }}>
                          <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Email de notificación</label>
                          <Input value={editUser.notificationEmail || ""} onChange={v => setEditUser({ ...editUser, notificationEmail: v })} placeholder="destinatario@empresa.com" icon="mail" />
                        </div>

                        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 14 }}>
                          <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff", maxHeight: 300, overflow: "auto" }}>
                            <div style={{ padding: "8px 10px", borderBottom: `1px solid ${C.gray100}`, fontSize: 11, fontWeight: 700, color: C.gray600 }}>Fabricantes</div>
                            {subscriptionCatalog.length === 0 && <div style={{ padding: 10, fontSize: 11, color: C.gray500 }}>Sin catálogo disponible aún.</div>}
                            {subscriptionCatalog.map(item => {
                              const checked = subscriberVendors.includes(item.vendor);
                              return (
                                <label key={item.vendor} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", borderBottom: `1px solid ${C.gray100}`, cursor: "pointer", fontSize: 12 }}>
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={e => toggleVendorSelection(item.vendor, e.target.checked)}
                                  />
                                  <span onClick={() => setActiveVendor(item.vendor)} style={{ color: activeVendor === item.vendor ? C.navy : C.text, fontWeight: activeVendor === item.vendor ? 700 : 500 }}>
                                    {item.vendor}
                                  </span>
                                </label>
                              );
                            })}
                          </div>

                          <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 6, background: "#fff", maxHeight: 300, overflow: "auto" }}>
                            <div style={{ padding: "8px 10px", borderBottom: `1px solid ${C.gray100}`, fontSize: 11, fontWeight: 700, color: C.gray600 }}>
                              Software {activeVendor ? `de ${activeVendor}` : ""}
                            </div>
                            {!activeVendor && <div style={{ padding: 10, fontSize: 11, color: C.gray500 }}>Selecciona un fabricante.</div>}
                            {activeVendor && ((subscriptionCatalog.find(v => v.vendor === activeVendor)?.products) || []).map(p => {
                              const sub = (editUser.subscriptions || []).find(s => s.vendor === activeVendor && s.product === p.product);
                              const checked = !!sub;
                              const selectedVersions = sub?.versions || [];
                              return (
                                <div key={`${activeVendor}-${p.product}`} style={{ padding: "8px 10px", borderBottom: `1px solid ${C.gray100}` }}>
                                  <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, fontWeight: 600 }}>
                                    <input type="checkbox" checked={checked} onChange={e => toggleProductSubscription(activeVendor, p.product, e.target.checked)} />
                                    {p.product}
                                  </label>
                                  {checked && (
                                    <div style={{ marginTop: 6, marginLeft: 22 }}>
                                      <div style={{ fontSize: 10, color: C.gray500, marginBottom: 4 }}>Versiones (si no marcas ninguna, se notifican todas)</div>
                                      {(!p.versions || p.versions.length === 0) && <div style={{ fontSize: 10, color: C.gray400 }}>No hay versiones catalogadas.</div>}
                                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                                        {(p.versions || []).map(ver => (
                                          <label key={ver} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10, padding: "2px 6px", background: C.gray50, border: `1px solid ${C.gray200}`, borderRadius: 12 }}>
                                            <input
                                              type="checkbox"
                                              checked={selectedVersions.includes(ver)}
                                              onChange={e => toggleSubscriptionVersion(activeVendor, p.product, ver, e.target.checked)}
                                            />
                                            <span>{ver}</span>
                                          </label>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    )}

                    <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 20 }}>
                      <Btn onClick={() => setShowUserForm(false)}>Cancelar</Btn>
                      <Btn primary onClick={() => saveUser(editUser)}>Guardar</Btn>
                    </div>
                  </div>
                </div>
              )}
            </>}

            {/* Tags Tab */}
            {settingsTab === "tags" && <Card title="Etiquetas de Vulnerabilidades" icon="edit">
              <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                <Input value={newTagName} onChange={setNewTagName} placeholder="Nombre de etiqueta" style={{ flex: 1 }} />
                <input type="color" value={newTagColor} onChange={e => setNewTagColor(e.target.value)} style={{ width: 40, height: 38, border: `1px solid ${C.gray200}`, borderRadius: 6, cursor: "pointer" }} />
                <Btn primary onClick={addTag}><I name="plus" size={14} /> Añadir</Btn>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {tags.map(t => (
                  <div key={t.id} style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "6px 14px", borderRadius: 16, background: `${t.color}18`, border: `1px solid ${t.color}40`, fontSize: 12, fontWeight: 600, color: t.color }}>
                    <span style={{ width: 10, height: 10, borderRadius: "50%", background: t.color }} />
                    {t.name}
                    <span style={{ cursor: "pointer", marginLeft: 4, opacity: 0.6 }} onClick={() => deleteTag(t.id)}>×</span>
                  </div>
                ))}
                {tags.length === 0 && <div style={{ color: C.gray400, fontSize: 12, padding: 8 }}>No hay etiquetas. Añade una para empezar.</div>}
              </div>
            </Card>}
          </>}

          {/* ═══ COLLECTOR ═══ */}
          {view === "collector" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 16px" }}>Collector</h1>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 18 }}>
              <Metric icon="clock" label="Intervalo" value="30m" sub="*/30 * * * *" color={C.navy} />
              <Metric icon="server" label="Fuentes" value="4" sub="NVD · KEV · EPSS · GitHub" color={C.blue} />
              <Metric icon="check" label="Estado" value={dash.lastRun?.status || "-"} sub={timeAgo(dash.lastRun?.finishedAt) + " ago"} color={C.low} />
              <Metric icon="activity" label="Duración" value={fmtMs(dash.lastRun?.durationMs)} color={C.high} />
            </div>

            <Card title="Pipeline" icon="arrowRight" style={{ marginBottom: 16 }}>
              <div style={{ display: "flex", gap: 0, alignItems: "center" }}>
                {[
                  { label: "NVD API", desc: "CVE + CVSS + CPE", color: C.blue, icon: "shield" },
                  { label: "CISA KEV", desc: "Explotación activa", color: C.critical, icon: "zap" },
                  { label: "EPSS", desc: "Prob. explotación", color: C.high, icon: "activity" },
                  { label: "GitHub PoC", desc: "Exploits públicos", color: C.navy, icon: "bug" },
                  { label: "MySQL", desc: "Persistencia", color: C.low, icon: "server" },
                ].map((s, i, a) => (
                  <div key={s.label} style={{ display: "flex", alignItems: "center", flex: 1 }}>
                    <div style={{ flex: 1, padding: "12px 10px", background: `${s.color}10`, border: `1px solid ${s.color}25`, borderRadius: 6, textAlign: "center" }}>
                      <I name={s.icon} size={18} color={s.color} />
                      <div style={{ fontWeight: 700, fontSize: 10, color: s.color, marginTop: 4 }}>{s.label}</div>
                      <div style={{ fontSize: 8, color: C.gray500 }}>{s.desc}</div>
                    </div>
                    {i < a.length - 1 && <span style={{ color: C.gray300, padding: "0 3px", fontSize: 14 }}>→</span>}
                  </div>
                ))}
              </div>
            </Card>

            <Card
              title="Restore NVD (Backfill 10 años)"
              icon="refresh"
              style={{ marginBottom: 16 }}
              action={(
                <div style={{ display: "flex", gap: 8 }}>
                  <Btn small onClick={() => refreshBackfillStatus()} disabled={backfillBusy || !backfillJobId}>
                    <I name="refresh" size={12} /> Estado
                  </Btn>
                  <Btn small onClick={() => setStoredBackfillJobId("")} disabled={backfillBusy || !backfillJobId}>
                    Limpiar jobId
                  </Btn>
                </div>
              )}
            >
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: 8, alignItems: "center", marginBottom: 12 }}>
                <Input
                  value={backfillJobId}
                  onChange={(v) => setStoredBackfillJobId(v)}
                  placeholder="jobId backfill (se guarda en este navegador)"
                  icon="clock"
                />
                <Btn primary onClick={startBackfill} disabled={backfillBusy}>
                  {backfillBusy ? "Procesando..." : "Iniciar/Reanudar"}
                </Btn>
                <Btn onClick={runBackfillToCompletion} disabled={backfillBusy || !backfillJobId}>
                  Ejecutar hasta completar
                </Btn>
              </div>

              {backfillMsg && (
                <div style={{
                  marginBottom: 10,
                  padding: "8px 10px",
                  borderRadius: 6,
                  fontSize: 12,
                  fontWeight: 600,
                  background: backfillMsg.type === "error" ? C.criticalBg : C.lowBg,
                  color: backfillMsg.type === "error" ? C.critical : C.low,
                  border: `1px solid ${backfillMsg.type === "error" ? "#fecaca" : "#bbf7d0"}`,
                }}>
                  {backfillMsg.text}
                </div>
              )}

              {backfillStatus?.job ? (
                <div style={{ border: `1px solid ${C.gray200}`, borderRadius: 6, overflow: "hidden" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 0 }}>
                    <div style={{ padding: "10px 12px", borderRight: `1px solid ${C.gray100}` }}>
                      <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Estado</div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillStatus.job.status || "-"}</div>
                    </div>
                    <div style={{ padding: "10px 12px", borderRight: `1px solid ${C.gray100}` }}>
                      <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Checkpoints</div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillStatus?.checkpoints?.DONE || 0} / {(backfillStatus?.remaining || 0) + (backfillStatus?.checkpoints?.DONE || 0)}</div>
                    </div>
                    <div style={{ padding: "10px 12px", borderRight: `1px solid ${C.gray100}` }}>
                      <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Insertados/Actualizados</div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillMetrics.inserted || 0} / {backfillMetrics.updated || 0}</div>
                    </div>
                    <div style={{ padding: "10px 12px" }}>
                      <div style={{ fontSize: 10, color: C.gray500, textTransform: "uppercase", fontWeight: 700 }}>Páginas / Items</div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: C.text }}>{backfillMetrics.pagesProcessed || 0} / {backfillMetrics.itemsFetched || 0}</div>
                    </div>
                  </div>
                  <div style={{ borderTop: `1px solid ${C.gray100}`, padding: "8px 12px", fontSize: 11, color: C.gray600, fontFamily: "monospace" }}>
                    jobId: {backfillStatus.job.jobId} · rango: {fmtDate(backfillStatus.job.fromTs)} → {fmtDate(backfillStatus.job.toTs)}
                  </div>
                  {backfillStatus?.latestError?.lastError && (
                    <div style={{ borderTop: `1px solid ${C.gray100}`, padding: "8px 12px", fontSize: 11, color: C.critical, background: C.criticalBg }}>
                      Último error checkpoint #{backfillStatus.latestError.id} (intentos: {backfillStatus.latestError.attempts}):
                      {" "}
                      {String(backfillStatus.latestError.lastError)}
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ fontSize: 11, color: C.gray500 }}>No hay estado cargado. Inicia/reanuda un backfill o pega un `jobId` y pulsa `Estado`.</div>
              )}
            </Card>

            <Card title="Historial de ejecuciones" icon="clock" noPad>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr style={{ background: C.gray50 }}>
                  {["#", "Inicio", "Fuente", "Estado", "Obtenidos", "Nuevos", "Duración"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 9, fontWeight: 700, color: C.gray500, textTransform: "uppercase", borderBottom: `2px solid ${C.gray200}` }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{(Array.isArray(runs) ? runs : []).map(r => (
                  <tr key={r.id} className="rh">
                    <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 11, color: C.gray400 }}>#{r.id}</td>
                    <td style={{ padding: "8px 12px", fontSize: 10, fontFamily: "monospace" }}>{fmtDate(r.startedAt)}</td>
                    <td style={{ padding: "8px 12px" }}><span style={{ padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600, background: r.source === "manual" ? C.bluePale : C.gray100, color: r.source === "manual" ? C.blue : C.gray600 }}>{r.source}</span></td>
                    <td style={{ padding: "8px 12px", color: r.status === "success" ? C.low : C.critical, fontWeight: 600, fontSize: 10 }}>{r.status === "success" ? "✓" : "✗"} {r.status}</td>
                    <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 11, fontWeight: 600 }}>{r.cvesFetched}</td>
                    <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 11, color: r.cvesNew > 0 ? C.low : C.gray400, fontWeight: r.cvesNew > 0 ? 700 : 400 }}>+{r.cvesNew}</td>
                    <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 11, color: C.gray400 }}>{fmtMs(r.durationMs)}</td>
                  </tr>
                ))}</tbody>
              </table>
            </Card>
          </>}

        </div>
      </main>
    </div>
  );
}
