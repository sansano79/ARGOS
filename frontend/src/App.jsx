import { useState, useEffect, useCallback, useRef } from "react";

// ─── Config ──────────────────────────────────────────────────────────────────
const API_BASE = "/api";
const OLLAMA_BASE = "http://localhost:11434";

// ─── SEIDOR Brand Colors (from corporate slide) ─────────────────────────────
const C = {
  navy: "#1B2A4A",
  navyDark: "#0F1B33",
  navyDeep: "#0A1628",
  navyLight: "#2A3F6A",
  blue: "#3B6CB5",
  blueLight: "#5A8FD4",
  bluePale: "#E8EFF8",
  accent: "#4ECDC4",
  white: "#FFFFFF",
  gray50: "#F8FAFB",
  gray100: "#EFF2F5",
  gray200: "#DDE2E8",
  gray300: "#C4CCD6",
  gray400: "#8E99A8",
  gray500: "#6B7688",
  gray600: "#4A5568",
  gray700: "#2D3748",
  text: "#1A202C",
  critical: "#DC2626",
  criticalBg: "#FEF2F2",
  high: "#EA580C",
  highBg: "#FFF7ED",
  medium: "#CA8A04",
  mediumBg: "#FEFCE8",
  low: "#16A34A",
  lowBg: "#F0FDF4",
  info: "#2563EB",
  infoBg: "#EFF6FF",
};

// ─── Mock Data ───────────────────────────────────────────────────────────────
const MOCK_DASHBOARD = {
  totalAll: 1247,
  today: [
    { cvssV31Severity: "CRITICAL", _count: 3 },
    { cvssV31Severity: "HIGH", _count: 12 },
    { cvssV31Severity: "MEDIUM", _count: 28 },
    { cvssV31Severity: "LOW", _count: 8 },
  ],
  week: [
    { cvssV31Severity: "CRITICAL", _count: 14 },
    { cvssV31Severity: "HIGH", _count: 67 },
    { cvssV31Severity: "MEDIUM", _count: 189 },
    { cvssV31Severity: "LOW", _count: 45 },
  ],
  topExploited: [
    { cveId: "CVE-2025-21298", cvssV31Score: 9.8, cvssV31Severity: "CRITICAL", epssScore: 0.943, affectedProducts: [{ vendor: "microsoft", product: "windows_11" }], firstSeenAt: "2025-01-14T10:00:00Z" },
    { cveId: "CVE-2025-0282", cvssV31Score: 9.0, cvssV31Severity: "CRITICAL", epssScore: 0.891, affectedProducts: [{ vendor: "ivanti", product: "connect_secure" }], firstSeenAt: "2025-01-08T15:00:00Z" },
    { cveId: "CVE-2024-55591", cvssV31Score: 9.8, cvssV31Severity: "CRITICAL", epssScore: 0.876, affectedProducts: [{ vendor: "fortinet", product: "fortios" }], firstSeenAt: "2025-01-14T08:00:00Z" },
    { cveId: "CVE-2025-24085", cvssV31Score: 7.8, cvssV31Severity: "HIGH", epssScore: 0.812, affectedProducts: [{ vendor: "apple", product: "macos" }], firstSeenAt: "2025-01-27T12:00:00Z" },
    { cveId: "CVE-2024-12356", cvssV31Score: 9.8, cvssV31Severity: "CRITICAL", epssScore: 0.789, affectedProducts: [{ vendor: "beyondtrust", product: "remote_support" }], firstSeenAt: "2024-12-17T10:00:00Z" },
  ],
  lastRun: { startedAt: new Date(Date.now() - 18 * 60000).toISOString(), finishedAt: new Date(Date.now() - 16 * 60000).toISOString(), status: "success", cvesFetched: 23, cvesNew: 5, cvesUpdated: 18, durationMs: 127400 },
};

const MOCK_VULNS = [
  { id: 1, cveId: "CVE-2025-21298", description: "Windows OLE Remote Code Execution vulnerability allows remote attackers to execute arbitrary code via crafted documents.", cvssV31Score: 9.8, cvssV31Severity: "CRITICAL", epssScore: 0.943, epssPercentile: 0.992, isKnownExploited: true, hasPublicExploit: true, affectedProducts: [{ vendor: "microsoft", product: "windows_11", versionRange: ">=22H2 <24H2" }, { vendor: "microsoft", product: "windows_server_2022" }], remediationInfo: { patchAvailable: true, vendorAdvisories: ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298"] }, publishedAt: "2025-01-14T10:00:00Z" },
  { id: 2, cveId: "CVE-2025-0282", description: "Ivanti Connect Secure stack-based buffer overflow allows unauthenticated remote code execution in VPN appliances.", cvssV31Score: 9.0, cvssV31Severity: "CRITICAL", epssScore: 0.891, epssPercentile: 0.988, isKnownExploited: true, hasPublicExploit: true, affectedProducts: [{ vendor: "ivanti", product: "connect_secure", versionRange: "<22.7R2.5" }, { vendor: "ivanti", product: "policy_secure" }], remediationInfo: { patchAvailable: true, vendorAdvisories: ["https://forums.ivanti.com/s/article/Security-Advisory"] }, publishedAt: "2025-01-08T15:00:00Z" },
  { id: 3, cveId: "CVE-2024-55591", description: "FortiOS and FortiProxy authentication bypass allows unauthenticated attackers to gain super-admin privileges via crafted CSF proxy requests.", cvssV31Score: 9.8, cvssV31Severity: "CRITICAL", epssScore: 0.876, epssPercentile: 0.985, isKnownExploited: true, hasPublicExploit: false, affectedProducts: [{ vendor: "fortinet", product: "fortios", versionRange: ">=7.0.0 <7.0.17" }, { vendor: "fortinet", product: "fortiproxy" }], remediationInfo: { patchAvailable: true, vendorAdvisories: ["https://fortiguard.fortinet.com/psirt/FG-IR-24-535"] }, publishedAt: "2025-01-14T08:00:00Z" },
  { id: 4, cveId: "CVE-2025-24085", description: "Apple CoreMedia use-after-free vulnerability allows malicious application to elevate privileges on macOS.", cvssV31Score: 7.8, cvssV31Severity: "HIGH", epssScore: 0.812, epssPercentile: 0.978, isKnownExploited: true, hasPublicExploit: false, affectedProducts: [{ vendor: "apple", product: "macos", versionRange: "<15.3" }, { vendor: "apple", product: "ios" }], remediationInfo: { patchAvailable: true, vendorAdvisories: ["https://support.apple.com/en-us/122067"] }, publishedAt: "2025-01-27T12:00:00Z" },
  { id: 5, cveId: "CVE-2024-50603", description: "Aviatrix Controller OS command injection allows unauthenticated attackers to execute arbitrary commands via API.", cvssV31Score: 10.0, cvssV31Severity: "CRITICAL", epssScore: 0.756, epssPercentile: 0.969, isKnownExploited: false, hasPublicExploit: true, affectedProducts: [{ vendor: "aviatrix", product: "controller", versionRange: "<7.2.4996" }], remediationInfo: { patchAvailable: true, vendorAdvisories: [] }, publishedAt: "2025-01-08T18:00:00Z" },
  { id: 6, cveId: "CVE-2025-23006", description: "SonicWall SMA 1000 pre-authentication deserialization allows remote unauthenticated OS command execution.", cvssV31Score: 9.8, cvssV31Severity: "CRITICAL", epssScore: 0.698, epssPercentile: 0.951, isKnownExploited: true, hasPublicExploit: false, affectedProducts: [{ vendor: "sonicwall", product: "sma_1000", versionRange: "<12.4.3-02854" }], remediationInfo: { patchAvailable: true, vendorAdvisories: ["https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0002"] }, publishedAt: "2025-01-23T10:00:00Z" },
  { id: 7, cveId: "CVE-2025-0411", description: "7-Zip Mark-of-the-Web bypass allows execution of arbitrary code via crafted archives without security warnings.", cvssV31Score: 7.0, cvssV31Severity: "HIGH", epssScore: 0.634, epssPercentile: 0.938, isKnownExploited: false, hasPublicExploit: true, affectedProducts: [{ vendor: "7-zip", product: "7-zip", versionRange: "<24.09" }], remediationInfo: { patchAvailable: true, vendorAdvisories: [] }, publishedAt: "2025-01-25T14:00:00Z" },
  { id: 8, cveId: "CVE-2025-21307", description: "Windows RMTP remote code execution allows network-adjacent attackers to execute code without authentication.", cvssV31Score: 9.8, cvssV31Severity: "CRITICAL", epssScore: 0.421, epssPercentile: 0.897, isKnownExploited: false, hasPublicExploit: false, affectedProducts: [{ vendor: "microsoft", product: "windows_server_2025" }, { vendor: "microsoft", product: "windows_server_2022" }], remediationInfo: { patchAvailable: true, vendorAdvisories: ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21307"] }, publishedAt: "2025-01-14T10:00:00Z" },
  { id: 9, cveId: "CVE-2024-8963", description: "Ivanti CSA path traversal allows unauthenticated access to restricted functionality.", cvssV31Score: 9.4, cvssV31Severity: "CRITICAL", epssScore: 0.385, epssPercentile: 0.882, isKnownExploited: true, hasPublicExploit: true, affectedProducts: [{ vendor: "ivanti", product: "cloud_services_appliance", versionRange: "<4.6.2" }], remediationInfo: { patchAvailable: true, vendorAdvisories: [] }, publishedAt: "2024-09-19T10:00:00Z" },
  { id: 10, cveId: "CVE-2025-20156", description: "Cisco Meeting Management privilege escalation allows authenticated remote attackers to gain administrator privileges.", cvssV31Score: 6.5, cvssV31Severity: "MEDIUM", epssScore: 0.124, epssPercentile: 0.712, isKnownExploited: false, hasPublicExploit: false, affectedProducts: [{ vendor: "cisco", product: "meeting_management", versionRange: "<3.9.1" }], remediationInfo: { patchAvailable: true, vendorAdvisories: ["https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory"] }, publishedAt: "2025-01-22T16:00:00Z" },
  { id: 11, cveId: "CVE-2025-21311", description: "Windows NTLM V1 elevation of privilege allows authenticated attacker to access credentials.", cvssV31Score: 6.5, cvssV31Severity: "MEDIUM", epssScore: 0.089, epssPercentile: 0.645, isKnownExploited: false, hasPublicExploit: false, affectedProducts: [{ vendor: "microsoft", product: "windows_11" }, { vendor: "microsoft", product: "windows_10" }], remediationInfo: { patchAvailable: true, vendorAdvisories: [] }, publishedAt: "2025-01-14T10:00:00Z" },
  { id: 12, cveId: "CVE-2025-0107", description: "Palo Alto Expedition OS command injection allows authenticated attacker to run arbitrary commands as www-data.", cvssV31Score: 6.3, cvssV31Severity: "MEDIUM", epssScore: 0.067, epssPercentile: 0.589, isKnownExploited: false, hasPublicExploit: false, affectedProducts: [{ vendor: "paloaltonetworks", product: "expedition", versionRange: "<1.2.101" }], remediationInfo: { patchAvailable: true, vendorAdvisories: [] }, publishedAt: "2025-01-11T10:00:00Z" },
];

const MOCK_CONTACTS = [
  { id: 1, name: "Equipo Infraestructura Windows", email: "infra-windows@corp.local", products: ["microsoft/windows_11", "microsoft/windows_server_2022", "microsoft/windows_server_2025", "microsoft/windows_10"], notes: "Ventana de parcheo: domingos 02:00-06:00. Contactar a Pedro Gómez para urgencias fuera de horario.", contactPerson: "Pedro Gómez", phone: "+34 612 345 678" },
  { id: 2, name: "Equipo Redes y Firewalls", email: "redes-fw@corp.local", products: ["fortinet/fortios", "fortinet/fortiproxy", "sonicwall/sma_1000", "paloaltonetworks/expedition"], notes: "Cambios en firewalls requieren CAB approval excepto P1. FortiOS en HA activo-pasivo.", contactPerson: "Laura Martín", phone: "+34 623 456 789" },
  { id: 3, name: "Equipo VPN y Acceso Remoto", email: "vpn-team@corp.local", products: ["ivanti/connect_secure", "ivanti/policy_secure", "ivanti/cloud_services_appliance"], notes: "Ivanti CS: actualizar fuera de horario laboral. 2 appliances en producción (Madrid y Barcelona).", contactPerson: "Carlos Ruiz", phone: "+34 634 567 890" },
  { id: 4, name: "Equipo Endpoint / Escritorio", email: "endpoint@corp.local", products: ["apple/macos", "apple/ios", "7-zip/7-zip"], notes: "Fleet de 450 MacBooks gestionados con Jamf. 7-Zip desplegado via SCCM en Windows.", contactPerson: "Ana López", phone: "+34 645 678 901" },
  { id: 5, name: "Equipo Cloud y DevOps", email: "cloud-devops@corp.local", products: ["aviatrix/controller", "cisco/meeting_management"], notes: "Aviatrix controller en AWS eu-west-1. Cisco Meeting en SaaS — verificar versión con el vendor.", contactPerson: "Miguel Torres", phone: "+34 656 789 012" },
];

const MOCK_RUNS = [
  { id: 50, startedAt: new Date(Date.now() - 18 * 60000).toISOString(), finishedAt: new Date(Date.now() - 16 * 60000).toISOString(), source: "scheduled", status: "success", cvesFetched: 23, cvesNew: 5, cvesUpdated: 18, durationMs: 127400 },
  { id: 49, startedAt: new Date(Date.now() - 48 * 60000).toISOString(), finishedAt: new Date(Date.now() - 46 * 60000).toISOString(), source: "scheduled", status: "success", cvesFetched: 11, cvesNew: 2, cvesUpdated: 9, durationMs: 89200 },
  { id: 48, startedAt: new Date(Date.now() - 78 * 60000).toISOString(), finishedAt: new Date(Date.now() - 77 * 60000).toISOString(), source: "scheduled", status: "success", cvesFetched: 0, cvesNew: 0, cvesUpdated: 0, durationMs: 12100 },
  { id: 47, startedAt: new Date(Date.now() - 108 * 60000).toISOString(), finishedAt: new Date(Date.now() - 106 * 60000).toISOString(), source: "scheduled", status: "success", cvesFetched: 34, cvesNew: 8, cvesUpdated: 26, durationMs: 156800 },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────
const sevColor = (s) => ({ CRITICAL: C.critical, HIGH: C.high, MEDIUM: C.medium, LOW: C.low }[s] || C.gray500);
const sevBg = (s) => ({ CRITICAL: C.criticalBg, HIGH: C.highBg, MEDIUM: C.mediumBg, LOW: C.lowBg }[s] || C.gray100);
const timeAgo = (d) => { if (!d) return "-"; const s = Math.floor((Date.now() - new Date(d).getTime()) / 1000); if (s < 60) return `${s}s`; if (s < 3600) return `${Math.floor(s / 60)}m`; if (s < 86400) return `${Math.floor(s / 3600)}h`; return `${Math.floor(s / 86400)}d`; };
const fmtDate = (d) => d ? new Date(d).toLocaleString("es-ES", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "-";
const fmtEpss = (e) => e != null ? `${(parseFloat(e) * 100).toFixed(1)}%` : "-";
const fmtScore = (s) => s != null ? parseFloat(s).toFixed(1) : "-";
const fmtMs = (ms) => ms ? `${(ms / 1000).toFixed(1)}s` : "-";

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
  const [view, setView] = useState("overview");
  const [collapsed, setCollapsed] = useState(false);
  const [searchQ, setSearchQ] = useState("");
  const [searchType, setSearchType] = useState("all");
  const [sevFilter, setSevFilter] = useState("");
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [contacts, setContacts] = useState(MOCK_CONTACTS);
  const [editContact, setEditContact] = useState(null);
  const [showContactForm, setShowContactForm] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [reportResult, setReportResult] = useState(null);
  const [reportHours, setReportHours] = useState("24");
  const [reportSev, setReportSev] = useState("MEDIUM");
  const [aiQuery, setAiQuery] = useState("");
  const [aiMessages, setAiMessages] = useState([]);
  const [aiLoading, setAiLoading] = useState(false);
  const [now, setNow] = useState(Date.now());
  const [smtpConfig, setSmtpConfig] = useState({ host: "", port: "", user: "", pass: "", secure: false, from: "" });
  const [smtpLoading, setSmtpLoading] = useState(false);
  const [smtpSaving, setSmtpSaving] = useState(false);
  const [testEmail, setTestEmail] = useState("");
  const [testSending, setTestSending] = useState(false);
  const [smtpMsg, setSmtpMsg] = useState(null);
  const aiEndRef = useRef(null);

  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 30000); return () => clearInterval(t); }, []);
  useEffect(() => { aiEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [aiMessages]);

  useEffect(() => {
    if (view === "settings") {
      setSmtpLoading(true);
      fetch(`${API_BASE}/notifications/config`)
        .then(res => res.json())
        .then(data => {
          if (data) setSmtpConfig({ ...data, pass: "" }); // Don't show password
          setSmtpLoading(false);
        })
        .catch(() => setSmtpLoading(false));
    }
  }, [view]);

  const handleCreateTest = async () => {
    if (!testEmail) return;
    setTestSending(true);
    try {
      const res = await fetch(`${API_BASE}/notifications/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: testEmail }),
      });
      if (res.ok) setSmtpMsg({ type: "success", text: "Email de prueba enviado correctamente" });
      else throw new Error("Error enviando email");
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error enviando email de prueba" });
    }
    setTestSending(false);
    setTimeout(() => setSmtpMsg(null), 3000);
  };

  const handleSaveSmtp = async () => {
    setSmtpSaving(true);
    try {
      const res = await fetch(`${API_BASE}/notifications/config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(smtpConfig),
      });
      if (res.ok) setSmtpMsg({ type: "success", text: "Configuración guardada correctamente" });
      else throw new Error("Error guardando configuración");
    } catch (e) {
      setSmtpMsg({ type: "error", text: "Error guardando configuración" });
    }
    setSmtpSaving(false);
    setTimeout(() => setSmtpMsg(null), 3000);
  };

  const dash = MOCK_DASHBOARD;
  const todayT = dash.today.reduce((s, c) => s + c._count, 0);
  const weekT = dash.week.reduce((s, c) => s + c._count, 0);
  const gc = (arr, sev) => arr.find(c => c.cvssV31Severity === sev)?._count || 0;
  const nextRun = () => { if (!dash.lastRun?.finishedAt) return "-"; return Math.max(0, Math.floor((new Date(dash.lastRun.finishedAt).getTime() + 1800000 - now) / 60000)) + "m"; };

  // Search logic
  const searchResults = searchQ.trim().length >= 2 ? MOCK_VULNS.filter(v => {
    const q = searchQ.toLowerCase();
    if (searchType === "cve") return v.cveId.toLowerCase().includes(q);
    if (searchType === "product") return (v.affectedProducts || []).some(p => `${p.vendor}/${p.product}`.toLowerCase().includes(q) || p.vendor.toLowerCase().includes(q) || p.product.toLowerCase().includes(q));
    return v.cveId.toLowerCase().includes(q) || v.description.toLowerCase().includes(q) || (v.affectedProducts || []).some(p => `${p.vendor} ${p.product}`.toLowerCase().includes(q));
  }) : [];

  // Find contacts affected by a CVE
  const getAffectedContacts = (vuln) => {
    if (!vuln) return [];
    const prods = (vuln.affectedProducts || []).map(p => `${p.vendor}/${p.product}`);
    return contacts.filter(c => c.products.some(cp => prods.includes(cp)));
  };

  // AI Chat handler
  const handleAiSend = async () => {
    if (!aiQuery.trim()) return;
    const userMsg = aiQuery.trim();
    setAiMessages(prev => [...prev, { role: "user", content: userMsg }]);
    setAiQuery("");
    setAiLoading(true);

    const context = `Eres el asistente de IA de la Oficina de Ciberseguridad Corporativa (OCC) de SEIDOR. Tu rol es analizar vulnerabilidades (CVEs), evaluar impacto en la infraestructura corporativa, y recomendar acciones de remediación.

Base de datos actual: ${MOCK_VULNS.length} CVEs indexados.
Top CVEs con explotación activa: ${MOCK_VULNS.filter(v => v.isKnownExploited).map(v => v.cveId).join(", ")}.
Equipos IT registrados: ${contacts.map(c => `${c.name} (${c.products.join(", ")})`).join("; ")}.

Responde siempre en español, con rigor técnico. Incluye CVE IDs específicos cuando sea relevante. Si te preguntan sobre impacto, correlaciona con los productos y equipos IT registrados.`;

    try {
      const res = await fetch(`${OLLAMA_BASE}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: "llama3.1", messages: [{ role: "system", content: context }, ...aiMessages.map(m => ({ role: m.role, content: m.content })), { role: "user", content: userMsg }], stream: false }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiMessages(prev => [...prev, { role: "assistant", content: data.message?.content || "Sin respuesta del modelo." }]);
      } else {
        throw new Error("Ollama error");
      }
    } catch {
      // Simulated response for demo
      const simulated = generateSimulatedResponse(userMsg);
      setAiMessages(prev => [...prev, { role: "assistant", content: simulated }]);
    }
    setAiLoading(false);
  };

  const generateSimulatedResponse = (q) => {
    const ql = q.toLowerCase();
    if (ql.includes("cve-2025-21298") || ql.includes("windows ole")) return `**CVE-2025-21298 — Windows OLE RCE**\n\n**Severidad:** CRITICAL (CVSS 9.8) | **EPSS:** 94.3% probabilidad de explotación\n**Estado:** ⚠️ Explotación activa confirmada (CISA KEV)\n\n**Impacto en infraestructura OCC:**\n- Afecta a microsoft/windows_11 y windows_server_2022\n- **Equipo afectado:** Infraestructura Windows (infra-windows@corp.local)\n- Ventana de parcheo configurada: domingos 02:00-06:00\n\n**Recomendación:**\nDada la explotación activa, recomiendo solicitar parcheo de emergencia fuera de la ventana habitual. El vector de ataque es via documentos manipulados (OLE), lo que implica riesgo directo por phishing.\n\n**Acciones inmediatas:**\n1. Notificar a Pedro Gómez (infra-windows) para parcheo urgente\n2. Bloquear adjuntos OLE en el gateway de correo temporalmente\n3. Verificar detecciones en EDR para intentos de explotación`;
    if (ql.includes("fortinet") || ql.includes("fortigate") || ql.includes("fortios")) return `**Análisis FortiOS — CVE-2024-55591**\n\n**Severidad:** CRITICAL (CVSS 9.8) | Authentication Bypass\n**Estado:** Explotación activa confirmada\n\n**Detalle técnico:**\nBypass de autenticación via Node.js websocket en FortiOS permite a un atacante no autenticado obtener privilegios de super-admin mediante requests CSF proxy manipulados.\n\n**Impacto en OCC:**\n- **Equipo afectado:** Redes y Firewalls (redes-fw@corp.local)\n- FortiOS configurado en HA activo-pasivo según notas del equipo\n- Requiere CAB approval excepto P1 — esta vulnerabilidad califica como P1\n\n**Remediación:**\n1. Actualizar a FortiOS ≥7.0.17 inmediatamente\n2. Verificar logs de admin para accesos no autorizados\n3. Revisar reglas CSF proxy y deshabilitar si no se usa\n4. Contactar a Laura Martín para coordinar`;
    if (ql.includes("resumen") || ql.includes("estado") || ql.includes("informe")) return `**Resumen ejecutivo — Estado de vulnerabilidades**\n\n📊 **Últimas 24h:** ${todayT} CVEs procesados\n- 🔴 Critical: ${gc(dash.today, "CRITICAL")} | 🟠 High: ${gc(dash.today, "HIGH")} | 🟡 Medium: ${gc(dash.today, "MEDIUM")}\n\n⚡ **Explotación activa:** ${dash.topExploited.length} CVEs confirmados en CISA KEV\n\n**Top prioridades:**\n1. **CVE-2025-21298** (Windows OLE) — CVSS 9.8, EPSS 94.3% → Equipo Infra Windows\n2. **CVE-2024-55591** (FortiOS) — CVSS 9.8, EPSS 87.6% → Equipo Redes\n3. **CVE-2025-0282** (Ivanti CS) — CVSS 9.0, EPSS 89.1% → Equipo VPN\n\n**Recomendación:** Convocar reunión de emergencia con los 3 equipos afectados para coordinar parcheo prioritario de las 3 CVEs con explotación activa y CVSS ≥9.0.`;
    if (ql.includes("ivanti")) return `**Análisis Ivanti — Múltiples CVEs activas**\n\n**CVE-2025-0282** (Connect Secure) — CVSS 9.0\nBuffer overflow en stack permite RCE sin autenticación. Exploit público disponible.\n\n**CVE-2024-8963** (CSA) — CVSS 9.4\nPath traversal permite acceso no autenticado a funcionalidad restringida.\n\n**Impacto OCC:**\n- **Equipo VPN y Acceso Remoto** (vpn-team@corp.local)\n- 2 appliances en producción (Madrid y Barcelona)\n- Contacto: Carlos Ruiz\n\n**Acciones:**\n1. Verificar versión actual de Connect Secure (vulnerable si <22.7R2.5)\n2. Aplicar parche fuera de horario laboral según protocolo del equipo\n3. Ejecutar Integrity Checker Tool de Ivanti post-parcheo\n4. Revisar logs de acceso VPN de las últimas 2 semanas`;
    return `Procesando consulta: "${q}"\n\n**Análisis basado en la base de datos OCC:**\n\nActualmente hay ${MOCK_VULNS.length} CVEs indexados, de los cuales ${MOCK_VULNS.filter(v => v.isKnownExploited).length} tienen explotación activa confirmada.\n\nLos equipos IT con mayor exposición son:\n${contacts.map(c => `- **${c.name}**: ${c.products.length} productos monitorizados`).join("\n")}\n\n¿Necesitas un análisis más específico? Puedo detallar:\n- Impacto de un CVE concreto en la infraestructura\n- Vulnerabilidades que afectan a un producto/vendor\n- Priorización de parcheo recomendada\n- Draft de comunicación a un equipo IT`;
  };

  const handleCollect = async () => { setCollecting(true); await new Promise(r => setTimeout(r, 2000)); setCollecting(false); };
  const handleReport = async () => { setGenerating(true); setReportResult(null); await new Promise(r => setTimeout(r, 2500)); setReportResult({ message: "Informe generado", summary: { total: todayT, critical: gc(dash.today, "CRITICAL"), exploited: dash.topExploited.length } }); setGenerating(false); };

  const saveContact = (c) => {
    if (c.id) { setContacts(prev => prev.map(x => x.id === c.id ? c : x)); }
    else { setContacts(prev => [...prev, { ...c, id: Date.now() }]); }
    setEditContact(null);
    setShowContactForm(false);
  };

  const sw = collapsed ? 58 : 230;

  const nav = [
    { id: "overview", label: "Visión General", icon: "shield" },
    { id: "vulns", label: "Vulnerabilidades", icon: "bug" },
    { id: "search", label: "Búsqueda", icon: "search" },
    { id: "exploited", label: "Explotación Activa", icon: "zap" },
    { id: "contacts", label: "Servicios IT", icon: "users" },
    { id: "reports", label: "Informes", icon: "file" },
    { id: "ai", label: "Asistente IA", icon: "brain" },
    { id: "collector", label: "Collector", icon: "server" },
    { id: "settings", label: "Configuración", icon: "settings" },
  ];

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
            <div style={{ width: 30, height: 30, borderRadius: "50%", background: C.navy, display: "flex", alignItems: "center", justifyContent: "center", color: "#fff", fontWeight: 700, fontSize: 11, cursor: "pointer" }} title="Cerrar Sesión" onClick={() => window.location.reload()}>A</div>
          </div>
        </header>

        <div style={{ padding: 22, flex: 1 }} className="fade" key={view}>

          {/* ═══ OVERVIEW ═══ */}
          {view === "overview" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 4px" }}>Panel de Vulnerabilidades</h1>
            <p style={{ color: C.gray500, fontSize: 12, marginBottom: 20 }}>Última actualización: {fmtDate(dash.lastRun?.finishedAt)}</p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 20 }}>
              <Metric icon="bug" label="Total CVEs" value={dash.totalAll} sub="En base de datos" color={C.navy} />
              <Metric icon="alert" label="Últimas 24h" value={todayT} sub={`${gc(dash.today, "CRITICAL")} críticas`} color={C.critical} />
              <Metric icon="zap" label="Explotación activa" value={dash.topExploited.length} sub="CISA KEV confirmadas" color="#B91C1C" />
              <Metric icon="activity" label="Semana" value={weekT} sub={`${gc(dash.week, "HIGH")} altas`} color={C.high} />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <Card title="Severidad (24h)" icon="shield">
                <Bar label="Critical" count={gc(dash.today, "CRITICAL")} total={todayT} color={C.critical} />
                <Bar label="High" count={gc(dash.today, "HIGH")} total={todayT} color={C.high} />
                <Bar label="Medium" count={gc(dash.today, "MEDIUM")} total={todayT} color={C.medium} />
                <Bar label="Low" count={gc(dash.today, "LOW")} total={todayT} color={C.low} />
              </Card>
              <Card title="Estado Collector" icon="server">
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 12 }}>
                  {[["CVEs", dash.lastRun.cvesFetched], ["Nuevos", dash.lastRun.cvesNew], ["Duración", fmtMs(dash.lastRun.durationMs)]].map(([l, v]) => (
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
                <tbody>{(dash.topExploited || []).map(v => {
                  const aff = getAffectedContacts(v);
                  return (
                    <tr key={v.cveId} className="rh" style={{ cursor: "pointer" }} onClick={() => { setSelectedVuln(MOCK_VULNS.find(x => x.cveId === v.cveId)); setView("vulns"); }}>
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
          {view === "vulns" && <>
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
                  {["CVE", "Sev", "CVSS", "EPSS", "KEV", "Exploit", "Productos", "Parche", "Publicada"].map(h => (
                    <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontSize: 9, fontWeight: 700, color: C.gray500, textTransform: "uppercase", letterSpacing: "0.7px", borderBottom: `2px solid ${C.gray200}`, whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{MOCK_VULNS.filter(v => !sevFilter || v.cvssV31Severity === sevFilter).map(v => (
                  <tr key={v.cveId} className="rh" onClick={() => setSelectedVuln(selectedVuln?.cveId === v.cveId ? null : v)} style={{ cursor: "pointer", background: v.isKnownExploited ? C.criticalBg : selectedVuln?.cveId === v.cveId ? C.bluePale : "#fff", borderLeft: v.isKnownExploited ? `3px solid ${C.critical}` : "3px solid transparent", transition: "background 0.1s" }}>
                    <td style={{ padding: "10px 12px", fontWeight: 700, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>{v.cveId}</td>
                    <td style={{ padding: "10px 12px" }}><SevBadge s={v.cvssV31Severity} small /></td>
                    <td style={{ padding: "10px 12px", fontFamily: "monospace", fontWeight: 700, fontSize: 12 }}>{fmtScore(v.cvssV31Score)}</td>
                    <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 11 }}>{fmtEpss(v.epssScore)}</td>
                    <td style={{ padding: "10px 12px" }}>{v.isKnownExploited ? <span style={{ color: C.critical, fontWeight: 800, fontSize: 11 }}>● SÍ</span> : <span style={{ color: C.gray300 }}>—</span>}</td>
                    <td style={{ padding: "10px 12px" }}>{v.hasPublicExploit ? <span style={{ color: C.high, fontWeight: 700, fontSize: 10 }}>⚡ SÍ</span> : <span style={{ color: C.gray300 }}>—</span>}</td>
                    <td style={{ padding: "10px 12px" }}>{(v.affectedProducts || []).slice(0, 2).map((p, i) => <span key={i} style={{ display: "inline-block", background: C.bluePale, color: C.navy, padding: "1px 5px", borderRadius: 2, fontSize: 8, fontWeight: 600, marginRight: 2 }}>{p.vendor}/{p.product}</span>)}{(v.affectedProducts || []).length > 2 && <span style={{ fontSize: 8, color: C.gray400 }}>+{v.affectedProducts.length - 2}</span>}</td>
                    <td style={{ padding: "10px 12px" }}>{v.remediationInfo?.patchAvailable ? "✅" : "❌"}</td>
                    <td style={{ padding: "10px 12px", fontSize: 10, color: C.gray500, fontFamily: "monospace" }}>{fmtDate(v.publishedAt)}</td>
                  </tr>
                ))}</tbody>
              </table>
            </Card>

            {selectedVuln && (
              <div className="fade" style={{ marginTop: 14 }}>
                <Card style={{ borderLeft: `4px solid ${sevColor(selectedVuln.cvssV31Severity)}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
                    <div>
                      <h2 style={{ fontSize: 18, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace", margin: "0 0 6px" }}>{selectedVuln.cveId}</h2>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        <SevBadge s={selectedVuln.cvssV31Severity} />
                        {selectedVuln.isKnownExploited && <span style={{ background: C.critical, color: "#fff", padding: "2px 8px", borderRadius: 3, fontSize: 10, fontWeight: 700 }}>🔴 CISA KEV</span>}
                        {selectedVuln.hasPublicExploit && <span style={{ background: C.high, color: "#fff", padding: "2px 8px", borderRadius: 3, fontSize: 10, fontWeight: 700 }}>⚡ EXPLOIT PÚBLICO</span>}
                      </div>
                    </div>
                    <span onClick={() => setSelectedVuln(null)} style={{ cursor: "pointer", color: C.gray400 }}><I name="x" size={18} /></span>
                  </div>
                  <p style={{ color: C.gray600, fontSize: 12, lineHeight: 1.6, marginBottom: 14 }}>{selectedVuln.description}</p>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
                    <div>
                      <h4 style={{ fontSize: 11, fontWeight: 700, color: C.gray500, marginBottom: 6, textTransform: "uppercase" }}>Software afectado</h4>
                      {(selectedVuln.affectedProducts || []).map((p, i) => <div key={i} style={{ display: "flex", gap: 6, padding: "5px 8px", background: C.bluePale, borderRadius: 4, marginBottom: 3, fontSize: 11 }}><strong style={{ color: C.navy }}>{p.vendor}</strong><span>{p.product}</span>{p.versionRange && <span style={{ fontFamily: "monospace", fontSize: 9, color: C.gray500 }}>{p.versionRange}</span>}</div>)}
                      <h4 style={{ fontSize: 11, fontWeight: 700, color: C.gray500, margin: "12px 0 6px", textTransform: "uppercase" }}>Equipos IT afectados</h4>
                      {getAffectedContacts(selectedVuln).map(c => (
                        <div key={c.id} style={{ padding: "8px 10px", background: C.gray50, borderRadius: 4, marginBottom: 4, borderLeft: `3px solid ${C.blue}` }}>
                          <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{c.name}</div>
                          <div style={{ fontSize: 11, color: C.blue, display: "flex", alignItems: "center", gap: 4 }}><I name="mail" size={12} color={C.blue} /> {c.email}</div>
                          <div style={{ fontSize: 10, color: C.gray500, marginTop: 2 }}>{c.contactPerson} · {c.phone}</div>
                        </div>
                      ))}
                    </div>
                    <div>
                      <h4 style={{ fontSize: 11, fontWeight: 700, color: C.gray500, marginBottom: 6, textTransform: "uppercase" }}>Remediación</h4>
                      <div style={{ padding: "10px 12px", borderRadius: 6, background: selectedVuln.remediationInfo?.patchAvailable ? C.lowBg : C.highBg, borderLeft: `3px solid ${selectedVuln.remediationInfo?.patchAvailable ? C.low : C.high}` }}>
                        <strong style={{ fontSize: 12, color: selectedVuln.remediationInfo?.patchAvailable ? C.low : C.high }}>{selectedVuln.remediationInfo?.patchAvailable ? "✅ Parche disponible" : "❌ Sin parche"}</strong>
                        {(selectedVuln.remediationInfo?.vendorAdvisories || []).map((u, i) => <div key={i} style={{ marginTop: 4, fontSize: 10, display: "flex", alignItems: "center", gap: 4 }}><I name="link" size={11} color={C.blue} /><a href={u} target="_blank" rel="noreferrer" style={{ color: C.blue, textDecoration: "none", wordBreak: "break-all" }}>{u}</a></div>)}
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 12 }}>
                        {[["CVSS", fmtScore(selectedVuln.cvssV31Score)], ["EPSS", fmtEpss(selectedVuln.epssScore)]].map(([l, v]) => <div key={l} style={{ background: C.gray50, borderRadius: 4, padding: "8px 10px" }}><div style={{ fontSize: 9, color: C.gray500, fontWeight: 600 }}>{l}</div><div style={{ fontSize: 18, fontWeight: 800, fontFamily: "monospace", color: C.text }}>{v}</div></div>)}
                      </div>
                      <Btn small style={{ marginTop: 12 }} onClick={() => { setAiQuery(`Analiza el impacto de ${selectedVuln.cveId} en nuestra infraestructura y recomienda acciones`); setView("ai"); }}>
                        <I name="brain" size={14} /> Analizar con IA
                      </Btn>
                    </div>
                  </div>
                </Card>
              </div>
            )}
          </>}

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
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
                <span style={{ fontSize: 11, color: C.gray500, lineHeight: "26px" }}>Búsquedas rápidas:</span>
                {["fortinet", "microsoft", "ivanti", "cisco", "CVE-2025", "sonicwall", "apple"].map(q => (
                  <span key={q} onClick={() => { setSearchQ(q); setSearchType(q.startsWith("CVE") ? "cve" : "product"); }} style={{ padding: "3px 10px", background: C.bluePale, color: C.navy, borderRadius: 4, fontSize: 11, fontWeight: 600, cursor: "pointer", transition: "all 0.1s" }}>{q}</span>
                ))}
              </div>
            </Card>

            {searchQ.trim().length >= 2 && (
              <div className="fade" style={{ marginTop: 14 }}>
                <div style={{ fontSize: 12, color: C.gray500, marginBottom: 10 }}>
                  {searchResults.length} resultado{searchResults.length !== 1 ? "s" : ""} para "{searchQ}"
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
                          <Btn small style={{ marginTop: 6 }} onClick={() => { setSelectedVuln(v); setView("vulns"); }}>Detalle →</Btn>
                        </div>
                      </div>
                    </Card>
                  );
                })}
                {searchResults.length === 0 && <Card><div style={{ textAlign: "center", padding: 20, color: C.gray500 }}>Sin resultados para "{searchQ}"</div></Card>}
              </div>
            )}
          </>}

          {/* ═══ EXPLOITED ═══ */}
          {view === "exploited" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 14px" }}>Explotación Activa</h1>
            <div style={{ background: C.critical, color: "#fff", borderRadius: 8, padding: "14px 18px", marginBottom: 16, display: "flex", alignItems: "center", gap: 10 }}>
              <I name="alert" size={20} color="#fff" />
              <div><div style={{ fontWeight: 700, fontSize: 13 }}>{MOCK_VULNS.filter(v => v.isKnownExploited).length} vulnerabilidades con explotación activa</div><div style={{ fontSize: 11, opacity: 0.85 }}>Parcheo prioritario según CISA BOD 22-01</div></div>
            </div>
            {MOCK_VULNS.filter(v => v.isKnownExploited).map(v => {
              const aff = getAffectedContacts(v);
              return (
                <Card key={v.cveId} style={{ marginBottom: 10, borderLeft: `4px solid ${C.critical}` }}>
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
                </Card>
              );
            })}
          </>}

          {/* ═══ CONTACTS ═══ */}
          {view === "contacts" && <>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div>
                <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: 0 }}>Servicios IT</h1>
                <p style={{ color: C.gray500, fontSize: 12, marginTop: 2 }}>Directorio de equipos IT para comunicación de vulnerabilidades</p>
              </div>
              <Btn primary onClick={() => { setEditContact({ id: null, name: "", email: "", products: [], notes: "", contactPerson: "", phone: "" }); setShowContactForm(true); }}><I name="plus" size={14} color="#fff" /> Nuevo servicio</Btn>
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
              const affectedVulns = MOCK_VULNS.filter(v => (v.affectedProducts || []).some(p => c.products.includes(`${p.vendor}/${p.product}`)));
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
                        {c.products.map(p => <span key={p} style={{ background: C.bluePale, color: C.navy, padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600 }}>{p}</span>)}
                      </div>
                      {c.notes && <div style={{ fontSize: 11, color: C.gray500, background: C.gray50, padding: "6px 10px", borderRadius: 4, borderLeft: `2px solid ${C.gray300}`, lineHeight: 1.5 }}>{c.notes}</div>}
                    </div>
                    <div style={{ display: "flex", gap: 6, flexShrink: 0, marginLeft: 12 }}>
                      <Btn small onClick={() => { setEditContact({ ...c }); setShowContactForm(true); }}><I name="edit" size={12} /></Btn>
                    </div>
                  </div>
                  {affectedVulns.length > 0 && (
                    <div style={{ marginTop: 10, padding: "8px 10px", background: C.gray50, borderRadius: 4 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: C.gray500, marginBottom: 4, textTransform: "uppercase" }}>CVEs que afectan a este equipo ({affectedVulns.length})</div>
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                        {affectedVulns.map(v => (
                          <span key={v.cveId} onClick={() => { setSelectedVuln(v); setView("vulns"); }} style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 8px", background: sevBg(v.cvssV31Severity), border: `1px solid ${sevColor(v.cvssV31Severity)}30`, borderRadius: 3, fontSize: 9, fontWeight: 700, fontFamily: "monospace", cursor: "pointer", color: sevColor(v.cvssV31Severity) }}>
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

          {/* ═══ REPORTS ═══ */}
          {view === "reports" && <>
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 16px" }}>Generación de Informes</h1>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <Card title="Nuevo Informe PDF" icon="file">
                <div style={{ marginBottom: 12 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Periodo</label>
                  <select value={reportHours} onChange={e => setReportHours(e.target.value)} style={{ width: "100%", padding: "10px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12 }}>
                    <option value="6">Últimas 6h</option><option value="12">Últimas 12h</option><option value="24">Últimas 24h</option><option value="48">Últimas 48h</option><option value="168">Última semana</option>
                  </select>
                </div>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: C.gray600, display: "block", marginBottom: 4 }}>Severidad mínima</label>
                  <select value={reportSev} onChange={e => setReportSev(e.target.value)} style={{ width: "100%", padding: "10px", border: `1px solid ${C.gray200}`, borderRadius: 6, fontSize: 12 }}>
                    <option value="CRITICAL">Solo CRITICAL</option><option value="HIGH">HIGH+</option><option value="MEDIUM">MEDIUM+</option><option value="LOW">Todas</option>
                  </select>
                </div>
                <Btn primary onClick={handleReport} disabled={generating} style={{ width: "100%" }}>
                  {generating ? <><span style={{ animation: "spin 1s linear infinite", display: "inline-block" }}>⟳</span> Generando...</> : <><I name="file" size={14} color="#fff" /> Generar PDF</>}
                </Btn>
                {reportResult && <div className="fade" style={{ marginTop: 12, padding: "10px 12px", background: C.lowBg, borderRadius: 4, borderLeft: `3px solid ${C.low}`, fontSize: 12, color: C.low, fontWeight: 600 }}>✅ {reportResult.message} — {reportResult.summary.total} CVEs, {reportResult.summary.critical} críticas</div>}
              </Card>
              <Card title="Contenido del informe" icon="check">
                {[["Portada", "Branding SEIDOR OCC con clasificación TLP"], ["Resumen ejecutivo", "Métricas de severidad y explotación"], ["Acción inmediata", "CVEs con explotación activa (CISA KEV)"], ["Equipos afectados", "Correlación automática con servicios IT"], ["Tabla detallada", "CVSS, EPSS, productos, parche, remediación"]].map(([t, d]) => (
                  <div key={t} style={{ display: "flex", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.gray100}`, fontSize: 12 }}>
                    <I name="check" size={13} color={C.low} /><div><strong>{t}:</strong> {d}</div>
                  </div>
                ))}
              </Card>
            </div>
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
            <h1 style={{ fontSize: 22, fontWeight: 800, color: C.text, margin: "0 0 16px" }}>Configuración de Notificaciones</h1>
            <Card title="Configuración SMTP" icon="settings">
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
                      <Input value={smtpConfig.pass} onChange={v => setSmtpConfig({ ...smtpConfig, pass: v })} placeholder="••••••••" type="password" />
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
            </Card>
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
                  { label: "PostgreSQL", desc: "Persistencia", color: C.low, icon: "server" },
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

            <Card title="Historial de ejecuciones" icon="clock" noPad>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr style={{ background: C.gray50 }}>
                  {["#", "Inicio", "Fuente", "Estado", "Obtenidos", "Nuevos", "Duración"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 9, fontWeight: 700, color: C.gray500, textTransform: "uppercase", borderBottom: `2px solid ${C.gray200}` }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>{MOCK_RUNS.map(r => (
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
