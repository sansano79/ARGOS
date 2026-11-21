import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  DataTable,
  InlineMessage,
  PageHeader,
  Panel,
  StatGrid,
  Tabs,
  TextInput,
  teamColors,
} from "../../subscriber-teams/components/TeamUi.jsx";
import { createDefenderApi } from "../api/defenderApi.js";
import DefenderConfigPanel from "../components/DefenderConfigPanel.jsx";
import DeviceFindingsPanel from "../components/DeviceFindingsPanel.jsx";
import { Badge, Cell, Count } from "../components/DefenderUi.jsx";
import {
  formatDateTime,
  formatDuration,
  isRunPending,
  runStatusMeta,
  sortDevicesByRisk,
  summarizeDevices,
} from "../utils/defenderViewModel.js";

const deviceColumns = [
  { key: "name", label: "Servidor" },
  { key: "kev", label: "KEV" },
  { key: "exploit", label: "Exploit público" },
  { key: "critical", label: "Críticas" },
  { key: "high", label: "Altas" },
  { key: "total", label: "Abiertas" },
  { key: "exposure", label: "Exposición" },
  { key: "team", label: "Equipo ARGOS" },
  { key: "seen", label: "Último contacto" },
];

const runColumns = [
  { key: "when", label: "Inicio" },
  { key: "mode", label: "Tipo" },
  { key: "status", label: "Estado" },
  { key: "devices", label: "Servidores" },
  { key: "findings", label: "Hallazgos" },
  { key: "fixed", label: "Corregidos" },
  { key: "duration", label: "Duración" },
  { key: "detail", label: "Detalle" },
];

const exposureTone = (level) => ({ High: "crit", Medium: "warn", Low: "ok" })[level] || "muted";

export default function DefenderServersPage({ apiFetch, onOpenCve }) {
  const api = useMemo(() => createDefenderApi(apiFetch), [apiFetch]);
  const [tab, setTab] = useState("devices");
  const [devices, setDevices] = useState([]);
  const [runs, setRuns] = useState([]);
  const [config, setConfig] = useState(null);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [message, setMessage] = useState(null);
  const pollRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const [deviceRes, runList, cfg] = await Promise.all([api.listDevices(), api.listRuns(15), api.getConfig()]);
      setDevices(deviceRes?.items || []);
      setRuns(Array.isArray(runList) ? runList : []);
      setConfig(cfg);
    } catch (error) {
      setMessage({ type: "error", text: error.message });
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    load();
  }, [load]);

  // Mientras haya una sincronización en curso, refresca cada 10 s.
  useEffect(() => {
    clearInterval(pollRef.current);
    if (isRunPending(runs)) pollRef.current = setInterval(load, 10_000);
    return () => clearInterval(pollRef.current);
  }, [runs, load]);

  const startSync = async (mode) => {
    setSyncing(true);
    setMessage(null);
    try {
      const res = await api.requestSync(mode);
      setMessage({
        type: "info",
        text: res.alreadyPending
          ? `Ya había una sincronización pendiente (#${res.runId}); se sigue su progreso.`
          : `Sincronización ${mode === "full" ? "completa" : "incremental"} #${res.runId} en cola.`,
      });
      setTab("runs");
      await load();
    } catch (error) {
      setMessage({ type: "error", text: error.message });
    } finally {
      setSyncing(false);
    }
  };

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = q
      ? devices.filter((d) => [d.name, d.tags, d.team?.name, d.platform].some((v) => String(v || "").toLowerCase().includes(q)))
      : devices;
    return sortDevicesByRisk(filtered);
  }, [devices, search]);

  const summary = summarizeDevices(devices);
  const lastRun = runs[0];
  const configured = config?.isActive && config?.tenantId && config?.clientId && config?.hasClientSecret && config?.teamId;

  if (selected) {
    return <DeviceFindingsPanel api={api} device={selected} onBack={() => setSelected(null)} onOpenCve={onOpenCve} />;
  }

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <PageHeader
        title="Servidores (Microsoft Defender)"
        subtitle={`Vulnerabilidades que Defender detecta en los servidores${config?.serverTags?.length ? ` con tag ${config.serverTags.join(", ")}` : ""}. Solo lectura.`}
        actions={
          <>
            <Button onClick={() => startSync("delta")} disabled={!configured || syncing || isRunPending(runs)}>Sync incremental</Button>
            <Button primary onClick={() => startSync("full")} disabled={!configured || syncing || isRunPending(runs)}>Sync completo</Button>
          </>
        }
      />

      {message && <InlineMessage type={message.type}>{message.text}</InlineMessage>}
      {!loading && !configured && (
        <InlineMessage type="error">
          La integración no está lista: completa tenant, aplicación, secreto y equipo de destino en la pestaña Configuración.
        </InlineMessage>
      )}

      <Tabs
        items={[
          { id: "devices", label: `Servidores (${devices.length})` },
          { id: "runs", label: "Sincronizaciones" },
          { id: "config", label: "Configuración" },
        ]}
        activeId={tab}
        onChange={setTab}
      />

      {tab === "devices" && (
        <>
          <StatGrid
            items={[
              { label: "Servidores", value: summary.devices },
              { label: "Con CVE explotada (KEV)", value: summary.devicesWithKev, color: summary.devicesWithKev ? "var(--ds-crit)" : undefined },
              { label: "Vulnerabilidades abiertas", value: summary.findings },
              {
                label: "Última sincronización",
                value: lastRun ? runStatusMeta(lastRun.status).label : "—",
                sub: lastRun ? formatDateTime(lastRun.finishedAt || lastRun.startedAt || lastRun.createdAt) : "Nunca",
              },
            ]}
          />
          <Panel
            noPad
            title="Servidores"
            subtitle="Ordenados por explotación activa, exploit público y severidad. Pulsa un servidor para ver sus vulnerabilidades."
            action={<div style={{ width: 260 }}><TextInput value={search} onChange={setSearch} placeholder="Buscar servidor, tag o equipo" /></div>}
          >
            <DataTable
              columns={deviceColumns}
              rows={visible}
              loading={loading}
              rowKey="id"
              empty={
                <span style={{ fontSize: 12, color: teamColors.gray500 }}>
                  {devices.length ? "Ningún servidor coincide con la búsqueda." : "Aún no hay servidores. Configura la integración y lanza un sync completo."}
                </span>
              }
              renderRow={(d) => (
                <tr key={d.id} onClick={() => setSelected(d)} style={{ cursor: "pointer" }} tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter") setSelected(d); }}>
                  <Cell>
                    <strong>{d.name}</strong>
                    <div style={{ color: teamColors.gray500, fontSize: 11 }}>{[d.platform, d.tags].filter(Boolean).join(" · ")}</div>
                  </Cell>
                  <Cell align="center"><Count value={d.openFindings?.knownExploited} tone="crit" /></Cell>
                  <Cell align="center"><Count value={d.openFindings?.publicExploit} tone="high" /></Cell>
                  <Cell align="center"><Count value={d.openFindings?.critical} tone="crit" /></Cell>
                  <Cell align="center"><Count value={d.openFindings?.high} tone="high" /></Cell>
                  <Cell align="center">{d.openFindings?.total || 0}</Cell>
                  <Cell><Badge tone={exposureTone(d.exposureLevel)}>{d.exposureLevel || "—"}</Badge></Cell>
                  <Cell muted>{d.team?.name || "—"}</Cell>
                  <Cell muted>{formatDateTime(d.lastSeen)}</Cell>
                </tr>
              )}
            />
          </Panel>
        </>
      )}

      {tab === "runs" && (
        <Panel noPad title="Historial de sincronizaciones" subtitle={isRunPending(runs) ? "Hay una sincronización en curso; esta vista se actualiza sola." : undefined}>
          <DataTable
            columns={runColumns}
            rows={runs}
            loading={loading}
            rowKey="id"
            empty={<span style={{ fontSize: 12, color: teamColors.gray500 }}>Sin sincronizaciones todavía.</span>}
            renderRow={(r) => {
              const meta = runStatusMeta(r.status);
              const failures = Array.isArray(r.failures) ? r.failures : [];
              return (
                <tr key={r.id}>
                  <Cell muted>{formatDateTime(r.startedAt || r.createdAt)}</Cell>
                  <Cell>{r.mode === "full" ? "Completo" : "Incremental"}</Cell>
                  <Cell><Badge tone={meta.tone}>{meta.label}</Badge></Cell>
                  <Cell>{r.devicesSeen}{r.devicesFailed ? <div style={{ color: "var(--ds-high)", fontSize: 11 }}>{r.devicesFailed} con error</div> : null}</Cell>
                  <Cell>{r.findingsUpserted}{r.unknownCves ? <div style={{ color: teamColors.gray500, fontSize: 11 }}>{r.unknownCves} CVEs no catalogadas</div> : null}</Cell>
                  <Cell>{r.findingsFixed}</Cell>
                  <Cell muted>{formatDuration(r.durationMs)}</Cell>
                  <Cell muted>
                    {r.errorMessage || (failures.length
                      ? failures.slice(0, 3).map((f, i) => <div key={i}>{f.device ? `${f.device}: ` : ""}{f.error}</div>)
                      : "—")}
                    {failures.length > 3 && <div>… y {failures.length - 3} más</div>}
                  </Cell>
                </tr>
              );
            }}
          />
        </Panel>
      )}

      {tab === "config" && <DefenderConfigPanel api={api} onSaved={(cfg) => setConfig(cfg)} />}
    </div>
  );
}
