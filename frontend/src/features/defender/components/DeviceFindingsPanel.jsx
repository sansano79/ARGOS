import { useEffect, useState } from "react";
import {
  Button,
  DataTable,
  InlineMessage,
  Panel,
  StatGrid,
  Tabs,
  TextInput,
  teamColors,
} from "../../subscriber-teams/components/TeamUi.jsx";
import { Badge, Cell } from "./DefenderUi.jsx";
import { exploitLabel, formatDateTime, formatEpss, severityTone } from "../utils/defenderViewModel.js";

const PAGE_SIZE = 100;

const columns = [
  { key: "cve", label: "CVE" },
  { key: "software", label: "Software" },
  { key: "severity", label: "Severidad Defender" },
  { key: "cvss", label: "CVSS" },
  { key: "epss", label: "EPSS" },
  { key: "exploit", label: "Explotación" },
  { key: "kb", label: "Remediación" },
  { key: "seen", label: "Detectado" },
];

export default function DeviceFindingsPanel({ api, device, onBack, onOpenCve }) {
  const [status, setStatus] = useState("open");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState({ items: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    const timer = setTimeout(async () => {
      try {
        const res = await api.listFindings(device.id, { status, search: search.trim(), page, pageSize: PAGE_SIZE });
        if (!cancelled) setData(res || { items: [], total: 0 });
      } catch (e) {
        if (!cancelled) setError(e.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, search ? 300 : 0);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [api, device.id, status, search, page]);

  const f = device.openFindings || {};
  const pages = Math.max(1, Math.ceil((data.total || 0) / PAGE_SIZE));

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        <Button small onClick={onBack}>← Servidores</Button>
        <div>
          <div style={{ fontSize: 17, fontWeight: 800, color: teamColors.text }}>{device.name}</div>
          <div style={{ fontSize: 11.5, color: teamColors.gray500 }}>
            {[device.platform, device.osVersion, device.team?.name && `Equipo: ${device.team.name}`, device.lastIpAddress].filter(Boolean).join(" · ")}
          </div>
        </div>
      </div>

      <StatGrid
        items={[
          { label: "Abiertas", value: f.total || 0 },
          { label: "Explotadas (KEV)", value: f.knownExploited || 0, color: f.knownExploited ? "var(--ds-crit)" : undefined },
          { label: "Exploit público", value: f.publicExploit || 0, color: f.publicExploit ? "var(--ds-high)" : undefined },
          { label: "Críticas", value: f.critical || 0 },
          { label: "Exposición Defender", value: device.exposureLevel || "—", sub: `Riesgo: ${device.defenderRiskScore || "—"}` },
        ]}
      />

      {f.notInCatalog > 0 && (
        <InlineMessage>
          {f.notInCatalog} hallazgos son CVEs que aún no están en el catálogo de ARGOS: se muestran sin KEV/EPSS hasta que se enriquezcan.
        </InlineMessage>
      )}

      <Panel
        noPad
        title="Vulnerabilidades detectadas por Defender"
        subtitle="Ordenadas por explotación activa y CVSS. Esta lista aún no indica si hay un camino de ataque real: eso llega en la fase de análisis."
        action={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Tabs
              items={[{ id: "open", label: "Abiertas" }, { id: "fixed", label: "Corregidas" }, { id: "all", label: "Todas" }]}
              activeId={status}
              onChange={(id) => { setStatus(id); setPage(1); }}
            />
          </div>
        }
      >
        <div style={{ padding: "12px 18px 0", maxWidth: 360 }}>
          <TextInput value={search} onChange={(v) => { setSearch(v); setPage(1); }} placeholder="Buscar CVE, software o KB" />
        </div>
        {error && <div style={{ padding: "12px 18px 0" }}><InlineMessage type="error">{error}</InlineMessage></div>}
        <div style={{ paddingTop: 12 }}>
          <DataTable
            columns={columns}
            rows={data.items || []}
            loading={loading}
            rowKey="id"
            empty={<span style={{ fontSize: 12, color: teamColors.gray500 }}>Sin hallazgos con estos filtros.</span>}
            renderRow={(row) => {
              const intel = row.intelligence;
              const exploit = exploitLabel(row);
              return (
                <tr key={row.id}>
                  <Cell mono>
                    {row.inCatalog && onOpenCve
                      ? <button type="button" onClick={() => onOpenCve(row.cveId)} style={{ border: "none", background: "none", padding: 0, color: "var(--ds-primary)", cursor: "pointer", font: "inherit", fontWeight: 700 }}>{row.cveId}</button>
                      : <strong>{row.cveId}</strong>}
                    {!row.inCatalog && <div><Badge>no catalogada</Badge></div>}
                  </Cell>
                  <Cell>
                    {row.productName}
                    <div style={{ color: teamColors.gray500, fontSize: 11 }}>{[row.productVendor, row.productVersion].filter(Boolean).join(" · ")}</div>
                  </Cell>
                  <Cell><Badge tone={severityTone(row.defenderSeverity)}>{row.defenderSeverity || "—"}</Badge></Cell>
                  <Cell mono>{intel?.cvssV31Score ?? row.defenderCvss ?? "—"}</Cell>
                  <Cell mono>{formatEpss(intel?.epssScore)}</Cell>
                  <Cell>{exploit ? <Badge tone={exploit === "KEV" ? "crit" : "high"}>{exploit}</Badge> : <span style={{ color: teamColors.gray300 }}>—</span>}</Cell>
                  <Cell mono muted={!row.fixingKbId}>{row.fixingKbId || (intel?.patchAvailable ? "Parche disponible" : "—")}</Cell>
                  <Cell muted>
                    {formatDateTime(row.firstSeenAt)}
                    {row.status === "fixed" && <div><Badge tone="ok">Corregida {formatDateTime(row.fixedAt)}</Badge></div>}
                  </Cell>
                </tr>
              );
            }}
          />
        </div>
        {pages > 1 && (
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", alignItems: "center", padding: 12, fontSize: 12, color: teamColors.gray500 }}>
            <Button small disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Anterior</Button>
            Página {page} de {pages} · {data.total} hallazgos
            <Button small disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Siguiente</Button>
          </div>
        )}
      </Panel>
    </div>
  );
}
