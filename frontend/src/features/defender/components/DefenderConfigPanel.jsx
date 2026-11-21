import { useEffect, useState } from "react";
import {
  Button,
  CheckboxField,
  InlineMessage,
  Panel,
  SelectField,
  TextInput,
} from "../../subscriber-teams/components/TeamUi.jsx";
import { configToForm, formToPayload, validateConfigForm } from "../utils/defenderViewModel.js";

const grid = { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 14 };

export default function DefenderConfigPanel({ api, onSaved }) {
  const [config, setConfig] = useState(null);
  const [teams, setTeams] = useState([]);
  const [form, setForm] = useState(configToForm({}));
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [message, setMessage] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const [cfg, teamList] = await Promise.all([api.getConfig(), api.listTeams().catch(() => [])]);
      setConfig(cfg);
      setTeams(Array.isArray(teamList) ? teamList : []);
      setForm(configToForm(cfg));
    } catch (error) {
      setMessage({ type: "error", text: error.message });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value }));

  const save = async () => {
    const validation = validateConfigForm(form);
    setErrors(validation);
    if (Object.keys(validation).length) return;
    setSaving(true);
    setMessage(null);
    try {
      const saved = await api.saveConfig(formToPayload(form));
      setConfig(saved);
      setForm(configToForm(saved));
      setMessage({ type: "success", text: "Configuración guardada." });
      onSaved?.(saved);
    } catch (error) {
      setMessage({ type: "error", text: error.message });
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    setTesting(true);
    setMessage(null);
    try {
      const res = await api.testConfig();
      if (res?.ok) {
        const names = (res.sample || []).map((m) => m.computerDnsName).filter(Boolean).join(", ");
        setMessage({
          type: "success",
          text: `Conexión correcta. ${res.sampleCount}${res.sampleTruncated ? "+" : ""} equipos con ${res.sampleFilter || "el primer filtro"}${names ? ` (p. ej. ${names})` : ""}.`,
        });
      } else {
        setMessage({ type: "error", text: res?.error || "La prueba de conexión falló." });
      }
    } catch (error) {
      setMessage({ type: "error", text: error.message });
    } finally {
      setTesting(false);
    }
  };

  if (loading) return <Panel title="Configuración de Defender">Cargando…</Panel>;

  const secretHelp = config?.secretSource === "env"
    ? "Se usa DEFENDER_CLIENT_SECRET del entorno; el valor guardado aquí se ignora."
    : config?.hasClientSecret
      ? "Hay un secreto guardado (cifrado). Déjalo vacío para conservarlo."
      : config?.secretStorageAvailable
        ? "Se guarda cifrado en la base de datos."
        : "Falta DEFENDER_SECRET_KEY en el servidor: define DEFENDER_CLIENT_SECRET en el entorno.";

  return (
    <div style={{ display: "grid", gap: 16 }}>
      {message && <InlineMessage type={message.type}>{message.text}</InlineMessage>}

      <Panel
        title="Conexión con Microsoft Defender for Endpoint"
        subtitle="App de Entra ID con permisos de solo lectura sobre WindowsDefenderATP: Machine.Read.All, Vulnerability.Read.All, Software.Read.All y SecurityRecommendation.Read.All."
      >
        <div style={{ display: "grid", gap: 14 }}>
          <CheckboxField checked={form.isActive} onChange={set("isActive")} label="Integración activa" />
          <div style={grid}>
            <TextInput label="Tenant ID" value={form.tenantId} onChange={set("tenantId")} error={errors.tenantId} placeholder="00000000-0000-0000-0000-000000000000" />
            <TextInput label="Client ID (aplicación)" value={form.clientId} onChange={set("clientId")} error={errors.clientId} placeholder="00000000-0000-0000-0000-000000000000" />
            <TextInput
              label="Client secret"
              type="password"
              value={form.clientSecret}
              onChange={set("clientSecret")}
              placeholder={config?.hasClientSecret ? "•••••••• (guardado)" : ""}
              disabled={config?.secretSource === "env" || (!config?.secretStorageAvailable && !config?.hasClientSecret)}
              help={secretHelp}
            />
            <TextInput label="Endpoint de la API" value={form.baseUrl} onChange={set("baseUrl")} help="Recomendado el regional: https://eu.api.security.microsoft.com" />
          </div>
        </div>
      </Panel>

      <Panel title="Qué equipos se sincronizan" subtitle="Solo servidores, para no saturar la API ni ARGOS. Un equipo entra si cumple cualquiera de los filtros.">
        <div style={grid}>
          <TextInput label="Tags de Defender" value={form.serverTags} onChange={set("serverTags")} error={errors.serverTags} help="Separados por comas, p. ej. server, prod-server" />
          <TextInput label="Plataformas de SO (opcional)" value={form.serverOsPlatforms} onChange={set("serverOsPlatforms")} help="p. ej. WindowsServer2019, WindowsServer2022" />
          <SelectField
            label="Equipo de ARGOS para servidores nuevos"
            value={form.teamId}
            onChange={set("teamId")}
            options={[{ value: "", label: "— Selecciona un equipo —" }, ...teams.map((t) => ({ value: String(t.id), label: t.name }))]}
            help="Los servidores ya asignados a otro equipo se quedan donde están."
          />
          <TextInput label="Ignorar equipos sin contacto (días)" value={form.staleDeviceDays} onChange={set("staleDeviceDays")} />
        </div>
      </Panel>

      <Panel title="Ritmo y programación">
        <div style={{ display: "grid", gap: 14 }}>
          <CheckboxField
            checked={form.autoSyncEnabled}
            onChange={set("autoSyncEnabled")}
            label="Sincronización automática"
            help="Completa cada N horas y deltas entre medias. Desactivada, solo se sincroniza a mano."
          />
          <div style={grid}>
            <TextInput label="Sync completo cada (horas)" value={form.fullSyncIntervalHours} onChange={set("fullSyncIntervalHours")} />
            <TextInput label="Delta cada (horas)" value={form.deltaSyncIntervalHours} onChange={set("deltaSyncIntervalHours")} help="Defender regenera los datos cada 6 h." />
            <TextInput label="Peticiones por minuto" value={form.requestsPerMinute} onChange={set("requestsPerMinute")} error={errors.requestsPerMinute} help="Vulnerabilidades por equipo. Límite Microsoft: 50/min." />
            <TextInput label="Máx. servidores por ejecución" value={form.maxDevicesPerRun} onChange={set("maxDevicesPerRun")} />
          </div>
        </div>
      </Panel>

      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <Button onClick={test} disabled={testing || saving}>{testing ? "Probando…" : "Probar conexión"}</Button>
        <Button primary onClick={save} disabled={saving}>{saving ? "Guardando…" : "Guardar"}</Button>
      </div>
    </div>
  );
}
