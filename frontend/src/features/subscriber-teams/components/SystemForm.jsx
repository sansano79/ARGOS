import {
  SYSTEM_RISK_OPTIONS,
  buildSystemPayload,
  buildSystemUpdatePayload,
  createDefaultSystemForm,
  validateSystemForm,
} from "../utils/teamForms.js";
import { Button, CheckboxField, DialogFrame, SelectField, TextArea, TextInput } from "./TeamUi.jsx";

export default function SystemForm({
  open,
  initialValue = null,
  loading = false,
  onClose,
  onChange,
  onSubmit,
}) {
  const value = initialValue || createDefaultSystemForm();
  const errors = validateSystemForm(value);

  if (!open) return null;

  const handleSubmit = (event) => {
    event.preventDefault();
    if (Object.keys(errors).length > 0) return;
    onSubmit(value.id ? buildSystemUpdatePayload(value) : buildSystemPayload(value));
  };

  return (
    <DialogFrame
      title={value.id ? "Editar sistema / unidad" : "Añadir sistema / unidad"}
      subtitle="El backend actual no expone edición de rawData y todavía no acepta healthStatus o tags en create/update."
      onClose={loading ? () => {} : onClose}
      wide
      footer={(
        <>
          <Button onClick={onClose} disabled={loading}>Cancelar</Button>
          <Button primary onClick={handleSubmit} disabled={loading || Object.keys(errors).length > 0}>
            {loading ? "Guardando..." : value.id ? "Guardar cambios" : "Registrar sistema"}
          </Button>
        </>
      )}
    >
      <form onSubmit={handleSubmit} style={{ display: "grid", gap: 18 }}>
        <section style={{ display: "grid", gap: 12 }}>
          <div style={{ fontSize: 12, fontWeight: 800 }}>Información principal</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
            <TextInput label="Nombre" value={value.name} onChange={(next) => onChange({ ...value, name: next })} error={errors.name} autoFocus />
            <TextInput label="External ID" value={value.externalId} onChange={(next) => onChange({ ...value, externalId: next })} error={errors.externalId} />
            <TextInput label="Origen" value={value.source} onChange={(next) => onChange({ ...value, source: next })} error={errors.source} />
          </div>
          <TextArea label="Descripción" value={value.description} onChange={(next) => onChange({ ...value, description: next })} rows={3} />
        </section>

        <section style={{ display: "grid", gap: 12 }}>
          <div style={{ fontSize: 12, fontWeight: 800 }}>Datos técnicos</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
            <TextInput label="Hostname" value={value.hostname} onChange={(next) => onChange({ ...value, hostname: next })} error={errors.hostname} />
            <TextInput label="FQDN" value={value.fqdn} onChange={(next) => onChange({ ...value, fqdn: next })} error={errors.fqdn} />
            <TextInput label="Plataforma" value={value.platform} onChange={(next) => onChange({ ...value, platform: next })} error={errors.platform} />
            <TextInput label="Versión del SO" value={value.osVersion} onChange={(next) => onChange({ ...value, osVersion: next })} error={errors.osVersion} />
            <SelectField
              label="Riesgo"
              value={value.riskLevel}
              onChange={(next) => onChange({ ...value, riskLevel: next })}
              options={[{ value: "", label: "Sin clasificar" }, ...SYSTEM_RISK_OPTIONS.map((item) => ({ value: item, label: item }))]}
              error={errors.riskLevel}
            />
          </div>
        </section>

        <section style={{ display: "grid", gap: 12 }}>
          <div style={{ fontSize: 12, fontWeight: 800 }}>Estado</div>
          <div style={{ display: "grid", gap: 10 }}>
            <CheckboxField checked={value.isSelected !== false} onChange={(next) => onChange({ ...value, isSelected: next })} label="Seleccionado para seguimiento" />
            <CheckboxField checked={value.isActive !== false} onChange={(next) => onChange({ ...value, isActive: next })} label="Sistema activo" />
          </div>
        </section>
      </form>
    </DialogFrame>
  );
}
