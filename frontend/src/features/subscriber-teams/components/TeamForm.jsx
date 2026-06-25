import {
  buildTeamPayload,
  createDefaultTeamForm,
  validateTeamForm,
} from "../utils/teamForms.js";
import { Button, CheckboxField, DialogFrame, TextArea, TextInput } from "./TeamUi.jsx";

export default function TeamForm({
  open,
  initialValue = null,
  loading = false,
  submitLabel = "Guardar",
  onClose,
  onChange,
  onSubmit,
}) {
  const value = initialValue || createDefaultTeamForm();
  const errors = validateTeamForm(value);

  if (!open) return null;

  const handleSubmit = (event) => {
    event.preventDefault();
    if (Object.keys(errors).length > 0) return;
    onSubmit(buildTeamPayload(value));
  };

  return (
    <DialogFrame
      title={value.id ? "Editar equipo" : "Crear equipo"}
      subtitle="Configura el identificador y los datos generales del equipo suscriptor."
      onClose={loading ? () => {} : onClose}
      footer={(
        <>
          <Button onClick={onClose} disabled={loading}>Cancelar</Button>
          <Button primary onClick={handleSubmit} disabled={loading || Object.keys(errors).length > 0}>
            {loading ? "Guardando..." : submitLabel}
          </Button>
        </>
      )}
    >
      <form onSubmit={handleSubmit} style={{ display: "grid", gap: 14 }}>
        <TextInput label="Nombre" value={value.name} onChange={(next) => onChange({ ...value, name: next })} error={errors.name} autoFocus />
        <TextInput label="Código" value={value.code} onChange={(next) => onChange({ ...value, code: next })} error={errors.code} help="Ejemplo: it-es" />
        <TextArea label="Descripción" value={value.description} onChange={(next) => onChange({ ...value, description: next })} rows={4} />
        <CheckboxField
          checked={value.isActive !== false}
          onChange={(next) => onChange({ ...value, isActive: next })}
          label="Equipo activo"
          help="Los equipos inactivos siguen visibles para ADMIN, pero no operan desde el portal."
        />
      </form>
    </DialogFrame>
  );
}
