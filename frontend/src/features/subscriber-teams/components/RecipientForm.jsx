import {
  LANGUAGE_OPTIONS,
  RECIPIENT_TYPE_OPTIONS,
  TIMEZONE_OPTIONS,
  buildRecipientPayload,
  createDefaultRecipientForm,
  validateRecipientForm,
} from "../utils/teamForms.js";
import { Button, CheckboxField, DialogFrame, SelectField, TextInput } from "./TeamUi.jsx";

export default function RecipientForm({
  open,
  initialValue = null,
  loading = false,
  onClose,
  onChange,
  onSubmit,
}) {
  const value = initialValue || createDefaultRecipientForm();
  const errors = validateRecipientForm(value);

  if (!open) return null;

  const handleSubmit = (event) => {
    event.preventDefault();
    if (Object.keys(errors).length > 0) return;
    onSubmit(buildRecipientPayload(value));
  };

  return (
    <DialogFrame
      title={value.id ? "Editar destinatario" : "Añadir destinatario"}
      subtitle="Un destinatario puede recibir notificaciones sin tener acceso a la aplicación."
      onClose={loading ? () => {} : onClose}
      footer={(
        <>
          <Button onClick={onClose} disabled={loading}>Cancelar</Button>
          <Button primary onClick={handleSubmit} disabled={loading || Object.keys(errors).length > 0}>
            {loading ? "Guardando..." : value.id ? "Guardar cambios" : "Crear destinatario"}
          </Button>
        </>
      )}
    >
      <form onSubmit={handleSubmit} style={{ display: "grid", gap: 14 }}>
        <TextInput label="Email" value={value.email} onChange={(next) => onChange({ ...value, email: next })} error={errors.email} autoFocus />
        <TextInput label="Nombre visible" value={value.name} onChange={(next) => onChange({ ...value, name: next })} error={errors.name} />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12 }}>
          <SelectField label="Tipo" value={value.type} onChange={(next) => onChange({ ...value, type: next })} options={RECIPIENT_TYPE_OPTIONS} error={errors.type} />
          <SelectField label="Idioma" value={value.language} onChange={(next) => onChange({ ...value, language: next })} options={LANGUAGE_OPTIONS} error={errors.language} />
          <SelectField label="Zona horaria" value={value.timezone} onChange={(next) => onChange({ ...value, timezone: next })} options={TIMEZONE_OPTIONS.map((item) => ({ value: item, label: item }))} error={errors.timezone} />
        </div>
        <CheckboxField checked={value.isActive !== false} onChange={(next) => onChange({ ...value, isActive: next })} label="Destinatario activo" />
      </form>
    </DialogFrame>
  );
}

