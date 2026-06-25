import {
  buildSubscriptionPayload,
  createDefaultSubscriptionForm,
  validateSubscriptionForm,
} from "../utils/teamForms.js";
import { Button, CheckboxField, DialogFrame, TextInput } from "./TeamUi.jsx";

export default function SubscriptionForm({
  open,
  initialValue = null,
  loading = false,
  onClose,
  onChange,
  onSubmit,
}) {
  const value = initialValue || createDefaultSubscriptionForm();
  const errors = validateSubscriptionForm(value);

  if (!open) return null;

  const handleSubmit = (event) => {
    event.preventDefault();
    if (Object.keys(errors).length > 0) return;
    onSubmit(buildSubscriptionPayload(value));
  };

  return (
    <DialogFrame
      title={value.id ? "Editar suscripción" : "Añadir suscripción"}
      subtitle="Las suscripciones de equipo todavía no sustituyen las suscripciones legacy en el motor de notificaciones."
      onClose={loading ? () => {} : onClose}
      footer={(
        <>
          <Button onClick={onClose} disabled={loading}>Cancelar</Button>
          <Button primary onClick={handleSubmit} disabled={loading || Object.keys(errors).length > 0}>
            {loading ? "Guardando..." : value.id ? "Guardar cambios" : "Crear suscripción"}
          </Button>
        </>
      )}
    >
      <form onSubmit={handleSubmit} style={{ display: "grid", gap: 14 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
          <TextInput label="Fabricante / vendor" value={value.vendor} onChange={(next) => onChange({ ...value, vendor: next })} error={errors.vendor} autoFocus />
          <TextInput label="Producto" value={value.product} onChange={(next) => onChange({ ...value, product: next })} error={errors.product} />
        </div>
        <TextInput
          label="Versiones"
          value={value.versionsText}
          onChange={(next) => onChange({ ...value, versionsText: next })}
          help="Separadas por comas. Si lo dejas vacío, aplica a todas."
        />
        <CheckboxField checked={value.isActive !== false} onChange={(next) => onChange({ ...value, isActive: next })} label="Suscripción activa" />
      </form>
    </DialogFrame>
  );
}

