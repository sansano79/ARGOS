import {
  TEAM_ROLE_OPTIONS,
  buildMemberPayload,
  createDefaultMemberForm,
  validateMemberForm,
} from "../utils/teamForms.js";
import { Button, CheckboxField, DialogFrame, SelectField } from "./TeamUi.jsx";

export default function MemberForm({
  open,
  initialValue = null,
  userOptions = [],
  loading = false,
  onClose,
  onChange,
  onSubmit,
}) {
  const value = initialValue || createDefaultMemberForm();
  const errors = validateMemberForm(value);

  if (!open) return null;

  const selectOptions = [
    { value: "", label: "Selecciona un usuario..." },
    ...userOptions.map((user) => ({
      value: String(user.id),
      label: `${user.name} · ${user.email}${user.disabled ? " · Ya es miembro" : ""}`,
      disabled: user.disabled,
    })),
  ];

  const handleSubmit = (event) => {
    event.preventDefault();
    if (Object.keys(errors).length > 0) return;
    onSubmit(buildMemberPayload(value));
  };

  return (
    <DialogFrame
      title={value.id ? "Actualizar miembro" : "Añadir miembro"}
      subtitle="Selecciona un usuario existente y asígnale un rol en el equipo."
      onClose={loading ? () => {} : onClose}
      footer={(
        <>
          <Button onClick={onClose} disabled={loading}>Cancelar</Button>
          <Button primary onClick={handleSubmit} disabled={loading || Object.keys(errors).length > 0}>
            {loading ? "Guardando..." : value.id ? "Guardar cambios" : "Añadir miembro"}
          </Button>
        </>
      )}
    >
      <form onSubmit={handleSubmit} style={{ display: "grid", gap: 14 }}>
        <SelectField label="Usuario" value={String(value.userId || "")} onChange={(next) => onChange({ ...value, userId: next })} options={selectOptions} error={errors.userId} />
        <SelectField label="Rol de equipo" value={value.role} onChange={(next) => onChange({ ...value, role: next })} options={TEAM_ROLE_OPTIONS.map((option) => ({ value: option.value, label: option.label }))} error={errors.role} />
        {value.id && (
          <CheckboxField
            checked={value.isActive !== false}
            onChange={(next) => onChange({ ...value, isActive: next })}
            label="Membresía activa"
            help="Desactiva el acceso sin borrar el historial de la relación."
          />
        )}
      </form>
    </DialogFrame>
  );
}

