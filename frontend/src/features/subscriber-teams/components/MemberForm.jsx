import {
  TEAM_ROLE_OPTIONS,
  buildMemberPayload,
  createDefaultMemberForm,
  validateMemberForm,
} from "../utils/teamForms.js";
import {
  getAllowedTeamRolesForGlobalRole,
  getGlobalUserRoleLabel,
  getTeamRoleCompatibilityMessage,
} from "../../../utils/userManagement.js";
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
  const selectedUser = userOptions.find((user) => String(user.id) === String(value.userId || ""));
  const compatibilityError = selectedUser
    ? getTeamRoleCompatibilityMessage(selectedUser.globalRole, value.role)
    : "";

  if (!open) return null;

  const selectOptions = [
    { value: "", label: "Selecciona un usuario..." },
    ...userOptions.map((user) => ({
      value: String(user.id),
      label: `${user.name} · ${user.email} · ${getGlobalUserRoleLabel(user.globalRole)}${user.disabled ? " · Ya es miembro" : ""}`,
      disabled: user.disabled,
    })),
  ];
  const teamRoleOptions = TEAM_ROLE_OPTIONS
    .filter((option) => !selectedUser || getAllowedTeamRolesForGlobalRole(selectedUser.globalRole).includes(option.value))
    .map((option) => ({ value: option.value, label: option.label }));

  const handleSubmit = (event) => {
    event.preventDefault();
    if (Object.keys(errors).length > 0 || compatibilityError) return;
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
          <Button primary onClick={handleSubmit} disabled={loading || Object.keys(errors).length > 0 || !!compatibilityError}>
            {loading ? "Guardando..." : value.id ? "Guardar cambios" : "Añadir miembro"}
          </Button>
        </>
      )}
    >
      <form onSubmit={handleSubmit} style={{ display: "grid", gap: 14 }}>
        <SelectField label="Usuario" value={String(value.userId || "")} onChange={(next) => onChange({ ...value, userId: next })} options={selectOptions} error={errors.userId} />
        {selectedUser && (
          <div style={{ fontSize: 11, color: "#4b5563", marginTop: -6 }}>
            Rol global: <strong>{getGlobalUserRoleLabel(selectedUser.globalRole)}</strong>
          </div>
        )}
        <SelectField label="Rol de equipo" value={value.role} onChange={(next) => onChange({ ...value, role: next })} options={teamRoleOptions} error={errors.role || compatibilityError} />
        {compatibilityError && (
          <div style={{ fontSize: 11, color: "#b91c1c", fontWeight: 600 }}>
            {compatibilityError}
          </div>
        )}
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
