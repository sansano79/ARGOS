import React from "react";
import { buildUserFormViewModel } from "./userFormViewModel.js";

const DEFAULT_COLORS = {
  text: "#111827",
  gray50: "#F9FAFB",
  gray100: "#F3F4F6",
  gray200: "#E5E7EB",
  gray500: "#6B7280",
  gray600: "#4B5563",
  gray700: "#374151",
  critical: "#DC2626",
  criticalBg: "#FEF2F2",
};

const DefaultButton = ({ children, type = "button", disabled, onClick, small, primary }) => (
  <button
    type={type}
    disabled={disabled}
    onClick={onClick}
    style={{
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 6,
      padding: small ? "5px 10px" : "8px 16px",
      fontSize: small ? 11 : 12.5,
      fontWeight: 600,
      borderRadius: 8,
      border: primary ? "none" : `1px solid ${DEFAULT_COLORS.gray200}`,
      background: disabled ? DEFAULT_COLORS.gray200 : primary ? "#0F172A" : "#fff",
      color: primary ? "#fff" : DEFAULT_COLORS.gray700,
      cursor: disabled ? "not-allowed" : "pointer",
    }}
  >
    {children}
  </button>
);

const DefaultInput = ({ value, onChange, placeholder, type = "text" }) => (
  <input
    type={type}
    value={value}
    onChange={(event) => onChange(event.target.value)}
    placeholder={placeholder}
    style={{
      width: "100%",
      padding: "9px 12px",
      fontSize: 13,
      border: `1px solid ${DEFAULT_COLORS.gray200}`,
      borderRadius: 8,
      background: "#fff",
      color: DEFAULT_COLORS.text,
      boxSizing: "border-box",
    }}
  />
);

export default function UserFormModal({
  user,
  getTeamOptions = () => [],
  assignmentErrors = {},
  onClose,
  onSave,
  onFieldChange,
  onAddAssignment,
  onUpdateAssignment,
  onRemoveAssignment,
  saveDisabled = false,
  colors = DEFAULT_COLORS,
  ButtonComponent = DefaultButton,
  InputComponent = DefaultInput,
}) {
  if (!user) return null;

  const Button = ButtonComponent;
  const Input = InputComponent;
  const viewModel = buildUserFormViewModel({ user, getTeamOptions, assignmentErrors });

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: "rgba(0,0,0,0.4)",
        zIndex: 200,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
      onClick={onClose}
    >
      <div
        style={{ background: "#fff", borderRadius: 12, padding: 28, width: 680, maxHeight: "92vh", overflow: "auto" }}
        onClick={(event) => event.stopPropagation()}
      >
        <h3 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 16px" }}>{viewModel.title}</h3>

        <div style={{ marginBottom: 16, fontSize: 12, color: colors.gray600 }}>
          {viewModel.note}
        </div>

        {viewModel.hiddenCurrentRole && (
          <div
            style={{
              marginBottom: 12,
              padding: "10px 12px",
              borderRadius: 8,
              border: `1px solid ${colors.gray200}`,
              background: colors.gray50,
              fontSize: 11,
              color: colors.gray600,
            }}
          >
            {viewModel.hiddenRoleMessage}
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {[{ key: "name", label: "Nombre" }, { key: "email", label: "Email" }].map((field) => (
            <div key={field.key} style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: colors.gray600, display: "block", marginBottom: 4 }}>{field.label}</label>
              <Input
                value={user[field.key] || ""}
                onChange={(value) => onFieldChange(field.key, value)}
                placeholder={field.label}
              />
            </div>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input
              type="checkbox"
              checked={!!user.canLogin}
              onChange={(event) => onFieldChange("canLogin", event.target.checked)}
            />
            <span style={{ fontSize: 12, color: colors.text }}>Permitir inicio de sesión</span>
          </label>
          <div>
            <label style={{ fontSize: 11, fontWeight: 600, color: colors.gray600, display: "block", marginBottom: 4 }}>Rol global</label>
            <select
              value={user.role || "USER"}
              onChange={(event) => onFieldChange("role", event.target.value, { roleTouched: true })}
              style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${colors.gray200}`, borderRadius: 6, background: "#fff" }}
            >
              {viewModel.roleOptions.map((option) => (
                <option key={option.value} value={option.value} disabled={option.hidden === true}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ marginBottom: 12 }}>
          <label style={{ fontSize: 11, fontWeight: 600, color: colors.gray600, display: "block", marginBottom: 4 }}>
            {user.id ? "Nueva contraseña (opcional)" : "Contraseña (obligatoria si permites acceso)"}
          </label>
          <Input
            type="password"
            value={user.password || ""}
            onChange={(value) => onFieldChange("password", value)}
            placeholder="Mínimo 8 caracteres"
          />
        </div>

        <div style={{ display: "grid", gap: 10, marginBottom: 12, padding: 14, border: `1px solid ${colors.gray200}`, borderRadius: 10, background: colors.gray50 }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: colors.text }}>{viewModel.assignmentsTitle}</div>
            <div style={{ fontSize: 11, color: colors.gray600, marginTop: 4 }}>{viewModel.assignmentsNote}</div>
          </div>

          {viewModel.assignmentRows.map((assignment, index) => (
            <div key={`team-assignment-${index}`} style={{ display: "grid", gridTemplateColumns: "minmax(220px, 1fr) 220px auto", gap: 10, alignItems: "end" }}>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: colors.gray600, display: "block", marginBottom: 4 }}>Equipo</label>
                <select
                  value={assignment.teamId || ""}
                  onChange={(event) => onUpdateAssignment(index, { teamId: event.target.value })}
                  style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${assignment.error ? colors.critical : colors.gray200}`, borderRadius: 6, background: "#fff" }}
                >
                  <option value="">Selecciona un equipo...</option>
                  {assignment.teamOptions.map((option) => (
                    <option key={option.value} value={option.value} disabled={option.disabled}>{option.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: colors.gray600, display: "block", marginBottom: 4 }}>Rol en el equipo</label>
                <select
                  value={assignment.role || "TEAM_VIEWER"}
                  onChange={(event) => onUpdateAssignment(index, { role: event.target.value })}
                  style={{ width: "100%", padding: "10px 12px", fontSize: 13, border: `1px solid ${assignment.error ? colors.critical : colors.gray200}`, borderRadius: 6, background: "#fff" }}
                >
                  {assignment.teamRoleOptions.map((teamRole) => (
                    <option key={teamRole.value} value={teamRole.value}>{teamRole.label}</option>
                  ))}
                </select>
              </div>
              <Button small onClick={() => onRemoveAssignment(index)}>Retirar</Button>
              {assignment.error && (
                <div style={{ gridColumn: "1 / -1", fontSize: 11, color: colors.critical, fontWeight: 600 }}>
                  {assignment.error}
                </div>
              )}
            </div>
          ))}

          <div>
            <Button onClick={onAddAssignment} disabled={!viewModel.canAddAssignments}>
              Añadir equipo
            </Button>
          </div>
        </div>

        {user.id && (
          <label style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <input
              type="checkbox"
              checked={!!user.isActive}
              onChange={(event) => onFieldChange("isActive", event.target.checked)}
            />
            <span style={{ fontSize: 12, color: colors.text }}>Usuario activo</span>
          </label>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 18 }}>
          <Button onClick={onClose}>Cancelar</Button>
          <Button primary onClick={() => onSave(user)} disabled={saveDisabled}>
            {user.id ? "Guardar cambios" : "Crear usuario"}
          </Button>
        </div>
      </div>
    </div>
  );
}
