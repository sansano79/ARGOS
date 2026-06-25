import { useEffect, useId, useRef } from "react";

export const teamColors = {
  navy: "#1e293b",
  text: "#0f172a",
  blue: "#2563eb",
  blueLight: "#60a5fa",
  bluePale: "#eff6ff",
  white: "#ffffff",
  gray50: "#f8fafc",
  gray100: "#f1f5f9",
  gray200: "#e2e8f0",
  gray300: "#cbd5e1",
  gray400: "#94a3b8",
  gray500: "#64748b",
  gray600: "#475569",
  gray700: "#334155",
  critical: "#dc2626",
  criticalBg: "#fef2f2",
  warning: "#ea580c",
  warningBg: "#fff7ed",
  low: "#16a34a",
  lowBg: "#f0fdf4",
};

export const DIALOG_AUTOFOCUS_SELECTOR = "[autofocus]";
export const DIALOG_FOCUS_PRIORITY_SELECTORS = [
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[contenteditable='true']",
  "[href]",
  "[tabindex]:not([tabindex='-1'])",
  "button:not([disabled])",
];

export const findPreferredDialogFocusTarget = (panel) => {
  if (!panel?.querySelector) return null;

  const autoFocusTarget = panel.querySelector(DIALOG_AUTOFOCUS_SELECTOR);
  if (autoFocusTarget) return autoFocusTarget;

  for (const selector of DIALOG_FOCUS_PRIORITY_SELECTORS) {
    const candidate = panel.querySelector(selector);
    if (candidate) return candidate;
  }

  return null;
};

export const setupDialogFrameFocusLifecycle = ({
  panel,
  restoreFocusRef,
  onCloseRef,
  documentTarget = document,
  windowTarget = window,
}) => {
  restoreFocusRef.current = documentTarget?.activeElement || null;

  const preferredFocus = findPreferredDialogFocusTarget(panel);
  preferredFocus?.focus?.();

  const handleKeyDown = (event) => {
    if (event.key === "Escape") {
      onCloseRef.current?.();
    }
  };

  windowTarget?.addEventListener?.("keydown", handleKeyDown);

  return () => {
    windowTarget?.removeEventListener?.("keydown", handleKeyDown);
    restoreFocusRef.current?.focus?.();
  };
};

export const PageHeader = ({ title, subtitle, actions }) => (
  <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, marginBottom: 20 }}>
    <div>
      <h1 style={{ margin: 0, color: teamColors.text, fontSize: 21, fontWeight: 800 }}>{title}</h1>
      {subtitle && <p style={{ margin: "6px 0 0", color: teamColors.gray500, fontSize: 12, lineHeight: 1.5 }}>{subtitle}</p>}
    </div>
    {actions && <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>{actions}</div>}
  </div>
);

export const Panel = ({ title, subtitle, action, children, noPad = false }) => (
  <section style={{ background: "#fff", borderRadius: 12, border: `1px solid ${teamColors.gray200}`, overflow: "hidden" }}>
    {(title || action) && (
      <div style={{ padding: "14px 18px", borderBottom: `1px solid ${teamColors.gray100}`, display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
        <div>
          {title && <div style={{ fontSize: 13, fontWeight: 700, color: teamColors.text }}>{title}</div>}
          {subtitle && <div style={{ marginTop: 4, fontSize: 11, color: teamColors.gray500, lineHeight: 1.5 }}>{subtitle}</div>}
        </div>
        {action}
      </div>
    )}
    {noPad ? children : <div style={{ padding: 18 }}>{children}</div>}
  </section>
);

export const InlineMessage = ({ type = "info", children }) => {
  const palette = type === "error"
    ? { background: teamColors.criticalBg, border: "#fecaca", color: teamColors.critical }
    : type === "success"
      ? { background: teamColors.lowBg, border: "#bbf7d0", color: teamColors.low }
      : { background: teamColors.bluePale, border: "#bfdbfe", color: teamColors.blue };

  return (
    <div style={{ padding: "10px 12px", borderRadius: 10, border: `1px solid ${palette.border}`, background: palette.background, color: palette.color, fontSize: 12, lineHeight: 1.5 }}>
      {children}
    </div>
  );
};

export const Button = ({ children, onClick, primary = false, danger = false, disabled = false, small = false, type = "button", style = {}, ariaLabel }) => (
  <button
    type={type}
    aria-label={ariaLabel}
    onClick={onClick}
    disabled={disabled}
    style={{
      display: "inline-flex",
      alignItems: "center",
      justifyContent: "center",
      gap: 6,
      padding: small ? "6px 10px" : "9px 14px",
      borderRadius: 8,
      border: primary || danger ? "none" : `1px solid ${teamColors.gray200}`,
      background: disabled
        ? teamColors.gray300
        : primary
          ? teamColors.navy
          : danger
            ? teamColors.critical
            : "#fff",
      color: primary || danger ? "#fff" : teamColors.gray700,
      fontSize: small ? 11 : 12.5,
      fontWeight: 700,
      cursor: disabled ? "not-allowed" : "pointer",
      ...style,
    }}
  >
    {children}
  </button>
);

export const TextInput = ({ label, value, onChange, placeholder = "", error = "", disabled = false, type = "text", autoFocus = false, name, help }) => {
  const id = useId();
  return (
    <div>
      {label && <label htmlFor={id} style={{ display: "block", marginBottom: 5, fontSize: 11, fontWeight: 700, color: teamColors.gray600 }}>{label}</label>}
      <input
        id={id}
        name={name}
        type={type}
        value={value}
        autoFocus={autoFocus}
        disabled={disabled}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
        style={{
          width: "100%",
          padding: "10px 12px",
          borderRadius: 8,
          border: `1px solid ${error ? "#fca5a5" : teamColors.gray200}`,
          background: disabled ? teamColors.gray50 : "#fff",
          color: teamColors.text,
          fontSize: 13,
          boxSizing: "border-box",
        }}
      />
      {help && <div style={{ marginTop: 4, fontSize: 11, color: teamColors.gray500 }}>{help}</div>}
      {error && <div style={{ marginTop: 4, fontSize: 11, color: teamColors.critical }}>{error}</div>}
    </div>
  );
};

export const TextArea = ({ label, value, onChange, placeholder = "", error = "", rows = 4, help }) => {
  const id = useId();
  return (
    <div>
      {label && <label htmlFor={id} style={{ display: "block", marginBottom: 5, fontSize: 11, fontWeight: 700, color: teamColors.gray600 }}>{label}</label>}
      <textarea
        id={id}
        value={value}
        rows={rows}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
        style={{
          width: "100%",
          padding: "10px 12px",
          borderRadius: 8,
          border: `1px solid ${error ? "#fca5a5" : teamColors.gray200}`,
          background: "#fff",
          color: teamColors.text,
          fontSize: 13,
          resize: "vertical",
          boxSizing: "border-box",
          fontFamily: "inherit",
        }}
      />
      {help && <div style={{ marginTop: 4, fontSize: 11, color: teamColors.gray500 }}>{help}</div>}
      {error && <div style={{ marginTop: 4, fontSize: 11, color: teamColors.critical }}>{error}</div>}
    </div>
  );
};

export const SelectField = ({ label, value, onChange, options = [], error = "", disabled = false, help = "" }) => {
  const id = useId();
  return (
    <div>
      {label && <label htmlFor={id} style={{ display: "block", marginBottom: 5, fontSize: 11, fontWeight: 700, color: teamColors.gray600 }}>{label}</label>}
      <select
        id={id}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
        style={{
          width: "100%",
          padding: "10px 12px",
          borderRadius: 8,
          border: `1px solid ${error ? "#fca5a5" : teamColors.gray200}`,
          background: disabled ? teamColors.gray50 : "#fff",
          color: teamColors.text,
          fontSize: 13,
          boxSizing: "border-box",
        }}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} disabled={option.disabled === true}>
            {option.label}
          </option>
        ))}
      </select>
      {help && <div style={{ marginTop: 4, fontSize: 11, color: teamColors.gray500 }}>{help}</div>}
      {error && <div style={{ marginTop: 4, fontSize: 11, color: teamColors.critical }}>{error}</div>}
    </div>
  );
};

export const CheckboxField = ({ checked, onChange, label, help = "" }) => (
  <label style={{ display: "flex", alignItems: "flex-start", gap: 8, cursor: "pointer" }}>
    <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} style={{ marginTop: 2 }} />
    <span style={{ fontSize: 12, color: teamColors.text, lineHeight: 1.4 }}>
      <strong style={{ display: "block" }}>{label}</strong>
      {help && <span style={{ display: "block", marginTop: 2, color: teamColors.gray500, fontWeight: 400 }}>{help}</span>}
    </span>
  </label>
);

export const StatGrid = ({ items }) => (
  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10 }}>
    {items.map((item) => (
      <div key={item.label} style={{ padding: "12px 14px", borderRadius: 10, border: `1px solid ${teamColors.gray200}`, background: item.background || teamColors.gray50 }}>
        <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: teamColors.gray500, letterSpacing: "0.05em" }}>{item.label}</div>
        <div style={{ marginTop: 6, fontSize: 22, fontWeight: 800, color: item.color || teamColors.text }}>{item.value}</div>
        {item.sub && <div style={{ marginTop: 4, fontSize: 11, color: teamColors.gray500 }}>{item.sub}</div>}
      </div>
    ))}
  </div>
);

export const Tabs = ({ items, activeId, onChange }) => (
  <div style={{ display: "flex", gap: 4, flexWrap: "wrap", padding: 4, background: teamColors.gray100, borderRadius: 10 }}>
    {items.map((item) => {
      const active = item.id === activeId;
      return (
        <button
          key={item.id}
          type="button"
          onClick={() => onChange(item.id)}
          style={{
            padding: "8px 14px",
            borderRadius: 8,
            border: "none",
            background: active ? "#fff" : "transparent",
            color: active ? teamColors.text : teamColors.gray500,
            fontSize: 12,
            fontWeight: active ? 700 : 600,
            cursor: "pointer",
          }}
        >
          {item.label}
        </button>
      );
    })}
  </div>
);

export const DataTable = ({ columns, rows, empty, loading = false, rowKey, renderRow }) => (
  <div style={{ overflowX: "auto" }}>
    <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 760 }}>
      <thead>
        <tr style={{ background: teamColors.gray50 }}>
          {columns.map((column) => (
            <th key={column.key} style={{ padding: "10px 12px", textAlign: "left", fontSize: 10, color: teamColors.gray500, textTransform: "uppercase", letterSpacing: "0.05em", borderBottom: `1px solid ${teamColors.gray200}` }}>
              {column.label}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {loading && (
          <tr>
            <td colSpan={columns.length} style={{ padding: 18, fontSize: 12, color: teamColors.gray500 }}>
              Cargando datos...
            </td>
          </tr>
        )}
        {!loading && rows.length === 0 && (
          <tr>
            <td colSpan={columns.length} style={{ padding: 18 }}>
              {empty}
            </td>
          </tr>
        )}
        {!loading && rows.map((row) => renderRow(row, row[rowKey]))}
      </tbody>
    </table>
  </div>
);

export const DialogFrame = ({ title, subtitle, children, onClose, footer, wide = false }) => {
  const panelRef = useRef(null);
  const restoreFocusRef = useRef(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    return setupDialogFrameFocusLifecycle({
      panel: panelRef.current,
      restoreFocusRef,
      onCloseRef,
    });
  }, []);

  return (
    <div
      role="dialog"
      aria-modal="true"
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "rgba(15, 23, 42, 0.55)", display: "flex", alignItems: "center", justifyContent: "center", padding: 20, zIndex: 220 }}
    >
      <div
        ref={panelRef}
        onClick={(event) => event.stopPropagation()}
        style={{ width: wide ? "min(980px, 100%)" : "min(640px, 100%)", maxHeight: "92vh", overflowY: "auto", borderRadius: 14, background: "#fff", border: `1px solid ${teamColors.gray200}`, boxShadow: "0 30px 90px rgba(2, 8, 23, 0.24)" }}
      >
        <div style={{ padding: "18px 20px", borderBottom: `1px solid ${teamColors.gray100}`, display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
          <div>
            <div style={{ fontSize: 17, fontWeight: 800, color: teamColors.text }}>{title}</div>
            {subtitle && <div style={{ marginTop: 4, fontSize: 12, color: teamColors.gray500, lineHeight: 1.5 }}>{subtitle}</div>}
          </div>
          <Button onClick={onClose} small ariaLabel="Cerrar diálogo">Cerrar</Button>
        </div>
        <div style={{ padding: 20 }}>{children}</div>
        {footer && <div style={{ padding: "0 20px 20px", display: "flex", justifyContent: "flex-end", gap: 8 }}>{footer}</div>}
      </div>
    </div>
  );
};
