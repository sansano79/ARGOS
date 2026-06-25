import { teamColors } from "./TeamUi.jsx";

export default function TeamStatusBadge({ isActive, activeLabel = "Activo", inactiveLabel = "Inactivo" }) {
  const active = isActive !== false;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "3px 9px",
        borderRadius: 999,
        border: `1px solid ${active ? "#bbf7d0" : "#fecaca"}`,
        background: active ? teamColors.lowBg : teamColors.criticalBg,
        color: active ? teamColors.low : teamColors.critical,
        fontSize: 11,
        fontWeight: 700,
      }}
    >
      {active ? activeLabel : inactiveLabel}
    </span>
  );
}

