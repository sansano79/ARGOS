import { teamColors } from "./TeamUi.jsx";

export default function EmptyState({ title, description, action = null }) {
  return (
    <div style={{ padding: 22, borderRadius: 12, border: `1px dashed ${teamColors.gray300}`, background: teamColors.gray50, color: teamColors.gray600 }}>
      <div style={{ fontSize: 14, fontWeight: 800, color: teamColors.text }}>{title}</div>
      <p style={{ margin: "8px 0 0", fontSize: 12, lineHeight: 1.6 }}>{description}</p>
      {action && <div style={{ marginTop: 14 }}>{action}</div>}
    </div>
  );
}

