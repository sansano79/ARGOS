import { teamColors } from "../../subscriber-teams/components/TeamUi.jsx";

const TONES = {
  crit: { color: "var(--ds-crit)", background: "var(--ds-danger-soft)" },
  high: { color: "var(--ds-high)", background: "var(--ds-danger-soft)" },
  warn: { color: "var(--ds-warn)", background: "var(--ds-warn-soft)" },
  ok: { color: "var(--ds-ok)", background: "var(--ds-ok-soft)" },
  info: { color: "var(--ds-primary)", background: "var(--ds-primary-soft)" },
  muted: { color: teamColors.gray500, background: teamColors.gray100 },
};

export const Badge = ({ tone = "muted", children, title }) => {
  const t = TONES[tone] || TONES.muted;
  return (
    <span
      title={title}
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: 999,
        fontSize: 10.5,
        fontWeight: 700,
        whiteSpace: "nowrap",
        color: t.color,
        background: t.background,
      }}
    >
      {children}
    </span>
  );
};

export const Cell = ({ children, mono = false, muted = false, align = "left" }) => (
  <td
    style={{
      padding: "10px 12px",
      borderBottom: `1px solid ${teamColors.gray100}`,
      fontSize: 12,
      color: muted ? teamColors.gray500 : teamColors.text,
      fontFamily: mono ? "var(--ds-font-mono, ui-monospace, monospace)" : undefined,
      textAlign: align,
      verticalAlign: "top",
    }}
  >
    {children}
  </td>
);

/** Recuento compacto: no muestra nada si es cero, para que destaque lo relevante. */
export const Count = ({ value, tone }) =>
  value ? <Badge tone={tone}>{value}</Badge> : <span style={{ color: teamColors.gray300 }}>·</span>;
