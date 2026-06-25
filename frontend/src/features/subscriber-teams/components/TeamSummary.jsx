import { formatDateTime } from "../utils/teamViewModel.js";
import TeamStatusBadge from "./TeamStatusBadge.jsx";
import { Button, InlineMessage, Panel, StatGrid } from "./TeamUi.jsx";

export default function TeamSummary({ team, counts, canManage = true, onEdit, onToggleActive }) {
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Panel
        title={team.name}
        subtitle={`Código: ${team.code}`}
        action={canManage ? (
          <div style={{ display: "flex", gap: 8 }}>
            <Button onClick={onEdit}>Editar equipo</Button>
            <Button danger={team.isActive === false} primary={team.isActive !== false} onClick={onToggleActive}>
              {team.isActive !== false ? "Desactivar" : "Activar"}
            </Button>
          </div>
        ) : null}
      >
        <div style={{ display: "grid", gap: 14 }}>
          <div><TeamStatusBadge isActive={team.isActive} /></div>
          {team.description && <InlineMessage type="info">{team.description}</InlineMessage>}
          <StatGrid
            items={[
              { label: "Miembros", value: counts.members },
              { label: "Managers", value: counts.managers },
              { label: "Viewers", value: counts.viewers },
              { label: "Destinatarios activos", value: counts.activeRecipients },
              { label: "Suscripciones activas", value: counts.activeSubscriptions },
              { label: "Sistemas activos", value: counts.activeSystems },
            ]}
          />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
            <InlineMessage type="info">Creado: {formatDateTime(team.createdAt)}</InlineMessage>
            <InlineMessage type="info">Actualizado: {formatDateTime(team.updatedAt)}</InlineMessage>
          </div>
        </div>
      </Panel>
    </div>
  );
}
