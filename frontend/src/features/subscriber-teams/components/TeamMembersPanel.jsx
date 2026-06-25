import { getTeamRoleLabel } from "../utils/teamViewModel.js";
import EmptyState from "./EmptyState.jsx";
import TeamStatusBadge from "./TeamStatusBadge.jsx";
import { Button, DataTable, InlineMessage, Panel, teamColors } from "./TeamUi.jsx";

export default function TeamMembersPanel({ members, loading, error, canManage, onAdd, onEdit, onRemove }) {
  return (
    <Panel
      title="Miembros"
      subtitle="Gestiona quién tiene acceso al equipo y con qué nivel."
      action={canManage ? <Button primary onClick={onAdd}>Añadir miembro</Button> : null}
    >
      <div style={{ display: "grid", gap: 12 }}>
        {error && <InlineMessage type="error">{error}</InlineMessage>}
        <DataTable
          columns={[
            { key: "name", label: "Nombre" },
            { key: "email", label: "Email" },
            { key: "globalRole", label: "Rol global" },
            { key: "teamRole", label: "Rol de equipo" },
            { key: "status", label: "Estado" },
            { key: "createdAt", label: "Alta" },
            { key: "actions", label: "Acciones" },
          ]}
          rows={members}
          rowKey="id"
          loading={loading}
          empty={<EmptyState title="Sin miembros" description="Añade un responsable o un usuario de solo consulta para empezar." action={canManage ? <Button primary onClick={onAdd}>Añadir miembro</Button> : null} />}
          renderRow={(member) => (
            <tr key={member.id} style={{ borderTop: `1px solid ${teamColors.gray100}` }}>
              <td style={{ padding: "12px", fontSize: 12, fontWeight: 700 }}>{member.user?.name || "Sin nombre"}</td>
              <td style={{ padding: "12px", fontSize: 11, color: teamColors.gray500 }}>{member.user?.email || "-"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{member.user?.role || "—"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{getTeamRoleLabel(member.role)}</td>
              <td style={{ padding: "12px" }}><TeamStatusBadge isActive={member.isActive} /></td>
              <td style={{ padding: "12px", fontSize: 11, color: teamColors.gray500 }}>{new Date(member.createdAt).toLocaleDateString("es-ES")}</td>
              <td style={{ padding: "12px" }}>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {canManage && <Button small onClick={() => onEdit(member)}>Editar</Button>}
                  {canManage && <Button small danger onClick={() => onRemove(member)}>Retirar</Button>}
                </div>
              </td>
            </tr>
          )}
        />
      </div>
    </Panel>
  );
}

