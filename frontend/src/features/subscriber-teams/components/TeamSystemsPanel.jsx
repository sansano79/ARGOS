import EmptyState from "./EmptyState.jsx";
import TeamStatusBadge from "./TeamStatusBadge.jsx";
import { Button, DataTable, InlineMessage, Panel, teamColors } from "./TeamUi.jsx";

export default function TeamSystemsPanel({ systems, loading, error, canManage, onAdd, onEdit, onRemove }) {
  return (
    <Panel
      title="Sistemas / unidades"
      subtitle="Vista compacta del inventario asociado al equipo."
      action={canManage ? <Button primary onClick={onAdd}>Añadir sistema</Button> : null}
    >
      <div style={{ display: "grid", gap: 12 }}>
        <InlineMessage type="info">`rawData` no se expone en la UI ni se envía al backend en esta fase.</InlineMessage>
        {error && <InlineMessage type="error">{error}</InlineMessage>}
        <DataTable
          columns={[
            { key: "name", label: "Nombre" },
            { key: "externalId", label: "External ID" },
            { key: "source", label: "Origen" },
            { key: "hostname", label: "Hostname" },
            { key: "fqdn", label: "FQDN" },
            { key: "platform", label: "Plataforma" },
            { key: "osVersion", label: "SO" },
            { key: "riskLevel", label: "Riesgo" },
            { key: "healthStatus", label: "Salud" },
            { key: "status", label: "Estado" },
            { key: "selected", label: "Seleccionado" },
            { key: "actions", label: "Acciones" },
          ]}
          rows={systems}
          rowKey="id"
          loading={loading}
          empty={<EmptyState title="Sin sistemas" description="Añade las unidades o sistemas que pertenecen al equipo." action={canManage ? <Button primary onClick={onAdd}>Añadir sistema</Button> : null} />}
          renderRow={(system) => (
            <tr key={system.id} style={{ borderTop: `1px solid ${teamColors.gray100}` }}>
              <td style={{ padding: "12px", fontSize: 12, fontWeight: 700 }}>{system.name}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.externalId || "—"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.source || "manual"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.hostname || "—"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.fqdn || "—"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.platform || "—"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.osVersion || "—"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.riskLevel || "—"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.healthStatus || "—"}</td>
              <td style={{ padding: "12px" }}><TeamStatusBadge isActive={system.isActive} /></td>
              <td style={{ padding: "12px", fontSize: 11 }}>{system.isSelected ? "Sí" : "No"}</td>
              <td style={{ padding: "12px" }}>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {canManage && <Button small onClick={() => onEdit(system)}>Editar</Button>}
                  {canManage && <Button small danger onClick={() => onRemove(system)}>Eliminar</Button>}
                </div>
              </td>
            </tr>
          )}
        />
      </div>
    </Panel>
  );
}

