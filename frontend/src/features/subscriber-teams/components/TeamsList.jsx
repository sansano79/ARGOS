import {
  ACTIVE_FILTER_OPTIONS,
} from "../utils/teamForms.js";
import { formatDateTime } from "../utils/teamViewModel.js";
import EmptyState from "./EmptyState.jsx";
import TeamStatusBadge from "./TeamStatusBadge.jsx";
import { Button, DataTable, InlineMessage, PageHeader, Panel, SelectField, TextInput, teamColors } from "./TeamUi.jsx";

export default function TeamsList({
  teams,
  loading,
  error,
  canCreate = true,
  canEdit = true,
  canToggleActive = true,
  query,
  statusFilter,
  onQueryChange,
  onStatusFilterChange,
  onCreate,
  onOpen,
  onEdit,
  onToggleActive,
}) {
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <PageHeader
        title="Equipos suscriptores"
        subtitle="Gestión administrativa de equipos, miembros, destinatarios, suscripciones y sistemas."
        actions={canCreate ? <Button primary onClick={onCreate}>Crear equipo</Button> : null}
      />

      <Panel title="Listado" subtitle="Sin paginación artificial: el backend actual devuelve la colección completa.">
        <div style={{ display: "grid", gap: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(220px, 1fr) 220px", gap: 12 }}>
            <TextInput label="Buscar por nombre o código" value={query} onChange={onQueryChange} placeholder="IT España, it-es..." />
            <SelectField label="Estado" value={statusFilter} onChange={onStatusFilterChange} options={ACTIVE_FILTER_OPTIONS} />
          </div>

          {error && <InlineMessage type="error">{error}</InlineMessage>}

          <DataTable
            columns={[
              { key: "name", label: "Equipo" },
              { key: "status", label: "Estado" },
              { key: "members", label: "Miembros" },
              { key: "recipients", label: "Destinatarios" },
              { key: "subscriptions", label: "Suscripciones" },
              { key: "systems", label: "Sistemas" },
              { key: "updatedAt", label: "Actualizado" },
              { key: "actions", label: "Acciones" },
            ]}
            rows={teams}
            rowKey="id"
            loading={loading}
            empty={(
              <EmptyState
                title="No hay equipos"
                description={query || statusFilter !== "all"
                  ? "No hay resultados para los filtros actuales."
                  : "Crea el primer equipo suscriptor para empezar a gestionar miembros y destinatarios."
                }
                action={canCreate && !query && statusFilter === "all" ? <Button primary onClick={onCreate}>Crear equipo</Button> : null}
              />
            )}
            renderRow={(team) => (
              <tr key={team.id} style={{ borderTop: `1px solid ${teamColors.gray100}` }}>
                <td style={{ padding: "12px" }}>
                  <div style={{ fontSize: 12, fontWeight: 800, color: teamColors.text }}>{team.name}</div>
                  <div style={{ marginTop: 4, fontSize: 11, color: teamColors.gray500 }}>{team.code}{team.description ? ` · ${team.description}` : ""}</div>
                </td>
                <td style={{ padding: "12px" }}><TeamStatusBadge isActive={team.isActive} /></td>
                <td style={{ padding: "12px", fontSize: 12 }}>{team.stats.members}</td>
                <td style={{ padding: "12px", fontSize: 12 }}>{team.stats.recipients}</td>
                <td style={{ padding: "12px", fontSize: 12 }}>{team.stats.subscriptions}</td>
                <td style={{ padding: "12px", fontSize: 12 }}>{team.stats.systems}</td>
                <td style={{ padding: "12px", fontSize: 11, color: teamColors.gray500 }}>{formatDateTime(team.updatedAt)}</td>
                <td style={{ padding: "12px" }}>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <Button small primary onClick={() => onOpen(team)}>Abrir</Button>
                    {canEdit && <Button small onClick={() => onEdit(team)}>Editar</Button>}
                    {canToggleActive && (
                      <Button small danger={!team.isActive} onClick={() => onToggleActive(team)}>
                        {team.isActive !== false ? "Desactivar" : "Activar"}
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            )}
          />
        </div>
      </Panel>
    </div>
  );
}
