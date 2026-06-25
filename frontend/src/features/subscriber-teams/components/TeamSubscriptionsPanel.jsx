import EmptyState from "./EmptyState.jsx";
import TeamStatusBadge from "./TeamStatusBadge.jsx";
import { Button, DataTable, InlineMessage, Panel, teamColors } from "./TeamUi.jsx";

export default function TeamSubscriptionsPanel({ subscriptions, loading, error, canManage, onAdd, onEdit, onRemove }) {
  return (
    <Panel
      title="Suscripciones"
      subtitle="Gestión visual del catálogo de fabricante, producto y versiones del equipo."
      action={canManage ? <Button primary onClick={onAdd}>Añadir suscripción</Button> : null}
    >
      <div style={{ display: "grid", gap: 12 }}>
        <InlineMessage type="info">Las suscripciones de equipo todavía no sustituyen las suscripciones legacy en el motor de notificaciones.</InlineMessage>
        {error && <InlineMessage type="error">{error}</InlineMessage>}
        <DataTable
          columns={[
            { key: "vendor", label: "Fabricante" },
            { key: "product", label: "Producto" },
            { key: "versions", label: "Versiones" },
            { key: "status", label: "Estado" },
            { key: "actions", label: "Acciones" },
          ]}
          rows={subscriptions}
          rowKey="id"
          loading={loading}
          empty={<EmptyState title="Sin suscripciones" description="Añade las combinaciones vendor/product que debe vigilar el equipo." action={canManage ? <Button primary onClick={onAdd}>Añadir suscripción</Button> : null} />}
          renderRow={(subscription) => (
            <tr key={subscription.id} style={{ borderTop: `1px solid ${teamColors.gray100}` }}>
              <td style={{ padding: "12px", fontSize: 12, fontWeight: 700 }}>{subscription.vendor}</td>
              <td style={{ padding: "12px", fontSize: 12 }}>{subscription.product}</td>
              <td style={{ padding: "12px", fontSize: 11, color: teamColors.gray500 }}>
                {Array.isArray(subscription.versions) && subscription.versions.length > 0 ? subscription.versions.join(", ") : "Todas"}
              </td>
              <td style={{ padding: "12px" }}><TeamStatusBadge isActive={subscription.isActive} /></td>
              <td style={{ padding: "12px" }}>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {canManage && <Button small onClick={() => onEdit(subscription)}>Editar</Button>}
                  {canManage && <Button small danger onClick={() => onRemove(subscription)}>Eliminar</Button>}
                </div>
              </td>
            </tr>
          )}
        />
      </div>
    </Panel>
  );
}

