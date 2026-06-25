import { getRecipientTypeLabel } from "../utils/teamViewModel.js";
import EmptyState from "./EmptyState.jsx";
import TeamStatusBadge from "./TeamStatusBadge.jsx";
import { Button, DataTable, InlineMessage, Panel, teamColors } from "./TeamUi.jsx";

export default function TeamRecipientsPanel({ recipients, loading, error, canManage, onAdd, onEdit, onRemove }) {
  return (
    <Panel
      title="Destinatarios"
      subtitle="Un destinatario puede recibir notificaciones sin tener acceso a la aplicación."
      action={canManage ? <Button primary onClick={onAdd}>Añadir destinatario</Button> : null}
    >
      <div style={{ display: "grid", gap: 12 }}>
        <InlineMessage type="info">La integración de estos destinatarios con el motor de notificaciones se habilitará en una fase posterior.</InlineMessage>
        {error && <InlineMessage type="error">{error}</InlineMessage>}
        <DataTable
          columns={[
            { key: "name", label: "Nombre" },
            { key: "email", label: "Email" },
            { key: "type", label: "Tipo" },
            { key: "language", label: "Idioma" },
            { key: "timezone", label: "Zona horaria" },
            { key: "verified", label: "Verificación" },
            { key: "status", label: "Estado" },
            { key: "actions", label: "Acciones" },
          ]}
          rows={recipients}
          rowKey="id"
          loading={loading}
          empty={<EmptyState title="Sin destinatarios" description="Añade un buzón o lista de distribución para separar acceso y recepción de alertas." action={canManage ? <Button primary onClick={onAdd}>Añadir destinatario</Button> : null} />}
          renderRow={(recipient) => (
            <tr key={recipient.id} style={{ borderTop: `1px solid ${teamColors.gray100}` }}>
              <td style={{ padding: "12px", fontSize: 12, fontWeight: 700 }}>{recipient.name || "Sin nombre"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{recipient.email}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{getRecipientTypeLabel(recipient.type)}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{recipient.language || "es"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{recipient.timezone || "Europe/Madrid"}</td>
              <td style={{ padding: "12px", fontSize: 11 }}>{recipient.verifiedAt ? "Verificado" : "No verificado"}</td>
              <td style={{ padding: "12px" }}><TeamStatusBadge isActive={recipient.isActive} /></td>
              <td style={{ padding: "12px" }}>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {canManage && <Button small onClick={() => onEdit(recipient)}>Editar</Button>}
                  {canManage && <Button small danger onClick={() => onRemove(recipient)}>Eliminar</Button>}
                </div>
              </td>
            </tr>
          )}
        />
      </div>
    </Panel>
  );
}

