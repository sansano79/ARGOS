import { useEffect, useMemo, useState } from "react";

import { createSubscriberTeamsApi } from "../api/subscriberTeamsApi.js";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import MemberForm from "../components/MemberForm.jsx";
import RecipientForm from "../components/RecipientForm.jsx";
import SubscriptionForm from "../components/SubscriptionForm.jsx";
import SystemForm from "../components/SystemForm.jsx";
import TeamForm from "../components/TeamForm.jsx";
import TeamMembersPanel from "../components/TeamMembersPanel.jsx";
import TeamRecipientsPanel from "../components/TeamRecipientsPanel.jsx";
import TeamSubscriptionsPanel from "../components/TeamSubscriptionsPanel.jsx";
import TeamSummary from "../components/TeamSummary.jsx";
import TeamSystemsPanel from "../components/TeamSystemsPanel.jsx";
import {
  Button,
  InlineMessage,
  PageHeader,
  Tabs,
} from "../components/TeamUi.jsx";
import {
  createDefaultMemberForm,
  createDefaultRecipientForm,
  createDefaultSubscriptionForm,
  createDefaultSystemForm,
  createDefaultTeamForm,
  joinCsvList,
} from "../utils/teamForms.js";
import {
  canAccessSubscriberTeamsAdmin,
} from "../utils/teamPermissions.js";
import {
  buildUserSelectOptions,
  parseJsonStringArray,
  summarizeTeamWorkspace,
  toErrorMessage,
} from "../utils/teamViewModel.js";

const TABS = [
  { id: "summary", label: "Resumen" },
  { id: "members", label: "Miembros" },
  { id: "recipients", label: "Destinatarios" },
  { id: "subscriptions", label: "Suscripciones" },
  { id: "systems", label: "Sistemas / unidades" },
];

const normalizeSubscription = (item) => ({
  ...item,
  versions: parseJsonStringArray(item?.versions),
});

const buildEditableTeam = (team) => ({
  id: team.id,
  name: team.name || "",
  code: team.code || "",
  description: team.description || "",
  isActive: team.isActive !== false,
});

const buildEditableMember = (member) => ({
  id: member.id,
  userId: String(member.user?.id || ""),
  role: member.role || "TEAM_MANAGER",
  isActive: member.isActive !== false,
});

const buildEditableRecipient = (recipient) => ({
  id: recipient.id,
  email: recipient.email || "",
  name: recipient.name || "",
  type: recipient.type || "MAILBOX",
  language: recipient.language || "es",
  timezone: recipient.timezone || "Europe/Madrid",
  isActive: recipient.isActive !== false,
});

const buildEditableSubscription = (subscription) => ({
  id: subscription.id,
  vendor: subscription.vendor || "",
  product: subscription.product || "",
  versionsText: joinCsvList(parseJsonStringArray(subscription.versions)),
  isActive: subscription.isActive !== false,
});

const buildEditableSystem = (system) => ({
  id: system.id,
  name: system.name || "",
  externalId: system.externalId || "",
  source: system.source || "manual",
  hostname: system.hostname || "",
  fqdn: system.fqdn || "",
  platform: system.platform || "",
  osVersion: system.osVersion || "",
  description: system.description || "",
  riskLevel: system.riskLevel || "",
  healthStatus: system.healthStatus || "",
  tags: joinCsvList(parseJsonStringArray(system.tags)),
  isSelected: system.isSelected !== false,
  isActive: system.isActive !== false,
});

export default function SubscriberTeamDetailPage({
  apiFetch,
  currentUser,
  teamId,
  onBack,
}) {
  const api = useMemo(() => createSubscriberTeamsApi(apiFetch), [apiFetch]);
  const [activeTab, setActiveTab] = useState("summary");
  const [workspace, setWorkspace] = useState({
    team: null,
    members: [],
    recipients: [],
    subscriptions: [],
    systems: [],
    users: [],
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [teamFormOpen, setTeamFormOpen] = useState(false);
  const [teamFormValue, setTeamFormValue] = useState(createDefaultTeamForm());
  const [memberFormOpen, setMemberFormOpen] = useState(false);
  const [memberFormValue, setMemberFormValue] = useState(createDefaultMemberForm());
  const [recipientFormOpen, setRecipientFormOpen] = useState(false);
  const [recipientFormValue, setRecipientFormValue] = useState(createDefaultRecipientForm());
  const [subscriptionFormOpen, setSubscriptionFormOpen] = useState(false);
  const [subscriptionFormValue, setSubscriptionFormValue] = useState(createDefaultSubscriptionForm());
  const [systemFormOpen, setSystemFormOpen] = useState(false);
  const [systemFormValue, setSystemFormValue] = useState(createDefaultSystemForm());
  const [confirmState, setConfirmState] = useState({ open: false, type: "", item: null });

  const isAdmin = canAccessSubscriberTeamsAdmin(currentUser?.role);

  const loadWorkspace = async () => {
    setLoading(true);
    setError("");
    try {
      const [team, members, recipients, subscriptions, systems, users] = await Promise.all([
        api.getTeam(teamId),
        api.listMembers(teamId),
        api.listRecipients(teamId),
        api.listSubscriptions(teamId),
        api.listSystems(teamId),
        api.listUsers(),
      ]);

      setWorkspace({
        team,
        members,
        recipients,
        subscriptions: (subscriptions || []).map(normalizeSubscription),
        systems,
        users,
      });
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo cargar el detalle del equipo."));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadWorkspace();
  }, [teamId]);

  const counts = useMemo(
    () => summarizeTeamWorkspace(workspace),
    [workspace],
  );

  const userOptions = useMemo(
    () => buildUserSelectOptions(workspace.users, workspace.members),
    [workspace.members, workspace.users],
  );

  const setSuccess = (next) => {
    setMessage(next);
    setError("");
  };

  const handleTeamSubmit = async (payload) => {
    setSaving(true);
    try {
      await api.updateTeam(teamId, payload);
      setTeamFormOpen(false);
      setSuccess("Equipo actualizado.");
      await loadWorkspace();
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo guardar el equipo."));
    } finally {
      setSaving(false);
    }
  };

  const handleMemberSubmit = async (payload) => {
    setSaving(true);
    try {
      if (memberFormValue.id) {
        await api.updateMember(teamId, memberFormValue.id, {
          role: payload.role,
          isActive: memberFormValue.isActive !== false,
        });
      } else {
        await api.addMember(teamId, payload);
      }
      setMemberFormOpen(false);
      setSuccess("Miembro guardado.");
      await loadWorkspace();
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo guardar el miembro."));
    } finally {
      setSaving(false);
    }
  };

  const handleRecipientSubmit = async (payload) => {
    setSaving(true);
    try {
      if (recipientFormValue.id) {
        await api.updateRecipient(teamId, recipientFormValue.id, payload);
      } else {
        await api.createRecipient(teamId, payload);
      }
      setRecipientFormOpen(false);
      setSuccess("Destinatario guardado.");
      await loadWorkspace();
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo guardar el destinatario."));
    } finally {
      setSaving(false);
    }
  };

  const handleSubscriptionSubmit = async (payload) => {
    setSaving(true);
    try {
      if (subscriptionFormValue.id) {
        await api.updateSubscription(teamId, subscriptionFormValue.id, payload);
      } else {
        await api.createSubscription(teamId, payload);
      }
      setSubscriptionFormOpen(false);
      setSuccess("Suscripción guardada.");
      await loadWorkspace();
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo guardar la suscripción."));
    } finally {
      setSaving(false);
    }
  };

  const handleSystemSubmit = async (payload) => {
    setSaving(true);
    try {
      if (systemFormValue.id) {
        await api.updateSystem(teamId, systemFormValue.id, payload);
      } else {
        await api.createSystem(teamId, payload);
      }
      setSystemFormOpen(false);
      setSuccess("Sistema guardado.");
      await loadWorkspace();
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo guardar el sistema."));
    } finally {
      setSaving(false);
    }
  };

  const handleConfirm = async () => {
    if (!confirmState.item) return;
    setSaving(true);
    try {
      if (confirmState.type === "team-status") {
        await api.updateTeam(teamId, { isActive: workspace.team?.isActive === false });
        setSuccess("Estado del equipo actualizado.");
      } else if (confirmState.type === "member") {
        await api.removeMember(teamId, confirmState.item.id);
        setSuccess("Miembro retirado.");
      } else if (confirmState.type === "recipient") {
        await api.removeRecipient(teamId, confirmState.item.id);
        setSuccess("Destinatario eliminado.");
      } else if (confirmState.type === "subscription") {
        await api.removeSubscription(teamId, confirmState.item.id);
        setSuccess("Suscripción eliminada.");
      } else if (confirmState.type === "system") {
        await api.removeSystem(teamId, confirmState.item.id);
        setSuccess("Sistema eliminado.");
      }
      setConfirmState({ open: false, type: "", item: null });
      await loadWorkspace();
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo completar la operación."));
    } finally {
      setSaving(false);
    }
  };

  const confirmCopy = (() => {
    if (confirmState.type === "team-status") {
      return workspace.team?.isActive === false
        ? { title: "Activar equipo", description: `Se volverá a activar ${workspace.team?.name}.`, confirmLabel: "Activar", danger: false }
        : { title: "Desactivar equipo", description: `Se desactivará ${workspace.team?.name} y dejará de estar disponible para el portal.`, confirmLabel: "Desactivar", danger: true };
    }
    if (confirmState.type === "member") return { title: "Retirar miembro", description: "Esta acción elimina la membresía del equipo.", confirmLabel: "Retirar", danger: true };
    if (confirmState.type === "recipient") return { title: "Eliminar destinatario", description: "Esta acción elimina el destinatario del equipo.", confirmLabel: "Eliminar", danger: true };
    if (confirmState.type === "subscription") return { title: "Eliminar suscripción", description: "Esta acción elimina la suscripción del equipo.", confirmLabel: "Eliminar", danger: true };
    if (confirmState.type === "system") return { title: "Eliminar sistema", description: "Esta acción elimina el sistema del equipo.", confirmLabel: "Eliminar", danger: true };
    return { title: "", description: "", confirmLabel: "Confirmar", danger: false };
  })();

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <PageHeader
        title={workspace.team?.name || "Detalle del equipo"}
        subtitle={workspace.team ? `Código: ${workspace.team.code}` : "Cargando detalle del equipo..."}
        actions={<Button onClick={onBack}>Volver al listado</Button>}
      />

      {message && <InlineMessage type="success">{message}</InlineMessage>}
      {error && <InlineMessage type="error">{error}</InlineMessage>}
      {!isAdmin && <InlineMessage type="error">No existe acceso a miembros ni administración de equipos para usuarios no ADMIN.</InlineMessage>}

      <Tabs items={TABS} activeId={activeTab} onChange={setActiveTab} />

      {activeTab === "summary" && workspace.team && (
        <TeamSummary
          team={workspace.team}
          counts={counts}
          onEdit={() => {
            setTeamFormValue(buildEditableTeam(workspace.team));
            setTeamFormOpen(true);
          }}
          onToggleActive={() => setConfirmState({ open: true, type: "team-status", item: workspace.team })}
        />
      )}

      {activeTab === "members" && (
        <TeamMembersPanel
          members={workspace.members}
          loading={loading}
          error=""
          canManage={isAdmin}
          onAdd={() => {
            setMemberFormValue(createDefaultMemberForm());
            setMemberFormOpen(true);
          }}
          onEdit={(member) => {
            setMemberFormValue(buildEditableMember(member));
            setMemberFormOpen(true);
          }}
          onRemove={(member) => setConfirmState({ open: true, type: "member", item: member })}
        />
      )}

      {activeTab === "recipients" && (
        <TeamRecipientsPanel
          recipients={workspace.recipients}
          loading={loading}
          error=""
          canManage={isAdmin}
          onAdd={() => {
            setRecipientFormValue(createDefaultRecipientForm());
            setRecipientFormOpen(true);
          }}
          onEdit={(recipient) => {
            setRecipientFormValue(buildEditableRecipient(recipient));
            setRecipientFormOpen(true);
          }}
          onRemove={(recipient) => setConfirmState({ open: true, type: "recipient", item: recipient })}
        />
      )}

      {activeTab === "subscriptions" && (
        <TeamSubscriptionsPanel
          subscriptions={workspace.subscriptions}
          loading={loading}
          error=""
          canManage={isAdmin}
          onAdd={() => {
            setSubscriptionFormValue(createDefaultSubscriptionForm());
            setSubscriptionFormOpen(true);
          }}
          onEdit={(subscription) => {
            setSubscriptionFormValue(buildEditableSubscription(subscription));
            setSubscriptionFormOpen(true);
          }}
          onRemove={(subscription) => setConfirmState({ open: true, type: "subscription", item: subscription })}
        />
      )}

      {activeTab === "systems" && (
        <TeamSystemsPanel
          systems={workspace.systems}
          loading={loading}
          error=""
          canManage={isAdmin}
          onAdd={() => {
            setSystemFormValue(createDefaultSystemForm());
            setSystemFormOpen(true);
          }}
          onEdit={(system) => {
            setSystemFormValue(buildEditableSystem(system));
            setSystemFormOpen(true);
          }}
          onRemove={(system) => setConfirmState({ open: true, type: "system", item: system })}
        />
      )}

      <TeamForm
        open={teamFormOpen}
        initialValue={teamFormValue}
        loading={saving}
        onClose={() => setTeamFormOpen(false)}
        onChange={setTeamFormValue}
        onSubmit={handleTeamSubmit}
        submitLabel="Guardar cambios"
      />

      <MemberForm
        open={memberFormOpen}
        initialValue={memberFormValue}
        userOptions={userOptions}
        loading={saving}
        onClose={() => setMemberFormOpen(false)}
        onChange={setMemberFormValue}
        onSubmit={handleMemberSubmit}
      />

      <RecipientForm
        open={recipientFormOpen}
        initialValue={recipientFormValue}
        loading={saving}
        onClose={() => setRecipientFormOpen(false)}
        onChange={setRecipientFormValue}
        onSubmit={handleRecipientSubmit}
      />

      <SubscriptionForm
        open={subscriptionFormOpen}
        initialValue={subscriptionFormValue}
        loading={saving}
        onClose={() => setSubscriptionFormOpen(false)}
        onChange={setSubscriptionFormValue}
        onSubmit={handleSubscriptionSubmit}
      />

      <SystemForm
        open={systemFormOpen}
        initialValue={systemFormValue}
        loading={saving}
        onClose={() => setSystemFormOpen(false)}
        onChange={setSystemFormValue}
        onSubmit={handleSystemSubmit}
      />

      <ConfirmDialog
        open={confirmState.open}
        title={confirmCopy.title}
        description={confirmCopy.description}
        confirmLabel={confirmCopy.confirmLabel}
        danger={confirmCopy.danger}
        loading={saving}
        onConfirm={handleConfirm}
        onClose={() => setConfirmState({ open: false, type: "", item: null })}
      />
    </div>
  );
}
