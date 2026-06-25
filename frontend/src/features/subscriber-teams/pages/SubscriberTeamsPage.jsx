import { useEffect, useMemo, useState } from "react";

import { createSubscriberTeamsApi } from "../api/subscriberTeamsApi.js";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import TeamForm from "../components/TeamForm.jsx";
import TeamsList from "../components/TeamsList.jsx";
import {
  createDefaultTeamForm,
} from "../utils/teamForms.js";
import {
  attachTeamStats,
  filterAndSortTeams,
  summarizeTeamWorkspace,
  toErrorMessage,
} from "../utils/teamViewModel.js";
import {
  canAccessSubscriberTeamsAdmin,
} from "../utils/teamPermissions.js";

const buildEditableTeam = (team) => ({
  id: team.id,
  name: team.name || "",
  code: team.code || "",
  description: team.description || "",
  isActive: team.isActive !== false,
});

export default function SubscriberTeamsPage({
  apiFetch,
  currentUser,
  onOpenTeam,
}) {
  const api = useMemo(() => createSubscriberTeamsApi(apiFetch), [apiFetch]);
  const isAdmin = canAccessSubscriberTeamsAdmin(currentUser?.role);
  const [teams, setTeams] = useState([]);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [teamFormOpen, setTeamFormOpen] = useState(false);
  const [teamFormValue, setTeamFormValue] = useState(createDefaultTeamForm());
  const [confirmState, setConfirmState] = useState({ open: false, team: null });

  const loadTeams = async () => {
    setLoading(true);
    setError("");
    try {
      const baseTeams = isAdmin ? await api.listTeams() : await api.listMyTeams();
      const statsEntries = await Promise.all(
        (baseTeams || []).map(async (team) => {
          const [members, recipients, subscriptions, systems] = await Promise.all([
            isAdmin ? api.listMembers(team.id) : api.listPortalMembers(team.id),
            isAdmin ? api.listRecipients(team.id) : api.listPortalRecipients(team.id),
            isAdmin ? api.listSubscriptions(team.id) : api.listPortalSubscriptions(team.id),
            isAdmin ? api.listSystems(team.id) : api.listPortalSystems(team.id),
          ]);
          return [team.id, summarizeTeamWorkspace({ members, recipients, subscriptions, systems })];
        }),
      );
      setTeams(attachTeamStats(baseTeams || [], Object.fromEntries(statsEntries)));
    } catch (requestError) {
      setTeams([]);
      setError(toErrorMessage(requestError, "No se pudo cargar el listado de equipos."));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTeams();
  }, []);

  const filteredTeams = useMemo(
    () => filterAndSortTeams(teams, { query, status: statusFilter }),
    [query, statusFilter, teams],
  );

  const handleCreate = () => {
    setTeamFormValue(createDefaultTeamForm());
    setTeamFormOpen(true);
  };

  const handleEdit = (team) => {
    setTeamFormValue(buildEditableTeam(team));
    setTeamFormOpen(true);
  };

  const handleSubmitTeam = async (payload) => {
    setSaving(true);
    setError("");
    try {
      const saved = teamFormValue.id
        ? await api.updateTeam(teamFormValue.id, payload)
        : await api.createTeam(payload);
      setTeamFormOpen(false);
      await loadTeams();
      onOpenTeam(saved.id);
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo guardar el equipo."));
    } finally {
      setSaving(false);
    }
  };

  const handleToggleActive = async () => {
    if (!confirmState.team) return;
    setSaving(true);
    setError("");
    try {
      await api.updateTeam(confirmState.team.id, { isActive: confirmState.team.isActive === false });
      setConfirmState({ open: false, team: null });
      await loadTeams();
    } catch (requestError) {
      setError(toErrorMessage(requestError, "No se pudo cambiar el estado del equipo."));
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <TeamsList
        teams={filteredTeams}
        loading={loading}
        error={error}
        canCreate={isAdmin}
        canEdit={isAdmin}
        canToggleActive={isAdmin}
        query={query}
        statusFilter={statusFilter}
        onQueryChange={setQuery}
        onStatusFilterChange={setStatusFilter}
        onCreate={handleCreate}
        onOpen={(team) => onOpenTeam(team.id)}
        onEdit={handleEdit}
        onToggleActive={(team) => setConfirmState({ open: true, team })}
      />

      <TeamForm
        open={teamFormOpen}
        initialValue={teamFormValue}
        loading={saving}
        onClose={() => setTeamFormOpen(false)}
        onChange={setTeamFormValue}
        onSubmit={handleSubmitTeam}
        submitLabel={teamFormValue.id ? "Guardar cambios" : "Crear equipo"}
      />

      <ConfirmDialog
        open={confirmState.open}
        title={confirmState.team?.isActive === false ? "Activar equipo" : "Desactivar equipo"}
        description={confirmState.team?.isActive === false
          ? `Se volverá a habilitar ${confirmState.team?.name} para su uso.`
          : `Se desactivará ${confirmState.team?.name}. Los miembros del portal dejarán de operar sobre este equipo.`
        }
        confirmLabel={confirmState.team?.isActive === false ? "Activar" : "Desactivar"}
        danger={confirmState.team?.isActive !== false}
        loading={saving}
        onConfirm={handleToggleActive}
        onClose={() => setConfirmState({ open: false, team: null })}
      />
    </>
  );
}
