const parsePayload = async (response) => {
  const raw = await response.text();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
};

const getMessageFromPayload = (payload) => {
  if (!payload) return "";
  if (typeof payload === "string") return payload;
  if (Array.isArray(payload?.message)) return payload.message.join(". ");
  return payload?.message || payload?.error || "";
};

const buildApiError = (response, payload) => {
  const statusCode = Number(response?.status || 0);
  const fallback = (
    statusCode === 400 ? "Revisa los campos enviados."
      : statusCode === 401 ? "Sesión caducada."
        : statusCode === 403 ? "Sin permisos para esta operación."
          : statusCode === 404 ? "Recurso no encontrado."
            : statusCode === 409 ? "El recurso ya existe."
              : statusCode >= 500 ? "Error interno del servidor."
                : "No se pudo completar la operación."
  );
  const error = new Error(getMessageFromPayload(payload) || fallback);
  error.statusCode = statusCode;
  error.payload = payload;
  return error;
};

export const createSubscriberTeamsApi = (request) => {
  const requestJson = async (path, options = {}) => {
    let response;
    try {
      response = await request(path, options);
    } catch (error) {
      if (String(error?.message || "").includes("Unauthorized")) {
        const unauthorized = new Error("Sesión caducada.");
        unauthorized.statusCode = 401;
        throw unauthorized;
      }
      const networkError = new Error("Servicio no disponible.");
      networkError.statusCode = 0;
      throw networkError;
    }

    const payload = await parsePayload(response);
    if (!response.ok) throw buildApiError(response, payload);
    return payload;
  };

  return {
    listUsers: () => requestJson("/users"),
    listTeams: () => requestJson("/subscriber-teams"),
    createTeam: (payload) => requestJson("/subscriber-teams", { method: "POST", body: JSON.stringify(payload) }),
    getTeam: (teamId) => requestJson(`/subscriber-teams/${teamId}`),
    updateTeam: (teamId, payload) => requestJson(`/subscriber-teams/${teamId}`, { method: "PATCH", body: JSON.stringify(payload) }),
    listMembers: (teamId) => requestJson(`/subscriber-teams/${teamId}/members`),
    addMember: (teamId, payload) => requestJson(`/subscriber-teams/${teamId}/members`, { method: "POST", body: JSON.stringify(payload) }),
    updateMember: (teamId, memberId, payload) => requestJson(`/subscriber-teams/${teamId}/members/${memberId}`, { method: "PATCH", body: JSON.stringify(payload) }),
    removeMember: (teamId, memberId) => requestJson(`/subscriber-teams/${teamId}/members/${memberId}`, { method: "DELETE" }),
    listRecipients: (teamId) => requestJson(`/subscriber-teams/${teamId}/recipients`),
    createRecipient: (teamId, payload) => requestJson(`/subscriber-teams/${teamId}/recipients`, { method: "POST", body: JSON.stringify(payload) }),
    updateRecipient: (teamId, recipientId, payload) => requestJson(`/subscriber-teams/${teamId}/recipients/${recipientId}`, { method: "PATCH", body: JSON.stringify(payload) }),
    removeRecipient: (teamId, recipientId) => requestJson(`/subscriber-teams/${teamId}/recipients/${recipientId}`, { method: "DELETE" }),
    listSubscriptions: (teamId) => requestJson(`/subscriber-teams/${teamId}/subscriptions`),
    createSubscription: (teamId, payload) => requestJson(`/subscriber-teams/${teamId}/subscriptions`, { method: "POST", body: JSON.stringify(payload) }),
    updateSubscription: (teamId, subscriptionId, payload) => requestJson(`/subscriber-teams/${teamId}/subscriptions/${subscriptionId}`, { method: "PATCH", body: JSON.stringify(payload) }),
    removeSubscription: (teamId, subscriptionId) => requestJson(`/subscriber-teams/${teamId}/subscriptions/${subscriptionId}`, { method: "DELETE" }),
    listSystems: (teamId) => requestJson(`/subscriber-teams/${teamId}/systems`),
    createSystem: (teamId, payload) => requestJson(`/subscriber-teams/${teamId}/systems`, { method: "POST", body: JSON.stringify(payload) }),
    updateSystem: (teamId, systemId, payload) => requestJson(`/subscriber-teams/${teamId}/systems/${systemId}`, { method: "PATCH", body: JSON.stringify(payload) }),
    removeSystem: (teamId, systemId) => requestJson(`/subscriber-teams/${teamId}/systems/${systemId}`, { method: "DELETE" }),
  };
};

