const parsePayload = async (response) => {
  const raw = await response.text();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
};

export const errorMessageFromPayload = (payload, statusCode) => {
  if (payload && typeof payload === "object") {
    if (Array.isArray(payload.message)) return payload.message.join(". ");
    if (payload.message) return String(payload.message);
    if (payload.error) return String(payload.error);
  }
  if (typeof payload === "string" && payload.trim()) return payload;
  if (statusCode === 401) return "Sesión caducada.";
  if (statusCode === 403) return "Sin permisos para esta operación.";
  if (statusCode === 404) return "Recurso no encontrado.";
  if (statusCode >= 500) return "Error interno del servidor.";
  return "No se pudo completar la operación.";
};

export const createDefenderApi = (request) => {
  const requestJson = async (path, options = {}) => {
    let response;
    try {
      response = await request(path, options);
    } catch (error) {
      const wrapped = new Error(String(error?.message || "").includes("Unauthorized") ? "Sesión caducada." : "Servicio no disponible.");
      wrapped.statusCode = 0;
      throw wrapped;
    }
    const payload = await parsePayload(response);
    if (!response.ok) {
      const error = new Error(errorMessageFromPayload(payload, response.status));
      error.statusCode = response.status;
      throw error;
    }
    return payload;
  };

  const query = (params) => {
    const qs = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
    });
    const s = qs.toString();
    return s ? `?${s}` : "";
  };

  return {
    getConfig: () => requestJson("/defender/config"),
    saveConfig: (payload) => requestJson("/defender/config", { method: "PUT", body: JSON.stringify(payload) }),
    testConfig: () => requestJson("/defender/config/test", { method: "POST" }),
    requestSync: (mode) => requestJson("/defender/sync", { method: "POST", body: JSON.stringify({ mode }) }),
    listRuns: (limit = 20) => requestJson(`/defender/sync/runs${query({ limit })}`),
    listDevices: (params) => requestJson(`/defender/devices${query(params)}`),
    listFindings: (deviceId, params) => requestJson(`/defender/devices/${encodeURIComponent(deviceId)}/findings${query(params)}`),
    listTeams: () => requestJson("/subscriber-teams"),
  };
};
