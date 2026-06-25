export const VULN_LIST_PATH = "/vulnerabilities";
export const KEV_LIST_PATH = "/kev";
export const ACCOUNT_PATH = "/account";
export const PORTAL_PATH = "/portal";
export const SUBSCRIBER_TEAMS_PATH = "/admin/subscriber-teams";
export const DETAIL_VIEW = "vuln-detail";

export const normalizeDetailSourceView = (value) => value === "exploited" ? "exploited" : "vulns";

export const getListPathForView = (value) => {
  switch (value) {
    case "exploited":
      return KEV_LIST_PATH;
    case "account":
      return ACCOUNT_PATH;
    case "portal":
      return PORTAL_PATH;
    default:
      return VULN_LIST_PATH;
  }
};

export const getDetailPathForView = (value, cveId) =>
  `${getListPathForView(normalizeDetailSourceView(value))}/${encodeURIComponent(String(cveId || "").trim().toUpperCase())}`;

export const getSubscriberTeamDetailPath = (teamId) =>
  `${SUBSCRIBER_TEAMS_PATH}/${encodeURIComponent(String(teamId || "").trim())}`;

export const parseAppRoute = (pathname) => {
  const currentPath = String(pathname || "").trim() || "/";
  if (/^\/reset-password\/[^/]+$/.test(currentPath)) return null;

  const kevDetail = currentPath.match(/^\/kev\/([^/]+)$/);
  if (kevDetail?.[1]) {
    return {
      view: DETAIL_VIEW,
      sourceView: "exploited",
      cveId: decodeURIComponent(kevDetail[1]).trim().toUpperCase(),
    };
  }

  const vulnDetail = currentPath.match(/^\/vulnerabilities\/([^/]+)$/);
  if (vulnDetail?.[1]) {
    return {
      view: DETAIL_VIEW,
      sourceView: "vulns",
      cveId: decodeURIComponent(vulnDetail[1]).trim().toUpperCase(),
    };
  }

  if (currentPath === KEV_LIST_PATH) return { view: "exploited" };
  if (currentPath === VULN_LIST_PATH) return { view: "vulns" };
  if (currentPath === ACCOUNT_PATH) return { view: "account" };
  if (currentPath === PORTAL_PATH) return { view: "portal" };
  if (currentPath === SUBSCRIBER_TEAMS_PATH) return { view: "subscriber-teams", teamId: null };

  const subscriberTeamsDetail = currentPath.match(/^\/admin\/subscriber-teams\/([^/]+)$/);
  if (subscriberTeamsDetail?.[1]) {
    const teamId = Number(decodeURIComponent(subscriberTeamsDetail[1]));
    return {
      view: "subscriber-teams",
      teamId: Number.isInteger(teamId) && teamId > 0 ? teamId : null,
    };
  }
  return null;
};

export const isViewAllowedForRole = (role, view) => {
  const normalizedRole = String(role || "").toUpperCase();
  const normalizedView = String(view || "");

  if (normalizedRole === "ADMIN") return true;
  if (normalizedRole === "TEAM_MANAGER") {
    return ["vulns", "exploited", "account", "subscriber-teams", DETAIL_VIEW].includes(normalizedView);
  }
  if (normalizedView === "subscriber-teams") return false;
  if (normalizedRole === "SUBSCRIBER") {
    return ["vulns", "exploited", "portal", "account", DETAIL_VIEW].includes(normalizedView);
  }
  if (normalizedRole === "VIEWER") {
    return ["vulns", "exploited", "account", DETAIL_VIEW].includes(normalizedView);
  }
  return true;
};
