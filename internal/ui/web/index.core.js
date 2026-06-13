const el = {
  langBtn: document.getElementById("langBtn"),
  refreshBtn: document.getElementById("refreshBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  form: document.getElementById("siteForm"),
  formTitle: document.getElementById("formTitle"),
  clearBtn: document.getElementById("clearBtn"),
  cancelEditBtn: document.getElementById("cancelEditBtn"),
  submitBtn: document.getElementById("submitBtn"),
  errorBox: document.getElementById("errorBox"),
  successBox: document.getElementById("successBox"),
  certForm: document.getElementById("certForm"),
  certType: document.getElementById("certType"),
  acmeFields: document.getElementById("acmeFields"),
  selfSignedFields: document.getElementById("selfSignedFields"),
  certName: document.getElementById("certName"),
  certDomains: document.getElementById("certDomains"),
  acmeEmail: document.getElementById("acmeEmail"),
  acmeProvider: document.getElementById("acmeProvider"),
  acmeChallenge: document.getElementById("acmeChallenge"),
  acmeKeyType: document.getElementById("acmeKeyType"),
  acmeRenewBeforeDays: document.getElementById("acmeRenewBeforeDays"),
  acmeAutoIssue: document.getElementById("acmeAutoIssue"),
  acmeDirectoryURL: document.getElementById("acmeDirectoryURL"),
  acmePreferredChain: document.getElementById("acmePreferredChain"),
  dnsProviderName: document.getElementById("dnsProviderName"),
  dnsProviderConfig: document.getElementById("dnsProviderConfig"),
  dnsProviderFields: document.getElementById("dnsProviderFields"),
  selfCommonName: document.getElementById("selfCommonName"),
  selfKeyAlgorithm: document.getElementById("selfKeyAlgorithm"),
  selfValidDays: document.getElementById("selfValidDays"),
  selfRSABits: document.getElementById("selfRSABits"),
  selfECDSACurve: document.getElementById("selfECDSACurve"),
  selfIsCA: document.getElementById("selfIsCA"),
  selfOrganization: document.getElementById("selfOrganization"),
  selfOrganizationalUnit: document.getElementById("selfOrganizationalUnit"),
  selfCountry: document.getElementById("selfCountry"),
  selfProvince: document.getElementById("selfProvince"),
  selfLocality: document.getElementById("selfLocality"),
  selfDNSNames: document.getElementById("selfDNSNames"),
  selfIPAddresses: document.getElementById("selfIPAddresses"),
  selfEmailAddresses: document.getElementById("selfEmailAddresses"),
  selfURIs: document.getElementById("selfURIs"),
  certErrorBox: document.getElementById("certErrorBox"),
  certSuccessBox: document.getElementById("certSuccessBox"),
  certSubmitBtn: document.getElementById("certSubmitBtn"),
  certClearBtn: document.getElementById("certClearBtn"),
  certsBody: document.getElementById("certsBody"),
  certDownloadModal: document.getElementById("certDownloadModal"),
  certDownloadCloseBtn: document.getElementById("certDownloadCloseBtn"),
  certDownloadTarget: document.getElementById("certDownloadTarget"),
  nodeId: document.getElementById("nodeId"),
  certDownloadAsset: document.getElementById("certDownloadAsset"),
  certDownloadFormat: document.getElementById("certDownloadFormat"),
  certDownloadPassword: document.getElementById("certDownloadPassword"),
  certDownloadConfirmBtn: document.getElementById("certDownloadConfirmBtn"),
  certDownloadCancelBtn: document.getElementById("certDownloadCancelBtn"),
  reloadCertsBtn: document.getElementById("reloadCertsBtn"),
  sitesBody: document.getElementById("sitesBody"),
  logsBody: document.getElementById("logsBody"),
  searchInput: document.getElementById("searchInput"),
  reloadSitesBtn: document.getElementById("reloadSitesBtn"),
  reloadLogsBtn: document.getElementById("reloadLogsBtn"),
  logFoldEnabled: document.getElementById("logFoldEnabled"),
  logLiveEnabled: document.getElementById("logLiveEnabled"),
  logFoldWindow: document.getElementById("logFoldWindow"),
  settingsForm: document.getElementById("settingsForm"),
  settingsLanguage: document.getElementById("settingsLanguage"),
  settingsWebPort: document.getElementById("settingsWebPort"),
  alertWebhookUrl: document.getElementById("alertWebhookUrl"),
  alertConsecutive5xx: document.getElementById("alertConsecutive5xx"),
  alertLatencyMs: document.getElementById("alertLatencyMs"),
  alertCooldown: document.getElementById("alertCooldown"),
  adminTlsEnabled: document.getElementById("adminTlsEnabled"),
  adminTlsHttpsPort: document.getElementById("adminTlsHttpsPort"),
  adminTlsRedirectHttp: document.getElementById("adminTlsRedirectHttp"),
  adminTlsAutoSelfSigned: document.getElementById("adminTlsAutoSelfSigned"),
  adminTlsCertificateId: document.getElementById("adminTlsCertificateId"),
  clusterSyncCertificateSyncEnabled: document.getElementById("clusterSyncCertificateSyncEnabled"),
  clusterSyncFailCloseEnabled: document.getElementById("clusterSyncFailCloseEnabled"),
  clusterSyncFailCloseConsecutiveFailures: document.getElementById("clusterSyncFailCloseConsecutiveFailures"),
  clusterSyncFailCloseStaleAfter: document.getElementById("clusterSyncFailCloseStaleAfter"),
  backupEnabled: document.getElementById("backupEnabled"),
  backupInterval: document.getElementById("backupInterval"),
  backupKeepLast: document.getElementById("backupKeepLast"),
  backupQuickDownloadBtn: document.getElementById("backupQuickDownloadBtn"),
  backupNowBtn: document.getElementById("backupNowBtn"),
  backupUploadBtn: document.getElementById("backupUploadBtn"),
  backupUploadInput: document.getElementById("backupUploadInput"),
  backupReloadBtn: document.getElementById("backupReloadBtn"),
  backupBody: document.getElementById("backupBody"),
  settingsErrorBox: document.getElementById("settingsErrorBox"),
  settingsSuccessBox: document.getElementById("settingsSuccessBox"),
  settingsResetBtn: document.getElementById("settingsResetBtn"),
  ipSettingsForm: document.getElementById("ipSettingsForm"),
  ipSettingsAllowCidrs: document.getElementById("ipSettingsAllowCidrs"),
  ipSettingsDenyCidrs: document.getElementById("ipSettingsDenyCidrs"),
  ipRuleSourceOrder: document.getElementById("ipRuleSourceOrder"),
  ipSettingsIPRuleSets: document.getElementById("ipSettingsIPRuleSets"),
  ipSettingsIPCountryAutoUpdates: document.getElementById("ipSettingsIPCountryAutoUpdates"),
  ipSettingsOverview: document.getElementById("ipSettingsOverview"),
  ipRuleSetListSummary: document.getElementById("ipRuleSetListSummary"),
  ipCountryTaskListSummary: document.getElementById("ipCountryTaskListSummary"),
  ipSettingsNormalizeBtn: document.getElementById("ipSettingsNormalizeBtn"),
  ipRulesImportBtn: document.getElementById("ipRulesImportBtn"),
  ipRulesImportInput: document.getElementById("ipRulesImportInput"),
  ipRulesExportTxtBtn: document.getElementById("ipRulesExportTxtBtn"),
  ipRulesExportCsvBtn: document.getElementById("ipRulesExportCsvBtn"),
  ipRulesExportJsonBtn: document.getElementById("ipRulesExportJsonBtn"),
  ipRuleSetCreatorHost: document.getElementById("ipRuleSetCreatorHost"),
  ipRuleEditorTitle: document.getElementById("ipRuleEditorTitle"),
  ipRuleCreatorResetBtn: document.getElementById("ipRuleCreatorResetBtn"),
  ipRuleCreatorCancelBtn: document.getElementById("ipRuleCreatorCancelBtn"),
  ipRuleSetManageCards: document.getElementById("ipRuleSetManageCards"),
  addIPPageRuleSetBtn: document.getElementById("addIPPageRuleSetBtn"),
  addIPCountryAutoUpdateBtn: document.getElementById("addIPCountryAutoUpdateBtn"),
  ipSettingsErrorBox: document.getElementById("ipSettingsErrorBox"),
  ipSettingsSuccessBox: document.getElementById("ipSettingsSuccessBox"),
  currentAdminUsername: document.getElementById("currentAdminUsername"),
  newAdminUsername: document.getElementById("newAdminUsername"),
  currentAdminPassword: document.getElementById("currentAdminPassword"),
  newAdminPassword: document.getElementById("newAdminPassword"),
  confirmAdminPassword: document.getElementById("confirmAdminPassword"),
  accountSaveBtn: document.getElementById("accountSaveBtn"),
  addUpstreamBtn: document.getElementById("addUpstreamBtn"),
  upstreams: document.getElementById("upstreams"),
  addCanaryUpstreamBtn: document.getElementById("addCanaryUpstreamBtn"),
  canaryUpstreams: document.getElementById("canaryUpstreams"),
  addRouteBtn: document.getElementById("addRouteBtn"),
  ipRuleSetId: document.getElementById("ipRuleSetId"),
  siteIPRuleSetSummary: document.getElementById("siteIPRuleSetSummary"),
  routes: document.getElementById("routes"),
  certificateId: document.getElementById("certificateId"),
  addReqHeaderBtn: document.getElementById("addReqHeaderBtn"),
  addRespHeaderBtn: document.getElementById("addRespHeaderBtn"),
  requestHeaders: document.getElementById("requestHeaders"),
  responseHeaders: document.getElementById("responseHeaders"),
  logLimit: document.getElementById("logLimit"),
  kpiTotalSites: document.getElementById("kpiTotalSites"),
  kpiEnabledSites: document.getElementById("kpiEnabledSites"),
  kpiTotalReq: document.getElementById("kpiTotalReq"),
  kpiSuccessRate: document.getElementById("kpiSuccessRate"),
  kpiLatency: document.getElementById("kpiLatency"),
  nodeForm: document.getElementById("nodeForm"),
  nodeFormTitle: document.getElementById("nodeFormTitle"),
  nodeClearBtn: document.getElementById("nodeClearBtn"),
  nodeSubmitBtn: document.getElementById("nodeSubmitBtn"),
  nodeNodeId: document.getElementById("nodeNodeId"),
  nodeName: document.getElementById("nodeName"),
  nodeEndpoint: document.getElementById("nodeEndpoint"),
  nodeTags: document.getElementById("nodeTags"),
  nodeEnabled: document.getElementById("nodeEnabled"),
  nodeErrorBox: document.getElementById("nodeErrorBox"),
  nodeSuccessBox: document.getElementById("nodeSuccessBox"),
  nodesBody: document.getElementById("nodesBody"),
  controlPlaneStatusCard: document.getElementById("controlPlaneStatusCard"),
  clusterSyncStatusCard: document.getElementById("clusterSyncStatusCard"),
  navButtons: [...document.querySelectorAll(".nav-btn")],
  viewPanels: [...document.querySelectorAll("[data-view-panel]")]
};

const LANG_SEQUENCE = ["zh", "zh-tw", "en"];
const LANG_SWITCH_LABEL = {
  zh: "繁中",
  "zh-tw": "EN",
  en: "简中"
};
const LANG_LOCALE = {
  zh: "zh-CN",
  "zh-tw": "zh-TW",
  en: "en-US"
};

function normalizeLang(input) {
  const raw = String(input || "").trim().toLowerCase();
  if (!raw) return "en";
  if (raw === "zh" || raw === "zh-cn" || raw === "zh-hans") return "zh";
  if (raw === "zh-tw" || raw === "zh-hk" || raw === "zh-mo" || raw === "zh-hant") return "zh-tw";
  if (raw === "en" || raw.startsWith("en-")) return "en";
  return "en";
}

function nextLang(current) {
  const idx = LANG_SEQUENCE.indexOf(current);
  if (idx < 0) return LANG_SEQUENCE[0];
  return LANG_SEQUENCE[(idx + 1) % LANG_SEQUENCE.length];
}

const storedLangRaw = localStorage.getItem("fp_lang");
const storedLang = normalizeLang(storedLangRaw);
let lang = storedLang;
let pinnedLang = Boolean(storedLangRaw);
let activeView = localStorage.getItem("fp_view") || "overview";
let editingId = "";
let sites = [];
let cachedInterfaces = null;
let pendingBindInterfaceValues = null;
let certificates = [];
let backups = [];
let backupStatus = null;
let stats = null;
let nodes = [];
let appSettings = null;
let clusterSyncStatus = null;
let siteStatsMap = new Map();
let refreshTimer = null;
let downloadModalCertID = "";
let downloadModalCertName = "";
let editingNodeID = "";
let ipRuleSetEditingIndex = -1;
const expandedLogGroups = new Set();
let ipSettingsDraftDirty = false;
const IP_SETTINGS_DRAFT_STORAGE_KEY = "fp_ipsettings_draft_v1";

const fmtInt = new Intl.NumberFormat();

function t(key) {
  const dict = i18n[lang] || i18n.en;
  return dict[key] || key;
}

const RULESET_COUNTRY_TASK_ID_PREFIX = "ruleset-country::";
const DEFAULT_IP_RULE_SOURCE_ORDER = ["site", "custom", "country"];
const DEFAULT_IP_RULE_CONFLICT_POLICY = "allow_first";

function isGeneratedRuleSetCountryTaskID(id) {
  return String(id || "").trim().toLowerCase().startsWith(RULESET_COUNTRY_TASK_ID_PREFIX);
}

function normalizeRuleSetCountryTaskID(ruleSetID, list) {
  const id = String(ruleSetID || "").trim().toLowerCase();
  const kind = String(list || "allow").trim().toLowerCase() === "deny" ? "deny" : "allow";
  if (!id) return "";
  return `${RULESET_COUNTRY_TASK_ID_PREFIX}${id}::${kind}`;
}

function normalizeRuleMode(rawMode) {
  const mode = String(rawMode || "").trim().toLowerCase();
  if (mode === "manual" || mode === "country") return mode;
  return "manual";
}

function suggestRuleSetID(name) {
  return String(name || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function suggestIPCountryTaskID(ruleSetID, countries = []) {
  const ruleKey = suggestRuleSetID(ruleSetID) || "ruleset";
  const countryKey = uniqCaseInsensitive(countries)
    .map((item) => String(item || "").trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 3)
    .join("-");
  return `task-${ruleKey}-${countryKey || "country"}`;
}

function ensureUniqueIdentifier(base, seen, fallbackPrefix = "item") {
  const normalizedBase = String(base || "").trim() || `${fallbackPrefix}-1`;
  let candidate = normalizedBase;
  let key = candidate.toLowerCase();
  let index = 1;
  while (seen.has(key)) {
    index += 1;
    candidate = `${normalizedBase}-${index}`;
    key = candidate.toLowerCase();
  }
  seen.add(key);
  return candidate;
}

function normalizeIPRuleSource(input) {
  const value = String(input || "").trim().toLowerCase();
  if (value === "site") return "site";
  if (value === "custom" || value === "manual" || value === "ruleset" || value === "rule_set") return "custom";
  if (value === "country" || value === "geo") return "country";
  return "";
}

function normalizeIPRuleSourceOrder(input) {
  const raw = Array.isArray(input) ? input : splitCSV(input);
  const out = [];
  const invalid = [];
  const seen = new Set();
  for (const item of raw) {
    const value = normalizeIPRuleSource(item);
    if (!value) {
      invalid.push(String(item || "").trim());
      continue;
    }
    if (seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  for (const fallback of DEFAULT_IP_RULE_SOURCE_ORDER) {
    if (!seen.has(fallback)) {
      out.push(fallback);
    }
  }
  return {
    order: out,
    invalid: uniqCaseInsensitive(invalid.filter(Boolean))
  };
}

function normalizeIPRuleConflictPolicy(input) {
  const value = String(input || "").trim().toLowerCase();
  if (value === "allow_first" || value === "allowfirst" || value === "allow-first") return "allow_first";
  if (value === "deny_first" || value === "denyfirst" || value === "deny-first") return "deny_first";
  return "allow_first";
}

function conflictPriorityOrderByPolicy(policy) {
  return normalizeIPRuleConflictPolicy(policy) === "allow_first" ? ["allow", "deny"] : ["deny", "allow"];
}

function conflictPolicyByPriorityOrder(order) {
  return Array.isArray(order) && String(order[0] || "").toLowerCase() === "allow" ? "allow_first" : "deny_first";
}

function splitCSV(input) {
  return String(input || "")
    .split(/[\n\r,;，；]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

function uniqCaseInsensitive(items) {
  const out = [];
  const seen = new Set();
  for (const item of Array.isArray(items) ? items : []) {
    const text = String(item || "").trim();
    if (!text) continue;
    const key = text.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(text);
  }
  return out;
}

function isValidIPv4(input) {
  const text = String(input || "").trim();
  const parts = text.split(".");
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return false;
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) return false;
  }
  return true;
}

function parseIPv6Section(input) {
  const text = String(input || "").trim();
  if (!text) return { ok: true, count: 0 };
  const parts = text.split(":");
  let count = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (!part) return { ok: false, count: 0 };
    if (part.includes(".")) {
      if (i !== parts.length - 1 || !isValidIPv4(part)) return { ok: false, count: 0 };
      count += 2;
      continue;
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return { ok: false, count: 0 };
    count += 1;
  }
  return { ok: true, count };
}

function isValidIPv6(input) {
  const text = String(input || "").trim();
  if (!text.includes(":")) return false;
  if (text.startsWith(":") && !text.startsWith("::")) return false;
  if (text.endsWith(":") && !text.endsWith("::")) return false;

  if (text.includes("::")) {
    if (text.indexOf("::") !== text.lastIndexOf("::")) return false;
    const [left, right] = text.split("::");
    const leftPart = parseIPv6Section(left);
    const rightPart = parseIPv6Section(right);
    if (!leftPart.ok || !rightPart.ok) return false;
    return leftPart.count + rightPart.count < 8;
  }

  const part = parseIPv6Section(text);
  return part.ok && part.count === 8;
}

function isValidCIDR(input) {
  const text = String(input || "").trim();
  const slashAt = text.indexOf("/");
  if (slashAt <= 0 || slashAt >= text.length - 1) return false;
  const ipPart = text.slice(0, slashAt).trim();
  const prefixPart = text.slice(slashAt + 1).trim();
  if (!/^\d+$/.test(prefixPart)) return false;
  const prefix = Number(prefixPart);
  if (isValidIPv4(ipPart)) return Number.isInteger(prefix) && prefix >= 0 && prefix <= 32;
  if (isValidIPv6(ipPart)) return Number.isInteger(prefix) && prefix >= 0 && prefix <= 128;
  return false;
}

function isValidIPOrCIDR(input) {
  const text = String(input || "").trim();
  if (!text) return false;
  if (text.includes("/")) return isValidCIDR(text);
  return isValidIPv4(text) || isValidIPv6(text);
}

function parseIPTokensWithIssues(rawInput) {
  const tokens = splitCSV(rawInput);
  const invalid = [];
  const duplicates = [];
  const seen = new Set();
  for (const token of tokens) {
    const key = token.toLowerCase();
    if (seen.has(key)) {
      duplicates.push(token);
    } else {
      seen.add(key);
    }
    if (!isValidIPOrCIDR(token)) {
      invalid.push(token);
    }
  }
  return { tokens, invalid: uniqCaseInsensitive(invalid), duplicates: uniqCaseInsensitive(duplicates) };
}

function parseCountryCodesWithIssues(rawInput) {
  const tokens = splitCSV(rawInput).map((item) => String(item || "").trim().toUpperCase()).filter(Boolean);
  const invalid = [];
  const duplicates = [];
  const seen = new Set();
  for (const token of tokens) {
    if (!/^[A-Z]{2}$/.test(token)) {
      invalid.push(token);
      continue;
    }
    if (seen.has(token)) {
      duplicates.push(token);
      continue;
    }
    seen.add(token);
  }
  return {
    tokens: [...seen.values()],
    invalid: uniqCaseInsensitive(invalid),
    duplicates: uniqCaseInsensitive(duplicates)
  };
}

function parseASNTokensWithIssues(rawInput) {
  const rawTokens = splitCSV(rawInput);
  const invalid = [];
  const duplicates = [];
  const seen = new Set();
  const tokens = [];
  for (const raw of rawTokens) {
    const upper = String(raw || "").trim().toUpperCase();
    const normalized = upper.startsWith("AS") ? upper.slice(2) : upper;
    if (!/^\d+$/.test(normalized)) {
      invalid.push(raw);
      continue;
    }
    const value = Number(normalized);
    if (!Number.isInteger(value) || value <= 0 || value > 4294967295) {
      invalid.push(raw);
      continue;
    }
    const canonical = `AS${value}`;
    const key = canonical.toLowerCase();
    if (seen.has(key)) {
      duplicates.push(canonical);
      continue;
    }
    seen.add(key);
    tokens.push(canonical);
  }
  return {
    tokens,
    invalid: uniqCaseInsensitive(invalid),
    duplicates: uniqCaseInsensitive(duplicates)
  };
}

function ensureStringList(input) {
  if (Array.isArray(input)) {
    return input
      .map((item) => String(item || "").trim())
      .filter(Boolean);
  }
  if (typeof input === "string") {
    return splitCSV(input);
  }
  return [];
}

function normalizeImportedIPRulesPayload(rawInput) {
  const raw = rawInput && typeof rawInput === "object" ? rawInput : {};
  const webRaw = raw.webAccess || raw.web || {};
  const webAllow = ensureStringList(webRaw.allowCidrs ?? webRaw.allow ?? raw.allowCidrs ?? raw.allow);
  const webDeny = ensureStringList(webRaw.denyCidrs ?? webRaw.deny ?? raw.denyCidrs ?? raw.deny);
  const sourceOrder = normalizeIPRuleSourceOrder(raw.ipRuleSourceOrder).order;

  const presetsRaw = Array.isArray(raw.ipRuleSets)
    ? raw.ipRuleSets
    : Array.isArray(raw.ruleSets)
      ? raw.ruleSets
      : Array.isArray(raw.presets)
        ? raw.presets
        : [];

  const presets = presetsRaw
    .map((item) => {
      if (!item || typeof item !== "object") return null;
      const id = String(item.id || "").trim();
      const name = String(item.name || "").trim();
      const priority = Number(item.priority || 0);
      const conflictPolicy = normalizeIPRuleConflictPolicy(item.conflictPolicy);
      const allowCidrs = ensureStringList(item.allowCidrs ?? item.allow);
      const denyCidrs = ensureStringList(item.denyCidrs ?? item.deny);
      const allowAsns = ensureStringList(item.allowAsns);
      const denyAsns = ensureStringList(item.denyAsns);
      const denyReputationCidrs = ensureStringList(item.denyReputationCidrs);
      const allowCountries = ensureStringList(item.allowCountries).map((code) => String(code || "").trim().toUpperCase()).filter(Boolean);
      const legacyDenyCountries = ensureStringList(item.denyCountries).map((code) => String(code || "").trim().toUpperCase()).filter(Boolean);
      const mergedAllowCountries = uniqCaseInsensitive([...allowCountries, ...legacyDenyCountries]).map((code) => String(code || "").trim().toUpperCase()).filter(Boolean);
      const countryIncludeIpv6 = !!item.countryIncludeIpv6;
      const countryInterval = String(item.countryInterval || "24h").trim();
      const countrySource = String(item.countrySource || "ipdeny").trim().toLowerCase();
      const mode = normalizeRuleMode(item.mode);
      if (!id && !name && allowCidrs.length === 0 && denyCidrs.length === 0 && allowAsns.length === 0 && denyAsns.length === 0 && denyReputationCidrs.length === 0 && mergedAllowCountries.length === 0) return null;
      return {
        id,
        name,
        priority: Number.isFinite(priority) ? Math.trunc(priority) : 0,
        conflictPolicy,
        mode,
        allowCidrs,
        denyCidrs,
        allowAsns,
        denyAsns,
        denyReputationCidrs,
        allowCountries: mergedAllowCountries,
        denyCountries: [],
        countryIncludeIpv6,
        countryInterval: countryInterval || "24h",
        countrySource: countrySource || "ipdeny"
      };
    })
    .filter(Boolean);

  const hasAutoUpdatesField = Array.isArray(raw.ipCountryAutoUpdates);
  const autoUpdatesRaw = hasAutoUpdatesField ? raw.ipCountryAutoUpdates : [];
  const autoUpdates = autoUpdatesRaw
    .map((item) => {
      if (!item || typeof item !== "object") return null;
      const id = String(item.id || "").trim();
      const ruleSetId = String(item.ruleSetId || "").trim();
      const list = String(item.list || "allow").trim().toLowerCase();
      const countries = ensureStringList(item.countries).map((code) => String(code || "").trim().toUpperCase()).filter(Boolean);
      const interval = String(item.interval || "24h").trim();
      const source = String(item.source || "ipdeny").trim().toLowerCase();
      const hasFields = id || ruleSetId || countries.length > 0 || interval || source || !!item.enabled || !!item.includeIpv6;
      if (!hasFields) return null;
      return {
        id,
        enabled: item.enabled !== false,
        ruleSetId,
        list: "allow",
        countries,
        includeIpv6: !!item.includeIpv6,
        interval: interval || "24h",
        source: source || "ipdeny"
      };
    })
    .filter(Boolean);

  return {
    webAccess: {
      allowCidrs: webAllow,
      denyCidrs: webDeny
    },
    ipRuleSourceOrder: sourceOrder,
    ipRuleSets: presets,
    ipCountryAutoUpdates: hasAutoUpdatesField ? autoUpdates : undefined
  };
}

function hasCurrentIPRulesDraftData() {
  if (!el.ipSettingsForm) return false;
  const draft = buildIPSettingsDraft(false);
  return draft.diagnostics.presetCount > 0 || draft.diagnostics.autoUpdateCount > 0 || draft.diagnostics.globalAllowCount > 0 || draft.diagnostics.globalDenyCount > 0;
}

function applyImportedIPRulesPayload(rawPayload) {
  const payload = normalizeImportedIPRulesPayload(rawPayload);
  fillIPSettingsForm({
    webAccess: payload.webAccess,
    ipRuleSourceOrder: payload.ipRuleSourceOrder,
    ipRuleSets: payload.ipRuleSets,
    ipCountryAutoUpdates: payload.ipCountryAutoUpdates === undefined ? [] : payload.ipCountryAutoUpdates
  }, { force: true });
  markIPSettingsDraftDirty();
}

function ipRulesExportFilename(ext) {
  const now = new Date();
  const pad2 = (n) => String(n).padStart(2, "0");
  const stamp = `${now.getFullYear()}${pad2(now.getMonth() + 1)}${pad2(now.getDate())}-${pad2(now.getHours())}${pad2(now.getMinutes())}${pad2(now.getSeconds())}`;
  return `flowproxy-ip-rules-${stamp}.${ext}`;
}

function downloadTextAsFile(filename, content, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([String(content || "")], { type: mime });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
}

function normalizeIPListType(rawType) {
  const value = String(rawType || "").trim().toLowerCase();
  if (!value) return "";
  if (value === "allow" || value === "allowed" || value === "allowlist" || value === "white" || value === "whitelist" || value === "pass" || value === "permit") return "allow";
  if (value === "deny" || value === "denied" || value === "block" || value === "blocked" || value === "black" || value === "blacklist" || value === "reject") return "deny";
  if (value === "放行" || value === "允许" || value === "白名单" || value === "白名單") return "allow";
  if (value === "拦截" || value === "拒绝" || value === "拒絕" || value === "黑名单" || value === "黑名單") return "deny";
  return "";
}

function csvEscape(value) {
  const text = String(value ?? "");
  if (!text.includes(",") && !text.includes("\"") && !text.includes("\n") && !text.includes("\r")) return text;
  return `"${text.replaceAll("\"", "\"\"")}"`;
}

function parseCSVRows(text) {
  const source = String(text || "");
  const rows = [];
  let row = [];
  let cell = "";
  let inQuotes = false;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (inQuotes) {
      if (ch === "\"") {
        if (source[i + 1] === "\"") {
          cell += "\"";
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        cell += ch;
      }
      continue;
    }

    if (ch === "\"") {
      inQuotes = true;
      continue;
    }
    if (ch === ",") {
      row.push(cell);
      cell = "";
      continue;
    }
    if (ch === "\n" || ch === "\r") {
      row.push(cell);
      cell = "";
      if (ch === "\r" && source[i + 1] === "\n") {
        i += 1;
      }
      rows.push(row);
      row = [];
      continue;
    }
    cell += ch;
  }

  if (inQuotes) {
    throw new Error(t("ipRulesImportInvalidCSV"));
  }
  row.push(cell);
  rows.push(row);
  return rows.filter((cols) => cols.some((item) => String(item || "").trim() !== ""));
}

function parseIPRulesTXT(text) {
  const webAccess = { allowCidrs: [], denyCidrs: [] };
  let ipRuleSourceOrder = [...DEFAULT_IP_RULE_SOURCE_ORDER];
  const presetMap = new Map();
  const implicitAllow = [];
  const lines = String(text || "").split(/\r?\n/);
  let matchedStructured = 0;

  const ensurePreset = (id) => {
    const key = String(id || "").trim();
    if (!key) throw new Error(t("ipRulesImportInvalidPresetID"));
    const existing = presetMap.get(key);
    if (existing) return existing;
    const next = { id: key, name: "", priority: 0, conflictPolicy: DEFAULT_IP_RULE_CONFLICT_POLICY, allowCidrs: [], denyCidrs: [], allowAsns: [], denyAsns: [], denyReputationCidrs: [] };
    presetMap.set(key, next);
    return next;
  };

  for (const rawLine of lines) {
    const line = String(rawLine || "").trim();
    if (!line || line.startsWith("#")) continue;

    let match = line.match(/^WEB_(ALLOW|DENY)\s+(.+)$/i);
    if (match) {
      matchedStructured += 1;
      const listType = normalizeIPListType(match[1]);
      const values = splitCSV(match[2]);
      if (listType === "allow") webAccess.allowCidrs.push(...values);
      if (listType === "deny") webAccess.denyCidrs.push(...values);
      continue;
    }

    match = line.match(/^SOURCE_ORDER\s+(.+)$/i);
    if (match) {
      matchedStructured += 1;
      ipRuleSourceOrder = normalizeIPRuleSourceOrder(match[1]).order;
      continue;
    }

    match = line.match(/^PRESET\s+(\S+)\s+(NAME|PRIORITY|POLICY|ALLOW|DENY|ALLOW_ASN|DENY_ASN|DENY_REPUTATION)\s+(.+)$/i);
    if (match) {
      matchedStructured += 1;
      const preset = ensurePreset(match[1]);
      const field = String(match[2] || "").trim().toUpperCase();
      const rawValue = String(match[3] || "").trim();
      if (field === "NAME") {
        preset.name = rawValue;
      } else if (field === "PRIORITY") {
        const n = Number(rawValue);
        preset.priority = Number.isFinite(n) ? Math.trunc(n) : 0;
      } else if (field === "POLICY") {
        preset.conflictPolicy = normalizeIPRuleConflictPolicy(rawValue);
      } else if (field === "ALLOW") {
        preset.allowCidrs.push(...splitCSV(rawValue));
      } else if (field === "DENY") {
        preset.denyCidrs.push(...splitCSV(rawValue));
      } else if (field === "ALLOW_ASN") {
        preset.allowAsns.push(...splitCSV(rawValue));
      } else if (field === "DENY_ASN") {
        preset.denyAsns.push(...splitCSV(rawValue));
      } else if (field === "DENY_REPUTATION") {
        preset.denyReputationCidrs.push(...splitCSV(rawValue));
      }
      continue;
    }

    match = line.match(/^(ALLOW|DENY)\s+(.+)$/i);
    if (match) {
      matchedStructured += 1;
      const listType = normalizeIPListType(match[1]);
      const values = splitCSV(match[2]);
      if (listType === "allow") webAccess.allowCidrs.push(...values);
      if (listType === "deny") webAccess.denyCidrs.push(...values);
      continue;
    }

    implicitAllow.push(...splitCSV(line));
  }

  if (!matchedStructured && implicitAllow.length === 0) {
    throw new Error(t("ipRulesImportUnsupported"));
  }
  if (implicitAllow.length) {
    webAccess.allowCidrs.push(...implicitAllow);
  }

  return {
    webAccess,
    ipRuleSourceOrder,
    ipRuleSets: [...presetMap.values()]
  };
}

function parseIPRulesCSV(text) {
  const rows = parseCSVRows(text);
  if (!rows.length) throw new Error(t("ipRulesImportUnsupported"));

  const firstRow = rows[0].map((item) => String(item || "").trim().toLowerCase());
  const hasHeader = firstRow.includes("scope") && (firstRow.includes("list") || firstRow.includes("type")) && firstRow.includes("value");
  const header = hasHeader ? firstRow : ["scope", "id", "name", "list", "value"];
  const dataRows = hasHeader ? rows.slice(1) : rows;
  const idx = {
    scope: header.indexOf("scope"),
    id: header.indexOf("id"),
    name: header.indexOf("name"),
    priority: header.indexOf("priority"),
    policy: header.indexOf("policy"),
    list: header.indexOf("list") >= 0 ? header.indexOf("list") : header.indexOf("type"),
    value: header.indexOf("value")
  };

  if (idx.scope < 0 || idx.list < 0 || idx.value < 0) {
    throw new Error(t("ipRulesImportInvalidCSV"));
  }

  const webAccess = { allowCidrs: [], denyCidrs: [] };
  let ipRuleSourceOrder = [...DEFAULT_IP_RULE_SOURCE_ORDER];
  const presetMap = new Map();
  let matchedRows = 0;
  const ensurePreset = (id, name = "") => {
    const key = String(id || "").trim();
    if (!key) throw new Error(t("ipRulesImportInvalidPresetID"));
    const existing = presetMap.get(key);
    if (existing) {
      if (name && !existing.name) existing.name = name;
      return existing;
    }
    const next = { id: key, name: String(name || "").trim(), priority: 0, conflictPolicy: DEFAULT_IP_RULE_CONFLICT_POLICY, allowCidrs: [], denyCidrs: [], allowAsns: [], denyAsns: [], denyReputationCidrs: [] };
    presetMap.set(key, next);
    return next;
  };

  for (const row of dataRows) {
    const scopeText = String(row[idx.scope] || "").trim().toLowerCase();
    const rawListType = String(row[idx.list] || "").trim();
    const id = idx.id >= 0 ? String(row[idx.id] || "").trim() : "";
    const name = idx.name >= 0 ? String(row[idx.name] || "").trim() : "";
    const priorityText = idx.priority >= 0 ? String(row[idx.priority] || "").trim() : "";
    const policyText = idx.policy >= 0 ? String(row[idx.policy] || "").trim() : "";
    const listType = normalizeIPListType(rawListType);
    const isPresetScope = scopeText === "preset" || scopeText === "rule" || scopeText === "template" || scopeText === "模板" || scopeText === "範本";
    const isPresetPriorityRow = isPresetScope && (rawListType.toLowerCase() === "priority");
    const isPresetPolicyRow = isPresetScope && (rawListType.toLowerCase() === "policy");
    const valueText = String(row[idx.value] || "").trim();
    if (!scopeText && !valueText) continue;

    if (scopeText === "meta" || scopeText === "setting" || scopeText === "config") {
      if (rawListType.toLowerCase() === "source_order" || rawListType.toLowerCase() === "source-order") {
        matchedRows += 1;
        ipRuleSourceOrder = normalizeIPRuleSourceOrder(valueText).order;
      }
      continue;
    }
    if (!listType && !isPresetPriorityRow && !isPresetPolicyRow) continue;

    const values = splitCSV(valueText);
    if (scopeText === "web" || scopeText === "global" || scopeText === "system" || scopeText === "全局" || scopeText === "全域") {
      matchedRows += 1;
      if (listType === "allow") webAccess.allowCidrs.push(...values);
      if (listType === "deny") webAccess.denyCidrs.push(...values);
      continue;
    }

    if (isPresetScope) {
      const preset = ensurePreset(id, name);
      if (priorityText) {
        const n = Number(priorityText);
        if (Number.isFinite(n)) {
          preset.priority = Math.trunc(n);
        }
      }
      if (policyText) {
        preset.conflictPolicy = normalizeIPRuleConflictPolicy(policyText);
      }
      if (rawListType.toLowerCase() === "priority") {
        matchedRows += 1;
        const n = Number(valueText);
        preset.priority = Number.isFinite(n) ? Math.trunc(n) : 0;
        continue;
      }
      if (rawListType.toLowerCase() === "policy") {
        matchedRows += 1;
        preset.conflictPolicy = normalizeIPRuleConflictPolicy(valueText);
        continue;
      }
      matchedRows += 1;
      if (listType === "allow") preset.allowCidrs.push(...values);
      if (listType === "deny") preset.denyCidrs.push(...values);
      if (rawListType.toLowerCase() === "allow_asn" || rawListType.toLowerCase() === "allow-asn") preset.allowAsns.push(...values);
      if (rawListType.toLowerCase() === "deny_asn" || rawListType.toLowerCase() === "deny-asn") preset.denyAsns.push(...values);
      if (rawListType.toLowerCase() === "deny_reputation" || rawListType.toLowerCase() === "deny-reputation") preset.denyReputationCidrs.push(...values);
      continue;
    }
  }

  if (matchedRows === 0) {
    throw new Error(t("ipRulesImportUnsupported"));
  }

  return {
    webAccess,
    ipRuleSourceOrder,
    ipRuleSets: [...presetMap.values()]
  };
}

function parseIPRulesJSON(text) {
  let raw;
  try {
    raw = JSON.parse(String(text || ""));
  } catch (_) {
    throw new Error(t("ipRulesImportInvalidJSON"));
  }
  if (Array.isArray(raw)) {
    return {
      webAccess: { allowCidrs: raw, denyCidrs: [] },
      ipRuleSets: []
    };
  }
  if (!raw || typeof raw !== "object") {
    throw new Error(t("ipRulesImportInvalidJSON"));
  }
  const hasKnownField = "webAccess" in raw || "web" in raw || "ipRuleSets" in raw || "ruleSets" in raw || "presets" in raw || "ipCountryAutoUpdates" in raw || "ipRuleSourceOrder" in raw || "allowCidrs" in raw || "denyCidrs" in raw || "allow" in raw || "deny" in raw;
  if (!hasKnownField) {
    throw new Error(t("ipRulesImportUnsupported"));
  }
  return normalizeImportedIPRulesPayload(raw);
}

function parseImportedIPRulesByFile(fileName, content) {
  const name = String(fileName || "").trim().toLowerCase();
  const text = String(content || "");
  if (name.endsWith(".json")) {
    return parseIPRulesJSON(text);
  }
  if (name.endsWith(".csv")) {
    return parseIPRulesCSV(text);
  }
  if (name.endsWith(".txt")) {
    return parseIPRulesTXT(text);
  }

  const trimmed = text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return parseIPRulesJSON(text);
  }
  if (trimmed.includes(",") && /\bscope\b/i.test(trimmed) && /\bvalue\b/i.test(trimmed)) {
    return parseIPRulesCSV(text);
  }
  return parseIPRulesTXT(text);
}

function collectIPRulesForExport(requireStrictPresetID = false) {
  const draft = buildIPSettingsDraft(false);
  if (requireStrictPresetID) {
    if (draft.diagnostics.missingIDs.length) {
      throw new Error(`${t("ipRulesIssueMissingID")}: ${draft.diagnostics.missingIDs.slice(0, 5).join(", ")}`);
    }
    if (draft.diagnostics.duplicateIDs.length) {
      throw new Error(`${t("ipRulesIssueDuplicateID")}: ${draft.diagnostics.duplicateIDs.slice(0, 5).join(", ")}`);
    }
  }
  return draft.payload;
}

function exportIPRulesAsJSON() {
  const payload = collectIPRulesForExport(false);
  const data = JSON.stringify(payload, null, 2);
  downloadTextAsFile(ipRulesExportFilename("json"), `${data}\n`, "application/json;charset=utf-8");
}

function exportIPRulesAsTXT() {
  const payload = collectIPRulesForExport(true);
  const lines = [];
  lines.push("# FlowProxy IP Rules Export v1");
  lines.push(`# GeneratedAt: ${new Date().toISOString()}`);
  lines.push("# SOURCE_ORDER <site,custom,country>");
  lines.push("# WEB_ALLOW <ip-or-cidr>");
  lines.push("# WEB_DENY <ip-or-cidr>");
  lines.push("# PRESET <id> NAME <display-name>");
  lines.push("# PRESET <id> PRIORITY <number>");
  lines.push("# PRESET <id> POLICY <deny_first|allow_first>");
  lines.push("# PRESET <id> ALLOW <ip-or-cidr>");
  lines.push("# PRESET <id> DENY <ip-or-cidr>");
  lines.push("# PRESET <id> ALLOW_ASN <asn>");
  lines.push("# PRESET <id> DENY_ASN <asn>");
  lines.push("# PRESET <id> DENY_REPUTATION <ip-or-cidr>");
  lines.push("");
  lines.push(`SOURCE_ORDER ${(payload.ipRuleSourceOrder || DEFAULT_IP_RULE_SOURCE_ORDER).join(", ")}`);
  lines.push("");

  for (const item of payload.webAccess.allowCidrs || []) {
    lines.push(`WEB_ALLOW ${item}`);
  }
  for (const item of payload.webAccess.denyCidrs || []) {
    lines.push(`WEB_DENY ${item}`);
  }

  for (const preset of payload.ipRuleSets || []) {
    lines.push("");
    if (preset.name) {
      lines.push(`PRESET ${preset.id} NAME ${preset.name}`);
    }
    lines.push(`PRESET ${preset.id} PRIORITY ${Number(preset.priority || 0)}`);
    lines.push(`PRESET ${preset.id} POLICY ${normalizeIPRuleConflictPolicy(preset.conflictPolicy || DEFAULT_IP_RULE_CONFLICT_POLICY)}`);
    for (const item of preset.allowCidrs || []) {
      lines.push(`PRESET ${preset.id} ALLOW ${item}`);
    }
    for (const item of preset.denyCidrs || []) {
      lines.push(`PRESET ${preset.id} DENY ${item}`);
    }
    for (const item of preset.allowAsns || []) {
      lines.push(`PRESET ${preset.id} ALLOW_ASN ${item}`);
    }
    for (const item of preset.denyAsns || []) {
      lines.push(`PRESET ${preset.id} DENY_ASN ${item}`);
    }
    for (const item of preset.denyReputationCidrs || []) {
      lines.push(`PRESET ${preset.id} DENY_REPUTATION ${item}`);
    }
  }
  downloadTextAsFile(ipRulesExportFilename("txt"), `${lines.join("\n")}\n`);
}

function exportIPRulesAsCSV() {
  const payload = collectIPRulesForExport(true);
  const rows = [];
  rows.push(["scope", "id", "name", "priority", "policy", "list", "value"]);
  rows.push(["meta", "", "", "", "", "source_order", (payload.ipRuleSourceOrder || DEFAULT_IP_RULE_SOURCE_ORDER).join(", ")]);
  for (const item of payload.webAccess.allowCidrs || []) {
    rows.push(["web", "", "", "", "", "allow", item]);
  }
  for (const item of payload.webAccess.denyCidrs || []) {
    rows.push(["web", "", "", "", "", "deny", item]);
  }
  for (const preset of payload.ipRuleSets || []) {
    const presetPolicy = normalizeIPRuleConflictPolicy(preset.conflictPolicy || DEFAULT_IP_RULE_CONFLICT_POLICY);
    rows.push(["preset", preset.id, preset.name || "", String(Number(preset.priority || 0)), presetPolicy, "priority", String(Number(preset.priority || 0))]);
    rows.push(["preset", preset.id, preset.name || "", String(Number(preset.priority || 0)), presetPolicy, "policy", presetPolicy]);
    for (const item of preset.allowCidrs || []) {
      rows.push(["preset", preset.id, preset.name || "", String(Number(preset.priority || 0)), presetPolicy, "allow", item]);
    }
    for (const item of preset.denyCidrs || []) {
      rows.push(["preset", preset.id, preset.name || "", String(Number(preset.priority || 0)), presetPolicy, "deny", item]);
    }
    for (const item of preset.allowAsns || []) {
      rows.push(["preset", preset.id, preset.name || "", String(Number(preset.priority || 0)), presetPolicy, "allow_asn", item]);
    }
    for (const item of preset.denyAsns || []) {
      rows.push(["preset", preset.id, preset.name || "", String(Number(preset.priority || 0)), presetPolicy, "deny_asn", item]);
    }
    for (const item of preset.denyReputationCidrs || []) {
      rows.push(["preset", preset.id, preset.name || "", String(Number(preset.priority || 0)), presetPolicy, "deny_reputation", item]);
    }
  }
  const csvText = rows.map((row) => row.map(csvEscape).join(",")).join("\n");
  downloadTextAsFile(ipRulesExportFilename("csv"), `${csvText}\n`, "text/csv;charset=utf-8");
}

function selectedValues(selectEl) {
  if (!selectEl) return [];
  return [...selectEl.options]
    .filter((item) => item.selected)
    .map((item) => String(item.value || "").trim())
    .filter(Boolean);
}

function collectBindInterfaceValues() {
  const container = document.getElementById("bindInterfaceContainer");
  if (!container) return [];
  const allCheckbox = container.querySelector('input[data-iface-all="true"]');
  if (allCheckbox && allCheckbox.checked) return [];
  const values = [];
  for (const cb of container.querySelectorAll('input[name="bindInterface"]')) {
    if (cb.checked && cb.value) values.push(cb.value);
  }
  return values;
}

function normalizePort(value) {
  if (value === "" || value === null || value === undefined) return "";
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error("port must be within 1-65535");
  }
  return String(n);
}

function normalizeUpstreamURL(rawInput, portInput) {
  const raw = String(rawInput || "").trim();
  if (!raw) return "";
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;

  let u;
  try {
    u = new URL(withScheme);
  } catch (_) {
    throw new Error(`invalid upstream URL: ${rawInput}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("upstream URL must use http or https");
  }
  if (!u.hostname) {
    throw new Error("upstream host is required");
  }
  const port = normalizePort(String(portInput || "").trim());
  if (port) {
    u.port = port;
  }
  const out = u.toString();
  if (u.pathname === "/" && !u.search && !u.hash) {
    return out.slice(0, -1);
  }
  return out;
}

function parseUpstreamForForm(rawInput) {
  const raw = String(rawInput || "").trim();
  if (!raw) return { address: "", port: "" };
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  try {
    const u = new URL(withScheme);
    const port = u.port || "";
    if (port) {
      u.port = "";
    }
    const base = u.toString();
    const address = u.pathname === "/" && !u.search && !u.hash ? base.slice(0, -1) : base;
    return { address, port };
  } catch (_) {
    return { address: raw, port: "" };
  }
}

function parseWeightedUpstreamsCSV(rawInput) {
  const tokens = splitCSV(String(rawInput || ""));
  const out = [];
  for (const token of tokens) {
    const parts = token.split("#");
    const address = (parts[0] || "").trim();
    if (!address) continue;
    const weight = Number((parts[1] || "").trim() || "1");
    const url = normalizeUpstreamURL(address, "");
    out.push({ url, weight: Number.isFinite(weight) && weight > 0 ? weight : 1 });
  }
  return out;
}

function formatWeightedUpstreamsCSV(items) {
  const list = Array.isArray(items) ? items : [];
  return list
    .map((item) => {
      const parsed = parseUpstreamForForm(item?.url || "");
      const address = parsed.port ? `${parsed.address}:${parsed.port}` : parsed.address;
      const weight = Number(item?.weight || 1);
      return `${address}#${weight > 0 ? weight : 1}`;
    })
    .filter(Boolean)
    .join(", ");
}

function parseStatusCodesCSV(rawInput) {
  const values = splitCSV(String(rawInput || ""));
  const out = [];
  const seen = new Set();
  for (const value of values) {
    const code = Number(value);
    if (!Number.isInteger(code) || code < 100 || code > 599) {
      throw new Error(`invalid status code: ${value}`);
    }
    if (seen.has(code)) continue;
    seen.add(code);
    out.push(code);
  }
  return out;
}

function formatStatusCodesCSV(values) {
  if (!Array.isArray(values)) return "";
  return values
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value >= 100 && value <= 599)
    .join(", ");
}

function showError(msg = "") {
  el.errorBox.textContent = msg;
}

function showSuccess(msg = "") {
  el.successBox.textContent = msg;
}

function clearNotice() {
  showError("");
  showSuccess("");
}

function showCertError(msg = "") {
  el.certErrorBox.textContent = msg;
}

function showCertSuccess(msg = "") {
  el.certSuccessBox.textContent = msg;
}

function clearCertNotice() {
  showCertError("");
  showCertSuccess("");
}

function showSettingsError(msg = "") {
  el.settingsErrorBox.textContent = msg;
}

function showSettingsSuccess(msg = "") {
  el.settingsSuccessBox.textContent = msg;
}

function clearSettingsNotice() {
  showSettingsError("");
  showSettingsSuccess("");
}

function showIPSettingsError(msg = "") {
  if (!el.ipSettingsErrorBox) return;
  el.ipSettingsErrorBox.textContent = msg;
}

function showIPSettingsSuccess(msg = "") {
  if (!el.ipSettingsSuccessBox) return;
  el.ipSettingsSuccessBox.textContent = msg;
}

function clearIPSettingsNotice() {
  showIPSettingsError("");
  showIPSettingsSuccess("");
}

function markIPSettingsDraftDirty() {
  ipSettingsDraftDirty = true;
  persistIPSettingsDraftToLocal();
}

function clearIPSettingsDraftDirty() {
  ipSettingsDraftDirty = false;
}

function persistIPSettingsDraftToLocal() {
  if (!el.ipSettingsForm) return;
  try {
    const payload = {
      allowCidrs: String(el.ipSettingsAllowCidrs?.value || ""),
      denyCidrs: String(el.ipSettingsDenyCidrs?.value || ""),
      sourceOrder: String(el.ipRuleSourceOrder?.value || ""),
      ipRuleSets: [...(el.ipSettingsIPRuleSets?.children || [])].map((row) => ({
        id: String(row.querySelector(".ip-rule-id")?.value || ""),
        name: String(row.querySelector(".ip-rule-name")?.value || ""),
        mode: String(row.querySelector(".ip-rule-mode")?.value || "manual"),
        priority: String(row.querySelector(".ip-rule-priority")?.value || "0"),
        conflictPolicy: String(row.querySelector(".ip-rule-conflict-policy")?.value || DEFAULT_IP_RULE_CONFLICT_POLICY),
        allowCidrs: String(row.querySelector(".ip-rule-allow")?.value || ""),
        denyCidrs: String(row.querySelector(".ip-rule-deny")?.value || ""),
        allowAsns: String(row.querySelector(".ip-rule-allow-asns")?.value || ""),
        denyAsns: String(row.querySelector(".ip-rule-deny-asns")?.value || ""),
        denyReputationCidrs: String(row.querySelector(".ip-rule-deny-reputation-cidrs")?.value || ""),
        allowCountries: String(row.querySelector(".ip-rule-allow-countries")?.value || ""),
        countryIncludeIpv6: !!row.querySelector(".ip-rule-country-include-ipv6")?.checked,
        countryInterval: String(row.querySelector(".ip-rule-country-interval")?.value || ""),
        countrySource: String(row.querySelector(".ip-rule-country-source")?.value || "ipdeny")
      })),
      ipCountryAutoUpdates: [...(el.ipSettingsIPCountryAutoUpdates?.children || [])].map((row) => ({
        id: String(row.querySelector(".ip-country-id")?.value || ""),
        ruleSetId: String(row.querySelector(".ip-country-rule-set-id")?.value || ""),
        list: String(row.querySelector(".ip-country-list")?.value || "allow"),
        countries: String(row.querySelector(".ip-country-countries")?.value || ""),
        interval: String(row.querySelector(".ip-country-interval")?.value || ""),
        source: String(row.querySelector(".ip-country-source")?.value || "ipdeny"),
        includeIpv6: !!row.querySelector(".ip-country-include-ipv6")?.checked,
        enabled: !!row.querySelector(".ip-country-enabled")?.checked
      }))
    };
    localStorage.setItem(IP_SETTINGS_DRAFT_STORAGE_KEY, JSON.stringify(payload));
  } catch (_) {
  }
}

function clearLocalIPSettingsDraft() {
  try {
    localStorage.removeItem(IP_SETTINGS_DRAFT_STORAGE_KEY);
  } catch (_) {
  }
}

function restoreLocalIPSettingsDraft() {
  if (!el.ipSettingsForm) return false;
  let raw = "";
  try {
    raw = localStorage.getItem(IP_SETTINGS_DRAFT_STORAGE_KEY) || "";
  } catch (_) {
    return false;
  }
  if (!raw) return false;
  let draft = null;
  try {
    draft = JSON.parse(raw);
  } catch (_) {
    return false;
  }
  if (!draft || typeof draft !== "object") return false;

  el.ipSettingsAllowCidrs.value = String(draft.allowCidrs || "");
  el.ipSettingsDenyCidrs.value = String(draft.denyCidrs || "");
  if (el.ipRuleSourceOrder) {
    el.ipRuleSourceOrder.value = String(draft.sourceOrder || "");
  }

  el.ipSettingsIPRuleSets.innerHTML = "";
  for (const item of Array.isArray(draft.ipRuleSets) ? draft.ipRuleSets : []) {
    el.ipSettingsIPRuleSets.appendChild(newIPRuleSetRow({
      id: String(item?.id || ""),
      name: String(item?.name || ""),
      mode: String(item?.mode || "manual"),
      priority: Number(item?.priority || 0),
      conflictPolicy: String(item?.conflictPolicy || DEFAULT_IP_RULE_CONFLICT_POLICY),
      allowCidrs: splitCSV(String(item?.allowCidrs || "")),
      denyCidrs: splitCSV(String(item?.denyCidrs || "")),
      allowAsns: splitCSV(String(item?.allowAsns || "")),
      denyAsns: splitCSV(String(item?.denyAsns || "")),
      denyReputationCidrs: splitCSV(String(item?.denyReputationCidrs || "")),
      allowCountries: splitCSV(String(item?.allowCountries || "")),
      countryIncludeIpv6: !!item?.countryIncludeIpv6,
      countryInterval: String(item?.countryInterval || "24h"),
      countrySource: String(item?.countrySource || "ipdeny")
    }));
  }

  el.ipSettingsIPCountryAutoUpdates.innerHTML = "";
  for (const item of Array.isArray(draft.ipCountryAutoUpdates) ? draft.ipCountryAutoUpdates : []) {
    el.ipSettingsIPCountryAutoUpdates.appendChild(newIPCountryAutoUpdateRow({
      id: String(item?.id || ""),
      ruleSetId: String(item?.ruleSetId || ""),
      list: String(item?.list || "allow"),
      countries: splitCSV(String(item?.countries || "")),
      interval: String(item?.interval || ""),
      source: String(item?.source || "ipdeny"),
      includeIpv6: !!item?.includeIpv6,
      enabled: !!item?.enabled
    }));
  }

  refreshIPRuleSetRowsMeta();
  refreshIPCountryAutoUpdateRowsMeta();
  renderIPSettingsOverview();
  ipSettingsDraftDirty = true;
  return true;
}

function clearAccountSecrets() {
  el.currentAdminPassword.value = "";
  el.newAdminPassword.value = "";
  el.confirmAdminPassword.value = "";
}

function fillAccountForm(account) {
  const info = account || {};
  el.currentAdminUsername.value = info.username || "-";
  if (!el.newAdminUsername.value || el.newAdminUsername.value === "-") {
    el.newAdminUsername.value = info.username || "";
  }
}

function renderDownloadModalOptions() {
  const currentAsset = el.certDownloadAsset?.value || "cert";
  const currentFormat = el.certDownloadFormat?.value || "pem";
  if (!el.certDownloadAsset || !el.certDownloadFormat) return;
  el.certDownloadAsset.innerHTML = [
    `<option value="cert">${escapeHtml(t("certAssetCert"))}</option>`,
    `<option value="fullchain">${escapeHtml(t("certAssetFullchain"))}</option>`,
    `<option value="chain">${escapeHtml(t("certAssetChain"))}</option>`,
    `<option value="key">${escapeHtml(t("certAssetKey"))}</option>`,
    `<option value="pubkey">${escapeHtml(t("certAssetPubkey"))}</option>`,
    `<option value="bundle">${escapeHtml(t("certAssetBundle"))}</option>`
  ].join("");
  el.certDownloadFormat.innerHTML = [
    `<option value="pem">${escapeHtml(t("certFormatPem"))}</option>`,
    `<option value="der">${escapeHtml(t("certFormatDer"))}</option>`,
    `<option value="zip">${escapeHtml(t("certFormatZip"))}</option>`,
    `<option value="pfx">${escapeHtml(t("certFormatPfx"))}</option>`,
    `<option value="p12">${escapeHtml(t("certFormatP12"))}</option>`,
    `<option value="jks">${escapeHtml(t("certFormatJks"))}</option>`
  ].join("");
  el.certDownloadAsset.value = currentAsset;
  if (el.certDownloadAsset.value !== currentAsset) el.certDownloadAsset.value = "cert";
  el.certDownloadFormat.value = currentFormat;
  if (el.certDownloadFormat.value !== currentFormat) el.certDownloadFormat.value = "pem";
}

function updateDownloadModalTarget() {
  if (!el.certDownloadTarget) return;
  const targetName = downloadModalCertName || "-";
  el.certDownloadTarget.textContent = `${t("certDownloadTarget")}: ${targetName}`;
}

function closeDownloadModal() {
  downloadModalCertID = "";
  downloadModalCertName = "";
  if (el.certDownloadPassword) el.certDownloadPassword.value = "";
  if (el.certDownloadModal) el.certDownloadModal.hidden = true;
}

function openDownloadModal(certID) {
  const item = certificates.find((cert) => cert.id === certID);
  if (!item) return;
  downloadModalCertID = item.id;
  downloadModalCertName = certificateDisplayName(item);
  renderDownloadModalOptions();
  updateDownloadModalTarget();
  el.certDownloadAsset.value = "cert";
  el.certDownloadFormat.value = "pem";
  el.certDownloadPassword.value = "";
  el.certDownloadModal.hidden = false;
  el.certDownloadAsset.focus();
}

function selectableSiteCertificates() {
  return certificates.filter((item) => item?.type === "self_signed" && item?.status === "active");
}

function selectableAdminTLSCertificates() {
  return certificates.filter((item) => {
    if (item?.status !== "active") return false;
    const certType = String(item?.type || "").toLowerCase();
    return certType === "self_signed" || certType === "acme";
  });
}

function certificateDisplayName(item) {
  const name = item?.name || item?.domains?.[0] || item?.id || "-";
  const domains = (item?.domains || []).join(", ");
  return domains ? `${name} (${domains})` : name;
}

function certificateLabelByID(id) {
  const cert = certificates.find((item) => item.id === id);
  if (!cert) return "-";
  return certificateDisplayName(cert);
}

function renderCertificateOptions(selectedID = "") {
  if (!el.certificateId) return;
  const selected = String(selectedID || el.certificateId.value || "");
  const domains = [
    document.getElementById("domain").value.trim().toLowerCase(),
    ...splitCSV(document.getElementById("additionalDomains").value).map((item) => item.toLowerCase())
  ].filter(Boolean);
  const options = [`<option value="">${escapeHtml(t("customCertNone"))}</option>`];
  const sorted = selectableSiteCertificates().slice().sort((a, b) => {
    const aDomains = (a.domains || []).map((item) => String(item || "").toLowerCase().trim()).filter(Boolean);
    const bDomains = (b.domains || []).map((item) => String(item || "").toLowerCase().trim()).filter(Boolean);

    const bestScore = (certDomains) => {
      let score = -1;
      for (const domain of domains) {
        for (const certDomain of certDomains) {
          const current = matchScore(certDomain, domain);
          if (current > score) score = current;
        }
      }
      return score;
    };
    const scoreA = bestScore(aDomains);
    const scoreB = bestScore(bDomains);
    if (scoreA !== scoreB) return scoreB - scoreA;
    return certificateDisplayName(a).localeCompare(certificateDisplayName(b));
  });

  for (const item of sorted) {
    options.push(`<option value="${escapeHtml(item.id)}">${escapeHtml(certificateDisplayName(item))}</option>`);
  }
  el.certificateId.innerHTML = options.join("");
  el.certificateId.value = selected;
  if (el.certificateId.value !== selected) {
    el.certificateId.value = "";
  }
}

async function ensureInterfaces() {
  if (cachedInterfaces) return;
  try {
    const data = await httpJSON("/api/interfaces");
    cachedInterfaces = Array.isArray(data?.interfaces) ? data.interfaces : [];
    renderInterfaceSelect(cachedInterfaces);
  } catch (_) {
    cachedInterfaces = [];
  }
}

function matchesInterfaceSearch(name, addrs, searchRE) {
  if (!searchRE) return true;
  if (searchRE.test(name)) return true;
  if (addrs && searchRE.test(addrs)) return true;
  return false;
}

function renderInterfaceSearchResults(ifaces) {
  const container = document.getElementById("bindInterfaceContainer");
  if (!container) return;
  const scrollArea = container.querySelector(".bind-interface-scroll");
  if (!scrollArea) return;

  // Read current selections and search term
  const selected = new Set();
  for (const cb of scrollArea.querySelectorAll('input[type="checkbox"]')) {
    if (cb.checked && cb.value) selected.add(cb.value);
  }
  const searchInput = container.querySelector(".bind-interface-search-input");
  const searchTerm = (searchInput && searchInput.value.trim().toLowerCase()) || "";
  const searchRE = searchTerm ? new RegExp(searchTerm.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i") : null;

  // "All Interfaces" is selected when no specific interface is checked
  const allSelected = selected.has("__all__") || selected.size === 0;
  const hasIndividualSelection = !allSelected && selected.size > 0;

  // Filter
  const filtered = searchTerm
    ? ifaces.filter((iface) => {
        const name = String(iface.name || "").trim();
        if (!name) return false;
        const addrs = Array.isArray(iface.addrs) ? iface.addrs.join(", ") : "";
        return matchesInterfaceSearch(name, addrs, searchRE);
      })
    : ifaces;

  // Build scroll content only (search input above stays untouched)
  let html = `<div class="bind-interface-all-row">
    <label class="bind-iface-checkbox">
      <input type="checkbox" value="__all__" ${allSelected ? 'checked' : ''} data-iface-all="true" />
      <span class="iface-name">${escapeHtml(t("bindInterfaceAll"))}</span>
    </label>
  </div>`;
  html += `<div class="bind-interface-list">`;
  if (searchTerm && filtered.length === 0) {
    html += `<div class="bind-interface-no-match">${escapeHtml(t("bindInterfaceNoMatch"))}</div>`;
  }
  for (const iface of filtered) {
    const name = String(iface.name || "").trim();
    if (!name) continue;
    const addrs = Array.isArray(iface.addrs) ? iface.addrs.join(", ") : "";
    const isSelected = hasIndividualSelection && selected.has(name);
    html += `<label class="bind-iface-checkbox">
      <input type="checkbox" name="bindInterface" value="${escapeHtml(name)}" ${isSelected ? 'checked' : ''} />
      <span class="iface-name">${escapeHtml(name)}</span>
      ${addrs ? `<span class="iface-addrs" title="${escapeHtml(addrs)}">${escapeHtml(addrs)}</span>` : ''}
    </label>`;
  }
  html += `</div>`;
  html += `<div class="bind-interface-actions">
    <button type="button" class="btn-ghost btn-sm" id="selectAllBindInterfaces">${escapeHtml(t("selectAll"))}</button>
    <button type="button" class="btn-ghost btn-sm" id="deselectAllBindInterfaces">${escapeHtml(t("deselectAll"))}</button>
  </div>`;

  scrollArea.innerHTML = html;

  // Wire up checkbox handlers
  const allCheckbox = scrollArea.querySelector('input[data-iface-all="true"]');
  const ifaceCheckboxes = scrollArea.querySelectorAll('input[name="bindInterface"]');

  if (allCheckbox) {
    allCheckbox.addEventListener("change", function() {
      if (this.checked) {
        for (const cb of ifaceCheckboxes) cb.checked = false;
      }
    });
  }

  for (const cb of ifaceCheckboxes) {
    cb.addEventListener("change", function() {
      if (this.checked && allCheckbox) {
        allCheckbox.checked = false;
      }
      if (!this.checked && allCheckbox) {
        const anyChecked = [...ifaceCheckboxes].some(c => c.checked);
        if (!anyChecked) allCheckbox.checked = true;
      }
    });
  }

  const selectAllBtn = document.getElementById("selectAllBindInterfaces");
  const deselectAllBtn = document.getElementById("deselectAllBindInterfaces");

  if (selectAllBtn) {
    selectAllBtn.addEventListener("click", function() {
      for (const cb of ifaceCheckboxes) cb.checked = true;
      if (allCheckbox) allCheckbox.checked = false;
    });
  }
  if (deselectAllBtn) {
    deselectAllBtn.addEventListener("click", function() {
      for (const cb of ifaceCheckboxes) cb.checked = false;
      if (allCheckbox) allCheckbox.checked = true;
    });
  }
}

function renderInterfaceSelect(ifaces) {
  const container = document.getElementById("bindInterfaceContainer");
  if (!container) return;

  // Determine which values should be selected
  const selected = new Set();
  const hasPending = pendingBindInterfaceValues !== null;
  if (hasPending) {
    for (const v of pendingBindInterfaceValues) selected.add(v);
  } else {
    for (const cb of container.querySelectorAll('input[type="checkbox"]')) {
      if (cb.checked && cb.value) selected.add(cb.value);
    }
  }

  const allSelected = hasPending
    ? pendingBindInterfaceValues.length === 0
    : selected.has("__all__") || selected.size === 0;
  const hasIndividualSelection = hasPending
    ? pendingBindInterfaceValues.length > 0
    : !allSelected && selected.size > 0;

  // Build full UI: search input (static) + scroll area (replaced on each search)
  let html = `<div class="bind-interface-search">
    <input type="text" class="bind-interface-search-input" placeholder="${escapeHtml(t("bindInterfaceSearch"))}" autocomplete="off" />
  </div>`;
  html += `<div class="bind-interface-scroll">`;
  html += `<div class="bind-interface-all-row">
    <label class="bind-iface-checkbox">
      <input type="checkbox" value="__all__" ${allSelected ? 'checked' : ''} data-iface-all="true" />
      <span class="iface-name">${escapeHtml(t("bindInterfaceAll"))}</span>
    </label>
  </div>`;
  html += `<div class="bind-interface-list">`;
  for (const iface of ifaces) {
    const name = String(iface.name || "").trim();
    if (!name) continue;
    const addrs = Array.isArray(iface.addrs) ? iface.addrs.join(", ") : "";
    const isSelected = hasIndividualSelection && selected.has(name);
    html += `<label class="bind-iface-checkbox">
      <input type="checkbox" name="bindInterface" value="${escapeHtml(name)}" ${isSelected ? 'checked' : ''} />
      <span class="iface-name">${escapeHtml(name)}</span>
      ${addrs ? `<span class="iface-addrs" title="${escapeHtml(addrs)}">${escapeHtml(addrs)}</span>` : ''}
    </label>`;
  }
  html += `</div>`;
  html += `<div class="bind-interface-actions">
    <button type="button" class="btn-ghost btn-sm" id="selectAllBindInterfaces">${escapeHtml(t("selectAll"))}</button>
    <button type="button" class="btn-ghost btn-sm" id="deselectAllBindInterfaces">${escapeHtml(t("deselectAll"))}</button>
  </div>`;
  html += `</div>`;

  container.innerHTML = html;

  // Wire up full-render event handlers
  const scrollArea = container.querySelector(".bind-interface-scroll");
  const allCheckbox = scrollArea.querySelector('input[data-iface-all="true"]');
  const ifaceCheckboxes = scrollArea.querySelectorAll('input[name="bindInterface"]');

  if (allCheckbox) {
    allCheckbox.addEventListener("change", function() {
      if (this.checked) {
        for (const cb of ifaceCheckboxes) cb.checked = false;
      }
    });
  }
  for (const cb of ifaceCheckboxes) {
    cb.addEventListener("change", function() {
      if (this.checked && allCheckbox) {
        allCheckbox.checked = false;
      }
      if (!this.checked && allCheckbox) {
        const anyChecked = [...ifaceCheckboxes].some(c => c.checked);
        if (!anyChecked) allCheckbox.checked = true;
      }
    });
  }
  const selectAllBtn = document.getElementById("selectAllBindInterfaces");
  const deselectAllBtn = document.getElementById("deselectAllBindInterfaces");
  if (selectAllBtn) {
    selectAllBtn.addEventListener("click", function() {
      for (const cb of ifaceCheckboxes) cb.checked = true;
      if (allCheckbox) allCheckbox.checked = false;
    });
  }
  if (deselectAllBtn) {
    deselectAllBtn.addEventListener("click", function() {
      for (const cb of ifaceCheckboxes) cb.checked = false;
      if (allCheckbox) allCheckbox.checked = true;
    });
  }

  // Wire up search input — only updates the scroll area, keeps input focused
  const searchInput = container.querySelector(".bind-interface-search-input");
  if (searchInput) {
    searchInput.addEventListener("input", function() {
      // Persist current checkbox selections into pending state
      const scroll = container.querySelector(".bind-interface-scroll");
      const currentlySelected = new Set();
      for (const cb of (scroll || container).querySelectorAll('input[name="bindInterface"]')) {
        if (cb.checked) currentlySelected.add(cb.value);
      }
      const allCb = scroll && scroll.querySelector('input[data-iface-all="true"]');
      pendingBindInterfaceValues = (allCb && allCb.checked) || currentlySelected.size === 0
        ? []
        : [...currentlySelected].filter(Boolean);
      renderInterfaceSearchResults(ifaces);
    });
  }
}

function renderInterfaceOptions() {
  ensureInterfaces();
}

function resetBindInterfaceCheckboxes() {
  const container = document.getElementById("bindInterfaceContainer");
  if (!container) return;
  const allCheckbox = container.querySelector('input[data-iface-all="true"]');
  if (allCheckbox) allCheckbox.checked = true;
  for (const cb of container.querySelectorAll('input[name="bindInterface"]')) {
    cb.checked = false;
  }
}

function renderAdminTLSCertificateOptions(selectedID = "") {
  if (!el.adminTlsCertificateId) return;
  const selected = String(selectedID || el.adminTlsCertificateId.value || "");
  const options = [`<option value="">${escapeHtml(t("customCertNone"))}</option>`];
  const sorted = selectableAdminTLSCertificates().slice().sort((a, b) => {
    return certificateDisplayName(a).localeCompare(certificateDisplayName(b));
  });
  for (const item of sorted) {
    options.push(`<option value="${escapeHtml(item.id)}">${escapeHtml(certificateDisplayName(item))}</option>`);
  }
  el.adminTlsCertificateId.innerHTML = options.join("");
  el.adminTlsCertificateId.value = selected;
  if (el.adminTlsCertificateId.value !== selected) {
    el.adminTlsCertificateId.value = "";
  }
}

function wildcardMatches(certDomain, targetDomain) {
  if (!certDomain.startsWith("*.")) return false;
  const suffix = certDomain.slice(2);
  if (!suffix || !targetDomain.endsWith(`.${suffix}`)) return false;
  const left = targetDomain.slice(0, targetDomain.length - suffix.length - 1);
  return left.length > 0 && !left.includes(".");
}

function matchScore(certDomain, targetDomain) {
  if (!certDomain || !targetDomain) return -1;
  if (certDomain === targetDomain) return 10000 + certDomain.length;
  if (wildcardMatches(certDomain, targetDomain)) return 5000 + certDomain.length;
  return -1;
}

function setActiveView(view) {
  const nextView = el.viewPanels.some((panel) => panel.dataset.viewPanel === view) ? view : "overview";
  activeView = nextView;
  localStorage.setItem("fp_view", activeView);
  for (const btn of el.navButtons) {
    btn.classList.toggle("active", btn.dataset.view === activeView);
  }
  for (const panel of el.viewPanels) {
    panel.classList.toggle("active", panel.dataset.viewPanel === activeView);
  }
  // Disconnect live log stream when leaving logs view
  if (activeView !== "logs" && el.logLiveEnabled?.checked) {
    el.logLiveEnabled.checked = false;
    disconnectLogStream();
  }
}

function applyLang() {
  document.documentElement.lang = lang;
  el.langBtn.textContent = LANG_SWITCH_LABEL[lang] || "EN";
  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.dataset.i18n);
  }
  for (const node of document.querySelectorAll("[data-placeholder]")) {
    node.placeholder = t(node.dataset.placeholder);
  }
  el.formTitle.textContent = editingId ? t("formEdit") : t("formCreate");
  el.submitBtn.textContent = editingId ? t("update") : t("create");
  renderDownloadModalOptions();
  updateDownloadModalTarget();
  renderCertificateOptions();
  renderInterfaceOptions();
  renderAdminTLSCertificateOptions();
  renderSiteIPRuleSetOptions();
  const creatorRow = getIPRuleSetCreatorRow();
  const creatorTitle = creatorRow?.querySelector(".ip-rule-card-title");
  if (creatorTitle) creatorTitle.textContent = ipRuleSetEditingIndex >= 0 ? t("ipRuleEditorEditTitle") : t("addIPRuleSet");
  if (creatorRow) updateIPRuleSetRowMeta(creatorRow);
  updateIPRuleSetEditorState();
  refreshIPRuleSetRowsMeta();
  refreshIPCountryAutoUpdateRowsMeta();
  renderIPSettingsOverview();
  renderSites();
  renderCertificates();
  renderBackups();
  renderLogs();
}

function newUpstreamRow(data = {}) {
  const parsed = parseUpstreamForForm(data.url || "");
  const port = data.port || parsed.port || "";
  const address = data.url ? parsed.address : "";
  const row = document.createElement("div");
  row.className = "line-item";
  row.innerHTML = `
    <label><span>${escapeHtml(t("upstreamAddress"))}</span><input class="upstream-url" type="text" placeholder="127.0.0.1 or http://127.0.0.1" value="${escapeHtml(address)}" /></label>
    <label><span>${escapeHtml(t("upstreamPort"))}</span><input class="upstream-port" type="number" min="1" max="65535" value="${escapeHtml(String(port))}" /></label>
    <label><span>${escapeHtml(t("upstreamWeight"))}</span><input class="upstream-weight" type="number" min="1" value="${Number(data.weight || 1)}" /></label>
    <button type="button" class="btn-danger remove-row">-</button>
  `;
  row.querySelector(".remove-row").addEventListener("click", () => {
    row.remove();
  });
  return row;
}

function newRouteRow(data = {}) {
  const parsed = parseUpstreamForForm(data.upstream || "");
  const routePort = data.upstreamPort || parsed.port || "";
  const routeAddress = data.upstream ? parsed.address : "";
  const routeUpstreamsText = formatWeightedUpstreamsCSV(data.upstreams || []);
  const routeMethodsText = Array.isArray(data.methods) ? data.methods.join(", ") : "";
  const row = document.createElement("div");
  row.className = "line-item route";
  row.innerHTML = `
    <label><span>${escapeHtml(t("routeMatch"))}</span>
      <select class="route-match">
        <option value="prefix">prefix</option>
        <option value="exact">exact</option>
        <option value="regex">regex</option>
      </select>
    </label>
    <label><span>${escapeHtml(t("routePath"))}</span><input class="route-path" type="text" placeholder="/api" value="${escapeHtml(data.path || "")}" /></label>
    <label><span>${escapeHtml(t("routeUpstream"))}</span><input class="route-upstream" type="text" placeholder="127.0.0.1 or https://127.0.0.1" value="${escapeHtml(routeAddress)}" /></label>
    <label><span>${escapeHtml(t("routePort"))}</span><input class="route-upstream-port" type="number" min="1" max="65535" value="${escapeHtml(String(routePort))}" /></label>
    <label><span>${escapeHtml(t("routeLb"))}</span>
      <select class="route-lb-strategy">
        <option value="">default</option>
        <option value="round_robin">round_robin</option>
        <option value="weighted_round_robin">weighted_round_robin</option>
        <option value="least_conn">least_conn</option>
        <option value="ip_hash">ip_hash</option>
        <option value="random">random</option>
      </select>
    </label>
    <label><span>${escapeHtml(t("routeUpstreams"))}</span><input class="route-upstreams" type="text" placeholder="10.0.0.2:8080#2, 10.0.0.3:8080#1" value="${escapeHtml(routeUpstreamsText)}" /></label>
    <label><span>${escapeHtml(t("routePriority"))}</span><input class="route-priority" type="number" value="${Number(data.priority || 0)}" /></label>
    <button type="button" class="btn-danger remove-row">-</button>
    <details class="route-advanced">
      <summary>${escapeHtml(t("advancedRouteOptions"))}</summary>
      <div class="row2">
        <label><span>${escapeHtml(t("routeMethods"))}</span><input class="route-methods" type="text" placeholder="GET, POST" value="${escapeHtml(routeMethodsText)}" /></label>
        <label><span>${escapeHtml(t("routeHeader"))}</span><input class="route-header" type="text" value="${escapeHtml(data.header || "")}" /></label>
      </div>
      <div class="row3">
        <label><span>${escapeHtml(t("routeHeaderValue"))}</span><input class="route-header-value" type="text" value="${escapeHtml(data.headerValue || "")}" /></label>
        <label><span>${escapeHtml(t("routeCookie"))}</span><input class="route-cookie" type="text" value="${escapeHtml(data.cookie || "")}" /></label>
        <label><span>${escapeHtml(t("routeCookieValue"))}</span><input class="route-cookie-value" type="text" value="${escapeHtml(data.cookieValue || "")}" /></label>
      </div>
      <div class="row3">
        <label><span>${escapeHtml(t("routeQuery"))}</span><input class="route-query" type="text" value="${escapeHtml(data.query || "")}" /></label>
        <label><span>${escapeHtml(t("routeQueryValue"))}</span><input class="route-query-value" type="text" value="${escapeHtml(data.queryValue || "")}" /></label>
        <span></span>
      </div>
      <div class="row2">
        <label><span>${escapeHtml(t("routeRewritePattern"))}</span><input class="route-rewrite-pattern" type="text" value="${escapeHtml(data.rewritePattern || "")}" /></label>
        <label><span>${escapeHtml(t("routeRewriteReplacement"))}</span><input class="route-rewrite-replacement" type="text" value="${escapeHtml(data.rewriteReplacement || "")}" /></label>
      </div>
    </details>
  `;
  row.querySelector(".route-match").value = data.match || "prefix";
  row.querySelector(".route-lb-strategy").value = data.loadBalanceStrategy || "";
  const hasAdvanced = routeMethodsText ||
    data.header || data.headerValue || data.cookie || data.cookieValue || data.query || data.queryValue ||
    data.rewritePattern || data.rewriteReplacement;
  if (hasAdvanced) {
    row.querySelector(".route-advanced").open = true;
  }
  row.querySelector(".remove-row").addEventListener("click", () => row.remove());
  return row;
}

function newHeaderRow(data = {}) {
  const row = document.createElement("div");
  row.className = "line-item header-item";
  row.innerHTML = `
    <label><span>${escapeHtml(t("headerName"))}</span><input class="header-name" type="text" value="${escapeHtml(data.name || "")}" /></label>
    <label style="grid-column: span 1"><span>${escapeHtml(t("headerValue"))}</span><input class="header-value" type="text" value="${escapeHtml(data.value || "")}" /></label>
    <button type="button" class="btn-danger remove-row">-</button>
  `;
  row.querySelector(".remove-row").addEventListener("click", () => row.remove());
  return row;
}

function newIPRuleSetRow(data = {}, options = {}) {
  const isCreator = !!options.isCreator;
  const row = document.createElement("div");
  row.className = `ip-rule-card${isCreator ? " is-creator" : ""}`;
  row.innerHTML = `
    <div class="ip-rule-card-head">
      <strong class="ip-rule-card-title"></strong>
      ${isCreator ? "" : '<button type="button" class="btn-danger remove-row">-</button>'}
    </div>
    <div class="row2">
      <label>
        <span data-i18n="ipRuleSetModeLabel">${escapeHtml(t("ipRuleSetModeLabel"))}</span>
        <select class="ip-rule-mode">
          <option value="manual" data-i18n="ipRuleSetModeManual">${escapeHtml(t("ipRuleSetModeManual"))}</option>
          <option value="country" data-i18n="ipRuleSetModeCountry">${escapeHtml(t("ipRuleSetModeCountry"))}</option>
        </select>
      </label>
      <span></span>
    </div>
    <div class="row3">
      <input class="ip-rule-id" type="hidden" value="${escapeHtml(data.id || "")}" />
      <label>
        <span data-i18n="name">${escapeHtml(t("name"))}</span>
        <input class="ip-rule-name" type="text" value="${escapeHtml(data.name || "")}" />
      </label>
      <label>
        <span data-i18n="ipRuleSetPriorityLabel">${escapeHtml(t("ipRuleSetPriorityLabel"))}</span>
        <input class="ip-rule-priority" type="number" value="${Number(data.priority || 0)}" />
      </label>
    </div>
    <div class="row2">
      <label>
        <span data-i18n="ipRuleSetConflictPolicyLabel">${escapeHtml(t("ipRuleSetConflictPolicyLabel"))}</span>
        <select class="ip-rule-conflict-policy">
          <option value="allow_first" data-i18n="ipRuleSetConflictPolicyAllowFirst">${escapeHtml(t("ipRuleSetConflictPolicyAllowFirst"))}</option>
          <option value="deny_first" data-i18n="ipRuleSetConflictPolicyDenyFirst">${escapeHtml(t("ipRuleSetConflictPolicyDenyFirst"))}</option>
        </select>
      </label>
      <span></span>
    </div>
    <div class="ip-rule-conflict-dnd">
      <div class="ip-rule-conflict-dnd-title" data-i18n="ipRuleSetConflictDragLabel">${escapeHtml(t("ipRuleSetConflictDragLabel"))}</div>
      <div class="ip-rule-conflict-priority-list">
        <div class="ip-rule-conflict-priority-item" draggable="true" data-kind="allow">
          <span class="ip-rule-conflict-priority-handle">::</span>
          <span data-i18n="ipRuleSetConflictAllowModule">${escapeHtml(t("ipRuleSetConflictAllowModule"))}</span>
        </div>
        <div class="ip-rule-conflict-priority-item" draggable="true" data-kind="deny">
          <span class="ip-rule-conflict-priority-handle">::</span>
          <span data-i18n="ipRuleSetConflictDenyModule">${escapeHtml(t("ipRuleSetConflictDenyModule"))}</span>
        </div>
      </div>
      <div class="hint ip-rule-conflict-dnd-hint" data-i18n="ipRuleSetConflictDragHint">${escapeHtml(t("ipRuleSetConflictDragHint"))}</div>
    </div>
    <div class="row2 ip-rule-cidr-fields">
      <label>
        <span data-i18n="ipRuleSetAllowLabel">${escapeHtml(t("ipRuleSetAllowLabel"))}</span>
        <textarea class="ip-rule-allow" rows="3">${escapeHtml((data.allowCidrs || []).join("\n"))}</textarea>
      </label>
      <label>
        <span data-i18n="ipRuleSetDenyLabel">${escapeHtml(t("ipRuleSetDenyLabel"))}</span>
        <textarea class="ip-rule-deny" rows="3">${escapeHtml((data.denyCidrs || []).join("\n"))}</textarea>
      </label>
    </div>
    <div class="row3 ip-rule-cidr-fields">
      <label>
        <span data-i18n="allowAsnsLabel">${escapeHtml(t("allowAsnsLabel"))}</span>
        <textarea class="ip-rule-allow-asns" rows="2">${escapeHtml((ensureStringList(data.allowAsns) || []).join("\n"))}</textarea>
      </label>
      <label>
        <span data-i18n="denyAsnsLabel">${escapeHtml(t("denyAsnsLabel"))}</span>
        <textarea class="ip-rule-deny-asns" rows="2">${escapeHtml((ensureStringList(data.denyAsns) || []).join("\n"))}</textarea>
      </label>
      <label>
        <span data-i18n="denyReputationCidrsLabel">${escapeHtml(t("denyReputationCidrsLabel"))}</span>
        <textarea class="ip-rule-deny-reputation-cidrs" rows="2">${escapeHtml((ensureStringList(data.denyReputationCidrs) || []).join("\n"))}</textarea>
      </label>
    </div>
    <div class="row2 ip-rule-country-fields">
      <label>
        <span data-i18n="ipRuleSetAllowCountriesLabel">${escapeHtml(t("ipRuleSetAllowCountriesLabel"))}</span>
        <input class="ip-rule-allow-countries" type="text" value="${escapeHtml((ensureStringList(data.allowCountries) || []).join(", "))}" placeholder="CN, SG" />
      </label>
      <span></span>
    </div>
    <div class="row3 ip-rule-country-fields">
      <label class="toggle-row">
        <input class="ip-rule-country-include-ipv6" type="checkbox" ${data.countryIncludeIpv6 ? "checked" : ""} />
        <span data-i18n="ipRuleSetCountryIncludeIpv6">${escapeHtml(t("ipRuleSetCountryIncludeIpv6"))}</span>
      </label>
      <label>
        <span data-i18n="ipRuleSetCountryInterval">${escapeHtml(t("ipRuleSetCountryInterval"))}</span>
        <input class="ip-rule-country-interval" type="text" value="${escapeHtml(data.countryInterval || "24h")}" placeholder="24h" />
      </label>
      <label>
        <span data-i18n="ipRuleSetCountrySource">${escapeHtml(t("ipRuleSetCountrySource"))}</span>
        <select class="ip-rule-country-source">
          <option value="ipdeny" data-i18n="ipCountryTaskSourceIpdeny">${escapeHtml(t("ipCountryTaskSourceIpdeny"))}</option>
        </select>
      </label>
    </div>
    <div class="ip-rule-card-meta">
      <span class="ip-chip ip-chip-allow ip-rule-allow-count"></span>
      <span class="ip-chip ip-chip-deny ip-rule-deny-count"></span>
      <span class="ip-chip ip-chip-allow ip-rule-country-count"></span>
      <span class="ip-chip ip-chip-issue ip-rule-issue-count"></span>
    </div>
  `;
  const nameInput = row.querySelector(".ip-rule-name");
  const idInput = row.querySelector(".ip-rule-id");
  const modeSelect = row.querySelector(".ip-rule-mode");
  const titleNode = row.querySelector(".ip-rule-card-title");
  if (titleNode && isCreator) {
    titleNode.textContent = t("addIPRuleSet");
  }
  nameInput?.addEventListener("input", () => {
    if (!idInput) return;
    idInput.value = suggestRuleSetID(nameInput.value || "");
  });
  if (modeSelect) {
    modeSelect.value = normalizeRuleMode(data.mode);
  }
  const countrySource = row.querySelector(".ip-rule-country-source");
  if (countrySource) {
    countrySource.value = String(data.countrySource || "ipdeny").trim().toLowerCase() || "ipdeny";
  }
  const conflictPolicy = row.querySelector(".ip-rule-conflict-policy");
  if (conflictPolicy) {
    conflictPolicy.value = normalizeIPRuleConflictPolicy(data.conflictPolicy || DEFAULT_IP_RULE_CONFLICT_POLICY);
  }
  applyConflictPriorityListOrder(row, conflictPolicy?.value || DEFAULT_IP_RULE_CONFLICT_POLICY);
  setupConflictPriorityDrag(row);
  if (!isCreator) {
    row.querySelector(".remove-row").addEventListener("click", () => {
      markIPSettingsDraftDirty();
      row.remove();
      refreshIPRuleSetRowsMeta();
      renderIPSettingsOverview();
    });
  }
  row.addEventListener("input", () => {
    updateIPRuleSetRowMeta(row);
    if (!isCreator) {
      markIPSettingsDraftDirty();
      renderIPSettingsOverview();
      showIPSettingsSuccess("");
    }
  });
  modeSelect?.addEventListener("change", () => {
    updateIPRuleSetModeUI(row);
    updateIPRuleSetRowMeta(row);
    if (!isCreator) {
      markIPSettingsDraftDirty();
      renderIPSettingsOverview();
      showIPSettingsSuccess("");
    }
  });
  conflictPolicy?.addEventListener("change", () => {
    applyConflictPriorityListOrder(row, conflictPolicy.value);
    updateIPRuleSetRowMeta(row);
    if (!isCreator) {
      markIPSettingsDraftDirty();
      renderIPSettingsOverview();
      showIPSettingsSuccess("");
    }
  });
  updateIPRuleSetModeUI(row);
  updateIPRuleSetRowMeta(row);
  return row;
}

function resetIPRuleSetCreator(data = {}) {
  if (!el.ipRuleSetCreatorHost) return;
  el.ipRuleSetCreatorHost.innerHTML = "";
  el.ipRuleSetCreatorHost.appendChild(newIPRuleSetRow(data, { isCreator: true }));
  updateIPRuleSetEditorState();
}

function getIPRuleSetCreatorRow() {
  return el.ipRuleSetCreatorHost?.firstElementChild || null;
}

function updateIPRuleSetManageListEmptyState() {
  if (!el.ipRuleSetManageCards) return;
  const empty = el.ipSettingsIPRuleSets.children.length === 0;
  el.ipRuleSetManageCards.dataset.empty = empty ? "true" : "false";
  el.ipRuleSetManageCards.dataset.emptyLabel = t("ipRulesListEmpty");
}

function updateIPRuleSetEditorState() {
  if (el.ipRuleEditorTitle) {
    el.ipRuleEditorTitle.textContent = ipRuleSetEditingIndex >= 0 ? t("ipRuleEditorEditTitle") : t("addIPRuleSet");
  }
  if (el.addIPPageRuleSetBtn) {
    el.addIPPageRuleSetBtn.textContent = ipRuleSetEditingIndex >= 0 ? t("update") : t("addIPRuleSet");
  }
  if (el.ipRuleCreatorCancelBtn) {
    el.ipRuleCreatorCancelBtn.hidden = ipRuleSetEditingIndex < 0;
  }
}

function beginEditIPRuleSet(index) {
  const row = el.ipSettingsIPRuleSets?.children?.[index];
  if (!row) return;
  const parsed = parseIPRuleSetRow(row);
  if (!parsed) return;
  ipRuleSetEditingIndex = index;
  resetIPRuleSetCreator(parsed);
  clearIPSettingsNotice();
}

function cancelEditIPRuleSet() {
  ipRuleSetEditingIndex = -1;
  resetIPRuleSetCreator();
}

function applyIPRuleSetFromEditor() {
  const creatorRow = getIPRuleSetCreatorRow();
  const parsed = creatorRow ? parseIPRuleSetRow(creatorRow) : null;
  if (!parsed) {
    showIPSettingsError(t("ipRuleCreatorEmpty"));
    return false;
  }
  clearIPSettingsNotice();
  markIPSettingsDraftDirty();
  const nextRow = newIPRuleSetRow(parsed);
  if (ipRuleSetEditingIndex >= 0 && el.ipSettingsIPRuleSets?.children?.[ipRuleSetEditingIndex]) {
    el.ipSettingsIPRuleSets.replaceChild(nextRow, el.ipSettingsIPRuleSets.children[ipRuleSetEditingIndex]);
  } else {
    el.ipSettingsIPRuleSets.appendChild(nextRow);
  }
  ipRuleSetEditingIndex = -1;
  refreshIPRuleSetRowsMeta();
  renderIPSettingsOverview();
  resetIPRuleSetCreator();
  return true;
}

function applyConflictPriorityListOrder(row, policy) {
  const list = row.querySelector(".ip-rule-conflict-priority-list");
  if (!list) return;
  const itemMap = new Map(
    [...list.querySelectorAll(".ip-rule-conflict-priority-item")]
      .map((item) => [String(item.dataset.kind || "").toLowerCase(), item])
  );
  const order = conflictPriorityOrderByPolicy(policy);
  for (const kind of order) {
    const item = itemMap.get(kind);
    if (item) {
      list.appendChild(item);
    }
  }
  updateConflictPriorityListVisualState(list);
}

function conflictPriorityKindsFromList(row) {
  const list = row.querySelector(".ip-rule-conflict-priority-list");
  if (!list) return [];
  return [...list.querySelectorAll(".ip-rule-conflict-priority-item")]
    .map((item) => String(item.dataset.kind || "").toLowerCase())
    .filter(Boolean);
}

function syncConflictPolicyFromPriorityList(row, emitInput = true) {
  const select = row.querySelector(".ip-rule-conflict-policy");
  if (!select) return;
  const order = conflictPriorityKindsFromList(row);
  select.value = conflictPolicyByPriorityOrder(order);
  if (emitInput) {
    select.dispatchEvent(new Event("input", { bubbles: true }));
  }
}

function updateConflictPriorityListVisualState(list) {
  const items = [...list.querySelectorAll(".ip-rule-conflict-priority-item")];
  items.forEach((item, idx) => {
    item.classList.toggle("is-top", idx === 0);
    item.classList.toggle("is-bottom", idx === items.length - 1);
  });
}

function findConflictDragInsertBefore(list, draggingItem, y) {
  const candidates = [...list.querySelectorAll(".ip-rule-conflict-priority-item:not(.dragging)")];
  let closest = { offset: Number.NEGATIVE_INFINITY, node: null };
  for (const item of candidates) {
    if (item === draggingItem) continue;
    const rect = item.getBoundingClientRect();
    const offset = y - rect.top - rect.height / 2;
    if (offset < 0 && offset > closest.offset) {
      closest = { offset, node: item };
    }
  }
  return closest.node;
}

function setupConflictPriorityDrag(row) {
  const list = row.querySelector(".ip-rule-conflict-priority-list");
  if (!list) return;
  let draggingItem = null;

  for (const item of [...list.querySelectorAll(".ip-rule-conflict-priority-item")]) {
    item.addEventListener("dragstart", () => {
      draggingItem = item;
      item.classList.add("dragging");
    });
    item.addEventListener("dragend", () => {
      item.classList.remove("dragging");
      draggingItem = null;
      updateConflictPriorityListVisualState(list);
      syncConflictPolicyFromPriorityList(row, true);
    });
  }

  list.addEventListener("dragover", (event) => {
    if (!draggingItem) return;
    event.preventDefault();
    const before = findConflictDragInsertBefore(list, draggingItem, event.clientY);
    if (before) {
      list.insertBefore(draggingItem, before);
    } else {
      list.appendChild(draggingItem);
    }
    updateConflictPriorityListVisualState(list);
  });
}

function updateIPRuleSetModeUI(row) {
  const mode = normalizeRuleMode(row.querySelector(".ip-rule-mode")?.value);
  const cidrNodes = row.querySelectorAll(".ip-rule-cidr-fields");
  const countryNodes = row.querySelectorAll(".ip-rule-country-fields");
  const showCIDR = mode === "manual";
  const showCountry = mode === "country";
  for (const node of cidrNodes) {
    node.style.display = showCIDR ? "" : "none";
  }
  for (const node of countryNodes) {
    node.style.display = showCountry ? "" : "none";
  }
}

function parseIPRuleSetRow(row) {
  const mode = normalizeRuleMode(row.querySelector(".ip-rule-mode")?.value);
  const idInput = row.querySelector(".ip-rule-id");
  const idRaw = idInput?.value?.trim() || "";
  const name = row.querySelector(".ip-rule-name")?.value?.trim() || "";
  const id = idRaw || suggestRuleSetID(name);
  if (idInput && id && idInput.value.trim() !== id) {
    idInput.value = id;
  }
  const priority = Number(row.querySelector(".ip-rule-priority")?.value || 0);
  const conflictPolicy = normalizeIPRuleConflictPolicy(row.querySelector(".ip-rule-conflict-policy")?.value || DEFAULT_IP_RULE_CONFLICT_POLICY);
  const allow = parseIPTokensWithIssues(row.querySelector(".ip-rule-allow")?.value || "");
  const deny = parseIPTokensWithIssues(row.querySelector(".ip-rule-deny")?.value || "");
  const allowAsns = parseASNTokensWithIssues(row.querySelector(".ip-rule-allow-asns")?.value || "");
  const denyAsns = parseASNTokensWithIssues(row.querySelector(".ip-rule-deny-asns")?.value || "");
  const denyReputationCidrs = parseIPTokensWithIssues(row.querySelector(".ip-rule-deny-reputation-cidrs")?.value || "");
  const allowCountries = parseCountryCodesWithIssues(row.querySelector(".ip-rule-allow-countries")?.value || "");
  const countryIncludeIpv6 = !!row.querySelector(".ip-rule-country-include-ipv6")?.checked;
  const countryInterval = row.querySelector(".ip-rule-country-interval")?.value?.trim() || "24h";
  const countrySourceRaw = row.querySelector(".ip-rule-country-source")?.value || "ipdeny";
  const countrySource = String(countrySourceRaw || "ipdeny").trim().toLowerCase() || "ipdeny";
  if (!id && !name && allow.tokens.length === 0 && deny.tokens.length === 0 && allowAsns.tokens.length === 0 && denyAsns.tokens.length === 0 && denyReputationCidrs.tokens.length === 0 && allowCountries.tokens.length === 0) return null;

  const overlap = [];
  const denySet = new Set(deny.tokens.map((item) => item.toLowerCase()));
  for (const item of allow.tokens) {
    if (denySet.has(item.toLowerCase())) {
      overlap.push(item);
    }
  }
  const countryInvalid = [];
  if (countrySource !== "ipdeny") {
    countryInvalid.push(`source=${countrySource}`);
  }

  return {
    id,
    name,
    priority: Number.isFinite(priority) ? Math.trunc(priority) : 0,
    conflictPolicy,
    mode,
    allowCidrs: allow.tokens,
    denyCidrs: deny.tokens,
    allowAsns: allowAsns.tokens,
    denyAsns: denyAsns.tokens,
    denyReputationCidrs: denyReputationCidrs.tokens,
    allowCountries: allowCountries.tokens,
    denyCountries: [],
    countryIncludeIpv6,
    countryInterval,
    countrySource,
    diagnostics: {
      invalid: uniqCaseInsensitive([...allow.invalid, ...deny.invalid, ...allowAsns.invalid, ...denyAsns.invalid, ...denyReputationCidrs.invalid, ...allowCountries.invalid, ...countryInvalid]),
      duplicates: uniqCaseInsensitive([...allow.duplicates, ...deny.duplicates, ...allowAsns.duplicates, ...denyAsns.duplicates, ...denyReputationCidrs.duplicates, ...allowCountries.duplicates]),
      overlap: uniqCaseInsensitive(overlap)
    }
  };
}

function updateIPRuleSetRowMeta(row) {
  const parsed = parseIPRuleSetRow(row) || { allowCidrs: [], denyCidrs: [], allowCountries: [], denyCountries: [], diagnostics: { invalid: [], duplicates: [], overlap: [] } };
  const issueCount = parsed.diagnostics.invalid.length + parsed.diagnostics.duplicates.length + parsed.diagnostics.overlap.length;
  const allowNode = row.querySelector(".ip-rule-allow-count");
  const denyNode = row.querySelector(".ip-rule-deny-count");
  const countryNode = row.querySelector(".ip-rule-country-count");
  const issueNode = row.querySelector(".ip-rule-issue-count");
  if (allowNode) allowNode.textContent = `${t("ipRulesAllowCount")}: ${parsed.allowCidrs.length}`;
  if (denyNode) denyNode.textContent = `${t("ipRulesDenyCount")}: ${parsed.denyCidrs.length}`;
  if (countryNode) countryNode.textContent = `${t("ipRulesCountryCount")}: ${parsed.allowCountries.length + parsed.denyCountries.length}`;
  if (issueNode) issueNode.textContent = `${t("ipRulesIssueCount")}: ${issueCount}`;
}

function refreshIPRuleSetRowsMeta() {
  updateIPRuleSetManageListEmptyState();
  [...el.ipSettingsIPRuleSets.children].forEach((row, idx) => {
    const title = row.querySelector(".ip-rule-card-title");
    if (title) {
      title.textContent = `${t("ipRuleSetCardTitle")} #${idx + 1}`;
    }
    updateIPRuleSetRowMeta(row);
  });
}

function collectIPRuleSets(container, strict = true) {
  const out = [];
  const seen = new Set();
  for (const row of [...container.children]) {
    const parsed = parseIPRuleSetRow(row);
    if (!parsed) continue;
    const baseID = parsed.id || suggestRuleSetID(parsed.name || "") || `ruleset-${out.length + 1}`;
    const finalID = ensureUniqueIdentifier(baseID, seen, "ruleset");
    const idInput = row.querySelector(".ip-rule-id");
    if (idInput && idInput.value.trim() !== finalID) {
      idInput.value = finalID;
    }
    out.push({
      id: finalID,
      name: parsed.name,
      priority: Number(parsed.priority || 0),
      conflictPolicy: normalizeIPRuleConflictPolicy(parsed.conflictPolicy || DEFAULT_IP_RULE_CONFLICT_POLICY),
      mode: parsed.mode,
      allowCidrs: parsed.allowCidrs,
      denyCidrs: parsed.denyCidrs,
      allowAsns: parsed.allowAsns,
      denyAsns: parsed.denyAsns,
      denyReputationCidrs: parsed.denyReputationCidrs,
      allowCountries: parsed.allowCountries,
      denyCountries: parsed.denyCountries,
      countryIncludeIpv6: parsed.countryIncludeIpv6,
      countryInterval: parsed.countryInterval,
      countrySource: parsed.countrySource,
      diagnostics: parsed.diagnostics
    });
  }
  return out;
}

function newIPCountryAutoUpdateRow(data = {}) {
  const row = document.createElement("div");
  row.className = "ip-rule-card";
  row.__ipCountryRuntime = {
    cidrs: ensureStringList(data.cidrs),
    lastAttemptAt: String(data.lastAttemptAt || "").trim(),
    lastSyncAt: String(data.lastSyncAt || "").trim(),
    lastError: String(data.lastError || "").trim()
  };
  row.innerHTML = `
    <div class="ip-rule-card-head">
      <strong class="ip-rule-card-title"></strong>
      <button type="button" class="btn-danger remove-row">-</button>
    </div>
    <div class="row3">
      <input class="ip-country-id" type="hidden" value="${escapeHtml(data.id || "")}" />
      <label>
        <span data-i18n="ipCountryTaskRuleSetId">${escapeHtml(t("ipCountryTaskRuleSetId"))}</span>
        <input class="ip-country-rule-set-id" type="text" value="${escapeHtml(data.ruleSetId || "")}" placeholder="office_cn" />
      </label>
      <label>
        <span data-i18n="ipCountryTaskList">${escapeHtml(t("ipCountryTaskList"))}</span>
        <select class="ip-country-list">
          <option value="allow">allow</option>
        </select>
      </label>
    </div>
    <div class="row4">
      <label>
        <span data-i18n="ipCountryTaskCountries">${escapeHtml(t("ipCountryTaskCountries"))}</span>
        <input class="ip-country-countries" type="text" value="${escapeHtml((ensureStringList(data.countries) || []).join(", "))}" placeholder="CN, JP" />
      </label>
      <label>
        <span data-i18n="ipCountryTaskInterval">${escapeHtml(t("ipCountryTaskInterval"))}</span>
        <input class="ip-country-interval" type="text" value="${escapeHtml(data.interval || "")}" placeholder="24h" />
      </label>
      <label>
        <span data-i18n="ipCountryTaskSource">${escapeHtml(t("ipCountryTaskSource"))}</span>
        <select class="ip-country-source">
          <option value="ipdeny" data-i18n="ipCountryTaskSourceIpdeny">${escapeHtml(t("ipCountryTaskSourceIpdeny"))}</option>
        </select>
      </label>
      <label class="toggle-row">
        <input class="ip-country-include-ipv6" type="checkbox" ${data.includeIpv6 ? "checked" : ""} />
        <span data-i18n="ipCountryTaskIncludeIpv6">${escapeHtml(t("ipCountryTaskIncludeIpv6"))}</span>
      </label>
    </div>
    <div class="row2">
      <label class="toggle-row">
        <input class="ip-country-enabled" type="checkbox" ${data.enabled ? "checked" : ""} />
        <span data-i18n="ipCountryTaskEnabled">${escapeHtml(t("ipCountryTaskEnabled"))}</span>
      </label>
      <div class="ip-country-task-status"></div>
    </div>
    <div class="ip-rule-card-meta">
      <span class="ip-chip ip-chip-allow ip-country-countries-count"></span>
      <span class="ip-chip ip-chip-deny ip-country-cidrs-count"></span>
      <span class="ip-chip ip-chip-issue ip-country-issue-count"></span>
    </div>
  `;
  const listSelect = row.querySelector(".ip-country-list");
  if (listSelect) {
    listSelect.value = "allow";
  }
  const sourceSelect = row.querySelector(".ip-country-source");
  if (sourceSelect) {
    const source = String(data.source || "ipdeny").trim().toLowerCase();
    sourceSelect.value = source || "ipdeny";
  }
  row.querySelector(".remove-row").addEventListener("click", () => {
    markIPSettingsDraftDirty();
    row.remove();
    refreshIPCountryAutoUpdateRowsMeta();
    renderIPSettingsOverview();
  });
  row.addEventListener("input", () => {
    markIPSettingsDraftDirty();
    updateIPCountryAutoUpdateRowMeta(row);
    renderIPSettingsOverview();
    showIPSettingsSuccess("");
  });
  updateIPCountryAutoUpdateRowMeta(row);
  return row;
}

function parseIPCountryAutoUpdateRow(row) {
  const idInput = row.querySelector(".ip-country-id");
  const idRaw = idInput?.value?.trim() || "";
  const ruleSetId = row.querySelector(".ip-country-rule-set-id")?.value?.trim() || "";
  const listRaw = row.querySelector(".ip-country-list")?.value || "";
  const list = String(listRaw || "allow").trim().toLowerCase();
  const countriesRaw = row.querySelector(".ip-country-countries")?.value || "";
  const countries = parseCountryCodesWithIssues(countriesRaw);
  const intervalRaw = row.querySelector(".ip-country-interval")?.value?.trim() || "";
  const sourceRaw = row.querySelector(".ip-country-source")?.value?.trim() || "";
  const includeIpv6 = !!row.querySelector(".ip-country-include-ipv6")?.checked;
  const enabled = !!row.querySelector(".ip-country-enabled")?.checked;
  const runtime = row.__ipCountryRuntime || { cidrs: [], lastAttemptAt: "", lastSyncAt: "", lastError: "" };

  // Ignore the default placeholder row in the UI; only treat it as a task
  // when user provides meaningful fields beyond default source/list selectors.
  const hasMeaningfulInput = !!ruleSetId || countries.tokens.length > 0 || !!intervalRaw || includeIpv6 || enabled;
  if (!hasMeaningfulInput) {
    if (idInput) idInput.value = "";
    return null;
  }
  const id = idRaw || suggestIPCountryTaskID(ruleSetId, countries.tokens);
  if (idInput && idInput.value.trim() !== id) {
    idInput.value = id;
  }

  const invalid = [];
  if (list !== "allow") {
    invalid.push(`list=${listRaw}`);
  }
  const source = String(sourceRaw || "ipdeny").trim().toLowerCase();
  if (source && source !== "ipdeny") {
    invalid.push(`source=${source}`);
  }
  if (!ruleSetId) {
    invalid.push("ruleSetId(required)");
  }
  if (countries.tokens.length === 0) {
    invalid.push("countries(required)");
  }

  return {
    id,
    enabled,
    ruleSetId,
    list: "allow",
    countries: countries.tokens,
    includeIpv6,
    interval: intervalRaw || "24h",
    source: source || "ipdeny",
    cidrs: ensureStringList(runtime.cidrs),
    lastAttemptAt: String(runtime.lastAttemptAt || "").trim(),
    lastSyncAt: String(runtime.lastSyncAt || "").trim(),
    lastError: String(runtime.lastError || "").trim(),
    diagnostics: {
      invalid: uniqCaseInsensitive([...invalid, ...countries.invalid]),
      duplicates: uniqCaseInsensitive(countries.duplicates)
    }
  };
}

function updateIPCountryAutoUpdateRowMeta(row) {
  const parsed = parseIPCountryAutoUpdateRow(row) || { countries: [], cidrs: [], diagnostics: { invalid: [], duplicates: [] }, lastSyncAt: "", lastError: "" };
  const issueCount = parsed.diagnostics.invalid.length + parsed.diagnostics.duplicates.length;
  const countriesNode = row.querySelector(".ip-country-countries-count");
  const cidrsNode = row.querySelector(".ip-country-cidrs-count");
  const issueNode = row.querySelector(".ip-country-issue-count");
  if (countriesNode) countriesNode.textContent = `${t("ipCountryTaskCountries")}: ${parsed.countries.length}`;
  if (cidrsNode) cidrsNode.textContent = `${t("ipCountryTaskCidrsCount")}: ${parsed.cidrs.length}`;
  if (issueNode) issueNode.textContent = `${t("ipRulesIssueCount")}: ${issueCount}`;

  const statusNode = row.querySelector(".ip-country-task-status");
  if (!statusNode) return;
  const syncText = parsed.lastSyncAt ? formatDate(parsed.lastSyncAt) : "-";
  const lines = [`${escapeHtml(t("ipCountryTaskLastSyncAt"))}: ${escapeHtml(syncText)}`];
  if (parsed.lastError) {
    lines.push(`${escapeHtml(t("ipCountryTaskLastError"))}: <code>${escapeHtml(parsed.lastError)}</code>`);
  }
  statusNode.innerHTML = lines.join("<br/>");
}

function refreshIPCountryAutoUpdateRowsMeta() {
  [...el.ipSettingsIPCountryAutoUpdates.children].forEach((row, idx) => {
    const title = row.querySelector(".ip-rule-card-title");
    if (title) {
      title.textContent = `${t("ipCountryAutoUpdateCardTitle")} #${idx + 1}`;
    }
    updateIPCountryAutoUpdateRowMeta(row);
  });
}

function collectIPCountryAutoUpdates(container, strict = true) {
  const out = [];
  const seen = new Set();
  for (const row of [...container.children]) {
    const parsed = parseIPCountryAutoUpdateRow(row);
    if (!parsed) continue;
    const baseID = parsed.id || suggestIPCountryTaskID(parsed.ruleSetId, parsed.countries);
    const finalID = ensureUniqueIdentifier(baseID, seen, "task");
    const idInput = row.querySelector(".ip-country-id");
    if (idInput && idInput.value.trim() !== finalID) {
      idInput.value = finalID;
    }
    out.push({
      ...parsed,
      id: finalID
    });
  }
  return out;
}

function generatedRuleSetCountryTaskKey(ruleSetId, list) {
  const id = String(ruleSetId || "").trim().toLowerCase();
  const kind = String(list || "allow").trim().toLowerCase() === "deny" ? "deny" : "allow";
  if (!id) return "";
  return `${id}::${kind}`;
}

function extractGeneratedRuleSetCountryTaskMap(items) {
  const out = new Map();
  for (const item of Array.isArray(items) ? items : []) {
    const id = String(item?.id || "").trim();
    if (!isGeneratedRuleSetCountryTaskID(id)) continue;
    const key = generatedRuleSetCountryTaskKey(item?.ruleSetId, item?.list);
    if (!key) continue;
    out.set(key, item);
  }
  return out;
}

function taskRuntimeMapByID(items) {
  const out = new Map();
  for (const item of Array.isArray(items) ? items : []) {
    const id = String(item?.id || "").trim();
    if (!id) continue;
    out.set(id.toLowerCase(), {
      enabled: item?.enabled !== false,
      cidrs: ensureStringList(item?.cidrs),
      lastAttemptAt: String(item?.lastAttemptAt || "").trim(),
      lastSyncAt: String(item?.lastSyncAt || "").trim(),
      lastError: String(item?.lastError || "").trim()
    });
  }
  return out;
}

function getRows(container, parser) {
  return [...container.children].map(parser).filter(Boolean);
}

function readForm() {
  const domain = document.getElementById("domain").value.trim();
  const listenPortInput = document.getElementById("listenPort").value.trim();
  const listenPort = listenPortInput ? Number(normalizePort(listenPortInput)) : 0;

  const upstreams = getRows(el.upstreams, (row) => {
    const address = row.querySelector(".upstream-url").value.trim();
    const port = row.querySelector(".upstream-port").value.trim();
    if (!address) return null;
    const url = normalizeUpstreamURL(address, port);
    const weight = Number(row.querySelector(".upstream-weight").value || 1);
    return { url, weight: weight > 0 ? weight : 1 };
  });

  const routes = getRows(el.routes, (row) => {
    const path = row.querySelector(".route-path").value.trim();
    const address = row.querySelector(".route-upstream").value.trim();
    const port = row.querySelector(".route-upstream-port").value.trim();
    const routeUpstreamsRaw = row.querySelector(".route-upstreams").value.trim();
    const parsedRouteUpstreams = parseWeightedUpstreamsCSV(routeUpstreamsRaw);
    if (!path || (!address && parsedRouteUpstreams.length === 0)) return null;
    const upstream = address ? normalizeUpstreamURL(address, port) : "";
    return {
      match: row.querySelector(".route-match").value,
      path,
      methods: splitCSV(row.querySelector(".route-methods").value).map((method) => String(method || "").trim().toUpperCase()).filter(Boolean),
      header: row.querySelector(".route-header").value.trim(),
      headerValue: row.querySelector(".route-header-value").value.trim(),
      cookie: row.querySelector(".route-cookie").value.trim(),
      cookieValue: row.querySelector(".route-cookie-value").value.trim(),
      query: row.querySelector(".route-query").value.trim(),
      queryValue: row.querySelector(".route-query-value").value.trim(),
      loadBalanceStrategy: row.querySelector(".route-lb-strategy").value,
      upstream,
      upstreams: parsedRouteUpstreams,
      priority: Number(row.querySelector(".route-priority").value || 0),
      rewritePattern: row.querySelector(".route-rewrite-pattern").value.trim(),
      rewriteReplacement: row.querySelector(".route-rewrite-replacement").value.trim()
    };
  });

  const requestHeaders = getRows(el.requestHeaders, (row) => {
    const name = row.querySelector(".header-name").value.trim();
    const value = row.querySelector(".header-value").value.trim();
    if (!name) return null;
    return { name, value };
  });

  const responseHeaders = getRows(el.responseHeaders, (row) => {
    const name = row.querySelector(".header-name").value.trim();
    const value = row.querySelector(".header-value").value.trim();
    if (!name) return null;
    return { name, value };
  });
  const canaryUpstreams = getRows(el.canaryUpstreams, (row) => {
    const address = row.querySelector(".upstream-url").value.trim();
    const port = row.querySelector(".upstream-port").value.trim();
    if (!address) return null;
    const url = normalizeUpstreamURL(address, port);
    const weight = Number(row.querySelector(".upstream-weight").value || 1);
    return { url, weight: weight > 0 ? weight : 1 };
  });
  const canaryEnabled = document.getElementById("canaryEnabled").checked;
  if (canaryEnabled && !canaryUpstreams.length) {
    throw new Error("canary upstream is required when canary is enabled");
  }

  const protocol = document.getElementById("protocol").value || "";
  const isL4 = protocol === "tcp" || protocol === "udp" || protocol === "tls";

  if (!upstreams.length) {
    throw new Error("At least one upstream is required");
  }
  if (isL4) {
    if (!listenPort) {
      throw new Error("listenPort is required for TCP/UDP/TLS protocol");
    }
  } else {
    if (!domain && !listenPort) {
      throw new Error("Domain or listenPort is required");
    }
  }

  return {
    name: document.getElementById("name").value.trim(),
    nodeId: (el.nodeId?.value || "").trim(),
    protocol: document.getElementById("protocol").value || "",
    bindInterfaces: collectBindInterfaceValues(),
    domain,
    listenPort,
    additionalDomains: splitCSV(document.getElementById("additionalDomains").value),
    certificateId: (el.certificateId?.value || "").trim(),
    upstream: upstreams[0].url,
    upstreams,
    loadBalanceStrategy: document.getElementById("loadBalanceStrategy").value,
    routes,
    autoRequestHeaders: document.getElementById("autoRequestHeaders").checked,
    autoResponseHeaders: document.getElementById("autoResponseHeaders").checked,
    requestHeaders,
    responseHeaders,
    removeRequestHeaders: splitCSV(document.getElementById("removeReqHeaders").value),
    removeResponseHeaders: splitCSV(document.getElementById("removeRespHeaders").value),
    upstreamTls: {
      insecureSkipVerify: document.getElementById("upstreamTlsInsecureSkipVerify").checked,
      serverName: document.getElementById("upstreamTlsServerName").value.trim(),
      rootCAFile: document.getElementById("upstreamTlsRootCAFile").value.trim(),
      rootCAPem: document.getElementById("upstreamTlsRootCAPem").value.trim()
    },
    rateLimit: {
      enabled: document.getElementById("rateEnabled").checked,
      requestsPerMinute: Number(document.getElementById("requestsPerMinute").value || 0),
      burst: Number(document.getElementById("burst").value || 0),
      autoBlock: {
        enabled: document.getElementById("autoBlockEnabled").checked,
        violationThreshold: Number(document.getElementById("autoBlockThreshold").value || 0),
        violationWindowSeconds: Number(document.getElementById("autoBlockWindowSeconds").value || 0),
        blockSeconds: Number(document.getElementById("autoBlockSeconds").value || 0)
      }
    },
    ipAccess: {
      allowCidrs: splitCSV(document.getElementById("allowCidrs").value),
      denyCidrs: splitCSV(document.getElementById("denyCidrs").value),
      allowAsns: splitCSV(document.getElementById("allowAsns").value),
      denyAsns: splitCSV(document.getElementById("denyAsns").value),
      denyReputationCidrs: splitCSV(document.getElementById("denyReputationCidrs").value)
    },
    ipRuleSetIds: selectedValues(el.ipRuleSetId),
    ipRuleSetId: selectedValues(el.ipRuleSetId)[0] || "",
    basicAuth: {
      enabled: document.getElementById("authEnabled").checked,
      username: document.getElementById("authUsername").value.trim(),
      password: document.getElementById("authPassword").value.trim()
    },
    trafficControl: {
      maxConcurrentRequests: Number(document.getElementById("maxConcurrentRequests").value || 0),
      allowedMethods: splitCSV(document.getElementById("allowedMethods").value).map((method) => String(method || "").trim().toUpperCase()).filter(Boolean)
    },
    security: {
      enableSecurityHeaders: document.getElementById("enableSecurityHeaders").checked,
      blockUserAgentPatterns: splitCSV(document.getElementById("blockUserAgentPatterns").value)
    },
    resilience: {
      activeHealthCheck: {
        enabled: document.getElementById("healthCheckEnabled").checked,
        intervalSeconds: Number(document.getElementById("healthCheckIntervalSeconds").value || 0),
        timeoutSeconds: Number(document.getElementById("healthCheckTimeoutSeconds").value || 0),
        path: document.getElementById("healthCheckPath").value.trim(),
        expectedStatus: Number(document.getElementById("healthCheckExpectedStatus").value || 0)
      },
      retry: {
        enabled: document.getElementById("retryEnabled").checked,
        attempts: Number(document.getElementById("retryAttempts").value || 0),
        retryOnStatuses: parseStatusCodesCSV(document.getElementById("retryStatuses").value),
        backoffStrategy: document.getElementById("retryBackoffStrategy").value,
        backoffMillis: Number(document.getElementById("retryBackoffMillis").value || 0),
        maxBackoffMillis: Number(document.getElementById("retryMaxBackoffMillis").value || 0),
        jitterPercent: Number(document.getElementById("retryJitterPercent").value || 0),
        retryOn5xx: document.getElementById("retryOn5xx").checked,
        retryOnTimeout: document.getElementById("retryOnTimeout").checked,
        retryOnConnection: document.getElementById("retryOnConnection").checked
      },
      circuitBreaker: {
        enabled: document.getElementById("circuitEnabled").checked,
        failureThreshold: Number(document.getElementById("circuitFailureThreshold").value || 0),
        openSeconds: Number(document.getElementById("circuitOpenSeconds").value || 0)
      }
    },
    cache: {
      enabled: document.getElementById("cacheEnabled").checked,
      proactive: document.getElementById("cacheProactive").checked,
      ttlSeconds: Number(document.getElementById("cacheTTLSeconds").value || 0),
      maxEntries: Number(document.getElementById("cacheMaxEntries").value || 0),
      maxBodyBytes: Number(document.getElementById("cacheMaxBodyBytes").value || 0),
      keyIgnoreQueryParams: splitCSV(document.getElementById("cacheKeyIgnoreQueryParams").value).map((item) => item.toLowerCase())
    },
    timeouts: {
      connectMillis: Number(document.getElementById("timeoutConnectMillis").value || 0),
      responseHeaderMillis: Number(document.getElementById("timeoutResponseHeaderMillis").value || 0),
      expectContinueMillis: Number(document.getElementById("timeoutExpectContinueMillis").value || 0),
      idleConnMillis: Number(document.getElementById("timeoutIdleConnMillis").value || 0),
      requestMillis: Number(document.getElementById("timeoutRequestMillis").value || 0),
      backendKeepaliveMillis: Number(document.getElementById("timeoutBackendKeepaliveMillis").value || 0),
      tlsHandshakeMillis: Number(document.getElementById("timeoutTLSHandshakeMillis").value || 0),
      maxIdleConnsPerHost: Number(document.getElementById("timeoutMaxIdleConnsPerHost").value || 0),
      maxBackendConnections: Number(document.getElementById("timeoutMaxBackendConnections").value || 0),
      backendKeepaliveDisabled: document.getElementById("timeoutBackendKeepaliveDisabled").checked
    },
    gzip: {
      enabled: document.getElementById("gzipEnabled").checked
    },
    brotli: {
      enabled: document.getElementById("brotliEnabled").checked
    },
    canary: {
      enabled: canaryEnabled,
      header: document.getElementById("canaryHeader").value.trim(),
      headerValue: document.getElementById("canaryHeaderValue").value.trim(),
      cookie: document.getElementById("canaryCookie").value.trim(),
      cookieValue: document.getElementById("canaryCookieValue").value.trim(),
      weight: Number(document.getElementById("canaryWeight").value || 0),
      loadBalanceStrategy: document.getElementById("canaryLoadBalanceStrategy").value || "round_robin",
      upstream: canaryUpstreams[0]?.url || "",
      upstreams: canaryUpstreams
    },
    enabled: document.getElementById("enabled").checked,
    forceHttps: document.getElementById("forceHttps").checked,
    jwt: {
      enabled: document.getElementById("jwtEnabled").checked,
      extractFrom: document.getElementById("jwtExtractFrom").value,
      extractName: document.getElementById("jwtExtractName").value.trim(),
      signingAlgorithm: document.getElementById("jwtSigningAlgorithm").value,
      hmacSecret: document.getElementById("jwtHMACSecret").value.trim(),
      jwksUrl: document.getElementById("jwtJWKSURL").value.trim(),
      issuer: document.getElementById("jwtIssuer").value.trim(),
      audience: document.getElementById("jwtAudience").value.trim(),
      forwardToken: document.getElementById("jwtForwardToken").checked
    },
    waf: {
      enabled: document.getElementById("wafEnabled").checked,
      mode: document.getElementById("wafMode").value,
      severityThreshold: document.getElementById("wafSeverityThreshold").value,
      excludePaths: splitCSV(document.getElementById("wafExcludePaths").value)
    },
    oauth: {
      enabled: document.getElementById("oauthEnabled").checked,
      provider: document.getElementById("oauthProvider").value,
      clientId: document.getElementById("oauthClientID").value.trim(),
      clientSecret: document.getElementById("oauthClientSecret").value.trim(),
      allowedDomains: splitCSV(document.getElementById("oauthAllowedDomains").value),
      allowedEmails: splitCSV(document.getElementById("oauthAllowedEmails").value),
      callbackUrl: document.getElementById("oauthCallbackURL").value.trim()
    },
    grpc: {
      enabled: document.getElementById("grpcEnabled").checked,
      h2c: document.getElementById("grpcH2C").checked
    }
  };
}

function renderSiteIPRuleSetSelectionSummary(selectedIDs = selectedValues(el.ipRuleSetId)) {
  if (!el.siteIPRuleSetSummary) return;
  const selected = new Set(
    (Array.isArray(selectedIDs) ? selectedIDs : [selectedIDs])
      .map((item) => String(item || "").trim())
      .filter(Boolean)
  );
  if (!selected.size) {
    el.siteIPRuleSetSummary.innerHTML = `<div class="ip-rule-select-empty">${escapeHtml(t("ipRuleSetSelectionEmpty"))}</div>`;
    return;
  }
  const countryCountByRuleSet = new Map();
  for (const task of Array.isArray(appSettings?.ipCountryAutoUpdates) ? appSettings.ipCountryAutoUpdates : []) {
    const ruleSetID = String(task?.ruleSetId || "").trim();
    if (!ruleSetID) continue;
    const countries = ensureStringList(task?.countries).map((item) => String(item || "").trim().toUpperCase()).filter(Boolean);
    if (!countries.length) continue;
    const key = ruleSetID.toLowerCase();
    const merged = uniqCaseInsensitive([...(countryCountByRuleSet.get(key) || []), ...countries]);
    countryCountByRuleSet.set(key, merged);
  }
  const items = (Array.isArray(appSettings?.ipRuleSets) ? [...appSettings.ipRuleSets] : []).sort((a, b) => Number(b?.priority || 0) - Number(a?.priority || 0));
  const cards = [];
  for (const item of items) {
    const id = String(item?.id || "").trim();
    if (!id || !selected.has(id)) continue;
    const name = String(item?.name || "").trim();
    const priority = Number(item?.priority || 0);
    const allowCount = Array.isArray(item?.allowCidrs) ? item.allowCidrs.length : 0;
    const denyCount = Array.isArray(item?.denyCidrs) ? item.denyCidrs.length : 0;
    const countryCount = (countryCountByRuleSet.get(id.toLowerCase()) || []).length;
    cards.push(`
      <div class="ip-rule-select-item">
        <strong>${escapeHtml(name || id)}</strong>
        <small>${escapeHtml(id)}</small>
        <small>${escapeHtml(t("ipRuleSetPriorityLabel"))}: ${priority}</small>
        <small>${escapeHtml(t("ipRulesAllowCount"))}: ${allowCount} | ${escapeHtml(t("ipRulesDenyCount"))}: ${denyCount} | ${escapeHtml(t("ipRulesCountryCount"))}: ${countryCount}</small>
      </div>
    `);
  }
  el.siteIPRuleSetSummary.innerHTML = cards.length ? cards.join("") : `<div class="ip-rule-select-empty">${escapeHtml(t("ipRuleSetSelectionEmpty"))}</div>`;
}

function renderSiteIPRuleSetOptions(selectedIDs = selectedValues(el.ipRuleSetId)) {
  if (!el.ipRuleSetId) return;
  const selected = new Set(
    (Array.isArray(selectedIDs) ? selectedIDs : [selectedIDs])
      .map((item) => String(item || "").trim())
      .filter(Boolean)
  );
  const ipRuleSets = (Array.isArray(appSettings?.ipRuleSets) ? [...appSettings.ipRuleSets] : []).sort((a, b) => Number(b?.priority || 0) - Number(a?.priority || 0));
  const countryCountByRuleSet = new Map();
  for (const task of Array.isArray(appSettings?.ipCountryAutoUpdates) ? appSettings.ipCountryAutoUpdates : []) {
    const ruleSetID = String(task?.ruleSetId || "").trim();
    if (!ruleSetID) continue;
    const countries = ensureStringList(task?.countries).map((item) => String(item || "").trim().toUpperCase()).filter(Boolean);
    if (!countries.length) continue;
    const key = ruleSetID.toLowerCase();
    const merged = uniqCaseInsensitive([...(countryCountByRuleSet.get(key) || []), ...countries]);
    countryCountByRuleSet.set(key, merged);
  }
  const options = [];
  for (const item of ipRuleSets) {
    const id = String(item?.id || "").trim();
    if (!id) continue;
    const name = String(item?.name || "").trim();
    const priority = Number(item?.priority || 0);
    const allowCount = Array.isArray(item?.allowCidrs) ? item.allowCidrs.length : 0;
    const denyCount = Array.isArray(item?.denyCidrs) ? item.denyCidrs.length : 0;
    const countryCount = (countryCountByRuleSet.get(id.toLowerCase()) || []).length;
    const label = `${name || id} (${id}) · P:${priority} · ${t("ipRulesAllowCount")}:${allowCount} ${t("ipRulesDenyCount")}:${denyCount} ${t("ipRulesCountryCount")}:${countryCount}`;
    const selectedAttr = selected.has(id) ? " selected" : "";
    options.push(`<option value="${escapeHtml(id)}"${selectedAttr}>${escapeHtml(label)}</option>`);
  }
  el.ipRuleSetId.innerHTML = options.join("");
  renderSiteIPRuleSetSelectionSummary(selectedValues(el.ipRuleSetId));
}

function fillSettingsForm(value) {
  const current = value || {};
  const backup = current.backup || {};
  const alert = current.alert || {};
  const adminTls = current.adminTls || {};
  const clusterSync = current.clusterSync || {};
  const selectedLanguage = normalizeLang(current.language);
  el.settingsLanguage.value = i18n[selectedLanguage] ? selectedLanguage : "en";
  el.settingsWebPort.value = current.webPort || "";
  renderSiteIPRuleSetOptions(selectedValues(el.ipRuleSetId));
  el.alertWebhookUrl.value = alert.webhookUrl || "";
  el.alertConsecutive5xx.value = Number(alert.consecutive5xx || 10);
  el.alertLatencyMs.value = Number(alert.latencyMs || 0);
  el.alertCooldown.value = alert.cooldown || "5m";
  el.adminTlsEnabled.checked = !!adminTls.enabled;
  el.adminTlsHttpsPort.value = Number(adminTls.httpsPort || 9443);
  el.adminTlsRedirectHttp.checked = !!adminTls.redirectHttp;
  el.adminTlsAutoSelfSigned.checked = adminTls.autoSelfSigned !== false;
  renderAdminTLSCertificateOptions(adminTls.certificateId || "");
  if (el.clusterSyncCertificateSyncEnabled) el.clusterSyncCertificateSyncEnabled.checked = clusterSync.certificateSyncEnabled !== false;
  if (el.clusterSyncFailCloseEnabled) el.clusterSyncFailCloseEnabled.checked = clusterSync.failCloseEnabled !== false;
  if (el.clusterSyncFailCloseConsecutiveFailures) el.clusterSyncFailCloseConsecutiveFailures.value = Number(clusterSync.failCloseConsecutiveFailures || 10);
  if (el.clusterSyncFailCloseStaleAfter) el.clusterSyncFailCloseStaleAfter.value = clusterSync.failCloseStaleAfter || "5m";
  el.backupEnabled.checked = !!backup.enabled;
  el.backupInterval.value = backup.interval || "24h";
  el.backupKeepLast.value = Number(backup.keepLast || 30);

  // Distributed rate limit
  const rateLimit = current.rateLimit || {};
  if (document.getElementById("rateLimitBackend")) {
    document.getElementById("rateLimitBackend").value = rateLimit.backend || "local";
  }
  if (document.getElementById("rateLimitRedisEndpoint")) {
    document.getElementById("rateLimitRedisEndpoint").value = rateLimit.redis?.endpoints?.join(", ") || "";
    document.getElementById("rateLimitRedisPassword").value = rateLimit.redis?.password || "";
    document.getElementById("rateLimitRedisDB").value = rateLimit.redis?.db || 0;
  }
}

function readSettingsForm() {
  const language = (el.settingsLanguage.value || "en").trim().toLowerCase();
  if (language !== "zh" && language !== "zh-tw" && language !== "en") {
    throw new Error("language must be zh, zh-tw or en");
  }
  const webPort = Number(normalizePort(el.settingsWebPort.value.trim()));
  const keepLast = Number(el.backupKeepLast.value || 0);
  if (!Number.isInteger(keepLast) || keepLast < 1 || keepLast > 1000) {
    throw new Error("backup keepLast must be within 1-1000");
  }
  const backupInterval = (el.backupInterval.value || "").trim();
  if (!backupInterval) {
    throw new Error("backup interval is required");
  }
  const alertConsecutive5xx = Number(el.alertConsecutive5xx.value || 0);
  if (!Number.isInteger(alertConsecutive5xx) || alertConsecutive5xx < 1 || alertConsecutive5xx > 100000) {
    throw new Error("alert consecutive5xx must be within 1-100000");
  }
  const alertLatencyMs = Number(el.alertLatencyMs.value || 0);
  if (!Number.isInteger(alertLatencyMs) || alertLatencyMs < 0) {
    throw new Error("alert latencyMs must be >= 0");
  }
  const alertCooldown = (el.alertCooldown.value || "").trim();
  if (!alertCooldown) {
    throw new Error("alert cooldown is required");
  }

  const adminTlsEnabled = !!el.adminTlsEnabled.checked;
  const adminTlsHttpsPort = Number(normalizePort(String(el.adminTlsHttpsPort.value || "9443").trim()));
  const adminTlsAutoSelfSigned = !!el.adminTlsAutoSelfSigned.checked;
  const adminTlsCertificateId = (el.adminTlsCertificateId?.value || "").trim();
  if (adminTlsEnabled && !adminTlsAutoSelfSigned) {
    if (!adminTlsCertificateId) {
      throw new Error("admin tls requires certificateId or autoSelfSigned");
    }
  }
  const failCloseConsecutiveFailures = Number(el.clusterSyncFailCloseConsecutiveFailures?.value || 0);
  if (!Number.isInteger(failCloseConsecutiveFailures) || failCloseConsecutiveFailures < 1 || failCloseConsecutiveFailures > 100000) {
    throw new Error("clusterSync failCloseConsecutiveFailures must be within 1-100000");
  }
  const failCloseStaleAfter = (el.clusterSyncFailCloseStaleAfter?.value || "").trim();
  if (!failCloseStaleAfter) {
    throw new Error("clusterSync failCloseStaleAfter is required");
  }

  return {
    language,
    webPort,
    alert: {
      webhookUrl: (el.alertWebhookUrl.value || "").trim(),
      consecutive5xx: alertConsecutive5xx,
      latencyMs: alertLatencyMs,
      cooldown: alertCooldown
    },
    adminTls: {
      enabled: adminTlsEnabled,
      httpsPort: adminTlsHttpsPort,
      redirectHttp: !!el.adminTlsRedirectHttp.checked,
      autoSelfSigned: adminTlsAutoSelfSigned,
      certificateId: adminTlsCertificateId,
      certFile: "",
      keyFile: ""
    },
    clusterSync: {
      certificateSyncEnabled: !!el.clusterSyncCertificateSyncEnabled?.checked,
      failCloseEnabled: !!el.clusterSyncFailCloseEnabled?.checked,
      failCloseConsecutiveFailures,
      failCloseStaleAfter
    },
    backup: {
      enabled: !!el.backupEnabled.checked,
      interval: backupInterval,
      keepLast
    },
    rateLimit: {
      backend: document.getElementById("rateLimitBackend")?.value || "local",
      redis: {
        endpoints: document.getElementById("rateLimitRedisEndpoint")?.value.trim() ? [document.getElementById("rateLimitRedisEndpoint").value.trim()] : [],
        password: document.getElementById("rateLimitRedisPassword")?.value.trim() || "",
        db: Number(document.getElementById("rateLimitRedisDB")?.value || 0)
      }
    }
  };
}

function fillIPSettingsForm(value, options = {}) {
  if (!el.ipSettingsForm) return;
  const force = !!options?.force;
  if (!force && ipSettingsDraftDirty) return;
  ipRuleSetEditingIndex = -1;
  const current = value || {};
  const webAccess = current.webAccess || {};
  const ipRuleSets = Array.isArray(current.ipRuleSets) ? current.ipRuleSets : [];
  const allCountryTasks = Array.isArray(current.ipCountryAutoUpdates) ? current.ipCountryAutoUpdates : [];
  const generatedCountryTaskMap = extractGeneratedRuleSetCountryTaskMap(allCountryTasks);
  const manualCountryTasks = allCountryTasks.filter((item) => !isGeneratedRuleSetCountryTaskID(item?.id));
  const sourceOrder = normalizeIPRuleSourceOrder(current.ipRuleSourceOrder).order;
  el.ipSettingsAllowCidrs.value = (webAccess.allowCidrs || []).join("\n");
  el.ipSettingsDenyCidrs.value = (webAccess.denyCidrs || []).join("\n");
  if (el.ipRuleSourceOrder) {
    el.ipRuleSourceOrder.value = sourceOrder.join(", ");
  }
  el.ipSettingsIPRuleSets.innerHTML = "";
  ipRuleSets.forEach((item) => {
    const id = String(item?.id || "").trim();
    const allowTask = generatedCountryTaskMap.get(generatedRuleSetCountryTaskKey(id, "allow"));
    const denyTask = generatedCountryTaskMap.get(generatedRuleSetCountryTaskKey(id, "deny"));
    const allowCountries = ensureStringList(allowTask?.countries || []);
    const denyCountries = ensureStringList(denyTask?.countries || []);
    const mergedAllowCountries = uniqCaseInsensitive([...allowCountries, ...denyCountries]);
    const hasCountries = mergedAllowCountries.length > 0;
    const hasCIDRs = (Array.isArray(item?.allowCidrs) && item.allowCidrs.length > 0) || (Array.isArray(item?.denyCidrs) && item.denyCidrs.length > 0) || (Array.isArray(item?.allowAsns) && item.allowAsns.length > 0) || (Array.isArray(item?.denyAsns) && item.denyAsns.length > 0) || (Array.isArray(item?.denyReputationCidrs) && item.denyReputationCidrs.length > 0);
    const mode = normalizeRuleMode(item?.mode || (hasCountries && !hasCIDRs ? "country" : "manual"));
    const derived = {
      ...item,
      priority: Number(item?.priority || 0),
      conflictPolicy: normalizeIPRuleConflictPolicy(item?.conflictPolicy || DEFAULT_IP_RULE_CONFLICT_POLICY),
      mode,
      allowCountries: mergedAllowCountries,
      denyCountries: [],
      countryIncludeIpv6: !!(allowTask?.includeIpv6 || denyTask?.includeIpv6),
      countryInterval: String(allowTask?.interval || denyTask?.interval || "24h"),
      countrySource: String(allowTask?.source || denyTask?.source || "ipdeny").toLowerCase()
    };
    el.ipSettingsIPRuleSets.appendChild(newIPRuleSetRow(derived));
  });
  el.ipSettingsIPCountryAutoUpdates.innerHTML = "";
  manualCountryTasks.forEach((item) => el.ipSettingsIPCountryAutoUpdates.appendChild(newIPCountryAutoUpdateRow(item)));
  refreshIPRuleSetRowsMeta();
  refreshIPCountryAutoUpdateRowsMeta();
  renderIPSettingsOverview();
  clearIPSettingsDraftDirty();
  if (!force) {
    restoreLocalIPSettingsDraft();
  }
}

function buildIPSettingsDraft(strict = false) {
  const webAllow = parseIPTokensWithIssues(el.ipSettingsAllowCidrs.value || "");
  const webDeny = parseIPTokensWithIssues(el.ipSettingsDenyCidrs.value || "");
  const sourceOrderResult = normalizeIPRuleSourceOrder(el.ipRuleSourceOrder?.value || "");
  const ipRuleSetsRaw = collectIPRuleSets(el.ipSettingsIPRuleSets, false);
  const autoUpdatesRaw = collectIPCountryAutoUpdates(el.ipSettingsIPCountryAutoUpdates, false);
  const existingTaskRuntime = taskRuntimeMapByID(appSettings?.ipCountryAutoUpdates);

  const duplicateIDs = [];
  const missingIDs = [];
  const invalidEntries = [];
  const overlapEntries = [];
  const duplicateEntries = [];
  const seenIDs = new Set();
  const ipRuleSets = [];
  const autoUpdates = [];
  const seenAutoUpdateIDs = new Set();
  let generatedAutoUpdateCount = 0;

  const webDenySet = new Set(webDeny.tokens.map((item) => item.toLowerCase()));
  for (const item of webAllow.tokens) {
    if (webDenySet.has(item.toLowerCase())) {
      overlapEntries.push(`web: ${item}`);
    }
  }
  if (webAllow.duplicates.length) {
    duplicateEntries.push(...webAllow.duplicates.map((item) => `web allow: ${item}`));
  }
  if (webDeny.duplicates.length) {
    duplicateEntries.push(...webDeny.duplicates.map((item) => `web deny: ${item}`));
  }
  if (webAllow.invalid.length) {
    invalidEntries.push(...webAllow.invalid.map((item) => `web allow: ${item}`));
  }
  if (webDeny.invalid.length) {
    invalidEntries.push(...webDeny.invalid.map((item) => `web deny: ${item}`));
  }
  if (sourceOrderResult.invalid.length) {
    invalidEntries.push(...sourceOrderResult.invalid.map((item) => `source order: ${item}`));
  }

  ipRuleSetsRaw.forEach((item, idx) => {
    const label = item.name || item.id || `#${idx + 1}`;
    if (!item.id) {
      missingIDs.push(label);
    } else {
      const key = item.id.toLowerCase();
      if (seenIDs.has(key)) {
        duplicateIDs.push(item.id);
      } else {
        seenIDs.add(key);
      }
    }
    if (item.diagnostics?.invalid?.length) {
      invalidEntries.push(...item.diagnostics.invalid.map((value) => `${label}: ${value}`));
    }
    if (item.diagnostics?.duplicates?.length) {
      duplicateEntries.push(...item.diagnostics.duplicates.map((value) => `${label}: ${value}`));
    }
    if (item.diagnostics?.overlap?.length) {
      overlapEntries.push(...item.diagnostics.overlap.map((value) => `${label}: ${value}`));
    }

    if (item.id) {
      const mode = normalizeRuleMode(item.mode);
      const enableManual = mode === "manual";
      const enableCountry = mode === "country";
      ipRuleSets.push({
        id: item.id,
        name: item.name,
        priority: Number(item.priority || 0),
        conflictPolicy: normalizeIPRuleConflictPolicy(item.conflictPolicy || DEFAULT_IP_RULE_CONFLICT_POLICY),
        mode,
        allowCidrs: enableManual ? uniqCaseInsensitive(item.allowCidrs) : [],
        denyCidrs: enableManual ? uniqCaseInsensitive(item.denyCidrs) : [],
        allowAsns: enableManual ? parseASNTokensWithIssues(item.allowAsns || []).tokens : [],
        denyAsns: enableManual ? parseASNTokensWithIssues(item.denyAsns || []).tokens : [],
        denyReputationCidrs: enableManual ? uniqCaseInsensitive(item.denyReputationCidrs) : []
      });

      const ruleSetID = String(item.id || "").trim();
      const countryInterval = String(item.countryInterval || "24h").trim() || "24h";
      const countrySource = String(item.countrySource || "ipdeny").trim().toLowerCase() || "ipdeny";
      const includeIpv6 = !!item.countryIncludeIpv6;
      if (enableCountry) {
        const generatedItems = [
          { list: "allow", countries: uniqCaseInsensitive([...(item.allowCountries || []), ...(item.denyCountries || [])]) }
        ];
        for (const generated of generatedItems) {
          if (!generated.countries.length) continue;
          const taskID = normalizeRuleSetCountryTaskID(ruleSetID, generated.list);
          if (!taskID) continue;
          generatedAutoUpdateCount += 1;
          const taskKey = taskID.toLowerCase();
          if (seenAutoUpdateIDs.has(taskKey)) {
            duplicateIDs.push(taskID);
            continue;
          }
          seenAutoUpdateIDs.add(taskKey);
          const runtime = existingTaskRuntime.get(taskKey) || { enabled: true, cidrs: [], lastAttemptAt: "", lastSyncAt: "", lastError: "" };
          autoUpdates.push({
            id: taskID,
            enabled: runtime.enabled !== false,
            ruleSetId: ruleSetID,
            list: generated.list,
            countries: generated.countries,
            includeIpv6,
            interval: countryInterval,
            source: countrySource
          });
        }
      }
    }
  });

  const ruleSetIDSet = new Set(ipRuleSets.map((item) => String(item.id || "").toLowerCase()));
  autoUpdatesRaw.forEach((item, idx) => {
    if (isGeneratedRuleSetCountryTaskID(item.id)) {
      return;
    }
    const label = item.id || `task#${idx + 1}`;
    if (!item.id) {
      missingIDs.push(label);
    } else {
      const key = item.id.toLowerCase();
      if (seenAutoUpdateIDs.has(key)) {
        duplicateIDs.push(item.id);
      } else {
        seenAutoUpdateIDs.add(key);
      }
    }

    if (item.diagnostics?.invalid?.length) {
      invalidEntries.push(...item.diagnostics.invalid.map((value) => `${label}: ${value}`));
    }
    if (item.diagnostics?.duplicates?.length) {
      duplicateEntries.push(...item.diagnostics.duplicates.map((value) => `${label}: ${value}`));
    }
    if (item.ruleSetId && !ruleSetIDSet.has(item.ruleSetId.toLowerCase())) {
      invalidEntries.push(`${label}: ruleSetId(not found)=${item.ruleSetId}`);
    }

    if (item.id) {
      autoUpdates.push({
        id: item.id,
        enabled: !!item.enabled,
        ruleSetId: item.ruleSetId,
        list: item.list,
        countries: uniqCaseInsensitive(item.countries),
        includeIpv6: !!item.includeIpv6,
        interval: item.interval,
        source: item.source
      });
    }
  });

  if (strict) {
    if (missingIDs.length) {
      throw new Error(`${t("ipRulesIssueMissingID")}: ${missingIDs.slice(0, 5).join(", ")}`);
    }
    if (duplicateIDs.length) {
      throw new Error(`${t("ipRulesIssueDuplicateID")}: ${uniqCaseInsensitive(duplicateIDs).slice(0, 5).join(", ")}`);
    }
    if (invalidEntries.length) {
      throw new Error(`${t("ipRulesIssueInvalid")}: ${uniqCaseInsensitive(invalidEntries).slice(0, 5).join(", ")}`);
    }
  }

  return {
    payload: {
      webAccess: {
        allowCidrs: uniqCaseInsensitive(webAllow.tokens),
        denyCidrs: uniqCaseInsensitive(webDeny.tokens)
      },
      ipRuleSourceOrder: sourceOrderResult.order,
      ipRuleSets,
      ipCountryAutoUpdates: autoUpdates
    },
    diagnostics: {
      presetCount: ipRuleSetsRaw.length,
      autoUpdateCount: autoUpdatesRaw.filter((item) => !isGeneratedRuleSetCountryTaskID(item?.id)).length + generatedAutoUpdateCount,
      globalAllowCount: webAllow.tokens.length,
      globalDenyCount: webDeny.tokens.length,
      duplicateIDs: uniqCaseInsensitive(duplicateIDs),
      missingIDs: uniqCaseInsensitive(missingIDs),
      invalidEntries: uniqCaseInsensitive(invalidEntries),
      overlapEntries: uniqCaseInsensitive(overlapEntries),
      duplicateEntries: uniqCaseInsensitive(duplicateEntries)
    }
  };
}

function renderIPSettingsOverview() {
  if (!el.ipSettingsOverview) return;
  const { diagnostics } = buildIPSettingsDraft(false);
  const issues = [];
  if (diagnostics.duplicateIDs.length) {
    issues.push(`${t("ipRulesIssueDuplicateID")}: ${diagnostics.duplicateIDs.join(", ")}`);
  }
  if (diagnostics.missingIDs.length) {
    issues.push(`${t("ipRulesIssueMissingID")}: ${diagnostics.missingIDs.join(", ")}`);
  }
  if (diagnostics.invalidEntries.length) {
    issues.push(`${t("ipRulesIssueInvalid")}: ${diagnostics.invalidEntries.slice(0, 5).join(", ")}`);
  }
  if (diagnostics.overlapEntries.length) {
    issues.push(`${t("ipRulesIssueOverlap")}: ${diagnostics.overlapEntries.slice(0, 5).join(", ")}`);
  }
  if (diagnostics.duplicateEntries.length) {
    issues.push(`${t("ipRulesIssueDuplicateEntry")}: ${diagnostics.duplicateEntries.slice(0, 5).join(", ")}`);
  }

  const issueCount = issues.length;
  const metrics = [
    { label: t("ipRulesMetricPresets"), value: diagnostics.presetCount },
    { label: t("ipRulesMetricAutoUpdates"), value: diagnostics.autoUpdateCount },
    { label: t("ipRulesMetricGlobalAllow"), value: diagnostics.globalAllowCount },
    { label: t("ipRulesMetricGlobalDeny"), value: diagnostics.globalDenyCount },
    { label: t("ipRulesMetricIssues"), value: issueCount }
  ];
  const metricHTML = metrics.map((item) => `
    <div class="ip-rules-overview-item">
      <strong>${item.value}</strong>
      <span>${escapeHtml(item.label)}</span>
    </div>
  `).join("");

  const issueHTML = issues.length
    ? issues.map((item) => `<div class="ip-rules-overview-issue">${escapeHtml(item)}</div>`).join("")
    : `<div class="ip-rules-overview-issue ok">${escapeHtml(t("ipRulesIssueNone"))}</div>`;

  el.ipSettingsOverview.innerHTML = `
    <div class="ip-rules-overview-grid">${metricHTML}</div>
    <div class="ip-rules-overview-issues">${issueHTML}</div>
  `;
  renderIPSettingsSummaryLists();
}

function renderIPSettingsSummaryLists() {
  updateIPRuleSetManageListEmptyState();
  const presetRows = [...(el.ipSettingsIPRuleSets?.children || [])];
  const taskRows = [...(el.ipSettingsIPCountryAutoUpdates?.children || [])];
  const ipRuleSets = presetRows.map((row, idx) => {
    const parsed = parseIPRuleSetRow(row);
    if (parsed) return parsed;
    return {
      id: "",
      name: "",
      allowCidrs: [],
      denyCidrs: [],
      allowCountries: [],
      index: idx + 1
    };
  });
  const autoUpdates = taskRows.map((row, idx) => {
    const parsed = parseIPCountryAutoUpdateRow(row);
    if (parsed) return parsed;
    return {
      id: "",
      ruleSetId: "",
      countries: [],
      cidrs: [],
      enabled: false,
      index: idx + 1
    };
  });

  if (el.ipRuleSetManageCards) {
    if (!ipRuleSets.length) {
      el.ipRuleSetManageCards.innerHTML = "";
    } else {
      el.ipRuleSetManageCards.innerHTML = ipRuleSets.map((item, idx) => {
        const displayName = String(item?.name || item?.id || `${t("ipRuleSetCardTitle")} #${item?.index || idx + 1}`);
        const displayID = String(item?.id || `draft-${idx + 1}`);
        const activeClass = idx === ipRuleSetEditingIndex ? " is-active" : "";
        return `
          <div class="ip-settings-summary-item${activeClass}">
            <div class="ip-settings-summary-main">
              <strong>${escapeHtml(displayName)}</strong>
              <code>${escapeHtml(displayID)}</code>
            </div>
            <div class="ip-settings-summary-meta">
              <span class="ip-chip ip-chip-allow">${escapeHtml(t("ipRulesAllowCount"))}: ${Number(item?.allowCidrs?.length || 0)}</span>
              <span class="ip-chip ip-chip-deny">${escapeHtml(t("ipRulesDenyCount"))}: ${Number(item?.denyCidrs?.length || 0)}</span>
              <span class="ip-chip ip-chip-allow">${escapeHtml(t("ipRulesCountryCount"))}: ${Number(item?.allowCountries?.length || 0)}</span>
            </div>
            <div class="actions">
              <button type="button" class="btn-ghost" data-ip-rule-action="edit" data-ip-rule-index="${idx}">${escapeHtml(t("edit"))}</button>
              <button type="button" class="btn-danger" data-ip-rule-action="delete" data-ip-rule-index="${idx}">${escapeHtml(t("del"))}</button>
            </div>
          </div>
        `;
      }).join("");
    }
  }

  if (el.ipCountryTaskListSummary) {
    if (!autoUpdates.length) {
      el.ipCountryTaskListSummary.innerHTML = `<div class="ip-settings-summary-empty">${escapeHtml(t("ipRulesListEmpty"))}</div>`;
    } else {
      el.ipCountryTaskListSummary.innerHTML = autoUpdates.map((item, idx) => {
        const displayRuleSetID = String(item?.ruleSetId || `ruleset-${item?.index || idx + 1}`);
        const displayID = String(item?.id || `task-${idx + 1}`);
        return `
          <div class="ip-settings-summary-item">
            <div class="ip-settings-summary-main">
              <strong>${escapeHtml(displayRuleSetID)}</strong>
              <code>${escapeHtml(displayID)}</code>
            </div>
            <div class="ip-settings-summary-meta">
              <span class="ip-chip ip-chip-allow">${escapeHtml(t("ipCountryTaskCountries"))}: ${Number(item?.countries?.length || 0)}</span>
              <span class="ip-chip ip-chip-deny">${escapeHtml(t("ipCountryTaskCidrsCount"))}: ${Number(item?.cidrs?.length || 0)}</span>
              <span class="ip-chip ip-chip-allow">${escapeHtml(t("enabled"))}: ${item?.enabled ? "ON" : "OFF"}</span>
            </div>
          </div>
        `;
      }).join("");
    }
  }
}

function normalizeIPSettingsFormInputs() {
  if (!el.ipSettingsForm) return;
  el.ipSettingsAllowCidrs.value = uniqCaseInsensitive(splitCSV(el.ipSettingsAllowCidrs.value)).join("\n");
  el.ipSettingsDenyCidrs.value = uniqCaseInsensitive(splitCSV(el.ipSettingsDenyCidrs.value)).join("\n");
  if (el.ipRuleSourceOrder) {
    el.ipRuleSourceOrder.value = normalizeIPRuleSourceOrder(el.ipRuleSourceOrder.value).order.join(", ");
  }
  for (const row of [...el.ipSettingsIPRuleSets.children]) {
    const modeSelect = row.querySelector(".ip-rule-mode");
    const idInput = row.querySelector(".ip-rule-id");
    const nameInput = row.querySelector(".ip-rule-name");
    const priorityInput = row.querySelector(".ip-rule-priority");
    const conflictPolicySelect = row.querySelector(".ip-rule-conflict-policy");
    const allowInput = row.querySelector(".ip-rule-allow");
    const denyInput = row.querySelector(".ip-rule-deny");
    const allowAsnsInput = row.querySelector(".ip-rule-allow-asns");
    const denyAsnsInput = row.querySelector(".ip-rule-deny-asns");
    const denyReputationCidrsInput = row.querySelector(".ip-rule-deny-reputation-cidrs");
    const allowCountriesInput = row.querySelector(".ip-rule-allow-countries");
    const countryIntervalInput = row.querySelector(".ip-rule-country-interval");
    const countrySourceSelect = row.querySelector(".ip-rule-country-source");
    if (modeSelect) modeSelect.value = normalizeRuleMode(modeSelect.value);
    if (nameInput) nameInput.value = nameInput.value.trim();
    if (idInput) {
      idInput.value = idInput.value.trim();
      if (!idInput.value) idInput.value = suggestRuleSetID(nameInput?.value || "");
    }
    if (priorityInput) priorityInput.value = String(Number.isFinite(Number(priorityInput.value)) ? Math.trunc(Number(priorityInput.value)) : 0);
    if (allowInput) allowInput.value = uniqCaseInsensitive(splitCSV(allowInput.value || "")).join("\n");
    if (denyInput) denyInput.value = uniqCaseInsensitive(splitCSV(denyInput.value || "")).join("\n");
    if (allowAsnsInput) allowAsnsInput.value = parseASNTokensWithIssues(allowAsnsInput.value || "").tokens.join("\n");
    if (denyAsnsInput) denyAsnsInput.value = parseASNTokensWithIssues(denyAsnsInput.value || "").tokens.join("\n");
    if (denyReputationCidrsInput) denyReputationCidrsInput.value = uniqCaseInsensitive(splitCSV(denyReputationCidrsInput.value || "")).join("\n");
    if (allowCountriesInput) allowCountriesInput.value = uniqCaseInsensitive(splitCSV(allowCountriesInput.value || "")).map((code) => String(code || "").toUpperCase()).join(", ");
    if (countryIntervalInput) countryIntervalInput.value = countryIntervalInput.value.trim() || "24h";
    if (countrySourceSelect) countrySourceSelect.value = String(countrySourceSelect.value || "ipdeny").trim().toLowerCase() || "ipdeny";
    if (conflictPolicySelect) {
      conflictPolicySelect.value = normalizeIPRuleConflictPolicy(conflictPolicySelect.value || DEFAULT_IP_RULE_CONFLICT_POLICY);
      applyConflictPriorityListOrder(row, conflictPolicySelect.value);
    }
    updateIPRuleSetModeUI(row);
    updateIPRuleSetRowMeta(row);
  }
  for (const row of [...el.ipSettingsIPCountryAutoUpdates.children]) {
    const idInput = row.querySelector(".ip-country-id");
    const ruleSetInput = row.querySelector(".ip-country-rule-set-id");
    const countriesInput = row.querySelector(".ip-country-countries");
    const intervalInput = row.querySelector(".ip-country-interval");
    const sourceSelect = row.querySelector(".ip-country-source");
    const countries = splitCSV(countriesInput?.value || "").map((code) => String(code || "").trim().toUpperCase()).filter(Boolean);
    const hasMeaningfulInput = !!ruleSetInput?.value?.trim() || countries.length > 0 || !!intervalInput?.value?.trim() || !!row.querySelector(".ip-country-include-ipv6")?.checked || !!row.querySelector(".ip-country-enabled")?.checked;
    if (idInput) {
      if (hasMeaningfulInput) {
        const suggested = suggestIPCountryTaskID(ruleSetInput?.value || "", countries);
        idInput.value = idInput.value.trim() || suggested;
      } else {
        idInput.value = "";
      }
    }
    if (ruleSetInput) ruleSetInput.value = ruleSetInput.value.trim();
    if (countriesInput) countriesInput.value = uniqCaseInsensitive(splitCSV(countriesInput.value || "")).map((code) => String(code || "").toUpperCase()).join(", ");
    if (intervalInput) intervalInput.value = intervalInput.value.trim();
    if (sourceSelect) sourceSelect.value = String(sourceSelect.value || "ipdeny").trim().toLowerCase();
    updateIPCountryAutoUpdateRowMeta(row);
  }
  refreshIPRuleSetRowsMeta();
  refreshIPCountryAutoUpdateRowsMeta();
  renderIPSettingsOverview();
}

function readIPSettingsForm() {
  return buildIPSettingsDraft(true).payload;
}

function updateCertTypeUI() {
  const type = el.certType.value || "acme";
  el.acmeFields.style.display = type === "acme" ? "grid" : "none";
  el.selfSignedFields.style.display = type === "self_signed" ? "grid" : "none";
  // Show DNS provider fields only when acme + dns-01 is selected
  if (type === "acme") {
    const challenge = el.acmeChallenge.value || "http-01";
    el.dnsProviderFields.style.display = challenge === "dns-01" ? "grid" : "none";
  } else {
    el.dnsProviderFields.style.display = "none";
  }
}

function resetCertForm(keepNotice = false) {
  el.certForm.reset();
  el.certType.value = "acme";
  el.acmeProvider.value = "letsencrypt";
  el.acmeChallenge.value = "http-01";
  el.acmeKeyType.value = "ecdsa";
  el.acmeRenewBeforeDays.value = 30;
  el.acmeAutoIssue.checked = true;
  el.dnsProviderName.value = "";
  el.dnsProviderConfig.value = "";
  el.selfKeyAlgorithm.value = "rsa";
  el.selfValidDays.value = 397;
  el.selfRSABits.value = 2048;
  el.selfECDSACurve.value = "p256";
  el.selfIsCA.checked = false;
  updateCertTypeUI();
  if (!keepNotice) {
    clearCertNotice();
  }
}

function readCertForm() {
  const domains = splitCSV(el.certDomains.value);
  if (!domains.length) {
    throw new Error("at least one domain is required");
  }
  const type = el.certType.value || "acme";
  const payload = {
    name: el.certName.value.trim(),
    type,
    domains
  };
  if (type === "acme") {
    const challenge = el.acmeChallenge.value || "http-01";
    const acmePayload = {
      email: el.acmeEmail.value.trim(),
      provider: el.acmeProvider.value,
      challenge: challenge,
      keyType: el.acmeKeyType.value,
      renewBeforeDays: Number(el.acmeRenewBeforeDays.value || 30),
      autoIssue: el.acmeAutoIssue.checked,
      directoryUrl: el.acmeDirectoryURL.value.trim(),
      preferredChain: el.acmePreferredChain.value.trim()
    };
    if (challenge === "dns-01") {
      const dnsName = el.dnsProviderName.value;
      const dnsConfig = el.dnsProviderConfig.value.trim();
      if (!dnsName) {
        throw new Error("DNS provider is required for dns-01 challenge");
      }
      acmePayload.dnsProvider = {
        name: dnsName
      };
      if (dnsConfig) {
        try {
          acmePayload.dnsProvider.config = JSON.parse(dnsConfig);
        } catch (_) {
          throw new Error("DNS provider config must be valid JSON");
        }
      }
    }
    payload.acme = acmePayload;
    return payload;
  }
  payload.selfSigned = {
    commonName: el.selfCommonName.value.trim(),
    keyAlgorithm: el.selfKeyAlgorithm.value,
    validDays: Number(el.selfValidDays.value || 397),
    rsaBits: Number(el.selfRSABits.value || 2048),
    ecdsaCurve: el.selfECDSACurve.value,
    isCA: el.selfIsCA.checked,
    organization: splitCSV(el.selfOrganization.value),
    organizationalUnit: splitCSV(el.selfOrganizationalUnit.value),
    country: splitCSV(el.selfCountry.value),
    province: splitCSV(el.selfProvince.value),
    locality: splitCSV(el.selfLocality.value),
    dnsNames: splitCSV(el.selfDNSNames.value),
    ipAddresses: splitCSV(el.selfIPAddresses.value),
    emailAddresses: splitCSV(el.selfEmailAddresses.value),
    uris: splitCSV(el.selfURIs.value)
  };
  return payload;
}

function certStatusPill(status) {
  if (status === "active") return "pill-on";
  if (status === "pending") return "pill-warn";
  return "pill-off";
}

function renderCertificates() {
  const rows = certificates.map((item) => {
    const name = item.name || item.domains?.[0] || "-";
    const domains = (item.domains || []).join(", ");
    const status = item.status || "pending";
    const expireAt = item.notAfter ? formatDate(item.notAfter) : "-";
    return `
      <tr>
        <td>${escapeHtml(name)}</td>
        <td>${escapeHtml(item.type || "-")}</td>
        <td>${escapeHtml(domains || "-")}</td>
        <td><span class="pill ${certStatusPill(status)}">${escapeHtml(status)}</span></td>
        <td>${escapeHtml(item.issuer || "-")}</td>
        <td>${escapeHtml(expireAt)}</td>
        <td>
          <div class="actions">
            <button class="btn-neutral" data-cert-action="issue" data-id="${item.id}">${t("certIssue")}</button>
            <button class="btn-ghost" data-cert-action="download" data-id="${item.id}">${t("certDownload")}</button>
            <button class="btn-danger" data-cert-action="delete" data-id="${item.id}">${t("del")}</button>
          </div>
        </td>
      </tr>
    `;
  });
  el.certsBody.innerHTML = rows.length ? rows.join("") : `<tr><td colspan="7">${t("certNoData")}</td></tr>`;
}

async function fetchBackups() {
  const data = await httpJSON("/api/backups");
  backups = Array.isArray(data?.items) ? data.items : [];
  backupStatus = data?.status || null;
  renderBackups();
}

function renderBackups() {
  const rows = backups.map((item) => {
    const name = item?.name || "-";
    const size = formatBytes(item?.sizeBytes || 0);
    const timeText = formatDate(item?.createdAt);
    return `
      <tr>
        <td>${escapeHtml(name)}</td>
        <td>${escapeHtml(size)}</td>
        <td>${escapeHtml(timeText)}</td>
        <td>
          <div class="actions">
            <button class="btn-ghost" data-backup-action="download" data-name="${escapeHtml(name)}">${t("certDownload")}</button>
          </div>
        </td>
      </tr>
    `;
  });
  el.backupBody.innerHTML = rows.length ? rows.join("") : `<tr><td colspan="4">${t("backupNoData")}</td></tr>`;
}

function fillForm(site) {
  document.getElementById("name").value = site.name || "";
  document.getElementById("domain").value = site.domain || "";
  document.getElementById("protocol").value = site.protocol || "";
  renderNodeOptions(site.nodeId || "");
  document.getElementById("listenPort").value = site.listenPort || "";
  // Set bindInterfaces multi-select
  pendingBindInterfaceValues = (site.bindInterfaces || []).map(v => String(v).trim()).filter(Boolean);
  if (cachedInterfaces) renderInterfaceSelect(cachedInterfaces);
  document.getElementById("additionalDomains").value = (site.additionalDomains || []).join(", ");
  renderCertificateOptions(site.certificateId || "");
  document.getElementById("loadBalanceStrategy").value = site.loadBalanceStrategy || "round_robin";
  document.getElementById("enabled").checked = site.enabled;
  document.getElementById("forceHttps").checked = !!site.forceHttps;
  document.getElementById("allowCidrs").value = (site.ipAccess?.allowCidrs || []).join("\n");
  document.getElementById("denyCidrs").value = (site.ipAccess?.denyCidrs || []).join("\n");
  document.getElementById("allowAsns").value = (site.ipAccess?.allowAsns || []).join("\n");
  document.getElementById("denyAsns").value = (site.ipAccess?.denyAsns || []).join("\n");
  document.getElementById("denyReputationCidrs").value = (site.ipAccess?.denyReputationCidrs || []).join("\n");
  const selectedRuleSetIDs = Array.isArray(site.ipRuleSetIds) ? [...site.ipRuleSetIds] : [];
  if (!selectedRuleSetIDs.length && site.ipRuleSetId) {
    selectedRuleSetIDs.push(site.ipRuleSetId);
  }
  renderSiteIPRuleSetOptions(selectedRuleSetIDs);
  document.getElementById("removeReqHeaders").value = (site.removeRequestHeaders || []).join(", ");
  document.getElementById("removeRespHeaders").value = (site.removeResponseHeaders || []).join(", ");
  document.getElementById("autoRequestHeaders").checked = !!site.autoRequestHeaders;
  document.getElementById("autoResponseHeaders").checked = !!site.autoResponseHeaders;
  document.getElementById("rateEnabled").checked = !!site.rateLimit?.enabled;
  document.getElementById("requestsPerMinute").value = site.rateLimit?.requestsPerMinute || 120;
  document.getElementById("burst").value = site.rateLimit?.burst || 30;
  document.getElementById("autoBlockEnabled").checked = !!site.rateLimit?.autoBlock?.enabled;
  document.getElementById("autoBlockThreshold").value = site.rateLimit?.autoBlock?.violationThreshold || 5;
  document.getElementById("autoBlockWindowSeconds").value = site.rateLimit?.autoBlock?.violationWindowSeconds || 60;
  document.getElementById("autoBlockSeconds").value = site.rateLimit?.autoBlock?.blockSeconds || 600;
  document.getElementById("authEnabled").checked = !!site.basicAuth?.enabled;
  document.getElementById("authUsername").value = site.basicAuth?.username || "";
  document.getElementById("authPassword").value = "";
  document.getElementById("maxConcurrentRequests").value = site.trafficControl?.maxConcurrentRequests || 0;
  document.getElementById("allowedMethods").value = (site.trafficControl?.allowedMethods || []).join(", ");
  document.getElementById("enableSecurityHeaders").checked = !!site.security?.enableSecurityHeaders;
  document.getElementById("blockUserAgentPatterns").value = (site.security?.blockUserAgentPatterns || []).join(", ");
  document.getElementById("upstreamTlsInsecureSkipVerify").checked = !!site.upstreamTls?.insecureSkipVerify;
  document.getElementById("upstreamTlsServerName").value = site.upstreamTls?.serverName || "";
  document.getElementById("upstreamTlsRootCAFile").value = site.upstreamTls?.rootCAFile || "";
  document.getElementById("upstreamTlsRootCAPem").value = site.upstreamTls?.rootCAPem || "";
  document.getElementById("healthCheckEnabled").checked = !!site.resilience?.activeHealthCheck?.enabled;
  document.getElementById("healthCheckIntervalSeconds").value = site.resilience?.activeHealthCheck?.intervalSeconds || 10;
  document.getElementById("healthCheckTimeoutSeconds").value = site.resilience?.activeHealthCheck?.timeoutSeconds || 5;
  document.getElementById("healthCheckPath").value = site.resilience?.activeHealthCheck?.path || "/health";
  document.getElementById("healthCheckExpectedStatus").value = site.resilience?.activeHealthCheck?.expectedStatus || 200;
  document.getElementById("retryEnabled").checked = !!site.resilience?.retry?.enabled;
  document.getElementById("retryAttempts").value = site.resilience?.retry?.attempts || 2;
  document.getElementById("retryStatuses").value = formatStatusCodesCSV(site.resilience?.retry?.retryOnStatuses || []);
  document.getElementById("retryBackoffStrategy").value = site.resilience?.retry?.backoffStrategy || "fixed";
  document.getElementById("retryBackoffMillis").value = Number(site.resilience?.retry?.backoffMillis || 0);
  document.getElementById("retryMaxBackoffMillis").value = Number(site.resilience?.retry?.maxBackoffMillis || 0);
  document.getElementById("retryJitterPercent").value = Number(site.resilience?.retry?.jitterPercent || 0);
  const retryCfg = site.resilience?.retry || {};
  const hasRetryFlags = ("retryOn5xx" in retryCfg) || ("retryOnTimeout" in retryCfg) || ("retryOnConnection" in retryCfg);
  document.getElementById("retryOn5xx").checked = hasRetryFlags ? !!retryCfg.retryOn5xx : true;
  document.getElementById("retryOnTimeout").checked = !!retryCfg.retryOnTimeout;
  document.getElementById("retryOnConnection").checked = !!retryCfg.retryOnConnection;
  document.getElementById("circuitEnabled").checked = !!site.resilience?.circuitBreaker?.enabled;
  document.getElementById("circuitFailureThreshold").value = site.resilience?.circuitBreaker?.failureThreshold || 5;
  document.getElementById("circuitOpenSeconds").value = site.resilience?.circuitBreaker?.openSeconds || 30;
  document.getElementById("cacheEnabled").checked = !!site.cache?.enabled;
  document.getElementById("cacheProactive").checked = !!site.cache?.proactive;
  document.getElementById("cacheTTLSeconds").value = site.cache?.ttlSeconds || 30;
  document.getElementById("cacheMaxEntries").value = site.cache?.maxEntries || 512;
  document.getElementById("cacheMaxBodyBytes").value = site.cache?.maxBodyBytes || 1048576;
  document.getElementById("cacheKeyIgnoreQueryParams").value = (site.cache?.keyIgnoreQueryParams || []).join(", ");
  document.getElementById("timeoutConnectMillis").value = Number(site.timeouts?.connectMillis || 0);
  document.getElementById("timeoutResponseHeaderMillis").value = Number(site.timeouts?.responseHeaderMillis || 0);
  document.getElementById("timeoutExpectContinueMillis").value = Number(site.timeouts?.expectContinueMillis || 0);
  document.getElementById("timeoutIdleConnMillis").value = Number(site.timeouts?.idleConnMillis || 0);
  document.getElementById("timeoutRequestMillis").value = Number(site.timeouts?.requestMillis || 0);
  document.getElementById("timeoutBackendKeepaliveMillis").value = Number(site.timeouts?.backendKeepaliveMillis || 0);
  document.getElementById("timeoutTLSHandshakeMillis").value = Number(site.timeouts?.tlsHandshakeMillis || 0);
  document.getElementById("timeoutMaxIdleConnsPerHost").value = Number(site.timeouts?.maxIdleConnsPerHost || 0);
  document.getElementById("timeoutMaxBackendConnections").value = Number(site.timeouts?.maxBackendConnections || 0);
  document.getElementById("timeoutBackendKeepaliveDisabled").checked = !!site.timeouts?.backendKeepaliveDisabled;
  document.getElementById("gzipEnabled").checked = !!site.gzip?.enabled;
  document.getElementById("brotliEnabled").checked = !!site.brotli?.enabled;
  document.getElementById("canaryEnabled").checked = !!site.canary?.enabled;
  document.getElementById("canaryHeader").value = site.canary?.header || "";
  document.getElementById("canaryHeaderValue").value = site.canary?.headerValue || "";
  document.getElementById("canaryCookie").value = site.canary?.cookie || "";
  document.getElementById("canaryCookieValue").value = site.canary?.cookieValue || "";
  document.getElementById("canaryWeight").value = Number(site.canary?.weight || 0);
  document.getElementById("canaryLoadBalanceStrategy").value = site.canary?.loadBalanceStrategy || "round_robin";

  // JWT
  document.getElementById("jwtEnabled").checked = !!site.jwt?.enabled;
  document.getElementById("jwtExtractFrom").value = site.jwt?.extractFrom || "header";
  document.getElementById("jwtExtractName").value = site.jwt?.extractName || "";
  document.getElementById("jwtSigningAlgorithm").value = site.jwt?.signingAlgorithm || "HS256";
  document.getElementById("jwtHMACSecret").value = site.jwt?.hmacSecret || "";
  document.getElementById("jwtJWKSURL").value = site.jwt?.jwksUrl || "";
  document.getElementById("jwtIssuer").value = site.jwt?.issuer || "";
  document.getElementById("jwtAudience").value = site.jwt?.audience || "";
  document.getElementById("jwtForwardToken").checked = !!site.jwt?.forwardToken;

  // WAF
  document.getElementById("wafEnabled").checked = !!site.waf?.enabled;
  document.getElementById("wafMode").value = site.waf?.mode || "block";
  document.getElementById("wafSeverityThreshold").value = site.waf?.severityThreshold || "low";
  document.getElementById("wafExcludePaths").value = (site.waf?.excludePaths || []).join(", ");

  // OAuth
  document.getElementById("oauthEnabled").checked = !!site.oauth?.enabled;
  document.getElementById("oauthProvider").value = site.oauth?.provider || "google";
  document.getElementById("oauthClientID").value = site.oauth?.clientId || "";
  document.getElementById("oauthClientSecret").value = site.oauth?.clientSecret || "";
  document.getElementById("oauthAllowedDomains").value = (site.oauth?.allowedDomains || []).join(", ");
  document.getElementById("oauthAllowedEmails").value = (site.oauth?.allowedEmails || []).join(", ");
  document.getElementById("oauthCallbackURL").value = site.oauth?.callbackUrl || "";

  // gRPC
  document.getElementById("grpcEnabled").checked = !!site.grpc?.enabled;
  document.getElementById("grpcH2C").checked = !!site.grpc?.h2c;

  el.upstreams.innerHTML = "";
  const upstreamRows = site.upstreams && site.upstreams.length ? site.upstreams : [{ url: site.upstream || "", weight: 1 }];
  upstreamRows.forEach((item) => el.upstreams.appendChild(newUpstreamRow(item)));
  el.canaryUpstreams.innerHTML = "";
  const canaryRows = site.canary?.upstreams && site.canary?.upstreams.length
    ? site.canary.upstreams
    : (site.canary?.upstream ? [{ url: site.canary.upstream, weight: 1 }] : []);
  canaryRows.forEach((item) => el.canaryUpstreams.appendChild(newUpstreamRow(item)));

  el.routes.innerHTML = "";
  (site.routes || []).forEach((item) => el.routes.appendChild(newRouteRow(item)));

  el.requestHeaders.innerHTML = "";
  (site.requestHeaders || []).forEach((item) => el.requestHeaders.appendChild(newHeaderRow(item)));

  el.responseHeaders.innerHTML = "";
  (site.responseHeaders || []).forEach((item) => el.responseHeaders.appendChild(newHeaderRow(item)));

  if (!el.requestHeaders.children.length) el.requestHeaders.appendChild(newHeaderRow());
  if (!el.responseHeaders.children.length) el.responseHeaders.appendChild(newHeaderRow());
  if (!el.upstreams.children.length) el.upstreams.appendChild(newUpstreamRow());
  if (!el.canaryUpstreams.children.length) el.canaryUpstreams.appendChild(newUpstreamRow());
}

function resetForm(keepNotice = false) {
  editingId = "";
  el.form.reset();
  document.getElementById("enabled").checked = true;
  document.getElementById("forceHttps").checked = true;
  document.getElementById("protocol").value = "";
  document.getElementById("loadBalanceStrategy").value = "round_robin";
  document.getElementById("listenPort").value = "";
  document.getElementById("domain").value = "";

  // Reset new feature fields
  document.getElementById("jwtEnabled").checked = false;
  document.getElementById("jwtExtractFrom").value = "header";
  document.getElementById("jwtExtractName").value = "";
  document.getElementById("jwtSigningAlgorithm").value = "HS256";
  document.getElementById("jwtHMACSecret").value = "";
  document.getElementById("jwtJWKSURL").value = "";
  document.getElementById("jwtIssuer").value = "";
  document.getElementById("jwtAudience").value = "";
  document.getElementById("jwtForwardToken").checked = false;
  document.getElementById("wafEnabled").checked = false;
  document.getElementById("wafMode").value = "block";
  document.getElementById("wafSeverityThreshold").value = "low";
  document.getElementById("wafExcludePaths").value = "";
  document.getElementById("oauthEnabled").checked = false;
  document.getElementById("oauthProvider").value = "google";
  document.getElementById("oauthClientID").value = "";
  document.getElementById("oauthClientSecret").value = "";
  document.getElementById("oauthAllowedDomains").value = "";
  document.getElementById("oauthAllowedEmails").value = "";
  document.getElementById("oauthCallbackURL").value = "";
  document.getElementById("grpcEnabled").checked = false;
  document.getElementById("grpcH2C").checked = false;
  pendingBindInterfaceValues = null;
  resetBindInterfaceCheckboxes();
  document.getElementById("maxConcurrentRequests").value = "0";
  document.getElementById("allowedMethods").value = "";
  document.getElementById("autoRequestHeaders").checked = true;
  document.getElementById("autoResponseHeaders").checked = true;
  document.getElementById("enableSecurityHeaders").checked = false;
  document.getElementById("blockUserAgentPatterns").value = "";
  document.getElementById("allowAsns").value = "";
  document.getElementById("denyAsns").value = "";
  document.getElementById("denyReputationCidrs").value = "";
  document.getElementById("upstreamTlsInsecureSkipVerify").checked = false;
  document.getElementById("upstreamTlsServerName").value = "";
  document.getElementById("upstreamTlsRootCAFile").value = "";
  document.getElementById("upstreamTlsRootCAPem").value = "";
  document.getElementById("healthCheckEnabled").checked = false;
  document.getElementById("healthCheckIntervalSeconds").value = "10";
  document.getElementById("healthCheckTimeoutSeconds").value = "5";
  document.getElementById("healthCheckPath").value = "/health";
  document.getElementById("healthCheckExpectedStatus").value = "200";
  document.getElementById("retryEnabled").checked = false;
  document.getElementById("retryAttempts").value = "2";
  document.getElementById("retryStatuses").value = "502, 503, 504";
  document.getElementById("retryBackoffStrategy").value = "fixed";
  document.getElementById("retryBackoffMillis").value = "0";
  document.getElementById("retryMaxBackoffMillis").value = "0";
  document.getElementById("retryJitterPercent").value = "0";
  document.getElementById("retryOn5xx").checked = true;
  document.getElementById("retryOnTimeout").checked = false;
  document.getElementById("retryOnConnection").checked = false;
  document.getElementById("circuitEnabled").checked = false;
  document.getElementById("circuitFailureThreshold").value = "5";
  document.getElementById("circuitOpenSeconds").value = "30";
  document.getElementById("cacheEnabled").checked = false;
  document.getElementById("cacheProactive").checked = false;
  document.getElementById("cacheTTLSeconds").value = "30";
  document.getElementById("cacheMaxEntries").value = "512";
  document.getElementById("cacheMaxBodyBytes").value = "1048576";
  document.getElementById("cacheKeyIgnoreQueryParams").value = "";
  document.getElementById("timeoutConnectMillis").value = "0";
  document.getElementById("timeoutResponseHeaderMillis").value = "0";
  document.getElementById("timeoutExpectContinueMillis").value = "0";
  document.getElementById("timeoutIdleConnMillis").value = "0";
  document.getElementById("timeoutRequestMillis").value = "0";
  document.getElementById("timeoutBackendKeepaliveMillis").value = "0";
  document.getElementById("timeoutTLSHandshakeMillis").value = "0";
  document.getElementById("timeoutMaxIdleConnsPerHost").value = "0";
  document.getElementById("timeoutMaxBackendConnections").value = "0";
  document.getElementById("timeoutBackendKeepaliveDisabled").checked = false;
  document.getElementById("gzipEnabled").checked = false;
  document.getElementById("brotliEnabled").checked = false;
  document.getElementById("canaryEnabled").checked = false;
  document.getElementById("canaryHeader").value = "";
  document.getElementById("canaryHeaderValue").value = "";
  document.getElementById("canaryCookie").value = "";
  document.getElementById("canaryCookieValue").value = "";
  document.getElementById("canaryWeight").value = "0";
  document.getElementById("canaryLoadBalanceStrategy").value = "round_robin";
  el.upstreams.innerHTML = "";
  el.canaryUpstreams.innerHTML = "";
  el.routes.innerHTML = "";
  el.requestHeaders.innerHTML = "";
  el.responseHeaders.innerHTML = "";
  el.upstreams.appendChild(newUpstreamRow());
  el.canaryUpstreams.appendChild(newUpstreamRow());
  el.requestHeaders.appendChild(newHeaderRow());
  el.responseHeaders.appendChild(newHeaderRow());
  renderCertificateOptions("");
  renderNodeOptions(nodes.find((item) => item.isLocal)?.id || "");
  renderSiteIPRuleSetOptions([]);
  applyLang();
  if (!keepNotice) {
    clearNotice();
  }
  el.cancelEditBtn.hidden = true;
}

function clearNodeNotice() {
  if (el.nodeErrorBox) el.nodeErrorBox.textContent = "";
  if (el.nodeSuccessBox) el.nodeSuccessBox.textContent = "";
}

function showNodeError(message) {
  if (el.nodeErrorBox) el.nodeErrorBox.textContent = message || "";
  if (el.nodeSuccessBox) el.nodeSuccessBox.textContent = "";
}

function showNodeSuccess(message) {
  if (el.nodeSuccessBox) el.nodeSuccessBox.textContent = message || "";
  if (el.nodeErrorBox) el.nodeErrorBox.textContent = "";
}

function fillNodeForm(item) {
  editingNodeID = String(item?.id || "").trim();
  if (el.nodeNodeId) {
    el.nodeNodeId.value = editingNodeID;
    el.nodeNodeId.disabled = Boolean(editingNodeID);
  }
  if (el.nodeName) el.nodeName.value = item?.name || "";
  if (el.nodeEndpoint) el.nodeEndpoint.value = item?.endpoint || "";
  if (el.nodeTags) el.nodeTags.value = (item?.tags || []).join(", ");
  if (el.nodeEnabled) el.nodeEnabled.checked = item?.enabled !== false;
  if (el.nodeFormTitle) el.nodeFormTitle.textContent = editingNodeID ? t("nodeEdit") : t("nodeAdd");
  if (el.nodeSubmitBtn) el.nodeSubmitBtn.textContent = editingNodeID ? t("nodeUpdate") : t("nodeSave");
}

function resetNodeForm(keepNotice = false) {
  editingNodeID = "";
  if (el.nodeForm) el.nodeForm.reset();
  if (el.nodeNodeId) {
    el.nodeNodeId.disabled = false;
    el.nodeNodeId.value = "";
  }
  if (el.nodeEnabled) el.nodeEnabled.checked = true;
  if (el.nodeFormTitle) el.nodeFormTitle.textContent = t("nodeAdd");
  if (el.nodeSubmitBtn) el.nodeSubmitBtn.textContent = t("nodeSave");
  if (!keepNotice) clearNodeNotice();
}

function readNodeForm() {
  const id = String(el.nodeNodeId?.value || "").trim();
  if (!id && !editingNodeID) {
    throw new Error("node ID is required");
  }
  return {
    id: editingNodeID || id,
    name: String(el.nodeName?.value || "").trim(),
    endpoint: String(el.nodeEndpoint?.value || "").trim(),
    tags: splitCSV(el.nodeTags?.value || ""),
    enabled: Boolean(el.nodeEnabled?.checked)
  };
}

async function httpJSON(url, options = {}) {
  const res = await fetch(url, options);
  if (res.status === 401) {
    window.location.replace("/login");
    throw new Error("authentication required");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(formatAPIError(data));
  }
  return data;
}

function formatAPIError(data) {
  const message = String(data?.error || "").trim();
  const leaderNodeId = String(data?.leaderNodeId || "").trim();
  if (leaderNodeId) {
    return `${message || t("opFail")} (leader: ${leaderNodeId})`;
  }
  return message || t("opFail");
}

async function downloadCertificateMaterial(id, asset, format, password = "") {
  const params = new URLSearchParams();
  if (asset) params.set("asset", asset);
  if (format) params.set("format", format);
  if (password) params.set("password", password);
  const res = await fetch(`/api/certificates/${encodeURIComponent(id)}/download?${params.toString()}`);
  if (res.status === 401) {
    window.location.replace("/login");
    throw new Error("authentication required");
  }
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(formatAPIError(data));
  }
  const blob = await res.blob();
  const suffix = format ? `.${format}` : ".bin";
  const fallbackName = `certificate-${id}${suffix}`;
  let filename = fallbackName;
  const contentDisposition = res.headers.get("Content-Disposition") || "";
  const match = contentDisposition.match(/filename=\"?([^\";]+)\"?/i);
  if (match && match[1]) {
    filename = match[1];
  }

  const downloadURL = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = downloadURL;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(downloadURL);
}

async function fetchAll() {
  const [siteData, statData, certData, settingsData, meData, backupData, nodeData, clusterSyncData] = await Promise.all([
    httpJSON("/api/sites"),
    httpJSON("/api/stats"),
    httpJSON("/api/certificates"),
    httpJSON("/api/settings"),
    httpJSON("/auth/me"),
    httpJSON("/api/backups"),
    httpJSON("/api/nodes"),
    httpJSON("/api/cluster-sync")
  ]);
  sites = Array.isArray(siteData) ? siteData : [];
  stats = statData || null;
  certificates = Array.isArray(certData) ? certData : [];
  nodes = Array.isArray(nodeData) ? nodeData : [];
  clusterSyncStatus = clusterSyncData || null;
  appSettings = settingsData || null;
  backups = Array.isArray(backupData?.items) ? backupData.items : [];
  backupStatus = backupData?.status || null;
  ensureInterfaces();
  fillAccountForm(meData?.account || {});
  fillSettingsForm(appSettings);
  fillIPSettingsForm(appSettings);
  const appLang = normalizeLang(appSettings?.language);
  if (!pinnedLang && i18n[appLang] && lang !== appLang) {
    lang = appLang;
    applyLang();
  }
  renderCertificateOptions(el.certificateId?.value || "");
  renderNodeOptions(el.nodeId?.value || "");
  renderAdminTLSCertificateOptions(appSettings?.adminTls?.certificateId || "");
  siteStatsMap = new Map((stats?.topSites || []).map((item) => [item.siteId, item]));
  updateKPI();
  renderSites();
  renderNodes();
  renderControlPlaneStatus();
  renderClusterSyncStatus();
  renderCertificates();
  renderBackups();
  await fetchLogs();
}

async function fetchCertificates() {
  const certData = await httpJSON("/api/certificates");
  certificates = Array.isArray(certData) ? certData : [];
  renderCertificateOptions(el.certificateId?.value || "");
  renderAdminTLSCertificateOptions(appSettings?.adminTls?.certificateId || "");
  renderCertificates();
}

async function fetchLogs() {
  const limit = Number(el.logLimit.value || 50);
  const logs = await httpJSON(`/api/logs?limit=${limit}`);
  window.__logs = Array.isArray(logs) ? logs : [];
  renderLogs();
}

function updateKPI() {
  el.kpiTotalSites.textContent = fmtInt.format(stats?.totalSites || 0);
  el.kpiEnabledSites.textContent = fmtInt.format(stats?.enabledSites || 0);
  el.kpiTotalReq.textContent = fmtInt.format(stats?.totalRequests || 0);
  el.kpiSuccessRate.textContent = `${(stats?.successRate || 0).toFixed(2)}%`;
  el.kpiLatency.textContent = `${(stats?.averageLatencyMs || 0).toFixed(2)} ms`;
}

function nodeLabel(item) {
  if (!item) return "-";
  const name = String(item.name || "").trim();
  const id = String(item.id || "").trim();
  if (name && id && name !== id) return `${name} (${id})`;
  return name || id || "-";
}

function renderNodeOptions(selected = "") {
  if (!el.nodeId) return;
  const current = String(selected || el.nodeId.value || "").trim();
  const options = nodes.map((item) => {
    const value = String(item.id || "").trim();
    const selectedAttr = value === current ? " selected" : "";
    return `<option value="${escapeHtml(value)}"${selectedAttr}>${escapeHtml(nodeLabel(item))}</option>`;
  });
  el.nodeId.innerHTML = options.join("");
  if (!el.nodeId.value && nodes.length) {
    el.nodeId.value = String(nodes[0].id || "").trim();
  }
}

function renderSites() {
  const query = el.searchInput.value.trim().toLowerCase();
  const rows = sites
    .filter((item) => {
      if (!query) return true;
      const extra = (item.additionalDomains || []).join(",");
      return `${item.name || ""} ${item.domain} ${extra} ${item.listenPort || ""}`.toLowerCase().includes(query);
    })
    .map((item) => {
      const metric = siteStatsMap.get(item.id);
      const reqCount = metric?.requests || 0;
      const statusClass = item.enabled ? "pill-on" : "pill-off";
      const statusText = item.enabled ? t("enabledTag") : t("disabledTag");
      const upstreamCount = item.upstreams?.length || (item.upstream ? 1 : 0);
      const certText = item.certificateId ? certificateLabelByID(item.certificateId) : "-";
      const primaryDomain = item.domain || "-";
      const nodeText = nodeLabel(nodes.find((nodeItem) => String(nodeItem.id || "") === String(item.nodeId || "")));
      const proto = (item.protocol || "http").toLowerCase();
      const protoBadge = proto !== "http" ? `<span class="pill pill-proto">${escapeHtml(proto.toUpperCase())}</span> ` : "";
      const label = item.name ? `${protoBadge}${escapeHtml(item.name)}<br/><small>${escapeHtml(primaryDomain)}</small>` : `${protoBadge}${escapeHtml(primaryDomain)}`;
      const portLabel = item.listenPort ? `<br/><small>${proto !== "http" ? "▼" : ""} :${item.listenPort}</small>` : "";
      const upstreamShort = proto !== "http" && item.upstream ? `<br/><small>→ ${escapeHtml(item.upstream.replace(/^https?:\/\//, "").replace(/^udp?:\/\//, ""))}</small>` : "";
      const altDomains = item.additionalDomains?.length;
      const domains = altDomains ? `${label}<br/><small>+ ${altDomains} ${t("extraDomainAlt")}</small>${portLabel}${upstreamShort}` : `${label}${portLabel}${upstreamShort}`;
      return `
        <tr>
          <td>${domains}</td>
          <td>${escapeHtml(nodeText)}</td>
          <td>${upstreamCount}</td>
          <td>${escapeHtml(certText)}</td>
          <td><span class="pill ${statusClass}">${statusText}</span></td>
          <td>${fmtInt.format(reqCount)}</td>
          <td>${formatDate(item.updatedAt)}</td>
          <td>
            <div class="actions">
              <button class="btn-ghost" data-action="edit" data-id="${item.id}">${t("edit")}</button>
              <button class="btn-neutral" data-action="toggle" data-id="${item.id}">${item.enabled ? t("disable") : t("enable")}</button>
              <button class="btn-ghost" data-action="purge-cache" data-id="${item.id}">${t("purgeCache")}</button>
              <button class="btn-danger" data-action="delete" data-id="${item.id}">${t("del")}</button>
            </div>
          </td>
        </tr>
      `;
    });

  el.sitesBody.innerHTML = rows.length ? rows.join("") : `<tr><td colspan="8">${t("noData")}</td></tr>`;
}

function renderNodes() {
  if (!el.nodesBody) return;
  const rows = nodes.map((item) => {
    const statusClass = item.status === "online" ? "pill-on" : (item.status === "disabled" ? "pill-off" : "pill-warn");
    const statusText = item.status || "-";
    const siteCount = Number(item.assignedSites || 0);
    const enabledCount = Number(item.assignedEnabledSites || 0);
    const localBadge = item.isLocal ? `<br/><small>${t("local")}</small>` : "";
    return `
      <tr>
        <td>${escapeHtml(item.id || "-")}${localBadge}</td>
        <td>${escapeHtml(item.name || "-")}<br/><small>${escapeHtml((item.tags || []).join(", ") || "-")}</small></td>
        <td><span class="pill ${statusClass}">${escapeHtml(statusText)}</span></td>
        <td>${siteCount}<br/><small>${t("enabledSites")}: ${enabledCount}</small></td>
        <td>${formatDate(item.lastHeartbeatAt)}</td>
        <td>
          <div class="actions">
            <button class="btn-ghost" data-node-action="edit" data-id="${escapeHtml(item.id || "")}">${t("edit")}</button>
            <button class="btn-neutral" data-node-action="heartbeat" data-id="${escapeHtml(item.id || "")}">${t("nodeHeartbeat")}</button>
            ${item.isLocal ? "" : `<button class="btn-danger" data-node-action="delete" data-id="${escapeHtml(item.id || "")}">${t("del")}</button>`}
          </div>
        </td>
      </tr>
    `;
  });
  el.nodesBody.innerHTML = rows.length ? rows.join("") : `<tr><td colspan="6">${t("noData")}</td></tr>`;
}

function renderClusterSyncStatus() {
  if (!el.clusterSyncStatusCard) return;
  const data = clusterSyncStatus || {};
  const mode = String(data.mode || "-");
  const activeEndpoint = String(data.activeEndpoint || "").trim() || "-";
  const controlWritable = data.controlWritable === true ? t("controlWritable") : t("controlReadOnly");
  const failClose = !!data.failCloseActive;
  const failures = Number(data.consecutiveFailures || 0);
  const lastSuccessAt = data.lastSuccessAt ? formatDate(data.lastSuccessAt) : "-";
  const lastFailureAt = data.lastFailureAt ? formatDate(data.lastFailureAt) : "-";
  const lastError = String(data.lastError || "").trim() || "-";
  const cert = data.certificate || {};
  const certSyncState = cert.enabled === false ? t("certSyncOff") : t("certSyncOn");
  const certLine = `${t("certSync")}=${certSyncState}, ${t("mirrored")}=${Number(cert.syncedCount || 0)}`;
  const failCloseText = failClose ? `${t("failCloseOn")} (${String(data.failCloseReason || "active")})` : t("failCloseOff");
  el.clusterSyncStatusCard.textContent = `${t("syncMode")}: ${mode} | ${t("controlPlane")}: ${controlWritable} | ${t("endpoint")}: ${activeEndpoint} | ${t("failClose")}: ${failCloseText} | ${t("failures")}: ${failures} | ${t("lastSuccess")}: ${lastSuccessAt} | ${t("lastFailure")}: ${lastFailureAt} | ${t("lastError")}: ${lastError} | ${certLine}`;
}

function renderControlPlaneStatus() {
  if (!el.controlPlaneStatusCard) return;
  const cluster = stats?.cluster || {};
  const writable = cluster.controlWritable === true ? t("controlWritable") : t("controlReadOnly");
  const election = String(cluster.controlElectionMode || "standalone");
  const leaderNodeId = String(cluster.controlLeaderNodeId || "").trim() || "-";
  const leaderError = String(cluster.controlLeaderError || "").trim();
  const leaderSwitchCount = Number(cluster.controlLeaderSwitchCount || 0);
  const leaderFlapping = cluster.controlLeaderFlapping === true;
  const leaderRecentEventCount = Number(cluster.controlLeaderRecentEventCount || 0);
  const leaderFlappingWindowSeconds = Number(cluster.controlLeaderFlappingWindowSeconds || 0);
  const leaderLastEventKind = String(cluster.controlLeaderLastEventKind || "").trim() || "-";
  const leaderLastEventAt = cluster.controlLeaderLastEventAt ? formatDate(cluster.controlLeaderLastEventAt) : "-";
  const localNodeId = String(cluster.localNodeId || "-");
  const online = Number(cluster.onlineNodes || 0);
  const total = Number(cluster.totalNodes || 0);
  const errText = leaderError ? ` | leaderError: ${leaderError}` : "";
  const flapText = leaderFlapping ? `${t("flapping")}(${leaderRecentEventCount}/${leaderFlappingWindowSeconds || "-" }s)` : `${t("stable")}(${leaderRecentEventCount}/${leaderFlappingWindowSeconds || "-" }s)`;
  el.controlPlaneStatusCard.classList.toggle("hint-danger", leaderFlapping);
  el.controlPlaneStatusCard.textContent = `${t("controlPlane")}: ${writable} | ${t("election")}: ${election} | ${t("leader")}: ${leaderNodeId} | ${t("leaderEvents")}: ${leaderSwitchCount} | ${t("leaderHealth")}: ${flapText} | ${t("lastError")}: ${leaderLastEventKind}@${leaderLastEventAt} | ${t("local")}: ${localNodeId} | ${t("online")}: ${online}/${t("total")}: ${total}${errText}`;
}

function renderLogs() {
  const logs = window.__logs || [];
  const foldEnabled = Boolean(el.logFoldEnabled?.checked);
  if (el.logFoldWindow) {
    el.logFoldWindow.disabled = !foldEnabled;
  }
  if (!foldEnabled) {
    expandedLogGroups.clear();
  }

  const rows = foldEnabled ? renderFoldedLogs(logs) : logs.map((log) => renderLogRow(log));
  el.logsBody.innerHTML = rows.length ? rows.join("") : `<tr><td colspan="7">${t("noLogs")}</td></tr>`;
}

function renderFoldedLogs(logs) {
  const groups = buildLogGroups(logs, Number(el.logFoldWindow?.value || 3));
  const rows = [];
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i];
    if (group.items.length <= 1) {
      rows.push(renderLogRow(group.items[0]));
      continue;
    }

    const groupID = encodeURIComponent(`${i}:${group.key}:${group.newestTs}:${group.oldestTs}`);
    const expanded = expandedLogGroups.has(groupID);
    const avgDuration = Math.round(group.items.reduce((sum, item) => sum + Number(item.durationMs || 0), 0) / group.items.length);
    const statusText = summarizeStatus(group.items);
    const requestText = `${group.items.length} ${t("logFoldReqCount")}`;
    const pathSummary = summarizePaths(group.items);

    rows.push(`
      <tr>
        <td>${formatDate(group.newestTs)}<div class="log-fold-meta">${formatDate(group.oldestTs)}</div></td>
        <td>${escapeHtml(summarizeDomains(group.items))}</td>
        <td>
          <strong>${escapeHtml(requestText)}</strong>
          <div class="log-fold-meta">${escapeHtml(pathSummary)}</div>
          <button type="button" class="btn-ghost log-fold-toggle" data-log-group-id="${groupID}">${expanded ? t("logFoldCollapse") : t("logFoldExpand")}</button>
        </td>
        <td class="status-code ${statusClassByText(statusText)}">${escapeHtml(statusText)}</td>
        <td>${avgDuration} ms<div class="log-fold-meta">${t("logFoldDurationAvg")}</div></td>
        <td>${escapeHtml(group.backend)}</td>
        <td>${escapeHtml(group.client)}</td>
      </tr>
    `);

    if (expanded) {
      for (const item of group.items) {
        rows.push(renderLogRow(item, "log-fold-detail"));
      }
    }
  }
  return rows;
}

function renderLogRow(log, className = "") {
  const statusClass = `status-${String(log.statusCode || "").charAt(0)}`;
  const cls = className ? ` class="${className}"` : "";
  return `
    <tr${cls}>
      <td>${formatDate(log.timestamp)}</td>
      <td>${escapeHtml(log.domain || "-")}</td>
      <td>${escapeHtml(`${log.method || ""} ${log.path || ""}`.trim())}</td>
      <td class="status-code ${statusClass}">${log.statusCode || "-"}</td>
      <td>${log.durationMs || 0} ms</td>
      <td>${escapeHtml(log.upstream || "-")}</td>
      <td>${escapeHtml(log.clientIp || "-")}</td>
    </tr>
  `;
}

function buildLogGroups(logs, windowSec) {
  const out = [];
  const windowMs = Math.max(1, Number(windowSec) || 3) * 1000;
  let current = null;

  for (const item of logs) {
    const ts = parseTimeMs(item.timestamp);
    const client = String(item.clientIp || "-").trim() || "-";
    const backend = String(item.upstream || item.domain || "-").trim() || "-";
    const key = `${client.toLowerCase()}|${backend.toLowerCase()}`;

    if (current && current.key === key && Math.abs(current.oldestTs - ts) <= windowMs) {
      current.items.push(item);
      current.oldestTs = ts;
      continue;
    }

    current = {
      key,
      client,
      backend,
      newestTs: ts,
      oldestTs: ts,
      items: [item]
    };
    out.push(current);
  }
  return out;
}

function parseTimeMs(input) {
  const d = new Date(input);
  if (Number.isNaN(d.getTime())) return 0;
  return d.getTime();
}

function summarizeDomains(items) {
  const uniq = [...new Set(items.map((item) => String(item.domain || "-").trim() || "-"))];
  if (!uniq.length) return "-";
  if (uniq.length === 1) return uniq[0];
  return `${uniq[0]} +${uniq.length - 1}`;
}

function summarizePaths(items) {
  const uniq = [];
  const seen = new Set();
  for (const item of items) {
    const text = `${item.method || ""} ${item.path || ""}`.trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    if (uniq.length < 3) {
      uniq.push(text);
    }
  }
  if (!uniq.length) return "-";
  if (seen.size > uniq.length) {
    return `${uniq.join(" | ")} ...`;
  }
  return uniq.join(" | ");
}

function summarizeStatus(items) {
  const counters = new Map();
  for (const item of items) {
    const code = Number(item.statusCode || 0);
    if (!code) continue;
    counters.set(code, (counters.get(code) || 0) + 1);
  }
  if (!counters.size) return "-";
  if (counters.size === 1) return String(counters.keys().next().value);

  const parts = [...counters.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 2)
    .map(([code, count]) => `${code}x${count}`);
  return `${t("logFoldMixedStatus")} ${parts.join(", ")}`;
}

function statusClassByText(statusText) {
  const code = Number(String(statusText).match(/\d{3}/)?.[0] || 0);
  return `status-${String(code).charAt(0)}`;
}

function formatDate(input) {
  if (!input) return "-";
  const d = new Date(input);
  if (Number.isNaN(d.getTime())) return "-";
  return d.toLocaleString(LANG_LOCALE[lang] || "en-US", { hour12: false });
}

function formatBytes(input) {
  const size = Number(input || 0);
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = size;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  const digits = idx === 0 ? 0 : 2;
  return `${value.toFixed(digits)} ${units[idx]}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// --- WebSocket Real-Time Log Stream ---
let logLiveWs = null;
let logLiveBuffer = [];

function connectLogStream() {
  if (logLiveWs) return;
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsURL = `${proto}//${window.location.host}/api/logs/stream`;
  logLiveWs = new WebSocket(wsURL);

  logLiveWs.onmessage = (event) => {
    try {
      const entry = JSON.parse(event.data);
      logLiveBuffer.push(entry);
      if (logLiveBuffer.length > 50) {
        logLiveBuffer = logLiveBuffer.slice(-50);
      }
      const logs = window.__logs || [];
      logs.unshift(entry);
      if (logs.length > 500) logs.length = 500;
      window.__logs = logs;
      renderLogs();
    } catch (_) {
      // ignore parse errors
    }
  };

  logLiveWs.onclose = () => {
    logLiveWs = null;
    el.logLiveEnabled.checked = false;
  };

  logLiveWs.onerror = () => {
    if (logLiveWs) {
      logLiveWs.close();
      logLiveWs = null;
    }
    el.logLiveEnabled.checked = false;
  };
}

function disconnectLogStream() {
  if (logLiveWs) {
    logLiveWs.close();
    logLiveWs = null;
  }
  logLiveBuffer = [];
}
