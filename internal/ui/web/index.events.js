el.langBtn.addEventListener("click", () => {
  lang = nextLang(lang);
  pinnedLang = true;
  localStorage.setItem("fp_lang", lang);
  applyLang();
});

for (const btn of el.navButtons) {
  btn.addEventListener("click", () => {
    setActiveView(btn.dataset.view || "overview");
  });
}

el.refreshBtn.addEventListener("click", async () => {
  clearNotice();
  try {
    await fetchAll();
  } catch (err) {
    showError(err.message || t("loadFail"));
  }
});
el.logoutBtn.addEventListener("click", async () => {
  try {
    await httpJSON("/auth/logout", { method: "POST" });
  } catch (_) {
  }
  window.location.replace("/login");
});

el.reloadSitesBtn.addEventListener("click", async () => {
  try {
    const [siteData, statData, certData, nodeData] = await Promise.all([
      httpJSON("/api/sites"),
      httpJSON("/api/stats"),
      httpJSON("/api/certificates"),
      httpJSON("/api/nodes")
    ]);
    sites = Array.isArray(siteData) ? siteData : [];
    stats = statData || null;
    certificates = Array.isArray(certData) ? certData : [];
    nodes = Array.isArray(nodeData) ? nodeData : [];
    renderCertificateOptions(el.certificateId?.value || "");
    renderNodeOptions(el.nodeId?.value || "");
    renderAdminTLSCertificateOptions(appSettings?.adminTls?.certificateId || "");
    siteStatsMap = new Map((stats?.topSites || []).map((item) => [item.siteId, item]));
    updateKPI();
    renderSites();
    renderNodes();
  } catch (err) {
    showError(err.message);
  }
});

el.reloadLogsBtn.addEventListener("click", async () => {
  try {
    await fetchLogs();
  } catch (err) {
    showError(err.message);
  }
});
el.logLiveEnabled.addEventListener("change", () => {
  if (el.logLiveEnabled.checked) {
    connectLogStream();
  } else {
    disconnectLogStream();
  }
});
el.settingsResetBtn.addEventListener("click", () => {
  fillSettingsForm(appSettings || {});
  clearSettingsNotice();
});
el.addIPPageRuleSetBtn.addEventListener("click", () => {
  applyIPRuleSetFromEditor();
});
el.ipRuleCreatorResetBtn?.addEventListener("click", () => {
  if (ipRuleSetEditingIndex >= 0) {
    beginEditIPRuleSet(ipRuleSetEditingIndex);
  } else {
    resetIPRuleSetCreator();
  }
  clearIPSettingsNotice();
});
el.ipRuleCreatorCancelBtn?.addEventListener("click", () => {
  cancelEditIPRuleSet();
  clearIPSettingsNotice();
});
el.ipRuleSetManageCards?.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-ip-rule-action]");
  if (!btn) return;
  const action = btn.dataset.ipRuleAction;
  const index = Number(btn.dataset.ipRuleIndex);
  if (!Number.isInteger(index) || index < 0) return;
  if (action === "edit") {
    beginEditIPRuleSet(index);
    return;
  }
  if (action === "delete") {
    const row = el.ipSettingsIPRuleSets?.children?.[index];
    if (!row) return;
    markIPSettingsDraftDirty();
    row.remove();
    if (ipRuleSetEditingIndex === index) {
      cancelEditIPRuleSet();
    } else if (ipRuleSetEditingIndex > index) {
      ipRuleSetEditingIndex -= 1;
      updateIPRuleSetEditorState();
    }
    refreshIPRuleSetRowsMeta();
    renderIPSettingsOverview();
  }
});
el.addIPCountryAutoUpdateBtn?.addEventListener("click", () => {
  markIPSettingsDraftDirty();
  el.ipSettingsIPCountryAutoUpdates.appendChild(newIPCountryAutoUpdateRow());
  refreshIPCountryAutoUpdateRowsMeta();
  renderIPSettingsOverview();
});
el.ipSettingsNormalizeBtn?.addEventListener("click", () => {
  markIPSettingsDraftDirty();
  normalizeIPSettingsFormInputs();
  showIPSettingsSuccess(t("ipRulesNormalizedOk"));
});
el.ipRulesImportBtn?.addEventListener("click", () => {
  if (!el.ipRulesImportInput) return;
  el.ipRulesImportInput.value = "";
  el.ipRulesImportInput.click();
});
el.ipRulesImportInput?.addEventListener("change", async () => {
  const file = el.ipRulesImportInput.files && el.ipRulesImportInput.files[0];
  if (!file) return;
  clearIPSettingsNotice();
  try {
    const content = await file.text();
    const payload = parseImportedIPRulesByFile(file.name || "", content);
    if (hasCurrentIPRulesDraftData() && !window.confirm(t("ipRulesImportConfirmReplace"))) {
      return;
    }
    applyImportedIPRulesPayload(payload);
    showIPSettingsSuccess(t("ipRulesImportOk"));
  } catch (err) {
    showIPSettingsError(err.message || t("ipRulesImportFailed"));
  } finally {
    el.ipRulesImportInput.value = "";
  }
});
el.ipRulesExportTxtBtn?.addEventListener("click", () => {
  clearIPSettingsNotice();
  try {
    exportIPRulesAsTXT();
    showIPSettingsSuccess(t("ipRulesExportOk"));
  } catch (err) {
    showIPSettingsError(err.message || t("opFail"));
  }
});
el.ipRulesExportCsvBtn?.addEventListener("click", () => {
  clearIPSettingsNotice();
  try {
    exportIPRulesAsCSV();
    showIPSettingsSuccess(t("ipRulesExportOk"));
  } catch (err) {
    showIPSettingsError(err.message || t("opFail"));
  }
});
el.ipRulesExportJsonBtn?.addEventListener("click", () => {
  clearIPSettingsNotice();
  try {
    exportIPRulesAsJSON();
    showIPSettingsSuccess(t("ipRulesExportOk"));
  } catch (err) {
    showIPSettingsError(err.message || t("opFail"));
  }
});
el.ipSettingsAllowCidrs?.addEventListener("input", () => {
  markIPSettingsDraftDirty();
  renderIPSettingsOverview();
  showIPSettingsSuccess("");
});
el.ipSettingsDenyCidrs?.addEventListener("input", () => {
  markIPSettingsDraftDirty();
  renderIPSettingsOverview();
  showIPSettingsSuccess("");
});
el.ipRuleSourceOrder?.addEventListener("input", () => {
  markIPSettingsDraftDirty();
  renderIPSettingsOverview();
  showIPSettingsSuccess("");
});
el.ipRuleSetId?.addEventListener("change", () => {
  renderSiteIPRuleSetSelectionSummary(selectedValues(el.ipRuleSetId));
});
el.backupQuickDownloadBtn.addEventListener("click", () => {
  window.open("/api/backups/download", "_blank");
});
el.backupReloadBtn.addEventListener("click", async () => {
  try {
    await fetchBackups();
  } catch (err) {
    showSettingsError(err.message || t("opFail"));
  }
});
el.backupUploadBtn.addEventListener("click", () => {
  el.backupUploadInput.value = "";
  el.backupUploadInput.click();
});
el.backupUploadInput.addEventListener("change", async () => {
  const file = el.backupUploadInput.files && el.backupUploadInput.files[0];
  if (!file) return;
  clearSettingsNotice();
  try {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/backups/upload", {
      method: "POST",
      body: form
    });
    if (res.status === 401) {
      window.location.replace("/login");
      return;
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || t("opFail"));
    }
    await fetchBackups();
    showSettingsSuccess(t("backupUploadedOk"));
  } catch (err) {
    showSettingsError(err.message || t("opFail"));
  }
});
el.backupNowBtn.addEventListener("click", async () => {
  clearSettingsNotice();
  try {
    await httpJSON("/api/backups", { method: "POST" });
    await fetchBackups();
    showSettingsSuccess(t("backupCreatedOk"));
  } catch (err) {
    showSettingsError(err.message || t("opFail"));
  }
});
el.backupBody.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-backup-action]");
  if (!btn) return;
  const action = btn.dataset.backupAction;
  const name = (btn.dataset.name || "").trim();
  if (action === "download" && name) {
    window.open(`/api/backups/${encodeURIComponent(name)}/download`, "_blank");
  }
});
el.settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearSettingsNotice();
  try {
    const payload = readSettingsForm();
    const updated = await httpJSON("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    appSettings = updated || payload;
    fillSettingsForm(appSettings);
    const appLang = normalizeLang(appSettings?.language);
    if (i18n[appLang] && lang !== appLang) {
      lang = appLang;
      pinnedLang = true;
      localStorage.setItem("fp_lang", lang);
      applyLang();
    }
    showSettingsSuccess(t("settingsSavedOk"));
  } catch (err) {
    showSettingsError(err.message || t("opFail"));
  }
});
el.ipSettingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearIPSettingsNotice();
  try {
    normalizeIPSettingsFormInputs();
    const payload = readIPSettingsForm();
    const updated = await httpJSON("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    appSettings = updated || appSettings || {};
    fillSettingsForm(appSettings);
    fillIPSettingsForm(appSettings, { force: true });
    clearLocalIPSettingsDraft();
    renderSiteIPRuleSetOptions(selectedValues(el.ipRuleSetId));
    showIPSettingsSuccess(t("settingsSavedOk"));
  } catch (err) {
    showIPSettingsError(err.message || t("opFail"));
  }
});
el.accountSaveBtn.addEventListener("click", async () => {
  clearSettingsNotice();

  const currentPassword = (el.currentAdminPassword.value || "").trim();
  const newUsername = (el.newAdminUsername.value || "").trim();
  const newPassword = (el.newAdminPassword.value || "").trim();
  const confirmPassword = (el.confirmAdminPassword.value || "").trim();

  if (!currentPassword) {
    showSettingsError(t("accountCurrentPassRequired"));
    return;
  }
  if (newPassword !== confirmPassword) {
    showSettingsError(t("accountPassMismatch"));
    return;
  }

  try {
    const result = await httpJSON("/auth/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        currentPassword,
        newUsername,
        newPassword
      })
    });
    fillAccountForm(result?.account || {});
    clearAccountSecrets();
    showSettingsSuccess(t("accountSavedOk"));
  } catch (err) {
    showSettingsError(err.message || t("opFail"));
  }
});

el.logLimit.addEventListener("change", fetchLogs);
el.logFoldEnabled.addEventListener("change", () => {
  expandedLogGroups.clear();
  renderLogs();
});
el.logFoldWindow.addEventListener("change", () => {
  expandedLogGroups.clear();
  renderLogs();
});
el.logsBody.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-log-group-id]");
  if (!btn) return;
  const id = btn.dataset.logGroupId;
  if (!id) return;
  if (expandedLogGroups.has(id)) {
    expandedLogGroups.delete(id);
  } else {
    expandedLogGroups.add(id);
  }
  renderLogs();
});
el.searchInput.addEventListener("input", renderSites);
document.getElementById("domain").addEventListener("input", () => renderCertificateOptions(el.certificateId?.value || ""));
document.getElementById("additionalDomains").addEventListener("input", () => renderCertificateOptions(el.certificateId?.value || ""));
document.getElementById("protocol").addEventListener("change", () => {
  const protocol = document.getElementById("protocol").value;
  const isL4 = protocol === "tcp" || protocol === "udp" || protocol === "tls";
  const l4Hint = document.getElementById("l4Hint");
  const domainLabel = document.querySelector("label:has(#domain)");
  const extraDomainLabel = document.querySelector("label:has(#additionalDomains)");
  const certLabel = document.querySelector("label:has(#certificateId)");
  const forceHttpsLabel = document.querySelector("label:has(#forceHttps)");
  const lbLabel = document.querySelector("label:has(#loadBalanceStrategy)");
  if (l4Hint) l4Hint.style.display = isL4 ? "block" : "none";
  if (domainLabel) domainLabel.style.display = isL4 ? "none" : "";
  if (extraDomainLabel) extraDomainLabel.style.display = isL4 ? "none" : "";
  if (certLabel) certLabel.style.display = isL4 ? "none" : "";
  if (forceHttpsLabel) forceHttpsLabel.style.display = isL4 ? "none" : "";
  if (lbLabel) lbLabel.style.display = isL4 ? "none" : "";
});

el.addUpstreamBtn.addEventListener("click", () => {
  el.upstreams.appendChild(newUpstreamRow());
});
el.addCanaryUpstreamBtn.addEventListener("click", () => {
  el.canaryUpstreams.appendChild(newUpstreamRow());
});

el.addRouteBtn.addEventListener("click", () => {
  el.routes.appendChild(newRouteRow());
});

el.addReqHeaderBtn.addEventListener("click", () => {
  el.requestHeaders.appendChild(newHeaderRow());
});

el.addRespHeaderBtn.addEventListener("click", () => {
  el.responseHeaders.appendChild(newHeaderRow());
});

el.clearBtn.addEventListener("click", resetForm);
el.cancelEditBtn.addEventListener("click", resetForm);
el.nodeClearBtn?.addEventListener("click", () => resetNodeForm());
el.certType.addEventListener("change", updateCertTypeUI);
el.acmeChallenge.addEventListener("change", updateCertTypeUI);
el.certClearBtn.addEventListener("click", () => resetCertForm());
el.reloadCertsBtn.addEventListener("click", async () => {
  try {
    await fetchCertificates();
  } catch (err) {
    showCertError(err.message || t("opFail"));
  }
});
el.certDownloadCloseBtn.addEventListener("click", closeDownloadModal);
el.certDownloadCancelBtn.addEventListener("click", closeDownloadModal);
el.certDownloadModal.addEventListener("click", (event) => {
  if (event.target === el.certDownloadModal) {
    closeDownloadModal();
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !el.certDownloadModal.hidden) {
    closeDownloadModal();
  }
});
el.certDownloadConfirmBtn.addEventListener("click", async () => {
  if (!downloadModalCertID) return;
  const asset = el.certDownloadAsset.value || "cert";
  const format = el.certDownloadFormat.value || "pem";
  const password = (el.certDownloadPassword.value || "").trim();
  clearCertNotice();
  try {
    await downloadCertificateMaterial(downloadModalCertID, asset, format, password);
    closeDownloadModal();
  } catch (err) {
    showCertError(err.message || t("opFail"));
  }
});

el.certForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearCertNotice();
  try {
    const payload = readCertForm();
    await httpJSON("/api/certificates", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    showCertSuccess(t("certCreatedOk"));
    await fetchCertificates();
    resetCertForm(true);
  } catch (err) {
    showCertError(err.message || t("opFail"));
  }
});

el.certsBody.addEventListener("click", async (event) => {
  const btn = event.target.closest("button[data-cert-action]");
  if (!btn) return;
  const id = btn.dataset.id;
  const action = btn.dataset.certAction;
  if (!id) return;

  clearCertNotice();
  try {
    if (action === "issue") {
      await httpJSON(`/api/certificates/${id}/issue`, { method: "POST" });
      showCertSuccess(t("certIssuedOk"));
      await fetchCertificates();
      return;
    }
    if (action === "download") {
      openDownloadModal(id);
      return;
    }
    if (action === "delete") {
      if (!window.confirm(t("certDeleteConfirm"))) return;
      await httpJSON(`/api/certificates/${id}`, { method: "DELETE" });
      showCertSuccess(t("certDeletedOk"));
      await fetchCertificates();
    }
  } catch (err) {
    showCertError(err.message || t("opFail"));
  }
});

el.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearNotice();
  try {
    const payload = readForm();

    if (editingId) {
      await httpJSON(`/api/sites/${editingId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      showSuccess(t("updatedOk"));
    } else {
      await httpJSON("/api/sites", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      showSuccess(t("createdOk"));
    }
    await fetchAll();
    resetForm(true);
  } catch (err) {
    showError(err.message || t("opFail"));
  }
});

el.nodeForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearNodeNotice();
  try {
    const payload = readNodeForm();
    if (editingNodeID) {
      await httpJSON(`/api/nodes/${encodeURIComponent(editingNodeID)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      showNodeSuccess("节点已更新");
    } else {
      await httpJSON("/api/nodes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      showNodeSuccess("节点已创建");
    }
    await fetchAll();
    resetNodeForm(true);
  } catch (err) {
    showNodeError(err.message || t("opFail"));
  }
});

el.sitesBody.addEventListener("click", async (event) => {
  const btn = event.target.closest("button[data-action]");
  if (!btn) return;
  clearNotice();
  const id = btn.dataset.id;
  const action = btn.dataset.action;
  const target = sites.find((item) => item.id === id);
  if (!target) return;

  try {
    if (action === "edit") {
      editingId = id;
      fillForm(target);
      el.formTitle.textContent = t("formEdit");
      el.submitBtn.textContent = t("update");
      el.cancelEditBtn.hidden = false;
      setActiveView("sites");
      return;
    }

    if (action === "delete") {
      if (!window.confirm(t("deleteConfirm"))) return;
      await httpJSON(`/api/sites/${id}`, { method: "DELETE" });
      showSuccess(t("deletedOk"));
    }

    if (action === "toggle") {
      await httpJSON(`/api/sites/${id}/toggle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !target.enabled })
      });
      showSuccess(t("toggledOk"));
    }

    if (action === "purge-cache") {
      const result = await httpJSON(`/api/sites/${id}/cache/purge`, {
        method: "POST"
      });
      const count = Number(result?.purgedEntries || 0);
      showSuccess(`${t("cachePurgedOk")} (${count})`);
    }

    await fetchAll();
  } catch (err) {
    showError(err.message || t("opFail"));
  }
});

el.nodesBody?.addEventListener("click", async (event) => {
  const btn = event.target.closest("button[data-node-action]");
  if (!btn) return;
  clearNodeNotice();
  const id = String(btn.dataset.id || "").trim();
  const action = btn.dataset.nodeAction;
  const target = nodes.find((item) => String(item.id || "") === id);
  if (!id || !target) return;
  try {
    if (action === "edit") {
      fillNodeForm(target);
      setActiveView("nodes");
      return;
    }
    if (action === "heartbeat") {
      await httpJSON(`/api/nodes/${encodeURIComponent(id)}/heartbeat`, { method: "POST" });
      showNodeSuccess("心跳已刷新");
    }
    if (action === "delete") {
      if (!window.confirm("确定删除该节点吗？")) return;
      await httpJSON(`/api/nodes/${encodeURIComponent(id)}`, { method: "DELETE" });
      showNodeSuccess("节点已删除");
    }
    await fetchAll();
  } catch (err) {
    showNodeError(err.message || t("opFail"));
  }
});

async function boot() {
  resetForm();
  resetNodeForm();
  resetCertForm();
  resetIPRuleSetCreator();
  applyLang();
  setActiveView(activeView);
  try {
    await fetchAll();
  } catch (err) {
    showError(err.message || t("loadFail"));
  }
  refreshTimer = setInterval(async () => {
    try {
      await fetchAll();
    } catch (_) {
    }
  }, 8000);
}

boot();
