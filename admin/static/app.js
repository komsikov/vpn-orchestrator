"use strict";

const byId = (id) => document.getElementById(id);
const ui = Object.fromEntries([
  "boot", "login", "login-form", "login-status", "username", "password", "logout",
  "dashboard", "dashboard-status", "endpoint", "active-upstream", "service-status", "refresh",
  "devices-tab", "upstreams-tab", "devices-panel", "upstreams-panel",
  "create-device", "device-form", "device-name", "cancel-device", "devices-table", "device-rows", "devices-empty",
  "device-download", "download-title", "download-link", "dismiss-download",
  "create-upstream", "upstream-form", "upstream-form-title", "upstream-name", "upstream-kind", "upstream-file",
  "upstream-config", "cancel-upstream", "upstreams-table", "upstream-rows", "upstreams-empty",
].map((id) => [id, byId(id)]));

const dateFormat = new Intl.DateTimeFormat("ru-RU", { dateStyle: "short", timeStyle: "short" });
const protocols = { wireguard: "WireGuard", amneziawg: "AmneziaWG" };

let session = null;
let busy = false;
let stateRequest = null;
let upstreamId = null;
let downloadUrl = null;

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function api(path, input) {
  const options = { credentials: "same-origin", cache: "no-store" };
  if (input !== undefined) {
    options.method = "POST";
    options.headers = { "Content-Type": "application/json" };
    if (session?.csrf) options.headers["X-CSRF-Token"] = session.csrf;
    options.body = JSON.stringify(input);
  }

  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new ApiError("Панель недоступна. Проверь подключение и повтори попытку.", 0);
  }
  const result = await response.json().catch(() => null);
  if (!response.ok || !result || result.ok === false) {
    throw new ApiError(result?.error || "Сервер вернул ошибку. Повтори попытку.", response.status);
  }
  return result;
}

function notice(element, message, kind = "") {
  element.textContent = message;
  element.className = kind ? `notice ${kind}` : "notice";
  element.hidden = !message;
}

function clearDownload() {
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = null;
  ui["download-link"].removeAttribute("href");
  ui["download-link"].removeAttribute("download");
  ui["download-title"].textContent = "";
  ui["device-download"].hidden = true;
}

function setEditor(editor, trigger, open) {
  editor.hidden = !open;
  trigger.setAttribute("aria-expanded", String(open));
}

function closeDeviceEditor(returnFocus = false) {
  ui["device-form"].reset();
  setEditor(ui["device-form"], ui["create-device"], false);
  if (returnFocus) ui["create-device"].focus();
}

function closeUpstreamEditor(returnFocus = false) {
  ui["upstream-form"].reset();
  upstreamId = null;
  setEditor(ui["upstream-form"], ui["create-upstream"], false);
  if (returnFocus) ui["create-upstream"].focus();
}

function showLogin(message = "") {
  session = null;
  ui.boot.hidden = true;
  ui.dashboard.hidden = true;
  ui.logout.hidden = true;
  ui.login.hidden = false;
  ui.password.value = "";
  ui["device-rows"].replaceChildren();
  ui["upstream-rows"].replaceChildren();
  clearDownload();
  closeDeviceEditor();
  closeUpstreamEditor();
  notice(ui["login-status"], message, "error");
  (ui.username.value ? ui.password : ui.username).focus();
}

async function showDashboard(current) {
  session = current;
  ui.password.value = "";
  ui.login.hidden = true;
  ui.boot.hidden = true;
  ui.dashboard.hidden = false;
  ui.logout.hidden = false;
  ui["devices-table"].hidden = true;
  ui["upstreams-table"].hidden = true;
  ui["devices-empty"].hidden = false;
  ui["upstreams-empty"].hidden = false;
  ui["devices-empty"].textContent = "Загружаем устройства…";
  ui["upstreams-empty"].textContent = "Загружаем исходящие туннели…";
  ui["service-status"].textContent = "Проверяем…";
  ui["service-status"].className = "service-status";
  ui["active-upstream"].textContent = "Проверяем…";
  selectPanel("devices");
  notice(ui["dashboard-status"], "");
  await refreshState();
}

function selectPanel(name) {
  for (const tab of ["devices", "upstreams"]) {
    const selected = name === tab;
    ui[`${tab}-panel`].hidden = !selected;
    if (selected) ui[`${tab}-tab`].setAttribute("aria-current", "page");
    else ui[`${tab}-tab`].removeAttribute("aria-current");
  }
}

function labelCell(value, label = "", className = "") {
  const cell = document.createElement("td");
  cell.className = className;
  if (label) cell.dataset.label = label;
  if (value instanceof Node) cell.append(value);
  else cell.textContent = value;
  return cell;
}

function rowTitle(name) {
  const heading = document.createElement("th");
  heading.scope = "row";
  heading.textContent = name;
  return heading;
}

function rowButton(label, context, action, kind = "quiet") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `button ${kind}`;
  button.textContent = label;
  button.setAttribute("aria-label", `${label}: ${context}`);
  button.addEventListener("click", action);
  return button;
}

function actionsCell(...buttons) {
  const controls = document.createElement("div");
  controls.className = "row-actions";
  controls.append(...buttons);
  return labelCell(controls, "", "action-cell");
}

function handshakeLabel(seconds) {
  if (!seconds) return "Ещё не подключалось";
  const date = new Date(Number(seconds) * 1000);
  if (!Number.isFinite(date.getTime())) return "Время неизвестно";
  const time = document.createElement("time");
  time.dateTime = date.toISOString();
  time.textContent = dateFormat.format(date);
  return time;
}

function renderDevices(devices) {
  const rows = devices.map((device) => {
    const row = document.createElement("tr");
    const revoke = rowButton("Отозвать", device.name, () => revokeDevice(device), "danger");
    row.append(
      rowTitle(device.name),
      labelCell(device.address, "VPN-адрес", "address"),
      labelCell(handshakeLabel(device.last_handshake), "Последнее подключение"),
      actionsCell(revoke),
    );
    return row;
  });
  ui["device-rows"].replaceChildren(...rows);
  ui["devices-table"].hidden = !rows.length;
  ui["devices-empty"].hidden = Boolean(rows.length);
  ui["devices-empty"].textContent = "Добавь устройство, чтобы создать первый профиль WireGuard.";
}

function renderUpstreams(upstreams) {
  const rows = upstreams.map((item) => {
    const row = document.createElement("tr");
    const actions = [];
    if (item.replaceable) actions.push(rowButton("Заменить", item.name, () => openUpstreamEditor(item)));
    if (item.toggleable) {
      actions.push(rowButton(item.enabled ? "Отключить" : "Включить", item.name, () => toggleUpstream(item)));
    }
    const state = document.createElement("span");
    state.className = "status-tag";
    state.classList.toggle("active", Boolean(item.active));
    state.textContent = item.active ? "Активен" : item.enabled ? "Включён" : "Отключён";
    row.append(
      rowTitle(item.name),
      labelCell(protocols[item.kind] || item.kind, "Протокол"),
      labelCell(state, "Состояние"),
      actionsCell(...actions),
    );
    return row;
  });
  ui["upstream-rows"].replaceChildren(...rows);
  ui["upstreams-table"].hidden = !rows.length;
  ui["upstreams-empty"].hidden = Boolean(rows.length);
  ui["upstreams-empty"].textContent = "Добавь конфигурацию исходящего VPN.";
}

function refreshState() {
  if (stateRequest || !session) return stateRequest;
  ui.refresh.disabled = true;
  const current = session;
  stateRequest = loadState(current).finally(() => {
    stateRequest = null;
    if (!busy) ui.refresh.disabled = false;
  });
  return stateRequest;
}

async function loadState(current) {
  try {
    const state = await api("/api/state");
    if (session !== current) return;
    const upstreams = state.upstreams || [];
    const active = upstreams.find((entry) => entry.active || entry.id === state.active_upstream);
    if (state.endpoint) ui.endpoint.textContent = state.endpoint;
    ui["active-upstream"].textContent = active?.name || state.active_upstream || "Туннель не выбран";
    ui["service-status"].textContent = state.service_active ? "Служба работает" : "Служба остановлена";
    ui["service-status"].className = `service-status ${state.service_active ? "running" : "stopped"}`;
    renderDevices(state.devices || []);
    renderUpstreams(upstreams);
  } catch (error) {
    if (session !== current) return;
    if (error.status === 401) showLogin("Сеанс завершён. Войди снова.");
    else {
      ui["service-status"].textContent = "Статус недоступен";
      ui["service-status"].className = "service-status";
      if (ui["devices-table"].hidden) ui["devices-empty"].textContent = "Список устройств недоступен.";
      if (ui["upstreams-table"].hidden) ui["upstreams-empty"].textContent = "Список туннелей недоступен.";
      notice(ui["dashboard-status"], error.message, "error");
    }
  }
}

async function withChange(pending, change) {
  if (busy || !session) return;
  busy = true;
  const buttons = [ui.logout, ...ui.dashboard.querySelectorAll("button")];
  for (const button of buttons) button.disabled = true;
  notice(ui["dashboard-status"], pending);
  try {
    if (stateRequest) await stateRequest;
    if (!session) return;
    await change();
    await refreshState();
  } catch (error) {
    if (error.status === 401) showLogin("Сеанс завершён. Войди снова.");
    else notice(ui["dashboard-status"], error.message, "error");
  } finally {
    busy = false;
    for (const button of buttons) button.disabled = false;
    if (stateRequest) ui.refresh.disabled = true;
  }
}

function openDeviceEditor() {
  clearDownload();
  setEditor(ui["device-form"], ui["create-device"], true);
  ui["device-name"].focus();
}

async function createDevice(event) {
  event.preventDefault();
  const name = ui["device-name"].value.trim();
  if (!name) {
    notice(ui["dashboard-status"], "Укажи имя устройства.", "error");
    return;
  }
  await withChange("Создаём профиль…", async () => {
    const result = await api("/api/devices", { name });
    if (!result.config) throw new ApiError("Сервер создал устройство, но не вернул файл профиля.", 0);
    clearDownload();
    closeDeviceEditor();
    downloadUrl = URL.createObjectURL(new Blob([result.config], { type: "text/plain;charset=utf-8" }));
    ui["download-link"].href = downloadUrl;
    const filename = (result.filename || "wireguard.conf").replace(/[\u0000-\u001f\u007f/\\]/g, "-");
    ui["download-link"].download = filename;
    ui["download-title"].textContent = `Профиль «${result.device?.name || name}» готов`;
    ui["device-download"].hidden = false;
    ui["download-link"].focus();
    notice(ui["dashboard-status"], "");
  });
}

async function revokeDevice(device) {
  if (!window.confirm(`Отозвать профиль «${device.name}»? Это устройство потеряет доступ к VPN.`)) return;
  await withChange("Отзываем профиль…", async () => {
    await api("/api/devices/revoke", { id: device.id });
    clearDownload();
    notice(ui["dashboard-status"], `Профиль «${device.name}» отозван.`, "success");
  });
  if (!ui.dashboard.hidden) ui["create-device"].focus();
}

function openUpstreamEditor(item = null) {
  ui["upstream-form"].reset();
  upstreamId = item?.id ?? null;
  ui["upstream-form-title"].textContent = item ? `Заменить «${item.name}»` : "Добавить туннель";
  ui["upstream-name"].value = item?.name || "";
  ui["upstream-kind"].value = item?.kind || "amneziawg";
  setEditor(ui["upstream-form"], ui["create-upstream"], true);
  ui[item ? "upstream-config" : "upstream-name"].focus();
}

async function loadUpstreamFile(event) {
  const input = event.currentTarget;
  const file = input.files?.[0];
  if (!file) return;
  try {
    if (file.size > 24 * 1024) throw new Error("Файл конфигурации больше 24 КиБ.");
    ui["upstream-config"].value = await file.text();
    ui["upstream-config"].focus();
    notice(ui["dashboard-status"], "");
  } catch (error) {
    notice(ui["dashboard-status"], error.message || "Файл не удалось прочитать.", "error");
  } finally {
    input.value = "";
  }
}

async function saveUpstream(event) {
  event.preventDefault();
  const input = {
    name: ui["upstream-name"].value.trim(),
    kind: ui["upstream-kind"].value,
    config: ui["upstream-config"].value.trim(),
  };
  if (!input.name || !input.config) {
    notice(ui["dashboard-status"], "Укажи название и добавь конфигурацию.", "error");
    return;
  }
  if (upstreamId !== null) input.id = upstreamId;
  await withChange("Применяем конфигурацию туннеля…", async () => {
    await api("/api/upstreams", input);
    closeUpstreamEditor();
    notice(ui["dashboard-status"], `Конфигурация «${input.name}» сохранена.`, "success");
  });
  if (ui["upstream-form"].hidden && !ui.dashboard.hidden) ui["create-upstream"].focus();
}

async function toggleUpstream(item) {
  const enabled = !item.enabled;
  await withChange(enabled ? "Включаем туннель…" : "Отключаем туннель…", async () => {
    await api("/api/upstreams/toggle", { id: item.id, enabled });
    notice(ui["dashboard-status"], `Туннель «${item.name}» ${enabled ? "включён" : "отключён"}.`, "success");
  });
  if (!ui.dashboard.hidden) ui["create-upstream"].focus();
}

ui["login-form"].addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = event.currentTarget.querySelector("button");
  submit.disabled = true;
  notice(ui["login-status"], "Проверяем данные…");
  const data = { username: ui.username.value.trim(), password: ui.password.value };
  ui.password.value = "";
  try {
    const current = await api("/api/login", data);
    if (!current.authenticated) throw new ApiError("Вход не выполнен. Проверь логин и пароль.", 401);
    await showDashboard(current);
  } catch (error) {
    notice(ui["login-status"], error.message, "error");
    ui.password.focus();
  } finally {
    submit.disabled = false;
  }
});

ui.logout.addEventListener("click", () => withChange("Выходим из панели…", async () => {
  await api("/api/logout", {});
  showLogin();
}));
ui.refresh.addEventListener("click", () => {
  notice(ui["dashboard-status"], "");
  refreshState();
});
ui["devices-tab"].addEventListener("click", () => selectPanel("devices"));
ui["upstreams-tab"].addEventListener("click", () => selectPanel("upstreams"));
ui["create-device"].addEventListener("click", openDeviceEditor);
ui["device-form"].addEventListener("submit", createDevice);
ui["cancel-device"].addEventListener("click", () => closeDeviceEditor(true));
ui["dismiss-download"].addEventListener("click", () => {
  clearDownload();
  ui["create-device"].focus();
});
ui["create-upstream"].addEventListener("click", () => openUpstreamEditor());
ui["upstream-file"].addEventListener("change", loadUpstreamFile);
ui["upstream-form"].addEventListener("submit", saveUpstream);
ui["cancel-upstream"].addEventListener("click", () => closeUpstreamEditor(true));
window.addEventListener("pagehide", () => {
  clearDownload();
  ui.password.value = "";
  ui["upstream-config"].value = "";
});

(async function start() {
  try {
    const current = await api("/api/session");
    if (current.authenticated) await showDashboard(current);
    else showLogin();
  } catch (error) {
    showLogin(error.message);
  }
})();
