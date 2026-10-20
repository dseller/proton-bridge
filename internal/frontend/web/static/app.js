"use strict";

const POLL_INTERVAL_MS = 3000;

let csrfToken = "";
let pollTimer = null;
let settingsLoaded = false;
const revealedPasswords = new Set();

const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
  const options = { method, headers: {}, credentials: "same-origin" };

  if (method !== "GET") {
    options.headers["X-CSRF-Token"] = csrfToken;
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body || {});
  }

  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));

  if (res.status === 401 && path !== "/api/signin") {
    showView("signin");
    throw new Error("Your session has expired. Sign in again.");
  }

  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }

  return data;
}

function showView(name) {
  for (const view of ["setup", "signin", "main"]) {
    $(`view-${view}`).hidden = view !== name;
  }

  $("signout").hidden = name !== "main";

  if (name === "main") {
    startPolling();
  } else {
    stopPolling();
  }
}

function setMessage(form, kind, text) {
  const el = form.querySelector(`[data-${kind}]`);
  if (el) el.textContent = text || "";
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }

  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : String(child));
  }

  return node;
}

// Session

async function loadSession() {
  const session = await api("GET", "/api/session");

  if (session.signed_in) {
    csrfToken = session.csrf_token;
    showView("main");
  } else if (session.setup_required) {
    showView("setup");
  } else {
    showView("signin");
  }
}

$("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  setMessage(form, "error", "");

  if (form.password.value !== form.confirm.value) {
    setMessage(form, "error", "The passwords do not match.");
    return;
  }

  try {
    await api("POST", "/api/setup", { token: form.token.value.trim(), password: form.password.value });
    form.reset();
    await loadSession();
  } catch (err) {
    setMessage(form, "error", err.message);
  }
});

$("signin-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  setMessage(form, "error", "");

  try {
    await api("POST", "/api/signin", { password: form.password.value });
    form.reset();
    await loadSession();
  } catch (err) {
    setMessage(form, "error", err.message);
  }
});

$("signout").addEventListener("click", async () => {
  try {
    await api("POST", "/api/signout");
  } finally {
    csrfToken = "";
    settingsLoaded = false;
    revealedPasswords.clear();
    showView("signin");
  }
});

$("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  setMessage(form, "error", "");
  setMessage(form, "success", "");

  if (form.password.value !== form.confirm.value) {
    setMessage(form, "error", "The new passwords do not match.");
    return;
  }

  try {
    await api("POST", "/api/password", { current: form.current.value, password: form.password.value });
    form.reset();
    setMessage(form, "success", "The password was changed. Other browsers were signed out.");
  } catch (err) {
    setMessage(form, "error", err.message);
  }
});

// Status polling

function startPolling() {
  if (pollTimer) return;
  refresh();
  pollTimer = setInterval(refresh, POLL_INTERVAL_MS);
}

function stopPolling() {
  clearInterval(pollTimer);
  pollTimer = null;
}

async function refresh() {
  let status;

  try {
    status = await api("GET", "/api/status");
  } catch (err) {
    const connection = $("connection");
    connection.hidden = false;
    connection.className = "pill bad";
    connection.textContent = "Bridge unreachable";
    return;
  }

  renderHeader(status);
  renderNotices(status.notices);
  renderUpdate(status.update);
  renderAccounts(status.accounts, status.settings);

  if (!settingsLoaded) {
    fillSettings(status.settings);
    settingsLoaded = true;
  }
}

function renderHeader(status) {
  $("version").textContent = `v${status.version}`;

  const connection = $("connection");
  connection.hidden = false;
  connection.className = status.connected ? "pill ok" : "pill bad";
  connection.textContent = status.connected ? "Connected to Proton" : "No connection to Proton";
}

function renderNotices(notices) {
  const container = $("notices");
  container.replaceChildren(
    ...notices.map((notice) =>
      el("div", { class: `notice ${notice.level}` },
        el("span", {}, notice.text),
        el("button", {
          class: "link",
          onclick: async () => {
            await api("POST", `/api/notices/${notice.id}/dismiss`).catch(() => {});
            refresh();
          },
        }, "Dismiss"),
      ),
    ),
  );
}

function renderUpdate(update) {
  const available = Boolean(update.available_version);

  $("update").hidden = !available && !update.restart_needed;
  $("update-install").hidden = !available || update.restart_needed;
  $("restart").hidden = !update.restart_needed;
  $("update-text").textContent = update.restart_needed
    ? "An update was installed. Restart Bridge to use it."
    : `Bridge ${update.available_version} is available.`;
}

$("update-install").addEventListener("click", async (event) => {
  event.target.disabled = true;
  await api("POST", "/api/updates/install").catch((err) => alert(err.message));
  event.target.disabled = false;
});

$("restart").addEventListener("click", async () => {
  await api("POST", "/api/restart").catch((err) => alert(err.message));
});

$("check-updates").addEventListener("click", async () => {
  await api("POST", "/api/updates/check").catch((err) => alert(err.message));
});

// Accounts

const STATE_LABELS = {
  connected: "Connected",
  signed_out: "Signed out",
  locked: "Locked",
};

function renderAccounts(accounts, settings) {
  $("no-accounts").hidden = accounts.length > 0;
  $("accounts").replaceChildren(...accounts.map((account) => renderAccount(account, settings)));
}

function renderAccount(account, settings) {
  const actions = el("div", { class: "account-actions" });

  if (account.state === "signed_out") {
    actions.append(el("button", { class: "primary", onclick: () => openLoginDialog(account.username) }, "Sign in"));
  } else {
    actions.append(
      el("button", {
        onclick: () => accountAction(account, "mode", { split: !account.split },
          `Switch ${account.username} to ${account.split ? "combined" : "split"} address mode? Your email client will need to resynchronize.`),
      }, account.split ? "Use combined mode" : "Use split mode"),
      el("button", {
        onclick: () => accountAction(account, "signout", {}, `Sign out ${account.username}?`),
      }, "Sign out"),
    );
  }

  actions.append(el("button", {
    class: "danger",
    onclick: () => accountAction(account, "remove", {}, `Remove ${account.username} from Bridge? Its local cache is deleted.`),
  }, "Remove"));

  const node = el("div", { class: "account" },
    el("div", { class: "account-head" },
      el("div", {},
        el("div", { class: "account-name" }, account.username),
        el("div", { class: "muted" }, `${STATE_LABELS[account.state] || account.state} · ${account.split ? "Split" : "Combined"} addresses`),
      ),
      actions,
    ),
  );

  if (account.sync) {
    const percent = Math.round(account.sync.progress * 100);
    node.append(
      el("div", { class: "muted" }, `Synchronizing: ${percent}%${account.sync.remaining_ms > 0 ? `, about ${formatDuration(account.sync.remaining_ms)} left` : ""}`),
      el("progress", { max: "100", value: String(percent) }),
    );
  }

  if (account.bad_event) {
    node.append(el("div", { class: "bad-event" },
      el("div", {}, "Bridge ran into an internal error and cannot keep this account up to date. Resynchronize the account, or sign it out."),
      el("div", { class: "muted" }, account.bad_event),
      el("div", { class: "account-actions" },
        el("button", { class: "primary", onclick: () => accountAction(account, "bad-event", { resync: true }) }, "Resynchronize"),
        el("button", { onclick: () => accountAction(account, "bad-event", { resync: false }) }, "Sign out"),
      ),
    ));
  }

  if (account.state === "connected") {
    node.append(renderConfig(account, settings));
  }

  return node;
}

function renderConfig(account, settings) {
  const revealed = revealedPasswords.has(account.id);
  const addresses = account.split ? account.addresses : account.addresses.slice(0, 1);
  const password = revealed ? account.bridge_password : "••••••••••••";

  const toggle = el("button", {
    class: "link",
    onclick: () => {
      if (revealed) revealedPasswords.delete(account.id);
      else revealedPasswords.add(account.id);
      refresh();
    },
  }, revealed ? "Hide password" : "Show password");

  const blocks = [];

  for (const address of addresses) {
    for (const [name, port, ssl] of [["IMAP", settings.imap_port, settings.imap_ssl], ["SMTP", settings.smtp_port, settings.smtp_ssl]]) {
      blocks.push(el("dl", {},
        el("h3", {}, `${name}${addresses.length > 1 ? ` · ${address}` : ""}`),
        el("dt", {}, "Server"), el("dd", {}, settings.host),
        el("dt", {}, "Port"), el("dd", {}, port),
        el("dt", {}, "Security"), el("dd", {}, ssl ? "SSL" : "STARTTLS"),
        el("dt", {}, "Username"), el("dd", {}, address),
        el("dt", {}, "Password"), el("dd", {}, password),
      ));
    }
  }

  return el("div", {}, el("div", { class: "config" }, ...blocks), toggle);
}

async function accountAction(account, action, body, confirmText) {
  if (confirmText && !confirm(confirmText)) return;

  try {
    await api("POST", `/api/accounts/${encodeURIComponent(account.id)}/${action}`, body);
  } catch (err) {
    alert(err.message);
  }

  refresh();
}

function formatDuration(ms) {
  const minutes = Math.round(ms / 60000);
  if (minutes < 1) return "less than a minute";
  if (minutes < 60) return `${minutes} min`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

// Account sign-in

let loginStep = "credentials";

function setLoginStep(step) {
  loginStep = step;

  for (const form of $("login-dialog").querySelectorAll("form[data-step]")) {
    form.hidden = form.dataset.step !== step;
  }

  const current = $("login-dialog").querySelector(`form[data-step="${step}"]`);
  const input = current && current.querySelector("input");
  if (input) input.focus();
}

function openLoginDialog(username) {
  for (const form of $("login-dialog").querySelectorAll("form")) form.reset();
  $("login-credentials").username.value = username || "";
  $("login-error").textContent = "";
  $("login-next").disabled = false;
  setLoginStep("credentials");
  $("login-dialog").showModal();
}

async function closeLoginDialog() {
  $("login-dialog").close();

  if (loginStep !== "credentials") {
    await api("POST", "/api/accounts/login/abort").catch(() => {});
  }

  for (const form of $("login-dialog").querySelectorAll("form")) form.reset();
}

async function submitLoginStep() {
  const button = $("login-next");
  button.disabled = true;
  $("login-error").textContent = "";

  try {
    let result;

    switch (loginStep) {
      case "credentials": {
        const form = $("login-credentials");
        result = await api("POST", "/api/accounts/login", { username: form.username.value.trim(), password: form.password.value });
        break;
      }
      case "hv":
        result = await api("POST", "/api/accounts/login/hv");
        break;
      case "totp":
        result = await api("POST", "/api/accounts/login/totp", { code: $("login-totp").code.value.trim() });
        break;
      case "mailbox":
        result = await api("POST", "/api/accounts/login/mailbox", { password: $("login-mailbox").password.value });
        break;
    }

    handleLoginResult(result);
  } catch (err) {
    $("login-error").textContent = err.message;
  } finally {
    button.disabled = false;
  }
}

function handleLoginResult(result) {
  $("login-error").textContent = result.error || "";

  switch (result.step) {
    case "done":
      $("login-dialog").close();
      for (const form of $("login-dialog").querySelectorAll("form")) form.reset();
      loginStep = "credentials";
      refresh();
      break;

    case "hv":
      $("login-hv-url").href = result.hv_url;
      setLoginStep("hv");
      break;

    case "totp":
      $("login-totp").reset();
      setLoginStep("totp");
      break;

    case "mailbox":
      $("login-mailbox").reset();
      setLoginStep("mailbox");
      break;

    default:
      // The sign-in failed and the server dropped it, so it starts over from the credentials.
      $("login-credentials").password.value = "";
      setLoginStep("credentials");
  }
}

$("add-account").addEventListener("click", () => openLoginDialog(""));
$("login-cancel").addEventListener("click", closeLoginDialog);
$("login-next").addEventListener("click", submitLoginStep);
$("login-dialog").addEventListener("cancel", (event) => {
  event.preventDefault();
  closeLoginDialog();
});

for (const form of $("login-dialog").querySelectorAll("form")) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    submitLoginStep();
  });

  // Pressing Enter in a field submits the step.
  form.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      submitLoginStep();
    }
  });
}

// Settings

function fillSettings(settings) {
  const form = $("settings-form");
  form.imap_port.value = settings.imap_port;
  form.smtp_port.value = settings.smtp_port;
  form.imap_ssl.value = String(settings.imap_ssl);
  form.smtp_ssl.value = String(settings.smtp_ssl);
  form.cache_dir.value = settings.cache_dir;
  form.show_all_mail.checked = settings.show_all_mail;
  form.proxy_allowed.checked = settings.proxy_allowed;
  form.telemetry_disabled.checked = settings.telemetry_disabled;
  form.auto_update.checked = settings.auto_update;
  form.early_access.checked = settings.early_access;
}

$("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const button = form.querySelector("button[type=submit]");
  setMessage(form, "error", "");
  setMessage(form, "success", "");
  button.disabled = true;

  try {
    await api("POST", "/api/settings", {
      imap_port: Number(form.imap_port.value),
      smtp_port: Number(form.smtp_port.value),
      imap_ssl: form.imap_ssl.value === "true",
      smtp_ssl: form.smtp_ssl.value === "true",
      cache_dir: form.cache_dir.value.trim(),
      show_all_mail: form.show_all_mail.checked,
      proxy_allowed: form.proxy_allowed.checked,
      telemetry_disabled: form.telemetry_disabled.checked,
      auto_update: form.auto_update.checked,
      early_access: form.early_access.checked,
    });
    setMessage(form, "success", "Settings saved.");
  } catch (err) {
    setMessage(form, "error", err.message);
  } finally {
    button.disabled = false;
    settingsLoaded = false;
    refresh();
  }
});

loadSession().catch((err) => {
  document.body.textContent = `Could not reach Bridge: ${err.message}`;
});
