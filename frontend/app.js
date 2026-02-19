const state = {
  token: localStorage.getItem("token") || "",
  me: null,
  portfolios: [],
  transfers: [],
  audit: [],
  sessions: [],
  currentSessionId: "",
};

const $ = (s) => document.querySelector(s);
const toast = (msg) => {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 2200);
};

const api = async (path, options = {}) => {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.message || `Request failed: ${res.status}`);
  return data;
};

function renderMetrics() {
  const container = $("#metrics");
  const mine = state.portfolios.find((p) => p.user_id === state.me.id);
  const holdingsCount = mine?.holdings?.reduce((acc, x) => acc + x.quantity, 0) || 0;
  container.innerHTML = `
    <article class="metric"><span>Signed in as</span><strong>${state.me.email}</strong></article>
    <article class="metric"><span>Role</span><strong>${state.me.role}</strong></article>
    <article class="metric"><span>2FA</span><strong>${state.me.twofa_enabled ? "Enabled" : "Disabled"}</strong></article>
    <article class="metric"><span>Cash Balance</span><strong>$${(mine?.cash_balance || 0).toLocaleString()}</strong></article>
    <article class="metric"><span>Total Shares Held</span><strong>${holdingsCount.toLocaleString()}</strong></article>
  `;
}

function badge(status) {
  const lower = status.toLowerCase();
  return `<span class="badge ${lower}">${status}</span>`;
}

function actionButtons(t) {
  if (!["COMPLIANCE", "ADMIN"].includes(state.me.role)) return "-";
  if (t.status === "PENDING") {
    return `
      <button class="btn small" data-action="approve" data-id="${t.id}">Approve</button>
      <button class="btn small alt" data-action="reject" data-id="${t.id}">Reject</button>
    `;
  }
  if (t.status === "APPROVED") {
    return `<button class="btn small" data-action="execute" data-id="${t.id}">Execute</button>`;
  }
  return "-";
}

function renderTransfers() {
  $("#transferRows").innerHTML = state.transfers
    .map(
      (t) => `
      <tr>
        <td>${t.id}</td>
        <td>${t.from_email}</td>
        <td>${t.to_email}</td>
        <td>${t.symbol}</td>
        <td>${t.quantity}</td>
        <td>$${t.price_per_share}</td>
        <td>$${t.total_amount}</td>
        <td>${badge(t.status)}</td>
        <td>${actionButtons(t)}</td>
      </tr>
    `,
    )
    .join("");
}

function renderAudit() {
  const panel = $("#auditPanel");
  if (!["COMPLIANCE", "ADMIN"].includes(state.me.role)) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  $("#auditRows").innerHTML = state.audit
    .map(
      (a) => `
      <tr>
        <td>${a.id}</td>
        <td>${a.event_type}</td>
        <td>${a.actor_email || "SYSTEM"}</td>
        <td>${a.entity}:${a.entity_id || "-"}</td>
        <td title="${a.event_hash}">${a.event_hash.slice(0, 16)}...</td>
        <td>${new Date(a.created_at).toLocaleString()}</td>
      </tr>
    `,
    )
    .join("");
}

function renderSessions() {
  $("#sessionsList").innerHTML = state.sessions
    .map((s) => {
      const current = s.id === state.currentSessionId ? " (current)" : "";
      const revoked = s.revoked_at ? `revoked ${new Date(s.revoked_at).toLocaleString()}` : "active";
      const button = s.id === state.currentSessionId || s.revoked_at
        ? ""
        : `<button class=\"btn small ghost\" data-revoke-session=\"${s.id}\">Revoke</button>`;
      return `<div>${s.id.slice(0, 12)}...${current} | ${revoked} | ${s.ip || "-"} ${button}</div>`;
    })
    .join("");
}

async function refresh() {
  state.me = await api("/api/me");
  const [portfolioRes, transferRes, sessionRes] = await Promise.all([
    api("/api/portfolios"),
    api("/api/transfers"),
    api("/api/sessions"),
  ]);
  state.portfolios = portfolioRes.portfolios;
  state.transfers = transferRes.transfers;
  state.sessions = sessionRes.sessions;
  state.currentSessionId = sessionRes.current_session_id;

  if (["COMPLIANCE", "ADMIN"].includes(state.me.role)) {
    state.audit = (await api("/api/audit?limit=80")).audit;
  } else {
    state.audit = [];
  }

  $("#identity").textContent = `${state.me.email} (${state.me.role})`;
  renderMetrics();
  renderTransfers();
  renderAudit();
  renderSessions();
}

function setSignedIn(isIn) {
  $("#authSection").classList.toggle("hidden", isIn);
  $("#appSection").classList.toggle("hidden", !isIn);
}

async function loginOrRegister(endpoint, form) {
  const payload = Object.fromEntries(new FormData(form).entries());
  if (!payload.otp) delete payload.otp;
  const result = await api(endpoint, { method: "POST", body: JSON.stringify(payload) });
  if (result.requires_2fa) {
    throw new Error("2FA enabled on this account. Enter OTP and retry.");
  }
  state.token = result.token;
  localStorage.setItem("token", state.token);
  setSignedIn(true);
  await refresh();
}

$("#loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await loginOrRegister("/api/login", e.target);
    toast("Logged in");
  } catch (err) {
    toast(err.message);
  }
});

$("#registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await loginOrRegister("/api/register", e.target);
    toast("Account created");
  } catch (err) {
    toast(err.message);
  }
});

$("#transferForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  try {
    await api("/api/transfers", { method: "POST", body: JSON.stringify(payload) });
    e.target.reset();
    toast("Transfer request created");
    await refresh();
  } catch (err) {
    toast(err.message);
  }
});

$("#setup2faForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/2fa/setup", { method: "POST", body: "{}" });
    $("#twofaSecret").textContent = `Secret: ${res.secret}`;
    toast("2FA secret generated");
  } catch (err) {
    toast(err.message);
  }
});

$("#enable2faForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  try {
    await api("/api/2fa/enable", { method: "POST", body: JSON.stringify(payload) });
    toast("2FA enabled");
    e.target.reset();
    await refresh();
  } catch (err) {
    toast(err.message);
  }
});

$("#disable2faForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(e.target).entries());
  try {
    await api("/api/2fa/disable", { method: "POST", body: JSON.stringify(payload) });
    toast("2FA disabled");
    e.target.reset();
    await refresh();
  } catch (err) {
    toast(err.message);
  }
});

$("#refreshSessionsBtn").addEventListener("click", async () => {
  try {
    await refresh();
    toast("Sessions refreshed");
  } catch (err) {
    toast(err.message);
  }
});

$("#revokeOthersBtn").addEventListener("click", async () => {
  try {
    await api("/api/sessions/revoke-all", { method: "POST", body: JSON.stringify({ keep_current: true }) });
    toast("Other sessions revoked");
    await refresh();
  } catch (err) {
    toast(err.message);
  }
});

$("#sessionsList").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-revoke-session]");
  if (!btn) return;
  try {
    await api("/api/sessions/revoke", {
      method: "POST",
      body: JSON.stringify({ session_id: btn.dataset.revokeSession }),
    });
    toast("Session revoked");
    await refresh();
  } catch (err) {
    toast(err.message);
  }
});

$("#transferRows").addEventListener("click", async (e) => {
  const btn = e.target.closest("button[data-action]");
  if (!btn) return;
  const id = btn.dataset.id;
  const action = btn.dataset.action;
  const body = action === "reject" ? { reason: "Compliance policy rejected" } : {};
  try {
    await api(`/api/transfers/${id}/${action}`, { method: "POST", body: JSON.stringify(body) });
    toast(`Transfer ${action}d`);
    await refresh();
  } catch (err) {
    toast(err.message);
  }
});

$("#logoutBtn").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
  } catch {
    // no-op
  }
  localStorage.removeItem("token");
  state.token = "";
  state.me = null;
  $("#identity").textContent = "Not signed in";
  setSignedIn(false);
});

(async function boot() {
  if (!state.token) {
    setSignedIn(false);
    return;
  }
  try {
    setSignedIn(true);
    await refresh();
  } catch {
    localStorage.removeItem("token");
    state.token = "";
    setSignedIn(false);
  }
})();
