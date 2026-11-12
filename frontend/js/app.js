(() => {
  "use strict";

  const CASE_KEY = "mfa.caseId";
  const MODE_LABEL = { client: "Client", server: "Server" };

  const state = {
    caseId: null,
    caseName: "-",
    caseCreated: null,
    evidences: {},
    modes: [],
    modeApps: {},
    uploading: {},
    crossApps: [],
    pendingFocus: null,
  };

  const view = document.getElementById("view");
  const nav = document.getElementById("nav");
  let currentRoute = "";

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "class") el.className = v;
      else if (k === "style") el.style.cssText = v;
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat(Infinity)) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  async function api(method, url, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    const res = await fetch(url, opt);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(errorMessage(data, res.status));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function errorMessage(data, status) {
    const d = data && data.detail;
    if (Array.isArray(d)) return d.map((x) => x.msg || JSON.stringify(x)).join(", ");
    return d || `요청 실패 (${status})`;
  }

  let statusTimer;
  function status(msg, isError = false) {
    const el = document.getElementById("status-msg");
    el.textContent = msg;
    el.classList.toggle("error", isError);
    clearTimeout(statusTimer);
    if (!isError) statusTimer = setTimeout(() => (el.textContent = "준비"), 6000);
  }

  function fmtSize(n) {
    if (n == null) return "-";
    const u = ["B", "KB", "MB", "GB"];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
  }

  const key = (mode, app) => `${mode}/${app}`;
  const appsOf = (mode) => state.modeApps[mode]?.apps || [];
  const appMeta = (id) => state.modes.flatMap((m) => appsOf(m.id)).find((a) => a.id === id);
  const appMark = (a) => h("span", { class: "app-mark", style: `background:${a?.color || "#999"}` });

  const nodes = (x) => [x].flat(Infinity).filter((n) => n != null && n !== false);

  const show = (el, ...parts) => el.replaceChildren(...nodes(parts));

  const TZ_KEY = "mfa.tz";
  const TZ_OFFSET = { UTC: 0, KST: 9 };
  const TS_RE = /^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(\.\d{1,6})?(Z|[+-]00:?00)?$/;
  state.tz = (() => { try { return localStorage.getItem(TZ_KEY) === "KST" ? "KST" : "UTC"; } catch { return "UTC"; } })();

  function fmtTs(v, ms = true) {
    if (typeof v !== "string") return v;
    const m = v.match(TS_RE);
    if (!m) return v;
    const frac = ms && m[7] ? m[7].slice(0, 4) : "";
    const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) + TZ_OFFSET[state.tz] * 3600e3);
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} `
      + `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}${frac}`;
  }

  const fmtTime = (iso) => (iso ? fmtTs(iso, false) : "-");
  const tzName = () => state.tz;
  const tzLabel = (label) => (label.includes("(UTC)") ? label.replace("(UTC)", `(${state.tz})`) : `${label} (${state.tz})`);

  function isTimeColumn(c, rows) {
    if (/로컬/.test(c.label)) return false;
    let seen = 0;
    for (const r of rows) {
      const v = r[c.key];
      if (v == null || v === "") continue;
      if (typeof v !== "string" || !TS_RE.test(v)) return false;
      seen++;
    }
    return seen > 0;
  }

  const THEME_KEY = "mfa.theme";

  function renderThemeToggle() {
    const box = document.getElementById("theme-toggle");
    const cur = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
    show(box, [["light", "라이트"], ["dark", "다크"]].map(([t, label]) => h("button", {
      class: "tz-btn" + (cur === t ? " active" : ""),
      title: t === "dark" ? "어두운 화면으로 표시" : "밝은 화면으로 표시",
      onclick: () => {
        if (cur === t) return;
        document.documentElement.setAttribute("data-theme", t);
        try { localStorage.setItem(THEME_KEY, t); } catch {  }
        renderThemeToggle();
      },
    }, label)));
  }

  function renderTzToggle() {
    const box = document.getElementById("tz-toggle");
    show(box, ["UTC", "KST"].map((tz) => h("button", {
      class: "tz-btn" + (state.tz === tz ? " active" : ""),
      title: tz === "KST" ? "한국 표준시 (UTC+9) 로 표시" : "협정 세계시로 표시",
      onclick: () => {
        if (state.tz === tz) return;
        state.tz = tz;
        try { localStorage.setItem(TZ_KEY, tz); } catch {  }
        renderTzToggle();
        closeDetail();
        router();
        status(`시각을 ${tz === "KST" ? "KST (UTC+9)" : "UTC"} 로 표시합니다`);
      },
    }, tz)));
  }

  let activeSplit = null;

  function detailSplit() {
    const pane = h("div", { class: "dt-detail", hidden: true });
    let root = null;
    const api = {
      el(...main) {
        root = h("div", { class: "dt-split" }, h("div", { class: "dt-main" }, main), pane);
        return root;
      },
      open(tr, title, body) {
        if (activeSplit && activeSplit !== api) activeSplit.close();
        root.querySelectorAll("tr.sel").forEach((t) => t.classList.remove("sel"));
        tr.classList.add("sel");
        show(pane,
          h("div", { class: "dt-detail-head" }, h("strong", {}, title),
            h("button", { class: "btn", onclick: () => api.close(), title: "닫기 (Esc)" }, "닫기")),
          h("div", { class: "dt-detail-body" }, body));
        pane.hidden = false;
        root.classList.add("open");
        pane.scrollTop = 0;
        activeSplit = api;
      },
      close() {
        pane.hidden = true;
        if (root) {
          root.classList.remove("open");
          root.querySelectorAll("tr.sel").forEach((t) => t.classList.remove("sel"));
        }
        if (activeSplit === api) activeSplit = null;
      },
    };
    return api;
  }

  function closeDetail() {
    if (activeSplit) activeSplit.close();
  }

  function valueBlock(v) {
    const t = cellText(v);
    if (t === "") return h("span", { class: "faint" }, "(빈 값)");
    const s = t.trim();
    if ((s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"))) {
      try { return h("pre", { class: "val" }, JSON.stringify(JSON.parse(s), null, 2)); } catch {  }
    }
    if (t.length > 60 || t.includes("\n")) return h("pre", { class: "val" }, t);
    return h("span", { class: "val-inline" }, t);
  }

  const fieldList = (fields) => h("dl", { class: "detail" },
    fields.map((f) => [h("dt", {}, f.label), h("dd", {}, f.node || valueBlock(f.value))]));

  function gridfsLink(ctx, g, name) {
    const qs = new URLSearchParams({ bucket: g.bucket, key: g.key, name: name || "" });
    return h("div", { class: "cache-preview" },
      h("h4", {}, "GridFS 파일"),
      h("a", { class: "btn", href: `/api/cases/${state.caseId}/${ctx.mode}/${ctx.app}/mongo/gridfs?${qs}`, download: "" }, "파일 내려받기"),
      h("div", { class: "faint" }, "청크를 모든 출처(현재 파일, oplog 등)에서 모아 조립한 파일입니다. 불완전하면 파일 이름 앞에 INCOMPLETE_ 가 붙습니다."));
  }

  function cachePreview(ctx, url, key) {
    const base = `/api/cases/${state.caseId}/${ctx.mode}/${ctx.app}/cache`;
    const qs = `url=${encodeURIComponent(url)}` + (key ? `&key=${encodeURIComponent(key)}` : "");
    const box = h("div", { class: "cache-preview" }, h("div", { class: "faint" }, "캐시 내용을 읽는 중…"));
    api("GET", `${base}/meta?${qs}`).then((m) => {
      const body = `${base}/body?${qs}`;
      let content;
      if (m.kind === "image") {
        content = h("img", { class: "preview-img", src: body, alt: "캐시된 이미지" });
      } else if (m.kind === "text") {
        let t = m.text;
        if (/json/i.test(m.ctype)) { try { t = JSON.stringify(JSON.parse(t), null, 2); } catch {  } }
        content = [h("pre", { class: "val code" }, t),
          m.truncated ? h("div", { class: "faint" }, "앞 1MB 만 표시했습니다. 전체는 내려받아 확인하세요.") : null];
      } else if (m.kind === "binary") {
        content = h("pre", { class: "val hex" }, hexDump(m.hex));
      } else {
        content = h("div", { class: "faint" }, "본문이 없습니다.");
      }
      show(box,
        h("h4", {}, "캐시 응답"),
        fieldList([
          { label: "상태", value: m.status },
          { label: "Content-Type", value: m.ctype },
          { label: "인코딩", value: [m.encoding, m.note].filter(Boolean).join(", ") },
          { label: "크기", value: `저장 ${m.raw_size ?? "-"} bytes → 본문 ${m.size ?? "-"} bytes` },
          { label: `캐시 시각 (${tzName()})`, value: fmtTs(m.created) },
          { label: `응답 시각 (${tzName()})`, value: fmtTs(m.response_time) },
          { label: "저장 위치", value: m.location },
          { label: "캐시 키", value: m.key },
        ]),
        h("h4", {}, "HTTP 헤더"),
        m.headers.length ? h("table", { class: "grid kv" }, h("tbody", {},
          m.headers.map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", { class: "wrap" }, v)))))
          : h("div", { class: "faint" }, "헤더 없음"),
        h("h4", {}, "본문",
          h("a", { class: "btn btn-sm-inline", href: `${body}&download=1` }, "내려받기")),
        content);
    }).catch((e) => show(box, h("div", { class: "error-text" }, `캐시 내용을 읽지 못했습니다: ${e.message}`)));
    return box;
  }

  function hexDump(hex) {
    const lines = [];
    for (let off = 0; off < hex.length / 2; off += 16) {
      const bytes = [];
      let ascii = "";
      for (let i = 0; i < 16 && off + i < hex.length / 2; i++) {
        const b = parseInt(hex.substr((off + i) * 2, 2), 16);
        bytes.push(hex.substr((off + i) * 2, 2));
        ascii += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
      }
      lines.push(`${off.toString(16).padStart(8, "0")}  ${bytes.join(" ").padEnd(47)}  ${ascii}`);
    }
    return lines.join("\n") + (hex.length >= 4096 ? "\n… (앞 2KB 만 표시)" : "");
  }

  const modal = document.getElementById("modal");

  function openModal(title, body) {
    show(modal, h("div", { class: "modal", role: "dialog", "aria-label": title },
      h("div", { class: "modal-head" }, h("strong", {}, title),
        h("button", { class: "btn", onclick: closeModal, title: "닫기 (Esc)" }, "닫기")),
      h("div", { class: "modal-body" }, body)));
    modal.hidden = false;
  }

  function closeModal() {
    closeDetail();
    modal.hidden = true;
    show(modal);
  }

  modal.addEventListener("mousedown", (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (activeSplit) closeDetail();
    else if (!modal.hidden) closeModal();
  });

  async function loadMeta() {
    state.modes = await api("GET", "/api/modes");
    await Promise.all(state.modes.map((m) => getModeApps(m.id)));
    state.crossApps = await api("GET", "/api/cross").catch(() => []);
  }

  async function getModeApps(mode) {
    if (!state.modeApps[mode]) state.modeApps[mode] = await api("GET", `/api/modes/${mode}/apps`);
    return state.modeApps[mode];
  }

  async function loadCase() {
    const id = localStorage.getItem(CASE_KEY);
    let c = null;
    if (id) {
      try {
        c = await api("GET", `/api/cases/${id}`);
      } catch (e) {

        if (e.status !== 404 && e.status !== 400) throw e;
      }
    }
    if (!c) {
      c = await api("POST", "/api/cases", {});
      c.evidences = [];
      localStorage.setItem(CASE_KEY, c.id);
    }
    applyCase(c);
  }

  function applyCase(c) {
    state.caseId = c.id;
    state.caseName = c.name;
    state.caseCreated = c.created_at;
    state.evidences = {};
    for (const e of c.evidences || []) state.evidences[key(e.mode, e.app)] = e;
    document.getElementById("case-name").textContent = state.caseName;
    document.getElementById("status-case").textContent =
      `${state.caseId.slice(0, 8)}, 증거 ${Object.keys(state.evidences).length}건`;
    renderNav();
  }

  async function refreshCase() {
    const c = await api("GET", `/api/cases/${state.caseId}`);
    if (c.id === state.caseId) applyCase(c);
  }

  function renderNav() {
    const item = (href, label, extra, indent) => h("a", {
      class: "nav-item" + (indent ? " indent" : "") + (href === `#/${currentRoute}` ? " active" : ""),
      href,
    }, label, extra);

    const uploaded = state.modes
      .map((m) => ({ m, apps: appsOf(m.id).filter((a) => state.evidences[key(m.id, a.id)]) }))
      .filter((g) => g.apps.length);

    show(nav,
      h("div", { class: "nav-title" }, "케이스"),
      item("#/", "개요"),
      h("div", { class: "nav-title" }, "증거 추가"),
      state.modes.map((m) => {
        const done = appsOf(m.id).filter((a) => state.evidences[key(m.id, a.id)]).length;
        return item(`#/upload/${m.id}`, MODE_LABEL[m.id] || m.name,
          h("span", { class: "nav-count" }, `${done}/${appsOf(m.id).length}`));
      }),
      h("div", { class: "nav-title" }, "분석 결과"),
      uploaded.length
        ? uploaded.map(({ m, apps }) => [
            h("div", { class: "nav-sub" }, MODE_LABEL[m.id] || m.name),
            apps.map((a) => item(`#/results/${m.id}/${a.id}`, [appMark(a), a.name], null, true)),
          ])
        : h("div", { class: "nav-empty" }, "없음"),
      crossPairs().length ? [
        h("div", { class: "nav-title" }, "교차 분석"),
        crossPairs().map((a) => item(`#/cross/${a.id}`, [appMark(a), a.name], null, true)),
      ] : null,
    );
  }

  const crossPairs = () => state.crossApps
    .filter((id) => state.evidences[key("client", id)] && state.evidences[key("server", id)])
    .map((id) => appMeta(id))
    .filter(Boolean);

  async function renderHome() {
    const isCurrent = renderToken();
    const recent = await api("GET", "/api/cases?limit=10").catch(() => null);
    if (!isCurrent()) return;

    const count = Object.keys(state.evidences).length;
    show(view,
      h("h1", { class: "page-title" }, "개요"),

      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, "현재 케이스"),
        h("dl", { class: "props" },
          h("dt", {}, "이름"), h("dd", {}, state.caseName),
          h("dt", {}, "케이스 ID"), h("dd", { class: "mono" }, state.caseId),
          h("dt", {}, `생성 (${tzName()})`), h("dd", {}, fmtTime(state.caseCreated)),
          h("dt", {}, "증거"), h("dd", {}, count ? `${count}건` : "없음"),
        )),

      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, "증거 추가"),
        h("table", { class: "grid" },
          h("tbody", {}, state.modes.map((m) => {
            const done = new Set(appsOf(m.id).filter((a) => state.evidences[key(m.id, a.id)]).map((a) => key(m.id, a.id)));
            return h("tr", { class: "mode-row clickable", onclick: () => (location.hash = `#/upload/${m.id}`) },
              h("td", {}, MODE_LABEL[m.id] || m.name),
              h("td", { class: "wrap" }, m.description),
              h("td", {}, uploadedSummary([m], done, false)),
              h("td", {}, h("a", { href: `#/upload/${m.id}` }, "열기")));
          })))),

      recentCases(recent),
    );
  }

  function recentCases(recent) {
    const head = h("div", { class: "panel-head" }, "최근 케이스", h("span", { class: "aside" }, "최근 활동순 10건"));
    if (!recent) return h("section", { class: "panel" }, head, h("div", { class: "empty-msg" }, "목록을 불러오지 못했습니다."));
    if (!recent.length) return h("section", { class: "panel" }, head, h("div", { class: "empty-msg" }, "케이스가 없습니다."));

    const rows = recent.map((c) => {
      const done = new Set(c.evidences.map((e) => key(e.mode, e.app)));
      const current = c.id === state.caseId;
      return h("tr", { class: current ? "selected" : "clickable", onclick: current ? null : () => switchCase(c.id) },
        h("td", {}, c.name, h("span", { class: "case-id" }, c.id.slice(0, 8)),
          current ? h("span", { class: "current-mark" }, "현재") : null),
        h("td", {}, uploadedSummary(state.modes, done, true)),
        h("td", { class: "mono" }, fmtTime(c.created_at)),
        h("td", { class: "mono" }, fmtTime(c.updated_at)),
        h("td", { class: "row-actions" },
          h("button", { class: "link-btn danger", title: "케이스와 증거 전체 삭제",
            onclick: (e) => { e.stopPropagation(); deleteCase(c); } }, "삭제")),
      );
    });

    return h("section", { class: "panel" }, head,
      h("div", { class: "table-wrap" }, h("table", { class: "grid" },
        h("thead", {}, h("tr", {},
          h("th", {}, "케이스"), h("th", {}, "업로드된 아티팩트"),
          h("th", {}, `생성 (${tzName()})`), h("th", {}, `최근 활동 (${tzName()})`), h("th", {}, ""))),
        h("tbody", {}, rows))));
  }

  function uploadedSummary(modes, done, showMode) {
    const groups = modes
      .map((m) => ({ m, apps: appsOf(m.id).filter((a) => done.has(key(m.id, a.id))) }))
      .filter((g) => g.apps.length);
    if (!groups.length) return h("span", { class: "faint" }, "업로드 없음");
    return h("div", { class: "uploaded-groups" }, groups.map(({ m, apps }) =>
      h("div", { class: "uploaded-group" },
        showMode ? h("span", { class: "uploaded-mode" }, MODE_LABEL[m.id] || m.name) : null,
        apps.map((a) => h("span", { class: "app-chip" }, appMark(a), a.name)))));
  }

  function confirmLeaveUploads(message) {
    if (!uploads.size) return true;
    return confirm(`${message}\n진행 중인 업로드 ${uploads.size}건은 화면에서 중단됩니다.`
      + "\n(서버에서 이미 분석 단계에 들어간 항목은 완료되어 원래 케이스에 저장될 수 있습니다)");
  }

  function abortUploads() {
    uploads.forEach((x) => x.abort());
    uploads.clear();
    state.uploading = {};
  }

  function enterCase(c) {
    abortUploads();
    localStorage.setItem(CASE_KEY, c.id);
    applyCase(c);
  }

  let switchSeq = 0;

  async function switchCase(id) {
    if (!confirmLeaveUploads("다른 케이스로 전환할까요?")) return;
    const seq = ++switchSeq;
    try {
      const c = await api("GET", `/api/cases/${id}`);
      if (seq !== switchSeq) return;
      enterCase(c);
      status(`케이스 열림: ${state.caseName}`);
      router();
    } catch (e) {
      if (seq === switchSeq) status(`케이스를 열지 못했습니다: ${e.message}`, true);
    }
  }

  async function deleteCase(c) {
    const current = c.id === state.caseId;
    const n = c.evidences.length;
    const msg = `케이스 "${c.name}" (${c.id.slice(0, 8)}) 를 삭제합니다.\n`
      + (n ? `등록된 증거 ${n}건의 원본 ZIP과 분석 결과가 모두 삭제되며 되돌릴 수 없습니다.` : "등록된 증거는 없습니다.")
      + (current ? "\n\n현재 열려 있는 케이스입니다. 삭제 후 다른 케이스로 전환합니다." : "");
    if (!confirm(msg)) return;
    if (current && !confirmLeaveUploads("현재 케이스를 삭제할까요?")) return;
    const seq = ++switchSeq;
    try {
      await api("DELETE", `/api/cases/${c.id}`);
      status(`케이스 삭제됨: ${c.name}`);
    } catch (e) {
      return status(`케이스를 삭제하지 못했습니다: ${e.message}`, true);
    }
    if (current) {
      try {
        const [next] = await api("GET", "/api/cases?limit=1");
        const nc = next ? await api("GET", `/api/cases/${next.id}`)
                        : { ...(await api("POST", "/api/cases", {})), evidences: [] };
        if (seq !== switchSeq) return;
        enterCase(nc);
      } catch (e) {
        return status(`다른 케이스로 전환하지 못했습니다: ${e.message}`, true);
      }
    }
    router();
  }

  async function renderUpload(mode) {
    const isCurrent = renderToken();
    const { mode: m, apps } = await getModeApps(mode);
    if (!isCurrent()) return;
    show(view,
      h("h1", { class: "page-title" }, "증거 추가", h("span", { class: "crumb" }, `/ ${MODE_LABEL[mode]}`)),
      h("p", { class: "page-note" }, m.description, " 수집 가이드대로 ZIP을 만들어 올리면 올린 항목만 분석합니다."),
      apps.map((a) => appCard(mode, a)),
    );
  }

  function appCard(mode, a) {
    const g = a.guide;
    const k = key(mode, a.id);
    const card = h("section", { class: "panel app-panel", id: `card-${mode}-${a.id}` },
      h("div", { class: "panel-head" },
        appMark(a), a.name, statusText(mode, a.id),
        h("div", { class: "head-actions", id: `actions-${mode}-${a.id}` }, headActions(mode, a))),
      h("div", { class: "evidence-strip", id: `evidence-${mode}-${a.id}` }, evidenceStrip(mode, a)),
      h("div", { class: "guide" },
        h("p", { class: "guide-summary" }, g.summary),
        h("details", { open: !state.evidences[k] },
          h("summary", {}, "수집 가이드"),
          guideBody(g),
          g.notes?.length ? [h("h4", {}, "참고"), h("ul", {}, g.notes.map((n) => h("li", {}, n)))] : null,
        ),
      ),
    );

    card.addEventListener("dragover", (e) => { e.preventDefault(); card.classList.add("drag"); });
    card.addEventListener("dragleave", (e) => { if (!card.contains(e.relatedTarget)) card.classList.remove("drag"); });
    card.addEventListener("drop", (e) => {
      e.preventDefault();
      card.classList.remove("drag");
      const f = e.dataTransfer.files[0];
      if (f && !isBusy(k)) startUpload(mode, a, f);
    });
    return card;
  }

  function guideBody(g) {
    return h("div", { class: "guide-cols" },
      h("div", {},
        h("h4", {}, "수집 대상"),
        h("table", { class: "path-table" },
          g.paths.map((p) => h("tr", {}, h("td", {}, p.os), h("td", {}, h("code", {}, p.path))))),
        h("h4", {}, "절차"),
        h("ol", {}, g.steps.map((s) => h("li", {}, s)))),
      h("div", {},
        h("h4", {}, "ZIP 구성 예"),
        h("pre", {}, g.zip_example)));
  }

  const isBusy = (k) => !!(state.uploading[k] && !state.uploading[k].error);

  function statusText(mode, app) {
    const k = key(mode, app);
    const id = `badge-${mode}-${app}`;
    if (isBusy(k)) return h("span", { id, class: "st st-busy" }, "처리 중");
    if (state.evidences[k]) return h("span", { id, class: "st st-done" }, "분석 완료");
    return h("span", { id, class: "st st-idle" }, "미등록");
  }

  function headActions(mode, a) {
    const k = key(mode, a.id);
    const up = state.uploading[k];
    if (isBusy(k)) {
      return [
        h("span", { class: "head-progress-text" }, up.phase === "upload" ? `업로드 ${up.progress}%` : "압축 해제 및 분석 중"),
        h("div", { class: "progress head-progress" }, h("div", { style: `width:${up.phase === "upload" ? up.progress : 100}%` })),
      ];
    }
    const input = h("input", { type: "file", accept: ".zip", hidden: true,
      onchange: (e) => e.target.files[0] && startUpload(mode, a, e.target.files[0]) });
    if (state.evidences[k]) {
      return [
        h("button", { class: "btn btn-primary", onclick: () => (location.hash = `#/results/${mode}/${a.id}`) }, "결과 보기"),
        h("button", { class: "btn", title: "보관된 증거로 분석만 다시 실행 (증거 원본은 바뀌지 않음)",
          onclick: (e) => reanalyze(mode, a, e.currentTarget) }, "다시 분석"),
        h("button", { class: "btn", title: "다른 ZIP으로 교체 (패널에 끌어다 놓아도 됩니다)", onclick: () => input.click() }, "교체…"),
        h("button", { class: "btn btn-danger", onclick: () => removeEvidence(mode, a) }, "삭제"),
        input,
      ];
    }
    return [
      h("button", { class: "btn btn-primary", title: "패널에 ZIP을 끌어다 놓아도 됩니다", onclick: () => input.click() }, "ZIP 업로드…"),
      input,
    ];
  }

  function evidenceStrip(mode, a) {
    const k = key(mode, a.id);
    const up = state.uploading[k];
    const ev = state.evidences[k]?.evidence;
    return [
      ev ? h("dl", { class: "strip" },
        h("div", {}, h("dt", {}, "파일"), h("dd", {}, ev.filename)),
        h("div", {}, h("dt", {}, "크기"), h("dd", {}, `${fmtSize(ev.size)}, ${ev.file_count}개 항목`)),
        h("div", {}, h("dt", {}, "MD5"), h("dd", { class: "mono" }, ev.md5)),
        h("div", {}, h("dt", {}, "SHA-256"), h("dd", { class: "mono" }, ev.sha256)),
        h("div", {}, h("dt", {}, `등록 (${tzName()})`), h("dd", { class: "mono" }, fmtTime(ev.uploaded_at))),
      ) : null,
      up?.error ? h("div", { class: "error-text" }, up.error) : null,
    ];
  }

  function rerenderCard(mode, a) {
    const actions = document.getElementById(`actions-${mode}-${a.id}`);
    if (actions) show(actions, headActions(mode, a));
    const strip = document.getElementById(`evidence-${mode}-${a.id}`);
    if (strip) show(strip, evidenceStrip(mode, a));
    const badge = document.getElementById(`badge-${mode}-${a.id}`);
    if (badge) badge.replaceWith(statusText(mode, a.id));
  }

  const uploads = new Set();

  function startUpload(mode, a, file) {
    const k = key(mode, a.id);
    if (!file.name.toLowerCase().endsWith(".zip")) {
      state.uploading[k] = { error: "ZIP 파일만 올릴 수 있습니다." };
      return rerenderCard(mode, a);
    }
    const caseId = state.caseId;
    const up = { progress: 0, phase: "upload" };
    state.uploading[k] = up;
    rerenderCard(mode, a);
    status(`${a.name} (${MODE_LABEL[mode]}) 업로드 시작: ${file.name}`);

    const fd = new FormData();
    fd.append("file", file);
    const xhr = new XMLHttpRequest();
    uploads.add(xhr);

    const stale = () => state.caseId !== caseId || state.uploading[k] !== up;

    xhr.open("POST", `/api/cases/${caseId}/${mode}/${a.id}/upload`);
    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable || stale()) return;
      up.progress = Math.floor((e.loaded / e.total) * 100);
      if (up.progress >= 100) up.phase = "analyze";
      rerenderCard(mode, a);
    };
    xhr.onload = async () => {
      uploads.delete(xhr);
      if (stale()) return;
      let data = {};
      try { data = JSON.parse(xhr.responseText); } catch {  }
      const ok = xhr.status >= 200 && xhr.status < 300;
      if (ok) delete state.uploading[k];
      else state.uploading[k] = { error: errorMessage(data, xhr.status) };
      try {
        await refreshCase();
        if (ok) status(`${a.name} (${MODE_LABEL[mode]}) 분석 완료, 항목 ${data.evidence?.file_count ?? "-"}개`);
        else status(`${a.name} (${MODE_LABEL[mode]}) 실패: ${state.uploading[k].error}`, true);
      } catch (e) {
        status(`케이스 정보를 갱신하지 못했습니다: ${e.message}`, true);
      } finally {
        if (state.caseId === caseId) rerenderCard(mode, a);
      }
    };
    xhr.onerror = () => {
      uploads.delete(xhr);
      if (stale()) return;
      state.uploading[k] = { error: "네트워크 오류로 업로드에 실패했습니다." };
      status(state.uploading[k].error, true);
      rerenderCard(mode, a);
    };
    xhr.send(fd);
  }

  const reanalyzing = new Set();

  let lastReanalysis = null;

  async function reanalyze(mode, a, btn) {
    const k = key(mode, a.id);
    if (reanalyzing.has(k)) return;
    reanalyzing.add(k);
    const label = btn ? btn.textContent : "";
    if (btn) { btn.disabled = true; btn.textContent = "분석 중…"; }
    status(`${a.name} (${MODE_LABEL[mode]}) 다시 분석 중…`);
    try {
      const r = await api("POST", `/api/cases/${state.caseId}/${mode}/${a.id}/reanalyze`);
      lastReanalysis = { caseId: state.caseId, key: k, ok: true, ev: r.evidence || {} };
      await refreshCase();
      status(`${a.name} (${MODE_LABEL[mode]}) 다시 분석 완료, 증거 해시 대조 일치`);
      router();
    } catch (e) {
      lastReanalysis = { caseId: state.caseId, key: k, ok: false, error: e.message };
      status(`다시 분석하지 못했습니다: ${e.message}`, true);
      router();
    } finally {
      reanalyzing.delete(k);
      if (btn && btn.isConnected) { btn.disabled = false; btn.textContent = label; }
    }
  }

  async function removeEvidence(mode, a) {
    if (!confirm(`${a.name} (${MODE_LABEL[mode]}) 증거와 분석 결과를 삭제합니다. 원본 ZIP도 함께 삭제됩니다.`)) return;
    try {
      await api("DELETE", `/api/cases/${state.caseId}/${mode}/${a.id}`);
      await refreshCase();
      rerenderCard(mode, a);
      status(`${a.name} (${MODE_LABEL[mode]}) 삭제됨`);
    } catch (e) {
      status(e.message, true);
    }
  }

  async function renderResults(mode, app) {
    const isCurrent = renderToken();
    const list = Object.values(state.evidences);
    if (!list.length) {
      if (!isCurrent()) return;
      show(view,
        h("h1", { class: "page-title" }, "분석 결과"),
        h("section", { class: "panel" }, h("div", { class: "empty-msg" },
          "등록된 증거가 없습니다. ",
          h("a", { href: "#/upload/client" }, "Client"), " 또는 ",
          h("a", { href: "#/upload/server" }, "Server"), " 증거를 먼저 추가하세요.")));
      return;
    }

    if (!state.evidences[key(mode, app)]) {
      const first = list.find((e) => e.mode === "client") || list[0];
      if (isCurrent()) location.replace(`#/results/${first.mode}/${first.app}`);
      return;
    }

    const result = await api("GET", `/api/cases/${state.caseId}/${mode}/${app}/result`);
    if (!isCurrent()) return;
    const ev = result.evidence;
    const ast = result.analyzer_status || {};
    const ctx = { mode, app };
    const tabsPanel = sectionTabs(result.sections, ctx);
    ctx.goto = (ref) => gotoRef(ref, tabsPanel, app);
    const searchPanel = evidenceSearch(result, ctx, tabsPanel);

    show(view,
      h("h1", { class: "page-title" }, appMark(appMeta(app)), result.app_name,
        h("span", { class: "crumb" }, `/ ${MODE_LABEL[mode]}`),
        result.is_dummy ? h("span", { class: "tag", title: "파서 구현 전입니다. 표시 내용은 예시 데이터입니다" }, "더미 데이터") : null,
        result.pg ? h("button", { class: "btn title-action", title: "PostgreSQL 데이터 디렉터리의 테이블을 원본 그대로 보기",
          onclick: () => openModal("DB 원본 - PostgreSQL",
            pgBrowser({ description: "모든 테이블을 원본 그대로 봅니다. 삭제(deleted), UPDATE 이전 버전, WAL 에만 남은 행도 상태와 함께 표시됩니다. 행을 클릭하면 열별 값을 볼 수 있습니다." },
              { mode, app })) }, "DB 원본 보기…")
          : result.mongo ? h("button", { class: "btn title-action", title: "MongoDB 데이터 디렉터리의 컬렉션을 원본 그대로 보기",
          onclick: () => openModal("DB 원본 - MongoDB",
            mongoBrowser({ description: "모든 컬렉션을 원본 그대로 봅니다. 삭제(deleted), 이전 버전(히스토리 스토어, oplog, 끊긴 블록)도 상태와 함께 표시됩니다. 행을 클릭하면 문서 전체(JSON)를 볼 수 있습니다." },
              { mode, app })) }, "DB 원본 보기…") : null),

      reanalysisNotice(mode, app),

      ast.restart_needed ? h("div", { class: "notice" },
        `분석기 코드가 바뀌었지만 서버가 아직 이전 코드로 실행 중입니다 (실행 중 ${ast.loaded}, 파일 ${ast.disk}). `
        + "지금 다시 분석해도 이전 코드로 분석됩니다. run.bat 창을 닫고 다시 실행한 뒤 [다시 분석] 하세요.") : null,

      result.stale && !ast.restart_needed ? h("div", { class: "notice" },
        ast.outdated
          ? `이 결과는 이전 버전의 분석기(${ast.result})로 만든 것입니다 (현재 ${ast.loaded}). 보관된 증거로 다시 분석하면 현재 분석기 결과로 바뀝니다.`
          : "이 결과는 이전 버전의 분석기로 만든 것입니다. 보관된 증거로 다시 분석하면 현재 분석기 결과로 바뀝니다.",
        h("button", { class: "btn btn-primary", onclick: (e) => reanalyze(mode, appMeta(app), e.currentTarget) }, "다시 분석")) : null,

      evidencePanel(ev, h("button", { class: "link-btn", title: "보관된 증거로 분석만 다시 실행 (증거 원본은 바뀌지 않음)",
          onclick: (e) => { e.stopPropagation(); reanalyze(mode, appMeta(app), e.currentTarget); } }, "다시 분석"),
        h("dl", { class: "props" },
          h("dt", {}, "파일명"), h("dd", {}, ev.filename),
          h("dt", {}, "크기"), h("dd", {}, `${fmtSize(ev.size)} (${(ev.size ?? 0).toLocaleString()} bytes), ${ev.file_count}개 항목`),
          h("dt", {}, "MD5"), h("dd", { class: "mono" }, ev.md5),
          h("dt", {}, "SHA-256"), h("dd", { class: "mono" }, ev.sha256),
          h("dt", {}, `등록 (${tzName()})`), h("dd", { class: "mono" }, fmtTime(ev.uploaded_at)),
          ev.reanalyzed_at ? [h("dt", {}, `재분석 (${tzName()})`),
            h("dd", { class: "mono" }, `${fmtTime(ev.reanalyzed_at)}, 증거 해시 대조 일치`)] : null,
          h("dt", {}, `분석 완료 (${tzName()})`), h("dd", { class: "mono" }, fmtTime(ev.analyzed_at || ev.reanalyzed_at || ev.uploaded_at)),
          h("dt", {}, "분석기"), h("dd", { class: "mono" }, analyzerText(ast)),
        )),

      result.summary.length ? h("div", { class: "summary-line" },
        result.summary.map((s) => h("div", {},
          h("span", { class: "label" }, s.label), h("span", { class: "value" }, s.value)))) : null,

      searchPanel,
      tabsPanel,
    );
    view.classList.add("fill");

    const pf = state.pendingFocus;
    state.pendingFocus = null;
    if (pf && pf.mode === mode && pf.app === app && Date.now() - pf.at < 15000) gotoRef(pf, tabsPanel, app);
  }

  async function renderCross(app) {
    const isCurrent = renderToken();
    const a = appMeta(app);
    if (!a || !crossPairs().some((x) => x.id === app)) {
      if (!isCurrent()) return;
      show(view,
        h("h1", { class: "page-title" }, "교차 분석"),
        h("section", { class: "panel" }, h("div", { class: "empty-msg" },
          "교차 분석은 같은 앱의 Client 증거와 Server 증거가 이 케이스에 모두 있을 때만 할 수 있습니다. ",
          h("a", { href: "#/upload/client" }, "Client"), ", ", h("a", { href: "#/upload/server" }, "Server"), " 증거 추가")));
      return;
    }
    let d;
    try {
      d = await api("GET", `/api/cases/${state.caseId}/cross/${app}`);
    } catch (e) {
      if (!isCurrent()) return;
      show(view,
        h("h1", { class: "page-title" }, appMark(a), a.name, h("span", { class: "crumb" }, "/ 교차 분석 (Client ↔ Server)")),
        h("section", { class: "panel" }, h("div", { class: "empty-msg" }, `교차 분석을 열지 못했습니다: ${e.message}`)));
      status(e.message, true);
      return;
    }
    if (!isCurrent()) return;
    const ctx = { mode: null, app };
    const tabsPanel = sectionTabs(d.sections, ctx);
    ctx.goto = (ref) => gotoRef(ref, tabsPanel, app);
    const side = (mode) => {
      const x = d[mode];
      return [
        h("dt", {}, MODE_LABEL[mode]),
        h("dd", {}, h("a", { href: `#/results/${mode}/${app}` }, x.filename || "-"),
          h("span", { class: "mono" }, `, SHA-256 ${String(x.sha256 || "").slice(0, 16)}…, 분석 ${fmtTime(x.analyzed_at)} ${tzName()}`)),
      ];
    };
    const stale = ["client", "server"].filter((m) => d[m].stale);

    show(view,
      h("h1", { class: "page-title" }, appMark(a), d.app_name, h("span", { class: "crumb" }, "/ 교차 분석 (Client ↔ Server)")),
      stale.length ? h("div", { class: "notice" },
        `${stale.map((m) => MODE_LABEL[m]).join(", ")} 결과가 이전 버전의 분석기로 만든 것입니다. `
        + "교차 분석은 저장된 결과로 하므로, 해당 결과 화면에서 [다시 분석] 하면 더 정확해집니다.") : null,
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, "대조한 증거"),
        h("dl", { class: "props" }, side("client"), side("server"))),
      d.summary.length ? h("div", { class: "summary-line" },
        d.summary.map((s) => h("div", {}, h("span", { class: "label" }, s.label), h("span", { class: "value" }, s.value)))) : null,
      tabsPanel,
    );
    view.classList.add("fill");
  }

  function gotoRef(ref, tabsPanel, app) {
    if (!ref || !ref.section) return;
    const here = currentRoute.split("/");
    if (ref.mode && !(here[0] === "results" && here[1] === ref.mode && here[2] === app)) {
      state.pendingFocus = { ...ref, app, at: Date.now(), route: `results/${ref.mode}/${app}` };
      location.hash = `#/results/${ref.mode}/${app}`;
      return;
    }
    const ctl = tabsPanel.__ctl.select(ref.section);
    if (!ctl) return status("근거 섹션을 찾지 못했습니다.", true);
    const m = Object.entries(ref.match || {});
    if (!ctl.focusRow((r) => m.every(([k, v]) => String(r[k] ?? "") === String(v ?? "")))) {
      status("근거 행을 찾지 못했습니다 (결과를 다시 분석했다면 행이 바뀌었을 수 있습니다).", true);
    }
  }

  const EV_KEY = "mfa.evidenceCollapsed";

  function foldHead(attrs, toggle, ...children) {
    const el = h("div", { ...attrs, role: "button", tabindex: "0", title: "눌러서 접기 / 펼치기" }, ...children);
    el.addEventListener("click", (e) => { if (!e.target.closest("button, a")) toggle(); });
    el.addEventListener("keydown", (e) => {
      if (e.target === el && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggle(); }
    });
    return el;
  }

  function analyzerText(ast) {
    if (!ast.result) return `기록 없음 (이 표시 기능 이전에 만든 결과), 현재 ${ast.loaded || "-"}`;
    return ast.result === ast.loaded ? `${ast.result}, 현재 분석기와 같음` : `${ast.result}, 현재 ${ast.loaded} 와 다름`;
  }

  function reanalysisNotice(mode, app) {
    const r = lastReanalysis;
    if (!r || r.caseId !== state.caseId || r.key !== key(mode, app)) return null;
    if (!r.ok) return h("div", { class: "notice" }, `다시 분석하지 못했습니다: ${r.error}`);
    return h("div", { class: "notice notice-ok" },
      `다시 분석 완료 - ${fmtTime(r.ev.reanalyzed_at)} ${tzName()}, 증거 해시 대조 일치`
      + (r.ev.analyzer ? `, 분석기 ${r.ev.analyzer}` : ""),
      h("button", { class: "link-btn", onclick: (e) => { lastReanalysis = null; e.currentTarget.parentElement.remove(); } }, "닫기"));
  }

  function evidencePanel(ev, action, body) {
    let collapsed = false;
    try { collapsed = localStorage.getItem(EV_KEY) === "1"; } catch {  }
    const brief = h("span", { class: "ev-brief" },
      `${ev.filename || "-"}, ${fmtSize(ev.size)}, SHA-256 ${String(ev.sha256 || "").slice(0, 16)}…, `
      + `분석 ${fmtTime(ev.analyzed_at || ev.reanalyzed_at || ev.uploaded_at)} ${tzName()}`);
    const panel = h("section", { class: "panel ev-panel" });
    const head = foldHead({ class: "panel-head foldable" }, () => {
      collapsed = !collapsed;
      try { localStorage.setItem(EV_KEY, collapsed ? "1" : "0"); } catch {  }
      apply();
    }, "증거 파일", brief, h("span", { class: "aside" }, action));
    const apply = () => { panel.classList.toggle("collapsed", collapsed); head.setAttribute("aria-expanded", String(!collapsed)); };
    panel.append(head, body);
    apply();
    return panel;
  }

  function sectionTabs(sections, ctx) {
    sections = sections.filter((s) => s.type !== "pgbrowser");
    const body = h("div", { class: "tab-body" });
    const tabs = sections.map((s, i) => h("button", {
      class: "tab" + (i === 0 ? " active" : ""),
      onclick: (e) => {
        tabs.forEach((t) => t.classList.remove("active"));
        e.currentTarget.classList.add("active");
        show(body, renderSection(s, ctx));
      },
    }, s.title, s.type === "pgbrowser" ? null : h("span", { class: "count" }, s.rows.length)));
    if (sections.length) body.append(...nodes(renderSection(sections[0], ctx)));
    const panel = h("section", { class: "panel tabs-panel" }, h("div", { class: "tabs" }, tabs), body);

    panel.__ctl = {
      select(id) {
        const i = sections.findIndex((x) => x.id === id);
        if (i < 0) return null;
        tabs[i].click();
        return body.querySelector(".dt-root")?.__ctl || null;
      },
    };
    return panel;
  }

  function renderSection(s, ctx) {
    if (s.type === "pgbrowser") return pgBrowser(s, ctx);
    if (s.type === "kv") {
      return [
        s.description ? h("div", { class: "section-tools" }, h("span", { class: "desc" }, s.description)) : null,
        h("div", { class: "table-wrap" }, h("table", { class: "grid kv" },
          h("tbody", {}, s.rows.map((r) => h("tr", {}, h("th", {}, r.key), h("td", { class: "wrap" }, cellText(r.value))))))),
      ];
    }
    return dataTable(s, ctx);
  }

  function cellText(v) {
    if (v == null) return "";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  const PAGE_SIZE = 200;

  function dataTable(s, ctx) {
    let query = "";
    let sortKey = null;
    let sortDir = 1;
    let page = 0;

    const wrapCols = new Set(s.columns
      .filter((c) => s.rows.some((r) => String(r[c.key] ?? "").length > 40))
      .map((c) => c.key));

    const timeCols = new Set(s.columns.filter((c) => isTimeColumn(c, s.rows)).map((c) => c.key));
    const disp = (r, c) => (timeCols.has(c.key) ? fmtTs(r[c.key]) : cellText(r[c.key]));
    const label = (c) => (timeCols.has(c.key) ? tzLabel(c.label) : c.label);

    const split = detailSplit();

    function openRow(tr, r) {
      const fields = s.columns.map((c) => ({ label: label(c), value: disp(r, c) }));
      const extra = s.id === "cache_entries" && ctx && r.url ? cachePreview(ctx, r.url, r._key)
        : r._gridfs && ctx ? gridfsLink(ctx, r._gridfs, r.name) : null;

      const jump = r._ref && ctx?.goto ? h("div", { class: "detail-actions" },
        h("button", { class: "btn", onclick: () => ctx.goto(r._ref) },
          r._ref.mode ? `근거 행으로 이동 (${MODE_LABEL[r._ref.mode]} 결과)` : "근거 행으로 이동")) : null;
      split.open(tr, s.title, [jump, fieldList(fields), extra]);
    }

    const tbody = h("tbody");
    const rowsInfo = h("span", { class: "rows" });
    const thead = h("thead");
    const tableEl = h("table", { class: "grid" }, thead, tbody);
    const widths = new Map();
    const pager = h("div", { class: "pager" });

    function currentRows() {
      const q = query.toLowerCase();
      let rows = q
        ? s.rows.filter((r) => s.columns.some((c) => String(disp(r, c) ?? "").toLowerCase().includes(q)))
        : s.rows.slice();
      if (sortKey) {
        rows.sort((a, b) => {
          const x = a[sortKey] ?? "", y = b[sortKey] ?? "";
          return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true })) * sortDir;
        });
      }
      return rows;
    }

    function draw() {
      const rows = currentRows();
      thead.replaceChildren(h("tr", {}, s.columns.map((c) => h("th", {
        class: "sortable", "data-key": c.key,
        onclick: (e) => {
          if (e.currentTarget.dataset.resized) return;
          if (sortKey === c.key) sortDir = -sortDir; else { sortKey = c.key; sortDir = 1; }
          page = 0;
          draw();
        },
      }, label(c), sortKey === c.key ? h("span", { class: "sort" }, sortDir > 0 ? "▲" : "▼") : null))));
      enableColumnResize(tableEl, widths);
      const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
      page = Math.min(page, pages - 1);
      const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
      tbody.replaceChildren(...(pageRows.length
        ? pageRows.map((r) => {
            const tr = h("tr", {
              class: "clickable" + (s.row_class && r[s.row_class] ? ` rc-${r[s.row_class]}` : ""),
              onclick: (e) => openRow(e.currentTarget, r),
            }, s.columns.map((c) =>
              h("td", { class: (wrapCols.has(c.key) ? "wrap" : "") + (timeCols.has(c.key) ? " mono" : "") || null }, disp(r, c))));
            tr.__row = r;
            return tr;
          })
        : [h("tr", {}, h("td", { colspan: s.columns.length, class: "empty-msg" }, "일치하는 항목이 없습니다."))]));
      rowsInfo.textContent = `${rows.length.toLocaleString()} / ${s.rows.length.toLocaleString()}`;
      const go = (p) => () => { page = p; draw(); };
      pager.replaceChildren(...(pages > 1 ? [
        h("button", { class: "btn", disabled: page === 0, onclick: go(0) }, "«"),
        h("button", { class: "btn", disabled: page === 0, onclick: go(page - 1) }, "‹"),
        h("span", {}, `${page + 1} / ${pages}`),
        h("button", { class: "btn", disabled: page >= pages - 1, onclick: go(page + 1) }, "›"),
        h("button", { class: "btn", disabled: page >= pages - 1, onclick: go(pages - 1) }, "»"),
      ] : []));
    }

    let searchTimer;
    const search = h("input", { type: "search", placeholder: "필터",
      oninput: (e) => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => { query = e.target.value; page = 0; draw(); }, 200);
      } });
    draw();

    const rootEl = h("div", { class: "dt-root" },
      h("div", { class: "section-tools" }, search, h("span", { class: "desc" }, s.description || ""), rowsInfo),
      split.el(h("div", { class: "table-wrap" }, tableEl), pager));
    rootEl.__ctl = {

      focusRow(pred) {
        query = ""; search.value = "";
        const rows = currentRows();
        const i = rows.findIndex(pred);
        if (i < 0) return false;
        page = Math.floor(i / PAGE_SIZE);
        draw();
        const tr = [...tbody.rows].find((t) => t.__row === rows[i]);
        if (tr) { openRow(tr, rows[i]); setTimeout(() => tr.scrollIntoView({ block: "nearest" }), 0); }
        return true;
      },
      setFilter(q) { query = q; search.value = q; page = 0; draw(); },
    };
    return rootEl;
  }

  const SEARCH_SHOW = 50;

  const snip = (before, match, after) => h("span", { class: "snip" }, before, h("mark", {}, match), after);

  function snipOf(text, ql) {
    const i = text.toLowerCase().indexOf(ql);
    const a = Math.max(0, i - 50), b = Math.min(text.length, i + ql.length + 50);
    const one = (t) => t.replace(/\s+/g, " ");
    return snip((a ? "…" : "") + one(text.slice(a, i)), one(text.slice(i, i + ql.length)),
      one(text.slice(i + ql.length, b)) + (b < text.length ? "…" : ""));
  }

  function searchSections(sections, q) {
    const ql = q.toLowerCase();
    const out = [];
    for (const s of sections) {
      if (s.type === "pgbrowser") continue;
      const hits = [];
      if (s.type === "kv") {
        for (const r of s.rows) {
          const t = `${cellText(r.key)} : ${cellText(r.value)}`;
          if (t.toLowerCase().includes(ql)) hits.push({ row: r, label: cellText(r.key), node: snipOf(t, ql) });
        }
      } else {
        const timeCols = new Set(s.columns.filter((c) => isTimeColumn(c, s.rows)).map((c) => c.key));
        for (const r of s.rows) {
          for (const c of s.columns) {
            const t = String((timeCols.has(c.key) ? fmtTs(r[c.key]) : cellText(r[c.key])) ?? "");
            if (t.toLowerCase().includes(ql)) {
              hits.push({ row: r, label: timeCols.has(c.key) ? tzLabel(c.label) : c.label, node: snipOf(t, ql) });
              break;
            }
          }
        }
      }
      if (hits.length) out.push({ section: s, hits });
    }
    return out;
  }

  function evidenceSearch(result, ctx, tabsPanel) {
    const scope = `${MODE_LABEL[ctx.mode]}, ${result.app_name}`;
    const input = h("input", { type: "search", class: "search-input", placeholder: `${scope} 안에서 검색 (Enter)`,
      onkeydown: (e) => { if (e.key === "Enter") run(); } });
    const deep = h("input", { type: "checkbox" });
    const out = h("div", { class: "search-results", hidden: true });
    let seq = 0;
    let folded = false;

    const goTab = (id, pred, q) => {
      const ctl = tabsPanel.__ctl.select(id);
      if (ctl && pred) ctl.focusRow(pred);
      else if (ctl && q) ctl.setFilter(q);
      tabsPanel.scrollIntoView({ block: "start", behavior: "smooth" });
    };

    function group(title, info, items) {
      return h("div", { class: "search-group" },
        h("div", { class: "search-group-head" }, h("strong", {}, title), h("span", { class: "faint" }, info)),
        h("ul", { class: "search-list" }, items));
    }

    function localGroups(q) {
      const found = searchSections(result.sections, q);
      if (!found.length) return [h("div", { class: "faint search-empty" }, "분석 결과에 일치하는 항목이 없습니다.")];
      return found.map(({ section: s, hits }) => group(s.title, `${hits.length}건`, [
        hits.slice(0, SEARCH_SHOW).map((x) => h("li", {
          class: "search-item", title: "이 행으로 이동",
          onclick: () => goTab(s.id, s.type === "kv" ? null : (r) => r === x.row),
        }, h("span", { class: "search-col" }, x.label), x.node)),
        hits.length > SEARCH_SHOW ? h("li", { class: "search-more", onclick: () => goTab(s.id, null, q) },
          `외 ${hits.length - SEARCH_SHOW}건 - 탭에서 필터로 모두 보기`) : null,
      ]));
    }

    function deepGroups(d) {
      const g = [];
      const note = (x) => `${x.hits.length}건${x.truncated ? " (최대치에서 중단)" : ""}, ${x.scanned}, ${x.seconds}초`;

      const failed = (title, x) => group(title, "실패", h("li", { class: "error-text" }, x.error));
      for (const [k, title] of [["pg", "DB 원본 (PostgreSQL)"], ["mongo", "DB 원본 (MongoDB)"], ["cache", "캐시 본문"], ["files", "원본 파일 (바이트)"]]) {
        if (d[k] && d[k].error) { g.push(failed(title, d[k])); delete d[k]; }
      }
      if (d.pg) {
        g.push(group("DB 원본 (PostgreSQL)", note(d.pg), d.pg.hits.length ? d.pg.hits.map((x) => h("li", {
          class: "search-item", title: "DB 원본 창에서 이 테이블을 검색어로 열기",
          onclick: () => openModal("DB 원본 - PostgreSQL",
            pgBrowser({ description: "검색에서 연 테이블입니다. 행을 클릭하면 열별 값을 볼 수 있습니다." }, ctx, { rel: x.oid, q: d.q })),
        }, h("span", { class: "search-col" }, `${x.table}, ${x.column}`),
          h("span", { class: `search-state rc-${x.state}` }, `${x.state}, ${x.rid}`),
          snip(x.before, x.match, x.after))) : h("li", { class: "faint" }, "없음")));
      }
      if (d.mongo) {
        g.push(group("DB 원본 (MongoDB)", note(d.mongo), d.mongo.hits.length ? d.mongo.hits.map((x) => h("li", {
          class: "search-item", title: "DB 원본 창에서 이 컬렉션을 검색어로 열기",
          onclick: () => openModal("DB 원본 - MongoDB",
            mongoBrowser({ description: "검색에서 연 컬렉션입니다. 행을 클릭하면 문서 전체(JSON)를 볼 수 있습니다." }, ctx, { ns: x.ns, q: d.q })),
        }, h("span", { class: "search-col" }, x.ns),
          h("span", { class: `search-state rc-${x.state}` }, `${x.state}, ${x.rid}`),
          snip(x.before, x.match, x.after))) : h("li", { class: "faint" }, "없음")));
      }
      if (d.cache) {
        g.push(group("캐시 본문", note(d.cache), d.cache.hits.length ? d.cache.hits.map((x) => h("li", {
          class: "search-item", title: "캐시 엔트리 탭에서 이 항목 열기",
          onclick: () => goTab("cache_entries", (r) => (x.key && r._key ? r._key === x.key : r.url === x.url)),
        }, h("span", { class: "search-col" }, `${x.where}, ${x.ctype || "-"}`),
          h("span", { class: "search-url" }, x.url), snip(x.before, x.match, x.after))) : h("li", { class: "faint" }, "없음")));
      }
      if (d.files) {
        g.push(group("원본 파일 (바이트)", note(d.files), d.files.hits.length ? d.files.hits.map((x) => h("li", {
          class: "search-item static",
        }, h("span", { class: "search-col" }, `${x.encoding}, 오프셋 ${x.offset.toLocaleString()}`),
          h("span", { class: "search-url" }, x.path), snip(x.before, x.match, x.after))) : h("li", { class: "faint" }, "없음")));
      }
      return g;
    }

    async function run() {
      const q = input.value.trim();
      const my = ++seq;
      if (!q) { out.hidden = true; show(out); return; }
      const deepBox = h("div", {}, deep.checked
        ? h("div", { class: "faint search-empty" }, "원본(DB, 캐시 본문, 파일) 검색 중… 처음에는 DB 를 여느라 몇 초 걸릴 수 있습니다.")
        : null);
      const localCount = searchSections(result.sections, q).reduce((n, g) => n + g.hits.length, 0);
      const resBody = h("div", { class: "search-results-body" },
        h("div", { class: "search-section-title" }, "분석 결과"),
        localGroups(q),
        deep.checked ? [h("div", { class: "search-section-title" }, "원본"), deepBox] : null);

      const head = foldHead({ class: "search-results-head foldable" }, () => setFold(!folded),
        h("span", {}, `"${q}" 검색 결과 - ${scope}`, h("span", { class: "faint" }, `, 분석 결과 ${localCount}건`)),
        h("span", { class: "search-head-actions" },
          h("button", { class: "link-btn", onclick: () => { input.value = ""; run(); } }, "검색 지우기")));
      const setFold = (v) => { folded = v; out.classList.toggle("collapsed", folded); head.setAttribute("aria-expanded", String(!folded)); };
      show(out, head, resBody);
      setFold(false);
      out.hidden = false;
      if (!deep.checked) return;
      const t0 = performance.now();
      try {
        const d = await api("GET", `/api/cases/${state.caseId}/${ctx.mode}/${ctx.app}/search?q=${encodeURIComponent(q)}`);
        if (my !== seq) return;
        show(deepBox, deepGroups(d));
        status(`원본 검색 완료, ${((performance.now() - t0) / 1000).toFixed(1)}초`);
      } catch (e) {
        if (my === seq) show(deepBox, h("div", { class: "error-text search-empty" }, `원본 검색 실패: ${e.message}`));
      }
    }

    return h("section", { class: "panel search-panel" },
      h("div", { class: "search-bar" },
        input,
        h("button", { class: "btn btn-primary", onclick: run }, "검색"),
        h("label", { class: "search-opt", title: "DB 원본 전체 테이블(삭제, 이전 버전 포함), 캐시 본문, 추출 파일 바이트까지 찾습니다" },
          deep, " 원본까지 (DB, 캐시 본문, 파일)")),
      out);
  }

  function enableColumnResize(table, store) {
    const ths = [...table.tHead.rows[0].cells];
    const keyOf = (th, i) => th.dataset.key || String(i);

    function apply() {
      if (!store.size) {
        table.classList.remove("resized");
        table.style.width = "";
        ths.forEach((th) => { th.style.width = ""; });
        return;
      }
      let total = 0;
      ths.forEach((th, i) => {
        const w = store.get(keyOf(th, i)) ?? th.getBoundingClientRect().width;
        th.style.width = `${w}px`;
        total += w;
      });
      table.classList.add("resized");
      table.style.width = `${total}px`;
    }

    ths.forEach((th, i) => {
      const grip = h("span", { class: "col-grip", title: "드래그: 열 너비 조절, 더블클릭: 이 표의 너비 초기화" });
      grip.addEventListener("mousedown", (e) => {
        e.preventDefault();
        e.stopPropagation();

        ths.forEach((t, j) => { if (!store.has(keyOf(t, j))) store.set(keyOf(t, j), t.getBoundingClientRect().width); });
        const k = keyOf(th, i);
        const startX = e.clientX;
        const startW = store.get(k);
        document.body.classList.add("col-resizing");
        const move = (ev) => { store.set(k, Math.max(48, Math.round(startW + ev.clientX - startX))); apply(); };
        const up = () => {
          document.removeEventListener("mousemove", move);
          document.removeEventListener("mouseup", up);
          document.body.classList.remove("col-resizing");
          th.dataset.resized = "1";
          setTimeout(() => { delete th.dataset.resized; }, 0);
        };
        document.addEventListener("mousemove", move);
        document.addEventListener("mouseup", up);
      });
      grip.addEventListener("click", (e) => e.stopPropagation());
      grip.addEventListener("dblclick", (e) => { e.stopPropagation(); store.clear(); apply(); });
      th.append(grip);
    });
    if (store.size) apply();
  }

  const PG_STATES = [["live", "live"], ["deleted", "삭제"], ["updated", "이전 버전"],
                     ["aborted", "롤백"], ["in_progress", "진행 중"], ["unknown", "판단 불가"]];
  const PG_SOURCE = { heap: "현재 파일", wal: "WAL", carved: "빈 공간" };
  const PG_PAGE = 100;

  function pgBrowser(s, ctx, init = {}) {
    const base = `/api/cases/${state.caseId}/${ctx.mode}/${ctx.app}/pg`;
    const st = { db: null, rel: null, relName: "", system: false, hideEmpty: true, filter: "",
                 offset: 0, q: "", states: new Set(PG_STATES.map((x) => x[0])), tables: [], seq: 0 };

    const dbSelect = h("select", { onchange: (e) => {
      st.db = +e.target.value; st.rel = null; st.relName = ""; st.seq++;
      show(right, h("div", { class: "empty-msg" }, "테이블 목록을 불러오는 중…"));
      loadTables();
    } });
    const tableFilter = h("input", { type: "search", placeholder: "테이블 필터",
      oninput: (e) => { st.filter = e.target.value.toLowerCase(); drawTables(); } });
    const sysBox = h("input", { type: "checkbox", onchange: (e) => { st.system = e.target.checked; loadTables(); } });
    const emptyBox = h("input", { type: "checkbox", checked: true,
      onchange: (e) => { st.hideEmpty = e.target.checked; drawTables(); } });
    const list = h("div", { class: "pg-list" });
    const right = h("div", { class: "pg-main" }, h("div", { class: "empty-msg" }, "왼쪽에서 테이블을 고르세요."));

    async function loadTables() {
      show(list, h("div", { class: "faint pg-pad" }, "불러오는 중…"));
      try {
        const qs = new URLSearchParams({ system: st.system });
        if (st.db != null) qs.set("db", st.db);
        const d = await api("GET", `${base}/tables?${qs}`);
        st.db = d.db_oid;
        st.tables = d.tables;
        show(dbSelect, d.databases.map((x) =>
          h("option", { value: x.oid, selected: x.oid === d.db_oid }, `${x.name} (oid ${x.oid})`)));
        drawTables();
        if (st.rel == null) {

          const withData = d.tables.filter((t) => t.file_size);
          const want = init.rel != null ? d.tables.find((t) => t.oid === init.rel) : null;

          const posts = withData.find((t) => t.schema === "public" && t.name === "posts")
            || withData.find((t) => t.name === "zerver_message");
          if (want) { openTable(want, init.q || ""); init = {}; }
          else if (posts) openTable(posts);
          else show(right, h("div", { class: "empty-msg" }, withData.length
            ? "왼쪽에서 테이블을 고르세요."
            : "이 데이터베이스에는 데이터가 들어 있는 테이블이 없습니다."));
        }
      } catch (e) {
        show(list, h("div", { class: "error-text pg-pad" }, e.message));
        show(right);
      }
    }

    function drawTables() {
      const items = st.tables.filter((t) => (!st.hideEmpty || t.file_size)
        && (!st.filter || t.name.toLowerCase().includes(st.filter)));
      show(list, items.length ? items.map((t) => h("a", {
        class: "pg-item" + (t.oid === st.rel ? " active" : ""), href: "javascript:void 0",
        onclick: () => openTable(t),
      }, h("span", {}, t.schema !== "public" ? `${t.schema}.${t.name}` : t.name,
          t.kind !== "table" ? h("span", { class: "faint" }, ` ${t.kind}`) : null),
         h("span", { class: "pg-size" }, fmtSize(t.file_size))))
        : h("div", { class: "faint pg-pad" }, st.hideEmpty && !st.filter ? "데이터가 있는 테이블 없음" : "테이블 없음"));
    }

    function openTable(t, q = "") {
      st.rel = t.oid; st.relName = `${t.schema}.${t.name}`; st.offset = 0; st.q = q; st.widths = new Map();
      drawTables();
      loadRows();
    }

    async function loadRows() {
      const seq = ++st.seq;
      show(right, h("div", { class: "empty-msg" },
        `${st.relName} 읽는 중… (처음 열 때 WAL 을 읽어 몇 초 걸릴 수 있습니다)`));
      const qs = new URLSearchParams({ rel: st.rel, db: st.db, offset: st.offset, limit: PG_PAGE, q: st.q,
                                       states: [...st.states].join(",") });
      let d;
      try {
        d = await api("GET", `${base}/rows?${qs}`);
      } catch (e) {
        if (seq === st.seq) show(right, h("div", { class: "error-text pg-pad" }, e.message));
        return;
      }
      if (seq === st.seq) {
        drawRows(d);
        const grid = right.querySelector(".dt-main table.grid");
        if (grid && grid.tHead) enableColumnResize(grid, st.widths || (st.widths = new Map()));
      }
    }

    function drawRows(d) {
      const chips = PG_STATES.filter(([k]) => d.by_state[k]).map(([k, label]) => h("label", { class: `pg-chip rc-${k}` },
        h("input", { type: "checkbox", checked: st.states.has(k),
          onchange: (e) => { if (e.target.checked) st.states.add(k); else st.states.delete(k); st.offset = 0; loadRows(); } }),
        ` ${label} ${d.by_state[k]}`));
      const search = h("input", { type: "search", placeholder: "값 검색 (Enter)", value: st.q,
        onkeydown: (e) => { if (e.key === "Enter") { st.q = e.target.value; st.offset = 0; loadRows(); } } });
      const pages = Math.max(1, Math.ceil(d.matched / PG_PAGE));
      const page = Math.floor(st.offset / PG_PAGE);
      const go = (p) => () => { st.offset = p * PG_PAGE; loadRows(); };
      const stateLabel = (k) => (PG_STATES.find((x) => x[0] === k) || [k, k])[1];
      const tx = (t) => fmtTs(t || "");
      const split = detailSplit();
      const openPgRow = (tr, r) => {
        split.open(tr, `${d.table}, ${r.rid}`, fieldList([
          { label: "상태", value: stateLabel(r.state) },
          { label: "출처", value: PG_SOURCE[r.source] || r.source },
          { label: "위치 (rid)", value: r.rid },
          { label: `생성 트랜잭션 (${tzName()})`, value: tx(r.xmin_time) },
          { label: `삭제, 변경 트랜잭션 (${tzName()})`, value: tx(r.xmax_time) },
          ...d.columns.map((c, i) => ({
            label: `${c.dropped ? "(삭제된 컬럼)" : c.name}${c.type ? `, ${c.type}` : ""}`,
            node: r.values[i] == null ? h("span", { class: "faint" }, "NULL") : null,
            value: r.values[i],
          })),
          ...Object.entries(r.errors || {}).map(([k, v]) => ({ label: `해석 경고: ${k}`, value: v })),
        ]));
      };
      show(right,
        h("div", { class: "section-tools" },
          h("strong", {}, d.table), h("span", { class: "faint mono" }, d.path || ""),
          h("span", { class: "desc" }), h("span", { class: "rows" }, `${d.matched.toLocaleString()} / ${d.total.toLocaleString()}`)),
        h("div", { class: "section-tools" }, chips, search),
        split.el(h("div", { class: "table-wrap" }, h("table", { class: "grid" },
          h("thead", {}, h("tr", {},
            h("th", {}, "상태"), h("th", {}, "출처"), h("th", {}, "위치"),
            h("th", {}, `생성 트랜잭션 (${tzName()})`), h("th", {}, `삭제, 변경 트랜잭션 (${tzName()})`),
            d.columns.map((c) => h("th", { class: c.dropped ? "pg-dropped" : null, title: c.type || "" },
              c.dropped ? "(삭제된 컬럼)" : c.name, h("div", { class: "pg-type" }, c.type || ""))))),
          h("tbody", {}, d.rows.length ? d.rows.map((r) => h("tr", {
            class: "clickable" + (r.state !== "live" ? ` rc-${r.state}` : ""), onclick: (e) => openPgRow(e.currentTarget, r) },
            h("td", {}, stateLabel(r.state)),
            h("td", {}, PG_SOURCE[r.source] || r.source),
            h("td", { class: "mono" }, r.rid),
            h("td", { class: "mono" }, tx(r.xmin_time)),
            h("td", { class: "mono" }, tx(r.xmax_time)),
            r.values.map((v, i) => {
              const err = r.errors[d.columns[i].name];
              return h("td", { class: (cellText(v).length > 40 ? "wrap" : "") + (err ? " pg-err" : ""), title: err || null },
                v == null ? h("span", { class: "faint" }, "NULL") : cellText(v));
            })))
            : h("tr", {}, h("td", { colspan: d.columns.length + 5, class: "empty-msg" }, "일치하는 행이 없습니다."))))),
        h("div", { class: "pager" }, pages > 1 ? [
          h("button", { class: "btn", disabled: page === 0, onclick: go(0) }, "«"),
          h("button", { class: "btn", disabled: page === 0, onclick: go(page - 1) }, "‹"),
          h("span", {}, `${page + 1} / ${pages}`),
          h("button", { class: "btn", disabled: page >= pages - 1, onclick: go(page + 1) }, "›"),
          h("button", { class: "btn", disabled: page >= pages - 1, onclick: go(pages - 1) }, "»"),
        ] : null)),
      );
    }

    loadTables();
    return [
      s.description ? h("div", { class: "section-tools" }, h("span", { class: "desc" }, s.description)) : null,
      h("div", { class: "pg-layout" },
        h("div", { class: "pg-side" },
          h("div", { class: "pg-pad" }, dbSelect),
          h("div", { class: "pg-pad" }, tableFilter),
          h("label", { class: "pg-opt" }, sysBox, " 시스템 카탈로그 보기"),
          h("label", { class: "pg-opt" }, emptyBox, " 빈 테이블 숨기기"),
          list),
        right),
    ];
  }

  const MG_STATES = [["live", "live"], ["deleted", "삭제"], ["updated", "이전 버전"], ["unknown", "판단 불가"]];
  const MG_SOURCE = { file: "현재 파일", hs: "히스토리 스토어", stale: "끊긴 블록", oplog: "oplog 재구성" };

  function mongoBrowser(s, ctx, init = {}) {
    const base = `/api/cases/${state.caseId}/${ctx.mode}/${ctx.app}/mongo`;
    const st = { db: init.ns ? init.ns.split(".")[0] : "", ns: null, system: false, hideEmpty: true, filter: "",
                 offset: 0, q: "", states: new Set(MG_STATES.map((x) => x[0])), colls: [], seq: 0 };
    const dbSelect = h("select", { onchange: (e) => {
      st.db = e.target.value; st.ns = null; st.seq++;
      show(right, h("div", { class: "empty-msg" }, "컬렉션 목록을 불러오는 중…"));
      loadColls();
    } });
    const filter = h("input", { type: "search", placeholder: "컬렉션 필터",
      oninput: (e) => { st.filter = e.target.value.toLowerCase(); drawColls(); } });
    const sysBox = h("input", { type: "checkbox", onchange: (e) => { st.system = e.target.checked; loadColls(); } });
    const emptyBox = h("input", { type: "checkbox", checked: true, onchange: (e) => { st.hideEmpty = e.target.checked; drawColls(); } });
    const list = h("div", { class: "pg-list" });
    const right = h("div", { class: "pg-main" }, h("div", { class: "empty-msg" }, "왼쪽에서 컬렉션을 고르세요."));

    let collSeq = 0;
    async function loadColls() {
      const my = ++collSeq;
      show(list, h("div", { class: "faint pg-pad" }, "불러오는 중…"));
      try {
        const qs = new URLSearchParams({ system: st.system, db: st.db || "" });
        const d = await api("GET", `${base}/collections?${qs}`);
        if (my !== collSeq) return;
        st.db = d.db;
        st.colls = d.collections;
        show(dbSelect, d.databases.map((x) =>
          h("option", { value: x.name, selected: x.name === d.db }, `${x.name} (${x.collections}개 컬렉션)`)));
        drawColls();
        if (st.ns == null) {
          const want = init.ns ? d.collections.find((c) => c.ns === init.ns) : null;
          const msg = d.collections.find((c) => c.name === "rocketchat_message");
          if (want) { openColl(want, init.q || ""); init = {}; }
          else if (msg) openColl(msg);
          else show(right, h("div", { class: "empty-msg" }, "왼쪽에서 컬렉션을 고르세요."));
        }
      } catch (e) {
        if (my !== collSeq) return;
        show(list, h("div", { class: "error-text pg-pad" }, e.message));
        show(right, h("div", { class: "empty-msg" }, "컬렉션 목록을 읽지 못했습니다. 창을 닫고 다시 열거나 [다시 분석] 후 시도하세요."));
      }
    }

    function drawColls() {
      const items = st.colls.filter((c) => (!st.hideEmpty || c.count || c.file_size > 20480)
        && (!st.filter || c.name.toLowerCase().includes(st.filter)));
      show(list, items.length ? items.map((c) => h("a", {
        class: "pg-item" + (c.ns === st.ns ? " active" : ""), href: "javascript:void 0", onclick: () => openColl(c),
      }, h("span", {}, c.name, c.gridfs ? h("span", { class: "faint" }, ` GridFS ${c.gridfs}`) : null,
          c.capped ? h("span", { class: "faint" }, " capped") : null),
         h("span", { class: "pg-size" }, `${c.count ?? "-"}, ${fmtSize(c.file_size)}`)))
        : h("div", { class: "faint pg-pad" }, "컬렉션 없음"));
    }

    function openColl(c, q = "") {
      st.ns = c.ns; st.offset = 0; st.q = q; st.widths = new Map();
      drawColls();
      loadRows();
    }

    async function loadRows() {
      const seq = ++st.seq;
      show(right, h("div", { class: "empty-msg" }, `${st.ns} 읽는 중… (처음 열 때 oplog, 히스토리 스토어를 읽어 몇 초 걸릴 수 있습니다)`));
      const qs = new URLSearchParams({ ns: st.ns, offset: st.offset, limit: PG_PAGE, q: st.q, states: [...st.states].join(",") });
      let d;
      try {
        d = await api("GET", `${base}/rows?${qs}`);
      } catch (e) {
        if (seq === st.seq) show(right, h("div", { class: "error-text pg-pad" }, e.message));
        return;
      }
      if (seq === st.seq) {
        drawRows(d);
        const grid = right.querySelector(".dt-main table.grid");
        if (grid && grid.tHead) enableColumnResize(grid, st.widths || (st.widths = new Map()));
      }
    }

    function drawRows(d) {
      const chips = MG_STATES.filter(([k]) => d.by_state[k]).map(([k, label]) => h("label", { class: `pg-chip rc-${k}` },
        h("input", { type: "checkbox", checked: st.states.has(k),
          onchange: (e) => { if (e.target.checked) st.states.add(k); else st.states.delete(k); st.offset = 0; loadRows(); } }),
        ` ${label} ${d.by_state[k]}`));
      const search = h("input", { type: "search", placeholder: "값 검색 (Enter)", value: st.q,
        onkeydown: (e) => { if (e.key === "Enter") { st.q = e.target.value; st.offset = 0; loadRows(); } } });
      const pages = Math.max(1, Math.ceil(d.matched / PG_PAGE));
      const page = Math.floor(st.offset / PG_PAGE);
      const go = (p) => () => { st.offset = p * PG_PAGE; loadRows(); };
      const stateLabel = (k) => (MG_STATES.find((x) => x[0] === k) || [k, k])[1];
      const src = (r) => (MG_SOURCE[r.source] || r.source) + (r.also_in.length ? ` +${r.also_in.length}` : "");
      const tx = (t) => fmtTs(t || "");
      const split = detailSplit();
      const openRow = (tr, r) => {
        split.open(tr, `${d.ns}, ${r.rid}`, [fieldList([
          { label: "상태", value: stateLabel(r.state) },
          { label: "출처", value: [MG_SOURCE[r.source] || r.source, ...r.also_in.map((x) => MG_SOURCE[x] || x)].join(", ") },
          { label: "위치 (rid)", value: r.rid },
          { label: `만든 시각 (${tzName()})`, value: tx(r.created) },
          { label: `지운 시각 (${tzName()})`, value: tx(r.deleted_at) },
          { label: `버전 시각 (${tzName()})`, value: tx(r.vtime) },
          r.note ? { label: "비고", value: r.note } : null,
        ].filter(Boolean)),
        h("h4", {}, "문서 (확장 JSON)"),
        h("pre", { class: "val code" }, r.json == null ? "(해석 실패)" : JSON.stringify(r.json, null, 2))]);
      };
      show(right,
        h("div", { class: "section-tools" },
          h("strong", {}, d.ns), h("span", { class: "faint mono" }, d.file || ""),
          h("span", { class: "desc" }), h("span", { class: "rows" }, `${d.matched.toLocaleString()} / ${d.total.toLocaleString()}`)),
        h("div", { class: "section-tools" }, chips, search),
        split.el(h("div", { class: "table-wrap" }, h("table", { class: "grid" },
          h("thead", {}, h("tr", {},
            h("th", {}, "상태"), h("th", {}, "출처"), h("th", {}, `만든 시각 (${tzName()})`), h("th", {}, `지운 시각 (${tzName()})`),
            d.columns.map((c) => h("th", {}, c)))),
          h("tbody", {}, d.rows.length ? d.rows.map((r) => h("tr", {
            class: "clickable" + (r.state !== "live" ? ` rc-${r.state}` : ""), onclick: (e) => openRow(e.currentTarget, r) },
            h("td", {}, stateLabel(r.state)),
            h("td", {}, src(r)),
            h("td", { class: "mono" }, tx(r.created)),
            h("td", { class: "mono" }, tx(r.deleted_at)),
            r.values.map((v) => h("td", { class: cellText(v).length > 40 ? "wrap" : "" },
              v == null ? h("span", { class: "faint" }, "-") : cellText(v)))))
            : h("tr", {}, h("td", { colspan: d.columns.length + 4, class: "empty-msg" }, "일치하는 문서가 없습니다."))))),
        h("div", { class: "pager" }, pages > 1 ? [
          h("button", { class: "btn", disabled: page === 0, onclick: go(0) }, "«"),
          h("button", { class: "btn", disabled: page === 0, onclick: go(page - 1) }, "‹"),
          h("span", {}, `${page + 1} / ${pages}`),
          h("button", { class: "btn", disabled: page >= pages - 1, onclick: go(page + 1) }, "›"),
          h("button", { class: "btn", disabled: page >= pages - 1, onclick: go(pages - 1) }, "»"),
        ] : null)),
      );
    }

    loadColls();
    return [
      s.description ? h("div", { class: "section-tools" }, h("span", { class: "desc" }, s.description)) : null,
      h("div", { class: "pg-layout" },
        h("div", { class: "pg-side" },
          h("div", { class: "pg-pad" }, dbSelect),
          h("div", { class: "pg-pad" }, filter),
          h("label", { class: "pg-opt" }, sysBox, " 시스템 DB, system.* 보기"),
          h("label", { class: "pg-opt" }, emptyBox, " 빈 컬렉션 숨기기"),
          list),
        right),
    ];
  }

  let renderSeq = 0;
  function renderToken() {
    const seq = renderSeq;
    return () => seq === renderSeq;
  }

  let ready = false;

  async function router() {
    if (!ready) return;
    ++renderSeq;
    const isCurrent = renderToken();
    view.classList.remove("fill");
    currentRoute = location.hash.replace(/^#\/?/, "");
    const [page, a, b] = currentRoute.split("/");
    renderNav();

    if (state.pendingFocus && state.pendingFocus.route !== currentRoute) state.pendingFocus = null;
    try {
      if (page === "upload" && (a === "client" || a === "server")) await renderUpload(a);
      else if (page === "results") await renderResults(a, b);
      else if (page === "cross") await renderCross(a);
      else await renderHome();
    } catch (e) {
      if (!isCurrent()) return;
      show(view, h("section", { class: "panel" }, h("div", { class: "empty-msg" }, `화면을 불러오지 못했습니다: ${e.message}`)));
      status(e.message, true);
    }
  }

  document.getElementById("new-case").addEventListener("click", async () => {

    const name = prompt("새 케이스 이름 (비워 두면 자동으로 정합니다)", "");
    if (name === null) return;
    if (!confirmLeaveUploads("새 케이스를 시작할까요?")) return;
    const seq = ++switchSeq;
    try {
      const trimmed = Array.from(name.trim()).slice(0, 100).join("");
      const c = await api("POST", "/api/cases", trimmed ? { name: trimmed } : {});
      if (seq !== switchSeq) return;
      enterCase({ ...c, evidences: [] });
      status(`케이스 생성: ${state.caseName}`);
    } catch (e) {
      return status(`케이스를 만들지 못했습니다: ${e.message}`, true);
    }
    if (location.hash === "#/") router();
    else location.hash = "#/";
  });

  document.getElementById("case-name").addEventListener("click", () => (location.hash = "#/"));

  renderTzToggle();
  renderThemeToggle();
  window.addEventListener("hashchange", () => { closeDetail(); if (!modal.hidden) closeModal(); router(); });
  loadMeta()
    .then(loadCase)
    .then(() => { ready = true; return router(); })
    .catch((e) => status(`초기화 실패: ${e.message}`, true));
})();
