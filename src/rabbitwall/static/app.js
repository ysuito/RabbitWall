"use strict";
let snapshot = null, tab = "flows";
let control = null, controlBusy = false, controlDemo = false, controlEpoch = 0;
let controlReceivedAt = performance.now();
let controlAuthorized = false;
let nodeSettings=null, nodeDraft=[], nodeDirty=false, nodeBusy=false;
const $ = id => document.getElementById(id);
let sessionView = "map";
const atlas = new window.SessionAtlas({canvas:$("atlas-canvas"), list:$("atlas-routes"),
  detail:$("atlas-detail"), summary:$("atlas-summary"), onInspect:address => {
    $("search").value = address; setSessionView("table"); render();
  },onSelectionChange:key=>{$("atlas-clear").disabled=!key;}});
$("atlas-pause").setAttribute("aria-pressed", String(atlas.paused));
$("atlas-pause").textContent = atlas.paused ? "動 / 演出再開" : "止 / 演出停止";
function setSessionView(view) {
  const page=view==="map" ? "monitor" : "sessions";
  if(location.hash.slice(1)===page)navigate();else location.hash=page;
}
function resetAtlasView() {
  $("search").value="";$("scope").value="related";$("proto").value="all";tab="flows";
  for(const name of Object.keys(heads)){$("tab-"+name).classList.toggle("selected",name===tab);$("tab-"+name).setAttribute("aria-selected",String(name===tab));}
  atlas.clearSelection();atlas.setPaused(atlas.initialPaused);
  $("atlas-pause").setAttribute("aria-pressed",String(atlas.paused));$("atlas-pause").textContent=atlas.paused ? "動 / 演出再開" : "止 / 演出停止";
  atlas.resetPosition();
  setSessionView("map");render();
}
const heads = {
  flows: ["方向", "送信元", "宛先", "宛先国", "サービス", "状態", "送信 / 受信", "初回観測"],
  history: ["方向", "送信元", "宛先", "宛先国", "サービス", "観測状態", "送信 / 受信", "最終観測"],
  drops: ["方向", "送信元", "宛先", "宛先国", "プロトコル", "チェーン", "受信 → 送信IF", "時刻"]
};
let countryNames;
try { countryNames = new Intl.DisplayNames(["ja"], {type:"region"}); } catch (_) { countryNames = null; }
function countryText(info) {
  if (info?.kind === "private") return "LAN";
  if (info?.kind === "special") return "予約・特殊";
  if (!/^[A-Z]{2}$/.test(info?.code || "")) return "不明";
  const flag = [...info.code].map(c => String.fromCodePoint(127397 + c.charCodeAt(0))).join("");
  return flag + " " + (countryNames?.of(info.code) || info.code) + " · " + info.code;
}
function direction(flow) {
  const rabbitwall = (snapshot?.network?.local_ips || []).includes(flow.dst);
  return flow.scope === "MANAGEMENT" ? rabbitwall ? "LAN → RabbitWall" : "LAN → AI" : flow.scope === "RABBITWALL" ? "RabbitWall発信" : rabbitwall ? "AI → RabbitWall" : "AI → 上流";
}
function navigate() {
  const pages = {monitor:"広域通信監視",sessions:"通信記録一覧",settings:"環境設定",analytics:"通信分析"};
  const page = Object.hasOwn(pages, location.hash.slice(1)) ? location.hash.slice(1) : "monitor";
  for (const element of document.querySelectorAll("[data-page]")) element.hidden = element.dataset.page !== page;
  for (const link of document.querySelectorAll("[data-nav]")) {
    link.classList.toggle("active", link.dataset.nav === page);
    if (link.dataset.nav === page) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  }
  $("page-title").textContent = pages[page];
  document.body.classList.toggle("monitor-mode",page==="monitor");
  document.body.classList.toggle("workspace-mode",page==="monitor" || page==="sessions");
  if(page==="monitor" || page==="sessions"){
    sessionView=page==="monitor" ? "map" : "table";
    $(page==="monitor" ? "map-controls" : "list-controls").append($("session-controls"));
    for(const name of ["map","table"]){$("view-"+name).classList.toggle("selected",sessionView===name);$("view-"+name).setAttribute("aria-pressed",String(sessionView===name));}
  }
  if(page==="settings" && !nodeBusy && !nodeDirty)loadNodeSettings();
  atlas.setActive(page === "monitor");
  render();
}
function renderGeoip() {
  const data = snapshot?.geoip;
  $("geoip-status").textContent = data?.available ? "有" : "無";
  $("geoip-status").title=data?.available ? "国別IPデータを利用可能" : "国別IPデータが未導入または利用不可";
  $("geoip-status").setAttribute("aria-label",$("geoip-status").title);
  $("geoip-status").className = "badge " + (data?.available ? "good" : "warn");
  $("geoip-source").textContent = data?.source || "DB-IP Lite";
  $("geoip-edition").textContent = data?.edition || "—";
  $("geoip-updated").textContent = data?.updated_at ? new Date(data.updated_at).toLocaleString("ja-JP", {hour12:false}) : "—";
  $("geoip-message").textContent = data?.error || (data?.available ? "ローカルのデータを使って国を表示しています。" : "国別IPデータを導入すると公開IPの国を表示できます。LAN内と予約アドレスはデータ未導入でも区別します。");
}
function endpoint(ip, port) { return ip + (port === null || port === undefined || port === "" ? "" : ":" + port); }
function clock(value) { return value ? new Date(value).toLocaleTimeString("ja-JP", {hour12:false}) : "—"; }
function bytes(value) {
  if (value === null || value === undefined) return "—";
  for (const unit of ["B", "KB", "MB", "GB"]) { if (value < 1024 || unit === "GB") return value.toFixed(unit === "B" ? 0 : 1) + " " + unit; value /= 1024; }
}
function cell(row, value, className = "") {
  const td = document.createElement("td"); td.textContent = value; td.className = className; row.append(td); return td;
}
function renderGateTimer() {
  const known = control?.available && !control.error;
  const remaining = known && control.enabled ? control.remaining_seconds : null;
  const seconds = remaining == null ? null : Math.max(0, Math.ceil(remaining - (performance.now() - controlReceivedAt) / 1000));
  $("gate-timer").textContent = seconds !== null
    ? seconds > 0 ? `自動遮断まで ${Math.floor(seconds / 60)}分${String(seconds % 60).padStart(2,"0")}秒` : "期限到達・遮断状態を確認中"
    : "";
  $("gate-timer").hidden = seconds === null;
}
function renderControl() {
  const known = control && control.available && !control.error;
  const state = known ? control.enabled ? "online" : "offline" : "unknown";
  $("gate-panel").dataset.state=state;
  $("gate-panel").setAttribute("aria-busy",String(controlBusy));
  $("gate-state").textContent = known ? control.enabled ? "開" : "閉" : "不明";
  $("gate-state").className = "gate-state " + state;
  $("internet-toggle").disabled=controlBusy || !controlAuthorized;
  $("internet-toggle").setAttribute("aria-checked",String(Boolean(known && control.enabled)));
  $("internet-toggle").setAttribute("aria-label",known ? "AIセグメントの対外接続" : "AIセグメントの対外接続・状態不明（操作すると閉じます）");
  $("internet-toggle").title=controlBusy ? "変更中…" : !controlAuthorized ? "証明書付きHTTPSで接続してください" : known ? control.enabled ? "接続を閉じる" : "接続を開く" : "接続を閉じる（現在の状態は不明）";
  document.querySelectorAll("[data-duration]").forEach(button => { button.disabled=controlBusy || !controlAuthorized; });
  renderGateTimer();
  $("auth-link").hidden=controlAuthorized;
  $("nodes").replaceChildren();
  for (const node of control?.nodes || []) {
    const row = document.createElement("div"); row.className = "node-row";
    const identity = document.createElement("div"), title = document.createElement("strong"), ip = document.createElement("code");
    title.textContent = node.name; ip.textContent = node.ip; identity.append(title, ip);
    const status = document.createElement("span"), last = document.createElement("small");
    status.className = "node-state " + (node.state === "up" ? "good" : node.state === "disabled" ? "idle" : "warn");
    status.textContent = node.state === "up" ? "正" : node.state === "no_reply" ? "断" : node.state === "disabled" ? "休" : "不";
    let description=node.state==="up" ? "正常" : node.state==="no_reply" ? "応答なし" : node.state==="disabled" ? "監視しない" : "確認不能";
    const age = Date.now() - new Date(node.checked_at).getTime();
    if (!control.available || age > 30000) { status.textContent = !control.available ? "不" : "古"; status.className = "node-state warn";description=!control.available ? "状態未確認" : "監視データが古い"; }
    status.title=description;status.setAttribute("aria-label",description);
    last.textContent = (node.state === "disabled" ? "監視なし" : node.latency_ms == null ? "LOCAL" : node.latency_ms+" ms") + " / " + clock(node.checked_at);
    last.title="最終正常 "+clock(node.last_success);identity.append(last);row.append(status,identity);$("nodes").append(row);
  }
  if (!(control?.nodes || []).length) { const p = document.createElement("p"); p.className = "muted"; p.textContent = "監視データはまだありません。"; $("nodes").append(p); }
  updateNodeButtons();
  if (snapshot) snapshot.control = control;
}
async function refreshControl() {
  const epoch = controlEpoch;
  try {
    const response = await fetch("/api/control", {cache:"no-store", signal:AbortSignal.timeout(8000)});
    const data = await response.json(); if (!response.ok) throw new Error(data.error || "状態取得失敗");
    if (epoch !== controlEpoch || controlBusy) return;
    control = data.control; controlReceivedAt = performance.now(); controlDemo = data.demo; controlAuthorized=Boolean(data.auth?.can_control); renderControl();
    $("control-message").textContent = controlDemo ? "試験表示・実機操作なし" : control.error || "";
  } catch (e) {
    if (epoch !== controlEpoch || controlBusy) return;
    controlAuthorized=false; control = {available:false, nodes:control?.nodes || [], error:e.message}; renderControl();
    $("control-message").textContent = "通信状態を確認できません。" + e.message;
  } finally { setTimeout(refreshControl, 5000); }
}
async function setInternet(enabled, duration_seconds = null) {
  if (controlBusy) return;
  controlBusy = true; controlEpoch++; renderControl(); $("control-message").textContent = "通信状態を変更しています…";
  try {
    const response = await fetch("/api/internet", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(duration_seconds === null ? {enabled} : {enabled, duration_seconds}), signal:AbortSignal.timeout(10000)});
    const data = await response.json(); if (!response.ok) throw new Error(data.error || "変更失敗");
    control = data.control; controlReceivedAt = performance.now(); controlDemo = data.demo;
    $("control-message").textContent = controlDemo ? "試験 / " + (enabled ? "開" : "閉") : enabled ? "対外接続を許可しました" : "既存の外部通信も遮断しました";
  } catch (e) {
    // A timed-out response does not establish whether the change took effect.
    control = {available:false, nodes:control?.nodes || [], error:e.message};
    $("control-message").textContent = "変更結果は未確認です。" + e.message;
  } finally { controlBusy = false; controlEpoch++; renderControl(); }
}
function render() {
  if (!snapshot) return;
  document.title = (snapshot.network?.label || "RabbitWall") + " · NETWORK OBSERVATORY";
  const ai = snapshot.flows.filter(f => f.scope === "AI");
  $("ai-count").textContent = snapshot.collector_ok ? ai.length : "—";
  $("dest-count").textContent = snapshot.collector_ok ? new Set(ai.map(f => f.dst)).size : "—";
  $("tcp-count").textContent = snapshot.collector_ok ? ai.filter(f => f.proto === "TCP" && f.state === "ESTABLISHED").length : "—";
  $("drop-count").textContent = snapshot.drops.length;
  $("demo").hidden = !snapshot.demo;
  const bad = snapshot.stale || !snapshot.collector_ok || snapshot.errors.length;
  $("health").textContent = snapshot.stale ? "データ更新が停止" : bad ? "一部の収集に失敗" : snapshot.demo ? "デモデータ表示中" : "自動更新中 · 5秒";
  $("live-dot").classList.toggle("bad", Boolean(bad));
  $("updated").textContent = "最終収集 " + clock(snapshot.updated_at);
  const notices = [...snapshot.errors];
  if (snapshot.stale) notices.unshift("収集データが古くなっています。collectorサービスを確認してください。");
  $("notice").hidden = !notices.length; $("notice").textContent = notices.join("\n");
  renderGeoip();
  renderAnalytics();
  const search = $("search").value.toLowerCase(), scope = $("scope").value, proto = $("proto").value;
  const matches = f => (scope === "all" || (scope === "related" ? ["AI", "MANAGEMENT"].includes(f.scope) : f.scope === scope)) && (proto === "all" || f.proto === proto) &&
    [...(f.domain_hints || []).map(h => h.domain), f.src, f.dst, f.sport, f.dport, f.proto, f.service, f.state, f.chain, direction(f), countryText(f.src_country), countryText(f.dst_country)].join(" ").toLowerCase().includes(search);
  const rows = snapshot[tab].filter(matches);
  $("row-count").textContent = rows.length + " 件";
  atlas.update(rows, {kind:tab, stale:snapshot.stale || !snapshot.collector_ok, network:snapshot.network});
  $("table-head").replaceChildren(); const header = document.createElement("tr");
  for (const title of heads[tab]) { const th = document.createElement("th"); th.textContent = title; header.append(th); } $("table-head").append(header);
  $("rows").replaceChildren();
  for (const f of rows) {
    const row = document.createElement("tr");
    cell(row, direction(f));
    const srcCell = cell(row, endpoint(f.src, f.sport), "mono"), srcCountry = document.createElement("small");
    srcCountry.className = "endpoint-country"; srcCountry.textContent = countryText(f.src_country); srcCell.append(srcCountry);
    const dstCell = cell(row, endpoint(f.dst, f.dport), "mono");
    if (f.domain_hints?.length) {
      const hints = document.createElement("small"); hints.className = "endpoint-country";
      hints.textContent = "推定ドメイン: " + f.domain_hints.map(h => h.domain).join(" / ");
      hints.title = "同じ端末のDNS応答と宛先IPを照合した候補です。HTTPの接続先名を保証しません。";
      dstCell.append(hints);
      if (f.domain_hints.some(h => h.is_new)) dstCell.append(newDomainBadge());
    }
    cell(row, countryText(f.dst_country), "country");
    cell(row, tab === "drops" ? f.proto : f.service + " / " + f.proto);
    const status = tab === "drops" ? f.chain + " DROP" : tab === "history" ? f.ended_at ? "観測終了" : "追跡中" : f.state;
    const td = cell(row, ""), badge = document.createElement("span"); badge.textContent = status;
    badge.className = "badge " + (tab === "drops" || status === "UNREPLIED" ? "warn" : status === "ESTABLISHED" ? "good" : ""); td.append(badge);
    cell(row, tab === "drops" ? (f.in || "—") + " → " + (f.out || "—") : bytes(f.tx_bytes) + " / " + bytes(f.rx_bytes), "mono");
    cell(row, clock(tab === "drops" ? f.time : tab === "history" ? f.last_seen : f.first_seen), "mono"); $("rows").append(row);
  }
  if (!rows.length) { const tr = document.createElement("tr"), td = cell(tr, "該当する通信はありません", "empty"); td.colSpan = 8; $("rows").append(tr); }
  $("table-note").textContent = tab === "drops"
    ? "直近5分・最大200件。既存FWのログに記録された拒否のみ表示します。レート制限やログのないルールによる拒否は含みません。"
    : tab === "history"
    ? "約5秒ごとの観測履歴から直近500件を表示。終了済みの保存は24時間・全体目安2万件。短い通信は見逃す場合があります。観測終了はTCP切断時刻ではありません。"
    : "RabbitWallを通る通信を両方向の開始元で表示。LAN → AIの管理SSHも含みます。送受信量は開始元を基準にした累計、国はIPからの概算です。";
}
function newDomainBadge() {
  const badge = document.createElement("span"); badge.className = "new-domain-badge";
  badge.textContent = "新"; badge.title = "この機能で初めて観測してから24時間以内のドメイン";
  return badge;
}
function timestampText(seconds) {
  return Number.isFinite(seconds) ? new Date(seconds*1000).toLocaleString("ja-JP", {hour12:false}) : "—";
}
function renderAnalytics() {
  const data = snapshot.analytics;
  const windowData = data?.windows?.[$("ranking-window").value];
  $("ranking-rows").replaceChildren(); $("new-domain-rows").replaceChildren();
  $("ranking-period").textContent = data ? "集計開始 " + timestampText(data.since) : "収集サービスを更新してください";
  $("ranking-tx").textContent = bytes(windowData?.tx_bytes);
  $("ranking-rx").textContent = bytes(windowData?.rx_bytes);
  const coverage = data?.coverage;
  $("ranking-coverage").textContent = !coverage?.available ? "通信量収集を確認中" : coverage.missing
    ? `追跡 ${coverage.tracked}件 / カウンター未取得 ${coverage.missing}件` : `追跡 ${coverage.tracked}件`;
  if (coverage?.missing) $("ranking-coverage").textContent += " · nf_conntrack_acctと新規接続を確認";
  const sort = $("ranking-sort").value;
  const amount = row => sort === "tx" ? row.tx_bytes : sort === "rx" ? row.rx_bytes : row.tx_bytes+row.rx_bytes;
  const rows = [...(windowData?.[$("ranking-group").value === "ip" ? "by_ip" : "by_domain"] || [])]
    .sort((a,b) => amount(b)-amount(a) || a.label.localeCompare(b.label)).slice(0,20);
  for (const [index, entry] of rows.entries()) {
    const row = document.createElement("tr"); cell(row, index+1);
    const destination = cell(row, entry.label, "ranking-destination");
    const detail = document.createElement("small"); detail.className = "endpoint-country";
    detail.textContent = $("ranking-group").value === "ip"
      ? (entry.domains.length ? "推定: " + entry.domains.join(" / ") : "ドメイン不明")
      : entry.addresses.join(" / ") + (entry.label.startsWith("複数候補") ? " · " + entry.domains.join(" / ") : "");
    destination.append(detail);
    cell(row, bytes(entry.tx_bytes), "mono"); cell(row, bytes(entry.rx_bytes), "mono");
    cell(row, bytes(entry.tx_bytes+entry.rx_bytes), "mono"); $("ranking-rows").append(row);
  }
  if (!rows.length) { const row = document.createElement("tr"); cell(row, "集計対象の通信量はまだありません。", "empty").colSpan=5; $("ranking-rows").append(row); }
  $("new-domain-count").textContent = data ? `24時間以内 ${data.new_domain_count}件 / 既知 ${data.known_domain_count}件` : "—";
  $("domain-catalogue").textContent = "この機能で初めて観測してから24時間を「新」と表示。既知ドメインは再起動後も保持します。DNS問い合わせの観測であり、接続の成立を示すものではありません。直近100件を表示。" +
    (data?.domain_limit_reached ? " 台帳が上限10万件に達しました。未登録ドメインの新規判定は停止しています。" : "");
  for (const entry of data?.new_domains || []) {
    const row = document.createElement("tr"), name = cell(row, entry.domain, "ranking-destination");
    name.append(newDomainBadge()); cell(row, timestampText(entry.first_seen), "mono");
    cell(row, timestampText(entry.last_seen), "mono"); $("new-domain-rows").append(row);
  }
  if (!data?.new_domains?.length) { const row=document.createElement("tr"); cell(row,"新しく観測したドメインはありません。","empty").colSpan=3; $("new-domain-rows").append(row); }
}
for (const id of ["ranking-window", "ranking-group", "ranking-sort"]) $(id).addEventListener("change", () => snapshot && renderAnalytics());
async function refresh() {
  try {
    const response = await fetch("/api/state", {cache:"no-store", signal:AbortSignal.timeout(8000)});
    const data = await response.json(); if (!response.ok) throw new Error(data.error || "収集データ取得失敗"); snapshot = data; render();
  } catch (e) {
    $("health").textContent = "データ取得に失敗"; $("live-dot").classList.add("bad");
    $("notice").hidden = false; $("notice").textContent = "表示内容は最新ではありません。" + e.message;
  } finally { setTimeout(refresh, 5000); }
}
for (const name of Object.keys(heads)) $("tab-" + name).addEventListener("click", () => {
  tab = name;
  for (const other of Object.keys(heads)) { $("tab-" + other).classList.toggle("selected", other === tab); $("tab-" + other).setAttribute("aria-selected", String(other === tab)); }
  render();
});
for (const id of ["search", "scope", "proto"]) $(id).addEventListener("input", render);
$("export").addEventListener("click", () => {
  if (!snapshot) return; const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], {type:"application/json"}));
  const a = document.createElement("a"); a.href = url; a.download = "rabbitwall-sessions-" + new Date().toISOString().replace(/[:.]/g,"-") + ".json"; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
});
refresh();
$("internet-toggle").addEventListener("click", () => setInternet(Boolean(control?.available && !control.error && !control.enabled)));
$("view-map").addEventListener("click", () => setSessionView("map"));
$("view-table").addEventListener("click", () => setSessionView("table"));
$("atlas-pause").addEventListener("click", () => {
  atlas.setPaused(!atlas.paused); $("atlas-pause").setAttribute("aria-pressed", String(atlas.paused));
  $("atlas-pause").textContent = atlas.paused ? "動 / 演出再開" : "止 / 演出停止";
});
$("atlas-clear").addEventListener("click",()=>atlas.clearSelection());
$("atlas-reset").addEventListener("click",resetAtlasView);
window.addEventListener("hashchange", navigate);
navigate();
refreshControl();

function applyTheme(value) {
  const name = Object.hasOwn(window.SessionAtlas.themes,value) ? value : "amber";
  document.documentElement.dataset.theme=name;
  $("color-scheme").value=name;
  atlas.setTheme(name);
  return name;
}
let savedTheme="amber";
try { savedTheme=localStorage.getItem("rabbitwall-color-scheme") || "amber"; } catch (_) {}
applyTheme(savedTheme);
$("color-scheme").addEventListener("change",()=>{
  const name=applyTheme($("color-scheme").value);
  try { localStorage.setItem("rabbitwall-color-scheme",name);$("theme-message").textContent="配色をこのブラウザーに保存しました。"; }
  catch (_) { $("theme-message").textContent="配色を変更しました。ブラウザーに保存できないため、再読み込みすると元に戻ります。"; }
});


function updateNodeButtons() {
  $("node-fields").disabled=nodeBusy || !controlAuthorized || !nodeSettings;
  $("node-save").disabled=nodeBusy || !controlAuthorized || !nodeDirty;
  $("node-reload").disabled=nodeBusy;
  $("node-add").disabled=nodeDraft.length>=12;
  $("node-count").textContent=nodeDraft.length+" / 12";
}
function renderNodeEditor() {
  $("node-editor").replaceChildren();
  nodeDraft.forEach((node,index)=>{
    const row=document.createElement("section");row.className="node-edit-row";
    const labelInput=(title,key)=>{
      const label=document.createElement("label"),input=document.createElement("input");
      label.textContent=title;input.value=node[key];input.required=true;
      input.maxLength=key==="label" ? 32 : 15;
      input.setAttribute("aria-label",`ノード${index+1} ${title}`);
      input.addEventListener("input",()=>{node[key]=input.value;nodeDirty=true;updateNodeButtons();});
      label.append(input);row.append(label);
    };
    labelInput("名前","label");labelInput("IPv4アドレス","ip");
    const sideLabel=document.createElement("label"),side=document.createElement("select");sideLabel.textContent="接続先";
    side.setAttribute("aria-label",`ノード${index+1} 接続先`);
    for(const entry of nodeSettings.interfaces){const option=document.createElement("option");option.value=entry.name;option.textContent=(entry.side==="AI" ? "AI側" : "上流側")+` / ${entry.cidr}`;side.append(option);}
    side.value=node.interface;sideLabel.append(side);row.append(sideLabel);
    const flags=document.createElement("div");flags.className="node-edit-flags";
    const management=[];
    for(const [key,title] of [["monitor","死活監視"],["allow_ssh","管理PCからSSH"],["allow_ping","管理PCからPing"]]){
      const label=document.createElement("label"),box=document.createElement("input");box.type="checkbox";box.checked=node[key];
      box.setAttribute("aria-label",`ノード${index+1} ${title}`);
      if(key!=="monitor"){box.disabled=node.interface!==nodeSettings.interfaces.find(entry=>entry.side==="AI").name;management.push([key,box]);}
      box.addEventListener("change",()=>{node[key]=box.checked;nodeDirty=true;updateNodeButtons();});
      label.append(box,document.createTextNode(title));flags.append(label);
    }
    side.addEventListener("change",()=>{
      node.interface=side.value;
      const ai=nodeSettings.interfaces.find(entry=>entry.side==="AI").name;
      for(const [key,box] of management){box.disabled=node.interface!==ai;if(box.disabled){node[key]=false;box.checked=false;}}
      nodeDirty=true;updateNodeButtons();
    });
    row.append(flags);
    const remove=document.createElement("button");remove.type="button";remove.className="secondary node-remove";remove.textContent="削除";
    remove.setAttribute("aria-label",`ノード${index+1}を削除`);
    remove.addEventListener("click",()=>{nodeDraft.splice(index,1);nodeDirty=true;renderNodeEditor();});row.append(remove);
    $("node-editor").append(row);
  });
  if(!nodeDraft.length){const empty=document.createElement("p");empty.className="muted";empty.textContent="登録ノードはありません。AIセグメント全体の通信観測は継続します。";$("node-editor").append(empty);}
  updateNodeButtons();
}
async function loadNodeSettings() {
  if(nodeBusy)return;
  nodeBusy=true;updateNodeButtons();
  try{
    const response=await fetch("/api/nodes",{cache:"no-store",signal:AbortSignal.timeout(10000)});
    const data=await response.json();if(!response.ok)throw new Error(data.error || "読込失敗");
    nodeSettings=data.settings;nodeDraft=structuredClone(data.settings.nodes);nodeDirty=false;
    controlAuthorized=Boolean(data.auth?.can_control);
    $("node-message").textContent=data.demo ? "試験表示：変更はこのデモの実行中だけ保持します。" : controlAuthorized ? "変更後に「保存して反映」を押してください。" : "編集には証明書付きHTTPSで接続してください。";
    renderNodeEditor();
  }catch(error){$("node-message").textContent="読込失敗："+error.message;}
  finally{nodeBusy=false;updateNodeButtons();}
}
$("node-add").addEventListener("click",()=>{
  if(!nodeSettings || nodeBusy || !controlAuthorized || nodeDraft.length>=12)return;
  nodeDraft.push({id:"node-"+crypto.randomUUID().slice(0,8),label:"",ip:"",interface:nodeSettings.interfaces.find(entry=>entry.side==="AI").name,monitor:true,allow_ssh:false,allow_ping:false});
  nodeDirty=true;renderNodeEditor();
});
$("node-reload").addEventListener("click",()=>{if(!nodeDirty || window.confirm("未保存の変更を破棄して再読み込みしますか？"))loadNodeSettings();});
$("node-form").addEventListener("submit",async event=>{
  event.preventDefault();if(nodeBusy || !controlAuthorized || !nodeDirty)return;
  nodeBusy=true;updateNodeButtons();$("node-message").textContent="保存して反映しています…";
  try{
    const response=await fetch("/api/nodes",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({nodes:nodeDraft,revision:nodeSettings.revision}),signal:AbortSignal.timeout(20000)});
    const data=await response.json();if(!response.ok)throw new Error(response.status===409 ? "ほかの画面で設定が変更されました。再読み込みしてから編集してください。" : data.error || "保存失敗");
    nodeSettings=data.settings;nodeDraft=structuredClone(data.settings.nodes);nodeDirty=false;renderNodeEditor();
    $("node-message").textContent=data.demo ? "試験表示：デモ内に保存しました。" : "保存して反映しました。対外接続の開閉状態は変更していません。";
    refreshControl();refresh();
  }catch(error){$("node-message").textContent="保存結果を確認してください："+error.message;}
  finally{nodeBusy=false;updateNodeButtons();}
});

document.querySelectorAll("[data-duration]").forEach(button => button.addEventListener("click", () => setInternet(true, Number(button.dataset.duration))));

setInterval(renderGateTimer, 1000);
