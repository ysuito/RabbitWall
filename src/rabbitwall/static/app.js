"use strict";
let snapshot = null, tab = "flows";
let control = null, controlBusy = false, controlDemo = false, controlEpoch = 0;
let controlReceivedAt = performance.now();
let controlAuthorized = false;
let nodeSettings=null, nodeDraft=[], nodeDirty=false, nodeBusy=false;
let approvalNodes=[], approvalNodesLoading=false, gateTargetSignature=null;
const $ = id => document.getElementById(id);
const auditView = new window.AuditView();
const requestNotifications = new window.RequestNotifications();
const requestSound = new window.RequestSound(() => {
  const Audio = window.AudioContext || window.webkitAudioContext;
  if (!Audio) throw new Error("Audio is unavailable");
  return new Audio();
}, () => window.localStorage);
let alertRequestIds = [], requestListSignature = null, pendingChime = false;
let bannerSignature = null, bannerFeedback = "", bannerFeedbackState = "";
function renderSoundButton() {
  const waiting=requestSound.enabled && !requestSound.ready;
  $("request-sound").textContent = requestSound.enabled ? waiting ? "通知音 有効 · 待機" : "通知音 有効" : "通知音 無効";
  $("request-sound").setAttribute("aria-pressed", String(requestSound.enabled));
  $("request-sound").title = waiting ? "設定は有効です。画面を操作すると音声再生を再開します。" : "通知音の設定をこのブラウザーに保存します";
}
function soundUnavailable() { renderSoundButton(); }
function connectionLog(item, status="") {
  const log=document.createElement("div");log.className="connection-log";
  const primary=document.createElement("div");primary.className="log-primary";
  const createdAt=item.created_at || (item.expires_at && Number.isFinite(item.duration_seconds)
    ? new Date(Date.parse(item.expires_at)-item.duration_seconds*1000).toISOString() : null);
  if(createdAt){
    const time=document.createElement("time");time.className="log-time";time.dateTime=createdAt;
    time.textContent=new Date(createdAt).toLocaleString("ja-JP",{hour12:false});primary.append(time);
  }
  const fields=[
    ["src","Src",item.source+" ("+item.node_name+")"],
    ["dst","Dst",item.domains.join(", ")],
    ["duration","Duration",Number.isFinite(item.duration_seconds) ? (item.duration_seconds/60)+"分" : "—"]
  ];
  if(status)fields.push(["status","Status",status]);
  for(const [name,label,value] of fields){
    const field=document.createElement("span");field.className="log-field log-"+name;
    const key=document.createElement("span");key.className="log-key";key.textContent=label+":";
    const text=document.createElement("span");text.className="log-value";text.textContent=value;
    field.append(key,text);primary.append(field);
  }
  const purpose=document.createElement("p");purpose.className="log-purpose";
  const label=document.createElement("span");label.className="log-key";label.textContent="目的：";
  const value=document.createElement("span");value.className="log-value";value.textContent=item.purpose;
  purpose.append(label,value);log.append(primary,purpose);
  return log;
}
function updateRequestBanner(pending) {
  const visible=pending.filter(item=>item.status==="pending" && alertRequestIds.includes(item.id));
  const show=visible.length>0 || Boolean(bannerFeedback);
  $("request-alert").hidden=!show;
  document.body.classList.toggle("has-request-alert",show);
  if(!show)return;
  $("request-alert-text").textContent=visible.length ? "接続申請 · 承認待ち "+visible.length+"件" : "申請の処理結果";
  $("request-alert-message").textContent=bannerFeedback;
  $("request-alert-message").hidden=!bannerFeedback;
  $("request-alert-message").dataset.state=bannerFeedbackState;
  const known=Boolean(control?.available && !control.error);
  const signature=JSON.stringify([visible,controlBusy,controlAuthorized,known]);
  if(signature===bannerSignature)return;
  bannerSignature=signature;
  const list=$("request-alert-list");list.replaceChildren();
  for(const item of visible){
    const row=document.createElement("article");row.className="banner-request";row.setAttribute("aria-label",item.node_name+"の接続申請");
    const content=document.createElement("div");content.className="banner-request-content";
    content.append(connectionLog(item));
    const actions=document.createElement("div");actions.className="banner-request-actions";
    for(const [action,label] of [["approve_request","承認"],["reject_request","却下"]]){
      const button=document.createElement("button");button.type="button";button.className=action==="approve_request" ? "banner-approve" : "banner-reject";button.textContent=label;
      button.disabled=controlBusy || !controlAuthorized || !known;
      button.setAttribute("aria-label",item.domains.join(", ")+"への申請を"+label);
      button.addEventListener("click",()=>decideBannerRequest(action,item.id));actions.append(button);
    }
    row.append(content,actions);list.append(row);
  }
  $("request-alert-auth").hidden=!visible.length || controlAuthorized;
}
async function decideBannerRequest(action,id){
  if(controlBusy || !controlAuthorized || !control?.available || control.error)return;
  bannerFeedback=action==="approve_request" ? "承認を反映しています…" : "却下を反映しています…";
  bannerFeedbackState="busy";
  const ok=await changeDomains(action,{id});
  if(ok){
    bannerFeedback=action==="approve_request" ? "" : "却下しました。"+(controlDemo ? "（試験表示・実通信なし）" : "");
    bannerFeedbackState=bannerFeedback ? "success" : "";
  }else{
    bannerFeedback=$("approval-message").textContent;
    bannerFeedbackState="error";
  }
  updateRequestBanner(control?.domain_requests || []);
}
function dismissRequestBanner() {
  alertRequestIds=[];bannerFeedback="";bannerSignature=null;$("request-alert").hidden=true;
  document.body.classList.remove("has-request-alert");
}
function renderRequestNotifications() {
  if (!control?.available || control.error) {
    document.querySelectorAll("#request-alert-list button").forEach(button=>{button.disabled=true;});
    bannerSignature=null;
    return;
  }
  const {pending, added} = requestNotifications.update(control.domain_requests || []);
  $("request-count").hidden = pending.length === 0;
  $("request-count").textContent = pending.length;
  $("request-count").setAttribute("aria-label", "承認待ち"+pending.length+"件");
  $("pending-summary").textContent = "承認待ち "+pending.length+"件";
  const nav = document.querySelector('[data-nav="approvals"]');
  nav.classList.toggle("has-requests", pending.length > 0);
  if (added.length) {
    alertRequestIds = pending.map(item=>item.id);
    bannerFeedback="";bannerFeedbackState="";
    try { requestSound.play(); } catch (_) { pendingChime=requestSound.enabled; soundUnavailable(); }
  }
  if(!pending.length)pendingChime=false;
  updateRequestBanner(pending);
}
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
  const pages = {monitor:"広域通信監視",sessions:"通信記録一覧",settings:"環境設定",analytics:"通信分析",approvals:"一時許可",audit:"監査ログ"};
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
  if(page==="approvals" || page==="monitor")loadApprovalNodes();
  if(page==="settings" && !nodeBusy && !nodeDirty)loadNodeSettings();
  auditView.setActive(page === "audit");
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
function gateSelection() {
  const nodeId=$("gate-target").value;
  const grant=(control?.domain_approvals || []).find(item=>item.node_id===nodeId);
  const full=control?.mode==="full" || (control?.enabled && !control?.mode);
  const remaining=nodeId ? full ? control.remaining_seconds : grant?.remaining_seconds : control?.mode==="restricted"
    ? (control.domain_approvals?.length ? Math.min(...control.domain_approvals.map(item=>item.remaining_seconds)) : null) : control?.remaining_seconds;
  return {nodeId,grant,full,remaining,enabled:nodeId ? Boolean(full || grant) : Boolean(control?.enabled)};
}
function renderGateTargets() {
  const signature=JSON.stringify(approvalNodes);
  if(signature===gateTargetSignature)return;
  gateTargetSignature=signature;
  const select=$("gate-target"),previous=select.value;
  select.replaceChildren(new Option("全デバイス",""));
  for(const node of approvalNodes)select.add(new Option(node.label+" / "+node.ip,node.id));
  if([...select.options].some(option=>option.value===previous))select.value=previous;
}
function renderGateTimer() {
  const known = control?.available && !control.error;
  const selected=gateSelection(),remaining=known && selected.enabled ? selected.remaining : null;
  const seconds = remaining == null ? null : Math.max(0, Math.ceil(remaining - (performance.now() - controlReceivedAt) / 1000));
  $("gate-timer").textContent = seconds !== null
    ? seconds > 0 ? `${selected.nodeId ? "残り" : control?.mode === "restricted" ? "次の期限まで" : "自動遮断まで"} ${Math.floor(seconds / 60)}分${String(seconds % 60).padStart(2,"0")}秒` : "期限到達・遮断状態を確認中"
    : "";
  $("gate-timer").hidden = seconds === null;
}
function renderControl() {
  renderGateTargets();
  const known = control && control.available && !control.error,selected=gateSelection();
  const restricted=selected.nodeId ? selected.grant && !selected.full : control?.mode==="restricted";
  const state = known ? restricted ? "restricted" : selected.enabled ? "online" : "offline" : "unknown";
  $("gate-panel").dataset.state=state;
  $("gate-panel").setAttribute("aria-busy",String(controlBusy));
  $("gate-state").textContent = !known ? "不明" : selected.nodeId && selected.full ? "全体開放中" : restricted
    ? selected.nodeId ? selected.grant.scope==="any" ? "全域許可" : "限定許可" : "個別許可" : selected.enabled ? "開放" : "閉塞";
  $("gate-state").className = "gate-state " + state;
  $("internet-toggle").disabled=controlBusy || !controlAuthorized || Boolean(selected.nodeId && (!known || selected.full));
  $("internet-toggle").setAttribute("aria-checked",String(Boolean(known && selected.enabled)));
  $("internet-toggle").setAttribute("aria-label",selected.nodeId ? "選択デバイスの対外接続" : "AIセグメントの対外接続");
  $("internet-toggle").title=controlBusy ? "変更中…" : !controlAuthorized ? "証明書付きHTTPSで接続してください" : selected.nodeId && selected.full ? "全体開放中です。時間ボタンで個別許可に切り替えます" : selected.enabled ? "接続を閉じる" : selected.nodeId ? "このデバイスを5分間全域許可" : "接続を開く";
  document.querySelectorAll("[data-duration]").forEach(button => { button.disabled=controlBusy || !controlAuthorized || Boolean(selected.nodeId && !known); });
  $("gate-target").disabled=controlBusy;
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
  renderApprovals();
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
  if(enabled && control?.mode === "restricted" && !window.confirm("ドメイン限定許可を破棄し、AIセグメント全体を開通します。続行しますか？"))return;
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
    [...(f.domain_hints || []).map(h => h.domain), ...(f.dns_questions || []).flatMap(q=>[q.name,q.type]), ...(f.dns_country_candidates || []).flatMap(c=>[c.address,countryText(c.country)]), f.dns_error, f.src, f.dst, f.sport, f.dport, f.proto, f.service, f.state, f.chain, direction(f), countryText(f.src_country), countryText(f.dst_country)].join(" ").toLowerCase().includes(search);
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
    if (tab === "drops" && f.dns_questions) {
      const query=document.createElement("small");query.className="endpoint-country";
      query.textContent="DNS: " + (f.dns_questions.map(q=>q.name+" / "+q.type).join(" · ") || f.dns_error || "内容不明");
      query.title=f.dns_reason === "direct-dns" ? "RabbitWallを経由しないDNSの直接通信を遮断" : "対外接続が閉じているためDNSを遮断";
      dstCell.append(query);
    }
    if (f.domain_hints?.length) {
      const hints = document.createElement("small"); hints.className = "endpoint-country";
      hints.textContent = "推定ドメイン: " + f.domain_hints.map(h => h.domain).join(" / ");
      hints.title = "同じ端末のDNS応答と宛先IPを照合した候補です。HTTPの接続先名を保証しません。";
      dstCell.append(hints);
      if (f.domain_hints.some(h => h.is_new)) dstCell.append(newDomainBadge());
    }
    const destinationCountry=cell(row, countryText(f.dst_country), "country");
    if(tab === "drops" && f.dns_questions) {
      const estimate=document.createElement("small");estimate.className="endpoint-country";
      const names=[...new Set((f.dns_country_candidates || []).filter(c=>c.country?.kind === "country").map(c=>countryText(c.country)))];
      estimate.textContent="DNS推定国: " + (names.join(" / ") || "地域不明");
      estimate.title="過去のDNS応答IPからの推定です。実際の問い合わせ先や現在の接続先の国ではありません。";
      destinationCountry.append(estimate);
    }
    cell(row, tab === "drops" ? f.proto : f.service + " / " + f.proto);
    const status = tab === "drops" ? f.chain + " DROP" : tab === "history" ? f.ended_at ? "観測終了" : "追跡中" : f.state;
    const td = cell(row, ""), badge = document.createElement("span"); badge.textContent = status;
    badge.className = "badge " + (tab === "drops" || status === "UNREPLIED" ? "warn" : status === "ESTABLISHED" ? "good" : ""); td.append(badge);
    cell(row, tab === "drops" ? (f.in || "—") + " → " + (f.out || "—") : bytes(f.tx_bytes) + " / " + bytes(f.rx_bytes), "mono");
    cell(row, clock(tab === "drops" ? f.time : tab === "history" ? f.last_seen : f.first_seen), "mono"); $("rows").append(row);
  }
  if (!rows.length) { const tr = document.createElement("tr"), td = cell(tr, "該当する通信はありません", "empty"); td.colSpan = 8; $("rows").append(tr); }
  $("table-note").textContent = tab === "drops"
    ? "直近5分・最大200件。FWの拒否ログとUDP DNS拒否の観測を表示します。DNSは問い合わせ名・種類を取得します。TCP DNSの内容は観測せず、遮断は維持します。レート制限やログのないルールによる拒否は含みません。"
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
  $("ranking-period").textContent = data ? "集計対象 " + timestampText(windowData?.available_since ?? data.since) + " 以降" : "収集サービスを更新してください";
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
$("internet-toggle").addEventListener("click", () => changeGate(Boolean(control?.available && !control.error && !gateSelection().enabled)));
$("gate-target").addEventListener("change",()=>{ $("control-message").textContent=gateSelection().nodeId ? gateSelection().full ? "時間を選ぶと全体開通を停止し、個別許可に切り替えます。" : "時間を選ぶと、このデバイスを全域許可します。" : ""; renderControl(); });
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
  const name = Object.hasOwn(window.SessionAtlas.themes,value) ? value : "green";
  document.documentElement.dataset.theme=name;
  $("color-scheme").value=name;
  atlas.setTheme(name);
  return name;
}
let savedTheme="green";
try { savedTheme=localStorage.getItem("rabbitwall-color-scheme") || "green"; } catch (_) {}
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
    for(const [key,title] of [["monitor","死活監視"],["allow_ssh","管理PCからSSH"],["allow_https","管理PCからHTTPS"],["allow_ping","管理PCからPing"]]){
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
  nodeDraft.push({id:"node-"+crypto.randomUUID().slice(0,8),label:"",ip:"",interface:nodeSettings.interfaces.find(entry=>entry.side==="AI").name,monitor:true,allow_ssh:false,allow_https:false,allow_ping:false});
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
    loadApprovalNodes();refreshControl();refresh();
  }catch(error){$("node-message").textContent="保存結果を確認してください："+error.message;}
  finally{nodeBusy=false;updateNodeButtons();}
});

document.querySelectorAll("[data-duration]").forEach(button => button.addEventListener("click", () => changeGate(true, Number(button.dataset.duration))));

setInterval(()=>{renderGateTimer();renderApprovalTimers();}, 1000);


async function loadApprovalNodes() {
  if(approvalNodesLoading)return;
  approvalNodesLoading=true;
  try {
    const response=await fetch("/api/nodes",{cache:"no-store",signal:AbortSignal.timeout(8000)});
    const data=await response.json();if(!response.ok)throw new Error(data.error || "ノードを取得できません");
    const select=$("approval-node"),previous=select.value;
    select.replaceChildren();
    const ai=data.settings.interfaces.find(item=>item.side==="AI")?.name;
    approvalNodes=data.settings.nodes.filter(node=>node.interface===ai);
    for(const node of approvalNodes){
      const option=document.createElement("option");option.value=node.id;option.textContent=node.label+" / "+node.ip;select.append(option);
    }
    if([...select.options].some(option=>option.value===previous))select.value=previous;
    $("approval-message").textContent=select.options.length ? "" : "環境設定でAI側ノードを登録してください。";
    renderGateTargets();renderControl();
  } catch(error){$("approval-message").textContent=error.message;}
  finally{approvalNodesLoading=false;}
}
function renderApprovals(){
  const known=control?.available && !control.error;
  renderRequestNotifications();
  document.querySelector('[data-page="approvals"]').dataset.state=known ? control.enabled ? "active" : "closed" : "unknown";
  $("approval-mode").textContent=!known ? "状態不明" : control.mode === "restricted" ? "個別許可" : control.enabled ? "開放" : "閉塞";
  $("approval-submit").disabled=controlBusy || !controlAuthorized || !$("approval-node").options.length;
  const items=control?.domain_requests || [];
  const signature=JSON.stringify([items,controlBusy,controlAuthorized]);
  if(signature!==requestListSignature){
    requestListSignature=signature;
    const requests=$("domain-request-list"),history=$("domain-request-history");requests.replaceChildren();history.replaceChildren();
    const labels={approved:"承認済み",rejected:"却下",ended:"終了"};
    for(const item of [...items].reverse()){
      const entry=document.createElement("article");entry.className="approval-entry request-entry";
      const main=document.createElement("div");main.className="approval-main";
      main.append(connectionLog(item,item.status==="pending" ? "" : (labels[item.status] || item.status)));entry.append(main);
      if(item.status==="pending"){
        const actions=document.createElement("div");actions.className="request-actions";
        for(const [action,label] of [["approve_request","承認"],["reject_request","却下"]]){
          const button=document.createElement("button");button.type="button";button.className=action==="approve_request" ? "primary" : "secondary";button.textContent=label;
          button.disabled=controlBusy || !controlAuthorized;
          button.addEventListener("click",()=>changeDomains(action,{id:item.id}));actions.append(button);
        }
        entry.append(actions);requests.append(entry);
      }else history.append(entry);
    }
    $("request-history").hidden=!history.children.length;
    $("request-history-summary").textContent="処理済み "+history.children.length+"件";
    if(!requests.children.length){const empty=document.createElement("p");empty.className="approval-empty";empty.textContent=known ? "承認待ちの申請はありません" : "申請を確認できません";requests.append(empty);}
  }
  const list=$("approval-list");
  const expanded=new Set([...list.querySelectorAll("details[open]")].map(detail=>detail.dataset.grantId));
  list.replaceChildren();
  for(const grant of control?.domain_approvals || []){
    const entry=document.createElement("article");entry.className="approval-entry grant-entry";
    const main=document.createElement("div");main.className="approval-main";
    main.append(connectionLog(grant));
    const detail=document.createElement("details"),summary=document.createElement("summary");summary.textContent=grant.scope==="any" ? "全域許可：公開IPv4のHTTP／HTTPS・NTP" : "接続先の状態";detail.dataset.grantId=grant.id;detail.open=expanded.has(grant.id);detail.append(summary);
    const records=document.createElement("ul");
    for(const record of grant.records || []){
      const line=document.createElement("li");line.textContent=record.domain+" → "+(record.addresses.length ? record.addresses.join(", ") : record.error || "DNSを確認中・通信は未許可");records.append(line);
    }
    const revoke=document.createElement("button");revoke.type="button";revoke.className="secondary";revoke.textContent="取消";
    revoke.disabled=controlBusy || !controlAuthorized;revoke.addEventListener("click",()=>changeDomains("revoke",{id:grant.id}));
    detail.append(records);main.append(detail);
    const actions=document.createElement("div");actions.className="grant-actions";
    const timer=document.createElement("span");timer.className="approval-countdown";timer.setAttribute("role","timer");timer.setAttribute("aria-live","off");
    timer.dataset.remaining=grant.remaining_seconds;timer.dataset.receivedAt=controlReceivedAt;
    timer.title="期限 "+new Date(grant.expires_at).toLocaleString("ja-JP",{hour12:false});
    actions.append(timer,revoke);entry.append(main,actions);list.append(entry);
  }
  if(!list.children.length){const empty=document.createElement("p");empty.className="approval-empty";empty.textContent="許可中の通信はありません";list.append(empty);}
  renderApprovalTimers();
}
function renderApprovalTimers(){
  document.querySelectorAll(".approval-countdown").forEach(timer=>{
    const seconds=window.remainingGrantSeconds(Number(timer.dataset.remaining),Number(timer.dataset.receivedAt),performance.now());
    timer.textContent=seconds===null ? "残り時間を確認中" : seconds===0 ? "期限到達 · 確認中" : "残り "+String(Math.floor(seconds/60)).padStart(2,"0")+":"+String(seconds%60).padStart(2,"0");
    timer.classList.toggle("ending",seconds!==null && seconds<=60);
  });
}
async function changeDomains(action,request){
  if(controlBusy)return;
  controlBusy=true;controlEpoch++;renderControl();$("approval-message").textContent="DNSとFirewallの許可を更新しています…";
  try {
    const response=await fetch("/api/domain-approvals",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action,request}),signal:AbortSignal.timeout(30000)});
    const data=await response.json();if(!response.ok)throw new Error(data.error || "操作に失敗しました");
    control=data.control;controlReceivedAt=performance.now();controlDemo=data.demo;
    $("approval-message").textContent=controlDemo ? "試験表示：実際の通信許可やDNS照会は行っていません。" : (action==="approve" || action==="approve_request") ? "一時許可を反映しました。" : action==="reject_request" ? "申請を却下しました。" : "許可を取り消しました。";
    return true;
  } catch(error){$("approval-message").textContent="結果を確認できません。再確認してください。"+error.message;return false;}
  finally{controlBusy=false;controlEpoch++;renderControl();}
}
async function changeGate(enabled,duration=300){
  const selected=gateSelection();
  if(!selected.nodeId)return setInternet(enabled,arguments.length>1 ? duration : null);
  if(controlBusy || !controlAuthorized || !control?.available || control.error)return;
  if(!enabled && selected.full)return;
  const ok=enabled ? await changeDomains("approve",{node_id:selected.nodeId,domains:["Any"],duration_seconds:duration,purpose:"手動：デバイスのインターネット接続"}) : selected.grant ? await changeDomains("revoke",{id:selected.grant.id}) : true;
  $("control-message").textContent=ok ? (controlDemo ? "試験表示 · " : "")+(enabled ? "このデバイスを全域許可しました。" : "このデバイスの許可を取り消しました。") : $("approval-message").textContent;
}
$("approval-any").addEventListener("click",()=>{$("approval-domains").value="Any";});
$("approval-form").addEventListener("submit",event=>{
  event.preventDefault();
  const domains=$("approval-domains").value.split(/\r?\n/).map(value=>value.trim()).filter(Boolean);
  changeDomains("approve",{node_id:$("approval-node").value,domains,duration_seconds:Number($("approval-duration").value),purpose:$("approval-purpose").value});
});

$("request-sound").addEventListener("click", async () => {
  if (requestSound.enabled) { requestSound.disable(); pendingChime=false; renderSoundButton(); return; }
  $("request-sound").disabled = true;
  try { await requestSound.enable(); pendingChime=false; renderSoundButton(); }
  catch (_) { soundUnavailable(); }
  finally { $("request-sound").disabled = false; }
});
let restoringAudio=false;
async function restoreRequestSound(){
  if(!requestSound.enabled || requestSound.ready || restoringAudio)return;
  restoringAudio=true;
  try {
    await requestSound.restore();
    if(pendingChime && requestSound.enabled){requestSound.play();pendingChime=false;}
  } catch (_) {} finally {restoringAudio=false;renderSoundButton();}
}
// Audio settings survive reloads; browsers may still require the next user gesture.
for(const eventName of ["pointerdown","keydown"])document.addEventListener(eventName,event=>{
  if(event.target.closest?.("#request-sound"))return;
  // A resume started during page load can remain pending until this gesture.
  if(requestSound.enabled && !requestSound.ready)requestSound.context?.resume().then(()=>{
    if(pendingChime && requestSound.enabled){requestSound.play();pendingChime=false;}
    renderSoundButton();
  }).catch(soundUnavailable);
});
renderSoundButton();
void restoreRequestSound();
$("request-alert-close").addEventListener("click", dismissRequestBanner);
$("approval-tips-open").addEventListener("click", () => { $("approval-tips").showModal(); });
$("approval-tips-close").addEventListener("click", () => { $("approval-tips").close(); });
$("approval-tips").addEventListener("click", event => {
  const bounds=$("approval-tips").getBoundingClientRect();
  if(event.target===$("approval-tips") && (event.clientX<bounds.left || event.clientX>bounds.right || event.clientY<bounds.top || event.clientY>bounds.bottom))$("approval-tips").close();
});
