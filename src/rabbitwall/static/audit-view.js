"use strict";
(function(root) {
  const labels = {
    "domain-request":"申請", "domain-approval":"許可", "domain-request-decision":"申請判断",
    "domain-revoke":"取消し", "domain-ended":"許可終了", "control-operation":"操作",
    "enable":"全体開通", "disable":"全体閉鎖", "save_nodes":"ノード保存",
    "gate-ended":"全体許可終了", "controller-starting":"起動開始", "controller-start":"起動",
    "controller-stopping":"停止開始", "controller-stop":"停止", "controller-failure":"制御障害"
  };
  const actions = {submit_domain_request:"申請",revoke_domain_request:"自己取消し",decide_domain_request:"申請判断",approve_domains:"許可",revoke_domain:"取消し",enable:"全体開通",disable:"全体閉鎖",save_nodes:"ノード保存"};
  const reasons = {expired:"期限切れ",replaced:"置換",cleared:"破棄","kernel-reload":"カーネル再読込"};
  const outcomes = {started:"開始",success:"成功",failure:"失敗",approve:"承認",reject:"却下"};
  function permissionEvent(entry) {
    return ["domain-request","domain-approval","domain-request-decision","domain-revoke","domain-ended","enable","disable","gate-ended"].includes(entry.event) ||
      (entry.event === "control-operation" && entry.outcome === "failure" && Object.hasOwn(actions,entry.action) && entry.action !== "save_nodes");
  }
  function eventLabel(entry) { return (labels[entry.event] || entry.event || "不明") + (entry.action ? " / " + (actions[entry.action] || entry.action) : ""); }
  function actorLabel(entry) { return ({agent:"エージェント",administrator:"管理者"})[entry.actor?.channel] || "システム"; }
  function matches(entry, query, event, failed) {
    if (!permissionEvent(entry)) return false;
    if (event && entry.event !== event) return false;
    if (failed && entry.outcome !== "failure" && entry.event !== "controller-failure") return false;
    return !query || (JSON.stringify(entry) + " " + eventLabel(entry) + " " + actorLabel(entry) + " " + (reasons[entry.reason] || "") + " " + (outcomes[entry.decision || entry.outcome] || "")).toLowerCase().includes(query.toLowerCase());
  }
  class AuditView {
    constructor() {
      this.entries=[]; this.active=false; this.busy=false; this.timer=null; this.loaded=false;
      this.$=id=>document.getElementById(id);
      this.$("audit-search").addEventListener("input",()=>this.render());
      this.$("audit-event").addEventListener("change",()=>this.render());
      this.$("audit-failed").addEventListener("change",()=>this.render());
      this.$("audit-refresh").addEventListener("click",()=>this.load());
    }
    setActive(active) {
      this.active=active;
      clearTimeout(this.timer);
      if (active) this.load();
    }
    async load() {
      if (this.busy) return;
      clearTimeout(this.timer);
      this.busy=true; this.$("audit-refresh").disabled=true;
      try {
        const response=await fetch("/api/audit",{cache:"no-store",signal:AbortSignal.timeout(8000)});
        const data=await response.json();
        if(!response.ok) throw new Error(data.error || "監査ログを取得できません。");
        this.entries=(data.audit.entries || []).filter(permissionEvent); this.loaded=true;
        const select=this.$("audit-event"), previous=select.value;
        select.replaceChildren(new Option("すべてのイベント",""));
        for (const event of [...new Set(this.entries.map(e=>e.event))].sort()) select.add(new Option(labels[event] || event,event));
        select.value=[...select.options].some(o=>o.value===previous) ? previous : "";
        this.$("audit-message").textContent= !data.audit.available ? "監査ログはまだ保存されていません。" :
          (data.demo ? "試験表示 · " : "") + "取得 " + new Date().toLocaleTimeString("ja-JP") + " · 直近最大200件" + (data.audit.limited ? "（取得範囲に上限あり）" : "");
        this.$("audit-message").dataset.state="ok";
        this.render();
      } catch(error) {
        this.$("audit-message").textContent=(this.loaded ? "表示内容は最新ではありません。" : "") + error.message;
        this.$("audit-message").dataset.state="error";
        if (!this.loaded) this.$("audit-rows").textContent="監査ログを表示できません。";
      } finally {
        this.busy=false; this.$("audit-refresh").disabled=false;
        if(this.active) this.timer=setTimeout(()=>this.load(),10000);
      }
    }
    render() {
      const rows=this.$("audit-rows");
      const expanded=new Set([...rows.querySelectorAll("details[open]")].map(node=>node.dataset.key));
      rows.replaceChildren();
      const entries=this.entries.filter(e=>matches(e,this.$("audit-search").value.trim(),this.$("audit-event").value,this.$("audit-failed").checked));
      this.$("audit-count").textContent=entries.length+" / "+this.entries.length+"件";
      for(const entry of entries) {
        const row=document.createElement("article"); row.className="audit-entry";
        if(entry.outcome==="failure" || entry.event==="controller-failure") row.classList.add("audit-failure");
        const primary=document.createElement("div"); primary.className="audit-primary";
        const field=(tag,value,cls)=>{const node=document.createElement(tag);node.className=cls || "";node.textContent=value;primary.append(node);};
        const date=new Date(entry.at);
        field("time",Number.isNaN(date.getTime()) ? (entry.at || "—") : date.toLocaleString("ja-JP",{hour12:false}),"audit-time");
        field("strong",eventLabel(entry),"audit-event");
        field("span",actorLabel(entry),"audit-actor");
        if(entry.source) field("span","Src: "+entry.source,"audit-source");
        if(entry.domains?.length) field("strong","Dst: "+entry.domains.join(", "),"audit-destination");
        if(entry.ports?.length) field("span","Port: "+entry.ports.map(({protocol,port})=>protocol.toUpperCase()+" "+port).join(", "),"audit-ports");
        if(entry.duration_seconds) field("span","Duration: "+entry.duration_seconds+"s");
        const result=outcomes[entry.decision || entry.outcome] || reasons[entry.reason] || entry.error_type;
        if(result) field("span",result,"audit-result");
        if(entry.purpose) field("span","目的: "+entry.purpose,"audit-purpose");
        row.append(primary);
        const details=document.createElement("details"),summary=document.createElement("summary"),pre=document.createElement("pre");
        details.dataset.key=JSON.stringify(entry); details.open=expanded.has(details.dataset.key);
        summary.textContent="記録詳細"+(entry.id ? " · "+entry.id : "");pre.textContent=JSON.stringify(entry,null,2);
        details.append(summary,pre);row.append(details);rows.append(row);
      }
      if(!entries.length) rows.textContent=this.entries.length ? "該当する記録はありません。" : "監査ログはまだありません。";
    }
  }
  if(typeof module!=="undefined" && module.exports) module.exports={matches,eventLabel,actorLabel};
  root.AuditView=AuditView;
})(typeof window!=="undefined" ? window : globalThis);
