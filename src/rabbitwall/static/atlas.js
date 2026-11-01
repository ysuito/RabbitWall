(function (root) {
  "use strict";
  const COLORS = {HTTPS:"#54e0bd", HTTP:"#54e0bd", DNS:"#a89cef", SSH:"#ffa42a", OTHER:"#7fa4d8", DROP:"#ff483e"};
  function endpointNode(ip, country, countries) {
    if (country?.kind === "private" || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) {
      return {key:"local:" + ip, kind:"local", ip, label:ip};
    }
    if (country?.code && countries[country.code]) {
      return {key:"country:" + country.code, kind:"country", code:country.code,
        label:countries[country.code].name, point:countries[country.code].point};
    }
    return {key:"unknown", kind:"unknown", label:"地域不明・特殊IP"};
  }
  function routeColor(flow, kind) {
    if (kind === "drops") return COLORS.DROP;
    return COLORS[flow.service] || COLORS[({443:"HTTPS", 80:"HTTP", 53:"DNS", 22:"SSH"})[flow.dport]] || COLORS.OTHER;
  }
  function byteLabel(value) {
    if (value == null) return "通信量不明";
    for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
      if (value < 1024 || unit === "TB") return value.toFixed(unit === "B" ? 0 : 1) + " " + unit;
      value /= 1024;
    }
  }
  function routeVisual(route, kind) {
    if (kind !== "history") return {width:Math.min(2.2,.8+Math.log2(route.count+1)*.35), particles:1, period:4200};
    // Logarithmic, fixed scale: 1 KB through 1 GB; cap drawing cost per route.
    const volume = Math.min(1, Math.log2(1+(route.totalBytes || 0)/1024)/20);
    return {width:.9+5.1*volume, particles:route.totalBytes > 0 ? 1+Math.floor(7*volume) : 0,
      period:4200/(1+1.5*volume)};
  }
  function groupFlows(flows, countries, kind = "flows", limit = 80) {
    const groups = new Map(), nodes = new Map();
    for (const flow of flows) {
      const src = endpointNode(flow.src, flow.src_country, countries), dst = endpointNode(flow.dst, flow.dst_country, countries);
      const service = flow.service || flow.proto;
      const key = JSON.stringify([src.key, dst.key, service, flow.proto, flow.dport || "", kind]);
      if (!groups.has(key)) groups.set(key, {key, src, dst, service, color:routeColor(flow, kind),
        count:0, totalBytes:null, flows:[], animate:kind !== "drops" && !flow.ended_at});
      const group = groups.get(key);
      group.count++; group.flows.push(flow);
      group.animate = group.animate || (kind !== "drops" && !flow.ended_at);
      const counters = [flow.tx_bytes,flow.rx_bytes].filter(value => Number.isFinite(value) && value >= 0);
      if (counters.length) group.totalBytes = (group.totalBytes || 0) + counters.reduce((sum,value)=>sum+value,0);
      if (kind === "history") group.animate = group.totalBytes > 0;
      nodes.set(src.key, src); nodes.set(dst.key, dst);
    }
    const all = [...groups.values()].sort((a,b) => (kind === "history" ? (b.totalBytes || 0) - (a.totalBytes || 0) : 0) || b.count - a.count || (b.totalBytes || 0) - (a.totalBytes || 0) || a.key.localeCompare(b.key));
    const visible = all.slice(0, limit), visibleNodes = new Map();
    for (const group of visible) { visibleNodes.set(group.src.key, group.src); visibleNodes.set(group.dst.key, group.dst); }
    return {routes:visible, nodes:[...visibleNodes.values()], totalRoutes:all.length, totalFlows:flows.length,
      countryCount:[...nodes.values()].filter(node => node.kind === "country").length};
  }
  function quadratic(a, b, c, t) { return {x:(1-t)*(1-t)*a.x + 2*(1-t)*t*b.x + t*t*c.x, y:(1-t)*(1-t)*a.y + 2*(1-t)*t*b.y + t*t*c.y}; }
  function hash(text) { let n=0; for (const c of text) n=(n*31+c.charCodeAt(0))>>>0; return n; }
  function wrapLongitude(longitude, center=160) { return ((longitude-center+180)%360+360)%360-180; }
  function projection(point, width, height) {
    const scale=Math.min((width-32)/360,(height-54)/180);
    return {x:width/2+wrapLongitude(point[0])*scale,y:height*.51-point[1]*scale};
  }
  function unwrapRing(ring, center=160) {
    let previous;
    return ring.map(([lon,lat]) => {
      let longitude=previous===undefined ? center+wrapLongitude(lon,center) : lon;
      if (previous!==undefined) {while(longitude-previous>180)longitude-=360;while(longitude-previous < -180)longitude+=360;}
      previous=longitude;return [longitude,lat];
    });
  }
  function pacificInset(width,height) {
    const anchor=projection([202,7],width,height);
    const boxWidth=Math.min(400,Math.max(330,width*.4),width-28);
    const boxHeight=Math.min(280,Math.max(220,height*.68),height-96);
    const minY=Math.min(100,Math.max(32,height-boxHeight-12));
    const minX=width>1100 ? 244 : 14, maxX=Math.max(minX,width-boxWidth-(width>1100 ? 250 : 14));
    return {x:Math.max(minX,Math.min(maxX,anchor.x-boxWidth/2)),
      y:Math.max(minY,Math.min(height-boxHeight-12,anchor.y-boxHeight*.35+38)),width:boxWidth,height:boxHeight};
  }
  function toggledSelection(current,key) { return current===key ? null : key; }

  class SessionAtlas {
    constructor(options) {
      this.canvas = options.canvas; this.ctx = this.canvas.getContext("2d");
      this.list = options.list; this.detail = options.detail; this.summary = options.summary;
      this.onInspect = options.onInspect; this.world = {features:[], countries:{}};
      this.onSelectionChange=options.onSelectionChange || (()=>{});
      this.rows = []; this.model = groupFlows([], {}); this.kind = "flows";
      this.active = false; this.paused = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      this.initialPaused=this.paused;
      this.offset={x:0,y:0};this.zoom=1;this.drag=null;this.panFrame=null;this.suppressClick=false;this.theme="amber";
      this.stale = false; this.selected = null; this.animation = null; this.points = new Map(); this.paths = [];
      this.background = document.createElement("canvas");
      this.observer = new ResizeObserver(() => this.resize()); this.observer.observe(this.canvas.parentElement);
      document.addEventListener("visibilitychange", () => this.schedule());
      this.canvas.addEventListener("click", event => {if(this.suppressClick){this.suppressClick=false;return;}this.pick(event);});
      this.canvas.addEventListener("wheel",event=>this.wheelZoom(event),{passive:false});
      this.canvas.addEventListener("pointerdown",event=>this.startPan(event));
      this.canvas.addEventListener("pointermove",event=>this.movePan(event));
      for(const type of ["pointerup","pointercancel","lostpointercapture"])this.canvas.addEventListener(type,event=>this.endPan(event));
      document.addEventListener("keydown",event=>{if(event.key==="Escape" && this.active)this.clearSelection();});
      fetch("/world.json", {cache:"force-cache"}).then(response => { if (!response.ok) throw new Error("map unavailable"); return response.json(); })
        .then(world => {
          if (!Array.isArray(world.features) || !world.countries || typeof world.countries !== "object") throw new Error("invalid map data");
          this.world = world; this.update(this.rows, {kind:this.kind, stale:this.stale});
        })
        .catch(() => { this.mapError = true; this.paintSummary(); this.draw(performance.now()); });
    }
    color(value) { return SessionAtlas.themes[this.theme]?.[value] || value; }
    setTheme(name) {
      this.theme=Object.hasOwn(SessionAtlas.themes,name) ? name : "amber";
      this.paintBackground();this.draw(performance.now());
    }
    resetPosition() {
      if(this.panFrame)cancelAnimationFrame(this.panFrame);
      this.panFrame=null;this.drag=null;this.offset={x:0,y:0};this.zoom=1;
      this.canvas.classList.remove("dragging");this.layout();this.draw(performance.now());
    }
    wheelZoom(event) {
      // Leave browser zoom shortcuts intact; the wheel controls only this map.
      if(event.ctrlKey || event.metaKey || this.drag || !this.width || !Number.isFinite(event.deltaY) || !event.deltaY)return;
      event.preventDefault();
      const previous=this.zoom || 1;
      const delta=event.deltaY*(event.deltaMode===1 ? 16 : event.deltaMode===2 ? this.height : 1);
      const zoom=Math.max(1,Math.min(6,previous*Math.exp(-Math.max(-500,Math.min(500,delta))*.002)));
      if(zoom===previous)return;
      const rect=this.canvas.getBoundingClientRect();
      const x=(event.clientX-rect.left)*this.width/rect.width;
      const y=(event.clientY-rect.top)*this.height/rect.height;
      this.offset={x:this.offset.x+x/zoom-x/previous,y:this.offset.y+y/zoom-y/previous};
      this.zoom=zoom;
      if(!this.panFrame)this.panFrame=requestAnimationFrame(()=>{this.panFrame=null;this.layout();this.draw(performance.now());});
    }
    startPan(event) {
      if(this.drag || event.isPrimary===false || event.button!==0)return;
      this.suppressClick=false;
      this.drag={id:event.pointerId,x:event.clientX,y:event.clientY,origin:{...this.offset},moved:false};
      this.canvas.setPointerCapture(event.pointerId);
    }
    movePan(event) {
      if(!this.drag || event.pointerId!==this.drag.id)return;
      const dx=event.clientX-this.drag.x,dy=event.clientY-this.drag.y;
      if(Math.hypot(dx,dy)>4)this.drag.moved=true;
      if(!this.drag.moved)return;
      this.offset={x:this.drag.origin.x+dx/(this.zoom || 1),y:this.drag.origin.y+dy/(this.zoom || 1)};
      this.canvas.classList.add("dragging");
      if(!this.panFrame)this.panFrame=requestAnimationFrame(()=>{this.panFrame=null;this.layout();this.draw(performance.now());});
    }
    endPan(event) {
      if(!this.drag || event.pointerId!==this.drag.id)return;
      this.suppressClick=this.drag.moved;
      this.drag=null;this.canvas.classList.remove("dragging");
      if(this.canvas.hasPointerCapture(event.pointerId))this.canvas.releasePointerCapture(event.pointerId);
    }
    setActive(active) { this.active = active; if (active) this.resize(); this.schedule(); }
    setPaused(paused) { this.paused = paused; this.schedule(); }
    update(rows, options = {}) {
      this.network = options.network || this.network || {hosts:[],site_label:"LAN拠点",site_location:[139,36]};
      this.rows = rows; this.kind = options.kind || "flows"; this.stale = Boolean(options.stale);
      this.model = groupFlows(rows, this.world.countries, this.kind);
      const hosts=this.network.hosts || [];
      for(const route of this.model.routes)for(const node of [route.src,route.dst]){
        if(node.kind==="local")node.label=hosts.find(host=>host.ips.includes(node.ip))?.label || node.ip;
      }
      if (!this.model.routes.some(route => route.key === this.selected)) this.selected = null;
      this.paintList(); this.paintDetail(); this.paintSummary(); this.layout();
      this.draw(performance.now()); this.schedule();
    }
    paintSummary() {
      const model = this.model;
      this.summary.textContent = `${({flows:"現況",history:"履歴",drops:"拒否"})[this.kind]} · ${model.totalFlows} 件 · ${model.countryCount} か国 · ${model.routes.length}/${model.totalRoutes} 経路` +
        (this.kind === "history" ? " · 線幅・光＝累積通信量" : "") + (this.stale ? " · 更新停止中" : "") + (this.mapError ? " · 地図データを読み込めません" : "");
    }
    paintList() {
      const focused=document.activeElement?.dataset?.routeKey;
      this.list.replaceChildren();
      for (const route of this.model.routes) {
        const button = document.createElement("button"); button.type="button";
        button.className = "atlas-route" + (route.key === this.selected ? " selected" : "");
        button.dataset.routeKey = route.key;
        button.setAttribute("aria-pressed", String(route.key === this.selected));
        const line = document.createElement("strong"), sub = document.createElement("small");
        line.textContent = route.src.label + " → " + route.dst.label;
        sub.textContent = `${route.service} · ${route.count} セッション` + (this.kind === "history" ? " · " + byteLabel(route.totalBytes) : "");
        const names = [...new Set(route.flows.flatMap(f => (f.domain_hints || []).map(h => h.domain)))];
        if (names.length) sub.textContent += " · 推定: " + names.slice(0, 2).join(" / ");
        if (route.flows.some(f => (f.domain_hints || []).some(h => h.is_new))) {
          const badge = document.createElement("span"); badge.className = "new-domain-badge";
          badge.textContent = "新"; badge.title = "初めて観測してから24時間以内のドメイン"; line.append(badge);
        }
        button.append(line, sub); button.addEventListener("click", () => this.select(route.key)); this.list.append(button);
        if (route.key === focused) button.focus({preventScroll:true});
      }
      if (!this.model.routes.length) { const empty=document.createElement("p"); empty.className="atlas-empty"; empty.textContent="該当するセッションはありません。"; this.list.append(empty); }
    }
    select(key) { this.selected=toggledSelection(this.selected,key); this.paintList(); this.paintDetail(); this.draw(performance.now()); }
    clearSelection() { this.selected=null;this.paintList();this.paintDetail();this.draw(performance.now()); }
    paintDetail() {
      this.detail.replaceChildren();
      const route = this.model.routes.find(item => item.key === this.selected);
      this.detail.hidden=!route;this.onSelectionChange(route?.key || null);
      if (!route) return;
      const title=document.createElement("strong"); title.textContent=route.src.label + " → " + route.dst.label; this.detail.append(title);
      if (this.kind === "history") {
        const volume=document.createElement("small"); volume.textContent="累積送受信量: " + byteLabel(route.totalBytes) + " / 線幅・光は対数スケールの演出";
        this.detail.append(volume);
      }
      for (const flow of route.flows.slice(0, 8)) {
        const line=document.createElement("code");
        line.textContent=`${flow.src}${flow.sport ? ":"+flow.sport : ""} → ${flow.dst}${flow.dport ? ":"+flow.dport : ""} · ${flow.state || flow.proto}`;
        this.detail.append(line);
        if (flow.domain_hints?.length) {
          const hint = document.createElement("small");
          hint.textContent = "推定ドメイン: " + flow.domain_hints.map(h => (h.is_new ? "【新】" : "") + h.domain).join(" / ");
          this.detail.append(hint);
        }
      }
      if (route.count > 8) { const remaining=document.createElement("small"); remaining.textContent=`ほか ${route.count-8} セッション`; this.detail.append(remaining); }
      const button=document.createElement("button"); button.className="export"; button.textContent="このIPを表で確認";
      button.addEventListener("click", () => this.onInspect(route.flows[0].dst)); this.detail.append(button);
    }
    resize() {
      const rect = this.canvas.parentElement.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      this.width = rect.width; this.height = rect.height;
      const scale = Math.min(window.devicePixelRatio || 1, 2);
      this.scale = scale; this.canvas.width = Math.round(rect.width * scale); this.canvas.height = Math.round(rect.height * scale);
      this.background.width=this.canvas.width; this.background.height=this.canvas.height;
      this.layout(); this.paintBackground(); this.draw(performance.now());
    }
    project(point) {
      const p=projection(point,this.width,this.height);
      return {x:p.x+this.offset.x,y:p.y+this.offset.y};
    }
    layout() {
      if (!this.width) return;
      this.points = new Map();
      this.inset=pacificInset(this.width,this.height);
      this.inset.x+=this.offset.x;this.inset.y+=this.offset.y;
      const configured=this.network?.hosts || [];
      const known=configured.slice(0,5);
      const extras=this.model.nodes.filter(node=>node.kind==="local" && !known.some(host=>host.ips.includes(node.ip)));
      const remaining=[...new Set([...configured.slice(5).flatMap(host=>host.ips),...extras.map(node=>node.ip)])];
      const hosts=[...known];
      if(remaining.length)hosts.push({label:`他${remaining.length}端点`,glyph:"他",ip:"",ips:remaining});
      if(hosts.length>4){
        this.inset.width=Math.min(400,this.width-28);
        this.inset.x=Math.min(this.inset.x,this.width-this.inset.width-14+this.offset.x);
      }
      const columns=hosts.length===4 && this.inset.height<210 && this.inset.width>=328 ? 4 : hosts.length>4 ? 3 : 2;
      this.hostColumns=columns;
      const rows=Math.ceil(hosts.length/columns);
      hosts.forEach((host,index)=>{
        const point={x:this.inset.x+this.inset.width*(index%columns+.5)/columns,
          y:this.inset.y+(rows===1 ? (this.inset.height<160 ? 49 : (this.inset.height+30)/2) :
            72+(this.inset.height-136)*Math.floor(index/columns)/(rows-1)),
          node:{...host,kind:"local",observed:this.model.nodes.some(node=>host.ips.includes(node.ip))}};
        for(const ip of host.ips)this.points.set("local:"+ip,point);
      });
      for (const node of this.model.nodes) {
        if (node.kind === "country") this.points.set(node.key, {...this.project(node.point), node});
        if (node.kind === "unknown") this.points.set(node.key, {
          x:this.inset.x>=160 ? this.inset.x-80 : this.inset.x+this.inset.width*.5,
          y:this.inset.x>=160 ? this.inset.y+this.inset.height-24 : this.inset.y+this.inset.height+40,node});
      }
      this.paths = this.model.routes.map(route => {
        const a=this.points.get(route.src.key), c=this.points.get(route.dst.key), distance=Math.hypot(a.x-c.x,a.y-c.y);
        const local=route.src.kind === "local" && route.dst.kind === "local";
        const lift=local ? Math.min(38,12+distance*.08) : Math.min(160,55+Math.log10(Number(route.flows[0].dport)||1)*20);
        return {route,a,c,b:{x:(a.x+c.x)/2, y:Math.max(17+this.offset.y,Math.min(a.y,c.y)-lift)}};
      });
      this.paintBackground();
    }
    paintBackground() {
      if (!this.width) return;
      const ctx=this.background.getContext("2d"), w=this.width,h=this.height;
      ctx.setTransform(this.scale,0,0,this.scale,0,0); ctx.clearRect(0,0,w,h);
      const ocean=ctx.createRadialGradient(w*.55,h*.32,0,w*.55,h*.32,w*.7);
      ocean.addColorStop(0,this.color("#0b2424")); ocean.addColorStop(1,this.color("#030908")); ctx.fillStyle=ocean; ctx.fillRect(0,0,w,h);
      const viewScale=this.scale*(this.zoom || 1);ctx.setTransform(viewScale,0,0,viewScale,0,0);
      ctx.strokeStyle=this.color("#1b3c37"); ctx.lineWidth=.5;
      for (let lon=-180;lon<=180;lon+=30) { const a=this.project([lon,90]),b=this.project([lon,-90]);ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke(); }
      const scale=Math.min((w-32)/360,(h-54)/180),worldWidth=scale*360;
      for (let lat=-90;lat<=90;lat+=30) { const y=this.project([160,lat]).y;ctx.beginPath();ctx.moveTo(w/2-worldWidth/2+this.offset.x,y);ctx.lineTo(w/2+worldWidth/2+this.offset.x,y);ctx.stroke(); }
      for (const feature of this.world.features) {
        ctx.beginPath();
        for (const polygon of feature.polygons) for (const ring of polygon) {
          const coordinates=unwrapRing(ring);
          for(const shift of [-worldWidth,0,worldWidth]){
            coordinates.forEach(([lon,lat],index)=>{const x=w/2+(lon-160)*scale+shift+this.offset.x,y=h*.51-lat*scale+this.offset.y;if(!index)ctx.moveTo(x,y);else ctx.lineTo(x,y);});ctx.closePath();
          }
        }
        ctx.fillStyle=this.color("#102c27"); ctx.fill("evenodd"); ctx.strokeStyle=this.color("#356653");ctx.lineWidth=.7;ctx.stroke();
      }
      const box=this.inset,site=this.project(this.network?.site_location || [139,36]);
      ctx.strokeStyle=this.color("#df8a36");ctx.lineWidth=1;ctx.setLineDash([4,6]);ctx.beginPath();ctx.moveTo(site.x,site.y);ctx.lineTo(box.x,box.y+16);ctx.stroke();ctx.setLineDash([]);
      {
        ctx.fillStyle=this.color("#fca132");ctx.beginPath();ctx.arc(site.x,site.y,3,0,Math.PI*2);ctx.fill();
        ctx.font="13px -apple-system,sans-serif";ctx.fillText(this.network?.site_label || "LAN拠点",site.x+9,site.y-8);
      }
      ctx.save();ctx.globalAlpha=this.theme==="white" ? .82 : .68;ctx.fillStyle=this.color("#07110fef");ctx.fillRect(box.x,box.y,box.width,box.height);ctx.restore();ctx.strokeStyle=this.color("#e58b2e");ctx.strokeRect(box.x,box.y,box.width,box.height);
      ctx.fillStyle=this.color("#ed9630");ctx.fillRect(box.x,box.y,box.width,30);ctx.fillStyle=this.color("#11100b");ctx.font="bold 14px -apple-system,sans-serif";ctx.fillText(this.network?.site_label || "LAN拠点",box.x+12,box.y+21);
      ctx.fillStyle=this.color("#92a593");ctx.font="12px -apple-system,sans-serif";ctx.fillText("LANノードの配置図",box.x+12,box.y+box.height-7);
    }
    draw(now) {
      if (!this.width || !this.active) return;
      const ctx=this.ctx;ctx.setTransform(1,0,0,1,0,0);ctx.clearRect(0,0,this.canvas.width,this.canvas.height);ctx.drawImage(this.background,0,0);
      const viewScale=this.scale*(this.zoom || 1);ctx.setTransform(viewScale,0,0,viewScale,0,0);
      const moving=!this.paused && !this.stale && !document.hidden;
      for (const path of this.paths) {
        const {route,a,b,c}=path, highlighted=!this.selected || this.selected===route.key;
        ctx.globalAlpha=highlighted ? .78 : .12;ctx.strokeStyle=this.color(route.color);
        const visual=routeVisual(route,this.kind);
        ctx.lineWidth=this.kind === "history" ? visual.width + (this.selected===route.key ? 1.3 : 0) : this.selected===route.key ? 2.2 : visual.width;
        ctx.shadowColor=this.color(route.color);ctx.shadowBlur=highlighted ? 5 : 0;
        ctx.setLineDash(this.kind === "drops" || !route.animate ? [3,5] : []);
        ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.quadraticCurveTo(b.x,b.y,c.x,c.y);ctx.stroke();ctx.setLineDash([]);
        if (moving && route.animate && highlighted) {
          for(let index=0;index<visual.particles;index++) {
            const t=((now/visual.period)+(hash(route.key)%1000)/1000+index/visual.particles)%1;
            const point=quadratic(a,b,c,t);ctx.globalAlpha=.95;ctx.fillStyle=this.color(route.color);ctx.shadowBlur=13;
            ctx.beginPath();ctx.arc(point.x,point.y,2.4,0,Math.PI*2);ctx.fill();
          }
        }
        const tip=quadratic(a,b,c,.76), prior=quadratic(a,b,c,.73),angle=Math.atan2(tip.y-prior.y,tip.x-prior.x);
        ctx.fillStyle=this.color(route.color);ctx.beginPath();ctx.moveTo(tip.x,tip.y);ctx.lineTo(tip.x-6*Math.cos(angle-.45),tip.y-6*Math.sin(angle-.45));ctx.lineTo(tip.x-6*Math.cos(angle+.45),tip.y-6*Math.sin(angle+.45));ctx.closePath();ctx.fill();
      }
      ctx.globalAlpha=1;ctx.shadowBlur=0;
      for (const point of new Set(this.points.values())) {
        const {node,x,y}=point;
        ctx.fillStyle=node.kind === "local" ? node.observed ? this.color("#ffb148") : this.color("#637b68") : node.kind === "unknown" ? this.color("#c5a671") : this.color("#63dfbb");
        const labelX=Math.max(65+this.offset.x,Math.min(this.width-65+this.offset.x,x));
        if(node.kind==="local"){
          const compact=this.inset.height<160;
          ctx.textAlign="center";
          if(!compact){ctx.strokeStyle=ctx.fillStyle;ctx.lineWidth=1;ctx.strokeRect(x-11,y-11,22,22);ctx.font="bold 16px -apple-system,sans-serif";ctx.fillText(node.glyph,x,y+5);}
          ctx.fillStyle=this.color("#bddfcb");ctx.font="14px -apple-system,sans-serif";let label=node.label;
          const maxWidth=this.inset.width/this.hostColumns-14;
          while(label.length>1 && ctx.measureText(label).width>maxWidth)label=label.endsWith("…") ? label.slice(0,-2)+"…" : label.slice(0,-1)+"…";
          ctx.fillText(label,labelX,y+(compact ? 2 : -19));
          ctx.font="13px ui-monospace,monospace";ctx.fillText(node.ip || "",labelX,y+(compact ? 20 : 23));
          if(node.secondaryIP)ctx.fillText(node.secondaryIP,labelX,y+(compact ? 35 : 39));
        }else{
          ctx.shadowColor=ctx.fillStyle;ctx.shadowBlur=8;ctx.beginPath();ctx.arc(x,y,3.4,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;
          ctx.strokeStyle=this.color("#53967a99");ctx.beginPath();ctx.arc(x,y,8,0,Math.PI*2);ctx.stroke();ctx.font="13px -apple-system,sans-serif";ctx.textAlign="center";ctx.fillStyle=this.color("#bddfcb");ctx.fillText(node.label,labelX,y-13);
        }
      }
      ctx.textAlign="left";
      if (!this.paths.length) {ctx.fillStyle=this.color("#7e9fae");ctx.font="12px -apple-system,sans-serif";ctx.textAlign="center";ctx.fillText("該当するセッションはありません",this.width/2,this.height*.42);ctx.textAlign="left";}
    }
    schedule() {
      if (this.animation) cancelAnimationFrame(this.animation);
      this.animation=null;
      if (!this.active || this.paused || this.stale || document.hidden || !this.model.routes.some(route => route.animate)) {this.draw(performance.now());return;}
      let last=0;
      const frame=now => {if(now-last>=33){this.draw(now);last=now;}this.animation=requestAnimationFrame(frame);};
      this.animation=requestAnimationFrame(frame);
    }
    pick(event) {
      const rect=this.canvas.getBoundingClientRect(),zoom=this.zoom || 1;
      const point={x:(event.clientX-rect.left)*this.width/rect.width/zoom,y:(event.clientY-rect.top)*this.height/rect.height/zoom};
      let selected=null,nearest=13/zoom;
      for (const path of this.paths) for (let t=0;t<=1;t+=.025) {
        const p=quadratic(path.a,path.b,path.c,t),distance=Math.hypot(p.x-point.x,p.y-point.y);
        if(distance<nearest){nearest=distance;selected=path.route.key;}
      }
      this.select(selected);
    }
  }
  SessionAtlas.themes={
    amber:{},
    cyan:{"#0b2424":"#0a2035","#030908":"#030b17","#1b3c37":"#18394e","#102c27":"#112c42","#356653":"#326682","#07110fef":"#061322ef","#df8a36":"#3eafdb","#fca132":"#67d5ff","#e58b2e":"#49b9e5","#ed9630":"#5bc6eb","#ffb148":"#82ddff","#92a593":"#8faec5","#637b68":"#637d92","#8eac93":"#8fb1c9"},
    violet:{"#0b2424":"#21152e","#030908":"#090613","#1b3c37":"#382b4d","#102c27":"#291e3b","#356653":"#69527d","#07110fef":"#140c20ef","#df8a36":"#ac79dd","#fca132":"#d0a0ff","#e58b2e":"#b380eb","#ed9630":"#ba8cf0","#ffb148":"#d3a9ff","#92a593":"#b0a0c2","#637b68":"#7e6c90","#8eac93":"#b49cc8"}
  };
  SessionAtlas.themes.green={"#0b2424":"#0c2b19","#030908":"#030c07","#1b3c37":"#1c452d","#102c27":"#123a25","#356653":"#3a7950","#07110fef":"#06170cef","#df8a36":"#60bd80","#fca132":"#91f0ad","#e58b2e":"#6ac58b","#ed9630":"#7cdda0","#ffb148":"#a0f1b7","#92a593":"#9fbaaa","#637b68":"#668771","#8eac93":"#9abd9e"};
  SessionAtlas.themes.blue={"#0b2424":"#102845","#030908":"#040a18","#1b3c37":"#263e61","#102c27":"#182f50","#356653":"#446b9b","#07110fef":"#081426ef","#df8a36":"#71a0ed","#fca132":"#a6c7ff","#e58b2e":"#81adf3","#ed9630":"#8db9ff","#ffb148":"#b6d2ff","#92a593":"#a7b7cf","#637b68":"#7085a6","#8eac93":"#a4bbdb"};
  SessionAtlas.themes.red={"#0b2424":"#35151e","#030908":"#10060b","#1b3c37":"#502633","#102c27":"#3e1d2a","#356653":"#824758","#07110fef":"#1c0a12ef","#df8a36":"#dc7b94","#fca132":"#ffadc2","#e58b2e":"#ed8da6","#ed9630":"#f59ab0","#ffb148":"#ffbed0","#92a593":"#c7a6ae","#637b68":"#906976","#8eac93":"#cfadb7"};
  SessionAtlas.themes.white={"#0b2424":"#f7fbfd","#030908":"#e7eff3","#1b3c37":"#ccdbe1","#102c27":"#d5e3e7","#356653":"#95b2bd","#07110fef":"#ffffffef","#df8a36":"#567b90","#fca132":"#285e7f","#e58b2e":"#50798c","#ed9630":"#315e76","#ffb148":"#24556e","#92a593":"#516c7a","#637b68":"#6f828c","#8eac93":"#496776","#11100b":"#ffffff","#53967a99":"#528e8099","#63dfbb":"#187c65","#7e9fae":"#526774","#bddfcb":"#254b59","#c5a671":"#805b28","#54e0bd":"#187c65","#a89cef":"#7050a8","#ffa42a":"#a35b0c","#7fa4d8":"#416b9c","#ff483e":"#b92f38"};
  root.SessionAtlas = SessionAtlas;
  if (typeof module !== "undefined" && module.exports) module.exports = {routeVisual,byteLabel,endpointNode,groupFlows,quadratic,routeColor,projection,unwrapRing,pacificInset,toggledSelection,SessionAtlas};
})(typeof window !== "undefined" ? window : globalThis);
