(function (root) {
  "use strict";
  const SphereMap=root.SphereMap || (typeof require!=="undefined" ? require("./globe.js") : null);
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
      const src = endpointNode(flow.src, flow.src_country, countries);
      const targets = new Map();
      if (kind === "drops" && flow.dns_questions) {
        for(const candidate of flow.dns_country_candidates || []) {
          const country=candidate.country;
          if(country?.kind !== "country" || !countries[country.code])continue;
          const node=endpointNode(candidate.address,country,countries);
          node.key="dns-"+node.key;node.label+="（DNS推定）";node.dnsInferred=true;
          targets.set(node.key,node);
        }
        if(!targets.size)targets.set("unknown",endpointNode("",null,countries));
      } else {
        const dst=endpointNode(flow.dst,flow.dst_country,countries);targets.set(dst.key,dst);
      }
      for(const dst of targets.values()) {
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
    }
    const all = [...groups.values()].sort((a,b) => (kind === "history" ? (b.totalBytes || 0) - (a.totalBytes || 0) : 0) || b.count - a.count || (b.totalBytes || 0) - (a.totalBytes || 0) || a.key.localeCompare(b.key));
    const visible = all.slice(0, limit), visibleNodes = new Map();
    for (const group of visible) { visibleNodes.set(group.src.key, group.src); visibleNodes.set(group.dst.key, group.dst); }
    return {routes:visible, nodes:[...visibleNodes.values()], totalRoutes:all.length, totalFlows:flows.length,
      countryCount:new Set([...nodes.values()].filter(node => node.kind === "country").map(node=>node.code)).size};
  }
  function quadratic(a, b, c, t) { return {x:(1-t)*(1-t)*a.x + 2*(1-t)*t*b.x + t*t*c.x, y:(1-t)*(1-t)*a.y + 2*(1-t)*t*b.y + t*t*c.y}; }
  function routeDomains(route) {
    return [...new Set(route.flows.flatMap(flow => [
      ...(flow.domain_hints || []).map(hint=>hint.domain),
      ...(flow.dns_questions || []).map(question=>question.name)
    ]).filter(name=>typeof name==="string").map(name=>name.trim().replace(/\.$/,"").toLowerCase()).filter(Boolean))].sort();
  }
  function intersects(a,b,gap=0) {
    return a.x < b.x+b.width+gap && a.x+a.width+gap > b.x && a.y < b.y+b.height+gap && a.y+a.height+gap > b.y;
  }
  function placeRouteLabels(paths, {width,height,zoom=1,obstacles=[],measureText=text=>text.length*7,selected=null}) {
    const occupied=[...obstacles],labels=[];
    const ranked=[...paths].sort((a,b)=>Number(b.route.key===selected)-Number(a.route.key===selected));
    for(const path of ranked) {
      if(labels.length>=16)break;
      if(path.route.src.kind==="local" && path.route.dst.kind==="local")continue;
      const names=routeDomains(path.route);
      if(!names.length)continue;
      const maxWidth=Math.min(230,width-32);
      const lines=names.slice(0,5).map((name,index)=>{
        const suffix=index===4 && names.length>5 ? " +"+(names.length-5) : "";
        let shortened=name;
        while(shortened.length>1 && measureText(shortened+(shortened!==name ? "…" : "")+suffix)+16>maxWidth)shortened=shortened.slice(0,-1);
        return shortened+(shortened!==name ? "…" : "")+suffix;
      });
      const text=lines.join("\n"),labelHeight=lines.length*18+6;
      const labelWidth=Math.max(...lines.map(line=>measureText(line)))+16;
      if(labelWidth>maxWidth)continue;
      let placed=null;
      for(const t of [.62,.48,.76,.34,.86,.22]) {
        const point=quadratic(path.a,path.b,path.c,t);
        const dx=2*((1-t)*(path.b.x-path.a.x)+t*(path.c.x-path.b.x));
        const dy=2*((1-t)*(path.b.y-path.a.y)+t*(path.c.y-path.b.y)),length=Math.hypot(dx,dy)||1;
        for(const offset of [-16,16,-32,32]) {
          const anchor={x:point.x*zoom,y:point.y*zoom};
          const rect={x:anchor.x-dy/length*offset-labelWidth/2,y:anchor.y+dx/length*offset-labelHeight/2,width:labelWidth,height:labelHeight};
          if(rect.x<8 || rect.y<8 || rect.x+rect.width>width-8 || rect.y+rect.height>height-8 || occupied.some(box=>intersects(rect,box,5)))continue;
          placed={key:path.route.key,route:path.route,text,lines,rect,anchor};break;
        }
        if(placed)break;
      }
      if(placed){labels.push(placed);occupied.push(placed.rect);}
    }
    return labels;
  }
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
      this.globeMode=true;this.rotating=!this.paused;this.longitude=30;this.latitude=15;this.spherePolygons=[];
      this.offset={x:0,y:0};this.zoom=1;this.drag=null;this.panFrame=null;this.suppressClick=false;this.theme="green";
      this.restoreGlobeView();
      this.stale = false; this.selected = null; this.animation = null; this.points = new Map(); this.paths = []; this.routeLabels=[];
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
          this.spherePolygons=world.features.map(feature=>feature.polygons.map(polygon=>polygon.map(ring=>ring.map(SphereMap.vector))));
          this.paintBackground();this.draw(performance.now());
        })
        .catch(() => { this.mapError = true; this.paintSummary(); this.draw(performance.now()); });
    }
    color(value) { return SessionAtlas.themes[this.theme]?.[value] || value; }
    restoreGlobeView() {
      try {
        const view=JSON.parse(window.localStorage.getItem("rabbitwall-globe-view"));
        if(!view || ![view.longitude,view.latitude,view.zoom,view.offset?.x,view.offset?.y].every(Number.isFinite))return;
        if(Math.abs(view.latitude)>60 || view.zoom<1 || view.zoom>6)return;
        this.longitude=wrapLongitude(view.longitude,0);
        this.latitude=view.latitude;
        this.zoom=view.zoom;
        this.offset={x:view.offset.x,y:view.offset.y};
      } catch (_) {}
    }
    saveGlobeView() {
      if(!this.globeMode)return;
      const {longitude,latitude,zoom,offset}=this;
      try {
        window.localStorage.setItem("rabbitwall-globe-view",JSON.stringify({longitude,latitude,zoom,offset}));
      } catch (_) {}
    }
    setTheme(name) {
      this.theme=Object.hasOwn(SessionAtlas.themes,name) ? name : "green";
      this.paintBackground();this.draw(performance.now());
    }
    resetPosition() {
      if(this.panFrame)cancelAnimationFrame(this.panFrame);
      this.panFrame=null;this.drag=null;this.offset={x:0,y:0};this.zoom=1;
      this.longitude=30;this.latitude=15;
      this.saveGlobeView();
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
      this.saveGlobeView();
      if(!this.panFrame)this.panFrame=requestAnimationFrame(()=>{this.panFrame=null;this.layout();this.draw(performance.now());});
    }
    startPan(event) {
      if(this.drag || event.isPrimary===false || event.button!==0)return;
      this.suppressClick=false;
      this.drag={id:event.pointerId,x:event.clientX,y:event.clientY,origin:{...this.offset},moved:false,
        rotate:Boolean(this.globeMode && !event.shiftKey),longitude:this.longitude,latitude:this.latitude};
      this.canvas.setPointerCapture(event.pointerId);
    }
    movePan(event) {
      if(!this.drag || event.pointerId!==this.drag.id)return;
      const dx=event.clientX-this.drag.x,dy=event.clientY-this.drag.y;
      if(Math.hypot(dx,dy)>4)this.drag.moved=true;
      if(!this.drag.moved)return;
      if(this.drag.rotate) {
        const radius=Math.max(40,this.sphereScene?.radius || 100)*(this.zoom || 1);
        this.longitude=this.drag.longitude-dx/radius*70;
        this.latitude=Math.max(-60,Math.min(60,this.drag.latitude+dy/radius*50));
      } else this.offset={x:this.drag.origin.x+dx/(this.zoom || 1),y:this.drag.origin.y+dy/(this.zoom || 1)};
      this.canvas.classList.add("dragging");
      if(!this.panFrame)this.panFrame=requestAnimationFrame(()=>{this.panFrame=null;this.layout();this.draw(performance.now());});
    }
    endPan(event) {
      if(!this.drag || event.pointerId!==this.drag.id)return;
      this.suppressClick=this.drag.moved;
      if(this.drag.moved)this.saveGlobeView();
      this.drag=null;this.canvas.classList.remove("dragging");
      if(this.canvas.hasPointerCapture(event.pointerId))this.canvas.releasePointerCapture(event.pointerId);
    }
    setActive(active) { this.active = active; if (active) this.resize(); this.schedule(); }
    setPaused(paused) { this.paused = paused; this.schedule(); }
    setGlobeMode(enabled) { this.globeMode=enabled;this.layout();this.draw(performance.now());this.schedule(); }
    setRotating(enabled) { this.rotating=enabled;this.schedule(); }
    canSpin() { return Boolean(this.active && this.globeMode && this.rotating && !this.drag && !this.selected && !this.stale && (typeof document==="undefined" || !document.hidden)); }
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
        const queries = [...new Set(route.flows.flatMap(f => (f.dns_questions || []).map(q => q.name + " / " + q.type)))];
        if (queries.length) sub.textContent += " · DNS問: " + queries.slice(0, 2).join(" / ");
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
    select(key) {
      this.selected=toggledSelection(this.selected,key);
      const route=this.model?.routes?.find(item=>item.key===this.selected),target=[route?.dst,route?.src].find(node=>node?.kind==="country");
      if(this.globeMode && target){this.longitude=target.point[0];this.latitude=Math.max(-60,Math.min(60,target.point[1]));this.layout();}
      this.paintList();this.paintDetail();this.layoutLabels();this.draw(performance.now());this.schedule();
    }
    clearSelection() { this.selected=null;this.paintList();this.paintDetail();this.layoutLabels();this.draw(performance.now());this.schedule(); }
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
        if (flow.dns_questions) {
          const query = document.createElement("small");
          query.textContent = "DNS問い合わせ: " + (flow.dns_questions.map(q => q.name + " / " + q.type).join(" · ") || flow.dns_error || "内容不明");
          this.detail.append(query);
          const addresses=(flow.dns_country_candidates || []).filter(candidate=>!route.dst.code || candidate.country?.code===route.dst.code);
          for(const candidate of addresses.slice(0,4)) {
            const evidence=document.createElement("small");
            evidence.textContent=`過去のDNS応答: ${candidate.domain} → ${candidate.address} / ${new Date(candidate.observed_at*1000).toLocaleString("ja-JP")}`;
            this.detail.append(evidence);
          }
        }
        if (flow.domain_hints?.length) {
          const hint = document.createElement("small");
          hint.textContent = "推定ドメイン: " + flow.domain_hints.map(h => (h.is_new ? "【新】" : "") + h.domain).join(" / ");
          this.detail.append(hint);
        }
      }
      if (route.count > 8) { const remaining=document.createElement("small"); remaining.textContent=`ほか ${route.count-8} セッション`; this.detail.append(remaining); }
      const button=document.createElement("button"); button.className="export";
      const question=route.flows[0].dns_questions?.[0]?.name;
      button.textContent=question ? "このDNS問い合わせを表で確認" : "このIPを表で確認";
      button.addEventListener("click", () => this.onInspect(question || route.flows[0].dst)); this.detail.append(button);
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
      const p=this.globeMode ? SphereMap.project(point,this.sphereScene,SphereMap.camera(this.longitude,this.latitude)) : projection(point,this.width,this.height);
      return {...p,x:p.x+this.offset.x,y:p.y+this.offset.y};
    }
    layout() {
      if (!this.width) return;
      this.points = new Map();
      this.sphereScene=this.globeMode ? SphereMap.scene(this.width,this.height) : null;
      this.inset=this.globeMode ? {...this.sphereScene.inset} : pacificInset(this.width,this.height);
      this.inset.x+=this.offset.x;this.inset.y+=this.offset.y;
      const configured=this.network?.hosts || [];
      const known=configured.slice(0,5);
      const extras=this.model.nodes.filter(node=>node.kind==="local" && !known.some(host=>host.ips.includes(node.ip)));
      const remaining=[...new Set([...configured.slice(5).flatMap(host=>host.ips),...extras.map(node=>node.ip)])];
      const hosts=[...known];
      if(remaining.length)hosts.push({label:`他${remaining.length}端点`,glyph:"他",ip:"",ips:remaining});
      if(hosts.length>4 && !this.globeMode){
        this.inset.width=Math.min(400,this.width-28);
        this.inset.x=Math.min(this.inset.x,this.width-this.inset.width-14+this.offset.x);
      }
      const columns=this.globeMode ? hosts.length>4 ? 3 : 2 : hosts.length===4 && this.inset.height<210 && this.inset.width>=328 ? 4 : hosts.length>4 ? 3 : 2;
      this.hostColumns=columns;
      const rows=Math.ceil(hosts.length/columns);
      hosts.forEach((host,index)=>{
        const point={x:this.inset.x+this.inset.width*(index%columns+.5)/columns,
          y:this.inset.y+(this.globeMode ? this.inset.height<180 ? 43+(this.inset.height-58)*Math.floor(index/columns)/rows : 32+(this.inset.height-52)*(Math.floor(index/columns)+.5)/rows : rows===1 ? (this.inset.height<160 ? 49 : (this.inset.height+30)/2) :
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
        return {route,a,c,hidden:a.visible===false || c.visible===false,b:{x:(a.x+c.x)/2, y:Math.max((this.globeMode ? 88 : 17)+this.offset.y,Math.min(a.y,c.y)-lift)}};
      });
      this.layoutLabels();
      this.paintBackground();
    }
    layoutLabels() {
      if(!this.ctx?.measureText || !this.width)return;
      const zoom=this.zoom || 1,ctx=this.ctx;
      const obstacles=[{x:0,y:0,width:this.width,height:88}];
      if(this.inset)obstacles.push({x:this.inset.x*zoom,y:this.inset.y*zoom,width:this.inset.width*zoom,height:this.inset.height*zoom});
      ctx.save();ctx.font="13px -apple-system,sans-serif";
      const selectedRoute=this.model.routes.find(route=>route.key===this.selected),focused=selectedRoute?.dst.key;
      const countries=[...new Set(this.points.values())].sort((a,b)=>Number(b.node.key===focused)-Number(a.node.key===focused));
      const countryBoxes=[];this.countryLabelKeys=new Set();
      for(const point of countries) {
        if(point.node.kind==="local" || point.visible===false)continue;
        const x=Math.max(65+this.offset.x,Math.min(this.width-65+this.offset.x,point.x))*zoom;
        const width=Math.max(24,ctx.measureText(point.node.label).width+12)*zoom;
        const box={x:x-width/2,y:(point.y-31)*zoom,width,height:44*zoom};
        if(this.globeMode && (box.y<88 || countryBoxes.some(other=>intersects(box,other,3))))continue;
        this.countryLabelKeys.add(point.node.key);countryBoxes.push(box);obstacles.push(box);
      }
      const site=this.project(this.network?.site_location || [139,36]);
      if(site.visible!==false)obstacles.push({x:site.x*zoom-5,y:site.y*zoom-24,width:(ctx.measureText(this.network?.site_label || "LAN拠点").width+24)*zoom,height:30*zoom});
      ctx.font="12px ui-monospace,monospace";
      this.routeLabels=placeRouteLabels(this.paths.filter(path=>!path.hidden),{width:this.width,height:this.height,zoom,obstacles,selected:this.selected,measureText:text=>ctx.measureText(text).width});
      ctx.restore();
    }
    paintBackground() {
      if (!this.width) return;
      if(this.globeMode){this.paintGlobeBackground();return;}
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
      this.paintInset(ctx);
    }
    paintInset(ctx) {
      const box=this.inset,site=this.project(this.network?.site_location || [139,36]);
      if(site.visible!==false) {
        ctx.fillStyle=this.color("#fca132");ctx.beginPath();ctx.arc(site.x,site.y,3,0,Math.PI*2);ctx.fill();
        ctx.font="13px -apple-system,sans-serif";ctx.fillText(this.network?.site_label || "LAN拠点",site.x+9,site.y-8);
      }
      ctx.save();ctx.shadowColor=this.color("#63dfbb");ctx.shadowBlur=this.globeMode ? 16 : 0;
      ctx.globalAlpha=this.globeMode ? .94 : this.theme==="white" ? .82 : .68;ctx.fillStyle=this.color("#07110fef");ctx.fillRect(box.x,box.y,box.width,box.height);ctx.restore();ctx.strokeStyle=this.color("#e58b2e");ctx.strokeRect(box.x,box.y,box.width,box.height);
      ctx.fillStyle=this.color("#ed9630");ctx.fillRect(box.x,box.y,box.width,30);ctx.fillStyle=this.color("#11100b");ctx.font="bold 14px -apple-system,sans-serif";ctx.fillText(this.network?.site_label || "LAN拠点",box.x+12,box.y+21);
      ctx.fillStyle=this.color("#92a593");ctx.font="12px -apple-system,sans-serif";ctx.fillText(this.globeMode ? "LANセグメント · 手前" : "LANノードの配置図",box.x+12,box.y+box.height-7);
    }
    paintGlobeBackground() {
      const ctx=this.background.getContext("2d"),w=this.width,h=this.height;
      ctx.setTransform(this.scale,0,0,this.scale,0,0);ctx.clearRect(0,0,w,h);
      ctx.fillStyle=this.color("#030908");ctx.fillRect(0,0,w,h);
      const viewScale=this.scale*(this.zoom || 1);ctx.setTransform(viewScale,0,0,viewScale,0,0);
      const scene=this.sphereScene,cx=scene.x+this.offset.x,cy=scene.y+this.offset.y,r=scene.radius;
      const view=SphereMap.camera(this.longitude,this.latitude);
      ctx.save();ctx.strokeStyle=this.color("#1b3c37");ctx.lineWidth=1;ctx.setLineDash([2,7]);
      ctx.beginPath();ctx.ellipse(cx,cy+r*.84,r*1.12,r*.16,0,0,Math.PI*2);ctx.stroke();ctx.restore();
      const ocean=ctx.createRadialGradient(cx-r*.35,cy-r*.4,r*.08,cx,cy,r*1.05);
      ocean.addColorStop(0,this.color("#0b2424"));ocean.addColorStop(1,this.color("#030908"));
      ctx.save();ctx.shadowColor=this.color("#63dfbb");ctx.shadowBlur=22;ctx.fillStyle=ocean;
      ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.fill();ctx.restore();
      ctx.save();ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.clip();
      ctx.fillStyle=this.color("#102c27");ctx.strokeStyle=this.color("#356653");ctx.lineWidth=.65;
      for(const feature of this.spherePolygons || []) {
        ctx.beginPath();
        for(const polygon of feature)for(const ring of polygon) {
          const points=SphereMap.clipRing(ring.map(v=>SphereMap.rotate(v,view)));
          if(points.length<3)continue;
          points.forEach((point,index)=>{const x=cx+r*point.x,y=cy-r*point.y;if(!index)ctx.moveTo(x,y);else ctx.lineTo(x,y);});ctx.closePath();
        }
        ctx.fill("evenodd");ctx.stroke();
      }
      ctx.save();ctx.globalAlpha=.45;ctx.strokeStyle=this.color("#356653");ctx.lineWidth=.55;
      for(const line of SphereMap.grid) {
        ctx.beginPath();let started=false;
        for(const vertex of line) {
          const point=SphereMap.rotate(vertex,view);
          if(point.z<0){started=false;continue;}
          if(!started)ctx.moveTo(cx+r*point.x,cy-r*point.y);else ctx.lineTo(cx+r*point.x,cy-r*point.y);
          started=true;
        }
        ctx.stroke();
      }
      ctx.restore();
      const shade=ctx.createLinearGradient(cx-r*.7,cy-r*.8,cx+r,cy+r*.8);
      shade.addColorStop(0,"rgba(255,255,255,.1)");shade.addColorStop(.4,"rgba(0,0,0,0)");shade.addColorStop(1,"rgba(0,0,0,.65)");
      ctx.fillStyle=shade;ctx.fillRect(cx-r,cy-r,r*2,r*2);ctx.restore();
      ctx.strokeStyle=this.color("#53967a99");ctx.lineWidth=1.3;ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.stroke();
      this.paintInset(ctx);
    }
    draw(now) {
      if (!this.width || !this.active) return;
      const ctx=this.ctx;ctx.setTransform(1,0,0,1,0,0);ctx.clearRect(0,0,this.canvas.width,this.canvas.height);ctx.drawImage(this.background,0,0);
      const viewScale=this.scale*(this.zoom || 1);ctx.setTransform(viewScale,0,0,viewScale,0,0);
      const moving=!this.paused && !this.stale && !document.hidden;
      for (const path of this.paths) {
        if(path.hidden)continue;
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
      ctx.save();ctx.setTransform(this.scale,0,0,this.scale,0,0);ctx.font="12px ui-monospace,monospace";ctx.textAlign="left";ctx.textBaseline="middle";
      for(const label of this.routeLabels || []) {
        const {rect,anchor,route}=label;
        ctx.globalAlpha=!this.selected || this.selected===route.key ? 1 : .25;
        ctx.strokeStyle=this.color(route.color);ctx.lineWidth=this.selected===route.key ? 1.2 : .7;
        ctx.beginPath();ctx.moveTo(anchor.x,anchor.y);ctx.lineTo(Math.max(rect.x,Math.min(rect.x+rect.width,anchor.x)),Math.max(rect.y,Math.min(rect.y+rect.height,anchor.y)));ctx.stroke();
        ctx.fillStyle=this.color("#07110fef");ctx.fillRect(rect.x,rect.y,rect.width,rect.height);ctx.strokeRect(rect.x,rect.y,rect.width,rect.height);
        ctx.fillStyle=this.color(route.color);label.lines.forEach((line,index)=>ctx.fillText(line,rect.x+8,rect.y+12+index*18));
      }
      ctx.restore();
      for (const point of new Set(this.points.values())) {
        if(point.visible===false)continue;
        const {node,x,y}=point;
        ctx.fillStyle=node.kind === "local" ? node.observed ? this.color("#ffb148") : this.color("#637b68") : node.kind === "unknown" ? this.color("#c5a671") : this.color("#63dfbb");
        const labelX=Math.max(65+this.offset.x,Math.min(this.width-65+this.offset.x,x));
        if(node.kind==="local"){
          const compact=this.inset.height<(this.globeMode ? 180 : 160);
          ctx.textAlign="center";
          if(!compact){ctx.strokeStyle=ctx.fillStyle;ctx.lineWidth=1;ctx.strokeRect(x-11,y-11,22,22);ctx.font="bold 16px -apple-system,sans-serif";ctx.fillText(node.glyph,x,y+5);}
          ctx.fillStyle=this.color("#bddfcb");ctx.font="14px -apple-system,sans-serif";let label=node.label;
          const maxWidth=this.inset.width/this.hostColumns-14;
          while(label.length>1 && ctx.measureText(label).width>maxWidth)label=label.endsWith("…") ? label.slice(0,-2)+"…" : label.slice(0,-1)+"…";
          ctx.fillText(label,labelX,y+(compact ? 2 : -19));
          ctx.font=(compact ? "11px" : "13px")+" ui-monospace,monospace";ctx.fillText(node.ip || "",labelX,y+(compact ? 18 : 23));
          if(node.secondaryIP && !(compact && this.globeMode))ctx.fillText(node.secondaryIP,labelX,y+(compact ? 31 : 39));
        }else{
          ctx.shadowColor=ctx.fillStyle;ctx.shadowBlur=8;ctx.beginPath();ctx.arc(x,y,3.4,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;
          ctx.strokeStyle=this.color("#53967a99");ctx.beginPath();ctx.arc(x,y,8,0,Math.PI*2);ctx.stroke();ctx.font="13px -apple-system,sans-serif";ctx.textAlign="center";ctx.fillStyle=this.color("#bddfcb");if(!this.globeMode || this.countryLabelKeys?.has(node.key))ctx.fillText(node.label,labelX,y-13);
        }
      }
      ctx.textAlign="left";
      if (!this.paths.length) {ctx.fillStyle=this.color("#7e9fae");ctx.font="12px -apple-system,sans-serif";ctx.textAlign="center";ctx.fillText("該当するセッションはありません",this.width/2,this.height*.42);ctx.textAlign="left";}
    }
    schedule() {
      if (this.animation) cancelAnimationFrame(this.animation);
      this.animation=null;
      if (!this.active || document.hidden || (!this.canSpin() && (this.paused || this.stale || !this.model.routes.some(route => route.animate)))) {this.draw(performance.now());return;}
      let last=0;
      const frame=now => {
        if(now-last>=50){
          if(this.canSpin()) {this.longitude=SphereMap.advance(this.longitude,last ? now-last : 0);this.layout();}
          this.draw(now);last=now;
        }
        this.animation=requestAnimationFrame(frame);
      };
      this.animation=requestAnimationFrame(frame);
    }
    pick(event) {
      const rect=this.canvas.getBoundingClientRect(),zoom=this.zoom || 1;
      const screen={x:(event.clientX-rect.left)*this.width/rect.width,y:(event.clientY-rect.top)*this.height/rect.height};
      const label=(this.routeLabels || []).find(item=>screen.x>=item.rect.x && screen.x<=item.rect.x+item.rect.width && screen.y>=item.rect.y && screen.y<=item.rect.y+item.rect.height);
      if(label){this.select(label.key);return;}
      const point={x:screen.x/zoom,y:screen.y/zoom};
      let selected=null,nearest=13/zoom;
      for (const path of this.paths.filter(path=>!path.hidden)) for (let t=0;t<=1;t+=.025) {
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
  if (typeof module !== "undefined" && module.exports) module.exports = {routeDomains,placeRouteLabels,intersects,routeVisual,byteLabel,endpointNode,groupFlows,quadratic,routeColor,projection,unwrapRing,pacificInset,toggledSelection,SessionAtlas};
})(typeof window !== "undefined" ? window : globalThis);
