"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {routeDomains,placeRouteLabels,intersects,routeVisual,byteLabel,groupFlows, quadratic, routeColor, projection, unwrapRing, pacificInset, toggledSelection, SessionAtlas} = require("../src/rabbitwall/static/atlas.js");
const world = JSON.parse(fs.readFileSync(path.join(__dirname,"../src/rabbitwall/static/world.json"), "utf8"));
const privateIP = {kind:"private",code:null}, us = {kind:"country",code:"US"};
const flow = {src:"10.1.0.10",dst:"8.8.8.8",sport:50000,dport:443,proto:"TCP",service:"HTTPS",state:"ESTABLISHED",
  scope:"AI",src_country:privateIP,dst_country:us,tx_bytes:100,rx_bytes:200};

// Aggregate sessions without mistaking an animation or a route for packet counts.
const grouped = groupFlows([flow,{...flow,sport:50001,tx_bytes:300,rx_bytes:400}],world.countries);
assert.equal(grouped.totalFlows,2);
assert.equal(grouped.totalRoutes,1);
assert.equal(grouped.routes[0].count,2);
assert.equal(grouped.routes[0].totalBytes,1000);
assert.deepEqual(grouped.routes[0].dst.point,world.countries.US.point);
assert.equal(grouped.countryCount,1);

// Management SSH remains a local-to-local route and never receives a fake country.
const ssh={...flow,src:"10.0.0.9",dst:"10.1.0.10",dport:22,service:"SSH",scope:"MANAGEMENT",dst_country:privateIP};
const inbound=groupFlows([ssh],world.countries);
assert.equal(inbound.routes[0].src.kind,"local");
assert.equal(inbound.routes[0].dst.kind,"local");
assert.equal(inbound.countryCount,0);
assert.notEqual(routeColor(ssh,"flows"),routeColor(ssh,"drops"));

// Missing country data remains unlocated rather than silently defaulting to Japan.
const unlocated=groupFlows([{...flow,dst_country:{kind:"unknown",code:null}}],world.countries);
assert.equal(unlocated.routes[0].dst.kind,"unknown");
assert.equal(unlocated.countryCount,0);
assert.equal(unlocated.totalFlows,1);

// A display cap does not change the actual number of observed sessions/routes.
const many=Array.from({length:100},(_,i)=>({...flow,dport:10000+i}));
const capped=groupFlows(many,world.countries,"flows",80);
assert.equal(capped.routes.length,80);assert.equal(capped.totalRoutes,100);assert.equal(capped.totalFlows,100);

// History replays volume even for ended sessions; rejected attempts stay static.
assert.equal(groupFlows([{...flow,ended_at:"2026-10-26T00:00:00Z"}],world.countries,"history").routes[0].animate,true);
assert.equal(groupFlows([flow],world.countries,"drops").routes[0].animate,false);
assert.equal(groupFlows([],world.countries).routes.length,0);
const noAccounting=groupFlows([{...flow,tx_bytes:null,rx_bytes:null}],world.countries);
assert.equal(noAccounting.routes[0].totalBytes,null);
assert.deepEqual(quadratic({x:0,y:0},{x:5,y:10},{x:10,y:0},.5),{x:5,y:5});
assert.ok(world.features.length>100);assert.ok(world.countries.JP && world.countries.US && world.countries.AU);
assert.equal(world.license,"public domain");

// Japan is west of a Pacific LAN inset; the Americas remain to its east.
for(const [width,height] of [[1280,720],[1024,640],[420,800],[900,330],[720,280]]){
  const inset=pacificInset(width,height);
  assert.ok(inset.x>=0 && inset.x+inset.width<=width);
  assert.ok(inset.y>=0 && inset.y+inset.height<=height);
}
const jp=projection(world.countries.JP.point,1280,720),usPoint=projection(world.countries.US.point,1280,720),inset=pacificInset(1280,720);
assert.ok(jp.x<inset.x && inset.x+inset.width<usPoint.x);
assert.ok(jp.y<inset.y);
const dateline=unwrapRing([[170,10],[-170,10],[-170,0],[170,0]]);
for(let i=1;i<dateline.length;i++)assert.ok(Math.abs(dateline[i][0]-dateline[i-1][0])<=180);

// The actual selection method must toggle off and remain off after polling.
assert.equal(toggledSelection("route-a","route-a"),null);
const atlas=Object.create(SessionAtlas.prototype);
atlas.world=world;atlas.selected=null;
for(const name of ["paintList","paintDetail","paintSummary","layout","draw","schedule"])atlas[name]=()=>{};
const key=grouped.routes[0].key;
atlas.select(key);assert.equal(atlas.selected,key);
atlas.select(key);assert.equal(atlas.selected,null);
atlas.update([flow]);assert.equal(atlas.selected,null);
atlas.select(key);atlas.clearSelection();atlas.update([flow]);assert.equal(atlas.selected,null);
console.log("Session atlas: grouping, country map, Pacific LAN placement, dateline wrapping, selection toggle/clear, polling, and limits passed.");

// Dragging moves all map points together, survives updates, and can reset.
const pan=Object.create(SessionAtlas.prototype);
pan.network={hosts:[{label:"AI Host",glyph:"端",ip:"10.1.0.10",ips:["10.1.0.10"]},
 {label:"Gateway",glyph:"継",ip:"10.2.0.2",secondaryIP:"10.1.0.1",ips:["10.2.0.2","10.1.0.1"]}],site_location:[139,36]};
pan.world=world;pan.width=1280;pan.height=500;pan.offset={x:0,y:0};pan.model=grouped;
pan.paintBackground=()=>{};pan.draw=()=>{};
pan.layout();
const before=pan.points.get("local:10.1.0.10"), publicBefore=pan.points.get("country:US");
pan.offset={x:90,y:40};pan.layout();
assert.equal(pan.points.get("local:10.1.0.10").x-before.x,90);
assert.equal(pan.points.get("country:US").y-publicBefore.y,40);
pan.canvas={classList:{remove:()=>{}},hasPointerCapture:()=>false};
pan.resetPosition();assert.deepEqual(pan.offset,{x:0,y:0});
assert.equal(pan.points.get("local:10.1.0.10").x,before.x);
pan.drag={id:2,moved:true};pan.endPan({pointerId:2});
assert.equal(pan.suppressClick,true);assert.equal(pan.drag,null);
pan.drag={id:3,moved:false};pan.endPan({pointerId:3});assert.equal(pan.suppressClick,false);
// Every supported theme can repaint; invalid stored preferences fall back safely.
for(const theme of ["amber","cyan","violet","white","green","blue","red"]){pan.setTheme(theme);assert.equal(pan.theme,theme);}
pan.setTheme("__proto__");assert.equal(pan.theme,"green");
pan.setTheme("cyan");assert.notEqual(pan.color("#ed9630"),"#ed9630");
console.log("Session atlas: map pan/reset, drag-versus-click, and theme validation passed.");

// Zoom keeps the world point under the cursor fixed, including after a pan.
const zoom=Object.create(SessionAtlas.prototype);
Object.assign(zoom,{network:pan.network,world,width:1280,height:500,zoom:1,
  offset:{x:90,y:40},model:{...grouped,routes:[grouped.routes[0]]},
  paintBackground:()=>{},draw:()=>{},drag:null,panFrame:null});
zoom.canvas={getBoundingClientRect:()=>({left:20,top:30,width:1280,height:500}),
  classList:{add:()=>{},remove:()=>{}},hasPointerCapture:()=>false};
global.requestAnimationFrame=()=>1;global.cancelAnimationFrame=()=>{};
let prevented=0;
const wheel={clientX:500,clientY:270,deltaY:-180,deltaMode:0,preventDefault:()=>prevented++};
const anchor={x:480/zoom.zoom-zoom.offset.x,y:240/zoom.zoom-zoom.offset.y};
zoom.wheelZoom(wheel);
assert.ok(zoom.zoom>1);
assert.ok(Math.abs((anchor.x+zoom.offset.x)*zoom.zoom-480)<1e-9);
assert.ok(Math.abs((anchor.y+zoom.offset.y)*zoom.zoom-240)<1e-9);
assert.equal(prevented,1);
zoom.layout();
// Click selection uses the same camera transform as map drawing.
const zoomPath=zoom.paths[0],mid=quadratic(zoomPath.a,zoomPath.b,zoomPath.c,.5);
let picked;zoom.select=key=>picked=key;
zoom.pick({clientX:20+mid.x*zoom.zoom,clientY:30+mid.y*zoom.zoom});
assert.equal(picked,zoomPath.route.key);
// A drag of 60 screen pixels must still move the map 60 pixels when zoomed.
const origin={...zoom.offset};zoom.drag={id:9,x:100,y:100,origin,moved:false};
zoom.movePan({pointerId:9,clientX:160,clientY:100});
assert.ok(Math.abs((zoom.offset.x-origin.x)*zoom.zoom-60)<1e-9);
zoom.drag=null;
for(let i=0;i<20;i++)zoom.wheelZoom({...wheel,deltaY:-500});
assert.equal(zoom.zoom,6);
for(let i=0;i<20;i++)zoom.wheelZoom({...wheel,deltaY:500});
assert.equal(zoom.zoom,1);
const priorPrevented=prevented;
zoom.wheelZoom({...wheel,ctrlKey:true});zoom.wheelZoom({...wheel,metaKey:true});
assert.equal(prevented,priorPrevented);assert.equal(zoom.zoom,1);
zoom.wheelZoom({...wheel,deltaY:-1,deltaMode:1});assert.ok(zoom.zoom>1);
zoom.wheelZoom({...wheel,deltaY:-1,deltaMode:2});assert.ok(zoom.zoom>2);
zoom.resetPosition();assert.equal(zoom.zoom,1);assert.deepEqual(zoom.offset,{x:0,y:0});
console.log('Session atlas: cursor-anchored wheel zoom, bounds, zoomed selection/drag, wheel units, browser shortcuts and reset passed.');

// Historical volume controls width, particle density and repetition with bounded costs.
const tiny=routeVisual({count:1,totalBytes:1024},"history");
const huge=routeVisual({count:1,totalBytes:1024**3},"history");
assert.ok(huge.width>tiny.width && huge.particles>tiny.particles && huge.period<tiny.period);
assert.ok(huge.width<=6 && huge.particles<=8);
assert.deepEqual(routeVisual({count:1,totalBytes:Number.MAX_VALUE},"history"),huge);
for(const totalBytes of [null,0]){
  const style=routeVisual({count:1,totalBytes},"history");assert.equal(style.particles,0);
}
const historical=groupFlows([{...flow,tx_bytes:1024,rx_bytes:0,ended_at:"ended"},
  {...flow,dport:80,service:"HTTP",tx_bytes:1024**3,rx_bytes:0,ended_at:"ended"}],world.countries,"history",1);
assert.equal(historical.routes[0].service,"HTTP");assert.equal(historical.routes[0].animate,true);
assert.equal(groupFlows([{...flow,tx_bytes:null,rx_bytes:null}],world.countries,"history").routes[0].animate,false);
assert.equal(groupFlows([{...flow,tx_bytes:-1,rx_bytes:NaN}],world.countries,"history").routes[0].totalBytes,null);
assert.equal(byteLabel(null),"通信量不明");assert.equal(byteLabel(1024**3),"1.0 GB");
assert.deepEqual(routeVisual({count:1,totalBytes:1},"flows"),routeVisual({count:1,totalBytes:1024**3},"flows"));
console.log("Session atlas: historical byte volume controls bounded line width, particle count, period and route priority.");

// Dropped DNS is drawn toward historical country candidates, never toward its local resolver.
const dnsDrop={...flow,proto:'UDP',service:'DNS',dport:53,dst:'10.1.0.1',dst_country:privateIP,
  dns_questions:[{name:'example.com.',type:'AAAA'}],tx_bytes:null,rx_bytes:null};
assert.equal(groupFlows([dnsDrop],world.countries,'drops').routes[0].dst.kind,'unknown');
const inferred={...dnsDrop,dns_country_candidates:[
  {address:'8.8.8.8',country:us}, {address:'1.1.1.1',country:us},
  {address:'1.0.0.1',country:{kind:'country',code:'AU'}}]};
const map=groupFlows([inferred],world.countries,'drops');
assert.equal(map.totalFlows,1);assert.equal(map.totalRoutes,2);assert.equal(map.countryCount,2);
assert.deepEqual(new Set(map.routes.map(route=>route.dst.code)),new Set(['US','AU']));
assert.ok(map.routes.every(route=>route.dst.dnsInferred && route.dst.label.includes('DNS推定') && !route.animate));
assert.equal(inferred.dst,'10.1.0.1');assert.equal(inferred.dst_country,privateIP);
assert.equal(groupFlows([inferred,flow],world.countries,'drops').countryCount,2);
const noGeo={...dnsDrop,dns_country_candidates:[{address:'8.8.8.8',country:{kind:'unknown'}}]};
assert.equal(groupFlows([noGeo],world.countries,'drops').routes[0].dst.kind,'unknown');
// Other views continue to use actual IP endpoints, not speculative DNS geography.
assert.equal(groupFlows([inferred],world.countries,'flows').routes[0].dst.kind,'local');
console.log('Session atlas: passive DNS-country candidates, multi-country fanout, unknown fallback and real endpoints passed.');

// Route labels preserve DNS evidence and avoid the LAN inset, country names and each other.
assert.deepEqual(routeDomains({flows:[{domain_hints:[{domain:'API.Example.com'},{domain:'api.example.com.'}],dns_questions:[{name:'Other.example.'},{name:'.'}]}]}),['api.example.com','other.example']);
function labeledPath(key,domains=['api.example.com']) {
  return {route:{key,src:{kind:'local'},dst:{kind:'country'},flows:[{domain_hints:domains.map(domain=>({domain}))}]},
    a:{x:150,y:320},b:{x:400,y:30},c:{x:720,y:170}};
}
const obstacles=[{x:0,y:0,width:800,height:88},{x:40,y:250,width:200,height:130},{x:680,y:140,width:110,height:55}];
const labeledPaths=[labeledPath('one'),labeledPath('two',['two.example']),labeledPath('long',['a-very-long-subdomain.'.repeat(12)+'example.com','second.example','third.example'])];
const labels=placeRouteLabels(labeledPaths,{width:800,height:400,obstacles});
assert.equal(labels.length,3);
for(const label of labels){
  assert.ok(label.rect.x>=0 && label.rect.x+label.rect.width<=800 && label.rect.y>=0 && label.rect.y+label.rect.height<=400);
  assert.ok(obstacles.every(box=>!intersects(label.rect,box)));
  assert.ok(labels.filter(other=>other!==label).every(other=>!intersects(label.rect,other.rect)));
}
assert.ok(labels.find(label=>label.key==='long').text.includes('…'));
assert.ok(labels.find(label=>label.key==='long').text.endsWith('+2'));
assert.equal(placeRouteLabels(labeledPaths,{width:800,height:400,obstacles:[{x:0,y:0,width:800,height:400}]}).length,0);
assert.equal(placeRouteLabels([labeledPath('none',[])],{width:800,height:400}).length,0);
const local=labeledPath('local');local.route.dst.kind='local';
assert.equal(placeRouteLabels([local],{width:800,height:400}).length,0);
assert.equal(placeRouteLabels(labeledPaths,{width:800,height:400,obstacles,selected:'two'})[0].key,'two');
const manyLabels=Array.from({length:30},(_,index)=>{
  const item=labeledPath('label-'+index);
  for(const point of [item.a,item.b,item.c])point.x+=index*350;
  return item;
});
const boundedLabels=placeRouteLabels(manyLabels,{width:12000,height:400,selected:'label-29'});
assert.equal(boundedLabels.length,16);
assert.equal(boundedLabels[0].key,'label-29');
const zoomedLabels=placeRouteLabels(labeledPaths,{width:800,height:400,zoom:2});
for(const label of zoomedLabels)assert.ok(label.rect.x+label.rect.width<=800 && label.rect.y+label.rect.height<=400);
// Clicking a badge uses screen coordinates, independently of map zoom.
const badge=Object.create(SessionAtlas.prototype);let labelPicked;
badge.width=800;badge.height=400;badge.zoom=2;badge.canvas={getBoundingClientRect:()=>({left:20,top:30,width:800,height:400})};
badge.routeLabels=labels;badge.paths=[];badge.select=key=>labelPicked=key;
badge.pick({clientX:20+labels[0].rect.x+5,clientY:30+labels[0].rect.y+5});
assert.equal(labelPicked,labels[0].key);
console.log('Session atlas: domain labels, deduplication, crowded-route suppression, selected-route priority, viewport bounds and label selection passed.');
