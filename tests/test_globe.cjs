"use strict";
const assert=require("node:assert/strict");
const sphere=require("../src/rabbitwall/static/globe.js");
const {SessionAtlas}=require("../src/rabbitwall/static/atlas.js");
const scene=sphere.scene(1000,600),camera=sphere.camera(30,15);
const center=sphere.project([30,15],scene,camera);
assert.ok(Math.abs(center.x-scene.x)<1e-8 && Math.abs(center.y-scene.y)<1e-8);
assert.ok(center.visible && center.depth>.999);
const back=sphere.project([-150,-15],scene,camera);
assert.equal(back.visible,false);
for(let longitude=-180;longitude<=180;longitude+=10)for(let latitude=-90;latitude<=90;latitude+=10){
  const p=sphere.project([longitude,latitude],scene,camera);
  assert.ok(Math.hypot(p.x-scene.x,p.y-scene.y)<=scene.radius+1e-8);
}
// Globe and foreground LAN never overlap, on wide, short or mobile maps.
for(const [width,height] of [[1120,650],[965,530],[800,250],[360,250],[390,450],[600,480],[420,800]]) {
  const s=sphere.scene(width,height),b=s.inset;
  assert.ok(s.x-s.radius>=0 && s.x+s.radius<=width && s.y-s.radius>=80 && s.y+s.radius<=height);
  assert.ok(b.x>=0 && b.x+b.width<=width && b.y>=80 && b.y+b.height<=height);
  const nearest={x:Math.max(b.x,Math.min(b.x+b.width,s.x)),y:Math.max(b.y,Math.min(b.y+b.height,s.y))};
  assert.ok(Math.hypot(nearest.x-s.x,nearest.y-s.y)>s.radius);
}
// Hemisphere clipping removes the far side and follows the curved horizon.
const ring=[[-100,-30],[-100,30],[40,30],[40,-30],[-100,-30]].map(p=>sphere.rotate(sphere.vector(p),sphere.camera(0,0)));
const clipped=sphere.clipRing(ring);
assert.ok(clipped.length>4);
assert.ok(clipped.every(p=>p.z>=0 && Math.hypot(p.x,p.y,p.z)<=1+1e-8));
assert.deepEqual(sphere.clipRing([sphere.vector([180,0]),sphere.vector([170,10]),sphere.vector([-170,10])]),[]);
// Three-minute rotation, with bounded deltas after backgrounding/suspension.
let longitude=0;
for(let elapsed=0;elapsed<180000;elapsed+=50)longitude=sphere.advance(longitude,50);
assert.ok(Math.abs(longitude)<1e-6 || Math.abs(longitude-360)<1e-6);
assert.ok(sphere.advance(0,60000)<=.21);
assert.equal(sphere.advance(30,-1),30);
const atlas=Object.create(SessionAtlas.prototype);
Object.assign(atlas,{active:true,globeMode:true,rotating:true,stale:false,drag:null,selected:null});
assert.equal(atlas.canSpin(),true);
for(const flag of ['stale','drag','selected']){atlas[flag]=true;assert.equal(atlas.canSpin(),false);atlas[flag]=null;}
atlas.active=false;assert.equal(atlas.canSpin(),false);atlas.active=true;
atlas.rotating=false;assert.equal(atlas.canSpin(),false);atlas.rotating=true;
atlas.globeMode=false;assert.equal(atlas.canSpin(),false);
// Selecting a hidden destination faces it toward the viewer and pauses rotation.
Object.assign(atlas,{globeMode:true,longitude:30,latitude:15,model:{routes:[{key:'route',src:{kind:'local'},dst:{kind:'country',point:[140,36]}}]},
  layout:()=>{},paintList:()=>{},paintDetail:()=>{},layoutLabels:()=>{},draw:()=>{},schedule:()=>{}});
atlas.select('route');assert.equal(atlas.longitude,140);assert.equal(atlas.latitude,36);assert.equal(atlas.canSpin(),false);
atlas.clearSelection();assert.equal(atlas.canSpin(),true);
// Globe drag changes orientation; Shift-drag retains map panning.
atlas.canvas={setPointerCapture:()=>{},classList:{add:()=>{}}};atlas.offset={x:0,y:0};atlas.zoom=1;atlas.sphereScene=scene;atlas.panFrame=1;
atlas.startPan({pointerId:1,button:0,clientX:100,clientY:100});
atlas.movePan({pointerId:1,clientX:170,clientY:120});
assert.notEqual(atlas.longitude,140);assert.deepEqual(atlas.offset,{x:0,y:0});
atlas.drag=null;atlas.startPan({pointerId:2,button:0,shiftKey:true,clientX:100,clientY:100});
atlas.movePan({pointerId:2,clientX:130,clientY:140});assert.deepEqual(atlas.offset,{x:30,y:40});
console.log("Globe: spherical projection, horizon clipping, detached LAN, slow rotation, visibility/pause, route focus and drag controls passed.");
