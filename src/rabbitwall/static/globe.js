(function(root) {
  "use strict";
  const RAD=Math.PI/180;
  function vector([longitude,latitude]) {
    const lon=longitude*RAD,lat=latitude*RAD,c=Math.cos(lat);
    return {x:c*Math.sin(lon),y:Math.sin(lat),z:c*Math.cos(lon)};
  }
  function camera(longitude=30,latitude=15) {
    return {sinLon:Math.sin(longitude*RAD),cosLon:Math.cos(longitude*RAD),sinLat:Math.sin(latitude*RAD),cosLat:Math.cos(latitude*RAD)};
  }
  function rotate(v,camera) {
    const z=v.x*camera.sinLon+v.z*camera.cosLon;
    return {x:v.x*camera.cosLon-v.z*camera.sinLon,y:v.y*camera.cosLat-z*camera.sinLat,z:v.y*camera.sinLat+z*camera.cosLat};
  }
  function project(point,scene,view) {
    const v=rotate(vector(point),view);
    return {x:scene.x+scene.radius*v.x,y:scene.y-scene.radius*v.y,depth:v.z,visible:v.z>=0};
  }
  function scene(width,height) {
    const top=88,bottom=height-12;
    if(width>=700 || height<400) {
      const boxWidth=Math.min(340,Math.max(180,width*.34),width-28),boxX=width-boxWidth-16;
      const radius=Math.max(24,Math.min((boxX-40)/2,(bottom-top)/2-8));
      const boxHeight=Math.max(70,Math.min(236,bottom-top));
      return {x:(boxX-28)/2,y:top+(bottom-top)/2-4,radius,
        inset:{x:boxX,y:Math.min(bottom-boxHeight,top+(bottom-top-boxHeight)/2+radius*.12),width:boxWidth,height:boxHeight}};
    }
    const boxHeight=Math.min(170,(height-110)*.4),boxWidth=Math.min(380,width-28),boxY=bottom-boxHeight;
    const radius=Math.max(24,Math.min((width-36)/2,(boxY-top-24)/2));
    return {x:width/2,y:top+radius,radius,inset:{x:(width-boxWidth)/2,y:boxY,width:boxWidth,height:boxHeight}};
  }
  function horizon(a,b) {
    const t=a.z/(a.z-b.z),x=a.x+t*(b.x-a.x),y=a.y+t*(b.y-a.y),length=Math.hypot(x,y)||1;
    return {x:x/length,y:y/length,z:0};
  }
  function clipRing(vertices) {
    const clipped=[];
    for(let i=0;i<vertices.length;i++) {
      const a=vertices[(i+vertices.length-1)%vertices.length],b=vertices[i];
      if((a.z>=0)!==(b.z>=0))clipped.push(horizon(a,b));
      if(b.z>=0)clipped.push(b);
    }
    const result=[];
    for(let i=0;i<clipped.length;i++) {
      const a=clipped[i],b=clipped[(i+1)%clipped.length];result.push(a);
      if(a.z===0 && b.z===0) {
        const from=Math.atan2(a.y,a.x),delta=((Math.atan2(b.y,b.x)-from+3*Math.PI)%(2*Math.PI))-Math.PI;
        const steps=Math.ceil(Math.abs(delta)/(Math.PI/24));
        for(let step=1;step<steps;step++){const angle=from+delta*step/steps;result.push({x:Math.cos(angle),y:Math.sin(angle),z:0});}
      }
    }
    return result;
  }
  function advance(longitude,elapsed) { return ((longitude+Math.max(0,Math.min(100,elapsed))*.002)%360+360)%360; }
  const grid=[];
  for(let lon=-180;lon<180;lon+=30)grid.push(Array.from({length:37},(_,i)=>vector([lon,-90+i*5])));
  for(let lat=-60;lat<=60;lat+=30)grid.push(Array.from({length:73},(_,i)=>vector([-180+i*5,lat])));
  const api={vector,camera,rotate,project,scene,clipRing,advance,grid};
  root.SphereMap=api;
  if(typeof module!=="undefined" && module.exports)module.exports=api;
})(typeof window!=="undefined" ? window : globalThis);
