import{S as Cl,l as ws,s as Pl,a as Ul,b as Rs,c as Dl,g as Il,d as Ll,m as Pn,u as Nl,i as Cs,e as Fl,x as Un,f as Ps,h as Ol,j as Di,k as Bl,n as zl,o as Gl,p as Hl,q as Vl,r as kl,t as Wl,v as Xl,w as ut,y as ql,z as Us,A as Yl,B as jl,C as Nr,D as _r,E as xi,F as Dn,U as Kl,G as Ds,H as Jl,I as Is,J as Zl,K as $l,L as Ql,M as ec}from"./index-M9PJ1Wcu.js";/**
* @license
* Copyright 2010-2026 Three.js Authors
* SPDX-License-Identifier: MIT
*/const In="184",tc=0,Ls=1,ic=2,Fr=1,rc=2,vr=3,ni=0,bt=1,ai=2,si=0,ji=1,Ns=2,Fs=3,Os=4,nc=5,Ii=100,ac=101,sc=102,oc=103,lc=104,cc=200,uc=201,hc=202,dc=203,Ln=204,Nn=205,pc=206,fc=207,mc=208,gc=209,_c=210,vc=211,xc=212,Mc=213,Sc=214,Fn=0,On=1,Bn=2,Ki=3,zn=4,Gn=5,Hn=6,Vn=7,Bs=0,Ec=1,Tc=2,qt=0,zs=1,Gs=2,Hs=3,Vs=4,ks=5,Ws=6,Xs=7,qs=300,Li=301,Ji=302,kn=303,Wn=304,Or=306,Xn=1e3,oi=1001,qn=1002,_t=1003,yc=1004,Br=1005,vt=1006,Yn=1007,Ni=1008,Lt=1009,Ys=1010,js=1011,xr=1012,jn=1013,Yt=1014,jt=1015,li=1016,Kn=1017,Jn=1018,Mr=1020,Ks=35902,Js=35899,Zs=1021,$s=1022,Ot=1023,ci=1026,Fi=1027,Qs=1028,Zn=1029,Oi=1030,$n=1031,Qn=1033,zr=33776,Gr=33777,Hr=33778,Vr=33779,ea=35840,ta=35841,ia=35842,ra=35843,na=36196,aa=37492,sa=37496,oa=37488,la=37489,kr=37490,ca=37491,ua=37808,ha=37809,da=37810,pa=37811,fa=37812,ma=37813,ga=37814,_a=37815,va=37816,xa=37817,Ma=37818,Sa=37819,Ea=37820,Ta=37821,ya=36492,ba=36494,Aa=36495,wa=36283,Ra=36284,Wr=36285,Ca=36286,bc=3200,eo=0,Ac=1,Mi="",At="srgb",Xr="srgb-linear",qr="linear",Xe="srgb",Zi=7680,to=519,wc=512,Rc=513,Cc=514,Pa=515,Pc=516,Uc=517,Ua=518,Dc=519,io=35044,Yr=35048,ro="300 es",Kt=2e3,jr=2001;function Ic(r){for(let e=r.length-1;e>=0;--e)if(r[e]>=65535)return!0;return!1}function Kr(r){return document.createElementNS("http://www.w3.org/1999/xhtml",r)}function Lc(){const r=Kr("canvas");return r.style.display="block",r}const no={};function ao(...r){const e="THREE."+r.shift();console.log(e,...r)}function so(r){const e=r[0];if(typeof e=="string"&&e.startsWith("TSL:")){const t=r[1];t&&t.isStackTrace?r[0]+=" "+t.getLocation():r[1]='Stack trace not available. Enable "THREE.Node.captureStackTrace" to capture stack traces.'}return r}function Ae(...r){r=so(r);const e="THREE."+r.shift();{const t=r[0];t&&t.isStackTrace?console.warn(t.getError(e)):console.warn(e,...r)}}function He(...r){r=so(r);const e="THREE."+r.shift();{const t=r[0];t&&t.isStackTrace?console.error(t.getError(e)):console.error(e,...r)}}function Da(...r){const e=r.join(" ");e in no||(no[e]=!0,Ae(...r))}function Nc(r,e,t){return new Promise(function(i,n){function a(){switch(r.clientWaitSync(e,r.SYNC_FLUSH_COMMANDS_BIT,0)){case r.WAIT_FAILED:n();break;case r.TIMEOUT_EXPIRED:setTimeout(a,t);break;default:i()}}setTimeout(a,t)})}const Fc={[Fn]:On,[Bn]:Hn,[zn]:Vn,[Ki]:Gn,[On]:Fn,[Hn]:Bn,[Vn]:zn,[Gn]:Ki};class Bi{addEventListener(e,t){this._listeners===void 0&&(this._listeners={});const i=this._listeners;i[e]===void 0&&(i[e]=[]),i[e].indexOf(t)===-1&&i[e].push(t)}hasEventListener(e,t){const i=this._listeners;return i===void 0?!1:i[e]!==void 0&&i[e].indexOf(t)!==-1}removeEventListener(e,t){const i=this._listeners;if(i===void 0)return;const n=i[e];if(n!==void 0){const a=n.indexOf(t);a!==-1&&n.splice(a,1)}}dispatchEvent(e){const t=this._listeners;if(t===void 0)return;const i=t[e.type];if(i!==void 0){e.target=this;const n=i.slice(0);for(let a=0,s=n.length;a<s;a++)n[a].call(this,e);e.target=null}}}const xt=["00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"],Ia=Math.PI/180,La=180/Math.PI;function Sr(){const r=Math.random()*4294967295|0,e=Math.random()*4294967295|0,t=Math.random()*4294967295|0,i=Math.random()*4294967295|0;return(xt[r&255]+xt[r>>8&255]+xt[r>>16&255]+xt[r>>24&255]+"-"+xt[e&255]+xt[e>>8&255]+"-"+xt[e>>16&15|64]+xt[e>>24&255]+"-"+xt[t&63|128]+xt[t>>8&255]+"-"+xt[t>>16&255]+xt[t>>24&255]+xt[i&255]+xt[i>>8&255]+xt[i>>16&255]+xt[i>>24&255]).toLowerCase()}function Be(r,e,t){return Math.max(e,Math.min(t,r))}function Oc(r,e){return(r%e+e)%e}function Na(r,e,t){return(1-t)*r+t*e}function Er(r,e){switch(e.constructor){case Float32Array:return r;case Uint32Array:return r/4294967295;case Uint16Array:return r/65535;case Uint8Array:return r/255;case Int32Array:return Math.max(r/2147483647,-1);case Int16Array:return Math.max(r/32767,-1);case Int8Array:return Math.max(r/127,-1);default:throw new Error("Invalid component type.")}}function wt(r,e){switch(e.constructor){case Float32Array:return r;case Uint32Array:return Math.round(r*4294967295);case Uint16Array:return Math.round(r*65535);case Uint8Array:return Math.round(r*255);case Int32Array:return Math.round(r*2147483647);case Int16Array:return Math.round(r*32767);case Int8Array:return Math.round(r*127);default:throw new Error("Invalid component type.")}}const fs=class fs{constructor(e=0,t=0){this.x=e,this.y=t}get width(){return this.x}set width(e){this.x=e}get height(){return this.y}set height(e){this.y=e}set(e,t){return this.x=e,this.y=t,this}setScalar(e){return this.x=e,this.y=e,this}setX(e){return this.x=e,this}setY(e){return this.y=e,this}setComponent(e,t){switch(e){case 0:this.x=t;break;case 1:this.y=t;break;default:throw new Error("index is out of range: "+e)}return this}getComponent(e){switch(e){case 0:return this.x;case 1:return this.y;default:throw new Error("index is out of range: "+e)}}clone(){return new this.constructor(this.x,this.y)}copy(e){return this.x=e.x,this.y=e.y,this}add(e){return this.x+=e.x,this.y+=e.y,this}addScalar(e){return this.x+=e,this.y+=e,this}addVectors(e,t){return this.x=e.x+t.x,this.y=e.y+t.y,this}addScaledVector(e,t){return this.x+=e.x*t,this.y+=e.y*t,this}sub(e){return this.x-=e.x,this.y-=e.y,this}subScalar(e){return this.x-=e,this.y-=e,this}subVectors(e,t){return this.x=e.x-t.x,this.y=e.y-t.y,this}multiply(e){return this.x*=e.x,this.y*=e.y,this}multiplyScalar(e){return this.x*=e,this.y*=e,this}divide(e){return this.x/=e.x,this.y/=e.y,this}divideScalar(e){return this.multiplyScalar(1/e)}applyMatrix3(e){const t=this.x,i=this.y,n=e.elements;return this.x=n[0]*t+n[3]*i+n[6],this.y=n[1]*t+n[4]*i+n[7],this}min(e){return this.x=Math.min(this.x,e.x),this.y=Math.min(this.y,e.y),this}max(e){return this.x=Math.max(this.x,e.x),this.y=Math.max(this.y,e.y),this}clamp(e,t){return this.x=Be(this.x,e.x,t.x),this.y=Be(this.y,e.y,t.y),this}clampScalar(e,t){return this.x=Be(this.x,e,t),this.y=Be(this.y,e,t),this}clampLength(e,t){const i=this.length();return this.divideScalar(i||1).multiplyScalar(Be(i,e,t))}floor(){return this.x=Math.floor(this.x),this.y=Math.floor(this.y),this}ceil(){return this.x=Math.ceil(this.x),this.y=Math.ceil(this.y),this}round(){return this.x=Math.round(this.x),this.y=Math.round(this.y),this}roundToZero(){return this.x=Math.trunc(this.x),this.y=Math.trunc(this.y),this}negate(){return this.x=-this.x,this.y=-this.y,this}dot(e){return this.x*e.x+this.y*e.y}cross(e){return this.x*e.y-this.y*e.x}lengthSq(){return this.x*this.x+this.y*this.y}length(){return Math.sqrt(this.x*this.x+this.y*this.y)}manhattanLength(){return Math.abs(this.x)+Math.abs(this.y)}normalize(){return this.divideScalar(this.length()||1)}angle(){return Math.atan2(-this.y,-this.x)+Math.PI}angleTo(e){const t=Math.sqrt(this.lengthSq()*e.lengthSq());if(t===0)return Math.PI/2;const i=this.dot(e)/t;return Math.acos(Be(i,-1,1))}distanceTo(e){return Math.sqrt(this.distanceToSquared(e))}distanceToSquared(e){const t=this.x-e.x,i=this.y-e.y;return t*t+i*i}manhattanDistanceTo(e){return Math.abs(this.x-e.x)+Math.abs(this.y-e.y)}setLength(e){return this.normalize().multiplyScalar(e)}lerp(e,t){return this.x+=(e.x-this.x)*t,this.y+=(e.y-this.y)*t,this}lerpVectors(e,t,i){return this.x=e.x+(t.x-e.x)*i,this.y=e.y+(t.y-e.y)*i,this}equals(e){return e.x===this.x&&e.y===this.y}fromArray(e,t=0){return this.x=e[t],this.y=e[t+1],this}toArray(e=[],t=0){return e[t]=this.x,e[t+1]=this.y,e}fromBufferAttribute(e,t){return this.x=e.getX(t),this.y=e.getY(t),this}rotateAround(e,t){const i=Math.cos(t),n=Math.sin(t),a=this.x-e.x,s=this.y-e.y;return this.x=a*i-s*n+e.x,this.y=a*n+s*i+e.y,this}random(){return this.x=Math.random(),this.y=Math.random(),this}*[Symbol.iterator](){yield this.x,yield this.y}};fs.prototype.isVector2=!0;let Ke=fs;class $i{constructor(e=0,t=0,i=0,n=1){this.isQuaternion=!0,this._x=e,this._y=t,this._z=i,this._w=n}static slerpFlat(e,t,i,n,a,s,o){let c=i[n+0],l=i[n+1],d=i[n+2],m=i[n+3],u=a[s+0],g=a[s+1],x=a[s+2],E=a[s+3];if(m!==E||c!==u||l!==g||d!==x){let p=c*u+l*g+d*x+m*E;p<0&&(u=-u,g=-g,x=-x,E=-E,p=-p);let h=1-o;if(p<.9995){const S=Math.acos(p),A=Math.sin(S);h=Math.sin(h*S)/A,o=Math.sin(o*S)/A,c=c*h+u*o,l=l*h+g*o,d=d*h+x*o,m=m*h+E*o}else{c=c*h+u*o,l=l*h+g*o,d=d*h+x*o,m=m*h+E*o;const S=1/Math.sqrt(c*c+l*l+d*d+m*m);c*=S,l*=S,d*=S,m*=S}}e[t]=c,e[t+1]=l,e[t+2]=d,e[t+3]=m}static multiplyQuaternionsFlat(e,t,i,n,a,s){const o=i[n],c=i[n+1],l=i[n+2],d=i[n+3],m=a[s],u=a[s+1],g=a[s+2],x=a[s+3];return e[t]=o*x+d*m+c*g-l*u,e[t+1]=c*x+d*u+l*m-o*g,e[t+2]=l*x+d*g+o*u-c*m,e[t+3]=d*x-o*m-c*u-l*g,e}get x(){return this._x}set x(e){this._x=e,this._onChangeCallback()}get y(){return this._y}set y(e){this._y=e,this._onChangeCallback()}get z(){return this._z}set z(e){this._z=e,this._onChangeCallback()}get w(){return this._w}set w(e){this._w=e,this._onChangeCallback()}set(e,t,i,n){return this._x=e,this._y=t,this._z=i,this._w=n,this._onChangeCallback(),this}clone(){return new this.constructor(this._x,this._y,this._z,this._w)}copy(e){return this._x=e.x,this._y=e.y,this._z=e.z,this._w=e.w,this._onChangeCallback(),this}setFromEuler(e,t=!0){const i=e._x,n=e._y,a=e._z,s=e._order,o=Math.cos,c=Math.sin,l=o(i/2),d=o(n/2),m=o(a/2),u=c(i/2),g=c(n/2),x=c(a/2);switch(s){case"XYZ":this._x=u*d*m+l*g*x,this._y=l*g*m-u*d*x,this._z=l*d*x+u*g*m,this._w=l*d*m-u*g*x;break;case"YXZ":this._x=u*d*m+l*g*x,this._y=l*g*m-u*d*x,this._z=l*d*x-u*g*m,this._w=l*d*m+u*g*x;break;case"ZXY":this._x=u*d*m-l*g*x,this._y=l*g*m+u*d*x,this._z=l*d*x+u*g*m,this._w=l*d*m-u*g*x;break;case"ZYX":this._x=u*d*m-l*g*x,this._y=l*g*m+u*d*x,this._z=l*d*x-u*g*m,this._w=l*d*m+u*g*x;break;case"YZX":this._x=u*d*m+l*g*x,this._y=l*g*m+u*d*x,this._z=l*d*x-u*g*m,this._w=l*d*m-u*g*x;break;case"XZY":this._x=u*d*m-l*g*x,this._y=l*g*m-u*d*x,this._z=l*d*x+u*g*m,this._w=l*d*m+u*g*x;break;default:Ae("Quaternion: .setFromEuler() encountered an unknown order: "+s)}return t===!0&&this._onChangeCallback(),this}setFromAxisAngle(e,t){const i=t/2,n=Math.sin(i);return this._x=e.x*n,this._y=e.y*n,this._z=e.z*n,this._w=Math.cos(i),this._onChangeCallback(),this}setFromRotationMatrix(e){const t=e.elements,i=t[0],n=t[4],a=t[8],s=t[1],o=t[5],c=t[9],l=t[2],d=t[6],m=t[10],u=i+o+m;if(u>0){const g=.5/Math.sqrt(u+1);this._w=.25/g,this._x=(d-c)*g,this._y=(a-l)*g,this._z=(s-n)*g}else if(i>o&&i>m){const g=2*Math.sqrt(1+i-o-m);this._w=(d-c)/g,this._x=.25*g,this._y=(n+s)/g,this._z=(a+l)/g}else if(o>m){const g=2*Math.sqrt(1+o-i-m);this._w=(a-l)/g,this._x=(n+s)/g,this._y=.25*g,this._z=(c+d)/g}else{const g=2*Math.sqrt(1+m-i-o);this._w=(s-n)/g,this._x=(a+l)/g,this._y=(c+d)/g,this._z=.25*g}return this._onChangeCallback(),this}setFromUnitVectors(e,t){let i=e.dot(t)+1;return i<1e-8?(i=0,Math.abs(e.x)>Math.abs(e.z)?(this._x=-e.y,this._y=e.x,this._z=0,this._w=i):(this._x=0,this._y=-e.z,this._z=e.y,this._w=i)):(this._x=e.y*t.z-e.z*t.y,this._y=e.z*t.x-e.x*t.z,this._z=e.x*t.y-e.y*t.x,this._w=i),this.normalize()}angleTo(e){return 2*Math.acos(Math.abs(Be(this.dot(e),-1,1)))}rotateTowards(e,t){const i=this.angleTo(e);if(i===0)return this;const n=Math.min(1,t/i);return this.slerp(e,n),this}identity(){return this.set(0,0,0,1)}invert(){return this.conjugate()}conjugate(){return this._x*=-1,this._y*=-1,this._z*=-1,this._onChangeCallback(),this}dot(e){return this._x*e._x+this._y*e._y+this._z*e._z+this._w*e._w}lengthSq(){return this._x*this._x+this._y*this._y+this._z*this._z+this._w*this._w}length(){return Math.sqrt(this._x*this._x+this._y*this._y+this._z*this._z+this._w*this._w)}normalize(){let e=this.length();return e===0?(this._x=0,this._y=0,this._z=0,this._w=1):(e=1/e,this._x=this._x*e,this._y=this._y*e,this._z=this._z*e,this._w=this._w*e),this._onChangeCallback(),this}multiply(e){return this.multiplyQuaternions(this,e)}premultiply(e){return this.multiplyQuaternions(e,this)}multiplyQuaternions(e,t){const i=e._x,n=e._y,a=e._z,s=e._w,o=t._x,c=t._y,l=t._z,d=t._w;return this._x=i*d+s*o+n*l-a*c,this._y=n*d+s*c+a*o-i*l,this._z=a*d+s*l+i*c-n*o,this._w=s*d-i*o-n*c-a*l,this._onChangeCallback(),this}slerp(e,t){let i=e._x,n=e._y,a=e._z,s=e._w,o=this.dot(e);o<0&&(i=-i,n=-n,a=-a,s=-s,o=-o);let c=1-t;if(o<.9995){const l=Math.acos(o),d=Math.sin(l);c=Math.sin(c*l)/d,t=Math.sin(t*l)/d,this._x=this._x*c+i*t,this._y=this._y*c+n*t,this._z=this._z*c+a*t,this._w=this._w*c+s*t,this._onChangeCallback()}else this._x=this._x*c+i*t,this._y=this._y*c+n*t,this._z=this._z*c+a*t,this._w=this._w*c+s*t,this.normalize();return this}slerpQuaternions(e,t,i){return this.copy(e).slerp(t,i)}random(){const e=2*Math.PI*Math.random(),t=2*Math.PI*Math.random(),i=Math.random(),n=Math.sqrt(1-i),a=Math.sqrt(i);return this.set(n*Math.sin(e),n*Math.cos(e),a*Math.sin(t),a*Math.cos(t))}equals(e){return e._x===this._x&&e._y===this._y&&e._z===this._z&&e._w===this._w}fromArray(e,t=0){return this._x=e[t],this._y=e[t+1],this._z=e[t+2],this._w=e[t+3],this._onChangeCallback(),this}toArray(e=[],t=0){return e[t]=this._x,e[t+1]=this._y,e[t+2]=this._z,e[t+3]=this._w,e}fromBufferAttribute(e,t){return this._x=e.getX(t),this._y=e.getY(t),this._z=e.getZ(t),this._w=e.getW(t),this._onChangeCallback(),this}toJSON(){return this.toArray()}_onChange(e){return this._onChangeCallback=e,this}_onChangeCallback(){}*[Symbol.iterator](){yield this._x,yield this._y,yield this._z,yield this._w}}const ms=class ms{constructor(e=0,t=0,i=0){this.x=e,this.y=t,this.z=i}set(e,t,i){return i===void 0&&(i=this.z),this.x=e,this.y=t,this.z=i,this}setScalar(e){return this.x=e,this.y=e,this.z=e,this}setX(e){return this.x=e,this}setY(e){return this.y=e,this}setZ(e){return this.z=e,this}setComponent(e,t){switch(e){case 0:this.x=t;break;case 1:this.y=t;break;case 2:this.z=t;break;default:throw new Error("index is out of range: "+e)}return this}getComponent(e){switch(e){case 0:return this.x;case 1:return this.y;case 2:return this.z;default:throw new Error("index is out of range: "+e)}}clone(){return new this.constructor(this.x,this.y,this.z)}copy(e){return this.x=e.x,this.y=e.y,this.z=e.z,this}add(e){return this.x+=e.x,this.y+=e.y,this.z+=e.z,this}addScalar(e){return this.x+=e,this.y+=e,this.z+=e,this}addVectors(e,t){return this.x=e.x+t.x,this.y=e.y+t.y,this.z=e.z+t.z,this}addScaledVector(e,t){return this.x+=e.x*t,this.y+=e.y*t,this.z+=e.z*t,this}sub(e){return this.x-=e.x,this.y-=e.y,this.z-=e.z,this}subScalar(e){return this.x-=e,this.y-=e,this.z-=e,this}subVectors(e,t){return this.x=e.x-t.x,this.y=e.y-t.y,this.z=e.z-t.z,this}multiply(e){return this.x*=e.x,this.y*=e.y,this.z*=e.z,this}multiplyScalar(e){return this.x*=e,this.y*=e,this.z*=e,this}multiplyVectors(e,t){return this.x=e.x*t.x,this.y=e.y*t.y,this.z=e.z*t.z,this}applyEuler(e){return this.applyQuaternion(oo.setFromEuler(e))}applyAxisAngle(e,t){return this.applyQuaternion(oo.setFromAxisAngle(e,t))}applyMatrix3(e){const t=this.x,i=this.y,n=this.z,a=e.elements;return this.x=a[0]*t+a[3]*i+a[6]*n,this.y=a[1]*t+a[4]*i+a[7]*n,this.z=a[2]*t+a[5]*i+a[8]*n,this}applyNormalMatrix(e){return this.applyMatrix3(e).normalize()}applyMatrix4(e){const t=this.x,i=this.y,n=this.z,a=e.elements,s=1/(a[3]*t+a[7]*i+a[11]*n+a[15]);return this.x=(a[0]*t+a[4]*i+a[8]*n+a[12])*s,this.y=(a[1]*t+a[5]*i+a[9]*n+a[13])*s,this.z=(a[2]*t+a[6]*i+a[10]*n+a[14])*s,this}applyQuaternion(e){const t=this.x,i=this.y,n=this.z,a=e.x,s=e.y,o=e.z,c=e.w,l=2*(s*n-o*i),d=2*(o*t-a*n),m=2*(a*i-s*t);return this.x=t+c*l+s*m-o*d,this.y=i+c*d+o*l-a*m,this.z=n+c*m+a*d-s*l,this}project(e){return this.applyMatrix4(e.matrixWorldInverse).applyMatrix4(e.projectionMatrix)}unproject(e){return this.applyMatrix4(e.projectionMatrixInverse).applyMatrix4(e.matrixWorld)}transformDirection(e){const t=this.x,i=this.y,n=this.z,a=e.elements;return this.x=a[0]*t+a[4]*i+a[8]*n,this.y=a[1]*t+a[5]*i+a[9]*n,this.z=a[2]*t+a[6]*i+a[10]*n,this.normalize()}divide(e){return this.x/=e.x,this.y/=e.y,this.z/=e.z,this}divideScalar(e){return this.multiplyScalar(1/e)}min(e){return this.x=Math.min(this.x,e.x),this.y=Math.min(this.y,e.y),this.z=Math.min(this.z,e.z),this}max(e){return this.x=Math.max(this.x,e.x),this.y=Math.max(this.y,e.y),this.z=Math.max(this.z,e.z),this}clamp(e,t){return this.x=Be(this.x,e.x,t.x),this.y=Be(this.y,e.y,t.y),this.z=Be(this.z,e.z,t.z),this}clampScalar(e,t){return this.x=Be(this.x,e,t),this.y=Be(this.y,e,t),this.z=Be(this.z,e,t),this}clampLength(e,t){const i=this.length();return this.divideScalar(i||1).multiplyScalar(Be(i,e,t))}floor(){return this.x=Math.floor(this.x),this.y=Math.floor(this.y),this.z=Math.floor(this.z),this}ceil(){return this.x=Math.ceil(this.x),this.y=Math.ceil(this.y),this.z=Math.ceil(this.z),this}round(){return this.x=Math.round(this.x),this.y=Math.round(this.y),this.z=Math.round(this.z),this}roundToZero(){return this.x=Math.trunc(this.x),this.y=Math.trunc(this.y),this.z=Math.trunc(this.z),this}negate(){return this.x=-this.x,this.y=-this.y,this.z=-this.z,this}dot(e){return this.x*e.x+this.y*e.y+this.z*e.z}lengthSq(){return this.x*this.x+this.y*this.y+this.z*this.z}length(){return Math.sqrt(this.x*this.x+this.y*this.y+this.z*this.z)}manhattanLength(){return Math.abs(this.x)+Math.abs(this.y)+Math.abs(this.z)}normalize(){return this.divideScalar(this.length()||1)}setLength(e){return this.normalize().multiplyScalar(e)}lerp(e,t){return this.x+=(e.x-this.x)*t,this.y+=(e.y-this.y)*t,this.z+=(e.z-this.z)*t,this}lerpVectors(e,t,i){return this.x=e.x+(t.x-e.x)*i,this.y=e.y+(t.y-e.y)*i,this.z=e.z+(t.z-e.z)*i,this}cross(e){return this.crossVectors(this,e)}crossVectors(e,t){const i=e.x,n=e.y,a=e.z,s=t.x,o=t.y,c=t.z;return this.x=n*c-a*o,this.y=a*s-i*c,this.z=i*o-n*s,this}projectOnVector(e){const t=e.lengthSq();if(t===0)return this.set(0,0,0);const i=e.dot(this)/t;return this.copy(e).multiplyScalar(i)}projectOnPlane(e){return Fa.copy(this).projectOnVector(e),this.sub(Fa)}reflect(e){return this.sub(Fa.copy(e).multiplyScalar(2*this.dot(e)))}angleTo(e){const t=Math.sqrt(this.lengthSq()*e.lengthSq());if(t===0)return Math.PI/2;const i=this.dot(e)/t;return Math.acos(Be(i,-1,1))}distanceTo(e){return Math.sqrt(this.distanceToSquared(e))}distanceToSquared(e){const t=this.x-e.x,i=this.y-e.y,n=this.z-e.z;return t*t+i*i+n*n}manhattanDistanceTo(e){return Math.abs(this.x-e.x)+Math.abs(this.y-e.y)+Math.abs(this.z-e.z)}setFromSpherical(e){return this.setFromSphericalCoords(e.radius,e.phi,e.theta)}setFromSphericalCoords(e,t,i){const n=Math.sin(t)*e;return this.x=n*Math.sin(i),this.y=Math.cos(t)*e,this.z=n*Math.cos(i),this}setFromCylindrical(e){return this.setFromCylindricalCoords(e.radius,e.theta,e.y)}setFromCylindricalCoords(e,t,i){return this.x=e*Math.sin(t),this.y=i,this.z=e*Math.cos(t),this}setFromMatrixPosition(e){const t=e.elements;return this.x=t[12],this.y=t[13],this.z=t[14],this}setFromMatrixScale(e){const t=this.setFromMatrixColumn(e,0).length(),i=this.setFromMatrixColumn(e,1).length(),n=this.setFromMatrixColumn(e,2).length();return this.x=t,this.y=i,this.z=n,this}setFromMatrixColumn(e,t){return this.fromArray(e.elements,t*4)}setFromMatrix3Column(e,t){return this.fromArray(e.elements,t*3)}setFromEuler(e){return this.x=e._x,this.y=e._y,this.z=e._z,this}setFromColor(e){return this.x=e.r,this.y=e.g,this.z=e.b,this}equals(e){return e.x===this.x&&e.y===this.y&&e.z===this.z}fromArray(e,t=0){return this.x=e[t],this.y=e[t+1],this.z=e[t+2],this}toArray(e=[],t=0){return e[t]=this.x,e[t+1]=this.y,e[t+2]=this.z,e}fromBufferAttribute(e,t){return this.x=e.getX(t),this.y=e.getY(t),this.z=e.getZ(t),this}random(){return this.x=Math.random(),this.y=Math.random(),this.z=Math.random(),this}randomDirection(){const e=Math.random()*Math.PI*2,t=Math.random()*2-1,i=Math.sqrt(1-t*t);return this.x=i*Math.cos(e),this.y=t,this.z=i*Math.sin(e),this}*[Symbol.iterator](){yield this.x,yield this.y,yield this.z}};ms.prototype.isVector3=!0;let G=ms;const Fa=new G,oo=new $i,gs=class gs{constructor(e,t,i,n,a,s,o,c,l){this.elements=[1,0,0,0,1,0,0,0,1],e!==void 0&&this.set(e,t,i,n,a,s,o,c,l)}set(e,t,i,n,a,s,o,c,l){const d=this.elements;return d[0]=e,d[1]=n,d[2]=o,d[3]=t,d[4]=a,d[5]=c,d[6]=i,d[7]=s,d[8]=l,this}identity(){return this.set(1,0,0,0,1,0,0,0,1),this}copy(e){const t=this.elements,i=e.elements;return t[0]=i[0],t[1]=i[1],t[2]=i[2],t[3]=i[3],t[4]=i[4],t[5]=i[5],t[6]=i[6],t[7]=i[7],t[8]=i[8],this}extractBasis(e,t,i){return e.setFromMatrix3Column(this,0),t.setFromMatrix3Column(this,1),i.setFromMatrix3Column(this,2),this}setFromMatrix4(e){const t=e.elements;return this.set(t[0],t[4],t[8],t[1],t[5],t[9],t[2],t[6],t[10]),this}multiply(e){return this.multiplyMatrices(this,e)}premultiply(e){return this.multiplyMatrices(e,this)}multiplyMatrices(e,t){const i=e.elements,n=t.elements,a=this.elements,s=i[0],o=i[3],c=i[6],l=i[1],d=i[4],m=i[7],u=i[2],g=i[5],x=i[8],E=n[0],p=n[3],h=n[6],S=n[1],A=n[4],T=n[7],U=n[2],y=n[5],C=n[8];return a[0]=s*E+o*S+c*U,a[3]=s*p+o*A+c*y,a[6]=s*h+o*T+c*C,a[1]=l*E+d*S+m*U,a[4]=l*p+d*A+m*y,a[7]=l*h+d*T+m*C,a[2]=u*E+g*S+x*U,a[5]=u*p+g*A+x*y,a[8]=u*h+g*T+x*C,this}multiplyScalar(e){const t=this.elements;return t[0]*=e,t[3]*=e,t[6]*=e,t[1]*=e,t[4]*=e,t[7]*=e,t[2]*=e,t[5]*=e,t[8]*=e,this}determinant(){const e=this.elements,t=e[0],i=e[1],n=e[2],a=e[3],s=e[4],o=e[5],c=e[6],l=e[7],d=e[8];return t*s*d-t*o*l-i*a*d+i*o*c+n*a*l-n*s*c}invert(){const e=this.elements,t=e[0],i=e[1],n=e[2],a=e[3],s=e[4],o=e[5],c=e[6],l=e[7],d=e[8],m=d*s-o*l,u=o*c-d*a,g=l*a-s*c,x=t*m+i*u+n*g;if(x===0)return this.set(0,0,0,0,0,0,0,0,0);const E=1/x;return e[0]=m*E,e[1]=(n*l-d*i)*E,e[2]=(o*i-n*s)*E,e[3]=u*E,e[4]=(d*t-n*c)*E,e[5]=(n*a-o*t)*E,e[6]=g*E,e[7]=(i*c-l*t)*E,e[8]=(s*t-i*a)*E,this}transpose(){let e;const t=this.elements;return e=t[1],t[1]=t[3],t[3]=e,e=t[2],t[2]=t[6],t[6]=e,e=t[5],t[5]=t[7],t[7]=e,this}getNormalMatrix(e){return this.setFromMatrix4(e).invert().transpose()}transposeIntoArray(e){const t=this.elements;return e[0]=t[0],e[1]=t[3],e[2]=t[6],e[3]=t[1],e[4]=t[4],e[5]=t[7],e[6]=t[2],e[7]=t[5],e[8]=t[8],this}setUvTransform(e,t,i,n,a,s,o){const c=Math.cos(a),l=Math.sin(a);return this.set(i*c,i*l,-i*(c*s+l*o)+s+e,-n*l,n*c,-n*(-l*s+c*o)+o+t,0,0,1),this}scale(e,t){return this.premultiply(Oa.makeScale(e,t)),this}rotate(e){return this.premultiply(Oa.makeRotation(-e)),this}translate(e,t){return this.premultiply(Oa.makeTranslation(e,t)),this}makeTranslation(e,t){return e.isVector2?this.set(1,0,e.x,0,1,e.y,0,0,1):this.set(1,0,e,0,1,t,0,0,1),this}makeRotation(e){const t=Math.cos(e),i=Math.sin(e);return this.set(t,-i,0,i,t,0,0,0,1),this}makeScale(e,t){return this.set(e,0,0,0,t,0,0,0,1),this}equals(e){const t=this.elements,i=e.elements;for(let n=0;n<9;n++)if(t[n]!==i[n])return!1;return!0}fromArray(e,t=0){for(let i=0;i<9;i++)this.elements[i]=e[i+t];return this}toArray(e=[],t=0){const i=this.elements;return e[t]=i[0],e[t+1]=i[1],e[t+2]=i[2],e[t+3]=i[3],e[t+4]=i[4],e[t+5]=i[5],e[t+6]=i[6],e[t+7]=i[7],e[t+8]=i[8],e}clone(){return new this.constructor().fromArray(this.elements)}};gs.prototype.isMatrix3=!0;let Ce=gs;const Oa=new Ce,lo=new Ce().set(.4123908,.3575843,.1804808,.212639,.7151687,.0721923,.0193308,.1191948,.9505322),co=new Ce().set(3.2409699,-1.5373832,-.4986108,-.9692436,1.8759675,.0415551,.0556301,-.203977,1.0569715);function Bc(){const r={enabled:!0,workingColorSpace:Xr,spaces:{},convert:function(n,a,s){return this.enabled===!1||a===s||!a||!s||(this.spaces[a].transfer===Xe&&(n.r=ui(n.r),n.g=ui(n.g),n.b=ui(n.b)),this.spaces[a].primaries!==this.spaces[s].primaries&&(n.applyMatrix3(this.spaces[a].toXYZ),n.applyMatrix3(this.spaces[s].fromXYZ)),this.spaces[s].transfer===Xe&&(n.r=Qi(n.r),n.g=Qi(n.g),n.b=Qi(n.b))),n},workingToColorSpace:function(n,a){return this.convert(n,this.workingColorSpace,a)},colorSpaceToWorking:function(n,a){return this.convert(n,a,this.workingColorSpace)},getPrimaries:function(n){return this.spaces[n].primaries},getTransfer:function(n){return n===Mi?qr:this.spaces[n].transfer},getToneMappingMode:function(n){return this.spaces[n].outputColorSpaceConfig.toneMappingMode||"standard"},getLuminanceCoefficients:function(n,a=this.workingColorSpace){return n.fromArray(this.spaces[a].luminanceCoefficients)},define:function(n){Object.assign(this.spaces,n)},_getMatrix:function(n,a,s){return n.copy(this.spaces[a].toXYZ).multiply(this.spaces[s].fromXYZ)},_getDrawingBufferColorSpace:function(n){return this.spaces[n].outputColorSpaceConfig.drawingBufferColorSpace},_getUnpackColorSpace:function(n=this.workingColorSpace){return this.spaces[n].workingColorSpaceConfig.unpackColorSpace},fromWorkingColorSpace:function(n,a){return Da("ColorManagement: .fromWorkingColorSpace() has been renamed to .workingToColorSpace()."),r.workingToColorSpace(n,a)},toWorkingColorSpace:function(n,a){return Da("ColorManagement: .toWorkingColorSpace() has been renamed to .colorSpaceToWorking()."),r.colorSpaceToWorking(n,a)}},e=[.64,.33,.3,.6,.15,.06],t=[.2126,.7152,.0722],i=[.3127,.329];return r.define({[Xr]:{primaries:e,whitePoint:i,transfer:qr,toXYZ:lo,fromXYZ:co,luminanceCoefficients:t,workingColorSpaceConfig:{unpackColorSpace:At},outputColorSpaceConfig:{drawingBufferColorSpace:At}},[At]:{primaries:e,whitePoint:i,transfer:Xe,toXYZ:lo,fromXYZ:co,luminanceCoefficients:t,outputColorSpaceConfig:{drawingBufferColorSpace:At}}}),r}const ze=Bc();function ui(r){return r<.04045?r*.0773993808:Math.pow(r*.9478672986+.0521327014,2.4)}function Qi(r){return r<.0031308?r*12.92:1.055*Math.pow(r,.41666)-.055}let er;class zc{static getDataURL(e,t="image/png"){if(/^data:/i.test(e.src)||typeof HTMLCanvasElement>"u")return e.src;let i;if(e instanceof HTMLCanvasElement)i=e;else{er===void 0&&(er=Kr("canvas")),er.width=e.width,er.height=e.height;const n=er.getContext("2d");e instanceof ImageData?n.putImageData(e,0,0):n.drawImage(e,0,0,e.width,e.height),i=er}return i.toDataURL(t)}static sRGBToLinear(e){if(typeof HTMLImageElement<"u"&&e instanceof HTMLImageElement||typeof HTMLCanvasElement<"u"&&e instanceof HTMLCanvasElement||typeof ImageBitmap<"u"&&e instanceof ImageBitmap){const t=Kr("canvas");t.width=e.width,t.height=e.height;const i=t.getContext("2d");i.drawImage(e,0,0,e.width,e.height);const n=i.getImageData(0,0,e.width,e.height),a=n.data;for(let s=0;s<a.length;s++)a[s]=ui(a[s]/255)*255;return i.putImageData(n,0,0),t}else if(e.data){const t=e.data.slice(0);for(let i=0;i<t.length;i++)t instanceof Uint8Array||t instanceof Uint8ClampedArray?t[i]=Math.floor(ui(t[i]/255)*255):t[i]=ui(t[i]);return{data:t,width:e.width,height:e.height}}else return Ae("ImageUtils.sRGBToLinear(): Unsupported image type. No color space conversion applied."),e}}let Gc=0;class Ba{constructor(e=null){this.isSource=!0,Object.defineProperty(this,"id",{value:Gc++}),this.uuid=Sr(),this.data=e,this.dataReady=!0,this.version=0}getSize(e){const t=this.data;return typeof HTMLVideoElement<"u"&&t instanceof HTMLVideoElement?e.set(t.videoWidth,t.videoHeight,0):typeof VideoFrame<"u"&&t instanceof VideoFrame?e.set(t.displayWidth,t.displayHeight,0):t!==null?e.set(t.width,t.height,t.depth||0):e.set(0,0,0),e}set needsUpdate(e){e===!0&&this.version++}toJSON(e){const t=e===void 0||typeof e=="string";if(!t&&e.images[this.uuid]!==void 0)return e.images[this.uuid];const i={uuid:this.uuid,url:""},n=this.data;if(n!==null){let a;if(Array.isArray(n)){a=[];for(let s=0,o=n.length;s<o;s++)n[s].isDataTexture?a.push(za(n[s].image)):a.push(za(n[s]))}else a=za(n);i.url=a}return t||(e.images[this.uuid]=i),i}}function za(r){return typeof HTMLImageElement<"u"&&r instanceof HTMLImageElement||typeof HTMLCanvasElement<"u"&&r instanceof HTMLCanvasElement||typeof ImageBitmap<"u"&&r instanceof ImageBitmap?zc.getDataURL(r):r.data?{data:Array.from(r.data),width:r.width,height:r.height,type:r.data.constructor.name}:(Ae("Texture: Unable to serialize Texture."),{})}let Hc=0;const Ga=new G;class yt extends Bi{constructor(e=yt.DEFAULT_IMAGE,t=yt.DEFAULT_MAPPING,i=oi,n=oi,a=vt,s=Ni,o=Ot,c=Lt,l=yt.DEFAULT_ANISOTROPY,d=Mi){super(),this.isTexture=!0,Object.defineProperty(this,"id",{value:Hc++}),this.uuid=Sr(),this.name="",this.source=new Ba(e),this.mipmaps=[],this.mapping=t,this.channel=0,this.wrapS=i,this.wrapT=n,this.magFilter=a,this.minFilter=s,this.anisotropy=l,this.format=o,this.internalFormat=null,this.type=c,this.offset=new Ke(0,0),this.repeat=new Ke(1,1),this.center=new Ke(0,0),this.rotation=0,this.matrixAutoUpdate=!0,this.matrix=new Ce,this.generateMipmaps=!0,this.premultiplyAlpha=!1,this.flipY=!0,this.unpackAlignment=4,this.colorSpace=d,this.userData={},this.updateRanges=[],this.version=0,this.onUpdate=null,this.renderTarget=null,this.isRenderTargetTexture=!1,this.isArrayTexture=!!(e&&e.depth&&e.depth>1),this.pmremVersion=0,this.normalized=!1}get width(){return this.source.getSize(Ga).x}get height(){return this.source.getSize(Ga).y}get depth(){return this.source.getSize(Ga).z}get image(){return this.source.data}set image(e){this.source.data=e}updateMatrix(){this.matrix.setUvTransform(this.offset.x,this.offset.y,this.repeat.x,this.repeat.y,this.rotation,this.center.x,this.center.y)}addUpdateRange(e,t){this.updateRanges.push({start:e,count:t})}clearUpdateRanges(){this.updateRanges.length=0}clone(){return new this.constructor().copy(this)}copy(e){return this.name=e.name,this.source=e.source,this.mipmaps=e.mipmaps.slice(0),this.mapping=e.mapping,this.channel=e.channel,this.wrapS=e.wrapS,this.wrapT=e.wrapT,this.magFilter=e.magFilter,this.minFilter=e.minFilter,this.anisotropy=e.anisotropy,this.format=e.format,this.internalFormat=e.internalFormat,this.type=e.type,this.normalized=e.normalized,this.offset.copy(e.offset),this.repeat.copy(e.repeat),this.center.copy(e.center),this.rotation=e.rotation,this.matrixAutoUpdate=e.matrixAutoUpdate,this.matrix.copy(e.matrix),this.generateMipmaps=e.generateMipmaps,this.premultiplyAlpha=e.premultiplyAlpha,this.flipY=e.flipY,this.unpackAlignment=e.unpackAlignment,this.colorSpace=e.colorSpace,this.renderTarget=e.renderTarget,this.isRenderTargetTexture=e.isRenderTargetTexture,this.isArrayTexture=e.isArrayTexture,this.userData=JSON.parse(JSON.stringify(e.userData)),this.needsUpdate=!0,this}setValues(e){for(const t in e){const i=e[t];if(i===void 0){Ae(`Texture.setValues(): parameter '${t}' has value of undefined.`);continue}const n=this[t];if(n===void 0){Ae(`Texture.setValues(): property '${t}' does not exist.`);continue}n&&i&&n.isVector2&&i.isVector2||n&&i&&n.isVector3&&i.isVector3||n&&i&&n.isMatrix3&&i.isMatrix3?n.copy(i):this[t]=i}}toJSON(e){const t=e===void 0||typeof e=="string";if(!t&&e.textures[this.uuid]!==void 0)return e.textures[this.uuid];const i={metadata:{version:4.7,type:"Texture",generator:"Texture.toJSON"},uuid:this.uuid,name:this.name,image:this.source.toJSON(e).uuid,mapping:this.mapping,channel:this.channel,repeat:[this.repeat.x,this.repeat.y],offset:[this.offset.x,this.offset.y],center:[this.center.x,this.center.y],rotation:this.rotation,wrap:[this.wrapS,this.wrapT],format:this.format,internalFormat:this.internalFormat,type:this.type,normalized:this.normalized,colorSpace:this.colorSpace,minFilter:this.minFilter,magFilter:this.magFilter,anisotropy:this.anisotropy,flipY:this.flipY,generateMipmaps:this.generateMipmaps,premultiplyAlpha:this.premultiplyAlpha,unpackAlignment:this.unpackAlignment};return Object.keys(this.userData).length>0&&(i.userData=this.userData),t||(e.textures[this.uuid]=i),i}dispose(){this.dispatchEvent({type:"dispose"})}transformUv(e){if(this.mapping!==qs)return e;if(e.applyMatrix3(this.matrix),e.x<0||e.x>1)switch(this.wrapS){case Xn:e.x=e.x-Math.floor(e.x);break;case oi:e.x=e.x<0?0:1;break;case qn:Math.abs(Math.floor(e.x)%2)===1?e.x=Math.ceil(e.x)-e.x:e.x=e.x-Math.floor(e.x);break}if(e.y<0||e.y>1)switch(this.wrapT){case Xn:e.y=e.y-Math.floor(e.y);break;case oi:e.y=e.y<0?0:1;break;case qn:Math.abs(Math.floor(e.y)%2)===1?e.y=Math.ceil(e.y)-e.y:e.y=e.y-Math.floor(e.y);break}return this.flipY&&(e.y=1-e.y),e}set needsUpdate(e){e===!0&&(this.version++,this.source.needsUpdate=!0)}set needsPMREMUpdate(e){e===!0&&this.pmremVersion++}}yt.DEFAULT_IMAGE=null,yt.DEFAULT_MAPPING=qs,yt.DEFAULT_ANISOTROPY=1;const _s=class _s{constructor(e=0,t=0,i=0,n=1){this.x=e,this.y=t,this.z=i,this.w=n}get width(){return this.z}set width(e){this.z=e}get height(){return this.w}set height(e){this.w=e}set(e,t,i,n){return this.x=e,this.y=t,this.z=i,this.w=n,this}setScalar(e){return this.x=e,this.y=e,this.z=e,this.w=e,this}setX(e){return this.x=e,this}setY(e){return this.y=e,this}setZ(e){return this.z=e,this}setW(e){return this.w=e,this}setComponent(e,t){switch(e){case 0:this.x=t;break;case 1:this.y=t;break;case 2:this.z=t;break;case 3:this.w=t;break;default:throw new Error("index is out of range: "+e)}return this}getComponent(e){switch(e){case 0:return this.x;case 1:return this.y;case 2:return this.z;case 3:return this.w;default:throw new Error("index is out of range: "+e)}}clone(){return new this.constructor(this.x,this.y,this.z,this.w)}copy(e){return this.x=e.x,this.y=e.y,this.z=e.z,this.w=e.w!==void 0?e.w:1,this}add(e){return this.x+=e.x,this.y+=e.y,this.z+=e.z,this.w+=e.w,this}addScalar(e){return this.x+=e,this.y+=e,this.z+=e,this.w+=e,this}addVectors(e,t){return this.x=e.x+t.x,this.y=e.y+t.y,this.z=e.z+t.z,this.w=e.w+t.w,this}addScaledVector(e,t){return this.x+=e.x*t,this.y+=e.y*t,this.z+=e.z*t,this.w+=e.w*t,this}sub(e){return this.x-=e.x,this.y-=e.y,this.z-=e.z,this.w-=e.w,this}subScalar(e){return this.x-=e,this.y-=e,this.z-=e,this.w-=e,this}subVectors(e,t){return this.x=e.x-t.x,this.y=e.y-t.y,this.z=e.z-t.z,this.w=e.w-t.w,this}multiply(e){return this.x*=e.x,this.y*=e.y,this.z*=e.z,this.w*=e.w,this}multiplyScalar(e){return this.x*=e,this.y*=e,this.z*=e,this.w*=e,this}applyMatrix4(e){const t=this.x,i=this.y,n=this.z,a=this.w,s=e.elements;return this.x=s[0]*t+s[4]*i+s[8]*n+s[12]*a,this.y=s[1]*t+s[5]*i+s[9]*n+s[13]*a,this.z=s[2]*t+s[6]*i+s[10]*n+s[14]*a,this.w=s[3]*t+s[7]*i+s[11]*n+s[15]*a,this}divide(e){return this.x/=e.x,this.y/=e.y,this.z/=e.z,this.w/=e.w,this}divideScalar(e){return this.multiplyScalar(1/e)}setAxisAngleFromQuaternion(e){this.w=2*Math.acos(e.w);const t=Math.sqrt(1-e.w*e.w);return t<1e-4?(this.x=1,this.y=0,this.z=0):(this.x=e.x/t,this.y=e.y/t,this.z=e.z/t),this}setAxisAngleFromRotationMatrix(e){let t,i,n,a;const s=e.elements,o=s[0],c=s[4],l=s[8],d=s[1],m=s[5],u=s[9],g=s[2],x=s[6],E=s[10];if(Math.abs(c-d)<.01&&Math.abs(l-g)<.01&&Math.abs(u-x)<.01){if(Math.abs(c+d)<.1&&Math.abs(l+g)<.1&&Math.abs(u+x)<.1&&Math.abs(o+m+E-3)<.1)return this.set(1,0,0,0),this;t=Math.PI;const h=(o+1)/2,S=(m+1)/2,A=(E+1)/2,T=(c+d)/4,U=(l+g)/4,y=(u+x)/4;return h>S&&h>A?h<.01?(i=0,n=.707106781,a=.707106781):(i=Math.sqrt(h),n=T/i,a=U/i):S>A?S<.01?(i=.707106781,n=0,a=.707106781):(n=Math.sqrt(S),i=T/n,a=y/n):A<.01?(i=.707106781,n=.707106781,a=0):(a=Math.sqrt(A),i=U/a,n=y/a),this.set(i,n,a,t),this}let p=Math.sqrt((x-u)*(x-u)+(l-g)*(l-g)+(d-c)*(d-c));return Math.abs(p)<.001&&(p=1),this.x=(x-u)/p,this.y=(l-g)/p,this.z=(d-c)/p,this.w=Math.acos((o+m+E-1)/2),this}setFromMatrixPosition(e){const t=e.elements;return this.x=t[12],this.y=t[13],this.z=t[14],this.w=t[15],this}min(e){return this.x=Math.min(this.x,e.x),this.y=Math.min(this.y,e.y),this.z=Math.min(this.z,e.z),this.w=Math.min(this.w,e.w),this}max(e){return this.x=Math.max(this.x,e.x),this.y=Math.max(this.y,e.y),this.z=Math.max(this.z,e.z),this.w=Math.max(this.w,e.w),this}clamp(e,t){return this.x=Be(this.x,e.x,t.x),this.y=Be(this.y,e.y,t.y),this.z=Be(this.z,e.z,t.z),this.w=Be(this.w,e.w,t.w),this}clampScalar(e,t){return this.x=Be(this.x,e,t),this.y=Be(this.y,e,t),this.z=Be(this.z,e,t),this.w=Be(this.w,e,t),this}clampLength(e,t){const i=this.length();return this.divideScalar(i||1).multiplyScalar(Be(i,e,t))}floor(){return this.x=Math.floor(this.x),this.y=Math.floor(this.y),this.z=Math.floor(this.z),this.w=Math.floor(this.w),this}ceil(){return this.x=Math.ceil(this.x),this.y=Math.ceil(this.y),this.z=Math.ceil(this.z),this.w=Math.ceil(this.w),this}round(){return this.x=Math.round(this.x),this.y=Math.round(this.y),this.z=Math.round(this.z),this.w=Math.round(this.w),this}roundToZero(){return this.x=Math.trunc(this.x),this.y=Math.trunc(this.y),this.z=Math.trunc(this.z),this.w=Math.trunc(this.w),this}negate(){return this.x=-this.x,this.y=-this.y,this.z=-this.z,this.w=-this.w,this}dot(e){return this.x*e.x+this.y*e.y+this.z*e.z+this.w*e.w}lengthSq(){return this.x*this.x+this.y*this.y+this.z*this.z+this.w*this.w}length(){return Math.sqrt(this.x*this.x+this.y*this.y+this.z*this.z+this.w*this.w)}manhattanLength(){return Math.abs(this.x)+Math.abs(this.y)+Math.abs(this.z)+Math.abs(this.w)}normalize(){return this.divideScalar(this.length()||1)}setLength(e){return this.normalize().multiplyScalar(e)}lerp(e,t){return this.x+=(e.x-this.x)*t,this.y+=(e.y-this.y)*t,this.z+=(e.z-this.z)*t,this.w+=(e.w-this.w)*t,this}lerpVectors(e,t,i){return this.x=e.x+(t.x-e.x)*i,this.y=e.y+(t.y-e.y)*i,this.z=e.z+(t.z-e.z)*i,this.w=e.w+(t.w-e.w)*i,this}equals(e){return e.x===this.x&&e.y===this.y&&e.z===this.z&&e.w===this.w}fromArray(e,t=0){return this.x=e[t],this.y=e[t+1],this.z=e[t+2],this.w=e[t+3],this}toArray(e=[],t=0){return e[t]=this.x,e[t+1]=this.y,e[t+2]=this.z,e[t+3]=this.w,e}fromBufferAttribute(e,t){return this.x=e.getX(t),this.y=e.getY(t),this.z=e.getZ(t),this.w=e.getW(t),this}random(){return this.x=Math.random(),this.y=Math.random(),this.z=Math.random(),this.w=Math.random(),this}*[Symbol.iterator](){yield this.x,yield this.y,yield this.z,yield this.w}};_s.prototype.isVector4=!0;let ot=_s;class Vc extends Bi{constructor(e=1,t=1,i={}){super(),i=Object.assign({generateMipmaps:!1,internalFormat:null,minFilter:vt,depthBuffer:!0,stencilBuffer:!1,resolveDepthBuffer:!0,resolveStencilBuffer:!0,depthTexture:null,samples:0,count:1,depth:1,multiview:!1},i),this.isRenderTarget=!0,this.width=e,this.height=t,this.depth=i.depth,this.scissor=new ot(0,0,e,t),this.scissorTest=!1,this.viewport=new ot(0,0,e,t),this.textures=[];const n={width:e,height:t,depth:i.depth},a=new yt(n),s=i.count;for(let o=0;o<s;o++)this.textures[o]=a.clone(),this.textures[o].isRenderTargetTexture=!0,this.textures[o].renderTarget=this;this._setTextureOptions(i),this.depthBuffer=i.depthBuffer,this.stencilBuffer=i.stencilBuffer,this.resolveDepthBuffer=i.resolveDepthBuffer,this.resolveStencilBuffer=i.resolveStencilBuffer,this._depthTexture=null,this.depthTexture=i.depthTexture,this.samples=i.samples,this.multiview=i.multiview}_setTextureOptions(e={}){const t={minFilter:vt,generateMipmaps:!1,flipY:!1,internalFormat:null};e.mapping!==void 0&&(t.mapping=e.mapping),e.wrapS!==void 0&&(t.wrapS=e.wrapS),e.wrapT!==void 0&&(t.wrapT=e.wrapT),e.wrapR!==void 0&&(t.wrapR=e.wrapR),e.magFilter!==void 0&&(t.magFilter=e.magFilter),e.minFilter!==void 0&&(t.minFilter=e.minFilter),e.format!==void 0&&(t.format=e.format),e.type!==void 0&&(t.type=e.type),e.anisotropy!==void 0&&(t.anisotropy=e.anisotropy),e.colorSpace!==void 0&&(t.colorSpace=e.colorSpace),e.flipY!==void 0&&(t.flipY=e.flipY),e.generateMipmaps!==void 0&&(t.generateMipmaps=e.generateMipmaps),e.internalFormat!==void 0&&(t.internalFormat=e.internalFormat);for(let i=0;i<this.textures.length;i++)this.textures[i].setValues(t)}get texture(){return this.textures[0]}set texture(e){this.textures[0]=e}set depthTexture(e){this._depthTexture!==null&&(this._depthTexture.renderTarget=null),e!==null&&(e.renderTarget=this),this._depthTexture=e}get depthTexture(){return this._depthTexture}setSize(e,t,i=1){if(this.width!==e||this.height!==t||this.depth!==i){this.width=e,this.height=t,this.depth=i;for(let n=0,a=this.textures.length;n<a;n++)this.textures[n].image.width=e,this.textures[n].image.height=t,this.textures[n].image.depth=i,this.textures[n].isData3DTexture!==!0&&(this.textures[n].isArrayTexture=this.textures[n].image.depth>1);this.dispose()}this.viewport.set(0,0,e,t),this.scissor.set(0,0,e,t)}clone(){return new this.constructor().copy(this)}copy(e){this.width=e.width,this.height=e.height,this.depth=e.depth,this.scissor.copy(e.scissor),this.scissorTest=e.scissorTest,this.viewport.copy(e.viewport),this.textures.length=0;for(let t=0,i=e.textures.length;t<i;t++){this.textures[t]=e.textures[t].clone(),this.textures[t].isRenderTargetTexture=!0,this.textures[t].renderTarget=this;const n=Object.assign({},e.textures[t].image);this.textures[t].source=new Ba(n)}return this.depthBuffer=e.depthBuffer,this.stencilBuffer=e.stencilBuffer,this.resolveDepthBuffer=e.resolveDepthBuffer,this.resolveStencilBuffer=e.resolveStencilBuffer,e.depthTexture!==null&&(this.depthTexture=e.depthTexture.clone()),this.samples=e.samples,this.multiview=e.multiview,this}dispose(){this.dispatchEvent({type:"dispose"})}}class Jt extends Vc{constructor(e=1,t=1,i={}){super(e,t,i),this.isWebGLRenderTarget=!0}}class uo extends yt{constructor(e=null,t=1,i=1,n=1){super(null),this.isDataArrayTexture=!0,this.image={data:e,width:t,height:i,depth:n},this.magFilter=_t,this.minFilter=_t,this.wrapR=oi,this.generateMipmaps=!1,this.flipY=!1,this.unpackAlignment=1,this.layerUpdates=new Set}addLayerUpdate(e){this.layerUpdates.add(e)}clearLayerUpdates(){this.layerUpdates.clear()}}class kc extends yt{constructor(e=null,t=1,i=1,n=1){super(null),this.isData3DTexture=!0,this.image={data:e,width:t,height:i,depth:n},this.magFilter=_t,this.minFilter=_t,this.wrapR=oi,this.generateMipmaps=!1,this.flipY=!1,this.unpackAlignment=1}}const wn=class wn{constructor(e,t,i,n,a,s,o,c,l,d,m,u,g,x,E,p){this.elements=[1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1],e!==void 0&&this.set(e,t,i,n,a,s,o,c,l,d,m,u,g,x,E,p)}set(e,t,i,n,a,s,o,c,l,d,m,u,g,x,E,p){const h=this.elements;return h[0]=e,h[4]=t,h[8]=i,h[12]=n,h[1]=a,h[5]=s,h[9]=o,h[13]=c,h[2]=l,h[6]=d,h[10]=m,h[14]=u,h[3]=g,h[7]=x,h[11]=E,h[15]=p,this}identity(){return this.set(1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1),this}clone(){return new wn().fromArray(this.elements)}copy(e){const t=this.elements,i=e.elements;return t[0]=i[0],t[1]=i[1],t[2]=i[2],t[3]=i[3],t[4]=i[4],t[5]=i[5],t[6]=i[6],t[7]=i[7],t[8]=i[8],t[9]=i[9],t[10]=i[10],t[11]=i[11],t[12]=i[12],t[13]=i[13],t[14]=i[14],t[15]=i[15],this}copyPosition(e){const t=this.elements,i=e.elements;return t[12]=i[12],t[13]=i[13],t[14]=i[14],this}setFromMatrix3(e){const t=e.elements;return this.set(t[0],t[3],t[6],0,t[1],t[4],t[7],0,t[2],t[5],t[8],0,0,0,0,1),this}extractBasis(e,t,i){return this.determinant()===0?(e.set(1,0,0),t.set(0,1,0),i.set(0,0,1),this):(e.setFromMatrixColumn(this,0),t.setFromMatrixColumn(this,1),i.setFromMatrixColumn(this,2),this)}makeBasis(e,t,i){return this.set(e.x,t.x,i.x,0,e.y,t.y,i.y,0,e.z,t.z,i.z,0,0,0,0,1),this}extractRotation(e){if(e.determinant()===0)return this.identity();const t=this.elements,i=e.elements,n=1/tr.setFromMatrixColumn(e,0).length(),a=1/tr.setFromMatrixColumn(e,1).length(),s=1/tr.setFromMatrixColumn(e,2).length();return t[0]=i[0]*n,t[1]=i[1]*n,t[2]=i[2]*n,t[3]=0,t[4]=i[4]*a,t[5]=i[5]*a,t[6]=i[6]*a,t[7]=0,t[8]=i[8]*s,t[9]=i[9]*s,t[10]=i[10]*s,t[11]=0,t[12]=0,t[13]=0,t[14]=0,t[15]=1,this}makeRotationFromEuler(e){const t=this.elements,i=e.x,n=e.y,a=e.z,s=Math.cos(i),o=Math.sin(i),c=Math.cos(n),l=Math.sin(n),d=Math.cos(a),m=Math.sin(a);if(e.order==="XYZ"){const u=s*d,g=s*m,x=o*d,E=o*m;t[0]=c*d,t[4]=-c*m,t[8]=l,t[1]=g+x*l,t[5]=u-E*l,t[9]=-o*c,t[2]=E-u*l,t[6]=x+g*l,t[10]=s*c}else if(e.order==="YXZ"){const u=c*d,g=c*m,x=l*d,E=l*m;t[0]=u+E*o,t[4]=x*o-g,t[8]=s*l,t[1]=s*m,t[5]=s*d,t[9]=-o,t[2]=g*o-x,t[6]=E+u*o,t[10]=s*c}else if(e.order==="ZXY"){const u=c*d,g=c*m,x=l*d,E=l*m;t[0]=u-E*o,t[4]=-s*m,t[8]=x+g*o,t[1]=g+x*o,t[5]=s*d,t[9]=E-u*o,t[2]=-s*l,t[6]=o,t[10]=s*c}else if(e.order==="ZYX"){const u=s*d,g=s*m,x=o*d,E=o*m;t[0]=c*d,t[4]=x*l-g,t[8]=u*l+E,t[1]=c*m,t[5]=E*l+u,t[9]=g*l-x,t[2]=-l,t[6]=o*c,t[10]=s*c}else if(e.order==="YZX"){const u=s*c,g=s*l,x=o*c,E=o*l;t[0]=c*d,t[4]=E-u*m,t[8]=x*m+g,t[1]=m,t[5]=s*d,t[9]=-o*d,t[2]=-l*d,t[6]=g*m+x,t[10]=u-E*m}else if(e.order==="XZY"){const u=s*c,g=s*l,x=o*c,E=o*l;t[0]=c*d,t[4]=-m,t[8]=l*d,t[1]=u*m+E,t[5]=s*d,t[9]=g*m-x,t[2]=x*m-g,t[6]=o*d,t[10]=E*m+u}return t[3]=0,t[7]=0,t[11]=0,t[12]=0,t[13]=0,t[14]=0,t[15]=1,this}makeRotationFromQuaternion(e){return this.compose(Wc,e,Xc)}lookAt(e,t,i){const n=this.elements;return Pt.subVectors(e,t),Pt.lengthSq()===0&&(Pt.z=1),Pt.normalize(),Si.crossVectors(i,Pt),Si.lengthSq()===0&&(Math.abs(i.z)===1?Pt.x+=1e-4:Pt.z+=1e-4,Pt.normalize(),Si.crossVectors(i,Pt)),Si.normalize(),Jr.crossVectors(Pt,Si),n[0]=Si.x,n[4]=Jr.x,n[8]=Pt.x,n[1]=Si.y,n[5]=Jr.y,n[9]=Pt.y,n[2]=Si.z,n[6]=Jr.z,n[10]=Pt.z,this}multiply(e){return this.multiplyMatrices(this,e)}premultiply(e){return this.multiplyMatrices(e,this)}multiplyMatrices(e,t){const i=e.elements,n=t.elements,a=this.elements,s=i[0],o=i[4],c=i[8],l=i[12],d=i[1],m=i[5],u=i[9],g=i[13],x=i[2],E=i[6],p=i[10],h=i[14],S=i[3],A=i[7],T=i[11],U=i[15],y=n[0],C=n[4],v=n[8],b=n[12],F=n[1],w=n[5],N=n[9],W=n[13],q=n[2],L=n[6],V=n[10],H=n[14],Z=n[3],Q=n[7],re=n[11],ve=n[15];return a[0]=s*y+o*F+c*q+l*Z,a[4]=s*C+o*w+c*L+l*Q,a[8]=s*v+o*N+c*V+l*re,a[12]=s*b+o*W+c*H+l*ve,a[1]=d*y+m*F+u*q+g*Z,a[5]=d*C+m*w+u*L+g*Q,a[9]=d*v+m*N+u*V+g*re,a[13]=d*b+m*W+u*H+g*ve,a[2]=x*y+E*F+p*q+h*Z,a[6]=x*C+E*w+p*L+h*Q,a[10]=x*v+E*N+p*V+h*re,a[14]=x*b+E*W+p*H+h*ve,a[3]=S*y+A*F+T*q+U*Z,a[7]=S*C+A*w+T*L+U*Q,a[11]=S*v+A*N+T*V+U*re,a[15]=S*b+A*W+T*H+U*ve,this}multiplyScalar(e){const t=this.elements;return t[0]*=e,t[4]*=e,t[8]*=e,t[12]*=e,t[1]*=e,t[5]*=e,t[9]*=e,t[13]*=e,t[2]*=e,t[6]*=e,t[10]*=e,t[14]*=e,t[3]*=e,t[7]*=e,t[11]*=e,t[15]*=e,this}determinant(){const e=this.elements,t=e[0],i=e[4],n=e[8],a=e[12],s=e[1],o=e[5],c=e[9],l=e[13],d=e[2],m=e[6],u=e[10],g=e[14],x=e[3],E=e[7],p=e[11],h=e[15],S=c*g-l*u,A=o*g-l*m,T=o*u-c*m,U=s*g-l*d,y=s*u-c*d,C=s*m-o*d;return t*(E*S-p*A+h*T)-i*(x*S-p*U+h*y)+n*(x*A-E*U+h*C)-a*(x*T-E*y+p*C)}transpose(){const e=this.elements;let t;return t=e[1],e[1]=e[4],e[4]=t,t=e[2],e[2]=e[8],e[8]=t,t=e[6],e[6]=e[9],e[9]=t,t=e[3],e[3]=e[12],e[12]=t,t=e[7],e[7]=e[13],e[13]=t,t=e[11],e[11]=e[14],e[14]=t,this}setPosition(e,t,i){const n=this.elements;return e.isVector3?(n[12]=e.x,n[13]=e.y,n[14]=e.z):(n[12]=e,n[13]=t,n[14]=i),this}invert(){const e=this.elements,t=e[0],i=e[1],n=e[2],a=e[3],s=e[4],o=e[5],c=e[6],l=e[7],d=e[8],m=e[9],u=e[10],g=e[11],x=e[12],E=e[13],p=e[14],h=e[15],S=t*o-i*s,A=t*c-n*s,T=t*l-a*s,U=i*c-n*o,y=i*l-a*o,C=n*l-a*c,v=d*E-m*x,b=d*p-u*x,F=d*h-g*x,w=m*p-u*E,N=m*h-g*E,W=u*h-g*p,q=S*W-A*N+T*w+U*F-y*b+C*v;if(q===0)return this.set(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);const L=1/q;return e[0]=(o*W-c*N+l*w)*L,e[1]=(n*N-i*W-a*w)*L,e[2]=(E*C-p*y+h*U)*L,e[3]=(u*y-m*C-g*U)*L,e[4]=(c*F-s*W-l*b)*L,e[5]=(t*W-n*F+a*b)*L,e[6]=(p*T-x*C-h*A)*L,e[7]=(d*C-u*T+g*A)*L,e[8]=(s*N-o*F+l*v)*L,e[9]=(i*F-t*N-a*v)*L,e[10]=(x*y-E*T+h*S)*L,e[11]=(m*T-d*y-g*S)*L,e[12]=(o*b-s*w-c*v)*L,e[13]=(t*w-i*b+n*v)*L,e[14]=(E*A-x*U-p*S)*L,e[15]=(d*U-m*A+u*S)*L,this}scale(e){const t=this.elements,i=e.x,n=e.y,a=e.z;return t[0]*=i,t[4]*=n,t[8]*=a,t[1]*=i,t[5]*=n,t[9]*=a,t[2]*=i,t[6]*=n,t[10]*=a,t[3]*=i,t[7]*=n,t[11]*=a,this}getMaxScaleOnAxis(){const e=this.elements,t=e[0]*e[0]+e[1]*e[1]+e[2]*e[2],i=e[4]*e[4]+e[5]*e[5]+e[6]*e[6],n=e[8]*e[8]+e[9]*e[9]+e[10]*e[10];return Math.sqrt(Math.max(t,i,n))}makeTranslation(e,t,i){return e.isVector3?this.set(1,0,0,e.x,0,1,0,e.y,0,0,1,e.z,0,0,0,1):this.set(1,0,0,e,0,1,0,t,0,0,1,i,0,0,0,1),this}makeRotationX(e){const t=Math.cos(e),i=Math.sin(e);return this.set(1,0,0,0,0,t,-i,0,0,i,t,0,0,0,0,1),this}makeRotationY(e){const t=Math.cos(e),i=Math.sin(e);return this.set(t,0,i,0,0,1,0,0,-i,0,t,0,0,0,0,1),this}makeRotationZ(e){const t=Math.cos(e),i=Math.sin(e);return this.set(t,-i,0,0,i,t,0,0,0,0,1,0,0,0,0,1),this}makeRotationAxis(e,t){const i=Math.cos(t),n=Math.sin(t),a=1-i,s=e.x,o=e.y,c=e.z,l=a*s,d=a*o;return this.set(l*s+i,l*o-n*c,l*c+n*o,0,l*o+n*c,d*o+i,d*c-n*s,0,l*c-n*o,d*c+n*s,a*c*c+i,0,0,0,0,1),this}makeScale(e,t,i){return this.set(e,0,0,0,0,t,0,0,0,0,i,0,0,0,0,1),this}makeShear(e,t,i,n,a,s){return this.set(1,i,a,0,e,1,s,0,t,n,1,0,0,0,0,1),this}compose(e,t,i){const n=this.elements,a=t._x,s=t._y,o=t._z,c=t._w,l=a+a,d=s+s,m=o+o,u=a*l,g=a*d,x=a*m,E=s*d,p=s*m,h=o*m,S=c*l,A=c*d,T=c*m,U=i.x,y=i.y,C=i.z;return n[0]=(1-(E+h))*U,n[1]=(g+T)*U,n[2]=(x-A)*U,n[3]=0,n[4]=(g-T)*y,n[5]=(1-(u+h))*y,n[6]=(p+S)*y,n[7]=0,n[8]=(x+A)*C,n[9]=(p-S)*C,n[10]=(1-(u+E))*C,n[11]=0,n[12]=e.x,n[13]=e.y,n[14]=e.z,n[15]=1,this}decompose(e,t,i){const n=this.elements;e.x=n[12],e.y=n[13],e.z=n[14];const a=this.determinant();if(a===0)return i.set(1,1,1),t.identity(),this;let s=tr.set(n[0],n[1],n[2]).length();const o=tr.set(n[4],n[5],n[6]).length(),c=tr.set(n[8],n[9],n[10]).length();a<0&&(s=-s),Bt.copy(this);const l=1/s,d=1/o,m=1/c;return Bt.elements[0]*=l,Bt.elements[1]*=l,Bt.elements[2]*=l,Bt.elements[4]*=d,Bt.elements[5]*=d,Bt.elements[6]*=d,Bt.elements[8]*=m,Bt.elements[9]*=m,Bt.elements[10]*=m,t.setFromRotationMatrix(Bt),i.x=s,i.y=o,i.z=c,this}makePerspective(e,t,i,n,a,s,o=Kt,c=!1){const l=this.elements,d=2*a/(t-e),m=2*a/(i-n),u=(t+e)/(t-e),g=(i+n)/(i-n);let x,E;if(c)x=a/(s-a),E=s*a/(s-a);else if(o===Kt)x=-(s+a)/(s-a),E=-2*s*a/(s-a);else if(o===jr)x=-s/(s-a),E=-s*a/(s-a);else throw new Error("THREE.Matrix4.makePerspective(): Invalid coordinate system: "+o);return l[0]=d,l[4]=0,l[8]=u,l[12]=0,l[1]=0,l[5]=m,l[9]=g,l[13]=0,l[2]=0,l[6]=0,l[10]=x,l[14]=E,l[3]=0,l[7]=0,l[11]=-1,l[15]=0,this}makeOrthographic(e,t,i,n,a,s,o=Kt,c=!1){const l=this.elements,d=2/(t-e),m=2/(i-n),u=-(t+e)/(t-e),g=-(i+n)/(i-n);let x,E;if(c)x=1/(s-a),E=s/(s-a);else if(o===Kt)x=-2/(s-a),E=-(s+a)/(s-a);else if(o===jr)x=-1/(s-a),E=-a/(s-a);else throw new Error("THREE.Matrix4.makeOrthographic(): Invalid coordinate system: "+o);return l[0]=d,l[4]=0,l[8]=0,l[12]=u,l[1]=0,l[5]=m,l[9]=0,l[13]=g,l[2]=0,l[6]=0,l[10]=x,l[14]=E,l[3]=0,l[7]=0,l[11]=0,l[15]=1,this}equals(e){const t=this.elements,i=e.elements;for(let n=0;n<16;n++)if(t[n]!==i[n])return!1;return!0}fromArray(e,t=0){for(let i=0;i<16;i++)this.elements[i]=e[i+t];return this}toArray(e=[],t=0){const i=this.elements;return e[t]=i[0],e[t+1]=i[1],e[t+2]=i[2],e[t+3]=i[3],e[t+4]=i[4],e[t+5]=i[5],e[t+6]=i[6],e[t+7]=i[7],e[t+8]=i[8],e[t+9]=i[9],e[t+10]=i[10],e[t+11]=i[11],e[t+12]=i[12],e[t+13]=i[13],e[t+14]=i[14],e[t+15]=i[15],e}};wn.prototype.isMatrix4=!0;let ht=wn;const tr=new G,Bt=new ht,Wc=new G(0,0,0),Xc=new G(1,1,1),Si=new G,Jr=new G,Pt=new G,ho=new ht,po=new $i;class Xi{constructor(e=0,t=0,i=0,n=Xi.DEFAULT_ORDER){this.isEuler=!0,this._x=e,this._y=t,this._z=i,this._order=n}get x(){return this._x}set x(e){this._x=e,this._onChangeCallback()}get y(){return this._y}set y(e){this._y=e,this._onChangeCallback()}get z(){return this._z}set z(e){this._z=e,this._onChangeCallback()}get order(){return this._order}set order(e){this._order=e,this._onChangeCallback()}set(e,t,i,n=this._order){return this._x=e,this._y=t,this._z=i,this._order=n,this._onChangeCallback(),this}clone(){return new this.constructor(this._x,this._y,this._z,this._order)}copy(e){return this._x=e._x,this._y=e._y,this._z=e._z,this._order=e._order,this._onChangeCallback(),this}setFromRotationMatrix(e,t=this._order,i=!0){const n=e.elements,a=n[0],s=n[4],o=n[8],c=n[1],l=n[5],d=n[9],m=n[2],u=n[6],g=n[10];switch(t){case"XYZ":this._y=Math.asin(Be(o,-1,1)),Math.abs(o)<.9999999?(this._x=Math.atan2(-d,g),this._z=Math.atan2(-s,a)):(this._x=Math.atan2(u,l),this._z=0);break;case"YXZ":this._x=Math.asin(-Be(d,-1,1)),Math.abs(d)<.9999999?(this._y=Math.atan2(o,g),this._z=Math.atan2(c,l)):(this._y=Math.atan2(-m,a),this._z=0);break;case"ZXY":this._x=Math.asin(Be(u,-1,1)),Math.abs(u)<.9999999?(this._y=Math.atan2(-m,g),this._z=Math.atan2(-s,l)):(this._y=0,this._z=Math.atan2(c,a));break;case"ZYX":this._y=Math.asin(-Be(m,-1,1)),Math.abs(m)<.9999999?(this._x=Math.atan2(u,g),this._z=Math.atan2(c,a)):(this._x=0,this._z=Math.atan2(-s,l));break;case"YZX":this._z=Math.asin(Be(c,-1,1)),Math.abs(c)<.9999999?(this._x=Math.atan2(-d,l),this._y=Math.atan2(-m,a)):(this._x=0,this._y=Math.atan2(o,g));break;case"XZY":this._z=Math.asin(-Be(s,-1,1)),Math.abs(s)<.9999999?(this._x=Math.atan2(u,l),this._y=Math.atan2(o,a)):(this._x=Math.atan2(-d,g),this._y=0);break;default:Ae("Euler: .setFromRotationMatrix() encountered an unknown order: "+t)}return this._order=t,i===!0&&this._onChangeCallback(),this}setFromQuaternion(e,t,i){return ho.makeRotationFromQuaternion(e),this.setFromRotationMatrix(ho,t,i)}setFromVector3(e,t=this._order){return this.set(e.x,e.y,e.z,t)}reorder(e){return po.setFromEuler(this),this.setFromQuaternion(po,e)}equals(e){return e._x===this._x&&e._y===this._y&&e._z===this._z&&e._order===this._order}fromArray(e){return this._x=e[0],this._y=e[1],this._z=e[2],e[3]!==void 0&&(this._order=e[3]),this._onChangeCallback(),this}toArray(e=[],t=0){return e[t]=this._x,e[t+1]=this._y,e[t+2]=this._z,e[t+3]=this._order,e}_onChange(e){return this._onChangeCallback=e,this}_onChangeCallback(){}*[Symbol.iterator](){yield this._x,yield this._y,yield this._z,yield this._order}}Xi.DEFAULT_ORDER="XYZ";class fo{constructor(){this.mask=1}set(e){this.mask=(1<<e|0)>>>0}enable(e){this.mask|=1<<e|0}enableAll(){this.mask=-1}toggle(e){this.mask^=1<<e|0}disable(e){this.mask&=~(1<<e|0)}disableAll(){this.mask=0}test(e){return(this.mask&e.mask)!==0}isEnabled(e){return(this.mask&(1<<e|0))!==0}}let qc=0;const mo=new G,ir=new $i,hi=new ht,Zr=new G,Tr=new G,Yc=new G,jc=new $i,go=new G(1,0,0),_o=new G(0,1,0),vo=new G(0,0,1),xo={type:"added"},Kc={type:"removed"},rr={type:"childadded",child:null},Ha={type:"childremoved",child:null};class Dt extends Bi{constructor(){super(),this.isObject3D=!0,Object.defineProperty(this,"id",{value:qc++}),this.uuid=Sr(),this.name="",this.type="Object3D",this.parent=null,this.children=[],this.up=Dt.DEFAULT_UP.clone();const e=new G,t=new Xi,i=new $i,n=new G(1,1,1);function a(){i.setFromEuler(t,!1)}function s(){t.setFromQuaternion(i,void 0,!1)}t._onChange(a),i._onChange(s),Object.defineProperties(this,{position:{configurable:!0,enumerable:!0,value:e},rotation:{configurable:!0,enumerable:!0,value:t},quaternion:{configurable:!0,enumerable:!0,value:i},scale:{configurable:!0,enumerable:!0,value:n},modelViewMatrix:{value:new ht},normalMatrix:{value:new Ce}}),this.matrix=new ht,this.matrixWorld=new ht,this.matrixAutoUpdate=Dt.DEFAULT_MATRIX_AUTO_UPDATE,this.matrixWorldAutoUpdate=Dt.DEFAULT_MATRIX_WORLD_AUTO_UPDATE,this.matrixWorldNeedsUpdate=!1,this.layers=new fo,this.visible=!0,this.castShadow=!1,this.receiveShadow=!1,this.frustumCulled=!0,this.renderOrder=0,this.animations=[],this.customDepthMaterial=void 0,this.customDistanceMaterial=void 0,this.static=!1,this.userData={},this.pivot=null}onBeforeShadow(){}onAfterShadow(){}onBeforeRender(){}onAfterRender(){}applyMatrix4(e){this.matrixAutoUpdate&&this.updateMatrix(),this.matrix.premultiply(e),this.matrix.decompose(this.position,this.quaternion,this.scale)}applyQuaternion(e){return this.quaternion.premultiply(e),this}setRotationFromAxisAngle(e,t){this.quaternion.setFromAxisAngle(e,t)}setRotationFromEuler(e){this.quaternion.setFromEuler(e,!0)}setRotationFromMatrix(e){this.quaternion.setFromRotationMatrix(e)}setRotationFromQuaternion(e){this.quaternion.copy(e)}rotateOnAxis(e,t){return ir.setFromAxisAngle(e,t),this.quaternion.multiply(ir),this}rotateOnWorldAxis(e,t){return ir.setFromAxisAngle(e,t),this.quaternion.premultiply(ir),this}rotateX(e){return this.rotateOnAxis(go,e)}rotateY(e){return this.rotateOnAxis(_o,e)}rotateZ(e){return this.rotateOnAxis(vo,e)}translateOnAxis(e,t){return mo.copy(e).applyQuaternion(this.quaternion),this.position.add(mo.multiplyScalar(t)),this}translateX(e){return this.translateOnAxis(go,e)}translateY(e){return this.translateOnAxis(_o,e)}translateZ(e){return this.translateOnAxis(vo,e)}localToWorld(e){return this.updateWorldMatrix(!0,!1),e.applyMatrix4(this.matrixWorld)}worldToLocal(e){return this.updateWorldMatrix(!0,!1),e.applyMatrix4(hi.copy(this.matrixWorld).invert())}lookAt(e,t,i){e.isVector3?Zr.copy(e):Zr.set(e,t,i);const n=this.parent;this.updateWorldMatrix(!0,!1),Tr.setFromMatrixPosition(this.matrixWorld),this.isCamera||this.isLight?hi.lookAt(Tr,Zr,this.up):hi.lookAt(Zr,Tr,this.up),this.quaternion.setFromRotationMatrix(hi),n&&(hi.extractRotation(n.matrixWorld),ir.setFromRotationMatrix(hi),this.quaternion.premultiply(ir.invert()))}add(e){if(arguments.length>1){for(let t=0;t<arguments.length;t++)this.add(arguments[t]);return this}return e===this?(He("Object3D.add: object can't be added as a child of itself.",e),this):(e&&e.isObject3D?(e.removeFromParent(),e.parent=this,this.children.push(e),e.dispatchEvent(xo),rr.child=e,this.dispatchEvent(rr),rr.child=null):He("Object3D.add: object not an instance of THREE.Object3D.",e),this)}remove(e){if(arguments.length>1){for(let i=0;i<arguments.length;i++)this.remove(arguments[i]);return this}const t=this.children.indexOf(e);return t!==-1&&(e.parent=null,this.children.splice(t,1),e.dispatchEvent(Kc),Ha.child=e,this.dispatchEvent(Ha),Ha.child=null),this}removeFromParent(){const e=this.parent;return e!==null&&e.remove(this),this}clear(){return this.remove(...this.children)}attach(e){return this.updateWorldMatrix(!0,!1),hi.copy(this.matrixWorld).invert(),e.parent!==null&&(e.parent.updateWorldMatrix(!0,!1),hi.multiply(e.parent.matrixWorld)),e.applyMatrix4(hi),e.removeFromParent(),e.parent=this,this.children.push(e),e.updateWorldMatrix(!1,!0),e.dispatchEvent(xo),rr.child=e,this.dispatchEvent(rr),rr.child=null,this}getObjectById(e){return this.getObjectByProperty("id",e)}getObjectByName(e){return this.getObjectByProperty("name",e)}getObjectByProperty(e,t){if(this[e]===t)return this;for(let i=0,n=this.children.length;i<n;i++){const a=this.children[i].getObjectByProperty(e,t);if(a!==void 0)return a}}getObjectsByProperty(e,t,i=[]){this[e]===t&&i.push(this);const n=this.children;for(let a=0,s=n.length;a<s;a++)n[a].getObjectsByProperty(e,t,i);return i}getWorldPosition(e){return this.updateWorldMatrix(!0,!1),e.setFromMatrixPosition(this.matrixWorld)}getWorldQuaternion(e){return this.updateWorldMatrix(!0,!1),this.matrixWorld.decompose(Tr,e,Yc),e}getWorldScale(e){return this.updateWorldMatrix(!0,!1),this.matrixWorld.decompose(Tr,jc,e),e}getWorldDirection(e){this.updateWorldMatrix(!0,!1);const t=this.matrixWorld.elements;return e.set(t[8],t[9],t[10]).normalize()}raycast(){}traverse(e){e(this);const t=this.children;for(let i=0,n=t.length;i<n;i++)t[i].traverse(e)}traverseVisible(e){if(this.visible===!1)return;e(this);const t=this.children;for(let i=0,n=t.length;i<n;i++)t[i].traverseVisible(e)}traverseAncestors(e){const t=this.parent;t!==null&&(e(t),t.traverseAncestors(e))}updateMatrix(){this.matrix.compose(this.position,this.quaternion,this.scale);const e=this.pivot;if(e!==null){const t=e.x,i=e.y,n=e.z,a=this.matrix.elements;a[12]+=t-a[0]*t-a[4]*i-a[8]*n,a[13]+=i-a[1]*t-a[5]*i-a[9]*n,a[14]+=n-a[2]*t-a[6]*i-a[10]*n}this.matrixWorldNeedsUpdate=!0}updateMatrixWorld(e){this.matrixAutoUpdate&&this.updateMatrix(),(this.matrixWorldNeedsUpdate||e)&&(this.matrixWorldAutoUpdate===!0&&(this.parent===null?this.matrixWorld.copy(this.matrix):this.matrixWorld.multiplyMatrices(this.parent.matrixWorld,this.matrix)),this.matrixWorldNeedsUpdate=!1,e=!0);const t=this.children;for(let i=0,n=t.length;i<n;i++)t[i].updateMatrixWorld(e)}updateWorldMatrix(e,t){const i=this.parent;if(e===!0&&i!==null&&i.updateWorldMatrix(!0,!1),this.matrixAutoUpdate&&this.updateMatrix(),this.matrixWorldAutoUpdate===!0&&(this.parent===null?this.matrixWorld.copy(this.matrix):this.matrixWorld.multiplyMatrices(this.parent.matrixWorld,this.matrix)),t===!0){const n=this.children;for(let a=0,s=n.length;a<s;a++)n[a].updateWorldMatrix(!1,!0)}}toJSON(e){const t=e===void 0||typeof e=="string",i={};t&&(e={geometries:{},materials:{},textures:{},images:{},shapes:{},skeletons:{},animations:{},nodes:{}},i.metadata={version:4.7,type:"Object",generator:"Object3D.toJSON"});const n={};n.uuid=this.uuid,n.type=this.type,this.name!==""&&(n.name=this.name),this.castShadow===!0&&(n.castShadow=!0),this.receiveShadow===!0&&(n.receiveShadow=!0),this.visible===!1&&(n.visible=!1),this.frustumCulled===!1&&(n.frustumCulled=!1),this.renderOrder!==0&&(n.renderOrder=this.renderOrder),this.static!==!1&&(n.static=this.static),Object.keys(this.userData).length>0&&(n.userData=this.userData),n.layers=this.layers.mask,n.matrix=this.matrix.toArray(),n.up=this.up.toArray(),this.pivot!==null&&(n.pivot=this.pivot.toArray()),this.matrixAutoUpdate===!1&&(n.matrixAutoUpdate=!1),this.morphTargetDictionary!==void 0&&(n.morphTargetDictionary=Object.assign({},this.morphTargetDictionary)),this.morphTargetInfluences!==void 0&&(n.morphTargetInfluences=this.morphTargetInfluences.slice()),this.isInstancedMesh&&(n.type="InstancedMesh",n.count=this.count,n.instanceMatrix=this.instanceMatrix.toJSON(),this.instanceColor!==null&&(n.instanceColor=this.instanceColor.toJSON())),this.isBatchedMesh&&(n.type="BatchedMesh",n.perObjectFrustumCulled=this.perObjectFrustumCulled,n.sortObjects=this.sortObjects,n.drawRanges=this._drawRanges,n.reservedRanges=this._reservedRanges,n.geometryInfo=this._geometryInfo.map(o=>({...o,boundingBox:o.boundingBox?o.boundingBox.toJSON():void 0,boundingSphere:o.boundingSphere?o.boundingSphere.toJSON():void 0})),n.instanceInfo=this._instanceInfo.map(o=>({...o})),n.availableInstanceIds=this._availableInstanceIds.slice(),n.availableGeometryIds=this._availableGeometryIds.slice(),n.nextIndexStart=this._nextIndexStart,n.nextVertexStart=this._nextVertexStart,n.geometryCount=this._geometryCount,n.maxInstanceCount=this._maxInstanceCount,n.maxVertexCount=this._maxVertexCount,n.maxIndexCount=this._maxIndexCount,n.geometryInitialized=this._geometryInitialized,n.matricesTexture=this._matricesTexture.toJSON(e),n.indirectTexture=this._indirectTexture.toJSON(e),this._colorsTexture!==null&&(n.colorsTexture=this._colorsTexture.toJSON(e)),this.boundingSphere!==null&&(n.boundingSphere=this.boundingSphere.toJSON()),this.boundingBox!==null&&(n.boundingBox=this.boundingBox.toJSON()));function a(o,c){return o[c.uuid]===void 0&&(o[c.uuid]=c.toJSON(e)),c.uuid}if(this.isScene)this.background&&(this.background.isColor?n.background=this.background.toJSON():this.background.isTexture&&(n.background=this.background.toJSON(e).uuid)),this.environment&&this.environment.isTexture&&this.environment.isRenderTargetTexture!==!0&&(n.environment=this.environment.toJSON(e).uuid);else if(this.isMesh||this.isLine||this.isPoints){n.geometry=a(e.geometries,this.geometry);const o=this.geometry.parameters;if(o!==void 0&&o.shapes!==void 0){const c=o.shapes;if(Array.isArray(c))for(let l=0,d=c.length;l<d;l++){const m=c[l];a(e.shapes,m)}else a(e.shapes,c)}}if(this.isSkinnedMesh&&(n.bindMode=this.bindMode,n.bindMatrix=this.bindMatrix.toArray(),this.skeleton!==void 0&&(a(e.skeletons,this.skeleton),n.skeleton=this.skeleton.uuid)),this.material!==void 0)if(Array.isArray(this.material)){const o=[];for(let c=0,l=this.material.length;c<l;c++)o.push(a(e.materials,this.material[c]));n.material=o}else n.material=a(e.materials,this.material);if(this.children.length>0){n.children=[];for(let o=0;o<this.children.length;o++)n.children.push(this.children[o].toJSON(e).object)}if(this.animations.length>0){n.animations=[];for(let o=0;o<this.animations.length;o++){const c=this.animations[o];n.animations.push(a(e.animations,c))}}if(t){const o=s(e.geometries),c=s(e.materials),l=s(e.textures),d=s(e.images),m=s(e.shapes),u=s(e.skeletons),g=s(e.animations),x=s(e.nodes);o.length>0&&(i.geometries=o),c.length>0&&(i.materials=c),l.length>0&&(i.textures=l),d.length>0&&(i.images=d),m.length>0&&(i.shapes=m),u.length>0&&(i.skeletons=u),g.length>0&&(i.animations=g),x.length>0&&(i.nodes=x)}return i.object=n,i;function s(o){const c=[];for(const l in o){const d=o[l];delete d.metadata,c.push(d)}return c}}clone(e){return new this.constructor().copy(this,e)}copy(e,t=!0){if(this.name=e.name,this.up.copy(e.up),this.position.copy(e.position),this.rotation.order=e.rotation.order,this.quaternion.copy(e.quaternion),this.scale.copy(e.scale),this.pivot=e.pivot!==null?e.pivot.clone():null,this.matrix.copy(e.matrix),this.matrixWorld.copy(e.matrixWorld),this.matrixAutoUpdate=e.matrixAutoUpdate,this.matrixWorldAutoUpdate=e.matrixWorldAutoUpdate,this.matrixWorldNeedsUpdate=e.matrixWorldNeedsUpdate,this.layers.mask=e.layers.mask,this.visible=e.visible,this.castShadow=e.castShadow,this.receiveShadow=e.receiveShadow,this.frustumCulled=e.frustumCulled,this.renderOrder=e.renderOrder,this.static=e.static,this.animations=e.animations.slice(),this.userData=JSON.parse(JSON.stringify(e.userData)),t===!0)for(let i=0;i<e.children.length;i++){const n=e.children[i];this.add(n.clone())}return this}}Dt.DEFAULT_UP=new G(0,1,0),Dt.DEFAULT_MATRIX_AUTO_UPDATE=!0,Dt.DEFAULT_MATRIX_WORLD_AUTO_UPDATE=!0;class $r extends Dt{constructor(){super(),this.isGroup=!0,this.type="Group"}}const Jc={type:"move"};class Va{constructor(){this._targetRay=null,this._grip=null,this._hand=null}getHandSpace(){return this._hand===null&&(this._hand=new $r,this._hand.matrixAutoUpdate=!1,this._hand.visible=!1,this._hand.joints={},this._hand.inputState={pinching:!1}),this._hand}getTargetRaySpace(){return this._targetRay===null&&(this._targetRay=new $r,this._targetRay.matrixAutoUpdate=!1,this._targetRay.visible=!1,this._targetRay.hasLinearVelocity=!1,this._targetRay.linearVelocity=new G,this._targetRay.hasAngularVelocity=!1,this._targetRay.angularVelocity=new G),this._targetRay}getGripSpace(){return this._grip===null&&(this._grip=new $r,this._grip.matrixAutoUpdate=!1,this._grip.visible=!1,this._grip.hasLinearVelocity=!1,this._grip.linearVelocity=new G,this._grip.hasAngularVelocity=!1,this._grip.angularVelocity=new G,this._grip.eventsEnabled=!1),this._grip}dispatchEvent(e){return this._targetRay!==null&&this._targetRay.dispatchEvent(e),this._grip!==null&&this._grip.dispatchEvent(e),this._hand!==null&&this._hand.dispatchEvent(e),this}connect(e){if(e&&e.hand){const t=this._hand;if(t)for(const i of e.hand.values())this._getHandJoint(t,i)}return this.dispatchEvent({type:"connected",data:e}),this}disconnect(e){return this.dispatchEvent({type:"disconnected",data:e}),this._targetRay!==null&&(this._targetRay.visible=!1),this._grip!==null&&(this._grip.visible=!1),this._hand!==null&&(this._hand.visible=!1),this}update(e,t,i){let n=null,a=null,s=null;const o=this._targetRay,c=this._grip,l=this._hand;if(e&&t.session.visibilityState!=="visible-blurred"){if(l&&e.hand){s=!0;for(const E of e.hand.values()){const p=t.getJointPose(E,i),h=this._getHandJoint(l,E);p!==null&&(h.matrix.fromArray(p.transform.matrix),h.matrix.decompose(h.position,h.rotation,h.scale),h.matrixWorldNeedsUpdate=!0,h.jointRadius=p.radius),h.visible=p!==null}const d=l.joints["index-finger-tip"],m=l.joints["thumb-tip"],u=d.position.distanceTo(m.position),g=.02,x=.005;l.inputState.pinching&&u>g+x?(l.inputState.pinching=!1,this.dispatchEvent({type:"pinchend",handedness:e.handedness,target:this})):!l.inputState.pinching&&u<=g-x&&(l.inputState.pinching=!0,this.dispatchEvent({type:"pinchstart",handedness:e.handedness,target:this}))}else c!==null&&e.gripSpace&&(a=t.getPose(e.gripSpace,i),a!==null&&(c.matrix.fromArray(a.transform.matrix),c.matrix.decompose(c.position,c.rotation,c.scale),c.matrixWorldNeedsUpdate=!0,a.linearVelocity?(c.hasLinearVelocity=!0,c.linearVelocity.copy(a.linearVelocity)):c.hasLinearVelocity=!1,a.angularVelocity?(c.hasAngularVelocity=!0,c.angularVelocity.copy(a.angularVelocity)):c.hasAngularVelocity=!1,c.eventsEnabled&&c.dispatchEvent({type:"gripUpdated",data:e,target:this})));o!==null&&(n=t.getPose(e.targetRaySpace,i),n===null&&a!==null&&(n=a),n!==null&&(o.matrix.fromArray(n.transform.matrix),o.matrix.decompose(o.position,o.rotation,o.scale),o.matrixWorldNeedsUpdate=!0,n.linearVelocity?(o.hasLinearVelocity=!0,o.linearVelocity.copy(n.linearVelocity)):o.hasLinearVelocity=!1,n.angularVelocity?(o.hasAngularVelocity=!0,o.angularVelocity.copy(n.angularVelocity)):o.hasAngularVelocity=!1,this.dispatchEvent(Jc)))}return o!==null&&(o.visible=n!==null),c!==null&&(c.visible=a!==null),l!==null&&(l.visible=s!==null),this}_getHandJoint(e,t){if(e.joints[t.jointName]===void 0){const i=new $r;i.matrixAutoUpdate=!1,i.visible=!1,e.joints[t.jointName]=i,e.add(i)}return e.joints[t.jointName]}}const Mo={aliceblue:15792383,antiquewhite:16444375,aqua:65535,aquamarine:8388564,azure:15794175,beige:16119260,bisque:16770244,black:0,blanchedalmond:16772045,blue:255,blueviolet:9055202,brown:10824234,burlywood:14596231,cadetblue:6266528,chartreuse:8388352,chocolate:13789470,coral:16744272,cornflowerblue:6591981,cornsilk:16775388,crimson:14423100,cyan:65535,darkblue:139,darkcyan:35723,darkgoldenrod:12092939,darkgray:11119017,darkgreen:25600,darkgrey:11119017,darkkhaki:12433259,darkmagenta:9109643,darkolivegreen:5597999,darkorange:16747520,darkorchid:10040012,darkred:9109504,darksalmon:15308410,darkseagreen:9419919,darkslateblue:4734347,darkslategray:3100495,darkslategrey:3100495,darkturquoise:52945,darkviolet:9699539,deeppink:16716947,deepskyblue:49151,dimgray:6908265,dimgrey:6908265,dodgerblue:2003199,firebrick:11674146,floralwhite:16775920,forestgreen:2263842,fuchsia:16711935,gainsboro:14474460,ghostwhite:16316671,gold:16766720,goldenrod:14329120,gray:8421504,green:32768,greenyellow:11403055,grey:8421504,honeydew:15794160,hotpink:16738740,indianred:13458524,indigo:4915330,ivory:16777200,khaki:15787660,lavender:15132410,lavenderblush:16773365,lawngreen:8190976,lemonchiffon:16775885,lightblue:11393254,lightcoral:15761536,lightcyan:14745599,lightgoldenrodyellow:16448210,lightgray:13882323,lightgreen:9498256,lightgrey:13882323,lightpink:16758465,lightsalmon:16752762,lightseagreen:2142890,lightskyblue:8900346,lightslategray:7833753,lightslategrey:7833753,lightsteelblue:11584734,lightyellow:16777184,lime:65280,limegreen:3329330,linen:16445670,magenta:16711935,maroon:8388608,mediumaquamarine:6737322,mediumblue:205,mediumorchid:12211667,mediumpurple:9662683,mediumseagreen:3978097,mediumslateblue:8087790,mediumspringgreen:64154,mediumturquoise:4772300,mediumvioletred:13047173,midnightblue:1644912,mintcream:16121850,mistyrose:16770273,moccasin:16770229,navajowhite:16768685,navy:128,oldlace:16643558,olive:8421376,olivedrab:7048739,orange:16753920,orangered:16729344,orchid:14315734,palegoldenrod:15657130,palegreen:10025880,paleturquoise:11529966,palevioletred:14381203,papayawhip:16773077,peachpuff:16767673,peru:13468991,pink:16761035,plum:14524637,powderblue:11591910,purple:8388736,rebeccapurple:6697881,red:16711680,rosybrown:12357519,royalblue:4286945,saddlebrown:9127187,salmon:16416882,sandybrown:16032864,seagreen:3050327,seashell:16774638,sienna:10506797,silver:12632256,skyblue:8900331,slateblue:6970061,slategray:7372944,slategrey:7372944,snow:16775930,springgreen:65407,steelblue:4620980,tan:13808780,teal:32896,thistle:14204888,tomato:16737095,turquoise:4251856,violet:15631086,wheat:16113331,white:16777215,whitesmoke:16119285,yellow:16776960,yellowgreen:10145074},Ei={h:0,s:0,l:0},Qr={h:0,s:0,l:0};function ka(r,e,t){return t<0&&(t+=1),t>1&&(t-=1),t<1/6?r+(e-r)*6*t:t<1/2?e:t<2/3?r+(e-r)*6*(2/3-t):r}class qe{constructor(e,t,i){return this.isColor=!0,this.r=1,this.g=1,this.b=1,this.set(e,t,i)}set(e,t,i){if(t===void 0&&i===void 0){const n=e;n&&n.isColor?this.copy(n):typeof n=="number"?this.setHex(n):typeof n=="string"&&this.setStyle(n)}else this.setRGB(e,t,i);return this}setScalar(e){return this.r=e,this.g=e,this.b=e,this}setHex(e,t=At){return e=Math.floor(e),this.r=(e>>16&255)/255,this.g=(e>>8&255)/255,this.b=(e&255)/255,ze.colorSpaceToWorking(this,t),this}setRGB(e,t,i,n=ze.workingColorSpace){return this.r=e,this.g=t,this.b=i,ze.colorSpaceToWorking(this,n),this}setHSL(e,t,i,n=ze.workingColorSpace){if(e=Oc(e,1),t=Be(t,0,1),i=Be(i,0,1),t===0)this.r=this.g=this.b=i;else{const a=i<=.5?i*(1+t):i+t-i*t,s=2*i-a;this.r=ka(s,a,e+1/3),this.g=ka(s,a,e),this.b=ka(s,a,e-1/3)}return ze.colorSpaceToWorking(this,n),this}setStyle(e,t=At){function i(a){a!==void 0&&parseFloat(a)<1&&Ae("Color: Alpha component of "+e+" will be ignored.")}let n;if(n=/^(\w+)\(([^\)]*)\)/.exec(e)){let a;const s=n[1],o=n[2];switch(s){case"rgb":case"rgba":if(a=/^\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*(\d*\.?\d+)\s*)?$/.exec(o))return i(a[4]),this.setRGB(Math.min(255,parseInt(a[1],10))/255,Math.min(255,parseInt(a[2],10))/255,Math.min(255,parseInt(a[3],10))/255,t);if(a=/^\s*(\d+)\%\s*,\s*(\d+)\%\s*,\s*(\d+)\%\s*(?:,\s*(\d*\.?\d+)\s*)?$/.exec(o))return i(a[4]),this.setRGB(Math.min(100,parseInt(a[1],10))/100,Math.min(100,parseInt(a[2],10))/100,Math.min(100,parseInt(a[3],10))/100,t);break;case"hsl":case"hsla":if(a=/^\s*(\d*\.?\d+)\s*,\s*(\d*\.?\d+)\%\s*,\s*(\d*\.?\d+)\%\s*(?:,\s*(\d*\.?\d+)\s*)?$/.exec(o))return i(a[4]),this.setHSL(parseFloat(a[1])/360,parseFloat(a[2])/100,parseFloat(a[3])/100,t);break;default:Ae("Color: Unknown color model "+e)}}else if(n=/^\#([A-Fa-f\d]+)$/.exec(e)){const a=n[1],s=a.length;if(s===3)return this.setRGB(parseInt(a.charAt(0),16)/15,parseInt(a.charAt(1),16)/15,parseInt(a.charAt(2),16)/15,t);if(s===6)return this.setHex(parseInt(a,16),t);Ae("Color: Invalid hex color "+e)}else if(e&&e.length>0)return this.setColorName(e,t);return this}setColorName(e,t=At){const i=Mo[e.toLowerCase()];return i!==void 0?this.setHex(i,t):Ae("Color: Unknown color "+e),this}clone(){return new this.constructor(this.r,this.g,this.b)}copy(e){return this.r=e.r,this.g=e.g,this.b=e.b,this}copySRGBToLinear(e){return this.r=ui(e.r),this.g=ui(e.g),this.b=ui(e.b),this}copyLinearToSRGB(e){return this.r=Qi(e.r),this.g=Qi(e.g),this.b=Qi(e.b),this}convertSRGBToLinear(){return this.copySRGBToLinear(this),this}convertLinearToSRGB(){return this.copyLinearToSRGB(this),this}getHex(e=At){return ze.workingToColorSpace(Mt.copy(this),e),Math.round(Be(Mt.r*255,0,255))*65536+Math.round(Be(Mt.g*255,0,255))*256+Math.round(Be(Mt.b*255,0,255))}getHexString(e=At){return("000000"+this.getHex(e).toString(16)).slice(-6)}getHSL(e,t=ze.workingColorSpace){ze.workingToColorSpace(Mt.copy(this),t);const i=Mt.r,n=Mt.g,a=Mt.b,s=Math.max(i,n,a),o=Math.min(i,n,a);let c,l;const d=(o+s)/2;if(o===s)c=0,l=0;else{const m=s-o;switch(l=d<=.5?m/(s+o):m/(2-s-o),s){case i:c=(n-a)/m+(n<a?6:0);break;case n:c=(a-i)/m+2;break;case a:c=(i-n)/m+4;break}c/=6}return e.h=c,e.s=l,e.l=d,e}getRGB(e,t=ze.workingColorSpace){return ze.workingToColorSpace(Mt.copy(this),t),e.r=Mt.r,e.g=Mt.g,e.b=Mt.b,e}getStyle(e=At){ze.workingToColorSpace(Mt.copy(this),e);const t=Mt.r,i=Mt.g,n=Mt.b;return e!==At?`color(${e} ${t.toFixed(3)} ${i.toFixed(3)} ${n.toFixed(3)})`:`rgb(${Math.round(t*255)},${Math.round(i*255)},${Math.round(n*255)})`}offsetHSL(e,t,i){return this.getHSL(Ei),this.setHSL(Ei.h+e,Ei.s+t,Ei.l+i)}add(e){return this.r+=e.r,this.g+=e.g,this.b+=e.b,this}addColors(e,t){return this.r=e.r+t.r,this.g=e.g+t.g,this.b=e.b+t.b,this}addScalar(e){return this.r+=e,this.g+=e,this.b+=e,this}sub(e){return this.r=Math.max(0,this.r-e.r),this.g=Math.max(0,this.g-e.g),this.b=Math.max(0,this.b-e.b),this}multiply(e){return this.r*=e.r,this.g*=e.g,this.b*=e.b,this}multiplyScalar(e){return this.r*=e,this.g*=e,this.b*=e,this}lerp(e,t){return this.r+=(e.r-this.r)*t,this.g+=(e.g-this.g)*t,this.b+=(e.b-this.b)*t,this}lerpColors(e,t,i){return this.r=e.r+(t.r-e.r)*i,this.g=e.g+(t.g-e.g)*i,this.b=e.b+(t.b-e.b)*i,this}lerpHSL(e,t){this.getHSL(Ei),e.getHSL(Qr);const i=Na(Ei.h,Qr.h,t),n=Na(Ei.s,Qr.s,t),a=Na(Ei.l,Qr.l,t);return this.setHSL(i,n,a),this}setFromVector3(e){return this.r=e.x,this.g=e.y,this.b=e.z,this}applyMatrix3(e){const t=this.r,i=this.g,n=this.b,a=e.elements;return this.r=a[0]*t+a[3]*i+a[6]*n,this.g=a[1]*t+a[4]*i+a[7]*n,this.b=a[2]*t+a[5]*i+a[8]*n,this}equals(e){return e.r===this.r&&e.g===this.g&&e.b===this.b}fromArray(e,t=0){return this.r=e[t],this.g=e[t+1],this.b=e[t+2],this}toArray(e=[],t=0){return e[t]=this.r,e[t+1]=this.g,e[t+2]=this.b,e}fromBufferAttribute(e,t){return this.r=e.getX(t),this.g=e.getY(t),this.b=e.getZ(t),this}toJSON(){return this.getHex()}*[Symbol.iterator](){yield this.r,yield this.g,yield this.b}}const Mt=new qe;qe.NAMES=Mo;class Zc extends Dt{constructor(){super(),this.isScene=!0,this.type="Scene",this.background=null,this.environment=null,this.fog=null,this.backgroundBlurriness=0,this.backgroundIntensity=1,this.backgroundRotation=new Xi,this.environmentIntensity=1,this.environmentRotation=new Xi,this.overrideMaterial=null,typeof __THREE_DEVTOOLS__<"u"&&__THREE_DEVTOOLS__.dispatchEvent(new CustomEvent("observe",{detail:this}))}copy(e,t){return super.copy(e,t),e.background!==null&&(this.background=e.background.clone()),e.environment!==null&&(this.environment=e.environment.clone()),e.fog!==null&&(this.fog=e.fog.clone()),this.backgroundBlurriness=e.backgroundBlurriness,this.backgroundIntensity=e.backgroundIntensity,this.backgroundRotation.copy(e.backgroundRotation),this.environmentIntensity=e.environmentIntensity,this.environmentRotation.copy(e.environmentRotation),e.overrideMaterial!==null&&(this.overrideMaterial=e.overrideMaterial.clone()),this.matrixAutoUpdate=e.matrixAutoUpdate,this}toJSON(e){const t=super.toJSON(e);return this.fog!==null&&(t.object.fog=this.fog.toJSON()),this.backgroundBlurriness>0&&(t.object.backgroundBlurriness=this.backgroundBlurriness),this.backgroundIntensity!==1&&(t.object.backgroundIntensity=this.backgroundIntensity),t.object.backgroundRotation=this.backgroundRotation.toArray(),this.environmentIntensity!==1&&(t.object.environmentIntensity=this.environmentIntensity),t.object.environmentRotation=this.environmentRotation.toArray(),t}}const zt=new G,di=new G,Wa=new G,pi=new G,nr=new G,ar=new G,So=new G,Xa=new G,qa=new G,Ya=new G,ja=new ot,Ka=new ot,Ja=new ot;class kt{constructor(e=new G,t=new G,i=new G){this.a=e,this.b=t,this.c=i}static getNormal(e,t,i,n){n.subVectors(i,t),zt.subVectors(e,t),n.cross(zt);const a=n.lengthSq();return a>0?n.multiplyScalar(1/Math.sqrt(a)):n.set(0,0,0)}static getBarycoord(e,t,i,n,a){zt.subVectors(n,t),di.subVectors(i,t),Wa.subVectors(e,t);const s=zt.dot(zt),o=zt.dot(di),c=zt.dot(Wa),l=di.dot(di),d=di.dot(Wa),m=s*l-o*o;if(m===0)return a.set(0,0,0),null;const u=1/m,g=(l*c-o*d)*u,x=(s*d-o*c)*u;return a.set(1-g-x,x,g)}static containsPoint(e,t,i,n){return this.getBarycoord(e,t,i,n,pi)===null?!1:pi.x>=0&&pi.y>=0&&pi.x+pi.y<=1}static getInterpolation(e,t,i,n,a,s,o,c){return this.getBarycoord(e,t,i,n,pi)===null?(c.x=0,c.y=0,"z"in c&&(c.z=0),"w"in c&&(c.w=0),null):(c.setScalar(0),c.addScaledVector(a,pi.x),c.addScaledVector(s,pi.y),c.addScaledVector(o,pi.z),c)}static getInterpolatedAttribute(e,t,i,n,a,s){return ja.setScalar(0),Ka.setScalar(0),Ja.setScalar(0),ja.fromBufferAttribute(e,t),Ka.fromBufferAttribute(e,i),Ja.fromBufferAttribute(e,n),s.setScalar(0),s.addScaledVector(ja,a.x),s.addScaledVector(Ka,a.y),s.addScaledVector(Ja,a.z),s}static isFrontFacing(e,t,i,n){return zt.subVectors(i,t),di.subVectors(e,t),zt.cross(di).dot(n)<0}set(e,t,i){return this.a.copy(e),this.b.copy(t),this.c.copy(i),this}setFromPointsAndIndices(e,t,i,n){return this.a.copy(e[t]),this.b.copy(e[i]),this.c.copy(e[n]),this}setFromAttributeAndIndices(e,t,i,n){return this.a.fromBufferAttribute(e,t),this.b.fromBufferAttribute(e,i),this.c.fromBufferAttribute(e,n),this}clone(){return new this.constructor().copy(this)}copy(e){return this.a.copy(e.a),this.b.copy(e.b),this.c.copy(e.c),this}getArea(){return zt.subVectors(this.c,this.b),di.subVectors(this.a,this.b),zt.cross(di).length()*.5}getMidpoint(e){return e.addVectors(this.a,this.b).add(this.c).multiplyScalar(1/3)}getNormal(e){return kt.getNormal(this.a,this.b,this.c,e)}getPlane(e){return e.setFromCoplanarPoints(this.a,this.b,this.c)}getBarycoord(e,t){return kt.getBarycoord(e,this.a,this.b,this.c,t)}getInterpolation(e,t,i,n,a){return kt.getInterpolation(e,this.a,this.b,this.c,t,i,n,a)}containsPoint(e){return kt.containsPoint(e,this.a,this.b,this.c)}isFrontFacing(e){return kt.isFrontFacing(this.a,this.b,this.c,e)}intersectsBox(e){return e.intersectsTriangle(this)}closestPointToPoint(e,t){const i=this.a,n=this.b,a=this.c;let s,o;nr.subVectors(n,i),ar.subVectors(a,i),Xa.subVectors(e,i);const c=nr.dot(Xa),l=ar.dot(Xa);if(c<=0&&l<=0)return t.copy(i);qa.subVectors(e,n);const d=nr.dot(qa),m=ar.dot(qa);if(d>=0&&m<=d)return t.copy(n);const u=c*m-d*l;if(u<=0&&c>=0&&d<=0)return s=c/(c-d),t.copy(i).addScaledVector(nr,s);Ya.subVectors(e,a);const g=nr.dot(Ya),x=ar.dot(Ya);if(x>=0&&g<=x)return t.copy(a);const E=g*l-c*x;if(E<=0&&l>=0&&x<=0)return o=l/(l-x),t.copy(i).addScaledVector(ar,o);const p=d*x-g*m;if(p<=0&&m-d>=0&&g-x>=0)return So.subVectors(a,n),o=(m-d)/(m-d+(g-x)),t.copy(n).addScaledVector(So,o);const h=1/(p+E+u);return s=E*h,o=u*h,t.copy(i).addScaledVector(nr,s).addScaledVector(ar,o)}equals(e){return e.a.equals(this.a)&&e.b.equals(this.b)&&e.c.equals(this.c)}}class yr{constructor(e=new G(1/0,1/0,1/0),t=new G(-1/0,-1/0,-1/0)){this.isBox3=!0,this.min=e,this.max=t}set(e,t){return this.min.copy(e),this.max.copy(t),this}setFromArray(e){this.makeEmpty();for(let t=0,i=e.length;t<i;t+=3)this.expandByPoint(Gt.fromArray(e,t));return this}setFromBufferAttribute(e){this.makeEmpty();for(let t=0,i=e.count;t<i;t++)this.expandByPoint(Gt.fromBufferAttribute(e,t));return this}setFromPoints(e){this.makeEmpty();for(let t=0,i=e.length;t<i;t++)this.expandByPoint(e[t]);return this}setFromCenterAndSize(e,t){const i=Gt.copy(t).multiplyScalar(.5);return this.min.copy(e).sub(i),this.max.copy(e).add(i),this}setFromObject(e,t=!1){return this.makeEmpty(),this.expandByObject(e,t)}clone(){return new this.constructor().copy(this)}copy(e){return this.min.copy(e.min),this.max.copy(e.max),this}makeEmpty(){return this.min.x=this.min.y=this.min.z=1/0,this.max.x=this.max.y=this.max.z=-1/0,this}isEmpty(){return this.max.x<this.min.x||this.max.y<this.min.y||this.max.z<this.min.z}getCenter(e){return this.isEmpty()?e.set(0,0,0):e.addVectors(this.min,this.max).multiplyScalar(.5)}getSize(e){return this.isEmpty()?e.set(0,0,0):e.subVectors(this.max,this.min)}expandByPoint(e){return this.min.min(e),this.max.max(e),this}expandByVector(e){return this.min.sub(e),this.max.add(e),this}expandByScalar(e){return this.min.addScalar(-e),this.max.addScalar(e),this}expandByObject(e,t=!1){e.updateWorldMatrix(!1,!1);const i=e.geometry;if(i!==void 0){const a=i.getAttribute("position");if(t===!0&&a!==void 0&&e.isInstancedMesh!==!0)for(let s=0,o=a.count;s<o;s++)e.isMesh===!0?e.getVertexPosition(s,Gt):Gt.fromBufferAttribute(a,s),Gt.applyMatrix4(e.matrixWorld),this.expandByPoint(Gt);else e.boundingBox!==void 0?(e.boundingBox===null&&e.computeBoundingBox(),en.copy(e.boundingBox)):(i.boundingBox===null&&i.computeBoundingBox(),en.copy(i.boundingBox)),en.applyMatrix4(e.matrixWorld),this.union(en)}const n=e.children;for(let a=0,s=n.length;a<s;a++)this.expandByObject(n[a],t);return this}containsPoint(e){return e.x>=this.min.x&&e.x<=this.max.x&&e.y>=this.min.y&&e.y<=this.max.y&&e.z>=this.min.z&&e.z<=this.max.z}containsBox(e){return this.min.x<=e.min.x&&e.max.x<=this.max.x&&this.min.y<=e.min.y&&e.max.y<=this.max.y&&this.min.z<=e.min.z&&e.max.z<=this.max.z}getParameter(e,t){return t.set((e.x-this.min.x)/(this.max.x-this.min.x),(e.y-this.min.y)/(this.max.y-this.min.y),(e.z-this.min.z)/(this.max.z-this.min.z))}intersectsBox(e){return e.max.x>=this.min.x&&e.min.x<=this.max.x&&e.max.y>=this.min.y&&e.min.y<=this.max.y&&e.max.z>=this.min.z&&e.min.z<=this.max.z}intersectsSphere(e){return this.clampPoint(e.center,Gt),Gt.distanceToSquared(e.center)<=e.radius*e.radius}intersectsPlane(e){let t,i;return e.normal.x>0?(t=e.normal.x*this.min.x,i=e.normal.x*this.max.x):(t=e.normal.x*this.max.x,i=e.normal.x*this.min.x),e.normal.y>0?(t+=e.normal.y*this.min.y,i+=e.normal.y*this.max.y):(t+=e.normal.y*this.max.y,i+=e.normal.y*this.min.y),e.normal.z>0?(t+=e.normal.z*this.min.z,i+=e.normal.z*this.max.z):(t+=e.normal.z*this.max.z,i+=e.normal.z*this.min.z),t<=-e.constant&&i>=-e.constant}intersectsTriangle(e){if(this.isEmpty())return!1;this.getCenter(br),tn.subVectors(this.max,br),sr.subVectors(e.a,br),or.subVectors(e.b,br),lr.subVectors(e.c,br),Ti.subVectors(or,sr),yi.subVectors(lr,or),zi.subVectors(sr,lr);let t=[0,-Ti.z,Ti.y,0,-yi.z,yi.y,0,-zi.z,zi.y,Ti.z,0,-Ti.x,yi.z,0,-yi.x,zi.z,0,-zi.x,-Ti.y,Ti.x,0,-yi.y,yi.x,0,-zi.y,zi.x,0];return!Za(t,sr,or,lr,tn)||(t=[1,0,0,0,1,0,0,0,1],!Za(t,sr,or,lr,tn))?!1:(rn.crossVectors(Ti,yi),t=[rn.x,rn.y,rn.z],Za(t,sr,or,lr,tn))}clampPoint(e,t){return t.copy(e).clamp(this.min,this.max)}distanceToPoint(e){return this.clampPoint(e,Gt).distanceTo(e)}getBoundingSphere(e){return this.isEmpty()?e.makeEmpty():(this.getCenter(e.center),e.radius=this.getSize(Gt).length()*.5),e}intersect(e){return this.min.max(e.min),this.max.min(e.max),this.isEmpty()&&this.makeEmpty(),this}union(e){return this.min.min(e.min),this.max.max(e.max),this}applyMatrix4(e){return this.isEmpty()?this:(fi[0].set(this.min.x,this.min.y,this.min.z).applyMatrix4(e),fi[1].set(this.min.x,this.min.y,this.max.z).applyMatrix4(e),fi[2].set(this.min.x,this.max.y,this.min.z).applyMatrix4(e),fi[3].set(this.min.x,this.max.y,this.max.z).applyMatrix4(e),fi[4].set(this.max.x,this.min.y,this.min.z).applyMatrix4(e),fi[5].set(this.max.x,this.min.y,this.max.z).applyMatrix4(e),fi[6].set(this.max.x,this.max.y,this.min.z).applyMatrix4(e),fi[7].set(this.max.x,this.max.y,this.max.z).applyMatrix4(e),this.setFromPoints(fi),this)}translate(e){return this.min.add(e),this.max.add(e),this}equals(e){return e.min.equals(this.min)&&e.max.equals(this.max)}toJSON(){return{min:this.min.toArray(),max:this.max.toArray()}}fromJSON(e){return this.min.fromArray(e.min),this.max.fromArray(e.max),this}}const fi=[new G,new G,new G,new G,new G,new G,new G,new G],Gt=new G,en=new yr,sr=new G,or=new G,lr=new G,Ti=new G,yi=new G,zi=new G,br=new G,tn=new G,rn=new G,Gi=new G;function Za(r,e,t,i,n){for(let a=0,s=r.length-3;a<=s;a+=3){Gi.fromArray(r,a);const o=n.x*Math.abs(Gi.x)+n.y*Math.abs(Gi.y)+n.z*Math.abs(Gi.z),c=e.dot(Gi),l=t.dot(Gi),d=i.dot(Gi);if(Math.max(-Math.max(c,l,d),Math.min(c,l,d))>o)return!1}return!0}const lt=new G,nn=new Ke;let $c=0;class Nt extends Bi{constructor(e,t,i=!1){if(super(),Array.isArray(e))throw new TypeError("THREE.BufferAttribute: array should be a Typed Array.");this.isBufferAttribute=!0,Object.defineProperty(this,"id",{value:$c++}),this.name="",this.array=e,this.itemSize=t,this.count=e!==void 0?e.length/t:0,this.normalized=i,this.usage=io,this.updateRanges=[],this.gpuType=jt,this.version=0}onUploadCallback(){}set needsUpdate(e){e===!0&&this.version++}setUsage(e){return this.usage=e,this}addUpdateRange(e,t){this.updateRanges.push({start:e,count:t})}clearUpdateRanges(){this.updateRanges.length=0}copy(e){return this.name=e.name,this.array=new e.array.constructor(e.array),this.itemSize=e.itemSize,this.count=e.count,this.normalized=e.normalized,this.usage=e.usage,this.gpuType=e.gpuType,this}copyAt(e,t,i){e*=this.itemSize,i*=t.itemSize;for(let n=0,a=this.itemSize;n<a;n++)this.array[e+n]=t.array[i+n];return this}copyArray(e){return this.array.set(e),this}applyMatrix3(e){if(this.itemSize===2)for(let t=0,i=this.count;t<i;t++)nn.fromBufferAttribute(this,t),nn.applyMatrix3(e),this.setXY(t,nn.x,nn.y);else if(this.itemSize===3)for(let t=0,i=this.count;t<i;t++)lt.fromBufferAttribute(this,t),lt.applyMatrix3(e),this.setXYZ(t,lt.x,lt.y,lt.z);return this}applyMatrix4(e){for(let t=0,i=this.count;t<i;t++)lt.fromBufferAttribute(this,t),lt.applyMatrix4(e),this.setXYZ(t,lt.x,lt.y,lt.z);return this}applyNormalMatrix(e){for(let t=0,i=this.count;t<i;t++)lt.fromBufferAttribute(this,t),lt.applyNormalMatrix(e),this.setXYZ(t,lt.x,lt.y,lt.z);return this}transformDirection(e){for(let t=0,i=this.count;t<i;t++)lt.fromBufferAttribute(this,t),lt.transformDirection(e),this.setXYZ(t,lt.x,lt.y,lt.z);return this}set(e,t=0){return this.array.set(e,t),this}getComponent(e,t){let i=this.array[e*this.itemSize+t];return this.normalized&&(i=Er(i,this.array)),i}setComponent(e,t,i){return this.normalized&&(i=wt(i,this.array)),this.array[e*this.itemSize+t]=i,this}getX(e){let t=this.array[e*this.itemSize];return this.normalized&&(t=Er(t,this.array)),t}setX(e,t){return this.normalized&&(t=wt(t,this.array)),this.array[e*this.itemSize]=t,this}getY(e){let t=this.array[e*this.itemSize+1];return this.normalized&&(t=Er(t,this.array)),t}setY(e,t){return this.normalized&&(t=wt(t,this.array)),this.array[e*this.itemSize+1]=t,this}getZ(e){let t=this.array[e*this.itemSize+2];return this.normalized&&(t=Er(t,this.array)),t}setZ(e,t){return this.normalized&&(t=wt(t,this.array)),this.array[e*this.itemSize+2]=t,this}getW(e){let t=this.array[e*this.itemSize+3];return this.normalized&&(t=Er(t,this.array)),t}setW(e,t){return this.normalized&&(t=wt(t,this.array)),this.array[e*this.itemSize+3]=t,this}setXY(e,t,i){return e*=this.itemSize,this.normalized&&(t=wt(t,this.array),i=wt(i,this.array)),this.array[e+0]=t,this.array[e+1]=i,this}setXYZ(e,t,i,n){return e*=this.itemSize,this.normalized&&(t=wt(t,this.array),i=wt(i,this.array),n=wt(n,this.array)),this.array[e+0]=t,this.array[e+1]=i,this.array[e+2]=n,this}setXYZW(e,t,i,n,a){return e*=this.itemSize,this.normalized&&(t=wt(t,this.array),i=wt(i,this.array),n=wt(n,this.array),a=wt(a,this.array)),this.array[e+0]=t,this.array[e+1]=i,this.array[e+2]=n,this.array[e+3]=a,this}onUpload(e){return this.onUploadCallback=e,this}clone(){return new this.constructor(this.array,this.itemSize).copy(this)}toJSON(){const e={itemSize:this.itemSize,type:this.array.constructor.name,array:Array.from(this.array),normalized:this.normalized};return this.name!==""&&(e.name=this.name),this.usage!==io&&(e.usage=this.usage),e}dispose(){this.dispatchEvent({type:"dispose"})}}class Eo extends Nt{constructor(e,t,i){super(new Uint16Array(e),t,i)}}class To extends Nt{constructor(e,t,i){super(new Uint32Array(e),t,i)}}class mi extends Nt{constructor(e,t,i){super(new Float32Array(e),t,i)}}const Qc=new yr,Ar=new G,$a=new G;class wr{constructor(e=new G,t=-1){this.isSphere=!0,this.center=e,this.radius=t}set(e,t){return this.center.copy(e),this.radius=t,this}setFromPoints(e,t){const i=this.center;t!==void 0?i.copy(t):Qc.setFromPoints(e).getCenter(i);let n=0;for(let a=0,s=e.length;a<s;a++)n=Math.max(n,i.distanceToSquared(e[a]));return this.radius=Math.sqrt(n),this}copy(e){return this.center.copy(e.center),this.radius=e.radius,this}isEmpty(){return this.radius<0}makeEmpty(){return this.center.set(0,0,0),this.radius=-1,this}containsPoint(e){return e.distanceToSquared(this.center)<=this.radius*this.radius}distanceToPoint(e){return e.distanceTo(this.center)-this.radius}intersectsSphere(e){const t=this.radius+e.radius;return e.center.distanceToSquared(this.center)<=t*t}intersectsBox(e){return e.intersectsSphere(this)}intersectsPlane(e){return Math.abs(e.distanceToPoint(this.center))<=this.radius}clampPoint(e,t){const i=this.center.distanceToSquared(e);return t.copy(e),i>this.radius*this.radius&&(t.sub(this.center).normalize(),t.multiplyScalar(this.radius).add(this.center)),t}getBoundingBox(e){return this.isEmpty()?(e.makeEmpty(),e):(e.set(this.center,this.center),e.expandByScalar(this.radius),e)}applyMatrix4(e){return this.center.applyMatrix4(e),this.radius=this.radius*e.getMaxScaleOnAxis(),this}translate(e){return this.center.add(e),this}expandByPoint(e){if(this.isEmpty())return this.center.copy(e),this.radius=0,this;Ar.subVectors(e,this.center);const t=Ar.lengthSq();if(t>this.radius*this.radius){const i=Math.sqrt(t),n=(i-this.radius)*.5;this.center.addScaledVector(Ar,n/i),this.radius+=n}return this}union(e){return e.isEmpty()?this:this.isEmpty()?(this.copy(e),this):(this.center.equals(e.center)===!0?this.radius=Math.max(this.radius,e.radius):($a.subVectors(e.center,this.center).setLength(e.radius),this.expandByPoint(Ar.copy(e.center).add($a)),this.expandByPoint(Ar.copy(e.center).sub($a))),this)}equals(e){return e.center.equals(this.center)&&e.radius===this.radius}clone(){return new this.constructor().copy(this)}toJSON(){return{radius:this.radius,center:this.center.toArray()}}fromJSON(e){return this.radius=e.radius,this.center.fromArray(e.center),this}}let eu=0;const Ft=new ht,Qa=new Dt,cr=new G,Ut=new yr,Rr=new yr,mt=new G;class Vt extends Bi{constructor(){super(),this.isBufferGeometry=!0,Object.defineProperty(this,"id",{value:eu++}),this.uuid=Sr(),this.name="",this.type="BufferGeometry",this.index=null,this.indirect=null,this.indirectOffset=0,this.attributes={},this.morphAttributes={},this.morphTargetsRelative=!1,this.groups=[],this.boundingBox=null,this.boundingSphere=null,this.drawRange={start:0,count:1/0},this.userData={}}getIndex(){return this.index}setIndex(e){return Array.isArray(e)?this.index=new(Ic(e)?To:Eo)(e,1):this.index=e,this}setIndirect(e,t=0){return this.indirect=e,this.indirectOffset=t,this}getIndirect(){return this.indirect}getAttribute(e){return this.attributes[e]}setAttribute(e,t){return this.attributes[e]=t,this}deleteAttribute(e){return delete this.attributes[e],this}hasAttribute(e){return this.attributes[e]!==void 0}addGroup(e,t,i=0){this.groups.push({start:e,count:t,materialIndex:i})}clearGroups(){this.groups=[]}setDrawRange(e,t){this.drawRange.start=e,this.drawRange.count=t}applyMatrix4(e){const t=this.attributes.position;t!==void 0&&(t.applyMatrix4(e),t.needsUpdate=!0);const i=this.attributes.normal;if(i!==void 0){const a=new Ce().getNormalMatrix(e);i.applyNormalMatrix(a),i.needsUpdate=!0}const n=this.attributes.tangent;return n!==void 0&&(n.transformDirection(e),n.needsUpdate=!0),this.boundingBox!==null&&this.computeBoundingBox(),this.boundingSphere!==null&&this.computeBoundingSphere(),this}applyQuaternion(e){return Ft.makeRotationFromQuaternion(e),this.applyMatrix4(Ft),this}rotateX(e){return Ft.makeRotationX(e),this.applyMatrix4(Ft),this}rotateY(e){return Ft.makeRotationY(e),this.applyMatrix4(Ft),this}rotateZ(e){return Ft.makeRotationZ(e),this.applyMatrix4(Ft),this}translate(e,t,i){return Ft.makeTranslation(e,t,i),this.applyMatrix4(Ft),this}scale(e,t,i){return Ft.makeScale(e,t,i),this.applyMatrix4(Ft),this}lookAt(e){return Qa.lookAt(e),Qa.updateMatrix(),this.applyMatrix4(Qa.matrix),this}center(){return this.computeBoundingBox(),this.boundingBox.getCenter(cr).negate(),this.translate(cr.x,cr.y,cr.z),this}setFromPoints(e){const t=this.getAttribute("position");if(t===void 0){const i=[];for(let n=0,a=e.length;n<a;n++){const s=e[n];i.push(s.x,s.y,s.z||0)}this.setAttribute("position",new mi(i,3))}else{const i=Math.min(e.length,t.count);for(let n=0;n<i;n++){const a=e[n];t.setXYZ(n,a.x,a.y,a.z||0)}e.length>t.count&&Ae("BufferGeometry: Buffer size too small for points data. Use .dispose() and create a new geometry."),t.needsUpdate=!0}return this}computeBoundingBox(){this.boundingBox===null&&(this.boundingBox=new yr);const e=this.attributes.position,t=this.morphAttributes.position;if(e&&e.isGLBufferAttribute){He("BufferGeometry.computeBoundingBox(): GLBufferAttribute requires a manual bounding box.",this),this.boundingBox.set(new G(-1/0,-1/0,-1/0),new G(1/0,1/0,1/0));return}if(e!==void 0){if(this.boundingBox.setFromBufferAttribute(e),t)for(let i=0,n=t.length;i<n;i++){const a=t[i];Ut.setFromBufferAttribute(a),this.morphTargetsRelative?(mt.addVectors(this.boundingBox.min,Ut.min),this.boundingBox.expandByPoint(mt),mt.addVectors(this.boundingBox.max,Ut.max),this.boundingBox.expandByPoint(mt)):(this.boundingBox.expandByPoint(Ut.min),this.boundingBox.expandByPoint(Ut.max))}}else this.boundingBox.makeEmpty();(isNaN(this.boundingBox.min.x)||isNaN(this.boundingBox.min.y)||isNaN(this.boundingBox.min.z))&&He('BufferGeometry.computeBoundingBox(): Computed min/max have NaN values. The "position" attribute is likely to have NaN values.',this)}computeBoundingSphere(){this.boundingSphere===null&&(this.boundingSphere=new wr);const e=this.attributes.position,t=this.morphAttributes.position;if(e&&e.isGLBufferAttribute){He("BufferGeometry.computeBoundingSphere(): GLBufferAttribute requires a manual bounding sphere.",this),this.boundingSphere.set(new G,1/0);return}if(e){const i=this.boundingSphere.center;if(Ut.setFromBufferAttribute(e),t)for(let a=0,s=t.length;a<s;a++){const o=t[a];Rr.setFromBufferAttribute(o),this.morphTargetsRelative?(mt.addVectors(Ut.min,Rr.min),Ut.expandByPoint(mt),mt.addVectors(Ut.max,Rr.max),Ut.expandByPoint(mt)):(Ut.expandByPoint(Rr.min),Ut.expandByPoint(Rr.max))}Ut.getCenter(i);let n=0;for(let a=0,s=e.count;a<s;a++)mt.fromBufferAttribute(e,a),n=Math.max(n,i.distanceToSquared(mt));if(t)for(let a=0,s=t.length;a<s;a++){const o=t[a],c=this.morphTargetsRelative;for(let l=0,d=o.count;l<d;l++)mt.fromBufferAttribute(o,l),c&&(cr.fromBufferAttribute(e,l),mt.add(cr)),n=Math.max(n,i.distanceToSquared(mt))}this.boundingSphere.radius=Math.sqrt(n),isNaN(this.boundingSphere.radius)&&He('BufferGeometry.computeBoundingSphere(): Computed radius is NaN. The "position" attribute is likely to have NaN values.',this)}}computeTangents(){const e=this.index,t=this.attributes;if(e===null||t.position===void 0||t.normal===void 0||t.uv===void 0){He("BufferGeometry: .computeTangents() failed. Missing required attributes (index, position, normal or uv)");return}const i=t.position,n=t.normal,a=t.uv;this.hasAttribute("tangent")===!1&&this.setAttribute("tangent",new Nt(new Float32Array(4*i.count),4));const s=this.getAttribute("tangent"),o=[],c=[];for(let v=0;v<i.count;v++)o[v]=new G,c[v]=new G;const l=new G,d=new G,m=new G,u=new Ke,g=new Ke,x=new Ke,E=new G,p=new G;function h(v,b,F){l.fromBufferAttribute(i,v),d.fromBufferAttribute(i,b),m.fromBufferAttribute(i,F),u.fromBufferAttribute(a,v),g.fromBufferAttribute(a,b),x.fromBufferAttribute(a,F),d.sub(l),m.sub(l),g.sub(u),x.sub(u);const w=1/(g.x*x.y-x.x*g.y);isFinite(w)&&(E.copy(d).multiplyScalar(x.y).addScaledVector(m,-g.y).multiplyScalar(w),p.copy(m).multiplyScalar(g.x).addScaledVector(d,-x.x).multiplyScalar(w),o[v].add(E),o[b].add(E),o[F].add(E),c[v].add(p),c[b].add(p),c[F].add(p))}let S=this.groups;S.length===0&&(S=[{start:0,count:e.count}]);for(let v=0,b=S.length;v<b;++v){const F=S[v],w=F.start,N=F.count;for(let W=w,q=w+N;W<q;W+=3)h(e.getX(W+0),e.getX(W+1),e.getX(W+2))}const A=new G,T=new G,U=new G,y=new G;function C(v){U.fromBufferAttribute(n,v),y.copy(U);const b=o[v];A.copy(b),A.sub(U.multiplyScalar(U.dot(b))).normalize(),T.crossVectors(y,b);const F=T.dot(c[v])<0?-1:1;s.setXYZW(v,A.x,A.y,A.z,F)}for(let v=0,b=S.length;v<b;++v){const F=S[v],w=F.start,N=F.count;for(let W=w,q=w+N;W<q;W+=3)C(e.getX(W+0)),C(e.getX(W+1)),C(e.getX(W+2))}}computeVertexNormals(){const e=this.index,t=this.getAttribute("position");if(t!==void 0){let i=this.getAttribute("normal");if(i===void 0)i=new Nt(new Float32Array(t.count*3),3),this.setAttribute("normal",i);else for(let u=0,g=i.count;u<g;u++)i.setXYZ(u,0,0,0);const n=new G,a=new G,s=new G,o=new G,c=new G,l=new G,d=new G,m=new G;if(e)for(let u=0,g=e.count;u<g;u+=3){const x=e.getX(u+0),E=e.getX(u+1),p=e.getX(u+2);n.fromBufferAttribute(t,x),a.fromBufferAttribute(t,E),s.fromBufferAttribute(t,p),d.subVectors(s,a),m.subVectors(n,a),d.cross(m),o.fromBufferAttribute(i,x),c.fromBufferAttribute(i,E),l.fromBufferAttribute(i,p),o.add(d),c.add(d),l.add(d),i.setXYZ(x,o.x,o.y,o.z),i.setXYZ(E,c.x,c.y,c.z),i.setXYZ(p,l.x,l.y,l.z)}else for(let u=0,g=t.count;u<g;u+=3)n.fromBufferAttribute(t,u+0),a.fromBufferAttribute(t,u+1),s.fromBufferAttribute(t,u+2),d.subVectors(s,a),m.subVectors(n,a),d.cross(m),i.setXYZ(u+0,d.x,d.y,d.z),i.setXYZ(u+1,d.x,d.y,d.z),i.setXYZ(u+2,d.x,d.y,d.z);this.normalizeNormals(),i.needsUpdate=!0}}normalizeNormals(){const e=this.attributes.normal;for(let t=0,i=e.count;t<i;t++)mt.fromBufferAttribute(e,t),mt.normalize(),e.setXYZ(t,mt.x,mt.y,mt.z)}toNonIndexed(){function e(o,c){const l=o.array,d=o.itemSize,m=o.normalized,u=new l.constructor(c.length*d);let g=0,x=0;for(let E=0,p=c.length;E<p;E++){o.isInterleavedBufferAttribute?g=c[E]*o.data.stride+o.offset:g=c[E]*d;for(let h=0;h<d;h++)u[x++]=l[g++]}return new Nt(u,d,m)}if(this.index===null)return Ae("BufferGeometry.toNonIndexed(): BufferGeometry is already non-indexed."),this;const t=new Vt,i=this.index.array,n=this.attributes;for(const o in n){const c=n[o],l=e(c,i);t.setAttribute(o,l)}const a=this.morphAttributes;for(const o in a){const c=[],l=a[o];for(let d=0,m=l.length;d<m;d++){const u=l[d],g=e(u,i);c.push(g)}t.morphAttributes[o]=c}t.morphTargetsRelative=this.morphTargetsRelative;const s=this.groups;for(let o=0,c=s.length;o<c;o++){const l=s[o];t.addGroup(l.start,l.count,l.materialIndex)}return t}toJSON(){const e={metadata:{version:4.7,type:"BufferGeometry",generator:"BufferGeometry.toJSON"}};if(e.uuid=this.uuid,e.type=this.type,this.name!==""&&(e.name=this.name),Object.keys(this.userData).length>0&&(e.userData=this.userData),this.parameters!==void 0){const c=this.parameters;for(const l in c)c[l]!==void 0&&(e[l]=c[l]);return e}e.data={attributes:{}};const t=this.index;t!==null&&(e.data.index={type:t.array.constructor.name,array:Array.prototype.slice.call(t.array)});const i=this.attributes;for(const c in i){const l=i[c];e.data.attributes[c]=l.toJSON(e.data)}const n={};let a=!1;for(const c in this.morphAttributes){const l=this.morphAttributes[c],d=[];for(let m=0,u=l.length;m<u;m++){const g=l[m];d.push(g.toJSON(e.data))}d.length>0&&(n[c]=d,a=!0)}a&&(e.data.morphAttributes=n,e.data.morphTargetsRelative=this.morphTargetsRelative);const s=this.groups;s.length>0&&(e.data.groups=JSON.parse(JSON.stringify(s)));const o=this.boundingSphere;return o!==null&&(e.data.boundingSphere=o.toJSON()),e}clone(){return new this.constructor().copy(this)}copy(e){this.index=null,this.attributes={},this.morphAttributes={},this.groups=[],this.boundingBox=null,this.boundingSphere=null;const t={};this.name=e.name;const i=e.index;i!==null&&this.setIndex(i.clone());const n=e.attributes;for(const l in n){const d=n[l];this.setAttribute(l,d.clone(t))}const a=e.morphAttributes;for(const l in a){const d=[],m=a[l];for(let u=0,g=m.length;u<g;u++)d.push(m[u].clone(t));this.morphAttributes[l]=d}this.morphTargetsRelative=e.morphTargetsRelative;const s=e.groups;for(let l=0,d=s.length;l<d;l++){const m=s[l];this.addGroup(m.start,m.count,m.materialIndex)}const o=e.boundingBox;o!==null&&(this.boundingBox=o.clone());const c=e.boundingSphere;return c!==null&&(this.boundingSphere=c.clone()),this.drawRange.start=e.drawRange.start,this.drawRange.count=e.drawRange.count,this.userData=e.userData,this}dispose(){this.dispatchEvent({type:"dispose"})}}let tu=0;class an extends Bi{constructor(){super(),this.isMaterial=!0,Object.defineProperty(this,"id",{value:tu++}),this.uuid=Sr(),this.name="",this.type="Material",this.blending=ji,this.side=ni,this.vertexColors=!1,this.opacity=1,this.transparent=!1,this.alphaHash=!1,this.blendSrc=Ln,this.blendDst=Nn,this.blendEquation=Ii,this.blendSrcAlpha=null,this.blendDstAlpha=null,this.blendEquationAlpha=null,this.blendColor=new qe(0,0,0),this.blendAlpha=0,this.depthFunc=Ki,this.depthTest=!0,this.depthWrite=!0,this.stencilWriteMask=255,this.stencilFunc=to,this.stencilRef=0,this.stencilFuncMask=255,this.stencilFail=Zi,this.stencilZFail=Zi,this.stencilZPass=Zi,this.stencilWrite=!1,this.clippingPlanes=null,this.clipIntersection=!1,this.clipShadows=!1,this.shadowSide=null,this.colorWrite=!0,this.precision=null,this.polygonOffset=!1,this.polygonOffsetFactor=0,this.polygonOffsetUnits=0,this.dithering=!1,this.alphaToCoverage=!1,this.premultipliedAlpha=!1,this.forceSinglePass=!1,this.allowOverride=!0,this.visible=!0,this.toneMapped=!0,this.userData={},this.version=0,this._alphaTest=0}get alphaTest(){return this._alphaTest}set alphaTest(e){this._alphaTest>0!=e>0&&this.version++,this._alphaTest=e}onBeforeRender(){}onBeforeCompile(){}customProgramCacheKey(){return this.onBeforeCompile.toString()}setValues(e){if(e!==void 0)for(const t in e){const i=e[t];if(i===void 0){Ae(`Material: parameter '${t}' has value of undefined.`);continue}const n=this[t];if(n===void 0){Ae(`Material: '${t}' is not a property of THREE.${this.type}.`);continue}n&&n.isColor?n.set(i):n&&n.isVector3&&i&&i.isVector3?n.copy(i):this[t]=i}}toJSON(e){const t=e===void 0||typeof e=="string";t&&(e={textures:{},images:{}});const i={metadata:{version:4.7,type:"Material",generator:"Material.toJSON"}};i.uuid=this.uuid,i.type=this.type,this.name!==""&&(i.name=this.name),this.color&&this.color.isColor&&(i.color=this.color.getHex()),this.roughness!==void 0&&(i.roughness=this.roughness),this.metalness!==void 0&&(i.metalness=this.metalness),this.sheen!==void 0&&(i.sheen=this.sheen),this.sheenColor&&this.sheenColor.isColor&&(i.sheenColor=this.sheenColor.getHex()),this.sheenRoughness!==void 0&&(i.sheenRoughness=this.sheenRoughness),this.emissive&&this.emissive.isColor&&(i.emissive=this.emissive.getHex()),this.emissiveIntensity!==void 0&&this.emissiveIntensity!==1&&(i.emissiveIntensity=this.emissiveIntensity),this.specular&&this.specular.isColor&&(i.specular=this.specular.getHex()),this.specularIntensity!==void 0&&(i.specularIntensity=this.specularIntensity),this.specularColor&&this.specularColor.isColor&&(i.specularColor=this.specularColor.getHex()),this.shininess!==void 0&&(i.shininess=this.shininess),this.clearcoat!==void 0&&(i.clearcoat=this.clearcoat),this.clearcoatRoughness!==void 0&&(i.clearcoatRoughness=this.clearcoatRoughness),this.clearcoatMap&&this.clearcoatMap.isTexture&&(i.clearcoatMap=this.clearcoatMap.toJSON(e).uuid),this.clearcoatRoughnessMap&&this.clearcoatRoughnessMap.isTexture&&(i.clearcoatRoughnessMap=this.clearcoatRoughnessMap.toJSON(e).uuid),this.clearcoatNormalMap&&this.clearcoatNormalMap.isTexture&&(i.clearcoatNormalMap=this.clearcoatNormalMap.toJSON(e).uuid,i.clearcoatNormalScale=this.clearcoatNormalScale.toArray()),this.sheenColorMap&&this.sheenColorMap.isTexture&&(i.sheenColorMap=this.sheenColorMap.toJSON(e).uuid),this.sheenRoughnessMap&&this.sheenRoughnessMap.isTexture&&(i.sheenRoughnessMap=this.sheenRoughnessMap.toJSON(e).uuid),this.dispersion!==void 0&&(i.dispersion=this.dispersion),this.iridescence!==void 0&&(i.iridescence=this.iridescence),this.iridescenceIOR!==void 0&&(i.iridescenceIOR=this.iridescenceIOR),this.iridescenceThicknessRange!==void 0&&(i.iridescenceThicknessRange=this.iridescenceThicknessRange),this.iridescenceMap&&this.iridescenceMap.isTexture&&(i.iridescenceMap=this.iridescenceMap.toJSON(e).uuid),this.iridescenceThicknessMap&&this.iridescenceThicknessMap.isTexture&&(i.iridescenceThicknessMap=this.iridescenceThicknessMap.toJSON(e).uuid),this.anisotropy!==void 0&&(i.anisotropy=this.anisotropy),this.anisotropyRotation!==void 0&&(i.anisotropyRotation=this.anisotropyRotation),this.anisotropyMap&&this.anisotropyMap.isTexture&&(i.anisotropyMap=this.anisotropyMap.toJSON(e).uuid),this.map&&this.map.isTexture&&(i.map=this.map.toJSON(e).uuid),this.matcap&&this.matcap.isTexture&&(i.matcap=this.matcap.toJSON(e).uuid),this.alphaMap&&this.alphaMap.isTexture&&(i.alphaMap=this.alphaMap.toJSON(e).uuid),this.lightMap&&this.lightMap.isTexture&&(i.lightMap=this.lightMap.toJSON(e).uuid,i.lightMapIntensity=this.lightMapIntensity),this.aoMap&&this.aoMap.isTexture&&(i.aoMap=this.aoMap.toJSON(e).uuid,i.aoMapIntensity=this.aoMapIntensity),this.bumpMap&&this.bumpMap.isTexture&&(i.bumpMap=this.bumpMap.toJSON(e).uuid,i.bumpScale=this.bumpScale),this.normalMap&&this.normalMap.isTexture&&(i.normalMap=this.normalMap.toJSON(e).uuid,i.normalMapType=this.normalMapType,i.normalScale=this.normalScale.toArray()),this.displacementMap&&this.displacementMap.isTexture&&(i.displacementMap=this.displacementMap.toJSON(e).uuid,i.displacementScale=this.displacementScale,i.displacementBias=this.displacementBias),this.roughnessMap&&this.roughnessMap.isTexture&&(i.roughnessMap=this.roughnessMap.toJSON(e).uuid),this.metalnessMap&&this.metalnessMap.isTexture&&(i.metalnessMap=this.metalnessMap.toJSON(e).uuid),this.emissiveMap&&this.emissiveMap.isTexture&&(i.emissiveMap=this.emissiveMap.toJSON(e).uuid),this.specularMap&&this.specularMap.isTexture&&(i.specularMap=this.specularMap.toJSON(e).uuid),this.specularIntensityMap&&this.specularIntensityMap.isTexture&&(i.specularIntensityMap=this.specularIntensityMap.toJSON(e).uuid),this.specularColorMap&&this.specularColorMap.isTexture&&(i.specularColorMap=this.specularColorMap.toJSON(e).uuid),this.envMap&&this.envMap.isTexture&&(i.envMap=this.envMap.toJSON(e).uuid,this.combine!==void 0&&(i.combine=this.combine)),this.envMapRotation!==void 0&&(i.envMapRotation=this.envMapRotation.toArray()),this.envMapIntensity!==void 0&&(i.envMapIntensity=this.envMapIntensity),this.reflectivity!==void 0&&(i.reflectivity=this.reflectivity),this.refractionRatio!==void 0&&(i.refractionRatio=this.refractionRatio),this.gradientMap&&this.gradientMap.isTexture&&(i.gradientMap=this.gradientMap.toJSON(e).uuid),this.transmission!==void 0&&(i.transmission=this.transmission),this.transmissionMap&&this.transmissionMap.isTexture&&(i.transmissionMap=this.transmissionMap.toJSON(e).uuid),this.thickness!==void 0&&(i.thickness=this.thickness),this.thicknessMap&&this.thicknessMap.isTexture&&(i.thicknessMap=this.thicknessMap.toJSON(e).uuid),this.attenuationDistance!==void 0&&this.attenuationDistance!==1/0&&(i.attenuationDistance=this.attenuationDistance),this.attenuationColor!==void 0&&(i.attenuationColor=this.attenuationColor.getHex()),this.size!==void 0&&(i.size=this.size),this.shadowSide!==null&&(i.shadowSide=this.shadowSide),this.sizeAttenuation!==void 0&&(i.sizeAttenuation=this.sizeAttenuation),this.blending!==ji&&(i.blending=this.blending),this.side!==ni&&(i.side=this.side),this.vertexColors===!0&&(i.vertexColors=!0),this.opacity<1&&(i.opacity=this.opacity),this.transparent===!0&&(i.transparent=!0),this.blendSrc!==Ln&&(i.blendSrc=this.blendSrc),this.blendDst!==Nn&&(i.blendDst=this.blendDst),this.blendEquation!==Ii&&(i.blendEquation=this.blendEquation),this.blendSrcAlpha!==null&&(i.blendSrcAlpha=this.blendSrcAlpha),this.blendDstAlpha!==null&&(i.blendDstAlpha=this.blendDstAlpha),this.blendEquationAlpha!==null&&(i.blendEquationAlpha=this.blendEquationAlpha),this.blendColor&&this.blendColor.isColor&&(i.blendColor=this.blendColor.getHex()),this.blendAlpha!==0&&(i.blendAlpha=this.blendAlpha),this.depthFunc!==Ki&&(i.depthFunc=this.depthFunc),this.depthTest===!1&&(i.depthTest=this.depthTest),this.depthWrite===!1&&(i.depthWrite=this.depthWrite),this.colorWrite===!1&&(i.colorWrite=this.colorWrite),this.stencilWriteMask!==255&&(i.stencilWriteMask=this.stencilWriteMask),this.stencilFunc!==to&&(i.stencilFunc=this.stencilFunc),this.stencilRef!==0&&(i.stencilRef=this.stencilRef),this.stencilFuncMask!==255&&(i.stencilFuncMask=this.stencilFuncMask),this.stencilFail!==Zi&&(i.stencilFail=this.stencilFail),this.stencilZFail!==Zi&&(i.stencilZFail=this.stencilZFail),this.stencilZPass!==Zi&&(i.stencilZPass=this.stencilZPass),this.stencilWrite===!0&&(i.stencilWrite=this.stencilWrite),this.rotation!==void 0&&this.rotation!==0&&(i.rotation=this.rotation),this.polygonOffset===!0&&(i.polygonOffset=!0),this.polygonOffsetFactor!==0&&(i.polygonOffsetFactor=this.polygonOffsetFactor),this.polygonOffsetUnits!==0&&(i.polygonOffsetUnits=this.polygonOffsetUnits),this.linewidth!==void 0&&this.linewidth!==1&&(i.linewidth=this.linewidth),this.dashSize!==void 0&&(i.dashSize=this.dashSize),this.gapSize!==void 0&&(i.gapSize=this.gapSize),this.scale!==void 0&&(i.scale=this.scale),this.dithering===!0&&(i.dithering=!0),this.alphaTest>0&&(i.alphaTest=this.alphaTest),this.alphaHash===!0&&(i.alphaHash=!0),this.alphaToCoverage===!0&&(i.alphaToCoverage=!0),this.premultipliedAlpha===!0&&(i.premultipliedAlpha=!0),this.forceSinglePass===!0&&(i.forceSinglePass=!0),this.allowOverride===!1&&(i.allowOverride=!1),this.wireframe===!0&&(i.wireframe=!0),this.wireframeLinewidth>1&&(i.wireframeLinewidth=this.wireframeLinewidth),this.wireframeLinecap!=="round"&&(i.wireframeLinecap=this.wireframeLinecap),this.wireframeLinejoin!=="round"&&(i.wireframeLinejoin=this.wireframeLinejoin),this.flatShading===!0&&(i.flatShading=!0),this.visible===!1&&(i.visible=!1),this.toneMapped===!1&&(i.toneMapped=!1),this.fog===!1&&(i.fog=!1),Object.keys(this.userData).length>0&&(i.userData=this.userData);function n(a){const s=[];for(const o in a){const c=a[o];delete c.metadata,s.push(c)}return s}if(t){const a=n(e.textures),s=n(e.images);a.length>0&&(i.textures=a),s.length>0&&(i.images=s)}return i}clone(){return new this.constructor().copy(this)}copy(e){this.name=e.name,this.blending=e.blending,this.side=e.side,this.vertexColors=e.vertexColors,this.opacity=e.opacity,this.transparent=e.transparent,this.blendSrc=e.blendSrc,this.blendDst=e.blendDst,this.blendEquation=e.blendEquation,this.blendSrcAlpha=e.blendSrcAlpha,this.blendDstAlpha=e.blendDstAlpha,this.blendEquationAlpha=e.blendEquationAlpha,this.blendColor.copy(e.blendColor),this.blendAlpha=e.blendAlpha,this.depthFunc=e.depthFunc,this.depthTest=e.depthTest,this.depthWrite=e.depthWrite,this.stencilWriteMask=e.stencilWriteMask,this.stencilFunc=e.stencilFunc,this.stencilRef=e.stencilRef,this.stencilFuncMask=e.stencilFuncMask,this.stencilFail=e.stencilFail,this.stencilZFail=e.stencilZFail,this.stencilZPass=e.stencilZPass,this.stencilWrite=e.stencilWrite;const t=e.clippingPlanes;let i=null;if(t!==null){const n=t.length;i=new Array(n);for(let a=0;a!==n;++a)i[a]=t[a].clone()}return this.clippingPlanes=i,this.clipIntersection=e.clipIntersection,this.clipShadows=e.clipShadows,this.shadowSide=e.shadowSide,this.colorWrite=e.colorWrite,this.precision=e.precision,this.polygonOffset=e.polygonOffset,this.polygonOffsetFactor=e.polygonOffsetFactor,this.polygonOffsetUnits=e.polygonOffsetUnits,this.dithering=e.dithering,this.alphaTest=e.alphaTest,this.alphaHash=e.alphaHash,this.alphaToCoverage=e.alphaToCoverage,this.premultipliedAlpha=e.premultipliedAlpha,this.forceSinglePass=e.forceSinglePass,this.allowOverride=e.allowOverride,this.visible=e.visible,this.toneMapped=e.toneMapped,this.userData=JSON.parse(JSON.stringify(e.userData)),this}dispose(){this.dispatchEvent({type:"dispose"})}set needsUpdate(e){e===!0&&this.version++}}const gi=new G,es=new G,sn=new G,bi=new G,ts=new G,on=new G,is=new G;class iu{constructor(e=new G,t=new G(0,0,-1)){this.origin=e,this.direction=t}set(e,t){return this.origin.copy(e),this.direction.copy(t),this}copy(e){return this.origin.copy(e.origin),this.direction.copy(e.direction),this}at(e,t){return t.copy(this.origin).addScaledVector(this.direction,e)}lookAt(e){return this.direction.copy(e).sub(this.origin).normalize(),this}recast(e){return this.origin.copy(this.at(e,gi)),this}closestPointToPoint(e,t){t.subVectors(e,this.origin);const i=t.dot(this.direction);return i<0?t.copy(this.origin):t.copy(this.origin).addScaledVector(this.direction,i)}distanceToPoint(e){return Math.sqrt(this.distanceSqToPoint(e))}distanceSqToPoint(e){const t=gi.subVectors(e,this.origin).dot(this.direction);return t<0?this.origin.distanceToSquared(e):(gi.copy(this.origin).addScaledVector(this.direction,t),gi.distanceToSquared(e))}distanceSqToSegment(e,t,i,n){es.copy(e).add(t).multiplyScalar(.5),sn.copy(t).sub(e).normalize(),bi.copy(this.origin).sub(es);const a=e.distanceTo(t)*.5,s=-this.direction.dot(sn),o=bi.dot(this.direction),c=-bi.dot(sn),l=bi.lengthSq(),d=Math.abs(1-s*s);let m,u,g,x;if(d>0)if(m=s*c-o,u=s*o-c,x=a*d,m>=0)if(u>=-x)if(u<=x){const E=1/d;m*=E,u*=E,g=m*(m+s*u+2*o)+u*(s*m+u+2*c)+l}else u=a,m=Math.max(0,-(s*u+o)),g=-m*m+u*(u+2*c)+l;else u=-a,m=Math.max(0,-(s*u+o)),g=-m*m+u*(u+2*c)+l;else u<=-x?(m=Math.max(0,-(-s*a+o)),u=m>0?-a:Math.min(Math.max(-a,-c),a),g=-m*m+u*(u+2*c)+l):u<=x?(m=0,u=Math.min(Math.max(-a,-c),a),g=u*(u+2*c)+l):(m=Math.max(0,-(s*a+o)),u=m>0?a:Math.min(Math.max(-a,-c),a),g=-m*m+u*(u+2*c)+l);else u=s>0?-a:a,m=Math.max(0,-(s*u+o)),g=-m*m+u*(u+2*c)+l;return i&&i.copy(this.origin).addScaledVector(this.direction,m),n&&n.copy(es).addScaledVector(sn,u),g}intersectSphere(e,t){gi.subVectors(e.center,this.origin);const i=gi.dot(this.direction),n=gi.dot(gi)-i*i,a=e.radius*e.radius;if(n>a)return null;const s=Math.sqrt(a-n),o=i-s,c=i+s;return c<0?null:o<0?this.at(c,t):this.at(o,t)}intersectsSphere(e){return e.radius<0?!1:this.distanceSqToPoint(e.center)<=e.radius*e.radius}distanceToPlane(e){const t=e.normal.dot(this.direction);if(t===0)return e.distanceToPoint(this.origin)===0?0:null;const i=-(this.origin.dot(e.normal)+e.constant)/t;return i>=0?i:null}intersectPlane(e,t){const i=this.distanceToPlane(e);return i===null?null:this.at(i,t)}intersectsPlane(e){const t=e.distanceToPoint(this.origin);return t===0||e.normal.dot(this.direction)*t<0}intersectBox(e,t){let i,n,a,s,o,c;const l=1/this.direction.x,d=1/this.direction.y,m=1/this.direction.z,u=this.origin;return l>=0?(i=(e.min.x-u.x)*l,n=(e.max.x-u.x)*l):(i=(e.max.x-u.x)*l,n=(e.min.x-u.x)*l),d>=0?(a=(e.min.y-u.y)*d,s=(e.max.y-u.y)*d):(a=(e.max.y-u.y)*d,s=(e.min.y-u.y)*d),i>s||a>n||((a>i||isNaN(i))&&(i=a),(s<n||isNaN(n))&&(n=s),m>=0?(o=(e.min.z-u.z)*m,c=(e.max.z-u.z)*m):(o=(e.max.z-u.z)*m,c=(e.min.z-u.z)*m),i>c||o>n)||((o>i||i!==i)&&(i=o),(c<n||n!==n)&&(n=c),n<0)?null:this.at(i>=0?i:n,t)}intersectsBox(e){return this.intersectBox(e,gi)!==null}intersectTriangle(e,t,i,n,a){ts.subVectors(t,e),on.subVectors(i,e),is.crossVectors(ts,on);let s=this.direction.dot(is),o;if(s>0){if(n)return null;o=1}else if(s<0)o=-1,s=-s;else return null;bi.subVectors(this.origin,e);const c=o*this.direction.dot(on.crossVectors(bi,on));if(c<0)return null;const l=o*this.direction.dot(ts.cross(bi));if(l<0||c+l>s)return null;const d=-o*bi.dot(is);return d<0?null:this.at(d/s,a)}applyMatrix4(e){return this.origin.applyMatrix4(e),this.direction.transformDirection(e),this}equals(e){return e.origin.equals(this.origin)&&e.direction.equals(this.direction)}clone(){return new this.constructor().copy(this)}}class yo extends an{constructor(e){super(),this.isMeshBasicMaterial=!0,this.type="MeshBasicMaterial",this.color=new qe(16777215),this.map=null,this.lightMap=null,this.lightMapIntensity=1,this.aoMap=null,this.aoMapIntensity=1,this.specularMap=null,this.alphaMap=null,this.envMap=null,this.envMapRotation=new Xi,this.combine=Bs,this.reflectivity=1,this.refractionRatio=.98,this.wireframe=!1,this.wireframeLinewidth=1,this.wireframeLinecap="round",this.wireframeLinejoin="round",this.fog=!0,this.setValues(e)}copy(e){return super.copy(e),this.color.copy(e.color),this.map=e.map,this.lightMap=e.lightMap,this.lightMapIntensity=e.lightMapIntensity,this.aoMap=e.aoMap,this.aoMapIntensity=e.aoMapIntensity,this.specularMap=e.specularMap,this.alphaMap=e.alphaMap,this.envMap=e.envMap,this.envMapRotation.copy(e.envMapRotation),this.combine=e.combine,this.reflectivity=e.reflectivity,this.refractionRatio=e.refractionRatio,this.wireframe=e.wireframe,this.wireframeLinewidth=e.wireframeLinewidth,this.wireframeLinecap=e.wireframeLinecap,this.wireframeLinejoin=e.wireframeLinejoin,this.fog=e.fog,this}}const bo=new ht,Hi=new iu,ln=new wr,Ao=new G,cn=new G,un=new G,hn=new G,rs=new G,dn=new G,wo=new G,pn=new G;class Zt extends Dt{constructor(e=new Vt,t=new yo){super(),this.isMesh=!0,this.type="Mesh",this.geometry=e,this.material=t,this.morphTargetDictionary=void 0,this.morphTargetInfluences=void 0,this.count=1,this.updateMorphTargets()}copy(e,t){return super.copy(e,t),e.morphTargetInfluences!==void 0&&(this.morphTargetInfluences=e.morphTargetInfluences.slice()),e.morphTargetDictionary!==void 0&&(this.morphTargetDictionary=Object.assign({},e.morphTargetDictionary)),this.material=Array.isArray(e.material)?e.material.slice():e.material,this.geometry=e.geometry,this}updateMorphTargets(){const e=this.geometry.morphAttributes,t=Object.keys(e);if(t.length>0){const i=e[t[0]];if(i!==void 0){this.morphTargetInfluences=[],this.morphTargetDictionary={};for(let n=0,a=i.length;n<a;n++){const s=i[n].name||String(n);this.morphTargetInfluences.push(0),this.morphTargetDictionary[s]=n}}}}getVertexPosition(e,t){const i=this.geometry,n=i.attributes.position,a=i.morphAttributes.position,s=i.morphTargetsRelative;t.fromBufferAttribute(n,e);const o=this.morphTargetInfluences;if(a&&o){dn.set(0,0,0);for(let c=0,l=a.length;c<l;c++){const d=o[c],m=a[c];d!==0&&(rs.fromBufferAttribute(m,e),s?dn.addScaledVector(rs,d):dn.addScaledVector(rs.sub(t),d))}t.add(dn)}return t}raycast(e,t){const i=this.geometry,n=this.material,a=this.matrixWorld;n!==void 0&&(i.boundingSphere===null&&i.computeBoundingSphere(),ln.copy(i.boundingSphere),ln.applyMatrix4(a),Hi.copy(e.ray).recast(e.near),!(ln.containsPoint(Hi.origin)===!1&&(Hi.intersectSphere(ln,Ao)===null||Hi.origin.distanceToSquared(Ao)>(e.far-e.near)**2))&&(bo.copy(a).invert(),Hi.copy(e.ray).applyMatrix4(bo),!(i.boundingBox!==null&&Hi.intersectsBox(i.boundingBox)===!1)&&this._computeIntersections(e,t,Hi)))}_computeIntersections(e,t,i){let n;const a=this.geometry,s=this.material,o=a.index,c=a.attributes.position,l=a.attributes.uv,d=a.attributes.uv1,m=a.attributes.normal,u=a.groups,g=a.drawRange;if(o!==null)if(Array.isArray(s))for(let x=0,E=u.length;x<E;x++){const p=u[x],h=s[p.materialIndex],S=Math.max(p.start,g.start),A=Math.min(o.count,Math.min(p.start+p.count,g.start+g.count));for(let T=S,U=A;T<U;T+=3){const y=o.getX(T),C=o.getX(T+1),v=o.getX(T+2);n=fn(this,h,e,i,l,d,m,y,C,v),n&&(n.faceIndex=Math.floor(T/3),n.face.materialIndex=p.materialIndex,t.push(n))}}else{const x=Math.max(0,g.start),E=Math.min(o.count,g.start+g.count);for(let p=x,h=E;p<h;p+=3){const S=o.getX(p),A=o.getX(p+1),T=o.getX(p+2);n=fn(this,s,e,i,l,d,m,S,A,T),n&&(n.faceIndex=Math.floor(p/3),t.push(n))}}else if(c!==void 0)if(Array.isArray(s))for(let x=0,E=u.length;x<E;x++){const p=u[x],h=s[p.materialIndex],S=Math.max(p.start,g.start),A=Math.min(c.count,Math.min(p.start+p.count,g.start+g.count));for(let T=S,U=A;T<U;T+=3){const y=T,C=T+1,v=T+2;n=fn(this,h,e,i,l,d,m,y,C,v),n&&(n.faceIndex=Math.floor(T/3),n.face.materialIndex=p.materialIndex,t.push(n))}}else{const x=Math.max(0,g.start),E=Math.min(c.count,g.start+g.count);for(let p=x,h=E;p<h;p+=3){const S=p,A=p+1,T=p+2;n=fn(this,s,e,i,l,d,m,S,A,T),n&&(n.faceIndex=Math.floor(p/3),t.push(n))}}}}function ru(r,e,t,i,n,a,s,o){let c;if(e.side===bt?c=i.intersectTriangle(s,a,n,!0,o):c=i.intersectTriangle(n,a,s,e.side===ni,o),c===null)return null;pn.copy(o),pn.applyMatrix4(r.matrixWorld);const l=t.ray.origin.distanceTo(pn);return l<t.near||l>t.far?null:{distance:l,point:pn.clone(),object:r}}function fn(r,e,t,i,n,a,s,o,c,l){r.getVertexPosition(o,cn),r.getVertexPosition(c,un),r.getVertexPosition(l,hn);const d=ru(r,e,t,i,cn,un,hn,wo);if(d){const m=new G;kt.getBarycoord(wo,cn,un,hn,m),n&&(d.uv=kt.getInterpolatedAttribute(n,o,c,l,m,new Ke)),a&&(d.uv1=kt.getInterpolatedAttribute(a,o,c,l,m,new Ke)),s&&(d.normal=kt.getInterpolatedAttribute(s,o,c,l,m,new G),d.normal.dot(i.direction)>0&&d.normal.multiplyScalar(-1));const u={a:o,b:c,c:l,normal:new G,materialIndex:0};kt.getNormal(cn,un,hn,u.normal),d.face=u,d.barycoord=m}return d}class nu extends yt{constructor(e=null,t=1,i=1,n,a,s,o,c,l=_t,d=_t,m,u){super(null,s,o,c,l,d,n,a,m,u),this.isDataTexture=!0,this.image={data:e,width:t,height:i},this.generateMipmaps=!1,this.flipY=!1,this.unpackAlignment=1}}class mn extends Nt{constructor(e,t,i,n=1){super(e,t,i),this.isInstancedBufferAttribute=!0,this.meshPerAttribute=n}copy(e){return super.copy(e),this.meshPerAttribute=e.meshPerAttribute,this}toJSON(){const e=super.toJSON();return e.meshPerAttribute=this.meshPerAttribute,e.isInstancedBufferAttribute=!0,e}}const ns=new G,au=new G,su=new Ce;class Vi{constructor(e=new G(1,0,0),t=0){this.isPlane=!0,this.normal=e,this.constant=t}set(e,t){return this.normal.copy(e),this.constant=t,this}setComponents(e,t,i,n){return this.normal.set(e,t,i),this.constant=n,this}setFromNormalAndCoplanarPoint(e,t){return this.normal.copy(e),this.constant=-t.dot(this.normal),this}setFromCoplanarPoints(e,t,i){const n=ns.subVectors(i,t).cross(au.subVectors(e,t)).normalize();return this.setFromNormalAndCoplanarPoint(n,e),this}copy(e){return this.normal.copy(e.normal),this.constant=e.constant,this}normalize(){const e=1/this.normal.length();return this.normal.multiplyScalar(e),this.constant*=e,this}negate(){return this.constant*=-1,this.normal.negate(),this}distanceToPoint(e){return this.normal.dot(e)+this.constant}distanceToSphere(e){return this.distanceToPoint(e.center)-e.radius}projectPoint(e,t){return t.copy(e).addScaledVector(this.normal,-this.distanceToPoint(e))}intersectLine(e,t,i=!0){const n=e.delta(ns),a=this.normal.dot(n);if(a===0)return this.distanceToPoint(e.start)===0?t.copy(e.start):null;const s=-(e.start.dot(this.normal)+this.constant)/a;return i===!0&&(s<0||s>1)?null:t.copy(e.start).addScaledVector(n,s)}intersectsLine(e){const t=this.distanceToPoint(e.start),i=this.distanceToPoint(e.end);return t<0&&i>0||i<0&&t>0}intersectsBox(e){return e.intersectsPlane(this)}intersectsSphere(e){return e.intersectsPlane(this)}coplanarPoint(e){return e.copy(this.normal).multiplyScalar(-this.constant)}applyMatrix4(e,t){const i=t||su.getNormalMatrix(e),n=this.coplanarPoint(ns).applyMatrix4(e),a=this.normal.applyMatrix3(i).normalize();return this.constant=-n.dot(a),this}translate(e){return this.constant-=e.dot(this.normal),this}equals(e){return e.normal.equals(this.normal)&&e.constant===this.constant}clone(){return new this.constructor().copy(this)}}const ki=new wr,ou=new Ke(.5,.5),gn=new G;class Ro{constructor(e=new Vi,t=new Vi,i=new Vi,n=new Vi,a=new Vi,s=new Vi){this.planes=[e,t,i,n,a,s]}set(e,t,i,n,a,s){const o=this.planes;return o[0].copy(e),o[1].copy(t),o[2].copy(i),o[3].copy(n),o[4].copy(a),o[5].copy(s),this}copy(e){const t=this.planes;for(let i=0;i<6;i++)t[i].copy(e.planes[i]);return this}setFromProjectionMatrix(e,t=Kt,i=!1){const n=this.planes,a=e.elements,s=a[0],o=a[1],c=a[2],l=a[3],d=a[4],m=a[5],u=a[6],g=a[7],x=a[8],E=a[9],p=a[10],h=a[11],S=a[12],A=a[13],T=a[14],U=a[15];if(n[0].setComponents(l-s,g-d,h-x,U-S).normalize(),n[1].setComponents(l+s,g+d,h+x,U+S).normalize(),n[2].setComponents(l+o,g+m,h+E,U+A).normalize(),n[3].setComponents(l-o,g-m,h-E,U-A).normalize(),i)n[4].setComponents(c,u,p,T).normalize(),n[5].setComponents(l-c,g-u,h-p,U-T).normalize();else if(n[4].setComponents(l-c,g-u,h-p,U-T).normalize(),t===Kt)n[5].setComponents(l+c,g+u,h+p,U+T).normalize();else if(t===jr)n[5].setComponents(c,u,p,T).normalize();else throw new Error("THREE.Frustum.setFromProjectionMatrix(): Invalid coordinate system: "+t);return this}intersectsObject(e){if(e.boundingSphere!==void 0)e.boundingSphere===null&&e.computeBoundingSphere(),ki.copy(e.boundingSphere).applyMatrix4(e.matrixWorld);else{const t=e.geometry;t.boundingSphere===null&&t.computeBoundingSphere(),ki.copy(t.boundingSphere).applyMatrix4(e.matrixWorld)}return this.intersectsSphere(ki)}intersectsSprite(e){ki.center.set(0,0,0);const t=ou.distanceTo(e.center);return ki.radius=.7071067811865476+t,ki.applyMatrix4(e.matrixWorld),this.intersectsSphere(ki)}intersectsSphere(e){const t=this.planes,i=e.center,n=-e.radius;for(let a=0;a<6;a++)if(t[a].distanceToPoint(i)<n)return!1;return!0}intersectsBox(e){const t=this.planes;for(let i=0;i<6;i++){const n=t[i];if(gn.x=n.normal.x>0?e.max.x:e.min.x,gn.y=n.normal.y>0?e.max.y:e.min.y,gn.z=n.normal.z>0?e.max.z:e.min.z,n.distanceToPoint(gn)<0)return!1}return!0}containsPoint(e){const t=this.planes;for(let i=0;i<6;i++)if(t[i].distanceToPoint(e)<0)return!1;return!0}clone(){return new this.constructor().copy(this)}}class Co extends yt{constructor(e=[],t=Li,i,n,a,s,o,c,l,d){super(e,t,i,n,a,s,o,c,l,d),this.isCubeTexture=!0,this.flipY=!1}get images(){return this.image}set images(e){this.image=e}}class ur extends yt{constructor(e,t,i=Yt,n,a,s,o=_t,c=_t,l,d=ci,m=1){if(d!==ci&&d!==Fi)throw new Error("DepthTexture format must be either THREE.DepthFormat or THREE.DepthStencilFormat");const u={width:e,height:t,depth:m};super(u,n,a,s,o,c,d,i,l),this.isDepthTexture=!0,this.flipY=!1,this.generateMipmaps=!1,this.compareFunction=null}copy(e){return super.copy(e),this.source=new Ba(Object.assign({},e.image)),this.compareFunction=e.compareFunction,this}toJSON(e){const t=super.toJSON(e);return this.compareFunction!==null&&(t.compareFunction=this.compareFunction),t}}class lu extends ur{constructor(e,t=Yt,i=Li,n,a,s=_t,o=_t,c,l=ci){const d={width:e,height:e,depth:1},m=[d,d,d,d,d,d];super(e,e,t,i,n,a,s,o,c,l),this.image=m,this.isCubeDepthTexture=!0,this.isCubeTexture=!0}get images(){return this.image}set images(e){this.image=e}}class Po extends yt{constructor(e=null){super(),this.sourceTexture=e,this.isExternalTexture=!0}copy(e){return super.copy(e),this.sourceTexture=e.sourceTexture,this}}class Dr extends Vt{constructor(e=1,t=1,i=1,n=1,a=1,s=1){super(),this.type="BoxGeometry",this.parameters={width:e,height:t,depth:i,widthSegments:n,heightSegments:a,depthSegments:s};const o=this;n=Math.floor(n),a=Math.floor(a),s=Math.floor(s);const c=[],l=[],d=[],m=[];let u=0,g=0;x("z","y","x",-1,-1,i,t,e,s,a,0),x("z","y","x",1,-1,i,t,-e,s,a,1),x("x","z","y",1,1,e,i,t,n,s,2),x("x","z","y",1,-1,e,i,-t,n,s,3),x("x","y","z",1,-1,e,t,i,n,a,4),x("x","y","z",-1,-1,e,t,-i,n,a,5),this.setIndex(c),this.setAttribute("position",new mi(l,3)),this.setAttribute("normal",new mi(d,3)),this.setAttribute("uv",new mi(m,2));function x(E,p,h,S,A,T,U,y,C,v,b){const F=T/C,w=U/v,N=T/2,W=U/2,q=y/2,L=C+1,V=v+1;let H=0,Z=0;const Q=new G;for(let re=0;re<V;re++){const ve=re*w-W;for(let we=0;we<L;we++){const Ge=we*F-N;Q[E]=Ge*S,Q[p]=ve*A,Q[h]=q,l.push(Q.x,Q.y,Q.z),Q[E]=0,Q[p]=0,Q[h]=y>0?1:-1,d.push(Q.x,Q.y,Q.z),m.push(we/C),m.push(1-re/v),H+=1}}for(let re=0;re<v;re++)for(let ve=0;ve<C;ve++){const we=u+ve+L*re,Ge=u+ve+L*(re+1),Ye=u+(ve+1)+L*(re+1),Ue=u+(ve+1)+L*re;c.push(we,Ge,Ue),c.push(Ge,Ye,Ue),Z+=6}o.addGroup(g,Z,b),g+=Z,u+=H}}copy(e){return super.copy(e),this.parameters=Object.assign({},e.parameters),this}static fromJSON(e){return new Dr(e.width,e.height,e.depth,e.widthSegments,e.heightSegments,e.depthSegments)}}class An extends Vt{constructor(e=1,t=1,i=1,n=1){super(),this.type="PlaneGeometry",this.parameters={width:e,height:t,widthSegments:i,heightSegments:n};const a=e/2,s=t/2,o=Math.floor(i),c=Math.floor(n),l=o+1,d=c+1,m=e/o,u=t/c,g=[],x=[],E=[],p=[];for(let h=0;h<d;h++){const S=h*u-s;for(let A=0;A<l;A++){const T=A*m-a;x.push(T,-S,0),E.push(0,0,1),p.push(A/o),p.push(1-h/c)}}for(let h=0;h<c;h++)for(let S=0;S<o;S++){const A=S+l*h,T=S+l*(h+1),U=S+1+l*(h+1),y=S+1+l*h;g.push(A,T,y),g.push(T,U,y)}this.setIndex(g),this.setAttribute("position",new mi(x,3)),this.setAttribute("normal",new mi(E,3)),this.setAttribute("uv",new mi(p,2))}copy(e){return super.copy(e),this.parameters=Object.assign({},e.parameters),this}static fromJSON(e){return new An(e.width,e.height,e.widthSegments,e.heightSegments)}}function hr(r){const e={};for(const t in r){e[t]={};for(const i in r[t]){const n=r[t][i];if(Uo(n))n.isRenderTargetTexture?(Ae("UniformsUtils: Textures of render targets cannot be cloned via cloneUniforms() or mergeUniforms()."),e[t][i]=null):e[t][i]=n.clone();else if(Array.isArray(n))if(Uo(n[0])){const a=[];for(let s=0,o=n.length;s<o;s++)a[s]=n[s].clone();e[t][i]=a}else e[t][i]=n.slice();else e[t][i]=n}}return e}function Tt(r){const e={};for(let t=0;t<r.length;t++){const i=hr(r[t]);for(const n in i)e[n]=i[n]}return e}function Uo(r){return r&&(r.isColor||r.isMatrix3||r.isMatrix4||r.isVector2||r.isVector3||r.isVector4||r.isTexture||r.isQuaternion)}function cu(r){const e=[];for(let t=0;t<r.length;t++)e.push(r[t].clone());return e}function Do(r){const e=r.getRenderTarget();return e===null?r.outputColorSpace:e.isXRRenderTarget===!0?e.texture.colorSpace:ze.workingColorSpace}const uu={clone:hr,merge:Tt};var hu=`void main() {
	gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );
}`,du=`void main() {
	gl_FragColor = vec4( 1.0, 0.0, 0.0, 1.0 );
}`;class $t extends an{constructor(e){super(),this.isShaderMaterial=!0,this.type="ShaderMaterial",this.defines={},this.uniforms={},this.uniformsGroups=[],this.vertexShader=hu,this.fragmentShader=du,this.linewidth=1,this.wireframe=!1,this.wireframeLinewidth=1,this.fog=!1,this.lights=!1,this.clipping=!1,this.forceSinglePass=!0,this.extensions={clipCullDistance:!1,multiDraw:!1},this.defaultAttributeValues={color:[1,1,1],uv:[0,0],uv1:[0,0]},this.index0AttributeName=void 0,this.uniformsNeedUpdate=!1,this.glslVersion=null,e!==void 0&&this.setValues(e)}copy(e){return super.copy(e),this.fragmentShader=e.fragmentShader,this.vertexShader=e.vertexShader,this.uniforms=hr(e.uniforms),this.uniformsGroups=cu(e.uniformsGroups),this.defines=Object.assign({},e.defines),this.wireframe=e.wireframe,this.wireframeLinewidth=e.wireframeLinewidth,this.fog=e.fog,this.lights=e.lights,this.clipping=e.clipping,this.extensions=Object.assign({},e.extensions),this.glslVersion=e.glslVersion,this.defaultAttributeValues=Object.assign({},e.defaultAttributeValues),this.index0AttributeName=e.index0AttributeName,this.uniformsNeedUpdate=e.uniformsNeedUpdate,this}toJSON(e){const t=super.toJSON(e);t.glslVersion=this.glslVersion,t.uniforms={};for(const n in this.uniforms){const a=this.uniforms[n].value;a&&a.isTexture?t.uniforms[n]={type:"t",value:a.toJSON(e).uuid}:a&&a.isColor?t.uniforms[n]={type:"c",value:a.getHex()}:a&&a.isVector2?t.uniforms[n]={type:"v2",value:a.toArray()}:a&&a.isVector3?t.uniforms[n]={type:"v3",value:a.toArray()}:a&&a.isVector4?t.uniforms[n]={type:"v4",value:a.toArray()}:a&&a.isMatrix3?t.uniforms[n]={type:"m3",value:a.toArray()}:a&&a.isMatrix4?t.uniforms[n]={type:"m4",value:a.toArray()}:t.uniforms[n]={value:a}}Object.keys(this.defines).length>0&&(t.defines=this.defines),t.vertexShader=this.vertexShader,t.fragmentShader=this.fragmentShader,t.lights=this.lights,t.clipping=this.clipping;const i={};for(const n in this.extensions)this.extensions[n]===!0&&(i[n]=!0);return Object.keys(i).length>0&&(t.extensions=i),t}}class Io extends $t{constructor(e){super(e),this.isRawShaderMaterial=!0,this.type="RawShaderMaterial"}}class pu extends an{constructor(e){super(),this.isMeshDepthMaterial=!0,this.type="MeshDepthMaterial",this.depthPacking=bc,this.map=null,this.alphaMap=null,this.displacementMap=null,this.displacementScale=1,this.displacementBias=0,this.wireframe=!1,this.wireframeLinewidth=1,this.setValues(e)}copy(e){return super.copy(e),this.depthPacking=e.depthPacking,this.map=e.map,this.alphaMap=e.alphaMap,this.displacementMap=e.displacementMap,this.displacementScale=e.displacementScale,this.displacementBias=e.displacementBias,this.wireframe=e.wireframe,this.wireframeLinewidth=e.wireframeLinewidth,this}}class fu extends an{constructor(e){super(),this.isMeshDistanceMaterial=!0,this.type="MeshDistanceMaterial",this.map=null,this.alphaMap=null,this.displacementMap=null,this.displacementScale=1,this.displacementBias=0,this.setValues(e)}copy(e){return super.copy(e),this.map=e.map,this.alphaMap=e.alphaMap,this.displacementMap=e.displacementMap,this.displacementScale=e.displacementScale,this.displacementBias=e.displacementBias,this}}const _n=new G,vn=new $i,Qt=new G;class Lo extends Dt{constructor(){super(),this.isCamera=!0,this.type="Camera",this.matrixWorldInverse=new ht,this.projectionMatrix=new ht,this.projectionMatrixInverse=new ht,this.coordinateSystem=Kt,this._reversedDepth=!1}get reversedDepth(){return this._reversedDepth}copy(e,t){return super.copy(e,t),this.matrixWorldInverse.copy(e.matrixWorldInverse),this.projectionMatrix.copy(e.projectionMatrix),this.projectionMatrixInverse.copy(e.projectionMatrixInverse),this.coordinateSystem=e.coordinateSystem,this}getWorldDirection(e){return super.getWorldDirection(e).negate()}updateMatrixWorld(e){super.updateMatrixWorld(e),this.matrixWorld.decompose(_n,vn,Qt),Qt.x===1&&Qt.y===1&&Qt.z===1?this.matrixWorldInverse.copy(this.matrixWorld).invert():this.matrixWorldInverse.compose(_n,vn,Qt.set(1,1,1)).invert()}updateWorldMatrix(e,t){super.updateWorldMatrix(e,t),this.matrixWorld.decompose(_n,vn,Qt),Qt.x===1&&Qt.y===1&&Qt.z===1?this.matrixWorldInverse.copy(this.matrixWorld).invert():this.matrixWorldInverse.compose(_n,vn,Qt.set(1,1,1)).invert()}clone(){return new this.constructor().copy(this)}}const Ai=new G,No=new Ke,Fo=new Ke;class Ht extends Lo{constructor(e=50,t=1,i=.1,n=2e3){super(),this.isPerspectiveCamera=!0,this.type="PerspectiveCamera",this.fov=e,this.zoom=1,this.near=i,this.far=n,this.focus=10,this.aspect=t,this.view=null,this.filmGauge=35,this.filmOffset=0,this.updateProjectionMatrix()}copy(e,t){return super.copy(e,t),this.fov=e.fov,this.zoom=e.zoom,this.near=e.near,this.far=e.far,this.focus=e.focus,this.aspect=e.aspect,this.view=e.view===null?null:Object.assign({},e.view),this.filmGauge=e.filmGauge,this.filmOffset=e.filmOffset,this}setFocalLength(e){const t=.5*this.getFilmHeight()/e;this.fov=La*2*Math.atan(t),this.updateProjectionMatrix()}getFocalLength(){const e=Math.tan(Ia*.5*this.fov);return .5*this.getFilmHeight()/e}getEffectiveFOV(){return La*2*Math.atan(Math.tan(Ia*.5*this.fov)/this.zoom)}getFilmWidth(){return this.filmGauge*Math.min(this.aspect,1)}getFilmHeight(){return this.filmGauge/Math.max(this.aspect,1)}getViewBounds(e,t,i){Ai.set(-1,-1,.5).applyMatrix4(this.projectionMatrixInverse),t.set(Ai.x,Ai.y).multiplyScalar(-e/Ai.z),Ai.set(1,1,.5).applyMatrix4(this.projectionMatrixInverse),i.set(Ai.x,Ai.y).multiplyScalar(-e/Ai.z)}getViewSize(e,t){return this.getViewBounds(e,No,Fo),t.subVectors(Fo,No)}setViewOffset(e,t,i,n,a,s){this.aspect=e/t,this.view===null&&(this.view={enabled:!0,fullWidth:1,fullHeight:1,offsetX:0,offsetY:0,width:1,height:1}),this.view.enabled=!0,this.view.fullWidth=e,this.view.fullHeight=t,this.view.offsetX=i,this.view.offsetY=n,this.view.width=a,this.view.height=s,this.updateProjectionMatrix()}clearViewOffset(){this.view!==null&&(this.view.enabled=!1),this.updateProjectionMatrix()}updateProjectionMatrix(){const e=this.near;let t=e*Math.tan(Ia*.5*this.fov)/this.zoom,i=2*t,n=this.aspect*i,a=-.5*n;const s=this.view;if(this.view!==null&&this.view.enabled){const c=s.fullWidth,l=s.fullHeight;a+=s.offsetX*n/c,t-=s.offsetY*i/l,n*=s.width/c,i*=s.height/l}const o=this.filmOffset;o!==0&&(a+=e*o/this.getFilmWidth()),this.projectionMatrix.makePerspective(a,a+n,t,t-i,e,this.far,this.coordinateSystem,this.reversedDepth),this.projectionMatrixInverse.copy(this.projectionMatrix).invert()}toJSON(e){const t=super.toJSON(e);return t.object.fov=this.fov,t.object.zoom=this.zoom,t.object.near=this.near,t.object.far=this.far,t.object.focus=this.focus,t.object.aspect=this.aspect,this.view!==null&&(t.object.view=Object.assign({},this.view)),t.object.filmGauge=this.filmGauge,t.object.filmOffset=this.filmOffset,t}}class as extends Lo{constructor(e=-1,t=1,i=1,n=-1,a=.1,s=2e3){super(),this.isOrthographicCamera=!0,this.type="OrthographicCamera",this.zoom=1,this.view=null,this.left=e,this.right=t,this.top=i,this.bottom=n,this.near=a,this.far=s,this.updateProjectionMatrix()}copy(e,t){return super.copy(e,t),this.left=e.left,this.right=e.right,this.top=e.top,this.bottom=e.bottom,this.near=e.near,this.far=e.far,this.zoom=e.zoom,this.view=e.view===null?null:Object.assign({},e.view),this}setViewOffset(e,t,i,n,a,s){this.view===null&&(this.view={enabled:!0,fullWidth:1,fullHeight:1,offsetX:0,offsetY:0,width:1,height:1}),this.view.enabled=!0,this.view.fullWidth=e,this.view.fullHeight=t,this.view.offsetX=i,this.view.offsetY=n,this.view.width=a,this.view.height=s,this.updateProjectionMatrix()}clearViewOffset(){this.view!==null&&(this.view.enabled=!1),this.updateProjectionMatrix()}updateProjectionMatrix(){const e=(this.right-this.left)/(2*this.zoom),t=(this.top-this.bottom)/(2*this.zoom),i=(this.right+this.left)/2,n=(this.top+this.bottom)/2;let a=i-e,s=i+e,o=n+t,c=n-t;if(this.view!==null&&this.view.enabled){const l=(this.right-this.left)/this.view.fullWidth/this.zoom,d=(this.top-this.bottom)/this.view.fullHeight/this.zoom;a+=l*this.view.offsetX,s=a+l*this.view.width,o-=d*this.view.offsetY,c=o-d*this.view.height}this.projectionMatrix.makeOrthographic(a,s,o,c,this.near,this.far,this.coordinateSystem,this.reversedDepth),this.projectionMatrixInverse.copy(this.projectionMatrix).invert()}toJSON(e){const t=super.toJSON(e);return t.object.zoom=this.zoom,t.object.left=this.left,t.object.right=this.right,t.object.top=this.top,t.object.bottom=this.bottom,t.object.near=this.near,t.object.far=this.far,this.view!==null&&(t.object.view=Object.assign({},this.view)),t}}class mu extends Vt{constructor(){super(),this.isInstancedBufferGeometry=!0,this.type="InstancedBufferGeometry",this.instanceCount=1/0}copy(e){return super.copy(e),this.instanceCount=e.instanceCount,this}toJSON(){const e=super.toJSON();return e.instanceCount=this.instanceCount,e.isInstancedBufferGeometry=!0,e}}const dr=-90,pr=1;class gu extends Dt{constructor(e,t,i){super(),this.type="CubeCamera",this.renderTarget=i,this.coordinateSystem=null,this.activeMipmapLevel=0;const n=new Ht(dr,pr,e,t);n.layers=this.layers,this.add(n);const a=new Ht(dr,pr,e,t);a.layers=this.layers,this.add(a);const s=new Ht(dr,pr,e,t);s.layers=this.layers,this.add(s);const o=new Ht(dr,pr,e,t);o.layers=this.layers,this.add(o);const c=new Ht(dr,pr,e,t);c.layers=this.layers,this.add(c);const l=new Ht(dr,pr,e,t);l.layers=this.layers,this.add(l)}updateCoordinateSystem(){const e=this.coordinateSystem,t=this.children.concat(),[i,n,a,s,o,c]=t;for(const l of t)this.remove(l);if(e===Kt)i.up.set(0,1,0),i.lookAt(1,0,0),n.up.set(0,1,0),n.lookAt(-1,0,0),a.up.set(0,0,-1),a.lookAt(0,1,0),s.up.set(0,0,1),s.lookAt(0,-1,0),o.up.set(0,1,0),o.lookAt(0,0,1),c.up.set(0,1,0),c.lookAt(0,0,-1);else if(e===jr)i.up.set(0,-1,0),i.lookAt(-1,0,0),n.up.set(0,-1,0),n.lookAt(1,0,0),a.up.set(0,0,1),a.lookAt(0,1,0),s.up.set(0,0,-1),s.lookAt(0,-1,0),o.up.set(0,-1,0),o.lookAt(0,0,1),c.up.set(0,-1,0),c.lookAt(0,0,-1);else throw new Error("THREE.CubeCamera.updateCoordinateSystem(): Invalid coordinate system: "+e);for(const l of t)this.add(l),l.updateMatrixWorld()}update(e,t){this.parent===null&&this.updateMatrixWorld();const{renderTarget:i,activeMipmapLevel:n}=this;this.coordinateSystem!==e.coordinateSystem&&(this.coordinateSystem=e.coordinateSystem,this.updateCoordinateSystem());const[a,s,o,c,l,d]=this.children,m=e.getRenderTarget(),u=e.getActiveCubeFace(),g=e.getActiveMipmapLevel(),x=e.xr.enabled;e.xr.enabled=!1;const E=i.texture.generateMipmaps;i.texture.generateMipmaps=!1;let p=!1;e.isWebGLRenderer===!0?p=e.state.buffers.depth.getReversed():p=e.reversedDepthBuffer,e.setRenderTarget(i,0,n),p&&e.autoClear===!1&&e.clearDepth(),e.render(t,a),e.setRenderTarget(i,1,n),p&&e.autoClear===!1&&e.clearDepth(),e.render(t,s),e.setRenderTarget(i,2,n),p&&e.autoClear===!1&&e.clearDepth(),e.render(t,o),e.setRenderTarget(i,3,n),p&&e.autoClear===!1&&e.clearDepth(),e.render(t,c),e.setRenderTarget(i,4,n),p&&e.autoClear===!1&&e.clearDepth(),e.render(t,l),i.texture.generateMipmaps=E,e.setRenderTarget(i,5,n),p&&e.autoClear===!1&&e.clearDepth(),e.render(t,d),e.setRenderTarget(m,u,g),e.xr.enabled=x,i.texture.needsPMREMUpdate=!0}}class _u extends Ht{constructor(e=[]){super(),this.isArrayCamera=!0,this.isMultiViewCamera=!1,this.cameras=e}}const vs=class vs{constructor(e,t,i,n){this.elements=[1,0,0,1],e!==void 0&&this.set(e,t,i,n)}identity(){return this.set(1,0,0,1),this}fromArray(e,t=0){for(let i=0;i<4;i++)this.elements[i]=e[i+t];return this}set(e,t,i,n){const a=this.elements;return a[0]=e,a[2]=t,a[1]=i,a[3]=n,this}};vs.prototype.isMatrix2=!0;let Oo=vs;function Bo(r,e,t,i){const n=vu(i);switch(t){case Zs:return r*e;case Qs:return r*e/n.components*n.byteLength;case Zn:return r*e/n.components*n.byteLength;case Oi:return r*e*2/n.components*n.byteLength;case $n:return r*e*2/n.components*n.byteLength;case $s:return r*e*3/n.components*n.byteLength;case Ot:return r*e*4/n.components*n.byteLength;case Qn:return r*e*4/n.components*n.byteLength;case zr:case Gr:return Math.floor((r+3)/4)*Math.floor((e+3)/4)*8;case Hr:case Vr:return Math.floor((r+3)/4)*Math.floor((e+3)/4)*16;case ta:case ra:return Math.max(r,16)*Math.max(e,8)/4;case ea:case ia:return Math.max(r,8)*Math.max(e,8)/2;case na:case aa:case oa:case la:return Math.floor((r+3)/4)*Math.floor((e+3)/4)*8;case sa:case kr:case ca:return Math.floor((r+3)/4)*Math.floor((e+3)/4)*16;case ua:return Math.floor((r+3)/4)*Math.floor((e+3)/4)*16;case ha:return Math.floor((r+4)/5)*Math.floor((e+3)/4)*16;case da:return Math.floor((r+4)/5)*Math.floor((e+4)/5)*16;case pa:return Math.floor((r+5)/6)*Math.floor((e+4)/5)*16;case fa:return Math.floor((r+5)/6)*Math.floor((e+5)/6)*16;case ma:return Math.floor((r+7)/8)*Math.floor((e+4)/5)*16;case ga:return Math.floor((r+7)/8)*Math.floor((e+5)/6)*16;case _a:return Math.floor((r+7)/8)*Math.floor((e+7)/8)*16;case va:return Math.floor((r+9)/10)*Math.floor((e+4)/5)*16;case xa:return Math.floor((r+9)/10)*Math.floor((e+5)/6)*16;case Ma:return Math.floor((r+9)/10)*Math.floor((e+7)/8)*16;case Sa:return Math.floor((r+9)/10)*Math.floor((e+9)/10)*16;case Ea:return Math.floor((r+11)/12)*Math.floor((e+9)/10)*16;case Ta:return Math.floor((r+11)/12)*Math.floor((e+11)/12)*16;case ya:case ba:case Aa:return Math.ceil(r/4)*Math.ceil(e/4)*16;case wa:case Ra:return Math.ceil(r/4)*Math.ceil(e/4)*8;case Wr:case Ca:return Math.ceil(r/4)*Math.ceil(e/4)*16}throw new Error(`Unable to determine texture byte length for ${t} format.`)}function vu(r){switch(r){case Lt:case Ys:return{byteLength:1,components:1};case xr:case js:case li:return{byteLength:2,components:1};case Kn:case Jn:return{byteLength:2,components:4};case Yt:case jn:case jt:return{byteLength:4,components:1};case Ks:case Js:return{byteLength:4,components:3}}throw new Error(`Unknown texture type ${r}.`)}typeof __THREE_DEVTOOLS__<"u"&&__THREE_DEVTOOLS__.dispatchEvent(new CustomEvent("register",{detail:{revision:In}})),typeof window<"u"&&(window.__THREE__?Ae("WARNING: Multiple instances of Three.js being imported."):window.__THREE__=In);/**
* @license
* Copyright 2010-2026 Three.js Authors
* SPDX-License-Identifier: MIT
*/function zo(){let r=null,e=!1,t=null,i=null;function n(a,s){t(a,s),i=r.requestAnimationFrame(n)}return{start:function(){e!==!0&&t!==null&&r!==null&&(i=r.requestAnimationFrame(n),e=!0)},stop:function(){r!==null&&r.cancelAnimationFrame(i),e=!1},setAnimationLoop:function(a){t=a},setContext:function(a){r=a}}}function xu(r){const e=new WeakMap;function t(o,c){const l=o.array,d=o.usage,m=l.byteLength,u=r.createBuffer();r.bindBuffer(c,u),r.bufferData(c,l,d),o.onUploadCallback();let g;if(l instanceof Float32Array)g=r.FLOAT;else if(typeof Float16Array<"u"&&l instanceof Float16Array)g=r.HALF_FLOAT;else if(l instanceof Uint16Array)o.isFloat16BufferAttribute?g=r.HALF_FLOAT:g=r.UNSIGNED_SHORT;else if(l instanceof Int16Array)g=r.SHORT;else if(l instanceof Uint32Array)g=r.UNSIGNED_INT;else if(l instanceof Int32Array)g=r.INT;else if(l instanceof Int8Array)g=r.BYTE;else if(l instanceof Uint8Array)g=r.UNSIGNED_BYTE;else if(l instanceof Uint8ClampedArray)g=r.UNSIGNED_BYTE;else throw new Error("THREE.WebGLAttributes: Unsupported buffer data format: "+l);return{buffer:u,type:g,bytesPerElement:l.BYTES_PER_ELEMENT,version:o.version,size:m}}function i(o,c,l){const d=c.array,m=c.updateRanges;if(r.bindBuffer(l,o),m.length===0)r.bufferSubData(l,0,d);else{m.sort((g,x)=>g.start-x.start);let u=0;for(let g=1;g<m.length;g++){const x=m[u],E=m[g];E.start<=x.start+x.count+1?x.count=Math.max(x.count,E.start+E.count-x.start):(++u,m[u]=E)}m.length=u+1;for(let g=0,x=m.length;g<x;g++){const E=m[g];r.bufferSubData(l,E.start*d.BYTES_PER_ELEMENT,d,E.start,E.count)}c.clearUpdateRanges()}c.onUploadCallback()}function n(o){return o.isInterleavedBufferAttribute&&(o=o.data),e.get(o)}function a(o){o.isInterleavedBufferAttribute&&(o=o.data);const c=e.get(o);c&&(r.deleteBuffer(c.buffer),e.delete(o))}function s(o,c){if(o.isInterleavedBufferAttribute&&(o=o.data),o.isGLBufferAttribute){const d=e.get(o);(!d||d.version<o.version)&&e.set(o,{buffer:o.buffer,type:o.type,bytesPerElement:o.elementSize,version:o.version});return}const l=e.get(o);if(l===void 0)e.set(o,t(o,c));else if(l.version<o.version){if(l.size!==o.array.byteLength)throw new Error("THREE.WebGLAttributes: The size of the buffer attribute's array buffer does not match the original size. Resizing buffer attributes is not supported.");i(l.buffer,o,c),l.version=o.version}}return{get:n,remove:a,update:s}}var Mu=`#ifdef USE_ALPHAHASH
	if ( diffuseColor.a < getAlphaHashThreshold( vPosition ) ) discard;
#endif`,Su=`#ifdef USE_ALPHAHASH
	const float ALPHA_HASH_SCALE = 0.05;
	float hash2D( vec2 value ) {
		return fract( 1.0e4 * sin( 17.0 * value.x + 0.1 * value.y ) * ( 0.1 + abs( sin( 13.0 * value.y + value.x ) ) ) );
	}
	float hash3D( vec3 value ) {
		return hash2D( vec2( hash2D( value.xy ), value.z ) );
	}
	float getAlphaHashThreshold( vec3 position ) {
		float maxDeriv = max(
			length( dFdx( position.xyz ) ),
			length( dFdy( position.xyz ) )
		);
		float pixScale = 1.0 / ( ALPHA_HASH_SCALE * maxDeriv );
		vec2 pixScales = vec2(
			exp2( floor( log2( pixScale ) ) ),
			exp2( ceil( log2( pixScale ) ) )
		);
		vec2 alpha = vec2(
			hash3D( floor( pixScales.x * position.xyz ) ),
			hash3D( floor( pixScales.y * position.xyz ) )
		);
		float lerpFactor = fract( log2( pixScale ) );
		float x = ( 1.0 - lerpFactor ) * alpha.x + lerpFactor * alpha.y;
		float a = min( lerpFactor, 1.0 - lerpFactor );
		vec3 cases = vec3(
			x * x / ( 2.0 * a * ( 1.0 - a ) ),
			( x - 0.5 * a ) / ( 1.0 - a ),
			1.0 - ( ( 1.0 - x ) * ( 1.0 - x ) / ( 2.0 * a * ( 1.0 - a ) ) )
		);
		float threshold = ( x < ( 1.0 - a ) )
			? ( ( x < a ) ? cases.x : cases.y )
			: cases.z;
		return clamp( threshold , 1.0e-6, 1.0 );
	}
#endif`,Eu=`#ifdef USE_ALPHAMAP
	diffuseColor.a *= texture2D( alphaMap, vAlphaMapUv ).g;
#endif`,Tu=`#ifdef USE_ALPHAMAP
	uniform sampler2D alphaMap;
#endif`,yu=`#ifdef USE_ALPHATEST
	#ifdef ALPHA_TO_COVERAGE
	diffuseColor.a = smoothstep( alphaTest, alphaTest + fwidth( diffuseColor.a ), diffuseColor.a );
	if ( diffuseColor.a == 0.0 ) discard;
	#else
	if ( diffuseColor.a < alphaTest ) discard;
	#endif
#endif`,bu=`#ifdef USE_ALPHATEST
	uniform float alphaTest;
#endif`,Au=`#ifdef USE_AOMAP
	float ambientOcclusion = ( texture2D( aoMap, vAoMapUv ).r - 1.0 ) * aoMapIntensity + 1.0;
	reflectedLight.indirectDiffuse *= ambientOcclusion;
	#if defined( USE_CLEARCOAT ) 
		clearcoatSpecularIndirect *= ambientOcclusion;
	#endif
	#if defined( USE_SHEEN ) 
		sheenSpecularIndirect *= ambientOcclusion;
	#endif
	#if defined( USE_ENVMAP ) && defined( STANDARD )
		float dotNV = saturate( dot( geometryNormal, geometryViewDir ) );
		reflectedLight.indirectSpecular *= computeSpecularOcclusion( dotNV, ambientOcclusion, material.roughness );
	#endif
#endif`,wu=`#ifdef USE_AOMAP
	uniform sampler2D aoMap;
	uniform float aoMapIntensity;
#endif`,Ru=`#ifdef USE_BATCHING
	#if ! defined( GL_ANGLE_multi_draw )
	#define gl_DrawID _gl_DrawID
	uniform int _gl_DrawID;
	#endif
	uniform highp sampler2D batchingTexture;
	uniform highp usampler2D batchingIdTexture;
	mat4 getBatchingMatrix( const in float i ) {
		int size = textureSize( batchingTexture, 0 ).x;
		int j = int( i ) * 4;
		int x = j % size;
		int y = j / size;
		vec4 v1 = texelFetch( batchingTexture, ivec2( x, y ), 0 );
		vec4 v2 = texelFetch( batchingTexture, ivec2( x + 1, y ), 0 );
		vec4 v3 = texelFetch( batchingTexture, ivec2( x + 2, y ), 0 );
		vec4 v4 = texelFetch( batchingTexture, ivec2( x + 3, y ), 0 );
		return mat4( v1, v2, v3, v4 );
	}
	float getIndirectIndex( const in int i ) {
		int size = textureSize( batchingIdTexture, 0 ).x;
		int x = i % size;
		int y = i / size;
		return float( texelFetch( batchingIdTexture, ivec2( x, y ), 0 ).r );
	}
#endif
#ifdef USE_BATCHING_COLOR
	uniform sampler2D batchingColorTexture;
	vec4 getBatchingColor( const in float i ) {
		int size = textureSize( batchingColorTexture, 0 ).x;
		int j = int( i );
		int x = j % size;
		int y = j / size;
		return texelFetch( batchingColorTexture, ivec2( x, y ), 0 );
	}
#endif`,Cu=`#ifdef USE_BATCHING
	mat4 batchingMatrix = getBatchingMatrix( getIndirectIndex( gl_DrawID ) );
#endif`,Pu=`vec3 transformed = vec3( position );
#ifdef USE_ALPHAHASH
	vPosition = vec3( position );
#endif`,Uu=`vec3 objectNormal = vec3( normal );
#ifdef USE_TANGENT
	vec3 objectTangent = vec3( tangent.xyz );
#endif`,Du=`float G_BlinnPhong_Implicit( ) {
	return 0.25;
}
float D_BlinnPhong( const in float shininess, const in float dotNH ) {
	return RECIPROCAL_PI * ( shininess * 0.5 + 1.0 ) * pow( dotNH, shininess );
}
vec3 BRDF_BlinnPhong( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, const in vec3 specularColor, const in float shininess ) {
	vec3 halfDir = normalize( lightDir + viewDir );
	float dotNH = saturate( dot( normal, halfDir ) );
	float dotVH = saturate( dot( viewDir, halfDir ) );
	vec3 F = F_Schlick( specularColor, 1.0, dotVH );
	float G = G_BlinnPhong_Implicit( );
	float D = D_BlinnPhong( shininess, dotNH );
	return F * ( G * D );
} // validated`,Iu=`#ifdef USE_IRIDESCENCE
	const mat3 XYZ_TO_REC709 = mat3(
		 3.2404542, -0.9692660,  0.0556434,
		-1.5371385,  1.8760108, -0.2040259,
		-0.4985314,  0.0415560,  1.0572252
	);
	vec3 Fresnel0ToIor( vec3 fresnel0 ) {
		vec3 sqrtF0 = sqrt( fresnel0 );
		return ( vec3( 1.0 ) + sqrtF0 ) / ( vec3( 1.0 ) - sqrtF0 );
	}
	vec3 IorToFresnel0( vec3 transmittedIor, float incidentIor ) {
		return pow2( ( transmittedIor - vec3( incidentIor ) ) / ( transmittedIor + vec3( incidentIor ) ) );
	}
	float IorToFresnel0( float transmittedIor, float incidentIor ) {
		return pow2( ( transmittedIor - incidentIor ) / ( transmittedIor + incidentIor ));
	}
	vec3 evalSensitivity( float OPD, vec3 shift ) {
		float phase = 2.0 * PI * OPD * 1.0e-9;
		vec3 val = vec3( 5.4856e-13, 4.4201e-13, 5.2481e-13 );
		vec3 pos = vec3( 1.6810e+06, 1.7953e+06, 2.2084e+06 );
		vec3 var = vec3( 4.3278e+09, 9.3046e+09, 6.6121e+09 );
		vec3 xyz = val * sqrt( 2.0 * PI * var ) * cos( pos * phase + shift ) * exp( - pow2( phase ) * var );
		xyz.x += 9.7470e-14 * sqrt( 2.0 * PI * 4.5282e+09 ) * cos( 2.2399e+06 * phase + shift[ 0 ] ) * exp( - 4.5282e+09 * pow2( phase ) );
		xyz /= 1.0685e-7;
		vec3 rgb = XYZ_TO_REC709 * xyz;
		return rgb;
	}
	vec3 evalIridescence( float outsideIOR, float eta2, float cosTheta1, float thinFilmThickness, vec3 baseF0 ) {
		vec3 I;
		float iridescenceIOR = mix( outsideIOR, eta2, smoothstep( 0.0, 0.03, thinFilmThickness ) );
		float sinTheta2Sq = pow2( outsideIOR / iridescenceIOR ) * ( 1.0 - pow2( cosTheta1 ) );
		float cosTheta2Sq = 1.0 - sinTheta2Sq;
		if ( cosTheta2Sq < 0.0 ) {
			return vec3( 1.0 );
		}
		float cosTheta2 = sqrt( cosTheta2Sq );
		float R0 = IorToFresnel0( iridescenceIOR, outsideIOR );
		float R12 = F_Schlick( R0, 1.0, cosTheta1 );
		float T121 = 1.0 - R12;
		float phi12 = 0.0;
		if ( iridescenceIOR < outsideIOR ) phi12 = PI;
		float phi21 = PI - phi12;
		vec3 baseIOR = Fresnel0ToIor( clamp( baseF0, 0.0, 0.9999 ) );		vec3 R1 = IorToFresnel0( baseIOR, iridescenceIOR );
		vec3 R23 = F_Schlick( R1, 1.0, cosTheta2 );
		vec3 phi23 = vec3( 0.0 );
		if ( baseIOR[ 0 ] < iridescenceIOR ) phi23[ 0 ] = PI;
		if ( baseIOR[ 1 ] < iridescenceIOR ) phi23[ 1 ] = PI;
		if ( baseIOR[ 2 ] < iridescenceIOR ) phi23[ 2 ] = PI;
		float OPD = 2.0 * iridescenceIOR * thinFilmThickness * cosTheta2;
		vec3 phi = vec3( phi21 ) + phi23;
		vec3 R123 = clamp( R12 * R23, 1e-5, 0.9999 );
		vec3 r123 = sqrt( R123 );
		vec3 Rs = pow2( T121 ) * R23 / ( vec3( 1.0 ) - R123 );
		vec3 C0 = R12 + Rs;
		I = C0;
		vec3 Cm = Rs - T121;
		for ( int m = 1; m <= 2; ++ m ) {
			Cm *= r123;
			vec3 Sm = 2.0 * evalSensitivity( float( m ) * OPD, float( m ) * phi );
			I += Cm * Sm;
		}
		return max( I, vec3( 0.0 ) );
	}
#endif`,Lu=`#ifdef USE_BUMPMAP
	uniform sampler2D bumpMap;
	uniform float bumpScale;
	vec2 dHdxy_fwd() {
		vec2 dSTdx = dFdx( vBumpMapUv );
		vec2 dSTdy = dFdy( vBumpMapUv );
		float Hll = bumpScale * texture2D( bumpMap, vBumpMapUv ).x;
		float dBx = bumpScale * texture2D( bumpMap, vBumpMapUv + dSTdx ).x - Hll;
		float dBy = bumpScale * texture2D( bumpMap, vBumpMapUv + dSTdy ).x - Hll;
		return vec2( dBx, dBy );
	}
	vec3 perturbNormalArb( vec3 surf_pos, vec3 surf_norm, vec2 dHdxy, float faceDirection ) {
		vec3 vSigmaX = normalize( dFdx( surf_pos.xyz ) );
		vec3 vSigmaY = normalize( dFdy( surf_pos.xyz ) );
		vec3 vN = surf_norm;
		vec3 R1 = cross( vSigmaY, vN );
		vec3 R2 = cross( vN, vSigmaX );
		float fDet = dot( vSigmaX, R1 ) * faceDirection;
		vec3 vGrad = sign( fDet ) * ( dHdxy.x * R1 + dHdxy.y * R2 );
		return normalize( abs( fDet ) * surf_norm - vGrad );
	}
#endif`,Nu=`#if NUM_CLIPPING_PLANES > 0
	vec4 plane;
	#ifdef ALPHA_TO_COVERAGE
		float distanceToPlane, distanceGradient;
		float clipOpacity = 1.0;
		#pragma unroll_loop_start
		for ( int i = 0; i < UNION_CLIPPING_PLANES; i ++ ) {
			plane = clippingPlanes[ i ];
			distanceToPlane = - dot( vClipPosition, plane.xyz ) + plane.w;
			distanceGradient = fwidth( distanceToPlane ) / 2.0;
			clipOpacity *= smoothstep( - distanceGradient, distanceGradient, distanceToPlane );
			if ( clipOpacity == 0.0 ) discard;
		}
		#pragma unroll_loop_end
		#if UNION_CLIPPING_PLANES < NUM_CLIPPING_PLANES
			float unionClipOpacity = 1.0;
			#pragma unroll_loop_start
			for ( int i = UNION_CLIPPING_PLANES; i < NUM_CLIPPING_PLANES; i ++ ) {
				plane = clippingPlanes[ i ];
				distanceToPlane = - dot( vClipPosition, plane.xyz ) + plane.w;
				distanceGradient = fwidth( distanceToPlane ) / 2.0;
				unionClipOpacity *= 1.0 - smoothstep( - distanceGradient, distanceGradient, distanceToPlane );
			}
			#pragma unroll_loop_end
			clipOpacity *= 1.0 - unionClipOpacity;
		#endif
		diffuseColor.a *= clipOpacity;
		if ( diffuseColor.a == 0.0 ) discard;
	#else
		#pragma unroll_loop_start
		for ( int i = 0; i < UNION_CLIPPING_PLANES; i ++ ) {
			plane = clippingPlanes[ i ];
			if ( dot( vClipPosition, plane.xyz ) > plane.w ) discard;
		}
		#pragma unroll_loop_end
		#if UNION_CLIPPING_PLANES < NUM_CLIPPING_PLANES
			bool clipped = true;
			#pragma unroll_loop_start
			for ( int i = UNION_CLIPPING_PLANES; i < NUM_CLIPPING_PLANES; i ++ ) {
				plane = clippingPlanes[ i ];
				clipped = ( dot( vClipPosition, plane.xyz ) > plane.w ) && clipped;
			}
			#pragma unroll_loop_end
			if ( clipped ) discard;
		#endif
	#endif
#endif`,Fu=`#if NUM_CLIPPING_PLANES > 0
	varying vec3 vClipPosition;
	uniform vec4 clippingPlanes[ NUM_CLIPPING_PLANES ];
#endif`,Ou=`#if NUM_CLIPPING_PLANES > 0
	varying vec3 vClipPosition;
#endif`,Bu=`#if NUM_CLIPPING_PLANES > 0
	vClipPosition = - mvPosition.xyz;
#endif`,zu=`#if defined( USE_COLOR ) || defined( USE_COLOR_ALPHA )
	diffuseColor *= vColor;
#endif`,Gu=`#if defined( USE_COLOR ) || defined( USE_COLOR_ALPHA )
	varying vec4 vColor;
#endif`,Hu=`#if defined( USE_COLOR ) || defined( USE_COLOR_ALPHA ) || defined( USE_INSTANCING_COLOR ) || defined( USE_BATCHING_COLOR )
	varying vec4 vColor;
#endif`,Vu=`#if defined( USE_COLOR ) || defined( USE_COLOR_ALPHA ) || defined( USE_INSTANCING_COLOR ) || defined( USE_BATCHING_COLOR )
	vColor = vec4( 1.0 );
#endif
#ifdef USE_COLOR_ALPHA
	vColor *= color;
#elif defined( USE_COLOR )
	vColor.rgb *= color;
#endif
#ifdef USE_INSTANCING_COLOR
	vColor.rgb *= instanceColor.rgb;
#endif
#ifdef USE_BATCHING_COLOR
	vColor *= getBatchingColor( getIndirectIndex( gl_DrawID ) );
#endif`,ku=`#define PI 3.141592653589793
#define PI2 6.283185307179586
#define PI_HALF 1.5707963267948966
#define RECIPROCAL_PI 0.3183098861837907
#define RECIPROCAL_PI2 0.15915494309189535
#define EPSILON 1e-6
#ifndef saturate
#define saturate( a ) clamp( a, 0.0, 1.0 )
#endif
#define whiteComplement( a ) ( 1.0 - saturate( a ) )
float pow2( const in float x ) { return x*x; }
vec3 pow2( const in vec3 x ) { return x*x; }
float pow3( const in float x ) { return x*x*x; }
float pow4( const in float x ) { float x2 = x*x; return x2*x2; }
float max3( const in vec3 v ) { return max( max( v.x, v.y ), v.z ); }
float average( const in vec3 v ) { return dot( v, vec3( 0.3333333 ) ); }
highp float rand( const in vec2 uv ) {
	const highp float a = 12.9898, b = 78.233, c = 43758.5453;
	highp float dt = dot( uv.xy, vec2( a,b ) ), sn = mod( dt, PI );
	return fract( sin( sn ) * c );
}
#ifdef HIGH_PRECISION
	float precisionSafeLength( vec3 v ) { return length( v ); }
#else
	float precisionSafeLength( vec3 v ) {
		float maxComponent = max3( abs( v ) );
		return length( v / maxComponent ) * maxComponent;
	}
#endif
struct IncidentLight {
	vec3 color;
	vec3 direction;
	bool visible;
};
struct ReflectedLight {
	vec3 directDiffuse;
	vec3 directSpecular;
	vec3 indirectDiffuse;
	vec3 indirectSpecular;
};
#ifdef USE_ALPHAHASH
	varying vec3 vPosition;
#endif
vec3 transformDirection( in vec3 dir, in mat4 matrix ) {
	return normalize( ( matrix * vec4( dir, 0.0 ) ).xyz );
}
vec3 inverseTransformDirection( in vec3 dir, in mat4 matrix ) {
	return normalize( ( vec4( dir, 0.0 ) * matrix ).xyz );
}
bool isPerspectiveMatrix( mat4 m ) {
	return m[ 2 ][ 3 ] == - 1.0;
}
vec2 equirectUv( in vec3 dir ) {
	float u = atan( dir.z, dir.x ) * RECIPROCAL_PI2 + 0.5;
	float v = asin( clamp( dir.y, - 1.0, 1.0 ) ) * RECIPROCAL_PI + 0.5;
	return vec2( u, v );
}
vec3 BRDF_Lambert( const in vec3 diffuseColor ) {
	return RECIPROCAL_PI * diffuseColor;
}
vec3 F_Schlick( const in vec3 f0, const in float f90, const in float dotVH ) {
	float fresnel = exp2( ( - 5.55473 * dotVH - 6.98316 ) * dotVH );
	return f0 * ( 1.0 - fresnel ) + ( f90 * fresnel );
}
float F_Schlick( const in float f0, const in float f90, const in float dotVH ) {
	float fresnel = exp2( ( - 5.55473 * dotVH - 6.98316 ) * dotVH );
	return f0 * ( 1.0 - fresnel ) + ( f90 * fresnel );
} // validated`,Wu=`#ifdef ENVMAP_TYPE_CUBE_UV
	#define cubeUV_minMipLevel 4.0
	#define cubeUV_minTileSize 16.0
	float getFace( vec3 direction ) {
		vec3 absDirection = abs( direction );
		float face = - 1.0;
		if ( absDirection.x > absDirection.z ) {
			if ( absDirection.x > absDirection.y )
				face = direction.x > 0.0 ? 0.0 : 3.0;
			else
				face = direction.y > 0.0 ? 1.0 : 4.0;
		} else {
			if ( absDirection.z > absDirection.y )
				face = direction.z > 0.0 ? 2.0 : 5.0;
			else
				face = direction.y > 0.0 ? 1.0 : 4.0;
		}
		return face;
	}
	vec2 getUV( vec3 direction, float face ) {
		vec2 uv;
		if ( face == 0.0 ) {
			uv = vec2( direction.z, direction.y ) / abs( direction.x );
		} else if ( face == 1.0 ) {
			uv = vec2( - direction.x, - direction.z ) / abs( direction.y );
		} else if ( face == 2.0 ) {
			uv = vec2( - direction.x, direction.y ) / abs( direction.z );
		} else if ( face == 3.0 ) {
			uv = vec2( - direction.z, direction.y ) / abs( direction.x );
		} else if ( face == 4.0 ) {
			uv = vec2( - direction.x, direction.z ) / abs( direction.y );
		} else {
			uv = vec2( direction.x, direction.y ) / abs( direction.z );
		}
		return 0.5 * ( uv + 1.0 );
	}
	vec3 bilinearCubeUV( sampler2D envMap, vec3 direction, float mipInt ) {
		float face = getFace( direction );
		float filterInt = max( cubeUV_minMipLevel - mipInt, 0.0 );
		mipInt = max( mipInt, cubeUV_minMipLevel );
		float faceSize = exp2( mipInt );
		highp vec2 uv = getUV( direction, face ) * ( faceSize - 2.0 ) + 1.0;
		if ( face > 2.0 ) {
			uv.y += faceSize;
			face -= 3.0;
		}
		uv.x += face * faceSize;
		uv.x += filterInt * 3.0 * cubeUV_minTileSize;
		uv.y += 4.0 * ( exp2( CUBEUV_MAX_MIP ) - faceSize );
		uv.x *= CUBEUV_TEXEL_WIDTH;
		uv.y *= CUBEUV_TEXEL_HEIGHT;
		#ifdef texture2DGradEXT
			return texture2DGradEXT( envMap, uv, vec2( 0.0 ), vec2( 0.0 ) ).rgb;
		#else
			return texture2D( envMap, uv ).rgb;
		#endif
	}
	#define cubeUV_r0 1.0
	#define cubeUV_m0 - 2.0
	#define cubeUV_r1 0.8
	#define cubeUV_m1 - 1.0
	#define cubeUV_r4 0.4
	#define cubeUV_m4 2.0
	#define cubeUV_r5 0.305
	#define cubeUV_m5 3.0
	#define cubeUV_r6 0.21
	#define cubeUV_m6 4.0
	float roughnessToMip( float roughness ) {
		float mip = 0.0;
		if ( roughness >= cubeUV_r1 ) {
			mip = ( cubeUV_r0 - roughness ) * ( cubeUV_m1 - cubeUV_m0 ) / ( cubeUV_r0 - cubeUV_r1 ) + cubeUV_m0;
		} else if ( roughness >= cubeUV_r4 ) {
			mip = ( cubeUV_r1 - roughness ) * ( cubeUV_m4 - cubeUV_m1 ) / ( cubeUV_r1 - cubeUV_r4 ) + cubeUV_m1;
		} else if ( roughness >= cubeUV_r5 ) {
			mip = ( cubeUV_r4 - roughness ) * ( cubeUV_m5 - cubeUV_m4 ) / ( cubeUV_r4 - cubeUV_r5 ) + cubeUV_m4;
		} else if ( roughness >= cubeUV_r6 ) {
			mip = ( cubeUV_r5 - roughness ) * ( cubeUV_m6 - cubeUV_m5 ) / ( cubeUV_r5 - cubeUV_r6 ) + cubeUV_m5;
		} else {
			mip = - 2.0 * log2( 1.16 * roughness );		}
		return mip;
	}
	vec4 textureCubeUV( sampler2D envMap, vec3 sampleDir, float roughness ) {
		float mip = clamp( roughnessToMip( roughness ), cubeUV_m0, CUBEUV_MAX_MIP );
		float mipF = fract( mip );
		float mipInt = floor( mip );
		vec3 color0 = bilinearCubeUV( envMap, sampleDir, mipInt );
		if ( mipF == 0.0 ) {
			return vec4( color0, 1.0 );
		} else {
			vec3 color1 = bilinearCubeUV( envMap, sampleDir, mipInt + 1.0 );
			return vec4( mix( color0, color1, mipF ), 1.0 );
		}
	}
#endif`,Xu=`vec3 transformedNormal = objectNormal;
#ifdef USE_TANGENT
	vec3 transformedTangent = objectTangent;
#endif
#ifdef USE_BATCHING
	mat3 bm = mat3( batchingMatrix );
	transformedNormal /= vec3( dot( bm[ 0 ], bm[ 0 ] ), dot( bm[ 1 ], bm[ 1 ] ), dot( bm[ 2 ], bm[ 2 ] ) );
	transformedNormal = bm * transformedNormal;
	#ifdef USE_TANGENT
		transformedTangent = bm * transformedTangent;
	#endif
#endif
#ifdef USE_INSTANCING
	mat3 im = mat3( instanceMatrix );
	transformedNormal /= vec3( dot( im[ 0 ], im[ 0 ] ), dot( im[ 1 ], im[ 1 ] ), dot( im[ 2 ], im[ 2 ] ) );
	transformedNormal = im * transformedNormal;
	#ifdef USE_TANGENT
		transformedTangent = im * transformedTangent;
	#endif
#endif
transformedNormal = normalMatrix * transformedNormal;
#ifdef FLIP_SIDED
	transformedNormal = - transformedNormal;
#endif
#ifdef USE_TANGENT
	transformedTangent = ( modelViewMatrix * vec4( transformedTangent, 0.0 ) ).xyz;
	#ifdef FLIP_SIDED
		transformedTangent = - transformedTangent;
	#endif
#endif`,qu=`#ifdef USE_DISPLACEMENTMAP
	uniform sampler2D displacementMap;
	uniform float displacementScale;
	uniform float displacementBias;
#endif`,Yu=`#ifdef USE_DISPLACEMENTMAP
	transformed += normalize( objectNormal ) * ( texture2D( displacementMap, vDisplacementMapUv ).x * displacementScale + displacementBias );
#endif`,ju=`#ifdef USE_EMISSIVEMAP
	vec4 emissiveColor = texture2D( emissiveMap, vEmissiveMapUv );
	#ifdef DECODE_VIDEO_TEXTURE_EMISSIVE
		emissiveColor = sRGBTransferEOTF( emissiveColor );
	#endif
	totalEmissiveRadiance *= emissiveColor.rgb;
#endif`,Ku=`#ifdef USE_EMISSIVEMAP
	uniform sampler2D emissiveMap;
#endif`,Ju="gl_FragColor = linearToOutputTexel( gl_FragColor );",Zu=`vec4 LinearTransferOETF( in vec4 value ) {
	return value;
}
vec4 sRGBTransferEOTF( in vec4 value ) {
	return vec4( mix( pow( value.rgb * 0.9478672986 + vec3( 0.0521327014 ), vec3( 2.4 ) ), value.rgb * 0.0773993808, vec3( lessThanEqual( value.rgb, vec3( 0.04045 ) ) ) ), value.a );
}
vec4 sRGBTransferOETF( in vec4 value ) {
	return vec4( mix( pow( value.rgb, vec3( 0.41666 ) ) * 1.055 - vec3( 0.055 ), value.rgb * 12.92, vec3( lessThanEqual( value.rgb, vec3( 0.0031308 ) ) ) ), value.a );
}`,$u=`#ifdef USE_ENVMAP
	#ifdef ENV_WORLDPOS
		vec3 cameraToFrag;
		if ( isOrthographic ) {
			cameraToFrag = normalize( vec3( - viewMatrix[ 0 ][ 2 ], - viewMatrix[ 1 ][ 2 ], - viewMatrix[ 2 ][ 2 ] ) );
		} else {
			cameraToFrag = normalize( vWorldPosition - cameraPosition );
		}
		vec3 worldNormal = inverseTransformDirection( normal, viewMatrix );
		#ifdef ENVMAP_MODE_REFLECTION
			vec3 reflectVec = reflect( cameraToFrag, worldNormal );
		#else
			vec3 reflectVec = refract( cameraToFrag, worldNormal, refractionRatio );
		#endif
	#else
		vec3 reflectVec = vReflect;
	#endif
	#ifdef ENVMAP_TYPE_CUBE
		vec4 envColor = textureCube( envMap, envMapRotation * reflectVec );
		#ifdef ENVMAP_BLENDING_MULTIPLY
			outgoingLight = mix( outgoingLight, outgoingLight * envColor.xyz, specularStrength * reflectivity );
		#elif defined( ENVMAP_BLENDING_MIX )
			outgoingLight = mix( outgoingLight, envColor.xyz, specularStrength * reflectivity );
		#elif defined( ENVMAP_BLENDING_ADD )
			outgoingLight += envColor.xyz * specularStrength * reflectivity;
		#endif
	#endif
#endif`,Qu=`#ifdef USE_ENVMAP
	uniform float envMapIntensity;
	uniform mat3 envMapRotation;
	#ifdef ENVMAP_TYPE_CUBE
		uniform samplerCube envMap;
	#else
		uniform sampler2D envMap;
	#endif
#endif`,eh=`#ifdef USE_ENVMAP
	uniform float reflectivity;
	#if defined( USE_BUMPMAP ) || defined( USE_NORMALMAP ) || defined( PHONG ) || defined( LAMBERT )
		#define ENV_WORLDPOS
	#endif
	#ifdef ENV_WORLDPOS
		varying vec3 vWorldPosition;
		uniform float refractionRatio;
	#else
		varying vec3 vReflect;
	#endif
#endif`,th=`#ifdef USE_ENVMAP
	#if defined( USE_BUMPMAP ) || defined( USE_NORMALMAP ) || defined( PHONG ) || defined( LAMBERT )
		#define ENV_WORLDPOS
	#endif
	#ifdef ENV_WORLDPOS
		
		varying vec3 vWorldPosition;
	#else
		varying vec3 vReflect;
		uniform float refractionRatio;
	#endif
#endif`,ih=`#ifdef USE_ENVMAP
	#ifdef ENV_WORLDPOS
		vWorldPosition = worldPosition.xyz;
	#else
		vec3 cameraToVertex;
		if ( isOrthographic ) {
			cameraToVertex = normalize( vec3( - viewMatrix[ 0 ][ 2 ], - viewMatrix[ 1 ][ 2 ], - viewMatrix[ 2 ][ 2 ] ) );
		} else {
			cameraToVertex = normalize( worldPosition.xyz - cameraPosition );
		}
		vec3 worldNormal = inverseTransformDirection( transformedNormal, viewMatrix );
		#ifdef ENVMAP_MODE_REFLECTION
			vReflect = reflect( cameraToVertex, worldNormal );
		#else
			vReflect = refract( cameraToVertex, worldNormal, refractionRatio );
		#endif
	#endif
#endif`,rh=`#ifdef USE_FOG
	vFogDepth = - mvPosition.z;
#endif`,nh=`#ifdef USE_FOG
	varying float vFogDepth;
#endif`,ah=`#ifdef USE_FOG
	#ifdef FOG_EXP2
		float fogFactor = 1.0 - exp( - fogDensity * fogDensity * vFogDepth * vFogDepth );
	#else
		float fogFactor = smoothstep( fogNear, fogFar, vFogDepth );
	#endif
	gl_FragColor.rgb = mix( gl_FragColor.rgb, fogColor, fogFactor );
#endif`,sh=`#ifdef USE_FOG
	uniform vec3 fogColor;
	varying float vFogDepth;
	#ifdef FOG_EXP2
		uniform float fogDensity;
	#else
		uniform float fogNear;
		uniform float fogFar;
	#endif
#endif`,oh=`#ifdef USE_GRADIENTMAP
	uniform sampler2D gradientMap;
#endif
vec3 getGradientIrradiance( vec3 normal, vec3 lightDirection ) {
	float dotNL = dot( normal, lightDirection );
	vec2 coord = vec2( dotNL * 0.5 + 0.5, 0.0 );
	#ifdef USE_GRADIENTMAP
		return vec3( texture2D( gradientMap, coord ).r );
	#else
		vec2 fw = fwidth( coord ) * 0.5;
		return mix( vec3( 0.7 ), vec3( 1.0 ), smoothstep( 0.7 - fw.x, 0.7 + fw.x, coord.x ) );
	#endif
}`,lh=`#ifdef USE_LIGHTMAP
	uniform sampler2D lightMap;
	uniform float lightMapIntensity;
#endif`,ch=`LambertMaterial material;
material.diffuseColor = diffuseColor.rgb;
material.specularStrength = specularStrength;`,uh=`varying vec3 vViewPosition;
struct LambertMaterial {
	vec3 diffuseColor;
	float specularStrength;
};
void RE_Direct_Lambert( const in IncidentLight directLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in LambertMaterial material, inout ReflectedLight reflectedLight ) {
	float dotNL = saturate( dot( geometryNormal, directLight.direction ) );
	vec3 irradiance = dotNL * directLight.color;
	reflectedLight.directDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
void RE_IndirectDiffuse_Lambert( const in vec3 irradiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in LambertMaterial material, inout ReflectedLight reflectedLight ) {
	reflectedLight.indirectDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
#define RE_Direct				RE_Direct_Lambert
#define RE_IndirectDiffuse		RE_IndirectDiffuse_Lambert`,hh=`uniform bool receiveShadow;
uniform vec3 ambientLightColor;
#if defined( USE_LIGHT_PROBES )
	uniform vec3 lightProbe[ 9 ];
#endif
vec3 shGetIrradianceAt( in vec3 normal, in vec3 shCoefficients[ 9 ] ) {
	float x = normal.x, y = normal.y, z = normal.z;
	vec3 result = shCoefficients[ 0 ] * 0.886227;
	result += shCoefficients[ 1 ] * 2.0 * 0.511664 * y;
	result += shCoefficients[ 2 ] * 2.0 * 0.511664 * z;
	result += shCoefficients[ 3 ] * 2.0 * 0.511664 * x;
	result += shCoefficients[ 4 ] * 2.0 * 0.429043 * x * y;
	result += shCoefficients[ 5 ] * 2.0 * 0.429043 * y * z;
	result += shCoefficients[ 6 ] * ( 0.743125 * z * z - 0.247708 );
	result += shCoefficients[ 7 ] * 2.0 * 0.429043 * x * z;
	result += shCoefficients[ 8 ] * 0.429043 * ( x * x - y * y );
	return result;
}
vec3 getLightProbeIrradiance( const in vec3 lightProbe[ 9 ], const in vec3 normal ) {
	vec3 worldNormal = inverseTransformDirection( normal, viewMatrix );
	vec3 irradiance = shGetIrradianceAt( worldNormal, lightProbe );
	return irradiance;
}
vec3 getAmbientLightIrradiance( const in vec3 ambientLightColor ) {
	vec3 irradiance = ambientLightColor;
	return irradiance;
}
float getDistanceAttenuation( const in float lightDistance, const in float cutoffDistance, const in float decayExponent ) {
	float distanceFalloff = 1.0 / max( pow( lightDistance, decayExponent ), 0.01 );
	if ( cutoffDistance > 0.0 ) {
		distanceFalloff *= pow2( saturate( 1.0 - pow4( lightDistance / cutoffDistance ) ) );
	}
	return distanceFalloff;
}
float getSpotAttenuation( const in float coneCosine, const in float penumbraCosine, const in float angleCosine ) {
	return smoothstep( coneCosine, penumbraCosine, angleCosine );
}
#if NUM_DIR_LIGHTS > 0
	struct DirectionalLight {
		vec3 direction;
		vec3 color;
	};
	uniform DirectionalLight directionalLights[ NUM_DIR_LIGHTS ];
	void getDirectionalLightInfo( const in DirectionalLight directionalLight, out IncidentLight light ) {
		light.color = directionalLight.color;
		light.direction = directionalLight.direction;
		light.visible = true;
	}
#endif
#if NUM_POINT_LIGHTS > 0
	struct PointLight {
		vec3 position;
		vec3 color;
		float distance;
		float decay;
	};
	uniform PointLight pointLights[ NUM_POINT_LIGHTS ];
	void getPointLightInfo( const in PointLight pointLight, const in vec3 geometryPosition, out IncidentLight light ) {
		vec3 lVector = pointLight.position - geometryPosition;
		light.direction = normalize( lVector );
		float lightDistance = length( lVector );
		light.color = pointLight.color;
		light.color *= getDistanceAttenuation( lightDistance, pointLight.distance, pointLight.decay );
		light.visible = ( light.color != vec3( 0.0 ) );
	}
#endif
#if NUM_SPOT_LIGHTS > 0
	struct SpotLight {
		vec3 position;
		vec3 direction;
		vec3 color;
		float distance;
		float decay;
		float coneCos;
		float penumbraCos;
	};
	uniform SpotLight spotLights[ NUM_SPOT_LIGHTS ];
	void getSpotLightInfo( const in SpotLight spotLight, const in vec3 geometryPosition, out IncidentLight light ) {
		vec3 lVector = spotLight.position - geometryPosition;
		light.direction = normalize( lVector );
		float angleCos = dot( light.direction, spotLight.direction );
		float spotAttenuation = getSpotAttenuation( spotLight.coneCos, spotLight.penumbraCos, angleCos );
		if ( spotAttenuation > 0.0 ) {
			float lightDistance = length( lVector );
			light.color = spotLight.color * spotAttenuation;
			light.color *= getDistanceAttenuation( lightDistance, spotLight.distance, spotLight.decay );
			light.visible = ( light.color != vec3( 0.0 ) );
		} else {
			light.color = vec3( 0.0 );
			light.visible = false;
		}
	}
#endif
#if NUM_RECT_AREA_LIGHTS > 0
	struct RectAreaLight {
		vec3 color;
		vec3 position;
		vec3 halfWidth;
		vec3 halfHeight;
	};
	uniform sampler2D ltc_1;	uniform sampler2D ltc_2;
	uniform RectAreaLight rectAreaLights[ NUM_RECT_AREA_LIGHTS ];
#endif
#if NUM_HEMI_LIGHTS > 0
	struct HemisphereLight {
		vec3 direction;
		vec3 skyColor;
		vec3 groundColor;
	};
	uniform HemisphereLight hemisphereLights[ NUM_HEMI_LIGHTS ];
	vec3 getHemisphereLightIrradiance( const in HemisphereLight hemiLight, const in vec3 normal ) {
		float dotNL = dot( normal, hemiLight.direction );
		float hemiDiffuseWeight = 0.5 * dotNL + 0.5;
		vec3 irradiance = mix( hemiLight.groundColor, hemiLight.skyColor, hemiDiffuseWeight );
		return irradiance;
	}
#endif
#include <lightprobes_pars_fragment>`,dh=`#ifdef USE_ENVMAP
	vec3 getIBLIrradiance( const in vec3 normal ) {
		#ifdef ENVMAP_TYPE_CUBE_UV
			vec3 worldNormal = inverseTransformDirection( normal, viewMatrix );
			vec4 envMapColor = textureCubeUV( envMap, envMapRotation * worldNormal, 1.0 );
			return PI * envMapColor.rgb * envMapIntensity;
		#else
			return vec3( 0.0 );
		#endif
	}
	vec3 getIBLRadiance( const in vec3 viewDir, const in vec3 normal, const in float roughness ) {
		#ifdef ENVMAP_TYPE_CUBE_UV
			vec3 reflectVec = reflect( - viewDir, normal );
			reflectVec = normalize( mix( reflectVec, normal, pow4( roughness ) ) );
			reflectVec = inverseTransformDirection( reflectVec, viewMatrix );
			vec4 envMapColor = textureCubeUV( envMap, envMapRotation * reflectVec, roughness );
			return envMapColor.rgb * envMapIntensity;
		#else
			return vec3( 0.0 );
		#endif
	}
	#ifdef USE_ANISOTROPY
		vec3 getIBLAnisotropyRadiance( const in vec3 viewDir, const in vec3 normal, const in float roughness, const in vec3 bitangent, const in float anisotropy ) {
			#ifdef ENVMAP_TYPE_CUBE_UV
				vec3 bentNormal = cross( bitangent, viewDir );
				bentNormal = normalize( cross( bentNormal, bitangent ) );
				bentNormal = normalize( mix( bentNormal, normal, pow2( pow2( 1.0 - anisotropy * ( 1.0 - roughness ) ) ) ) );
				return getIBLRadiance( viewDir, bentNormal, roughness );
			#else
				return vec3( 0.0 );
			#endif
		}
	#endif
#endif`,ph=`ToonMaterial material;
material.diffuseColor = diffuseColor.rgb;`,fh=`varying vec3 vViewPosition;
struct ToonMaterial {
	vec3 diffuseColor;
};
void RE_Direct_Toon( const in IncidentLight directLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in ToonMaterial material, inout ReflectedLight reflectedLight ) {
	vec3 irradiance = getGradientIrradiance( geometryNormal, directLight.direction ) * directLight.color;
	reflectedLight.directDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
void RE_IndirectDiffuse_Toon( const in vec3 irradiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in ToonMaterial material, inout ReflectedLight reflectedLight ) {
	reflectedLight.indirectDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
#define RE_Direct				RE_Direct_Toon
#define RE_IndirectDiffuse		RE_IndirectDiffuse_Toon`,mh=`BlinnPhongMaterial material;
material.diffuseColor = diffuseColor.rgb;
material.specularColor = specular;
material.specularShininess = shininess;
material.specularStrength = specularStrength;`,gh=`varying vec3 vViewPosition;
struct BlinnPhongMaterial {
	vec3 diffuseColor;
	vec3 specularColor;
	float specularShininess;
	float specularStrength;
};
void RE_Direct_BlinnPhong( const in IncidentLight directLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in BlinnPhongMaterial material, inout ReflectedLight reflectedLight ) {
	float dotNL = saturate( dot( geometryNormal, directLight.direction ) );
	vec3 irradiance = dotNL * directLight.color;
	reflectedLight.directDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
	reflectedLight.directSpecular += irradiance * BRDF_BlinnPhong( directLight.direction, geometryViewDir, geometryNormal, material.specularColor, material.specularShininess ) * material.specularStrength;
}
void RE_IndirectDiffuse_BlinnPhong( const in vec3 irradiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in BlinnPhongMaterial material, inout ReflectedLight reflectedLight ) {
	reflectedLight.indirectDiffuse += irradiance * BRDF_Lambert( material.diffuseColor );
}
#define RE_Direct				RE_Direct_BlinnPhong
#define RE_IndirectDiffuse		RE_IndirectDiffuse_BlinnPhong`,_h=`PhysicalMaterial material;
material.diffuseColor = diffuseColor.rgb;
material.diffuseContribution = diffuseColor.rgb * ( 1.0 - metalnessFactor );
material.metalness = metalnessFactor;
vec3 dxy = max( abs( dFdx( nonPerturbedNormal ) ), abs( dFdy( nonPerturbedNormal ) ) );
float geometryRoughness = max( max( dxy.x, dxy.y ), dxy.z );
material.roughness = max( roughnessFactor, 0.0525 );material.roughness += geometryRoughness;
material.roughness = min( material.roughness, 1.0 );
#ifdef IOR
	material.ior = ior;
	#ifdef USE_SPECULAR
		float specularIntensityFactor = specularIntensity;
		vec3 specularColorFactor = specularColor;
		#ifdef USE_SPECULAR_COLORMAP
			specularColorFactor *= texture2D( specularColorMap, vSpecularColorMapUv ).rgb;
		#endif
		#ifdef USE_SPECULAR_INTENSITYMAP
			specularIntensityFactor *= texture2D( specularIntensityMap, vSpecularIntensityMapUv ).a;
		#endif
		material.specularF90 = mix( specularIntensityFactor, 1.0, metalnessFactor );
	#else
		float specularIntensityFactor = 1.0;
		vec3 specularColorFactor = vec3( 1.0 );
		material.specularF90 = 1.0;
	#endif
	material.specularColor = min( pow2( ( material.ior - 1.0 ) / ( material.ior + 1.0 ) ) * specularColorFactor, vec3( 1.0 ) ) * specularIntensityFactor;
	material.specularColorBlended = mix( material.specularColor, diffuseColor.rgb, metalnessFactor );
#else
	material.specularColor = vec3( 0.04 );
	material.specularColorBlended = mix( material.specularColor, diffuseColor.rgb, metalnessFactor );
	material.specularF90 = 1.0;
#endif
#ifdef USE_CLEARCOAT
	material.clearcoat = clearcoat;
	material.clearcoatRoughness = clearcoatRoughness;
	material.clearcoatF0 = vec3( 0.04 );
	material.clearcoatF90 = 1.0;
	#ifdef USE_CLEARCOATMAP
		material.clearcoat *= texture2D( clearcoatMap, vClearcoatMapUv ).x;
	#endif
	#ifdef USE_CLEARCOAT_ROUGHNESSMAP
		material.clearcoatRoughness *= texture2D( clearcoatRoughnessMap, vClearcoatRoughnessMapUv ).y;
	#endif
	material.clearcoat = saturate( material.clearcoat );	material.clearcoatRoughness = max( material.clearcoatRoughness, 0.0525 );
	material.clearcoatRoughness += geometryRoughness;
	material.clearcoatRoughness = min( material.clearcoatRoughness, 1.0 );
#endif
#ifdef USE_DISPERSION
	material.dispersion = dispersion;
#endif
#ifdef USE_IRIDESCENCE
	material.iridescence = iridescence;
	material.iridescenceIOR = iridescenceIOR;
	#ifdef USE_IRIDESCENCEMAP
		material.iridescence *= texture2D( iridescenceMap, vIridescenceMapUv ).r;
	#endif
	#ifdef USE_IRIDESCENCE_THICKNESSMAP
		material.iridescenceThickness = (iridescenceThicknessMaximum - iridescenceThicknessMinimum) * texture2D( iridescenceThicknessMap, vIridescenceThicknessMapUv ).g + iridescenceThicknessMinimum;
	#else
		material.iridescenceThickness = iridescenceThicknessMaximum;
	#endif
#endif
#ifdef USE_SHEEN
	material.sheenColor = sheenColor;
	#ifdef USE_SHEEN_COLORMAP
		material.sheenColor *= texture2D( sheenColorMap, vSheenColorMapUv ).rgb;
	#endif
	material.sheenRoughness = clamp( sheenRoughness, 0.0001, 1.0 );
	#ifdef USE_SHEEN_ROUGHNESSMAP
		material.sheenRoughness *= texture2D( sheenRoughnessMap, vSheenRoughnessMapUv ).a;
	#endif
#endif
#ifdef USE_ANISOTROPY
	#ifdef USE_ANISOTROPYMAP
		mat2 anisotropyMat = mat2( anisotropyVector.x, anisotropyVector.y, - anisotropyVector.y, anisotropyVector.x );
		vec3 anisotropyPolar = texture2D( anisotropyMap, vAnisotropyMapUv ).rgb;
		vec2 anisotropyV = anisotropyMat * normalize( 2.0 * anisotropyPolar.rg - vec2( 1.0 ) ) * anisotropyPolar.b;
	#else
		vec2 anisotropyV = anisotropyVector;
	#endif
	material.anisotropy = length( anisotropyV );
	if( material.anisotropy == 0.0 ) {
		anisotropyV = vec2( 1.0, 0.0 );
	} else {
		anisotropyV /= material.anisotropy;
		material.anisotropy = saturate( material.anisotropy );
	}
	material.alphaT = mix( pow2( material.roughness ), 1.0, pow2( material.anisotropy ) );
	material.anisotropyT = tbn[ 0 ] * anisotropyV.x + tbn[ 1 ] * anisotropyV.y;
	material.anisotropyB = tbn[ 1 ] * anisotropyV.x - tbn[ 0 ] * anisotropyV.y;
#endif`,vh=`uniform sampler2D dfgLUT;
struct PhysicalMaterial {
	vec3 diffuseColor;
	vec3 diffuseContribution;
	vec3 specularColor;
	vec3 specularColorBlended;
	float roughness;
	float metalness;
	float specularF90;
	float dispersion;
	#ifdef USE_CLEARCOAT
		float clearcoat;
		float clearcoatRoughness;
		vec3 clearcoatF0;
		float clearcoatF90;
	#endif
	#ifdef USE_IRIDESCENCE
		float iridescence;
		float iridescenceIOR;
		float iridescenceThickness;
		vec3 iridescenceFresnel;
		vec3 iridescenceF0;
		vec3 iridescenceFresnelDielectric;
		vec3 iridescenceFresnelMetallic;
	#endif
	#ifdef USE_SHEEN
		vec3 sheenColor;
		float sheenRoughness;
	#endif
	#ifdef IOR
		float ior;
	#endif
	#ifdef USE_TRANSMISSION
		float transmission;
		float transmissionAlpha;
		float thickness;
		float attenuationDistance;
		vec3 attenuationColor;
	#endif
	#ifdef USE_ANISOTROPY
		float anisotropy;
		float alphaT;
		vec3 anisotropyT;
		vec3 anisotropyB;
	#endif
};
vec3 clearcoatSpecularDirect = vec3( 0.0 );
vec3 clearcoatSpecularIndirect = vec3( 0.0 );
vec3 sheenSpecularDirect = vec3( 0.0 );
vec3 sheenSpecularIndirect = vec3(0.0 );
vec3 Schlick_to_F0( const in vec3 f, const in float f90, const in float dotVH ) {
    float x = clamp( 1.0 - dotVH, 0.0, 1.0 );
    float x2 = x * x;
    float x5 = clamp( x * x2 * x2, 0.0, 0.9999 );
    return ( f - vec3( f90 ) * x5 ) / ( 1.0 - x5 );
}
float V_GGX_SmithCorrelated( const in float alpha, const in float dotNL, const in float dotNV ) {
	float a2 = pow2( alpha );
	float gv = dotNL * sqrt( a2 + ( 1.0 - a2 ) * pow2( dotNV ) );
	float gl = dotNV * sqrt( a2 + ( 1.0 - a2 ) * pow2( dotNL ) );
	return 0.5 / max( gv + gl, EPSILON );
}
float D_GGX( const in float alpha, const in float dotNH ) {
	float a2 = pow2( alpha );
	float denom = pow2( dotNH ) * ( a2 - 1.0 ) + 1.0;
	return RECIPROCAL_PI * a2 / pow2( denom );
}
#ifdef USE_ANISOTROPY
	float V_GGX_SmithCorrelated_Anisotropic( const in float alphaT, const in float alphaB, const in float dotTV, const in float dotBV, const in float dotTL, const in float dotBL, const in float dotNV, const in float dotNL ) {
		float gv = dotNL * length( vec3( alphaT * dotTV, alphaB * dotBV, dotNV ) );
		float gl = dotNV * length( vec3( alphaT * dotTL, alphaB * dotBL, dotNL ) );
		return 0.5 / max( gv + gl, EPSILON );
	}
	float D_GGX_Anisotropic( const in float alphaT, const in float alphaB, const in float dotNH, const in float dotTH, const in float dotBH ) {
		float a2 = alphaT * alphaB;
		highp vec3 v = vec3( alphaB * dotTH, alphaT * dotBH, a2 * dotNH );
		highp float v2 = dot( v, v );
		float w2 = a2 / v2;
		return RECIPROCAL_PI * a2 * pow2 ( w2 );
	}
#endif
#ifdef USE_CLEARCOAT
	vec3 BRDF_GGX_Clearcoat( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, const in PhysicalMaterial material) {
		vec3 f0 = material.clearcoatF0;
		float f90 = material.clearcoatF90;
		float roughness = material.clearcoatRoughness;
		float alpha = pow2( roughness );
		vec3 halfDir = normalize( lightDir + viewDir );
		float dotNL = saturate( dot( normal, lightDir ) );
		float dotNV = saturate( dot( normal, viewDir ) );
		float dotNH = saturate( dot( normal, halfDir ) );
		float dotVH = saturate( dot( viewDir, halfDir ) );
		vec3 F = F_Schlick( f0, f90, dotVH );
		float V = V_GGX_SmithCorrelated( alpha, dotNL, dotNV );
		float D = D_GGX( alpha, dotNH );
		return F * ( V * D );
	}
#endif
vec3 BRDF_GGX( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, const in PhysicalMaterial material ) {
	vec3 f0 = material.specularColorBlended;
	float f90 = material.specularF90;
	float roughness = material.roughness;
	float alpha = pow2( roughness );
	vec3 halfDir = normalize( lightDir + viewDir );
	float dotNL = saturate( dot( normal, lightDir ) );
	float dotNV = saturate( dot( normal, viewDir ) );
	float dotNH = saturate( dot( normal, halfDir ) );
	float dotVH = saturate( dot( viewDir, halfDir ) );
	vec3 F = F_Schlick( f0, f90, dotVH );
	#ifdef USE_IRIDESCENCE
		F = mix( F, material.iridescenceFresnel, material.iridescence );
	#endif
	#ifdef USE_ANISOTROPY
		float dotTL = dot( material.anisotropyT, lightDir );
		float dotTV = dot( material.anisotropyT, viewDir );
		float dotTH = dot( material.anisotropyT, halfDir );
		float dotBL = dot( material.anisotropyB, lightDir );
		float dotBV = dot( material.anisotropyB, viewDir );
		float dotBH = dot( material.anisotropyB, halfDir );
		float V = V_GGX_SmithCorrelated_Anisotropic( material.alphaT, alpha, dotTV, dotBV, dotTL, dotBL, dotNV, dotNL );
		float D = D_GGX_Anisotropic( material.alphaT, alpha, dotNH, dotTH, dotBH );
	#else
		float V = V_GGX_SmithCorrelated( alpha, dotNL, dotNV );
		float D = D_GGX( alpha, dotNH );
	#endif
	return F * ( V * D );
}
vec2 LTC_Uv( const in vec3 N, const in vec3 V, const in float roughness ) {
	const float LUT_SIZE = 64.0;
	const float LUT_SCALE = ( LUT_SIZE - 1.0 ) / LUT_SIZE;
	const float LUT_BIAS = 0.5 / LUT_SIZE;
	float dotNV = saturate( dot( N, V ) );
	vec2 uv = vec2( roughness, sqrt( 1.0 - dotNV ) );
	uv = uv * LUT_SCALE + LUT_BIAS;
	return uv;
}
float LTC_ClippedSphereFormFactor( const in vec3 f ) {
	float l = length( f );
	return max( ( l * l + f.z ) / ( l + 1.0 ), 0.0 );
}
vec3 LTC_EdgeVectorFormFactor( const in vec3 v1, const in vec3 v2 ) {
	float x = dot( v1, v2 );
	float y = abs( x );
	float a = 0.8543985 + ( 0.4965155 + 0.0145206 * y ) * y;
	float b = 3.4175940 + ( 4.1616724 + y ) * y;
	float v = a / b;
	float theta_sintheta = ( x > 0.0 ) ? v : 0.5 * inversesqrt( max( 1.0 - x * x, 1e-7 ) ) - v;
	return cross( v1, v2 ) * theta_sintheta;
}
vec3 LTC_Evaluate( const in vec3 N, const in vec3 V, const in vec3 P, const in mat3 mInv, const in vec3 rectCoords[ 4 ] ) {
	vec3 v1 = rectCoords[ 1 ] - rectCoords[ 0 ];
	vec3 v2 = rectCoords[ 3 ] - rectCoords[ 0 ];
	vec3 lightNormal = cross( v1, v2 );
	if( dot( lightNormal, P - rectCoords[ 0 ] ) < 0.0 ) return vec3( 0.0 );
	vec3 T1, T2;
	T1 = normalize( V - N * dot( V, N ) );
	T2 = - cross( N, T1 );
	mat3 mat = mInv * transpose( mat3( T1, T2, N ) );
	vec3 coords[ 4 ];
	coords[ 0 ] = mat * ( rectCoords[ 0 ] - P );
	coords[ 1 ] = mat * ( rectCoords[ 1 ] - P );
	coords[ 2 ] = mat * ( rectCoords[ 2 ] - P );
	coords[ 3 ] = mat * ( rectCoords[ 3 ] - P );
	coords[ 0 ] = normalize( coords[ 0 ] );
	coords[ 1 ] = normalize( coords[ 1 ] );
	coords[ 2 ] = normalize( coords[ 2 ] );
	coords[ 3 ] = normalize( coords[ 3 ] );
	vec3 vectorFormFactor = vec3( 0.0 );
	vectorFormFactor += LTC_EdgeVectorFormFactor( coords[ 0 ], coords[ 1 ] );
	vectorFormFactor += LTC_EdgeVectorFormFactor( coords[ 1 ], coords[ 2 ] );
	vectorFormFactor += LTC_EdgeVectorFormFactor( coords[ 2 ], coords[ 3 ] );
	vectorFormFactor += LTC_EdgeVectorFormFactor( coords[ 3 ], coords[ 0 ] );
	float result = LTC_ClippedSphereFormFactor( vectorFormFactor );
	return vec3( result );
}
#if defined( USE_SHEEN )
float D_Charlie( float roughness, float dotNH ) {
	float alpha = pow2( roughness );
	float invAlpha = 1.0 / alpha;
	float cos2h = dotNH * dotNH;
	float sin2h = max( 1.0 - cos2h, 0.0078125 );
	return ( 2.0 + invAlpha ) * pow( sin2h, invAlpha * 0.5 ) / ( 2.0 * PI );
}
float V_Neubelt( float dotNV, float dotNL ) {
	return saturate( 1.0 / ( 4.0 * ( dotNL + dotNV - dotNL * dotNV ) ) );
}
vec3 BRDF_Sheen( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, vec3 sheenColor, const in float sheenRoughness ) {
	vec3 halfDir = normalize( lightDir + viewDir );
	float dotNL = saturate( dot( normal, lightDir ) );
	float dotNV = saturate( dot( normal, viewDir ) );
	float dotNH = saturate( dot( normal, halfDir ) );
	float D = D_Charlie( sheenRoughness, dotNH );
	float V = V_Neubelt( dotNV, dotNL );
	return sheenColor * ( D * V );
}
#endif
float IBLSheenBRDF( const in vec3 normal, const in vec3 viewDir, const in float roughness ) {
	float dotNV = saturate( dot( normal, viewDir ) );
	float r2 = roughness * roughness;
	float rInv = 1.0 / ( roughness + 0.1 );
	float a = -1.9362 + 1.0678 * roughness + 0.4573 * r2 - 0.8469 * rInv;
	float b = -0.6014 + 0.5538 * roughness - 0.4670 * r2 - 0.1255 * rInv;
	float DG = exp( a * dotNV + b );
	return saturate( DG );
}
vec3 EnvironmentBRDF( const in vec3 normal, const in vec3 viewDir, const in vec3 specularColor, const in float specularF90, const in float roughness ) {
	float dotNV = saturate( dot( normal, viewDir ) );
	vec2 fab = texture2D( dfgLUT, vec2( roughness, dotNV ) ).rg;
	return specularColor * fab.x + specularF90 * fab.y;
}
#ifdef USE_IRIDESCENCE
void computeMultiscatteringIridescence( const in vec3 normal, const in vec3 viewDir, const in vec3 specularColor, const in float specularF90, const in float iridescence, const in vec3 iridescenceF0, const in float roughness, inout vec3 singleScatter, inout vec3 multiScatter ) {
#else
void computeMultiscattering( const in vec3 normal, const in vec3 viewDir, const in vec3 specularColor, const in float specularF90, const in float roughness, inout vec3 singleScatter, inout vec3 multiScatter ) {
#endif
	float dotNV = saturate( dot( normal, viewDir ) );
	vec2 fab = texture2D( dfgLUT, vec2( roughness, dotNV ) ).rg;
	#ifdef USE_IRIDESCENCE
		vec3 Fr = mix( specularColor, iridescenceF0, iridescence );
	#else
		vec3 Fr = specularColor;
	#endif
	vec3 FssEss = Fr * fab.x + specularF90 * fab.y;
	float Ess = fab.x + fab.y;
	float Ems = 1.0 - Ess;
	vec3 Favg = Fr + ( 1.0 - Fr ) * 0.047619;	vec3 Fms = FssEss * Favg / ( 1.0 - Ems * Favg );
	singleScatter += FssEss;
	multiScatter += Fms * Ems;
}
vec3 BRDF_GGX_Multiscatter( const in vec3 lightDir, const in vec3 viewDir, const in vec3 normal, const in PhysicalMaterial material ) {
	vec3 singleScatter = BRDF_GGX( lightDir, viewDir, normal, material );
	float dotNL = saturate( dot( normal, lightDir ) );
	float dotNV = saturate( dot( normal, viewDir ) );
	vec2 dfgV = texture2D( dfgLUT, vec2( material.roughness, dotNV ) ).rg;
	vec2 dfgL = texture2D( dfgLUT, vec2( material.roughness, dotNL ) ).rg;
	vec3 FssEss_V = material.specularColorBlended * dfgV.x + material.specularF90 * dfgV.y;
	vec3 FssEss_L = material.specularColorBlended * dfgL.x + material.specularF90 * dfgL.y;
	float Ess_V = dfgV.x + dfgV.y;
	float Ess_L = dfgL.x + dfgL.y;
	float Ems_V = 1.0 - Ess_V;
	float Ems_L = 1.0 - Ess_L;
	vec3 Favg = material.specularColorBlended + ( 1.0 - material.specularColorBlended ) * 0.047619;
	vec3 Fms = FssEss_V * FssEss_L * Favg / ( 1.0 - Ems_V * Ems_L * Favg + EPSILON );
	float compensationFactor = Ems_V * Ems_L;
	vec3 multiScatter = Fms * compensationFactor;
	return singleScatter + multiScatter;
}
#if NUM_RECT_AREA_LIGHTS > 0
	void RE_Direct_RectArea_Physical( const in RectAreaLight rectAreaLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in PhysicalMaterial material, inout ReflectedLight reflectedLight ) {
		vec3 normal = geometryNormal;
		vec3 viewDir = geometryViewDir;
		vec3 position = geometryPosition;
		vec3 lightPos = rectAreaLight.position;
		vec3 halfWidth = rectAreaLight.halfWidth;
		vec3 halfHeight = rectAreaLight.halfHeight;
		vec3 lightColor = rectAreaLight.color;
		float roughness = material.roughness;
		vec3 rectCoords[ 4 ];
		rectCoords[ 0 ] = lightPos + halfWidth - halfHeight;		rectCoords[ 1 ] = lightPos - halfWidth - halfHeight;
		rectCoords[ 2 ] = lightPos - halfWidth + halfHeight;
		rectCoords[ 3 ] = lightPos + halfWidth + halfHeight;
		vec2 uv = LTC_Uv( normal, viewDir, roughness );
		vec4 t1 = texture2D( ltc_1, uv );
		vec4 t2 = texture2D( ltc_2, uv );
		mat3 mInv = mat3(
			vec3( t1.x, 0, t1.y ),
			vec3(    0, 1,    0 ),
			vec3( t1.z, 0, t1.w )
		);
		vec3 fresnel = ( material.specularColorBlended * t2.x + ( material.specularF90 - material.specularColorBlended ) * t2.y );
		reflectedLight.directSpecular += lightColor * fresnel * LTC_Evaluate( normal, viewDir, position, mInv, rectCoords );
		reflectedLight.directDiffuse += lightColor * material.diffuseContribution * LTC_Evaluate( normal, viewDir, position, mat3( 1.0 ), rectCoords );
		#ifdef USE_CLEARCOAT
			vec3 Ncc = geometryClearcoatNormal;
			vec2 uvClearcoat = LTC_Uv( Ncc, viewDir, material.clearcoatRoughness );
			vec4 t1Clearcoat = texture2D( ltc_1, uvClearcoat );
			vec4 t2Clearcoat = texture2D( ltc_2, uvClearcoat );
			mat3 mInvClearcoat = mat3(
				vec3( t1Clearcoat.x, 0, t1Clearcoat.y ),
				vec3(             0, 1,             0 ),
				vec3( t1Clearcoat.z, 0, t1Clearcoat.w )
			);
			vec3 fresnelClearcoat = material.clearcoatF0 * t2Clearcoat.x + ( material.clearcoatF90 - material.clearcoatF0 ) * t2Clearcoat.y;
			clearcoatSpecularDirect += lightColor * fresnelClearcoat * LTC_Evaluate( Ncc, viewDir, position, mInvClearcoat, rectCoords );
		#endif
	}
#endif
void RE_Direct_Physical( const in IncidentLight directLight, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in PhysicalMaterial material, inout ReflectedLight reflectedLight ) {
	float dotNL = saturate( dot( geometryNormal, directLight.direction ) );
	vec3 irradiance = dotNL * directLight.color;
	#ifdef USE_CLEARCOAT
		float dotNLcc = saturate( dot( geometryClearcoatNormal, directLight.direction ) );
		vec3 ccIrradiance = dotNLcc * directLight.color;
		clearcoatSpecularDirect += ccIrradiance * BRDF_GGX_Clearcoat( directLight.direction, geometryViewDir, geometryClearcoatNormal, material );
	#endif
	#ifdef USE_SHEEN
 
 		sheenSpecularDirect += irradiance * BRDF_Sheen( directLight.direction, geometryViewDir, geometryNormal, material.sheenColor, material.sheenRoughness );
 
 		float sheenAlbedoV = IBLSheenBRDF( geometryNormal, geometryViewDir, material.sheenRoughness );
 		float sheenAlbedoL = IBLSheenBRDF( geometryNormal, directLight.direction, material.sheenRoughness );
 
 		float sheenEnergyComp = 1.0 - max3( material.sheenColor ) * max( sheenAlbedoV, sheenAlbedoL );
 
 		irradiance *= sheenEnergyComp;
 
 	#endif
	reflectedLight.directSpecular += irradiance * BRDF_GGX_Multiscatter( directLight.direction, geometryViewDir, geometryNormal, material );
	reflectedLight.directDiffuse += irradiance * BRDF_Lambert( material.diffuseContribution );
}
void RE_IndirectDiffuse_Physical( const in vec3 irradiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in PhysicalMaterial material, inout ReflectedLight reflectedLight ) {
	vec3 diffuse = irradiance * BRDF_Lambert( material.diffuseContribution );
	#ifdef USE_SHEEN
		float sheenAlbedo = IBLSheenBRDF( geometryNormal, geometryViewDir, material.sheenRoughness );
		float sheenEnergyComp = 1.0 - max3( material.sheenColor ) * sheenAlbedo;
		diffuse *= sheenEnergyComp;
	#endif
	reflectedLight.indirectDiffuse += diffuse;
}
void RE_IndirectSpecular_Physical( const in vec3 radiance, const in vec3 irradiance, const in vec3 clearcoatRadiance, const in vec3 geometryPosition, const in vec3 geometryNormal, const in vec3 geometryViewDir, const in vec3 geometryClearcoatNormal, const in PhysicalMaterial material, inout ReflectedLight reflectedLight) {
	#ifdef USE_CLEARCOAT
		clearcoatSpecularIndirect += clearcoatRadiance * EnvironmentBRDF( geometryClearcoatNormal, geometryViewDir, material.clearcoatF0, material.clearcoatF90, material.clearcoatRoughness );
	#endif
	#ifdef USE_SHEEN
		sheenSpecularIndirect += irradiance * material.sheenColor * IBLSheenBRDF( geometryNormal, geometryViewDir, material.sheenRoughness ) * RECIPROCAL_PI;
 	#endif
	vec3 singleScatteringDielectric = vec3( 0.0 );
	vec3 multiScatteringDielectric = vec3( 0.0 );
	vec3 singleScatteringMetallic = vec3( 0.0 );
	vec3 multiScatteringMetallic = vec3( 0.0 );
	#ifdef USE_IRIDESCENCE
		computeMultiscatteringIridescence( geometryNormal, geometryViewDir, material.specularColor, material.specularF90, material.iridescence, material.iridescenceFresnelDielectric, material.roughness, singleScatteringDielectric, multiScatteringDielectric );
		computeMultiscatteringIridescence( geometryNormal, geometryViewDir, material.diffuseColor, material.specularF90, material.iridescence, material.iridescenceFresnelMetallic, material.roughness, singleScatteringMetallic, multiScatteringMetallic );
	#else
		computeMultiscattering( geometryNormal, geometryViewDir, material.specularColor, material.specularF90, material.roughness, singleScatteringDielectric, multiScatteringDielectric );
		computeMultiscattering( geometryNormal, geometryViewDir, material.diffuseColor, material.specularF90, material.roughness, singleScatteringMetallic, multiScatteringMetallic );
	#endif
	vec3 singleScattering = mix( singleScatteringDielectric, singleScatteringMetallic, material.metalness );
	vec3 multiScattering = mix( multiScatteringDielectric, multiScatteringMetallic, material.metalness );
	vec3 totalScatteringDielectric = singleScatteringDielectric + multiScatteringDielectric;
	vec3 diffuse = material.diffuseContribution * ( 1.0 - totalScatteringDielectric );
	vec3 cosineWeightedIrradiance = irradiance * RECIPROCAL_PI;
	vec3 indirectSpecular = radiance * singleScattering;
	indirectSpecular += multiScattering * cosineWeightedIrradiance;
	vec3 indirectDiffuse = diffuse * cosineWeightedIrradiance;
	#ifdef USE_SHEEN
		float sheenAlbedo = IBLSheenBRDF( geometryNormal, geometryViewDir, material.sheenRoughness );
		float sheenEnergyComp = 1.0 - max3( material.sheenColor ) * sheenAlbedo;
		indirectSpecular *= sheenEnergyComp;
		indirectDiffuse *= sheenEnergyComp;
	#endif
	reflectedLight.indirectSpecular += indirectSpecular;
	reflectedLight.indirectDiffuse += indirectDiffuse;
}
#define RE_Direct				RE_Direct_Physical
#define RE_Direct_RectArea		RE_Direct_RectArea_Physical
#define RE_IndirectDiffuse		RE_IndirectDiffuse_Physical
#define RE_IndirectSpecular		RE_IndirectSpecular_Physical
float computeSpecularOcclusion( const in float dotNV, const in float ambientOcclusion, const in float roughness ) {
	return saturate( pow( dotNV + ambientOcclusion, exp2( - 16.0 * roughness - 1.0 ) ) - 1.0 + ambientOcclusion );
}`,xh=`
vec3 geometryPosition = - vViewPosition;
vec3 geometryNormal = normal;
vec3 geometryViewDir = ( isOrthographic ) ? vec3( 0, 0, 1 ) : normalize( vViewPosition );
vec3 geometryClearcoatNormal = vec3( 0.0 );
#ifdef USE_CLEARCOAT
	geometryClearcoatNormal = clearcoatNormal;
#endif
#ifdef USE_IRIDESCENCE
	float dotNVi = saturate( dot( normal, geometryViewDir ) );
	if ( material.iridescenceThickness == 0.0 ) {
		material.iridescence = 0.0;
	} else {
		material.iridescence = saturate( material.iridescence );
	}
	if ( material.iridescence > 0.0 ) {
		material.iridescenceFresnelDielectric = evalIridescence( 1.0, material.iridescenceIOR, dotNVi, material.iridescenceThickness, material.specularColor );
		material.iridescenceFresnelMetallic = evalIridescence( 1.0, material.iridescenceIOR, dotNVi, material.iridescenceThickness, material.diffuseColor );
		material.iridescenceFresnel = mix( material.iridescenceFresnelDielectric, material.iridescenceFresnelMetallic, material.metalness );
		material.iridescenceF0 = Schlick_to_F0( material.iridescenceFresnel, 1.0, dotNVi );
	}
#endif
IncidentLight directLight;
#if ( NUM_POINT_LIGHTS > 0 ) && defined( RE_Direct )
	PointLight pointLight;
	#if defined( USE_SHADOWMAP ) && NUM_POINT_LIGHT_SHADOWS > 0
	PointLightShadow pointLightShadow;
	#endif
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_POINT_LIGHTS; i ++ ) {
		pointLight = pointLights[ i ];
		getPointLightInfo( pointLight, geometryPosition, directLight );
		#if defined( USE_SHADOWMAP ) && ( UNROLLED_LOOP_INDEX < NUM_POINT_LIGHT_SHADOWS ) && ( defined( SHADOWMAP_TYPE_PCF ) || defined( SHADOWMAP_TYPE_BASIC ) )
		pointLightShadow = pointLightShadows[ i ];
		directLight.color *= ( directLight.visible && receiveShadow ) ? getPointShadow( pointShadowMap[ i ], pointLightShadow.shadowMapSize, pointLightShadow.shadowIntensity, pointLightShadow.shadowBias, pointLightShadow.shadowRadius, vPointShadowCoord[ i ], pointLightShadow.shadowCameraNear, pointLightShadow.shadowCameraFar ) : 1.0;
		#endif
		RE_Direct( directLight, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
	}
	#pragma unroll_loop_end
#endif
#if ( NUM_SPOT_LIGHTS > 0 ) && defined( RE_Direct )
	SpotLight spotLight;
	vec4 spotColor;
	vec3 spotLightCoord;
	bool inSpotLightMap;
	#if defined( USE_SHADOWMAP ) && NUM_SPOT_LIGHT_SHADOWS > 0
	SpotLightShadow spotLightShadow;
	#endif
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_SPOT_LIGHTS; i ++ ) {
		spotLight = spotLights[ i ];
		getSpotLightInfo( spotLight, geometryPosition, directLight );
		#if ( UNROLLED_LOOP_INDEX < NUM_SPOT_LIGHT_SHADOWS_WITH_MAPS )
		#define SPOT_LIGHT_MAP_INDEX UNROLLED_LOOP_INDEX
		#elif ( UNROLLED_LOOP_INDEX < NUM_SPOT_LIGHT_SHADOWS )
		#define SPOT_LIGHT_MAP_INDEX NUM_SPOT_LIGHT_MAPS
		#else
		#define SPOT_LIGHT_MAP_INDEX ( UNROLLED_LOOP_INDEX - NUM_SPOT_LIGHT_SHADOWS + NUM_SPOT_LIGHT_SHADOWS_WITH_MAPS )
		#endif
		#if ( SPOT_LIGHT_MAP_INDEX < NUM_SPOT_LIGHT_MAPS )
			spotLightCoord = vSpotLightCoord[ i ].xyz / vSpotLightCoord[ i ].w;
			inSpotLightMap = all( lessThan( abs( spotLightCoord * 2. - 1. ), vec3( 1.0 ) ) );
			spotColor = texture2D( spotLightMap[ SPOT_LIGHT_MAP_INDEX ], spotLightCoord.xy );
			directLight.color = inSpotLightMap ? directLight.color * spotColor.rgb : directLight.color;
		#endif
		#undef SPOT_LIGHT_MAP_INDEX
		#if defined( USE_SHADOWMAP ) && ( UNROLLED_LOOP_INDEX < NUM_SPOT_LIGHT_SHADOWS )
		spotLightShadow = spotLightShadows[ i ];
		directLight.color *= ( directLight.visible && receiveShadow ) ? getShadow( spotShadowMap[ i ], spotLightShadow.shadowMapSize, spotLightShadow.shadowIntensity, spotLightShadow.shadowBias, spotLightShadow.shadowRadius, vSpotLightCoord[ i ] ) : 1.0;
		#endif
		RE_Direct( directLight, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
	}
	#pragma unroll_loop_end
#endif
#if ( NUM_DIR_LIGHTS > 0 ) && defined( RE_Direct )
	DirectionalLight directionalLight;
	#if defined( USE_SHADOWMAP ) && NUM_DIR_LIGHT_SHADOWS > 0
	DirectionalLightShadow directionalLightShadow;
	#endif
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_DIR_LIGHTS; i ++ ) {
		directionalLight = directionalLights[ i ];
		getDirectionalLightInfo( directionalLight, directLight );
		#if defined( USE_SHADOWMAP ) && ( UNROLLED_LOOP_INDEX < NUM_DIR_LIGHT_SHADOWS )
		directionalLightShadow = directionalLightShadows[ i ];
		directLight.color *= ( directLight.visible && receiveShadow ) ? getShadow( directionalShadowMap[ i ], directionalLightShadow.shadowMapSize, directionalLightShadow.shadowIntensity, directionalLightShadow.shadowBias, directionalLightShadow.shadowRadius, vDirectionalShadowCoord[ i ] ) : 1.0;
		#endif
		RE_Direct( directLight, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
	}
	#pragma unroll_loop_end
#endif
#if ( NUM_RECT_AREA_LIGHTS > 0 ) && defined( RE_Direct_RectArea )
	RectAreaLight rectAreaLight;
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_RECT_AREA_LIGHTS; i ++ ) {
		rectAreaLight = rectAreaLights[ i ];
		RE_Direct_RectArea( rectAreaLight, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
	}
	#pragma unroll_loop_end
#endif
#if defined( RE_IndirectDiffuse )
	vec3 iblIrradiance = vec3( 0.0 );
	vec3 irradiance = getAmbientLightIrradiance( ambientLightColor );
	#if defined( USE_LIGHT_PROBES )
		irradiance += getLightProbeIrradiance( lightProbe, geometryNormal );
	#endif
	#if ( NUM_HEMI_LIGHTS > 0 )
		#pragma unroll_loop_start
		for ( int i = 0; i < NUM_HEMI_LIGHTS; i ++ ) {
			irradiance += getHemisphereLightIrradiance( hemisphereLights[ i ], geometryNormal );
		}
		#pragma unroll_loop_end
	#endif
	#ifdef USE_LIGHT_PROBES_GRID
		vec3 probeWorldPos = ( ( vec4( geometryPosition, 1.0 ) - viewMatrix[ 3 ] ) * viewMatrix ).xyz;
		vec3 probeWorldNormal = inverseTransformDirection( geometryNormal, viewMatrix );
		irradiance += getLightProbeGridIrradiance( probeWorldPos, probeWorldNormal );
	#endif
#endif
#if defined( RE_IndirectSpecular )
	vec3 radiance = vec3( 0.0 );
	vec3 clearcoatRadiance = vec3( 0.0 );
#endif`,Mh=`#if defined( RE_IndirectDiffuse )
	#ifdef USE_LIGHTMAP
		vec4 lightMapTexel = texture2D( lightMap, vLightMapUv );
		vec3 lightMapIrradiance = lightMapTexel.rgb * lightMapIntensity;
		irradiance += lightMapIrradiance;
	#endif
	#if defined( USE_ENVMAP ) && defined( ENVMAP_TYPE_CUBE_UV )
		#if defined( STANDARD ) || defined( LAMBERT ) || defined( PHONG )
			iblIrradiance += getIBLIrradiance( geometryNormal );
		#endif
	#endif
#endif
#if defined( USE_ENVMAP ) && defined( RE_IndirectSpecular )
	#ifdef USE_ANISOTROPY
		radiance += getIBLAnisotropyRadiance( geometryViewDir, geometryNormal, material.roughness, material.anisotropyB, material.anisotropy );
	#else
		radiance += getIBLRadiance( geometryViewDir, geometryNormal, material.roughness );
	#endif
	#ifdef USE_CLEARCOAT
		clearcoatRadiance += getIBLRadiance( geometryViewDir, geometryClearcoatNormal, material.clearcoatRoughness );
	#endif
#endif`,Sh=`#if defined( RE_IndirectDiffuse )
	#if defined( LAMBERT ) || defined( PHONG )
		irradiance += iblIrradiance;
	#endif
	RE_IndirectDiffuse( irradiance, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
#endif
#if defined( RE_IndirectSpecular )
	RE_IndirectSpecular( radiance, iblIrradiance, clearcoatRadiance, geometryPosition, geometryNormal, geometryViewDir, geometryClearcoatNormal, material, reflectedLight );
#endif`,Eh=`#ifdef USE_LIGHT_PROBES_GRID
uniform highp sampler3D probesSH;
uniform vec3 probesMin;
uniform vec3 probesMax;
uniform vec3 probesResolution;
vec3 getLightProbeGridIrradiance( vec3 worldPos, vec3 worldNormal ) {
	vec3 res = probesResolution;
	vec3 gridRange = probesMax - probesMin;
	vec3 resMinusOne = res - 1.0;
	vec3 probeSpacing = gridRange / resMinusOne;
	vec3 samplePos = worldPos + worldNormal * probeSpacing * 0.5;
	vec3 uvw = clamp( ( samplePos - probesMin ) / gridRange, 0.0, 1.0 );
	uvw = uvw * resMinusOne / res + 0.5 / res;
	float nz          = res.z;
	float paddedSlices = nz + 2.0;
	float atlasDepth  = 7.0 * paddedSlices;
	float uvZBase     = uvw.z * nz + 1.0;
	vec4 s0 = texture( probesSH, vec3( uvw.xy, ( uvZBase                       ) / atlasDepth ) );
	vec4 s1 = texture( probesSH, vec3( uvw.xy, ( uvZBase +       paddedSlices   ) / atlasDepth ) );
	vec4 s2 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 2.0 * paddedSlices   ) / atlasDepth ) );
	vec4 s3 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 3.0 * paddedSlices   ) / atlasDepth ) );
	vec4 s4 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 4.0 * paddedSlices   ) / atlasDepth ) );
	vec4 s5 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 5.0 * paddedSlices   ) / atlasDepth ) );
	vec4 s6 = texture( probesSH, vec3( uvw.xy, ( uvZBase + 6.0 * paddedSlices   ) / atlasDepth ) );
	vec3 c0 = s0.xyz;
	vec3 c1 = vec3( s0.w, s1.xy );
	vec3 c2 = vec3( s1.zw, s2.x );
	vec3 c3 = s2.yzw;
	vec3 c4 = s3.xyz;
	vec3 c5 = vec3( s3.w, s4.xy );
	vec3 c6 = vec3( s4.zw, s5.x );
	vec3 c7 = s5.yzw;
	vec3 c8 = s6.xyz;
	float x = worldNormal.x, y = worldNormal.y, z = worldNormal.z;
	vec3 result = c0 * 0.886227;
	result += c1 * 2.0 * 0.511664 * y;
	result += c2 * 2.0 * 0.511664 * z;
	result += c3 * 2.0 * 0.511664 * x;
	result += c4 * 2.0 * 0.429043 * x * y;
	result += c5 * 2.0 * 0.429043 * y * z;
	result += c6 * ( 0.743125 * z * z - 0.247708 );
	result += c7 * 2.0 * 0.429043 * x * z;
	result += c8 * 0.429043 * ( x * x - y * y );
	return max( result, vec3( 0.0 ) );
}
#endif`,Th=`#if defined( USE_LOGARITHMIC_DEPTH_BUFFER )
	gl_FragDepth = vIsPerspective == 0.0 ? gl_FragCoord.z : log2( vFragDepth ) * logDepthBufFC * 0.5;
#endif`,yh=`#if defined( USE_LOGARITHMIC_DEPTH_BUFFER )
	uniform float logDepthBufFC;
	varying float vFragDepth;
	varying float vIsPerspective;
#endif`,bh=`#ifdef USE_LOGARITHMIC_DEPTH_BUFFER
	varying float vFragDepth;
	varying float vIsPerspective;
#endif`,Ah=`#ifdef USE_LOGARITHMIC_DEPTH_BUFFER
	vFragDepth = 1.0 + gl_Position.w;
	vIsPerspective = float( isPerspectiveMatrix( projectionMatrix ) );
#endif`,wh=`#ifdef USE_MAP
	vec4 sampledDiffuseColor = texture2D( map, vMapUv );
	#ifdef DECODE_VIDEO_TEXTURE
		sampledDiffuseColor = sRGBTransferEOTF( sampledDiffuseColor );
	#endif
	diffuseColor *= sampledDiffuseColor;
#endif`,Rh=`#ifdef USE_MAP
	uniform sampler2D map;
#endif`,Ch=`#if defined( USE_MAP ) || defined( USE_ALPHAMAP )
	#if defined( USE_POINTS_UV )
		vec2 uv = vUv;
	#else
		vec2 uv = ( uvTransform * vec3( gl_PointCoord.x, 1.0 - gl_PointCoord.y, 1 ) ).xy;
	#endif
#endif
#ifdef USE_MAP
	diffuseColor *= texture2D( map, uv );
#endif
#ifdef USE_ALPHAMAP
	diffuseColor.a *= texture2D( alphaMap, uv ).g;
#endif`,Ph=`#if defined( USE_POINTS_UV )
	varying vec2 vUv;
#else
	#if defined( USE_MAP ) || defined( USE_ALPHAMAP )
		uniform mat3 uvTransform;
	#endif
#endif
#ifdef USE_MAP
	uniform sampler2D map;
#endif
#ifdef USE_ALPHAMAP
	uniform sampler2D alphaMap;
#endif`,Uh=`float metalnessFactor = metalness;
#ifdef USE_METALNESSMAP
	vec4 texelMetalness = texture2D( metalnessMap, vMetalnessMapUv );
	metalnessFactor *= texelMetalness.b;
#endif`,Dh=`#ifdef USE_METALNESSMAP
	uniform sampler2D metalnessMap;
#endif`,Ih=`#ifdef USE_INSTANCING_MORPH
	float morphTargetInfluences[ MORPHTARGETS_COUNT ];
	float morphTargetBaseInfluence = texelFetch( morphTexture, ivec2( 0, gl_InstanceID ), 0 ).r;
	for ( int i = 0; i < MORPHTARGETS_COUNT; i ++ ) {
		morphTargetInfluences[i] =  texelFetch( morphTexture, ivec2( i + 1, gl_InstanceID ), 0 ).r;
	}
#endif`,Lh=`#if defined( USE_MORPHCOLORS )
	vColor *= morphTargetBaseInfluence;
	for ( int i = 0; i < MORPHTARGETS_COUNT; i ++ ) {
		#if defined( USE_COLOR_ALPHA )
			if ( morphTargetInfluences[ i ] != 0.0 ) vColor += getMorph( gl_VertexID, i, 2 ) * morphTargetInfluences[ i ];
		#elif defined( USE_COLOR )
			if ( morphTargetInfluences[ i ] != 0.0 ) vColor += getMorph( gl_VertexID, i, 2 ).rgb * morphTargetInfluences[ i ];
		#endif
	}
#endif`,Nh=`#ifdef USE_MORPHNORMALS
	objectNormal *= morphTargetBaseInfluence;
	for ( int i = 0; i < MORPHTARGETS_COUNT; i ++ ) {
		if ( morphTargetInfluences[ i ] != 0.0 ) objectNormal += getMorph( gl_VertexID, i, 1 ).xyz * morphTargetInfluences[ i ];
	}
#endif`,Fh=`#ifdef USE_MORPHTARGETS
	#ifndef USE_INSTANCING_MORPH
		uniform float morphTargetBaseInfluence;
		uniform float morphTargetInfluences[ MORPHTARGETS_COUNT ];
	#endif
	uniform sampler2DArray morphTargetsTexture;
	uniform ivec2 morphTargetsTextureSize;
	vec4 getMorph( const in int vertexIndex, const in int morphTargetIndex, const in int offset ) {
		int texelIndex = vertexIndex * MORPHTARGETS_TEXTURE_STRIDE + offset;
		int y = texelIndex / morphTargetsTextureSize.x;
		int x = texelIndex - y * morphTargetsTextureSize.x;
		ivec3 morphUV = ivec3( x, y, morphTargetIndex );
		return texelFetch( morphTargetsTexture, morphUV, 0 );
	}
#endif`,Oh=`#ifdef USE_MORPHTARGETS
	transformed *= morphTargetBaseInfluence;
	for ( int i = 0; i < MORPHTARGETS_COUNT; i ++ ) {
		if ( morphTargetInfluences[ i ] != 0.0 ) transformed += getMorph( gl_VertexID, i, 0 ).xyz * morphTargetInfluences[ i ];
	}
#endif`,Bh=`float faceDirection = gl_FrontFacing ? 1.0 : - 1.0;
#ifdef FLAT_SHADED
	vec3 fdx = dFdx( vViewPosition );
	vec3 fdy = dFdy( vViewPosition );
	vec3 normal = normalize( cross( fdx, fdy ) );
#else
	vec3 normal = normalize( vNormal );
	#ifdef DOUBLE_SIDED
		normal *= faceDirection;
	#endif
#endif
#if defined( USE_NORMALMAP_TANGENTSPACE ) || defined( USE_CLEARCOAT_NORMALMAP ) || defined( USE_ANISOTROPY )
	#ifdef USE_TANGENT
		mat3 tbn = mat3( normalize( vTangent ), normalize( vBitangent ), normal );
	#else
		mat3 tbn = getTangentFrame( - vViewPosition, normal,
		#if defined( USE_NORMALMAP )
			vNormalMapUv
		#elif defined( USE_CLEARCOAT_NORMALMAP )
			vClearcoatNormalMapUv
		#else
			vUv
		#endif
		);
	#endif
	#if defined( DOUBLE_SIDED ) && ! defined( FLAT_SHADED )
		tbn[0] *= faceDirection;
		tbn[1] *= faceDirection;
	#endif
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	#ifdef USE_TANGENT
		mat3 tbn2 = mat3( normalize( vTangent ), normalize( vBitangent ), normal );
	#else
		mat3 tbn2 = getTangentFrame( - vViewPosition, normal, vClearcoatNormalMapUv );
	#endif
	#if defined( DOUBLE_SIDED ) && ! defined( FLAT_SHADED )
		tbn2[0] *= faceDirection;
		tbn2[1] *= faceDirection;
	#endif
#endif
vec3 nonPerturbedNormal = normal;`,zh=`#ifdef USE_NORMALMAP_OBJECTSPACE
	normal = texture2D( normalMap, vNormalMapUv ).xyz * 2.0 - 1.0;
	#ifdef FLIP_SIDED
		normal = - normal;
	#endif
	#ifdef DOUBLE_SIDED
		normal = normal * faceDirection;
	#endif
	normal = normalize( normalMatrix * normal );
#elif defined( USE_NORMALMAP_TANGENTSPACE )
	vec3 mapN = texture2D( normalMap, vNormalMapUv ).xyz * 2.0 - 1.0;
	#if defined( USE_PACKED_NORMALMAP )
		mapN = vec3( mapN.xy, sqrt( saturate( 1.0 - dot( mapN.xy, mapN.xy ) ) ) );
	#endif
	mapN.xy *= normalScale;
	normal = normalize( tbn * mapN );
#elif defined( USE_BUMPMAP )
	normal = perturbNormalArb( - vViewPosition, normal, dHdxy_fwd(), faceDirection );
#endif`,Gh=`#ifndef FLAT_SHADED
	varying vec3 vNormal;
	#ifdef USE_TANGENT
		varying vec3 vTangent;
		varying vec3 vBitangent;
	#endif
#endif`,Hh=`#ifndef FLAT_SHADED
	varying vec3 vNormal;
	#ifdef USE_TANGENT
		varying vec3 vTangent;
		varying vec3 vBitangent;
	#endif
#endif`,Vh=`#ifndef FLAT_SHADED
	vNormal = normalize( transformedNormal );
	#ifdef USE_TANGENT
		vTangent = normalize( transformedTangent );
		vBitangent = normalize( cross( vNormal, vTangent ) * tangent.w );
	#endif
#endif`,kh=`#ifdef USE_NORMALMAP
	uniform sampler2D normalMap;
	uniform vec2 normalScale;
#endif
#ifdef USE_NORMALMAP_OBJECTSPACE
	uniform mat3 normalMatrix;
#endif
#if ! defined ( USE_TANGENT ) && ( defined ( USE_NORMALMAP_TANGENTSPACE ) || defined ( USE_CLEARCOAT_NORMALMAP ) || defined( USE_ANISOTROPY ) )
	mat3 getTangentFrame( vec3 eye_pos, vec3 surf_norm, vec2 uv ) {
		vec3 q0 = dFdx( eye_pos.xyz );
		vec3 q1 = dFdy( eye_pos.xyz );
		vec2 st0 = dFdx( uv.st );
		vec2 st1 = dFdy( uv.st );
		vec3 N = surf_norm;
		vec3 q1perp = cross( q1, N );
		vec3 q0perp = cross( N, q0 );
		vec3 T = q1perp * st0.x + q0perp * st1.x;
		vec3 B = q1perp * st0.y + q0perp * st1.y;
		float det = max( dot( T, T ), dot( B, B ) );
		float scale = ( det == 0.0 ) ? 0.0 : inversesqrt( det );
		return mat3( T * scale, B * scale, N );
	}
#endif`,Wh=`#ifdef USE_CLEARCOAT
	vec3 clearcoatNormal = nonPerturbedNormal;
#endif`,Xh=`#ifdef USE_CLEARCOAT_NORMALMAP
	vec3 clearcoatMapN = texture2D( clearcoatNormalMap, vClearcoatNormalMapUv ).xyz * 2.0 - 1.0;
	clearcoatMapN.xy *= clearcoatNormalScale;
	clearcoatNormal = normalize( tbn2 * clearcoatMapN );
#endif`,qh=`#ifdef USE_CLEARCOATMAP
	uniform sampler2D clearcoatMap;
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	uniform sampler2D clearcoatNormalMap;
	uniform vec2 clearcoatNormalScale;
#endif
#ifdef USE_CLEARCOAT_ROUGHNESSMAP
	uniform sampler2D clearcoatRoughnessMap;
#endif`,Yh=`#ifdef USE_IRIDESCENCEMAP
	uniform sampler2D iridescenceMap;
#endif
#ifdef USE_IRIDESCENCE_THICKNESSMAP
	uniform sampler2D iridescenceThicknessMap;
#endif`,jh=`#ifdef OPAQUE
diffuseColor.a = 1.0;
#endif
#ifdef USE_TRANSMISSION
diffuseColor.a *= material.transmissionAlpha;
#endif
gl_FragColor = vec4( outgoingLight, diffuseColor.a );`,Kh=`vec3 packNormalToRGB( const in vec3 normal ) {
	return normalize( normal ) * 0.5 + 0.5;
}
vec3 unpackRGBToNormal( const in vec3 rgb ) {
	return 2.0 * rgb.xyz - 1.0;
}
const float PackUpscale = 256. / 255.;const float UnpackDownscale = 255. / 256.;const float ShiftRight8 = 1. / 256.;
const float Inv255 = 1. / 255.;
const vec4 PackFactors = vec4( 1.0, 256.0, 256.0 * 256.0, 256.0 * 256.0 * 256.0 );
const vec2 UnpackFactors2 = vec2( UnpackDownscale, 1.0 / PackFactors.g );
const vec3 UnpackFactors3 = vec3( UnpackDownscale / PackFactors.rg, 1.0 / PackFactors.b );
const vec4 UnpackFactors4 = vec4( UnpackDownscale / PackFactors.rgb, 1.0 / PackFactors.a );
vec4 packDepthToRGBA( const in float v ) {
	if( v <= 0.0 )
		return vec4( 0., 0., 0., 0. );
	if( v >= 1.0 )
		return vec4( 1., 1., 1., 1. );
	float vuf;
	float af = modf( v * PackFactors.a, vuf );
	float bf = modf( vuf * ShiftRight8, vuf );
	float gf = modf( vuf * ShiftRight8, vuf );
	return vec4( vuf * Inv255, gf * PackUpscale, bf * PackUpscale, af );
}
vec3 packDepthToRGB( const in float v ) {
	if( v <= 0.0 )
		return vec3( 0., 0., 0. );
	if( v >= 1.0 )
		return vec3( 1., 1., 1. );
	float vuf;
	float bf = modf( v * PackFactors.b, vuf );
	float gf = modf( vuf * ShiftRight8, vuf );
	return vec3( vuf * Inv255, gf * PackUpscale, bf );
}
vec2 packDepthToRG( const in float v ) {
	if( v <= 0.0 )
		return vec2( 0., 0. );
	if( v >= 1.0 )
		return vec2( 1., 1. );
	float vuf;
	float gf = modf( v * 256., vuf );
	return vec2( vuf * Inv255, gf );
}
float unpackRGBAToDepth( const in vec4 v ) {
	return dot( v, UnpackFactors4 );
}
float unpackRGBToDepth( const in vec3 v ) {
	return dot( v, UnpackFactors3 );
}
float unpackRGToDepth( const in vec2 v ) {
	return v.r * UnpackFactors2.r + v.g * UnpackFactors2.g;
}
vec4 pack2HalfToRGBA( const in vec2 v ) {
	vec4 r = vec4( v.x, fract( v.x * 255.0 ), v.y, fract( v.y * 255.0 ) );
	return vec4( r.x - r.y / 255.0, r.y, r.z - r.w / 255.0, r.w );
}
vec2 unpackRGBATo2Half( const in vec4 v ) {
	return vec2( v.x + ( v.y / 255.0 ), v.z + ( v.w / 255.0 ) );
}
float viewZToOrthographicDepth( const in float viewZ, const in float near, const in float far ) {
	return ( viewZ + near ) / ( near - far );
}
float orthographicDepthToViewZ( const in float depth, const in float near, const in float far ) {
	#ifdef USE_REVERSED_DEPTH_BUFFER
	
		return depth * ( far - near ) - far;
	#else
		return depth * ( near - far ) - near;
	#endif
}
float viewZToPerspectiveDepth( const in float viewZ, const in float near, const in float far ) {
	return ( ( near + viewZ ) * far ) / ( ( far - near ) * viewZ );
}
float perspectiveDepthToViewZ( const in float depth, const in float near, const in float far ) {
	
	#ifdef USE_REVERSED_DEPTH_BUFFER
		return ( near * far ) / ( ( near - far ) * depth - near );
	#else
		return ( near * far ) / ( ( far - near ) * depth - far );
	#endif
}`,Jh=`#ifdef PREMULTIPLIED_ALPHA
	gl_FragColor.rgb *= gl_FragColor.a;
#endif`,Zh=`vec4 mvPosition = vec4( transformed, 1.0 );
#ifdef USE_BATCHING
	mvPosition = batchingMatrix * mvPosition;
#endif
#ifdef USE_INSTANCING
	mvPosition = instanceMatrix * mvPosition;
#endif
mvPosition = modelViewMatrix * mvPosition;
gl_Position = projectionMatrix * mvPosition;`,$h=`#ifdef DITHERING
	gl_FragColor.rgb = dithering( gl_FragColor.rgb );
#endif`,Qh=`#ifdef DITHERING
	vec3 dithering( vec3 color ) {
		float grid_position = rand( gl_FragCoord.xy );
		vec3 dither_shift_RGB = vec3( 0.25 / 255.0, -0.25 / 255.0, 0.25 / 255.0 );
		dither_shift_RGB = mix( 2.0 * dither_shift_RGB, -2.0 * dither_shift_RGB, grid_position );
		return color + dither_shift_RGB;
	}
#endif`,ed=`float roughnessFactor = roughness;
#ifdef USE_ROUGHNESSMAP
	vec4 texelRoughness = texture2D( roughnessMap, vRoughnessMapUv );
	roughnessFactor *= texelRoughness.g;
#endif`,td=`#ifdef USE_ROUGHNESSMAP
	uniform sampler2D roughnessMap;
#endif`,id=`#if NUM_SPOT_LIGHT_COORDS > 0
	varying vec4 vSpotLightCoord[ NUM_SPOT_LIGHT_COORDS ];
#endif
#if NUM_SPOT_LIGHT_MAPS > 0
	uniform sampler2D spotLightMap[ NUM_SPOT_LIGHT_MAPS ];
#endif
#ifdef USE_SHADOWMAP
	#if NUM_DIR_LIGHT_SHADOWS > 0
		#if defined( SHADOWMAP_TYPE_PCF )
			uniform sampler2DShadow directionalShadowMap[ NUM_DIR_LIGHT_SHADOWS ];
		#else
			uniform sampler2D directionalShadowMap[ NUM_DIR_LIGHT_SHADOWS ];
		#endif
		varying vec4 vDirectionalShadowCoord[ NUM_DIR_LIGHT_SHADOWS ];
		struct DirectionalLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
		};
		uniform DirectionalLightShadow directionalLightShadows[ NUM_DIR_LIGHT_SHADOWS ];
	#endif
	#if NUM_SPOT_LIGHT_SHADOWS > 0
		#if defined( SHADOWMAP_TYPE_PCF )
			uniform sampler2DShadow spotShadowMap[ NUM_SPOT_LIGHT_SHADOWS ];
		#else
			uniform sampler2D spotShadowMap[ NUM_SPOT_LIGHT_SHADOWS ];
		#endif
		struct SpotLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
		};
		uniform SpotLightShadow spotLightShadows[ NUM_SPOT_LIGHT_SHADOWS ];
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0
		#if defined( SHADOWMAP_TYPE_PCF )
			uniform samplerCubeShadow pointShadowMap[ NUM_POINT_LIGHT_SHADOWS ];
		#elif defined( SHADOWMAP_TYPE_BASIC )
			uniform samplerCube pointShadowMap[ NUM_POINT_LIGHT_SHADOWS ];
		#endif
		varying vec4 vPointShadowCoord[ NUM_POINT_LIGHT_SHADOWS ];
		struct PointLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
			float shadowCameraNear;
			float shadowCameraFar;
		};
		uniform PointLightShadow pointLightShadows[ NUM_POINT_LIGHT_SHADOWS ];
	#endif
	#if defined( SHADOWMAP_TYPE_PCF )
		float interleavedGradientNoise( vec2 position ) {
			return fract( 52.9829189 * fract( dot( position, vec2( 0.06711056, 0.00583715 ) ) ) );
		}
		vec2 vogelDiskSample( int sampleIndex, int samplesCount, float phi ) {
			const float goldenAngle = 2.399963229728653;
			float r = sqrt( ( float( sampleIndex ) + 0.5 ) / float( samplesCount ) );
			float theta = float( sampleIndex ) * goldenAngle + phi;
			return vec2( cos( theta ), sin( theta ) ) * r;
		}
	#endif
	#if defined( SHADOWMAP_TYPE_PCF )
		float getShadow( sampler2DShadow shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord ) {
			float shadow = 1.0;
			shadowCoord.xyz /= shadowCoord.w;
			shadowCoord.z += shadowBias;
			bool inFrustum = shadowCoord.x >= 0.0 && shadowCoord.x <= 1.0 && shadowCoord.y >= 0.0 && shadowCoord.y <= 1.0;
			bool frustumTest = inFrustum && shadowCoord.z <= 1.0;
			if ( frustumTest ) {
				vec2 texelSize = vec2( 1.0 ) / shadowMapSize;
				float radius = shadowRadius * texelSize.x;
				float phi = interleavedGradientNoise( gl_FragCoord.xy ) * PI2;
				shadow = (
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 0, 5, phi ) * radius, shadowCoord.z ) ) +
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 1, 5, phi ) * radius, shadowCoord.z ) ) +
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 2, 5, phi ) * radius, shadowCoord.z ) ) +
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 3, 5, phi ) * radius, shadowCoord.z ) ) +
					texture( shadowMap, vec3( shadowCoord.xy + vogelDiskSample( 4, 5, phi ) * radius, shadowCoord.z ) )
				) * 0.2;
			}
			return mix( 1.0, shadow, shadowIntensity );
		}
	#elif defined( SHADOWMAP_TYPE_VSM )
		float getShadow( sampler2D shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord ) {
			float shadow = 1.0;
			shadowCoord.xyz /= shadowCoord.w;
			#ifdef USE_REVERSED_DEPTH_BUFFER
				shadowCoord.z -= shadowBias;
			#else
				shadowCoord.z += shadowBias;
			#endif
			bool inFrustum = shadowCoord.x >= 0.0 && shadowCoord.x <= 1.0 && shadowCoord.y >= 0.0 && shadowCoord.y <= 1.0;
			bool frustumTest = inFrustum && shadowCoord.z <= 1.0;
			if ( frustumTest ) {
				vec2 distribution = texture2D( shadowMap, shadowCoord.xy ).rg;
				float mean = distribution.x;
				float variance = distribution.y * distribution.y;
				#ifdef USE_REVERSED_DEPTH_BUFFER
					float hard_shadow = step( mean, shadowCoord.z );
				#else
					float hard_shadow = step( shadowCoord.z, mean );
				#endif
				
				if ( hard_shadow == 1.0 ) {
					shadow = 1.0;
				} else {
					variance = max( variance, 0.0000001 );
					float d = shadowCoord.z - mean;
					float p_max = variance / ( variance + d * d );
					p_max = clamp( ( p_max - 0.3 ) / 0.65, 0.0, 1.0 );
					shadow = max( hard_shadow, p_max );
				}
			}
			return mix( 1.0, shadow, shadowIntensity );
		}
	#else
		float getShadow( sampler2D shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord ) {
			float shadow = 1.0;
			shadowCoord.xyz /= shadowCoord.w;
			#ifdef USE_REVERSED_DEPTH_BUFFER
				shadowCoord.z -= shadowBias;
			#else
				shadowCoord.z += shadowBias;
			#endif
			bool inFrustum = shadowCoord.x >= 0.0 && shadowCoord.x <= 1.0 && shadowCoord.y >= 0.0 && shadowCoord.y <= 1.0;
			bool frustumTest = inFrustum && shadowCoord.z <= 1.0;
			if ( frustumTest ) {
				float depth = texture2D( shadowMap, shadowCoord.xy ).r;
				#ifdef USE_REVERSED_DEPTH_BUFFER
					shadow = step( depth, shadowCoord.z );
				#else
					shadow = step( shadowCoord.z, depth );
				#endif
			}
			return mix( 1.0, shadow, shadowIntensity );
		}
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0
	#if defined( SHADOWMAP_TYPE_PCF )
	float getPointShadow( samplerCubeShadow shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord, float shadowCameraNear, float shadowCameraFar ) {
		float shadow = 1.0;
		vec3 lightToPosition = shadowCoord.xyz;
		vec3 bd3D = normalize( lightToPosition );
		vec3 absVec = abs( lightToPosition );
		float viewSpaceZ = max( max( absVec.x, absVec.y ), absVec.z );
		if ( viewSpaceZ - shadowCameraFar <= 0.0 && viewSpaceZ - shadowCameraNear >= 0.0 ) {
			#ifdef USE_REVERSED_DEPTH_BUFFER
				float dp = ( shadowCameraNear * ( shadowCameraFar - viewSpaceZ ) ) / ( viewSpaceZ * ( shadowCameraFar - shadowCameraNear ) );
				dp -= shadowBias;
			#else
				float dp = ( shadowCameraFar * ( viewSpaceZ - shadowCameraNear ) ) / ( viewSpaceZ * ( shadowCameraFar - shadowCameraNear ) );
				dp += shadowBias;
			#endif
			float texelSize = shadowRadius / shadowMapSize.x;
			vec3 absDir = abs( bd3D );
			vec3 tangent = absDir.x > absDir.z ? vec3( 0.0, 1.0, 0.0 ) : vec3( 1.0, 0.0, 0.0 );
			tangent = normalize( cross( bd3D, tangent ) );
			vec3 bitangent = cross( bd3D, tangent );
			float phi = interleavedGradientNoise( gl_FragCoord.xy ) * PI2;
			vec2 sample0 = vogelDiskSample( 0, 5, phi );
			vec2 sample1 = vogelDiskSample( 1, 5, phi );
			vec2 sample2 = vogelDiskSample( 2, 5, phi );
			vec2 sample3 = vogelDiskSample( 3, 5, phi );
			vec2 sample4 = vogelDiskSample( 4, 5, phi );
			shadow = (
				texture( shadowMap, vec4( bd3D + ( tangent * sample0.x + bitangent * sample0.y ) * texelSize, dp ) ) +
				texture( shadowMap, vec4( bd3D + ( tangent * sample1.x + bitangent * sample1.y ) * texelSize, dp ) ) +
				texture( shadowMap, vec4( bd3D + ( tangent * sample2.x + bitangent * sample2.y ) * texelSize, dp ) ) +
				texture( shadowMap, vec4( bd3D + ( tangent * sample3.x + bitangent * sample3.y ) * texelSize, dp ) ) +
				texture( shadowMap, vec4( bd3D + ( tangent * sample4.x + bitangent * sample4.y ) * texelSize, dp ) )
			) * 0.2;
		}
		return mix( 1.0, shadow, shadowIntensity );
	}
	#elif defined( SHADOWMAP_TYPE_BASIC )
	float getPointShadow( samplerCube shadowMap, vec2 shadowMapSize, float shadowIntensity, float shadowBias, float shadowRadius, vec4 shadowCoord, float shadowCameraNear, float shadowCameraFar ) {
		float shadow = 1.0;
		vec3 lightToPosition = shadowCoord.xyz;
		vec3 absVec = abs( lightToPosition );
		float viewSpaceZ = max( max( absVec.x, absVec.y ), absVec.z );
		if ( viewSpaceZ - shadowCameraFar <= 0.0 && viewSpaceZ - shadowCameraNear >= 0.0 ) {
			float dp = ( shadowCameraFar * ( viewSpaceZ - shadowCameraNear ) ) / ( viewSpaceZ * ( shadowCameraFar - shadowCameraNear ) );
			dp += shadowBias;
			vec3 bd3D = normalize( lightToPosition );
			float depth = textureCube( shadowMap, bd3D ).r;
			#ifdef USE_REVERSED_DEPTH_BUFFER
				depth = 1.0 - depth;
			#endif
			shadow = step( dp, depth );
		}
		return mix( 1.0, shadow, shadowIntensity );
	}
	#endif
	#endif
#endif`,rd=`#if NUM_SPOT_LIGHT_COORDS > 0
	uniform mat4 spotLightMatrix[ NUM_SPOT_LIGHT_COORDS ];
	varying vec4 vSpotLightCoord[ NUM_SPOT_LIGHT_COORDS ];
#endif
#ifdef USE_SHADOWMAP
	#if NUM_DIR_LIGHT_SHADOWS > 0
		uniform mat4 directionalShadowMatrix[ NUM_DIR_LIGHT_SHADOWS ];
		varying vec4 vDirectionalShadowCoord[ NUM_DIR_LIGHT_SHADOWS ];
		struct DirectionalLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
		};
		uniform DirectionalLightShadow directionalLightShadows[ NUM_DIR_LIGHT_SHADOWS ];
	#endif
	#if NUM_SPOT_LIGHT_SHADOWS > 0
		struct SpotLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
		};
		uniform SpotLightShadow spotLightShadows[ NUM_SPOT_LIGHT_SHADOWS ];
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0
		uniform mat4 pointShadowMatrix[ NUM_POINT_LIGHT_SHADOWS ];
		varying vec4 vPointShadowCoord[ NUM_POINT_LIGHT_SHADOWS ];
		struct PointLightShadow {
			float shadowIntensity;
			float shadowBias;
			float shadowNormalBias;
			float shadowRadius;
			vec2 shadowMapSize;
			float shadowCameraNear;
			float shadowCameraFar;
		};
		uniform PointLightShadow pointLightShadows[ NUM_POINT_LIGHT_SHADOWS ];
	#endif
#endif`,nd=`#if ( defined( USE_SHADOWMAP ) && ( NUM_DIR_LIGHT_SHADOWS > 0 || NUM_POINT_LIGHT_SHADOWS > 0 ) ) || ( NUM_SPOT_LIGHT_COORDS > 0 )
	#ifdef HAS_NORMAL
		vec3 shadowWorldNormal = inverseTransformDirection( transformedNormal, viewMatrix );
	#else
		vec3 shadowWorldNormal = vec3( 0.0 );
	#endif
	vec4 shadowWorldPosition;
#endif
#if defined( USE_SHADOWMAP )
	#if NUM_DIR_LIGHT_SHADOWS > 0
		#pragma unroll_loop_start
		for ( int i = 0; i < NUM_DIR_LIGHT_SHADOWS; i ++ ) {
			shadowWorldPosition = worldPosition + vec4( shadowWorldNormal * directionalLightShadows[ i ].shadowNormalBias, 0 );
			vDirectionalShadowCoord[ i ] = directionalShadowMatrix[ i ] * shadowWorldPosition;
		}
		#pragma unroll_loop_end
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0
		#pragma unroll_loop_start
		for ( int i = 0; i < NUM_POINT_LIGHT_SHADOWS; i ++ ) {
			shadowWorldPosition = worldPosition + vec4( shadowWorldNormal * pointLightShadows[ i ].shadowNormalBias, 0 );
			vPointShadowCoord[ i ] = pointShadowMatrix[ i ] * shadowWorldPosition;
		}
		#pragma unroll_loop_end
	#endif
#endif
#if NUM_SPOT_LIGHT_COORDS > 0
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_SPOT_LIGHT_COORDS; i ++ ) {
		shadowWorldPosition = worldPosition;
		#if ( defined( USE_SHADOWMAP ) && UNROLLED_LOOP_INDEX < NUM_SPOT_LIGHT_SHADOWS )
			shadowWorldPosition.xyz += shadowWorldNormal * spotLightShadows[ i ].shadowNormalBias;
		#endif
		vSpotLightCoord[ i ] = spotLightMatrix[ i ] * shadowWorldPosition;
	}
	#pragma unroll_loop_end
#endif`,ad=`float getShadowMask() {
	float shadow = 1.0;
	#ifdef USE_SHADOWMAP
	#if NUM_DIR_LIGHT_SHADOWS > 0
	DirectionalLightShadow directionalLight;
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_DIR_LIGHT_SHADOWS; i ++ ) {
		directionalLight = directionalLightShadows[ i ];
		shadow *= receiveShadow ? getShadow( directionalShadowMap[ i ], directionalLight.shadowMapSize, directionalLight.shadowIntensity, directionalLight.shadowBias, directionalLight.shadowRadius, vDirectionalShadowCoord[ i ] ) : 1.0;
	}
	#pragma unroll_loop_end
	#endif
	#if NUM_SPOT_LIGHT_SHADOWS > 0
	SpotLightShadow spotLight;
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_SPOT_LIGHT_SHADOWS; i ++ ) {
		spotLight = spotLightShadows[ i ];
		shadow *= receiveShadow ? getShadow( spotShadowMap[ i ], spotLight.shadowMapSize, spotLight.shadowIntensity, spotLight.shadowBias, spotLight.shadowRadius, vSpotLightCoord[ i ] ) : 1.0;
	}
	#pragma unroll_loop_end
	#endif
	#if NUM_POINT_LIGHT_SHADOWS > 0 && ( defined( SHADOWMAP_TYPE_PCF ) || defined( SHADOWMAP_TYPE_BASIC ) )
	PointLightShadow pointLight;
	#pragma unroll_loop_start
	for ( int i = 0; i < NUM_POINT_LIGHT_SHADOWS; i ++ ) {
		pointLight = pointLightShadows[ i ];
		shadow *= receiveShadow ? getPointShadow( pointShadowMap[ i ], pointLight.shadowMapSize, pointLight.shadowIntensity, pointLight.shadowBias, pointLight.shadowRadius, vPointShadowCoord[ i ], pointLight.shadowCameraNear, pointLight.shadowCameraFar ) : 1.0;
	}
	#pragma unroll_loop_end
	#endif
	#endif
	return shadow;
}`,sd=`#ifdef USE_SKINNING
	mat4 boneMatX = getBoneMatrix( skinIndex.x );
	mat4 boneMatY = getBoneMatrix( skinIndex.y );
	mat4 boneMatZ = getBoneMatrix( skinIndex.z );
	mat4 boneMatW = getBoneMatrix( skinIndex.w );
#endif`,od=`#ifdef USE_SKINNING
	uniform mat4 bindMatrix;
	uniform mat4 bindMatrixInverse;
	uniform highp sampler2D boneTexture;
	mat4 getBoneMatrix( const in float i ) {
		int size = textureSize( boneTexture, 0 ).x;
		int j = int( i ) * 4;
		int x = j % size;
		int y = j / size;
		vec4 v1 = texelFetch( boneTexture, ivec2( x, y ), 0 );
		vec4 v2 = texelFetch( boneTexture, ivec2( x + 1, y ), 0 );
		vec4 v3 = texelFetch( boneTexture, ivec2( x + 2, y ), 0 );
		vec4 v4 = texelFetch( boneTexture, ivec2( x + 3, y ), 0 );
		return mat4( v1, v2, v3, v4 );
	}
#endif`,ld=`#ifdef USE_SKINNING
	vec4 skinVertex = bindMatrix * vec4( transformed, 1.0 );
	vec4 skinned = vec4( 0.0 );
	skinned += boneMatX * skinVertex * skinWeight.x;
	skinned += boneMatY * skinVertex * skinWeight.y;
	skinned += boneMatZ * skinVertex * skinWeight.z;
	skinned += boneMatW * skinVertex * skinWeight.w;
	transformed = ( bindMatrixInverse * skinned ).xyz;
#endif`,cd=`#ifdef USE_SKINNING
	mat4 skinMatrix = mat4( 0.0 );
	skinMatrix += skinWeight.x * boneMatX;
	skinMatrix += skinWeight.y * boneMatY;
	skinMatrix += skinWeight.z * boneMatZ;
	skinMatrix += skinWeight.w * boneMatW;
	skinMatrix = bindMatrixInverse * skinMatrix * bindMatrix;
	objectNormal = vec4( skinMatrix * vec4( objectNormal, 0.0 ) ).xyz;
	#ifdef USE_TANGENT
		objectTangent = vec4( skinMatrix * vec4( objectTangent, 0.0 ) ).xyz;
	#endif
#endif`,ud=`float specularStrength;
#ifdef USE_SPECULARMAP
	vec4 texelSpecular = texture2D( specularMap, vSpecularMapUv );
	specularStrength = texelSpecular.r;
#else
	specularStrength = 1.0;
#endif`,hd=`#ifdef USE_SPECULARMAP
	uniform sampler2D specularMap;
#endif`,dd=`#if defined( TONE_MAPPING )
	gl_FragColor.rgb = toneMapping( gl_FragColor.rgb );
#endif`,pd=`#ifndef saturate
#define saturate( a ) clamp( a, 0.0, 1.0 )
#endif
uniform float toneMappingExposure;
vec3 LinearToneMapping( vec3 color ) {
	return saturate( toneMappingExposure * color );
}
vec3 ReinhardToneMapping( vec3 color ) {
	color *= toneMappingExposure;
	return saturate( color / ( vec3( 1.0 ) + color ) );
}
vec3 CineonToneMapping( vec3 color ) {
	color *= toneMappingExposure;
	color = max( vec3( 0.0 ), color - 0.004 );
	return pow( ( color * ( 6.2 * color + 0.5 ) ) / ( color * ( 6.2 * color + 1.7 ) + 0.06 ), vec3( 2.2 ) );
}
vec3 RRTAndODTFit( vec3 v ) {
	vec3 a = v * ( v + 0.0245786 ) - 0.000090537;
	vec3 b = v * ( 0.983729 * v + 0.4329510 ) + 0.238081;
	return a / b;
}
vec3 ACESFilmicToneMapping( vec3 color ) {
	const mat3 ACESInputMat = mat3(
		vec3( 0.59719, 0.07600, 0.02840 ),		vec3( 0.35458, 0.90834, 0.13383 ),
		vec3( 0.04823, 0.01566, 0.83777 )
	);
	const mat3 ACESOutputMat = mat3(
		vec3(  1.60475, -0.10208, -0.00327 ),		vec3( -0.53108,  1.10813, -0.07276 ),
		vec3( -0.07367, -0.00605,  1.07602 )
	);
	color *= toneMappingExposure / 0.6;
	color = ACESInputMat * color;
	color = RRTAndODTFit( color );
	color = ACESOutputMat * color;
	return saturate( color );
}
const mat3 LINEAR_REC2020_TO_LINEAR_SRGB = mat3(
	vec3( 1.6605, - 0.1246, - 0.0182 ),
	vec3( - 0.5876, 1.1329, - 0.1006 ),
	vec3( - 0.0728, - 0.0083, 1.1187 )
);
const mat3 LINEAR_SRGB_TO_LINEAR_REC2020 = mat3(
	vec3( 0.6274, 0.0691, 0.0164 ),
	vec3( 0.3293, 0.9195, 0.0880 ),
	vec3( 0.0433, 0.0113, 0.8956 )
);
vec3 agxDefaultContrastApprox( vec3 x ) {
	vec3 x2 = x * x;
	vec3 x4 = x2 * x2;
	return + 15.5 * x4 * x2
		- 40.14 * x4 * x
		+ 31.96 * x4
		- 6.868 * x2 * x
		+ 0.4298 * x2
		+ 0.1191 * x
		- 0.00232;
}
vec3 AgXToneMapping( vec3 color ) {
	const mat3 AgXInsetMatrix = mat3(
		vec3( 0.856627153315983, 0.137318972929847, 0.11189821299995 ),
		vec3( 0.0951212405381588, 0.761241990602591, 0.0767994186031903 ),
		vec3( 0.0482516061458583, 0.101439036467562, 0.811302368396859 )
	);
	const mat3 AgXOutsetMatrix = mat3(
		vec3( 1.1271005818144368, - 0.1413297634984383, - 0.14132976349843826 ),
		vec3( - 0.11060664309660323, 1.157823702216272, - 0.11060664309660294 ),
		vec3( - 0.016493938717834573, - 0.016493938717834257, 1.2519364065950405 )
	);
	const float AgxMinEv = - 12.47393;	const float AgxMaxEv = 4.026069;
	color *= toneMappingExposure;
	color = LINEAR_SRGB_TO_LINEAR_REC2020 * color;
	color = AgXInsetMatrix * color;
	color = max( color, 1e-10 );	color = log2( color );
	color = ( color - AgxMinEv ) / ( AgxMaxEv - AgxMinEv );
	color = clamp( color, 0.0, 1.0 );
	color = agxDefaultContrastApprox( color );
	color = AgXOutsetMatrix * color;
	color = pow( max( vec3( 0.0 ), color ), vec3( 2.2 ) );
	color = LINEAR_REC2020_TO_LINEAR_SRGB * color;
	color = clamp( color, 0.0, 1.0 );
	return color;
}
vec3 NeutralToneMapping( vec3 color ) {
	const float StartCompression = 0.8 - 0.04;
	const float Desaturation = 0.15;
	color *= toneMappingExposure;
	float x = min( color.r, min( color.g, color.b ) );
	float offset = x < 0.08 ? x - 6.25 * x * x : 0.04;
	color -= offset;
	float peak = max( color.r, max( color.g, color.b ) );
	if ( peak < StartCompression ) return color;
	float d = 1. - StartCompression;
	float newPeak = 1. - d * d / ( peak + d - StartCompression );
	color *= newPeak / peak;
	float g = 1. - 1. / ( Desaturation * ( peak - newPeak ) + 1. );
	return mix( color, vec3( newPeak ), g );
}
vec3 CustomToneMapping( vec3 color ) { return color; }`,fd=`#ifdef USE_TRANSMISSION
	material.transmission = transmission;
	material.transmissionAlpha = 1.0;
	material.thickness = thickness;
	material.attenuationDistance = attenuationDistance;
	material.attenuationColor = attenuationColor;
	#ifdef USE_TRANSMISSIONMAP
		material.transmission *= texture2D( transmissionMap, vTransmissionMapUv ).r;
	#endif
	#ifdef USE_THICKNESSMAP
		material.thickness *= texture2D( thicknessMap, vThicknessMapUv ).g;
	#endif
	vec3 pos = vWorldPosition;
	vec3 v = normalize( cameraPosition - pos );
	vec3 n = inverseTransformDirection( normal, viewMatrix );
	vec4 transmitted = getIBLVolumeRefraction(
		n, v, material.roughness, material.diffuseContribution, material.specularColorBlended, material.specularF90,
		pos, modelMatrix, viewMatrix, projectionMatrix, material.dispersion, material.ior, material.thickness,
		material.attenuationColor, material.attenuationDistance );
	material.transmissionAlpha = mix( material.transmissionAlpha, transmitted.a, material.transmission );
	totalDiffuse = mix( totalDiffuse, transmitted.rgb, material.transmission );
#endif`,md=`#ifdef USE_TRANSMISSION
	uniform float transmission;
	uniform float thickness;
	uniform float attenuationDistance;
	uniform vec3 attenuationColor;
	#ifdef USE_TRANSMISSIONMAP
		uniform sampler2D transmissionMap;
	#endif
	#ifdef USE_THICKNESSMAP
		uniform sampler2D thicknessMap;
	#endif
	uniform vec2 transmissionSamplerSize;
	uniform sampler2D transmissionSamplerMap;
	uniform mat4 modelMatrix;
	uniform mat4 projectionMatrix;
	varying vec3 vWorldPosition;
	float w0( float a ) {
		return ( 1.0 / 6.0 ) * ( a * ( a * ( - a + 3.0 ) - 3.0 ) + 1.0 );
	}
	float w1( float a ) {
		return ( 1.0 / 6.0 ) * ( a *  a * ( 3.0 * a - 6.0 ) + 4.0 );
	}
	float w2( float a ){
		return ( 1.0 / 6.0 ) * ( a * ( a * ( - 3.0 * a + 3.0 ) + 3.0 ) + 1.0 );
	}
	float w3( float a ) {
		return ( 1.0 / 6.0 ) * ( a * a * a );
	}
	float g0( float a ) {
		return w0( a ) + w1( a );
	}
	float g1( float a ) {
		return w2( a ) + w3( a );
	}
	float h0( float a ) {
		return - 1.0 + w1( a ) / ( w0( a ) + w1( a ) );
	}
	float h1( float a ) {
		return 1.0 + w3( a ) / ( w2( a ) + w3( a ) );
	}
	vec4 bicubic( sampler2D tex, vec2 uv, vec4 texelSize, float lod ) {
		uv = uv * texelSize.zw + 0.5;
		vec2 iuv = floor( uv );
		vec2 fuv = fract( uv );
		float g0x = g0( fuv.x );
		float g1x = g1( fuv.x );
		float h0x = h0( fuv.x );
		float h1x = h1( fuv.x );
		float h0y = h0( fuv.y );
		float h1y = h1( fuv.y );
		vec2 p0 = ( vec2( iuv.x + h0x, iuv.y + h0y ) - 0.5 ) * texelSize.xy;
		vec2 p1 = ( vec2( iuv.x + h1x, iuv.y + h0y ) - 0.5 ) * texelSize.xy;
		vec2 p2 = ( vec2( iuv.x + h0x, iuv.y + h1y ) - 0.5 ) * texelSize.xy;
		vec2 p3 = ( vec2( iuv.x + h1x, iuv.y + h1y ) - 0.5 ) * texelSize.xy;
		return g0( fuv.y ) * ( g0x * textureLod( tex, p0, lod ) + g1x * textureLod( tex, p1, lod ) ) +
			g1( fuv.y ) * ( g0x * textureLod( tex, p2, lod ) + g1x * textureLod( tex, p3, lod ) );
	}
	vec4 textureBicubic( sampler2D sampler, vec2 uv, float lod ) {
		vec2 fLodSize = vec2( textureSize( sampler, int( lod ) ) );
		vec2 cLodSize = vec2( textureSize( sampler, int( lod + 1.0 ) ) );
		vec2 fLodSizeInv = 1.0 / fLodSize;
		vec2 cLodSizeInv = 1.0 / cLodSize;
		vec4 fSample = bicubic( sampler, uv, vec4( fLodSizeInv, fLodSize ), floor( lod ) );
		vec4 cSample = bicubic( sampler, uv, vec4( cLodSizeInv, cLodSize ), ceil( lod ) );
		return mix( fSample, cSample, fract( lod ) );
	}
	vec3 getVolumeTransmissionRay( const in vec3 n, const in vec3 v, const in float thickness, const in float ior, const in mat4 modelMatrix ) {
		vec3 refractionVector = refract( - v, normalize( n ), 1.0 / ior );
		vec3 modelScale;
		modelScale.x = length( vec3( modelMatrix[ 0 ].xyz ) );
		modelScale.y = length( vec3( modelMatrix[ 1 ].xyz ) );
		modelScale.z = length( vec3( modelMatrix[ 2 ].xyz ) );
		return normalize( refractionVector ) * thickness * modelScale;
	}
	float applyIorToRoughness( const in float roughness, const in float ior ) {
		return roughness * clamp( ior * 2.0 - 2.0, 0.0, 1.0 );
	}
	vec4 getTransmissionSample( const in vec2 fragCoord, const in float roughness, const in float ior ) {
		float lod = log2( transmissionSamplerSize.x ) * applyIorToRoughness( roughness, ior );
		return textureBicubic( transmissionSamplerMap, fragCoord.xy, lod );
	}
	vec3 volumeAttenuation( const in float transmissionDistance, const in vec3 attenuationColor, const in float attenuationDistance ) {
		if ( isinf( attenuationDistance ) ) {
			return vec3( 1.0 );
		} else {
			vec3 attenuationCoefficient = -log( attenuationColor ) / attenuationDistance;
			vec3 transmittance = exp( - attenuationCoefficient * transmissionDistance );			return transmittance;
		}
	}
	vec4 getIBLVolumeRefraction( const in vec3 n, const in vec3 v, const in float roughness, const in vec3 diffuseColor,
		const in vec3 specularColor, const in float specularF90, const in vec3 position, const in mat4 modelMatrix,
		const in mat4 viewMatrix, const in mat4 projMatrix, const in float dispersion, const in float ior, const in float thickness,
		const in vec3 attenuationColor, const in float attenuationDistance ) {
		vec4 transmittedLight;
		vec3 transmittance;
		#ifdef USE_DISPERSION
			float halfSpread = ( ior - 1.0 ) * 0.025 * dispersion;
			vec3 iors = vec3( ior - halfSpread, ior, ior + halfSpread );
			for ( int i = 0; i < 3; i ++ ) {
				vec3 transmissionRay = getVolumeTransmissionRay( n, v, thickness, iors[ i ], modelMatrix );
				vec3 refractedRayExit = position + transmissionRay;
				vec4 ndcPos = projMatrix * viewMatrix * vec4( refractedRayExit, 1.0 );
				vec2 refractionCoords = ndcPos.xy / ndcPos.w;
				refractionCoords += 1.0;
				refractionCoords /= 2.0;
				vec4 transmissionSample = getTransmissionSample( refractionCoords, roughness, iors[ i ] );
				transmittedLight[ i ] = transmissionSample[ i ];
				transmittedLight.a += transmissionSample.a;
				transmittance[ i ] = diffuseColor[ i ] * volumeAttenuation( length( transmissionRay ), attenuationColor, attenuationDistance )[ i ];
			}
			transmittedLight.a /= 3.0;
		#else
			vec3 transmissionRay = getVolumeTransmissionRay( n, v, thickness, ior, modelMatrix );
			vec3 refractedRayExit = position + transmissionRay;
			vec4 ndcPos = projMatrix * viewMatrix * vec4( refractedRayExit, 1.0 );
			vec2 refractionCoords = ndcPos.xy / ndcPos.w;
			refractionCoords += 1.0;
			refractionCoords /= 2.0;
			transmittedLight = getTransmissionSample( refractionCoords, roughness, ior );
			transmittance = diffuseColor * volumeAttenuation( length( transmissionRay ), attenuationColor, attenuationDistance );
		#endif
		vec3 attenuatedColor = transmittance * transmittedLight.rgb;
		vec3 F = EnvironmentBRDF( n, v, specularColor, specularF90, roughness );
		float transmittanceFactor = ( transmittance.r + transmittance.g + transmittance.b ) / 3.0;
		return vec4( ( 1.0 - F ) * attenuatedColor, 1.0 - ( 1.0 - transmittedLight.a ) * transmittanceFactor );
	}
#endif`,gd=`#if defined( USE_UV ) || defined( USE_ANISOTROPY )
	varying vec2 vUv;
#endif
#ifdef USE_MAP
	varying vec2 vMapUv;
#endif
#ifdef USE_ALPHAMAP
	varying vec2 vAlphaMapUv;
#endif
#ifdef USE_LIGHTMAP
	varying vec2 vLightMapUv;
#endif
#ifdef USE_AOMAP
	varying vec2 vAoMapUv;
#endif
#ifdef USE_BUMPMAP
	varying vec2 vBumpMapUv;
#endif
#ifdef USE_NORMALMAP
	varying vec2 vNormalMapUv;
#endif
#ifdef USE_EMISSIVEMAP
	varying vec2 vEmissiveMapUv;
#endif
#ifdef USE_METALNESSMAP
	varying vec2 vMetalnessMapUv;
#endif
#ifdef USE_ROUGHNESSMAP
	varying vec2 vRoughnessMapUv;
#endif
#ifdef USE_ANISOTROPYMAP
	varying vec2 vAnisotropyMapUv;
#endif
#ifdef USE_CLEARCOATMAP
	varying vec2 vClearcoatMapUv;
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	varying vec2 vClearcoatNormalMapUv;
#endif
#ifdef USE_CLEARCOAT_ROUGHNESSMAP
	varying vec2 vClearcoatRoughnessMapUv;
#endif
#ifdef USE_IRIDESCENCEMAP
	varying vec2 vIridescenceMapUv;
#endif
#ifdef USE_IRIDESCENCE_THICKNESSMAP
	varying vec2 vIridescenceThicknessMapUv;
#endif
#ifdef USE_SHEEN_COLORMAP
	varying vec2 vSheenColorMapUv;
#endif
#ifdef USE_SHEEN_ROUGHNESSMAP
	varying vec2 vSheenRoughnessMapUv;
#endif
#ifdef USE_SPECULARMAP
	varying vec2 vSpecularMapUv;
#endif
#ifdef USE_SPECULAR_COLORMAP
	varying vec2 vSpecularColorMapUv;
#endif
#ifdef USE_SPECULAR_INTENSITYMAP
	varying vec2 vSpecularIntensityMapUv;
#endif
#ifdef USE_TRANSMISSIONMAP
	uniform mat3 transmissionMapTransform;
	varying vec2 vTransmissionMapUv;
#endif
#ifdef USE_THICKNESSMAP
	uniform mat3 thicknessMapTransform;
	varying vec2 vThicknessMapUv;
#endif`,_d=`#if defined( USE_UV ) || defined( USE_ANISOTROPY )
	varying vec2 vUv;
#endif
#ifdef USE_MAP
	uniform mat3 mapTransform;
	varying vec2 vMapUv;
#endif
#ifdef USE_ALPHAMAP
	uniform mat3 alphaMapTransform;
	varying vec2 vAlphaMapUv;
#endif
#ifdef USE_LIGHTMAP
	uniform mat3 lightMapTransform;
	varying vec2 vLightMapUv;
#endif
#ifdef USE_AOMAP
	uniform mat3 aoMapTransform;
	varying vec2 vAoMapUv;
#endif
#ifdef USE_BUMPMAP
	uniform mat3 bumpMapTransform;
	varying vec2 vBumpMapUv;
#endif
#ifdef USE_NORMALMAP
	uniform mat3 normalMapTransform;
	varying vec2 vNormalMapUv;
#endif
#ifdef USE_DISPLACEMENTMAP
	uniform mat3 displacementMapTransform;
	varying vec2 vDisplacementMapUv;
#endif
#ifdef USE_EMISSIVEMAP
	uniform mat3 emissiveMapTransform;
	varying vec2 vEmissiveMapUv;
#endif
#ifdef USE_METALNESSMAP
	uniform mat3 metalnessMapTransform;
	varying vec2 vMetalnessMapUv;
#endif
#ifdef USE_ROUGHNESSMAP
	uniform mat3 roughnessMapTransform;
	varying vec2 vRoughnessMapUv;
#endif
#ifdef USE_ANISOTROPYMAP
	uniform mat3 anisotropyMapTransform;
	varying vec2 vAnisotropyMapUv;
#endif
#ifdef USE_CLEARCOATMAP
	uniform mat3 clearcoatMapTransform;
	varying vec2 vClearcoatMapUv;
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	uniform mat3 clearcoatNormalMapTransform;
	varying vec2 vClearcoatNormalMapUv;
#endif
#ifdef USE_CLEARCOAT_ROUGHNESSMAP
	uniform mat3 clearcoatRoughnessMapTransform;
	varying vec2 vClearcoatRoughnessMapUv;
#endif
#ifdef USE_SHEEN_COLORMAP
	uniform mat3 sheenColorMapTransform;
	varying vec2 vSheenColorMapUv;
#endif
#ifdef USE_SHEEN_ROUGHNESSMAP
	uniform mat3 sheenRoughnessMapTransform;
	varying vec2 vSheenRoughnessMapUv;
#endif
#ifdef USE_IRIDESCENCEMAP
	uniform mat3 iridescenceMapTransform;
	varying vec2 vIridescenceMapUv;
#endif
#ifdef USE_IRIDESCENCE_THICKNESSMAP
	uniform mat3 iridescenceThicknessMapTransform;
	varying vec2 vIridescenceThicknessMapUv;
#endif
#ifdef USE_SPECULARMAP
	uniform mat3 specularMapTransform;
	varying vec2 vSpecularMapUv;
#endif
#ifdef USE_SPECULAR_COLORMAP
	uniform mat3 specularColorMapTransform;
	varying vec2 vSpecularColorMapUv;
#endif
#ifdef USE_SPECULAR_INTENSITYMAP
	uniform mat3 specularIntensityMapTransform;
	varying vec2 vSpecularIntensityMapUv;
#endif
#ifdef USE_TRANSMISSIONMAP
	uniform mat3 transmissionMapTransform;
	varying vec2 vTransmissionMapUv;
#endif
#ifdef USE_THICKNESSMAP
	uniform mat3 thicknessMapTransform;
	varying vec2 vThicknessMapUv;
#endif`,vd=`#if defined( USE_UV ) || defined( USE_ANISOTROPY )
	vUv = vec3( uv, 1 ).xy;
#endif
#ifdef USE_MAP
	vMapUv = ( mapTransform * vec3( MAP_UV, 1 ) ).xy;
#endif
#ifdef USE_ALPHAMAP
	vAlphaMapUv = ( alphaMapTransform * vec3( ALPHAMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_LIGHTMAP
	vLightMapUv = ( lightMapTransform * vec3( LIGHTMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_AOMAP
	vAoMapUv = ( aoMapTransform * vec3( AOMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_BUMPMAP
	vBumpMapUv = ( bumpMapTransform * vec3( BUMPMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_NORMALMAP
	vNormalMapUv = ( normalMapTransform * vec3( NORMALMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_DISPLACEMENTMAP
	vDisplacementMapUv = ( displacementMapTransform * vec3( DISPLACEMENTMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_EMISSIVEMAP
	vEmissiveMapUv = ( emissiveMapTransform * vec3( EMISSIVEMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_METALNESSMAP
	vMetalnessMapUv = ( metalnessMapTransform * vec3( METALNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_ROUGHNESSMAP
	vRoughnessMapUv = ( roughnessMapTransform * vec3( ROUGHNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_ANISOTROPYMAP
	vAnisotropyMapUv = ( anisotropyMapTransform * vec3( ANISOTROPYMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_CLEARCOATMAP
	vClearcoatMapUv = ( clearcoatMapTransform * vec3( CLEARCOATMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_CLEARCOAT_NORMALMAP
	vClearcoatNormalMapUv = ( clearcoatNormalMapTransform * vec3( CLEARCOAT_NORMALMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_CLEARCOAT_ROUGHNESSMAP
	vClearcoatRoughnessMapUv = ( clearcoatRoughnessMapTransform * vec3( CLEARCOAT_ROUGHNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_IRIDESCENCEMAP
	vIridescenceMapUv = ( iridescenceMapTransform * vec3( IRIDESCENCEMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_IRIDESCENCE_THICKNESSMAP
	vIridescenceThicknessMapUv = ( iridescenceThicknessMapTransform * vec3( IRIDESCENCE_THICKNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SHEEN_COLORMAP
	vSheenColorMapUv = ( sheenColorMapTransform * vec3( SHEEN_COLORMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SHEEN_ROUGHNESSMAP
	vSheenRoughnessMapUv = ( sheenRoughnessMapTransform * vec3( SHEEN_ROUGHNESSMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SPECULARMAP
	vSpecularMapUv = ( specularMapTransform * vec3( SPECULARMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SPECULAR_COLORMAP
	vSpecularColorMapUv = ( specularColorMapTransform * vec3( SPECULAR_COLORMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_SPECULAR_INTENSITYMAP
	vSpecularIntensityMapUv = ( specularIntensityMapTransform * vec3( SPECULAR_INTENSITYMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_TRANSMISSIONMAP
	vTransmissionMapUv = ( transmissionMapTransform * vec3( TRANSMISSIONMAP_UV, 1 ) ).xy;
#endif
#ifdef USE_THICKNESSMAP
	vThicknessMapUv = ( thicknessMapTransform * vec3( THICKNESSMAP_UV, 1 ) ).xy;
#endif`,xd=`#if defined( USE_ENVMAP ) || defined( DISTANCE ) || defined ( USE_SHADOWMAP ) || defined ( USE_TRANSMISSION ) || NUM_SPOT_LIGHT_COORDS > 0
	vec4 worldPosition = vec4( transformed, 1.0 );
	#ifdef USE_BATCHING
		worldPosition = batchingMatrix * worldPosition;
	#endif
	#ifdef USE_INSTANCING
		worldPosition = instanceMatrix * worldPosition;
	#endif
	worldPosition = modelMatrix * worldPosition;
#endif`;const Md=`varying vec2 vUv;
uniform mat3 uvTransform;
void main() {
	vUv = ( uvTransform * vec3( uv, 1 ) ).xy;
	gl_Position = vec4( position.xy, 1.0, 1.0 );
}`,Sd=`uniform sampler2D t2D;
uniform float backgroundIntensity;
varying vec2 vUv;
void main() {
	vec4 texColor = texture2D( t2D, vUv );
	#ifdef DECODE_VIDEO_TEXTURE
		texColor = vec4( mix( pow( texColor.rgb * 0.9478672986 + vec3( 0.0521327014 ), vec3( 2.4 ) ), texColor.rgb * 0.0773993808, vec3( lessThanEqual( texColor.rgb, vec3( 0.04045 ) ) ) ), texColor.w );
	#endif
	texColor.rgb *= backgroundIntensity;
	gl_FragColor = texColor;
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
}`,Ed=`varying vec3 vWorldDirection;
#include <common>
void main() {
	vWorldDirection = transformDirection( position, modelMatrix );
	#include <begin_vertex>
	#include <project_vertex>
	gl_Position.z = gl_Position.w;
}`,Td=`#ifdef ENVMAP_TYPE_CUBE
	uniform samplerCube envMap;
#elif defined( ENVMAP_TYPE_CUBE_UV )
	uniform sampler2D envMap;
#endif
uniform float backgroundBlurriness;
uniform float backgroundIntensity;
uniform mat3 backgroundRotation;
varying vec3 vWorldDirection;
#include <cube_uv_reflection_fragment>
void main() {
	#ifdef ENVMAP_TYPE_CUBE
		vec4 texColor = textureCube( envMap, backgroundRotation * vWorldDirection );
	#elif defined( ENVMAP_TYPE_CUBE_UV )
		vec4 texColor = textureCubeUV( envMap, backgroundRotation * vWorldDirection, backgroundBlurriness );
	#else
		vec4 texColor = vec4( 0.0, 0.0, 0.0, 1.0 );
	#endif
	texColor.rgb *= backgroundIntensity;
	gl_FragColor = texColor;
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
}`,yd=`varying vec3 vWorldDirection;
#include <common>
void main() {
	vWorldDirection = transformDirection( position, modelMatrix );
	#include <begin_vertex>
	#include <project_vertex>
	gl_Position.z = gl_Position.w;
}`,bd=`uniform samplerCube tCube;
uniform float tFlip;
uniform float opacity;
varying vec3 vWorldDirection;
void main() {
	vec4 texColor = textureCube( tCube, vec3( tFlip * vWorldDirection.x, vWorldDirection.yz ) );
	gl_FragColor = texColor;
	gl_FragColor.a *= opacity;
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
}`,Ad=`#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
varying vec2 vHighPrecisionZW;
void main() {
	#include <uv_vertex>
	#include <batching_vertex>
	#include <skinbase_vertex>
	#include <morphinstance_vertex>
	#ifdef USE_DISPLACEMENTMAP
		#include <beginnormal_vertex>
		#include <morphnormal_vertex>
		#include <skinnormal_vertex>
	#endif
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vHighPrecisionZW = gl_Position.zw;
}`,wd=`#if DEPTH_PACKING == 3200
	uniform float opacity;
#endif
#include <common>
#include <packing>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
varying vec2 vHighPrecisionZW;
void main() {
	vec4 diffuseColor = vec4( 1.0 );
	#include <clipping_planes_fragment>
	#if DEPTH_PACKING == 3200
		diffuseColor.a = opacity;
	#endif
	#include <map_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <logdepthbuf_fragment>
	#ifdef USE_REVERSED_DEPTH_BUFFER
		float fragCoordZ = vHighPrecisionZW[ 0 ] / vHighPrecisionZW[ 1 ];
	#else
		float fragCoordZ = 0.5 * vHighPrecisionZW[ 0 ] / vHighPrecisionZW[ 1 ] + 0.5;
	#endif
	#if DEPTH_PACKING == 3200
		gl_FragColor = vec4( vec3( 1.0 - fragCoordZ ), opacity );
	#elif DEPTH_PACKING == 3201
		gl_FragColor = packDepthToRGBA( fragCoordZ );
	#elif DEPTH_PACKING == 3202
		gl_FragColor = vec4( packDepthToRGB( fragCoordZ ), 1.0 );
	#elif DEPTH_PACKING == 3203
		gl_FragColor = vec4( packDepthToRG( fragCoordZ ), 0.0, 1.0 );
	#endif
}`,Rd=`#define DISTANCE
varying vec3 vWorldPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <batching_vertex>
	#include <skinbase_vertex>
	#include <morphinstance_vertex>
	#ifdef USE_DISPLACEMENTMAP
		#include <beginnormal_vertex>
		#include <morphnormal_vertex>
		#include <skinnormal_vertex>
	#endif
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <worldpos_vertex>
	#include <clipping_planes_vertex>
	vWorldPosition = worldPosition.xyz;
}`,Cd=`#define DISTANCE
uniform vec3 referencePosition;
uniform float nearDistance;
uniform float farDistance;
varying vec3 vWorldPosition;
#include <common>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <clipping_planes_pars_fragment>
void main () {
	vec4 diffuseColor = vec4( 1.0 );
	#include <clipping_planes_fragment>
	#include <map_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	float dist = length( vWorldPosition - referencePosition );
	dist = ( dist - nearDistance ) / ( farDistance - nearDistance );
	dist = saturate( dist );
	gl_FragColor = vec4( dist, 0.0, 0.0, 1.0 );
}`,Pd=`varying vec3 vWorldDirection;
#include <common>
void main() {
	vWorldDirection = transformDirection( position, modelMatrix );
	#include <begin_vertex>
	#include <project_vertex>
}`,Ud=`uniform sampler2D tEquirect;
varying vec3 vWorldDirection;
#include <common>
void main() {
	vec3 direction = normalize( vWorldDirection );
	vec2 sampleUV = equirectUv( direction );
	gl_FragColor = texture2D( tEquirect, sampleUV );
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
}`,Dd=`uniform float scale;
attribute float lineDistance;
varying float vLineDistance;
#include <common>
#include <uv_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <morphtarget_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	vLineDistance = scale * lineDistance;
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <fog_vertex>
}`,Id=`uniform vec3 diffuse;
uniform float opacity;
uniform float dashSize;
uniform float totalSize;
varying float vLineDistance;
#include <common>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <fog_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	if ( mod( vLineDistance, totalSize ) > dashSize ) {
		discard;
	}
	vec3 outgoingLight = vec3( 0.0 );
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	outgoingLight = diffuseColor.rgb;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
}`,Ld=`#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <envmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#if defined ( USE_ENVMAP ) || defined ( USE_SKINNING )
		#include <beginnormal_vertex>
		#include <morphnormal_vertex>
		#include <skinbase_vertex>
		#include <skinnormal_vertex>
		#include <defaultnormal_vertex>
	#endif
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <worldpos_vertex>
	#include <envmap_vertex>
	#include <fog_vertex>
}`,Nd=`uniform vec3 diffuse;
uniform float opacity;
#ifndef FLAT_SHADED
	varying vec3 vNormal;
#endif
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <envmap_common_pars_fragment>
#include <envmap_pars_fragment>
#include <fog_pars_fragment>
#include <specularmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <specularmap_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	#ifdef USE_LIGHTMAP
		vec4 lightMapTexel = texture2D( lightMap, vLightMapUv );
		reflectedLight.indirectDiffuse += lightMapTexel.rgb * lightMapIntensity * RECIPROCAL_PI;
	#else
		reflectedLight.indirectDiffuse += vec3( 1.0 );
	#endif
	#include <aomap_fragment>
	reflectedLight.indirectDiffuse *= diffuseColor.rgb;
	vec3 outgoingLight = reflectedLight.indirectDiffuse;
	#include <envmap_fragment>
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,Fd=`#define LAMBERT
varying vec3 vViewPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <envmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <shadowmap_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vViewPosition = - mvPosition.xyz;
	#include <worldpos_vertex>
	#include <envmap_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
}`,Od=`#define LAMBERT
uniform vec3 diffuse;
uniform vec3 emissive;
uniform float opacity;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <emissivemap_pars_fragment>
#include <cube_uv_reflection_fragment>
#include <envmap_common_pars_fragment>
#include <envmap_pars_fragment>
#include <envmap_physical_pars_fragment>
#include <fog_pars_fragment>
#include <bsdfs>
#include <lights_pars_begin>
#include <normal_pars_fragment>
#include <lights_lambert_pars_fragment>
#include <shadowmap_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <specularmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	vec3 totalEmissiveRadiance = emissive;
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <specularmap_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	#include <emissivemap_fragment>
	#include <lights_lambert_fragment>
	#include <lights_fragment_begin>
	#include <lights_fragment_maps>
	#include <lights_fragment_end>
	#include <aomap_fragment>
	vec3 outgoingLight = reflectedLight.directDiffuse + reflectedLight.indirectDiffuse + totalEmissiveRadiance;
	#include <envmap_fragment>
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,Bd=`#define MATCAP
varying vec3 vViewPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <color_pars_vertex>
#include <displacementmap_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <fog_vertex>
	vViewPosition = - mvPosition.xyz;
}`,zd=`#define MATCAP
uniform vec3 diffuse;
uniform float opacity;
uniform sampler2D matcap;
varying vec3 vViewPosition;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <fog_pars_fragment>
#include <normal_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	vec3 viewDir = normalize( vViewPosition );
	vec3 x = normalize( vec3( viewDir.z, 0.0, - viewDir.x ) );
	vec3 y = cross( viewDir, x );
	vec2 uv = vec2( dot( x, normal ), dot( y, normal ) ) * 0.495 + 0.5;
	#ifdef USE_MATCAP
		vec4 matcapColor = texture2D( matcap, uv );
	#else
		vec4 matcapColor = vec4( vec3( mix( 0.2, 0.8, uv.y ) ), 1.0 );
	#endif
	vec3 outgoingLight = diffuseColor.rgb * matcapColor.rgb;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,Gd=`#define NORMAL
#if defined( FLAT_SHADED ) || defined( USE_BUMPMAP ) || defined( USE_NORMALMAP_TANGENTSPACE )
	varying vec3 vViewPosition;
#endif
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphinstance_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
#if defined( FLAT_SHADED ) || defined( USE_BUMPMAP ) || defined( USE_NORMALMAP_TANGENTSPACE )
	vViewPosition = - mvPosition.xyz;
#endif
}`,Hd=`#define NORMAL
uniform float opacity;
#if defined( FLAT_SHADED ) || defined( USE_BUMPMAP ) || defined( USE_NORMALMAP_TANGENTSPACE )
	varying vec3 vViewPosition;
#endif
#include <uv_pars_fragment>
#include <normal_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( 0.0, 0.0, 0.0, opacity );
	#include <clipping_planes_fragment>
	#include <logdepthbuf_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	gl_FragColor = vec4( normalize( normal ) * 0.5 + 0.5, diffuseColor.a );
	#ifdef OPAQUE
		gl_FragColor.a = 1.0;
	#endif
}`,Vd=`#define PHONG
varying vec3 vViewPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <envmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <shadowmap_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphinstance_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vViewPosition = - mvPosition.xyz;
	#include <worldpos_vertex>
	#include <envmap_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
}`,kd=`#define PHONG
uniform vec3 diffuse;
uniform vec3 emissive;
uniform vec3 specular;
uniform float shininess;
uniform float opacity;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <emissivemap_pars_fragment>
#include <cube_uv_reflection_fragment>
#include <envmap_common_pars_fragment>
#include <envmap_pars_fragment>
#include <envmap_physical_pars_fragment>
#include <fog_pars_fragment>
#include <bsdfs>
#include <lights_pars_begin>
#include <normal_pars_fragment>
#include <lights_phong_pars_fragment>
#include <shadowmap_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <specularmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	vec3 totalEmissiveRadiance = emissive;
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <specularmap_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	#include <emissivemap_fragment>
	#include <lights_phong_fragment>
	#include <lights_fragment_begin>
	#include <lights_fragment_maps>
	#include <lights_fragment_end>
	#include <aomap_fragment>
	vec3 outgoingLight = reflectedLight.directDiffuse + reflectedLight.indirectDiffuse + reflectedLight.directSpecular + reflectedLight.indirectSpecular + totalEmissiveRadiance;
	#include <envmap_fragment>
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,Wd=`#define STANDARD
varying vec3 vViewPosition;
#ifdef USE_TRANSMISSION
	varying vec3 vWorldPosition;
#endif
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <shadowmap_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vViewPosition = - mvPosition.xyz;
	#include <worldpos_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
#ifdef USE_TRANSMISSION
	vWorldPosition = worldPosition.xyz;
#endif
}`,Xd=`#define STANDARD
#ifdef PHYSICAL
	#define IOR
	#define USE_SPECULAR
#endif
uniform vec3 diffuse;
uniform vec3 emissive;
uniform float roughness;
uniform float metalness;
uniform float opacity;
#ifdef IOR
	uniform float ior;
#endif
#ifdef USE_SPECULAR
	uniform float specularIntensity;
	uniform vec3 specularColor;
	#ifdef USE_SPECULAR_COLORMAP
		uniform sampler2D specularColorMap;
	#endif
	#ifdef USE_SPECULAR_INTENSITYMAP
		uniform sampler2D specularIntensityMap;
	#endif
#endif
#ifdef USE_CLEARCOAT
	uniform float clearcoat;
	uniform float clearcoatRoughness;
#endif
#ifdef USE_DISPERSION
	uniform float dispersion;
#endif
#ifdef USE_IRIDESCENCE
	uniform float iridescence;
	uniform float iridescenceIOR;
	uniform float iridescenceThicknessMinimum;
	uniform float iridescenceThicknessMaximum;
#endif
#ifdef USE_SHEEN
	uniform vec3 sheenColor;
	uniform float sheenRoughness;
	#ifdef USE_SHEEN_COLORMAP
		uniform sampler2D sheenColorMap;
	#endif
	#ifdef USE_SHEEN_ROUGHNESSMAP
		uniform sampler2D sheenRoughnessMap;
	#endif
#endif
#ifdef USE_ANISOTROPY
	uniform vec2 anisotropyVector;
	#ifdef USE_ANISOTROPYMAP
		uniform sampler2D anisotropyMap;
	#endif
#endif
varying vec3 vViewPosition;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <emissivemap_pars_fragment>
#include <iridescence_fragment>
#include <cube_uv_reflection_fragment>
#include <envmap_common_pars_fragment>
#include <envmap_physical_pars_fragment>
#include <fog_pars_fragment>
#include <lights_pars_begin>
#include <normal_pars_fragment>
#include <lights_physical_pars_fragment>
#include <transmission_pars_fragment>
#include <shadowmap_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <clearcoat_pars_fragment>
#include <iridescence_pars_fragment>
#include <roughnessmap_pars_fragment>
#include <metalnessmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	vec3 totalEmissiveRadiance = emissive;
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <roughnessmap_fragment>
	#include <metalnessmap_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	#include <clearcoat_normal_fragment_begin>
	#include <clearcoat_normal_fragment_maps>
	#include <emissivemap_fragment>
	#include <lights_physical_fragment>
	#include <lights_fragment_begin>
	#include <lights_fragment_maps>
	#include <lights_fragment_end>
	#include <aomap_fragment>
	vec3 totalDiffuse = reflectedLight.directDiffuse + reflectedLight.indirectDiffuse;
	vec3 totalSpecular = reflectedLight.directSpecular + reflectedLight.indirectSpecular;
	#include <transmission_fragment>
	vec3 outgoingLight = totalDiffuse + totalSpecular + totalEmissiveRadiance;
	#ifdef USE_SHEEN
 
		outgoingLight = outgoingLight + sheenSpecularDirect + sheenSpecularIndirect;
 
 	#endif
	#ifdef USE_CLEARCOAT
		float dotNVcc = saturate( dot( geometryClearcoatNormal, geometryViewDir ) );
		vec3 Fcc = F_Schlick( material.clearcoatF0, material.clearcoatF90, dotNVcc );
		outgoingLight = outgoingLight * ( 1.0 - material.clearcoat * Fcc ) + ( clearcoatSpecularDirect + clearcoatSpecularIndirect ) * material.clearcoat;
	#endif
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,qd=`#define TOON
varying vec3 vViewPosition;
#include <common>
#include <batching_pars_vertex>
#include <uv_pars_vertex>
#include <displacementmap_pars_vertex>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <normal_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <shadowmap_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <normal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <displacementmap_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	vViewPosition = - mvPosition.xyz;
	#include <worldpos_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
}`,Yd=`#define TOON
uniform vec3 diffuse;
uniform vec3 emissive;
uniform float opacity;
#include <common>
#include <dithering_pars_fragment>
#include <color_pars_fragment>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <aomap_pars_fragment>
#include <lightmap_pars_fragment>
#include <emissivemap_pars_fragment>
#include <gradientmap_pars_fragment>
#include <fog_pars_fragment>
#include <bsdfs>
#include <lights_pars_begin>
#include <normal_pars_fragment>
#include <lights_toon_pars_fragment>
#include <shadowmap_pars_fragment>
#include <bumpmap_pars_fragment>
#include <normalmap_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	ReflectedLight reflectedLight = ReflectedLight( vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ), vec3( 0.0 ) );
	vec3 totalEmissiveRadiance = emissive;
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <color_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	#include <normal_fragment_begin>
	#include <normal_fragment_maps>
	#include <emissivemap_fragment>
	#include <lights_toon_fragment>
	#include <lights_fragment_begin>
	#include <lights_fragment_maps>
	#include <lights_fragment_end>
	#include <aomap_fragment>
	vec3 outgoingLight = reflectedLight.directDiffuse + reflectedLight.indirectDiffuse + totalEmissiveRadiance;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
	#include <dithering_fragment>
}`,jd=`uniform float size;
uniform float scale;
#include <common>
#include <color_pars_vertex>
#include <fog_pars_vertex>
#include <morphtarget_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
#ifdef USE_POINTS_UV
	varying vec2 vUv;
	uniform mat3 uvTransform;
#endif
void main() {
	#ifdef USE_POINTS_UV
		vUv = ( uvTransform * vec3( uv, 1 ) ).xy;
	#endif
	#include <color_vertex>
	#include <morphinstance_vertex>
	#include <morphcolor_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <project_vertex>
	gl_PointSize = size;
	#ifdef USE_SIZEATTENUATION
		bool isPerspective = isPerspectiveMatrix( projectionMatrix );
		if ( isPerspective ) gl_PointSize *= ( scale / - mvPosition.z );
	#endif
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <worldpos_vertex>
	#include <fog_vertex>
}`,Kd=`uniform vec3 diffuse;
uniform float opacity;
#include <common>
#include <color_pars_fragment>
#include <map_particle_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <fog_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	vec3 outgoingLight = vec3( 0.0 );
	#include <logdepthbuf_fragment>
	#include <map_particle_fragment>
	#include <color_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	outgoingLight = diffuseColor.rgb;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
}`,Jd=`#include <common>
#include <batching_pars_vertex>
#include <fog_pars_vertex>
#include <morphtarget_pars_vertex>
#include <skinning_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <shadowmap_pars_vertex>
void main() {
	#include <batching_vertex>
	#include <beginnormal_vertex>
	#include <morphinstance_vertex>
	#include <morphnormal_vertex>
	#include <skinbase_vertex>
	#include <skinnormal_vertex>
	#include <defaultnormal_vertex>
	#include <begin_vertex>
	#include <morphtarget_vertex>
	#include <skinning_vertex>
	#include <project_vertex>
	#include <logdepthbuf_vertex>
	#include <worldpos_vertex>
	#include <shadowmap_vertex>
	#include <fog_vertex>
}`,Zd=`uniform vec3 color;
uniform float opacity;
#include <common>
#include <fog_pars_fragment>
#include <bsdfs>
#include <lights_pars_begin>
#include <logdepthbuf_pars_fragment>
#include <shadowmap_pars_fragment>
#include <shadowmask_pars_fragment>
void main() {
	#include <logdepthbuf_fragment>
	gl_FragColor = vec4( color, opacity * ( 1.0 - getShadowMask() ) );
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
	#include <premultiplied_alpha_fragment>
}`,$d=`uniform float rotation;
uniform vec2 center;
#include <common>
#include <uv_pars_vertex>
#include <fog_pars_vertex>
#include <logdepthbuf_pars_vertex>
#include <clipping_planes_pars_vertex>
void main() {
	#include <uv_vertex>
	vec4 mvPosition = modelViewMatrix[ 3 ];
	vec2 scale = vec2( length( modelMatrix[ 0 ].xyz ), length( modelMatrix[ 1 ].xyz ) );
	#ifndef USE_SIZEATTENUATION
		bool isPerspective = isPerspectiveMatrix( projectionMatrix );
		if ( isPerspective ) scale *= - mvPosition.z;
	#endif
	vec2 alignedPosition = ( position.xy - ( center - vec2( 0.5 ) ) ) * scale;
	vec2 rotatedPosition;
	rotatedPosition.x = cos( rotation ) * alignedPosition.x - sin( rotation ) * alignedPosition.y;
	rotatedPosition.y = sin( rotation ) * alignedPosition.x + cos( rotation ) * alignedPosition.y;
	mvPosition.xy += rotatedPosition;
	gl_Position = projectionMatrix * mvPosition;
	#include <logdepthbuf_vertex>
	#include <clipping_planes_vertex>
	#include <fog_vertex>
}`,Qd=`uniform vec3 diffuse;
uniform float opacity;
#include <common>
#include <uv_pars_fragment>
#include <map_pars_fragment>
#include <alphamap_pars_fragment>
#include <alphatest_pars_fragment>
#include <alphahash_pars_fragment>
#include <fog_pars_fragment>
#include <logdepthbuf_pars_fragment>
#include <clipping_planes_pars_fragment>
void main() {
	vec4 diffuseColor = vec4( diffuse, opacity );
	#include <clipping_planes_fragment>
	vec3 outgoingLight = vec3( 0.0 );
	#include <logdepthbuf_fragment>
	#include <map_fragment>
	#include <alphamap_fragment>
	#include <alphatest_fragment>
	#include <alphahash_fragment>
	outgoingLight = diffuseColor.rgb;
	#include <opaque_fragment>
	#include <tonemapping_fragment>
	#include <colorspace_fragment>
	#include <fog_fragment>
}`,De={alphahash_fragment:Mu,alphahash_pars_fragment:Su,alphamap_fragment:Eu,alphamap_pars_fragment:Tu,alphatest_fragment:yu,alphatest_pars_fragment:bu,aomap_fragment:Au,aomap_pars_fragment:wu,batching_pars_vertex:Ru,batching_vertex:Cu,begin_vertex:Pu,beginnormal_vertex:Uu,bsdfs:Du,iridescence_fragment:Iu,bumpmap_pars_fragment:Lu,clipping_planes_fragment:Nu,clipping_planes_pars_fragment:Fu,clipping_planes_pars_vertex:Ou,clipping_planes_vertex:Bu,color_fragment:zu,color_pars_fragment:Gu,color_pars_vertex:Hu,color_vertex:Vu,common:ku,cube_uv_reflection_fragment:Wu,defaultnormal_vertex:Xu,displacementmap_pars_vertex:qu,displacementmap_vertex:Yu,emissivemap_fragment:ju,emissivemap_pars_fragment:Ku,colorspace_fragment:Ju,colorspace_pars_fragment:Zu,envmap_fragment:$u,envmap_common_pars_fragment:Qu,envmap_pars_fragment:eh,envmap_pars_vertex:th,envmap_physical_pars_fragment:dh,envmap_vertex:ih,fog_vertex:rh,fog_pars_vertex:nh,fog_fragment:ah,fog_pars_fragment:sh,gradientmap_pars_fragment:oh,lightmap_pars_fragment:lh,lights_lambert_fragment:ch,lights_lambert_pars_fragment:uh,lights_pars_begin:hh,lights_toon_fragment:ph,lights_toon_pars_fragment:fh,lights_phong_fragment:mh,lights_phong_pars_fragment:gh,lights_physical_fragment:_h,lights_physical_pars_fragment:vh,lights_fragment_begin:xh,lights_fragment_maps:Mh,lights_fragment_end:Sh,lightprobes_pars_fragment:Eh,logdepthbuf_fragment:Th,logdepthbuf_pars_fragment:yh,logdepthbuf_pars_vertex:bh,logdepthbuf_vertex:Ah,map_fragment:wh,map_pars_fragment:Rh,map_particle_fragment:Ch,map_particle_pars_fragment:Ph,metalnessmap_fragment:Uh,metalnessmap_pars_fragment:Dh,morphinstance_vertex:Ih,morphcolor_vertex:Lh,morphnormal_vertex:Nh,morphtarget_pars_vertex:Fh,morphtarget_vertex:Oh,normal_fragment_begin:Bh,normal_fragment_maps:zh,normal_pars_fragment:Gh,normal_pars_vertex:Hh,normal_vertex:Vh,normalmap_pars_fragment:kh,clearcoat_normal_fragment_begin:Wh,clearcoat_normal_fragment_maps:Xh,clearcoat_pars_fragment:qh,iridescence_pars_fragment:Yh,opaque_fragment:jh,packing:Kh,premultiplied_alpha_fragment:Jh,project_vertex:Zh,dithering_fragment:$h,dithering_pars_fragment:Qh,roughnessmap_fragment:ed,roughnessmap_pars_fragment:td,shadowmap_pars_fragment:id,shadowmap_pars_vertex:rd,shadowmap_vertex:nd,shadowmask_pars_fragment:ad,skinbase_vertex:sd,skinning_pars_vertex:od,skinning_vertex:ld,skinnormal_vertex:cd,specularmap_fragment:ud,specularmap_pars_fragment:hd,tonemapping_fragment:dd,tonemapping_pars_fragment:pd,transmission_fragment:fd,transmission_pars_fragment:md,uv_pars_fragment:gd,uv_pars_vertex:_d,uv_vertex:vd,worldpos_vertex:xd,background_vert:Md,background_frag:Sd,backgroundCube_vert:Ed,backgroundCube_frag:Td,cube_vert:yd,cube_frag:bd,depth_vert:Ad,depth_frag:wd,distance_vert:Rd,distance_frag:Cd,equirect_vert:Pd,equirect_frag:Ud,linedashed_vert:Dd,linedashed_frag:Id,meshbasic_vert:Ld,meshbasic_frag:Nd,meshlambert_vert:Fd,meshlambert_frag:Od,meshmatcap_vert:Bd,meshmatcap_frag:zd,meshnormal_vert:Gd,meshnormal_frag:Hd,meshphong_vert:Vd,meshphong_frag:kd,meshphysical_vert:Wd,meshphysical_frag:Xd,meshtoon_vert:qd,meshtoon_frag:Yd,points_vert:jd,points_frag:Kd,shadow_vert:Jd,shadow_frag:Zd,sprite_vert:$d,sprite_frag:Qd},he={common:{diffuse:{value:new qe(16777215)},opacity:{value:1},map:{value:null},mapTransform:{value:new Ce},alphaMap:{value:null},alphaMapTransform:{value:new Ce},alphaTest:{value:0}},specularmap:{specularMap:{value:null},specularMapTransform:{value:new Ce}},envmap:{envMap:{value:null},envMapRotation:{value:new Ce},reflectivity:{value:1},ior:{value:1.5},refractionRatio:{value:.98},dfgLUT:{value:null}},aomap:{aoMap:{value:null},aoMapIntensity:{value:1},aoMapTransform:{value:new Ce}},lightmap:{lightMap:{value:null},lightMapIntensity:{value:1},lightMapTransform:{value:new Ce}},bumpmap:{bumpMap:{value:null},bumpMapTransform:{value:new Ce},bumpScale:{value:1}},normalmap:{normalMap:{value:null},normalMapTransform:{value:new Ce},normalScale:{value:new Ke(1,1)}},displacementmap:{displacementMap:{value:null},displacementMapTransform:{value:new Ce},displacementScale:{value:1},displacementBias:{value:0}},emissivemap:{emissiveMap:{value:null},emissiveMapTransform:{value:new Ce}},metalnessmap:{metalnessMap:{value:null},metalnessMapTransform:{value:new Ce}},roughnessmap:{roughnessMap:{value:null},roughnessMapTransform:{value:new Ce}},gradientmap:{gradientMap:{value:null}},fog:{fogDensity:{value:25e-5},fogNear:{value:1},fogFar:{value:2e3},fogColor:{value:new qe(16777215)}},lights:{ambientLightColor:{value:[]},lightProbe:{value:[]},directionalLights:{value:[],properties:{direction:{},color:{}}},directionalLightShadows:{value:[],properties:{shadowIntensity:1,shadowBias:{},shadowNormalBias:{},shadowRadius:{},shadowMapSize:{}}},directionalShadowMatrix:{value:[]},spotLights:{value:[],properties:{color:{},position:{},direction:{},distance:{},coneCos:{},penumbraCos:{},decay:{}}},spotLightShadows:{value:[],properties:{shadowIntensity:1,shadowBias:{},shadowNormalBias:{},shadowRadius:{},shadowMapSize:{}}},spotLightMap:{value:[]},spotLightMatrix:{value:[]},pointLights:{value:[],properties:{color:{},position:{},decay:{},distance:{}}},pointLightShadows:{value:[],properties:{shadowIntensity:1,shadowBias:{},shadowNormalBias:{},shadowRadius:{},shadowMapSize:{},shadowCameraNear:{},shadowCameraFar:{}}},pointShadowMatrix:{value:[]},hemisphereLights:{value:[],properties:{direction:{},skyColor:{},groundColor:{}}},rectAreaLights:{value:[],properties:{color:{},position:{},width:{},height:{}}},ltc_1:{value:null},ltc_2:{value:null},probesSH:{value:null},probesMin:{value:new G},probesMax:{value:new G},probesResolution:{value:new G}},points:{diffuse:{value:new qe(16777215)},opacity:{value:1},size:{value:1},scale:{value:1},map:{value:null},alphaMap:{value:null},alphaMapTransform:{value:new Ce},alphaTest:{value:0},uvTransform:{value:new Ce}},sprite:{diffuse:{value:new qe(16777215)},opacity:{value:1},center:{value:new Ke(.5,.5)},rotation:{value:0},map:{value:null},mapTransform:{value:new Ce},alphaMap:{value:null},alphaMapTransform:{value:new Ce},alphaTest:{value:0}}},ei={basic:{uniforms:Tt([he.common,he.specularmap,he.envmap,he.aomap,he.lightmap,he.fog]),vertexShader:De.meshbasic_vert,fragmentShader:De.meshbasic_frag},lambert:{uniforms:Tt([he.common,he.specularmap,he.envmap,he.aomap,he.lightmap,he.emissivemap,he.bumpmap,he.normalmap,he.displacementmap,he.fog,he.lights,{emissive:{value:new qe(0)},envMapIntensity:{value:1}}]),vertexShader:De.meshlambert_vert,fragmentShader:De.meshlambert_frag},phong:{uniforms:Tt([he.common,he.specularmap,he.envmap,he.aomap,he.lightmap,he.emissivemap,he.bumpmap,he.normalmap,he.displacementmap,he.fog,he.lights,{emissive:{value:new qe(0)},specular:{value:new qe(1118481)},shininess:{value:30},envMapIntensity:{value:1}}]),vertexShader:De.meshphong_vert,fragmentShader:De.meshphong_frag},standard:{uniforms:Tt([he.common,he.envmap,he.aomap,he.lightmap,he.emissivemap,he.bumpmap,he.normalmap,he.displacementmap,he.roughnessmap,he.metalnessmap,he.fog,he.lights,{emissive:{value:new qe(0)},roughness:{value:1},metalness:{value:0},envMapIntensity:{value:1}}]),vertexShader:De.meshphysical_vert,fragmentShader:De.meshphysical_frag},toon:{uniforms:Tt([he.common,he.aomap,he.lightmap,he.emissivemap,he.bumpmap,he.normalmap,he.displacementmap,he.gradientmap,he.fog,he.lights,{emissive:{value:new qe(0)}}]),vertexShader:De.meshtoon_vert,fragmentShader:De.meshtoon_frag},matcap:{uniforms:Tt([he.common,he.bumpmap,he.normalmap,he.displacementmap,he.fog,{matcap:{value:null}}]),vertexShader:De.meshmatcap_vert,fragmentShader:De.meshmatcap_frag},points:{uniforms:Tt([he.points,he.fog]),vertexShader:De.points_vert,fragmentShader:De.points_frag},dashed:{uniforms:Tt([he.common,he.fog,{scale:{value:1},dashSize:{value:1},totalSize:{value:2}}]),vertexShader:De.linedashed_vert,fragmentShader:De.linedashed_frag},depth:{uniforms:Tt([he.common,he.displacementmap]),vertexShader:De.depth_vert,fragmentShader:De.depth_frag},normal:{uniforms:Tt([he.common,he.bumpmap,he.normalmap,he.displacementmap,{opacity:{value:1}}]),vertexShader:De.meshnormal_vert,fragmentShader:De.meshnormal_frag},sprite:{uniforms:Tt([he.sprite,he.fog]),vertexShader:De.sprite_vert,fragmentShader:De.sprite_frag},background:{uniforms:{uvTransform:{value:new Ce},t2D:{value:null},backgroundIntensity:{value:1}},vertexShader:De.background_vert,fragmentShader:De.background_frag},backgroundCube:{uniforms:{envMap:{value:null},backgroundBlurriness:{value:0},backgroundIntensity:{value:1},backgroundRotation:{value:new Ce}},vertexShader:De.backgroundCube_vert,fragmentShader:De.backgroundCube_frag},cube:{uniforms:{tCube:{value:null},tFlip:{value:-1},opacity:{value:1}},vertexShader:De.cube_vert,fragmentShader:De.cube_frag},equirect:{uniforms:{tEquirect:{value:null}},vertexShader:De.equirect_vert,fragmentShader:De.equirect_frag},distance:{uniforms:Tt([he.common,he.displacementmap,{referencePosition:{value:new G},nearDistance:{value:1},farDistance:{value:1e3}}]),vertexShader:De.distance_vert,fragmentShader:De.distance_frag},shadow:{uniforms:Tt([he.lights,he.fog,{color:{value:new qe(0)},opacity:{value:1}}]),vertexShader:De.shadow_vert,fragmentShader:De.shadow_frag}};ei.physical={uniforms:Tt([ei.standard.uniforms,{clearcoat:{value:0},clearcoatMap:{value:null},clearcoatMapTransform:{value:new Ce},clearcoatNormalMap:{value:null},clearcoatNormalMapTransform:{value:new Ce},clearcoatNormalScale:{value:new Ke(1,1)},clearcoatRoughness:{value:0},clearcoatRoughnessMap:{value:null},clearcoatRoughnessMapTransform:{value:new Ce},dispersion:{value:0},iridescence:{value:0},iridescenceMap:{value:null},iridescenceMapTransform:{value:new Ce},iridescenceIOR:{value:1.3},iridescenceThicknessMinimum:{value:100},iridescenceThicknessMaximum:{value:400},iridescenceThicknessMap:{value:null},iridescenceThicknessMapTransform:{value:new Ce},sheen:{value:0},sheenColor:{value:new qe(0)},sheenColorMap:{value:null},sheenColorMapTransform:{value:new Ce},sheenRoughness:{value:1},sheenRoughnessMap:{value:null},sheenRoughnessMapTransform:{value:new Ce},transmission:{value:0},transmissionMap:{value:null},transmissionMapTransform:{value:new Ce},transmissionSamplerSize:{value:new Ke},transmissionSamplerMap:{value:null},thickness:{value:0},thicknessMap:{value:null},thicknessMapTransform:{value:new Ce},attenuationDistance:{value:0},attenuationColor:{value:new qe(0)},specularColor:{value:new qe(1,1,1)},specularColorMap:{value:null},specularColorMapTransform:{value:new Ce},specularIntensity:{value:1},specularIntensityMap:{value:null},specularIntensityMapTransform:{value:new Ce},anisotropyVector:{value:new Ke},anisotropyMap:{value:null},anisotropyMapTransform:{value:new Ce}}]),vertexShader:De.meshphysical_vert,fragmentShader:De.meshphysical_frag};const xn={r:0,b:0,g:0},ep=new ht,Go=new Ce;Go.set(-1,0,0,0,1,0,0,0,1);function tp(r,e,t,i,n,a){const s=new qe(0);let o=n===!0?0:1,c,l,d=null,m=0,u=null;function g(S){let A=S.isScene===!0?S.background:null;if(A&&A.isTexture){const T=S.backgroundBlurriness>0;A=e.get(A,T)}return A}function x(S){let A=!1;const T=g(S);T===null?p(s,o):T&&T.isColor&&(p(T,1),A=!0);const U=r.xr.getEnvironmentBlendMode();U==="additive"?t.buffers.color.setClear(0,0,0,1,a):U==="alpha-blend"&&t.buffers.color.setClear(0,0,0,0,a),(r.autoClear||A)&&(t.buffers.depth.setTest(!0),t.buffers.depth.setMask(!0),t.buffers.color.setMask(!0),r.clear(r.autoClearColor,r.autoClearDepth,r.autoClearStencil))}function E(S,A){const T=g(A);T&&(T.isCubeTexture||T.mapping===Or)?(l===void 0&&(l=new Zt(new Dr(1,1,1),new $t({name:"BackgroundCubeMaterial",uniforms:hr(ei.backgroundCube.uniforms),vertexShader:ei.backgroundCube.vertexShader,fragmentShader:ei.backgroundCube.fragmentShader,side:bt,depthTest:!1,depthWrite:!1,fog:!1,allowOverride:!1})),l.geometry.deleteAttribute("normal"),l.geometry.deleteAttribute("uv"),l.onBeforeRender=function(U,y,C){this.matrixWorld.copyPosition(C.matrixWorld)},Object.defineProperty(l.material,"envMap",{get:function(){return this.uniforms.envMap.value}}),i.update(l)),l.material.uniforms.envMap.value=T,l.material.uniforms.backgroundBlurriness.value=A.backgroundBlurriness,l.material.uniforms.backgroundIntensity.value=A.backgroundIntensity,l.material.uniforms.backgroundRotation.value.setFromMatrix4(ep.makeRotationFromEuler(A.backgroundRotation)).transpose(),T.isCubeTexture&&T.isRenderTargetTexture===!1&&l.material.uniforms.backgroundRotation.value.premultiply(Go),l.material.toneMapped=ze.getTransfer(T.colorSpace)!==Xe,(d!==T||m!==T.version||u!==r.toneMapping)&&(l.material.needsUpdate=!0,d=T,m=T.version,u=r.toneMapping),l.layers.enableAll(),S.unshift(l,l.geometry,l.material,0,0,null)):T&&T.isTexture&&(c===void 0&&(c=new Zt(new An(2,2),new $t({name:"BackgroundMaterial",uniforms:hr(ei.background.uniforms),vertexShader:ei.background.vertexShader,fragmentShader:ei.background.fragmentShader,side:ni,depthTest:!1,depthWrite:!1,fog:!1,allowOverride:!1})),c.geometry.deleteAttribute("normal"),Object.defineProperty(c.material,"map",{get:function(){return this.uniforms.t2D.value}}),i.update(c)),c.material.uniforms.t2D.value=T,c.material.uniforms.backgroundIntensity.value=A.backgroundIntensity,c.material.toneMapped=ze.getTransfer(T.colorSpace)!==Xe,T.matrixAutoUpdate===!0&&T.updateMatrix(),c.material.uniforms.uvTransform.value.copy(T.matrix),(d!==T||m!==T.version||u!==r.toneMapping)&&(c.material.needsUpdate=!0,d=T,m=T.version,u=r.toneMapping),c.layers.enableAll(),S.unshift(c,c.geometry,c.material,0,0,null))}function p(S,A){S.getRGB(xn,Do(r)),t.buffers.color.setClear(xn.r,xn.g,xn.b,A,a)}function h(){l!==void 0&&(l.geometry.dispose(),l.material.dispose(),l=void 0),c!==void 0&&(c.geometry.dispose(),c.material.dispose(),c=void 0)}return{getClearColor:function(){return s},setClearColor:function(S,A=1){s.set(S),o=A,p(s,o)},getClearAlpha:function(){return o},setClearAlpha:function(S){o=S,p(s,o)},render:x,addToRenderList:E,dispose:h}}function ip(r,e){const t=r.getParameter(r.MAX_VERTEX_ATTRIBS),i={},n=u(null);let a=n,s=!1;function o(w,N,W,q,L){let V=!1;const H=m(w,q,W,N);a!==H&&(a=H,l(a.object)),V=g(w,q,W,L),V&&x(w,q,W,L),L!==null&&e.update(L,r.ELEMENT_ARRAY_BUFFER),(V||s)&&(s=!1,T(w,N,W,q),L!==null&&r.bindBuffer(r.ELEMENT_ARRAY_BUFFER,e.get(L).buffer))}function c(){return r.createVertexArray()}function l(w){return r.bindVertexArray(w)}function d(w){return r.deleteVertexArray(w)}function m(w,N,W,q){const L=q.wireframe===!0;let V=i[N.id];V===void 0&&(V={},i[N.id]=V);const H=w.isInstancedMesh===!0?w.id:0;let Z=V[H];Z===void 0&&(Z={},V[H]=Z);let Q=Z[W.id];Q===void 0&&(Q={},Z[W.id]=Q);let re=Q[L];return re===void 0&&(re=u(c()),Q[L]=re),re}function u(w){const N=[],W=[],q=[];for(let L=0;L<t;L++)N[L]=0,W[L]=0,q[L]=0;return{geometry:null,program:null,wireframe:!1,newAttributes:N,enabledAttributes:W,attributeDivisors:q,object:w,attributes:{},index:null}}function g(w,N,W,q){const L=a.attributes,V=N.attributes;let H=0;const Z=W.getAttributes();for(const Q in Z)if(Z[Q].location>=0){const re=L[Q];let ve=V[Q];if(ve===void 0&&(Q==="instanceMatrix"&&w.instanceMatrix&&(ve=w.instanceMatrix),Q==="instanceColor"&&w.instanceColor&&(ve=w.instanceColor)),re===void 0||re.attribute!==ve||ve&&re.data!==ve.data)return!0;H++}return a.attributesNum!==H||a.index!==q}function x(w,N,W,q){const L={},V=N.attributes;let H=0;const Z=W.getAttributes();for(const Q in Z)if(Z[Q].location>=0){let re=V[Q];re===void 0&&(Q==="instanceMatrix"&&w.instanceMatrix&&(re=w.instanceMatrix),Q==="instanceColor"&&w.instanceColor&&(re=w.instanceColor));const ve={};ve.attribute=re,re&&re.data&&(ve.data=re.data),L[Q]=ve,H++}a.attributes=L,a.attributesNum=H,a.index=q}function E(){const w=a.newAttributes;for(let N=0,W=w.length;N<W;N++)w[N]=0}function p(w){h(w,0)}function h(w,N){const W=a.newAttributes,q=a.enabledAttributes,L=a.attributeDivisors;W[w]=1,q[w]===0&&(r.enableVertexAttribArray(w),q[w]=1),L[w]!==N&&(r.vertexAttribDivisor(w,N),L[w]=N)}function S(){const w=a.newAttributes,N=a.enabledAttributes;for(let W=0,q=N.length;W<q;W++)N[W]!==w[W]&&(r.disableVertexAttribArray(W),N[W]=0)}function A(w,N,W,q,L,V,H){H===!0?r.vertexAttribIPointer(w,N,W,L,V):r.vertexAttribPointer(w,N,W,q,L,V)}function T(w,N,W,q){E();const L=q.attributes,V=W.getAttributes(),H=N.defaultAttributeValues;for(const Z in V){const Q=V[Z];if(Q.location>=0){let re=L[Z];if(re===void 0&&(Z==="instanceMatrix"&&w.instanceMatrix&&(re=w.instanceMatrix),Z==="instanceColor"&&w.instanceColor&&(re=w.instanceColor)),re!==void 0){const ve=re.normalized,we=re.itemSize,Ge=e.get(re);if(Ge===void 0)continue;const Ye=Ge.buffer,Ue=Ge.type,j=Ge.bytesPerElement,oe=Ue===r.INT||Ue===r.UNSIGNED_INT||re.gpuType===jn;if(re.isInterleavedBufferAttribute){const ne=re.data,Te=ne.stride,Pe=re.offset;if(ne.isInstancedInterleavedBuffer){for(let fe=0;fe<Q.locationSize;fe++)h(Q.location+fe,ne.meshPerAttribute);w.isInstancedMesh!==!0&&q._maxInstanceCount===void 0&&(q._maxInstanceCount=ne.meshPerAttribute*ne.count)}else for(let fe=0;fe<Q.locationSize;fe++)p(Q.location+fe);r.bindBuffer(r.ARRAY_BUFFER,Ye);for(let fe=0;fe<Q.locationSize;fe++)A(Q.location+fe,we/Q.locationSize,Ue,ve,Te*j,(Pe+we/Q.locationSize*fe)*j,oe)}else{if(re.isInstancedBufferAttribute){for(let ne=0;ne<Q.locationSize;ne++)h(Q.location+ne,re.meshPerAttribute);w.isInstancedMesh!==!0&&q._maxInstanceCount===void 0&&(q._maxInstanceCount=re.meshPerAttribute*re.count)}else for(let ne=0;ne<Q.locationSize;ne++)p(Q.location+ne);r.bindBuffer(r.ARRAY_BUFFER,Ye);for(let ne=0;ne<Q.locationSize;ne++)A(Q.location+ne,we/Q.locationSize,Ue,ve,we*j,we/Q.locationSize*ne*j,oe)}}else if(H!==void 0){const ve=H[Z];if(ve!==void 0)switch(ve.length){case 2:r.vertexAttrib2fv(Q.location,ve);break;case 3:r.vertexAttrib3fv(Q.location,ve);break;case 4:r.vertexAttrib4fv(Q.location,ve);break;default:r.vertexAttrib1fv(Q.location,ve)}}}}S()}function U(){b();for(const w in i){const N=i[w];for(const W in N){const q=N[W];for(const L in q){const V=q[L];for(const H in V)d(V[H].object),delete V[H];delete q[L]}}delete i[w]}}function y(w){if(i[w.id]===void 0)return;const N=i[w.id];for(const W in N){const q=N[W];for(const L in q){const V=q[L];for(const H in V)d(V[H].object),delete V[H];delete q[L]}}delete i[w.id]}function C(w){for(const N in i){const W=i[N];for(const q in W){const L=W[q];if(L[w.id]===void 0)continue;const V=L[w.id];for(const H in V)d(V[H].object),delete V[H];delete L[w.id]}}}function v(w){for(const N in i){const W=i[N],q=w.isInstancedMesh===!0?w.id:0,L=W[q];if(L!==void 0){for(const V in L){const H=L[V];for(const Z in H)d(H[Z].object),delete H[Z];delete L[V]}delete W[q],Object.keys(W).length===0&&delete i[N]}}}function b(){F(),s=!0,a!==n&&(a=n,l(a.object))}function F(){n.geometry=null,n.program=null,n.wireframe=!1}return{setup:o,reset:b,resetDefaultState:F,dispose:U,releaseStatesOfGeometry:y,releaseStatesOfObject:v,releaseStatesOfProgram:C,initAttributes:E,enableAttribute:p,disableUnusedAttributes:S}}function rp(r,e,t){let i;function n(c){i=c}function a(c,l){r.drawArrays(i,c,l),t.update(l,i,1)}function s(c,l,d){d!==0&&(r.drawArraysInstanced(i,c,l,d),t.update(l,i,d))}function o(c,l,d){if(d===0)return;e.get("WEBGL_multi_draw").multiDrawArraysWEBGL(i,c,0,l,0,d);let m=0;for(let u=0;u<d;u++)m+=l[u];t.update(m,i,1)}this.setMode=n,this.render=a,this.renderInstances=s,this.renderMultiDraw=o}function np(r,e,t,i){let n;function a(){if(n!==void 0)return n;if(e.has("EXT_texture_filter_anisotropic")===!0){const C=e.get("EXT_texture_filter_anisotropic");n=r.getParameter(C.MAX_TEXTURE_MAX_ANISOTROPY_EXT)}else n=0;return n}function s(C){return!(C!==Ot&&i.convert(C)!==r.getParameter(r.IMPLEMENTATION_COLOR_READ_FORMAT))}function o(C){const v=C===li&&(e.has("EXT_color_buffer_half_float")||e.has("EXT_color_buffer_float"));return!(C!==Lt&&i.convert(C)!==r.getParameter(r.IMPLEMENTATION_COLOR_READ_TYPE)&&C!==jt&&!v)}function c(C){if(C==="highp"){if(r.getShaderPrecisionFormat(r.VERTEX_SHADER,r.HIGH_FLOAT).precision>0&&r.getShaderPrecisionFormat(r.FRAGMENT_SHADER,r.HIGH_FLOAT).precision>0)return"highp";C="mediump"}return C==="mediump"&&r.getShaderPrecisionFormat(r.VERTEX_SHADER,r.MEDIUM_FLOAT).precision>0&&r.getShaderPrecisionFormat(r.FRAGMENT_SHADER,r.MEDIUM_FLOAT).precision>0?"mediump":"lowp"}let l=t.precision!==void 0?t.precision:"highp";const d=c(l);d!==l&&(Ae("WebGLRenderer:",l,"not supported, using",d,"instead."),l=d);const m=t.logarithmicDepthBuffer===!0,u=t.reversedDepthBuffer===!0&&e.has("EXT_clip_control");t.reversedDepthBuffer===!0&&u===!1&&Ae("WebGLRenderer: Unable to use reversed depth buffer due to missing EXT_clip_control extension. Fallback to default depth buffer.");const g=r.getParameter(r.MAX_TEXTURE_IMAGE_UNITS),x=r.getParameter(r.MAX_VERTEX_TEXTURE_IMAGE_UNITS),E=r.getParameter(r.MAX_TEXTURE_SIZE),p=r.getParameter(r.MAX_CUBE_MAP_TEXTURE_SIZE),h=r.getParameter(r.MAX_VERTEX_ATTRIBS),S=r.getParameter(r.MAX_VERTEX_UNIFORM_VECTORS),A=r.getParameter(r.MAX_VARYING_VECTORS),T=r.getParameter(r.MAX_FRAGMENT_UNIFORM_VECTORS),U=r.getParameter(r.MAX_SAMPLES),y=r.getParameter(r.SAMPLES);return{isWebGL2:!0,getMaxAnisotropy:a,getMaxPrecision:c,textureFormatReadable:s,textureTypeReadable:o,precision:l,logarithmicDepthBuffer:m,reversedDepthBuffer:u,maxTextures:g,maxVertexTextures:x,maxTextureSize:E,maxCubemapSize:p,maxAttributes:h,maxVertexUniforms:S,maxVaryings:A,maxFragmentUniforms:T,maxSamples:U,samples:y}}function ap(r){const e=this;let t=null,i=0,n=!1,a=!1;const s=new Vi,o=new Ce,c={value:null,needsUpdate:!1};this.uniform=c,this.numPlanes=0,this.numIntersection=0,this.init=function(m,u){const g=m.length!==0||u||i!==0||n;return n=u,i=m.length,g},this.beginShadows=function(){a=!0,d(null)},this.endShadows=function(){a=!1},this.setGlobalState=function(m,u){t=d(m,u,0)},this.setState=function(m,u,g){const x=m.clippingPlanes,E=m.clipIntersection,p=m.clipShadows,h=r.get(m);if(!n||x===null||x.length===0||a&&!p)a?d(null):l();else{const S=a?0:i,A=S*4;let T=h.clippingState||null;c.value=T,T=d(x,u,A,g);for(let U=0;U!==A;++U)T[U]=t[U];h.clippingState=T,this.numIntersection=E?this.numPlanes:0,this.numPlanes+=S}};function l(){c.value!==t&&(c.value=t,c.needsUpdate=i>0),e.numPlanes=i,e.numIntersection=0}function d(m,u,g,x){const E=m!==null?m.length:0;let p=null;if(E!==0){if(p=c.value,x!==!0||p===null){const h=g+E*4,S=u.matrixWorldInverse;o.getNormalMatrix(S),(p===null||p.length<h)&&(p=new Float32Array(h));for(let A=0,T=g;A!==E;++A,T+=4)s.copy(m[A]).applyMatrix4(S,o),s.normal.toArray(p,T),p[T+3]=s.constant}c.value=p,c.needsUpdate=!0}return e.numPlanes=E,e.numIntersection=0,p}}const wi=4,Ho=[.125,.215,.35,.446,.526,.582],Wi=20,sp=256,Cr=new as,Vo=new qe;let ss=null,os=0,ls=0,cs=!1;const op=new G;class ko{constructor(e){this._renderer=e,this._pingPongRenderTarget=null,this._lodMax=0,this._cubeSize=0,this._sizeLods=[],this._sigmas=[],this._lodMeshes=[],this._backgroundBox=null,this._cubemapMaterial=null,this._equirectMaterial=null,this._blurMaterial=null,this._ggxMaterial=null}fromScene(e,t=0,i=.1,n=100,a={}){const{size:s=256,position:o=op}=a;ss=this._renderer.getRenderTarget(),os=this._renderer.getActiveCubeFace(),ls=this._renderer.getActiveMipmapLevel(),cs=this._renderer.xr.enabled,this._renderer.xr.enabled=!1,this._setSize(s);const c=this._allocateTargets();return c.depthBuffer=!0,this._sceneToCubeUV(e,i,n,c,o),t>0&&this._blur(c,0,0,t),this._applyPMREM(c),this._cleanup(c),c}fromEquirectangular(e,t=null){return this._fromTexture(e,t)}fromCubemap(e,t=null){return this._fromTexture(e,t)}compileCubemapShader(){this._cubemapMaterial===null&&(this._cubemapMaterial=qo(),this._compileMaterial(this._cubemapMaterial))}compileEquirectangularShader(){this._equirectMaterial===null&&(this._equirectMaterial=Xo(),this._compileMaterial(this._equirectMaterial))}dispose(){this._dispose(),this._cubemapMaterial!==null&&this._cubemapMaterial.dispose(),this._equirectMaterial!==null&&this._equirectMaterial.dispose(),this._backgroundBox!==null&&(this._backgroundBox.geometry.dispose(),this._backgroundBox.material.dispose())}_setSize(e){this._lodMax=Math.floor(Math.log2(e)),this._cubeSize=Math.pow(2,this._lodMax)}_dispose(){this._blurMaterial!==null&&this._blurMaterial.dispose(),this._ggxMaterial!==null&&this._ggxMaterial.dispose(),this._pingPongRenderTarget!==null&&this._pingPongRenderTarget.dispose();for(let e=0;e<this._lodMeshes.length;e++)this._lodMeshes[e].geometry.dispose()}_cleanup(e){this._renderer.setRenderTarget(ss,os,ls),this._renderer.xr.enabled=cs,e.scissorTest=!1,fr(e,0,0,e.width,e.height)}_fromTexture(e,t){e.mapping===Li||e.mapping===Ji?this._setSize(e.image.length===0?16:e.image[0].width||e.image[0].image.width):this._setSize(e.image.width/4),ss=this._renderer.getRenderTarget(),os=this._renderer.getActiveCubeFace(),ls=this._renderer.getActiveMipmapLevel(),cs=this._renderer.xr.enabled,this._renderer.xr.enabled=!1;const i=t||this._allocateTargets();return this._textureToCubeUV(e,i),this._applyPMREM(i),this._cleanup(i),i}_allocateTargets(){const e=3*Math.max(this._cubeSize,112),t=4*this._cubeSize,i={magFilter:vt,minFilter:vt,generateMipmaps:!1,type:li,format:Ot,colorSpace:Xr,depthBuffer:!1},n=Wo(e,t,i);if(this._pingPongRenderTarget===null||this._pingPongRenderTarget.width!==e||this._pingPongRenderTarget.height!==t){this._pingPongRenderTarget!==null&&this._dispose(),this._pingPongRenderTarget=Wo(e,t,i);const{_lodMax:a}=this;({lodMeshes:this._lodMeshes,sizeLods:this._sizeLods,sigmas:this._sigmas}=lp(a)),this._blurMaterial=up(a,e,t),this._ggxMaterial=cp(a,e,t)}return n}_compileMaterial(e){const t=new Zt(new Vt,e);this._renderer.compile(t,Cr)}_sceneToCubeUV(e,t,i,n,a){const s=new Ht(90,1,t,i),o=[1,-1,1,1,1,1],c=[1,1,1,-1,-1,-1],l=this._renderer,d=l.autoClear,m=l.toneMapping;l.getClearColor(Vo),l.toneMapping=qt,l.autoClear=!1,l.state.buffers.depth.getReversed()&&(l.setRenderTarget(n),l.clearDepth(),l.setRenderTarget(null)),this._backgroundBox===null&&(this._backgroundBox=new Zt(new Dr,new yo({name:"PMREM.Background",side:bt,depthWrite:!1,depthTest:!1})));const u=this._backgroundBox,g=u.material;let x=!1;const E=e.background;E?E.isColor&&(g.color.copy(E),e.background=null,x=!0):(g.color.copy(Vo),x=!0);for(let p=0;p<6;p++){const h=p%3;h===0?(s.up.set(0,o[p],0),s.position.set(a.x,a.y,a.z),s.lookAt(a.x+c[p],a.y,a.z)):h===1?(s.up.set(0,0,o[p]),s.position.set(a.x,a.y,a.z),s.lookAt(a.x,a.y+c[p],a.z)):(s.up.set(0,o[p],0),s.position.set(a.x,a.y,a.z),s.lookAt(a.x,a.y,a.z+c[p]));const S=this._cubeSize;fr(n,h*S,p>2?S:0,S,S),l.setRenderTarget(n),x&&l.render(u,s),l.render(e,s)}l.toneMapping=m,l.autoClear=d,e.background=E}_textureToCubeUV(e,t){const i=this._renderer,n=e.mapping===Li||e.mapping===Ji;n?(this._cubemapMaterial===null&&(this._cubemapMaterial=qo()),this._cubemapMaterial.uniforms.flipEnvMap.value=e.isRenderTargetTexture===!1?-1:1):this._equirectMaterial===null&&(this._equirectMaterial=Xo());const a=n?this._cubemapMaterial:this._equirectMaterial,s=this._lodMeshes[0];s.material=a;const o=a.uniforms;o.envMap.value=e;const c=this._cubeSize;fr(t,0,0,3*c,2*c),i.setRenderTarget(t),i.render(s,Cr)}_applyPMREM(e){const t=this._renderer,i=t.autoClear;t.autoClear=!1;const n=this._lodMeshes.length;for(let a=1;a<n;a++)this._applyGGXFilter(e,a-1,a);t.autoClear=i}_applyGGXFilter(e,t,i){const n=this._renderer,a=this._pingPongRenderTarget,s=this._ggxMaterial,o=this._lodMeshes[i];o.material=s;const c=s.uniforms,l=i/(this._lodMeshes.length-1),d=t/(this._lodMeshes.length-1),m=Math.sqrt(l*l-d*d),u=0+l*1.25,g=m*u,{_lodMax:x}=this,E=this._sizeLods[i],p=3*E*(i>x-wi?i-x+wi:0),h=4*(this._cubeSize-E);c.envMap.value=e.texture,c.roughness.value=g,c.mipInt.value=x-t,fr(a,p,h,3*E,2*E),n.setRenderTarget(a),n.render(o,Cr),c.envMap.value=a.texture,c.roughness.value=0,c.mipInt.value=x-i,fr(e,p,h,3*E,2*E),n.setRenderTarget(e),n.render(o,Cr)}_blur(e,t,i,n,a){const s=this._pingPongRenderTarget;this._halfBlur(e,s,t,i,n,"latitudinal",a),this._halfBlur(s,e,i,i,n,"longitudinal",a)}_halfBlur(e,t,i,n,a,s,o){const c=this._renderer,l=this._blurMaterial;s!=="latitudinal"&&s!=="longitudinal"&&He("blur direction must be either latitudinal or longitudinal!");const d=3,m=this._lodMeshes[n];m.material=l;const u=l.uniforms,g=this._sizeLods[i]-1,x=isFinite(a)?Math.PI/(2*g):2*Math.PI/(2*Wi-1),E=a/x,p=isFinite(a)?1+Math.floor(d*E):Wi;p>Wi&&Ae(`sigmaRadians, ${a}, is too large and will clip, as it requested ${p} samples when the maximum is set to ${Wi}`);const h=[];let S=0;for(let C=0;C<Wi;++C){const v=C/E,b=Math.exp(-v*v/2);h.push(b),C===0?S+=b:C<p&&(S+=2*b)}for(let C=0;C<h.length;C++)h[C]=h[C]/S;u.envMap.value=e.texture,u.samples.value=p,u.weights.value=h,u.latitudinal.value=s==="latitudinal",o&&(u.poleAxis.value=o);const{_lodMax:A}=this;u.dTheta.value=x,u.mipInt.value=A-i;const T=this._sizeLods[n],U=3*T*(n>A-wi?n-A+wi:0),y=4*(this._cubeSize-T);fr(t,U,y,3*T,2*T),c.setRenderTarget(t),c.render(m,Cr)}}function lp(r){const e=[],t=[],i=[];let n=r;const a=r-wi+1+Ho.length;for(let s=0;s<a;s++){const o=Math.pow(2,n);e.push(o);let c=1/o;s>r-wi?c=Ho[s-r+wi-1]:s===0&&(c=0),t.push(c);const l=1/(o-2),d=-l,m=1+l,u=[d,d,m,d,m,m,d,d,m,m,d,m],g=6,x=6,E=3,p=2,h=1,S=new Float32Array(E*x*g),A=new Float32Array(p*x*g),T=new Float32Array(h*x*g);for(let y=0;y<g;y++){const C=y%3*2/3-1,v=y>2?0:-1,b=[C,v,0,C+2/3,v,0,C+2/3,v+1,0,C,v,0,C+2/3,v+1,0,C,v+1,0];S.set(b,E*x*y),A.set(u,p*x*y);const F=[y,y,y,y,y,y];T.set(F,h*x*y)}const U=new Vt;U.setAttribute("position",new Nt(S,E)),U.setAttribute("uv",new Nt(A,p)),U.setAttribute("faceIndex",new Nt(T,h)),i.push(new Zt(U,null)),n>wi&&n--}return{lodMeshes:i,sizeLods:e,sigmas:t}}function Wo(r,e,t){const i=new Jt(r,e,t);return i.texture.mapping=Or,i.texture.name="PMREM.cubeUv",i.scissorTest=!0,i}function fr(r,e,t,i,n){r.viewport.set(e,t,i,n),r.scissor.set(e,t,i,n)}function cp(r,e,t){return new $t({name:"PMREMGGXConvolution",defines:{GGX_SAMPLES:sp,CUBEUV_TEXEL_WIDTH:1/e,CUBEUV_TEXEL_HEIGHT:1/t,CUBEUV_MAX_MIP:`${r}.0`},uniforms:{envMap:{value:null},roughness:{value:0},mipInt:{value:0}},vertexShader:Mn(),fragmentShader:`

			precision highp float;
			precision highp int;

			varying vec3 vOutputDirection;

			uniform sampler2D envMap;
			uniform float roughness;
			uniform float mipInt;

			#define ENVMAP_TYPE_CUBE_UV
			#include <cube_uv_reflection_fragment>

			#define PI 3.14159265359

			// Van der Corput radical inverse
			float radicalInverse_VdC(uint bits) {
				bits = (bits << 16u) | (bits >> 16u);
				bits = ((bits & 0x55555555u) << 1u) | ((bits & 0xAAAAAAAAu) >> 1u);
				bits = ((bits & 0x33333333u) << 2u) | ((bits & 0xCCCCCCCCu) >> 2u);
				bits = ((bits & 0x0F0F0F0Fu) << 4u) | ((bits & 0xF0F0F0F0u) >> 4u);
				bits = ((bits & 0x00FF00FFu) << 8u) | ((bits & 0xFF00FF00u) >> 8u);
				return float(bits) * 2.3283064365386963e-10; // / 0x100000000
			}

			// Hammersley sequence
			vec2 hammersley(uint i, uint N) {
				return vec2(float(i) / float(N), radicalInverse_VdC(i));
			}

			// GGX VNDF importance sampling (Eric Heitz 2018)
			// "Sampling the GGX Distribution of Visible Normals"
			// https://jcgt.org/published/0007/04/01/
			vec3 importanceSampleGGX_VNDF(vec2 Xi, vec3 V, float roughness) {
				float alpha = roughness * roughness;

				// Section 4.1: Orthonormal basis
				vec3 T1 = vec3(1.0, 0.0, 0.0);
				vec3 T2 = cross(V, T1);

				// Section 4.2: Parameterization of projected area
				float r = sqrt(Xi.x);
				float phi = 2.0 * PI * Xi.y;
				float t1 = r * cos(phi);
				float t2 = r * sin(phi);
				float s = 0.5 * (1.0 + V.z);
				t2 = (1.0 - s) * sqrt(1.0 - t1 * t1) + s * t2;

				// Section 4.3: Reprojection onto hemisphere
				vec3 Nh = t1 * T1 + t2 * T2 + sqrt(max(0.0, 1.0 - t1 * t1 - t2 * t2)) * V;

				// Section 3.4: Transform back to ellipsoid configuration
				return normalize(vec3(alpha * Nh.x, alpha * Nh.y, max(0.0, Nh.z)));
			}

			void main() {
				vec3 N = normalize(vOutputDirection);
				vec3 V = N; // Assume view direction equals normal for pre-filtering

				vec3 prefilteredColor = vec3(0.0);
				float totalWeight = 0.0;

				// For very low roughness, just sample the environment directly
				if (roughness < 0.001) {
					gl_FragColor = vec4(bilinearCubeUV(envMap, N, mipInt), 1.0);
					return;
				}

				// Tangent space basis for VNDF sampling
				vec3 up = abs(N.z) < 0.999 ? vec3(0.0, 0.0, 1.0) : vec3(1.0, 0.0, 0.0);
				vec3 tangent = normalize(cross(up, N));
				vec3 bitangent = cross(N, tangent);

				for(uint i = 0u; i < uint(GGX_SAMPLES); i++) {
					vec2 Xi = hammersley(i, uint(GGX_SAMPLES));

					// For PMREM, V = N, so in tangent space V is always (0, 0, 1)
					vec3 H_tangent = importanceSampleGGX_VNDF(Xi, vec3(0.0, 0.0, 1.0), roughness);

					// Transform H back to world space
					vec3 H = normalize(tangent * H_tangent.x + bitangent * H_tangent.y + N * H_tangent.z);
					vec3 L = normalize(2.0 * dot(V, H) * H - V);

					float NdotL = max(dot(N, L), 0.0);

					if(NdotL > 0.0) {
						// Sample environment at fixed mip level
						// VNDF importance sampling handles the distribution filtering
						vec3 sampleColor = bilinearCubeUV(envMap, L, mipInt);

						// Weight by NdotL for the split-sum approximation
						// VNDF PDF naturally accounts for the visible microfacet distribution
						prefilteredColor += sampleColor * NdotL;
						totalWeight += NdotL;
					}
				}

				if (totalWeight > 0.0) {
					prefilteredColor = prefilteredColor / totalWeight;
				}

				gl_FragColor = vec4(prefilteredColor, 1.0);
			}
		`,blending:si,depthTest:!1,depthWrite:!1})}function up(r,e,t){const i=new Float32Array(Wi),n=new G(0,1,0);return new $t({name:"SphericalGaussianBlur",defines:{n:Wi,CUBEUV_TEXEL_WIDTH:1/e,CUBEUV_TEXEL_HEIGHT:1/t,CUBEUV_MAX_MIP:`${r}.0`},uniforms:{envMap:{value:null},samples:{value:1},weights:{value:i},latitudinal:{value:!1},dTheta:{value:0},mipInt:{value:0},poleAxis:{value:n}},vertexShader:Mn(),fragmentShader:`

			precision mediump float;
			precision mediump int;

			varying vec3 vOutputDirection;

			uniform sampler2D envMap;
			uniform int samples;
			uniform float weights[ n ];
			uniform bool latitudinal;
			uniform float dTheta;
			uniform float mipInt;
			uniform vec3 poleAxis;

			#define ENVMAP_TYPE_CUBE_UV
			#include <cube_uv_reflection_fragment>

			vec3 getSample( float theta, vec3 axis ) {

				float cosTheta = cos( theta );
				// Rodrigues' axis-angle rotation
				vec3 sampleDirection = vOutputDirection * cosTheta
					+ cross( axis, vOutputDirection ) * sin( theta )
					+ axis * dot( axis, vOutputDirection ) * ( 1.0 - cosTheta );

				return bilinearCubeUV( envMap, sampleDirection, mipInt );

			}

			void main() {

				vec3 axis = latitudinal ? poleAxis : cross( poleAxis, vOutputDirection );

				if ( all( equal( axis, vec3( 0.0 ) ) ) ) {

					axis = vec3( vOutputDirection.z, 0.0, - vOutputDirection.x );

				}

				axis = normalize( axis );

				gl_FragColor = vec4( 0.0, 0.0, 0.0, 1.0 );
				gl_FragColor.rgb += weights[ 0 ] * getSample( 0.0, axis );

				for ( int i = 1; i < n; i++ ) {

					if ( i >= samples ) {

						break;

					}

					float theta = dTheta * float( i );
					gl_FragColor.rgb += weights[ i ] * getSample( -1.0 * theta, axis );
					gl_FragColor.rgb += weights[ i ] * getSample( theta, axis );

				}

			}
		`,blending:si,depthTest:!1,depthWrite:!1})}function Xo(){return new $t({name:"EquirectangularToCubeUV",uniforms:{envMap:{value:null}},vertexShader:Mn(),fragmentShader:`

			precision mediump float;
			precision mediump int;

			varying vec3 vOutputDirection;

			uniform sampler2D envMap;

			#include <common>

			void main() {

				vec3 outputDirection = normalize( vOutputDirection );
				vec2 uv = equirectUv( outputDirection );

				gl_FragColor = vec4( texture2D ( envMap, uv ).rgb, 1.0 );

			}
		`,blending:si,depthTest:!1,depthWrite:!1})}function qo(){return new $t({name:"CubemapToCubeUV",uniforms:{envMap:{value:null},flipEnvMap:{value:-1}},vertexShader:Mn(),fragmentShader:`

			precision mediump float;
			precision mediump int;

			uniform float flipEnvMap;

			varying vec3 vOutputDirection;

			uniform samplerCube envMap;

			void main() {

				gl_FragColor = textureCube( envMap, vec3( flipEnvMap * vOutputDirection.x, vOutputDirection.yz ) );

			}
		`,blending:si,depthTest:!1,depthWrite:!1})}function Mn(){return`

		precision mediump float;
		precision mediump int;

		attribute float faceIndex;

		varying vec3 vOutputDirection;

		// RH coordinate system; PMREM face-indexing convention
		vec3 getDirection( vec2 uv, float face ) {

			uv = 2.0 * uv - 1.0;

			vec3 direction = vec3( uv, 1.0 );

			if ( face == 0.0 ) {

				direction = direction.zyx; // ( 1, v, u ) pos x

			} else if ( face == 1.0 ) {

				direction = direction.xzy;
				direction.xz *= -1.0; // ( -u, 1, -v ) pos y

			} else if ( face == 2.0 ) {

				direction.x *= -1.0; // ( -u, v, 1 ) pos z

			} else if ( face == 3.0 ) {

				direction = direction.zyx;
				direction.xz *= -1.0; // ( -1, v, -u ) neg x

			} else if ( face == 4.0 ) {

				direction = direction.xzy;
				direction.xy *= -1.0; // ( -u, -1, v ) neg y

			} else if ( face == 5.0 ) {

				direction.z *= -1.0; // ( u, v, -1 ) neg z

			}

			return direction;

		}

		void main() {

			vOutputDirection = getDirection( uv, faceIndex );
			gl_Position = vec4( position, 1.0 );

		}
	`}class Yo extends Jt{constructor(e=1,t={}){super(e,e,t),this.isWebGLCubeRenderTarget=!0;const i={width:e,height:e,depth:1},n=[i,i,i,i,i,i];this.texture=new Co(n),this._setTextureOptions(t),this.texture.isRenderTargetTexture=!0}fromEquirectangularTexture(e,t){this.texture.type=t.type,this.texture.colorSpace=t.colorSpace,this.texture.generateMipmaps=t.generateMipmaps,this.texture.minFilter=t.minFilter,this.texture.magFilter=t.magFilter;const i={uniforms:{tEquirect:{value:null}},vertexShader:`

				varying vec3 vWorldDirection;

				vec3 transformDirection( in vec3 dir, in mat4 matrix ) {

					return normalize( ( matrix * vec4( dir, 0.0 ) ).xyz );

				}

				void main() {

					vWorldDirection = transformDirection( position, modelMatrix );

					#include <begin_vertex>
					#include <project_vertex>

				}
			`,fragmentShader:`

				uniform sampler2D tEquirect;

				varying vec3 vWorldDirection;

				#include <common>

				void main() {

					vec3 direction = normalize( vWorldDirection );

					vec2 sampleUV = equirectUv( direction );

					gl_FragColor = texture2D( tEquirect, sampleUV );

				}
			`},n=new Dr(5,5,5),a=new $t({name:"CubemapFromEquirect",uniforms:hr(i.uniforms),vertexShader:i.vertexShader,fragmentShader:i.fragmentShader,side:bt,blending:si});a.uniforms.tEquirect.value=t;const s=new Zt(n,a),o=t.minFilter;return t.minFilter===Ni&&(t.minFilter=vt),new gu(1,10,this).update(e,s),t.minFilter=o,s.geometry.dispose(),s.material.dispose(),this}clear(e,t=!0,i=!0,n=!0){const a=e.getRenderTarget();for(let s=0;s<6;s++)e.setRenderTarget(this,s),e.clear(t,i,n);e.setRenderTarget(a)}}function hp(r){let e=new WeakMap,t=new WeakMap,i=null;function n(u,g=!1){return u==null?null:g?s(u):a(u)}function a(u){if(u&&u.isTexture){const g=u.mapping;if(g===kn||g===Wn)if(e.has(u)){const x=e.get(u).texture;return o(x,u.mapping)}else{const x=u.image;if(x&&x.height>0){const E=new Yo(x.height);return E.fromEquirectangularTexture(r,u),e.set(u,E),u.addEventListener("dispose",l),o(E.texture,u.mapping)}else return null}}return u}function s(u){if(u&&u.isTexture){const g=u.mapping,x=g===kn||g===Wn,E=g===Li||g===Ji;if(x||E){let p=t.get(u);const h=p!==void 0?p.texture.pmremVersion:0;if(u.isRenderTargetTexture&&u.pmremVersion!==h)return i===null&&(i=new ko(r)),p=x?i.fromEquirectangular(u,p):i.fromCubemap(u,p),p.texture.pmremVersion=u.pmremVersion,t.set(u,p),p.texture;if(p!==void 0)return p.texture;{const S=u.image;return x&&S&&S.height>0||E&&S&&c(S)?(i===null&&(i=new ko(r)),p=x?i.fromEquirectangular(u):i.fromCubemap(u),p.texture.pmremVersion=u.pmremVersion,t.set(u,p),u.addEventListener("dispose",d),p.texture):null}}}return u}function o(u,g){return g===kn?u.mapping=Li:g===Wn&&(u.mapping=Ji),u}function c(u){let g=0;const x=6;for(let E=0;E<x;E++)u[E]!==void 0&&g++;return g===x}function l(u){const g=u.target;g.removeEventListener("dispose",l);const x=e.get(g);x!==void 0&&(e.delete(g),x.dispose())}function d(u){const g=u.target;g.removeEventListener("dispose",d);const x=t.get(g);x!==void 0&&(t.delete(g),x.dispose())}function m(){e=new WeakMap,t=new WeakMap,i!==null&&(i.dispose(),i=null)}return{get:n,dispose:m}}function dp(r){const e={};function t(i){if(e[i]!==void 0)return e[i];const n=r.getExtension(i);return e[i]=n,n}return{has:function(i){return t(i)!==null},init:function(){t("EXT_color_buffer_float"),t("WEBGL_clip_cull_distance"),t("OES_texture_float_linear"),t("EXT_color_buffer_half_float"),t("WEBGL_multisampled_render_to_texture"),t("WEBGL_render_shared_exponent")},get:function(i){const n=t(i);return n===null&&Da("WebGLRenderer: "+i+" extension not supported."),n}}}function pp(r,e,t,i){const n={},a=new WeakMap;function s(m){const u=m.target;u.index!==null&&e.remove(u.index);for(const x in u.attributes)e.remove(u.attributes[x]);u.removeEventListener("dispose",s),delete n[u.id];const g=a.get(u);g&&(e.remove(g),a.delete(u)),i.releaseStatesOfGeometry(u),u.isInstancedBufferGeometry===!0&&delete u._maxInstanceCount,t.memory.geometries--}function o(m,u){return n[u.id]===!0||(u.addEventListener("dispose",s),n[u.id]=!0,t.memory.geometries++),u}function c(m){const u=m.attributes;for(const g in u)e.update(u[g],r.ARRAY_BUFFER)}function l(m){const u=[],g=m.index,x=m.attributes.position;let E=0;if(x===void 0)return;if(g!==null){const S=g.array;E=g.version;for(let A=0,T=S.length;A<T;A+=3){const U=S[A+0],y=S[A+1],C=S[A+2];u.push(U,y,y,C,C,U)}}else{const S=x.array;E=x.version;for(let A=0,T=S.length/3-1;A<T;A+=3){const U=A+0,y=A+1,C=A+2;u.push(U,y,y,C,C,U)}}const p=new(x.count>=65535?To:Eo)(u,1);p.version=E;const h=a.get(m);h&&e.remove(h),a.set(m,p)}function d(m){const u=a.get(m);if(u){const g=m.index;g!==null&&u.version<g.version&&l(m)}else l(m);return a.get(m)}return{get:o,update:c,getWireframeAttribute:d}}function fp(r,e,t){let i;function n(m){i=m}let a,s;function o(m){a=m.type,s=m.bytesPerElement}function c(m,u){r.drawElements(i,u,a,m*s),t.update(u,i,1)}function l(m,u,g){g!==0&&(r.drawElementsInstanced(i,u,a,m*s,g),t.update(u,i,g))}function d(m,u,g){if(g===0)return;e.get("WEBGL_multi_draw").multiDrawElementsWEBGL(i,u,0,a,m,0,g);let x=0;for(let E=0;E<g;E++)x+=u[E];t.update(x,i,1)}this.setMode=n,this.setIndex=o,this.render=c,this.renderInstances=l,this.renderMultiDraw=d}function mp(r){const e={geometries:0,textures:0},t={frame:0,calls:0,triangles:0,points:0,lines:0};function i(a,s,o){switch(t.calls++,s){case r.TRIANGLES:t.triangles+=o*(a/3);break;case r.LINES:t.lines+=o*(a/2);break;case r.LINE_STRIP:t.lines+=o*(a-1);break;case r.LINE_LOOP:t.lines+=o*a;break;case r.POINTS:t.points+=o*a;break;default:He("WebGLInfo: Unknown draw mode:",s);break}}function n(){t.calls=0,t.triangles=0,t.points=0,t.lines=0}return{memory:e,render:t,programs:null,autoReset:!0,reset:n,update:i}}function gp(r,e,t){const i=new WeakMap,n=new ot;function a(s,o,c){const l=s.morphTargetInfluences,d=o.morphAttributes.position||o.morphAttributes.normal||o.morphAttributes.color,m=d!==void 0?d.length:0;let u=i.get(o);if(u===void 0||u.count!==m){let g=function(){v.dispose(),i.delete(o),o.removeEventListener("dispose",g)};u!==void 0&&u.texture.dispose();const x=o.morphAttributes.position!==void 0,E=o.morphAttributes.normal!==void 0,p=o.morphAttributes.color!==void 0,h=o.morphAttributes.position||[],S=o.morphAttributes.normal||[],A=o.morphAttributes.color||[];let T=0;x===!0&&(T=1),E===!0&&(T=2),p===!0&&(T=3);let U=o.attributes.position.count*T,y=1;U>e.maxTextureSize&&(y=Math.ceil(U/e.maxTextureSize),U=e.maxTextureSize);const C=new Float32Array(U*y*4*m),v=new uo(C,U,y,m);v.type=jt,v.needsUpdate=!0;const b=T*4;for(let F=0;F<m;F++){const w=h[F],N=S[F],W=A[F],q=U*y*4*F;for(let L=0;L<w.count;L++){const V=L*b;x===!0&&(n.fromBufferAttribute(w,L),C[q+V+0]=n.x,C[q+V+1]=n.y,C[q+V+2]=n.z,C[q+V+3]=0),E===!0&&(n.fromBufferAttribute(N,L),C[q+V+4]=n.x,C[q+V+5]=n.y,C[q+V+6]=n.z,C[q+V+7]=0),p===!0&&(n.fromBufferAttribute(W,L),C[q+V+8]=n.x,C[q+V+9]=n.y,C[q+V+10]=n.z,C[q+V+11]=W.itemSize===4?n.w:1)}}u={count:m,texture:v,size:new Ke(U,y)},i.set(o,u),o.addEventListener("dispose",g)}if(s.isInstancedMesh===!0&&s.morphTexture!==null)c.getUniforms().setValue(r,"morphTexture",s.morphTexture,t);else{let g=0;for(let E=0;E<l.length;E++)g+=l[E];const x=o.morphTargetsRelative?1:1-g;c.getUniforms().setValue(r,"morphTargetBaseInfluence",x),c.getUniforms().setValue(r,"morphTargetInfluences",l)}c.getUniforms().setValue(r,"morphTargetsTexture",u.texture,t),c.getUniforms().setValue(r,"morphTargetsTextureSize",u.size)}return{update:a}}function _p(r,e,t,i,n){let a=new WeakMap;function s(l){const d=n.render.frame,m=l.geometry,u=e.get(l,m);if(a.get(u)!==d&&(e.update(u),a.set(u,d)),l.isInstancedMesh&&(l.hasEventListener("dispose",c)===!1&&l.addEventListener("dispose",c),a.get(l)!==d&&(t.update(l.instanceMatrix,r.ARRAY_BUFFER),l.instanceColor!==null&&t.update(l.instanceColor,r.ARRAY_BUFFER),a.set(l,d))),l.isSkinnedMesh){const g=l.skeleton;a.get(g)!==d&&(g.update(),a.set(g,d))}return u}function o(){a=new WeakMap}function c(l){const d=l.target;d.removeEventListener("dispose",c),i.releaseStatesOfObject(d),t.remove(d.instanceMatrix),d.instanceColor!==null&&t.remove(d.instanceColor)}return{update:s,dispose:o}}const vp={[zs]:"LINEAR_TONE_MAPPING",[Gs]:"REINHARD_TONE_MAPPING",[Hs]:"CINEON_TONE_MAPPING",[Vs]:"ACES_FILMIC_TONE_MAPPING",[Ws]:"AGX_TONE_MAPPING",[Xs]:"NEUTRAL_TONE_MAPPING",[ks]:"CUSTOM_TONE_MAPPING"};function xp(r,e,t,i,n){const a=new Jt(e,t,{type:r,depthBuffer:i,stencilBuffer:n,depthTexture:i?new ur(e,t):void 0}),s=new Jt(e,t,{type:li,depthBuffer:!1,stencilBuffer:!1}),o=new Vt;o.setAttribute("position",new mi([-1,3,0,-1,-1,0,3,-1,0],3)),o.setAttribute("uv",new mi([0,2,0,0,2,0],2));const c=new Io({uniforms:{tDiffuse:{value:null}},vertexShader:`
			precision highp float;

			uniform mat4 modelViewMatrix;
			uniform mat4 projectionMatrix;

			attribute vec3 position;
			attribute vec2 uv;

			varying vec2 vUv;

			void main() {
				vUv = uv;
				gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );
			}`,fragmentShader:`
			precision highp float;

			uniform sampler2D tDiffuse;

			varying vec2 vUv;

			#include <tonemapping_pars_fragment>
			#include <colorspace_pars_fragment>

			void main() {
				gl_FragColor = texture2D( tDiffuse, vUv );

				#ifdef LINEAR_TONE_MAPPING
					gl_FragColor.rgb = LinearToneMapping( gl_FragColor.rgb );
				#elif defined( REINHARD_TONE_MAPPING )
					gl_FragColor.rgb = ReinhardToneMapping( gl_FragColor.rgb );
				#elif defined( CINEON_TONE_MAPPING )
					gl_FragColor.rgb = CineonToneMapping( gl_FragColor.rgb );
				#elif defined( ACES_FILMIC_TONE_MAPPING )
					gl_FragColor.rgb = ACESFilmicToneMapping( gl_FragColor.rgb );
				#elif defined( AGX_TONE_MAPPING )
					gl_FragColor.rgb = AgXToneMapping( gl_FragColor.rgb );
				#elif defined( NEUTRAL_TONE_MAPPING )
					gl_FragColor.rgb = NeutralToneMapping( gl_FragColor.rgb );
				#elif defined( CUSTOM_TONE_MAPPING )
					gl_FragColor.rgb = CustomToneMapping( gl_FragColor.rgb );
				#endif

				#ifdef SRGB_TRANSFER
					gl_FragColor = sRGBTransferOETF( gl_FragColor );
				#endif
			}`,depthTest:!1,depthWrite:!1}),l=new Zt(o,c),d=new as(-1,1,1,-1,0,1);let m=null,u=null,g=!1,x,E=null,p=[],h=!1;this.setSize=function(S,A){a.setSize(S,A),s.setSize(S,A);for(let T=0;T<p.length;T++){const U=p[T];U.setSize&&U.setSize(S,A)}},this.setEffects=function(S){p=S,h=p.length>0&&p[0].isRenderPass===!0;const A=a.width,T=a.height;for(let U=0;U<p.length;U++){const y=p[U];y.setSize&&y.setSize(A,T)}},this.begin=function(S,A){if(g||S.toneMapping===qt&&p.length===0)return!1;if(E=A,A!==null){const T=A.width,U=A.height;(a.width!==T||a.height!==U)&&this.setSize(T,U)}return h===!1&&S.setRenderTarget(a),x=S.toneMapping,S.toneMapping=qt,!0},this.hasRenderPass=function(){return h},this.end=function(S,A){S.toneMapping=x,g=!0;let T=a,U=s;for(let y=0;y<p.length;y++){const C=p[y];if(C.enabled!==!1&&(C.render(S,U,T,A),C.needsSwap!==!1)){const v=T;T=U,U=v}}if(m!==S.outputColorSpace||u!==S.toneMapping){m=S.outputColorSpace,u=S.toneMapping,c.defines={},ze.getTransfer(m)===Xe&&(c.defines.SRGB_TRANSFER="");const y=vp[u];y&&(c.defines[y]=""),c.needsUpdate=!0}c.uniforms.tDiffuse.value=T.texture,S.setRenderTarget(E),S.render(l,d),E=null,g=!1},this.isCompositing=function(){return g},this.dispose=function(){a.depthTexture&&a.depthTexture.dispose(),a.dispose(),s.dispose(),o.dispose(),c.dispose()}}const jo=new yt,us=new ur(1,1),Ko=new uo,Jo=new kc,Zo=new Co,$o=[],Qo=[],el=new Float32Array(16),tl=new Float32Array(9),il=new Float32Array(4);function mr(r,e,t){const i=r[0];if(i<=0||i>0)return r;const n=e*t;let a=$o[n];if(a===void 0&&(a=new Float32Array(n),$o[n]=a),e!==0){i.toArray(a,0);for(let s=1,o=0;s!==e;++s)o+=t,r[s].toArray(a,o)}return a}function dt(r,e){if(r.length!==e.length)return!1;for(let t=0,i=r.length;t<i;t++)if(r[t]!==e[t])return!1;return!0}function pt(r,e){for(let t=0,i=e.length;t<i;t++)r[t]=e[t]}function Sn(r,e){let t=Qo[e];t===void 0&&(t=new Int32Array(e),Qo[e]=t);for(let i=0;i!==e;++i)t[i]=r.allocateTextureUnit();return t}function Mp(r,e){const t=this.cache;t[0]!==e&&(r.uniform1f(this.addr,e),t[0]=e)}function Sp(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y)&&(r.uniform2f(this.addr,e.x,e.y),t[0]=e.x,t[1]=e.y);else{if(dt(t,e))return;r.uniform2fv(this.addr,e),pt(t,e)}}function Ep(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y||t[2]!==e.z)&&(r.uniform3f(this.addr,e.x,e.y,e.z),t[0]=e.x,t[1]=e.y,t[2]=e.z);else if(e.r!==void 0)(t[0]!==e.r||t[1]!==e.g||t[2]!==e.b)&&(r.uniform3f(this.addr,e.r,e.g,e.b),t[0]=e.r,t[1]=e.g,t[2]=e.b);else{if(dt(t,e))return;r.uniform3fv(this.addr,e),pt(t,e)}}function Tp(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y||t[2]!==e.z||t[3]!==e.w)&&(r.uniform4f(this.addr,e.x,e.y,e.z,e.w),t[0]=e.x,t[1]=e.y,t[2]=e.z,t[3]=e.w);else{if(dt(t,e))return;r.uniform4fv(this.addr,e),pt(t,e)}}function yp(r,e){const t=this.cache,i=e.elements;if(i===void 0){if(dt(t,e))return;r.uniformMatrix2fv(this.addr,!1,e),pt(t,e)}else{if(dt(t,i))return;il.set(i),r.uniformMatrix2fv(this.addr,!1,il),pt(t,i)}}function bp(r,e){const t=this.cache,i=e.elements;if(i===void 0){if(dt(t,e))return;r.uniformMatrix3fv(this.addr,!1,e),pt(t,e)}else{if(dt(t,i))return;tl.set(i),r.uniformMatrix3fv(this.addr,!1,tl),pt(t,i)}}function Ap(r,e){const t=this.cache,i=e.elements;if(i===void 0){if(dt(t,e))return;r.uniformMatrix4fv(this.addr,!1,e),pt(t,e)}else{if(dt(t,i))return;el.set(i),r.uniformMatrix4fv(this.addr,!1,el),pt(t,i)}}function wp(r,e){const t=this.cache;t[0]!==e&&(r.uniform1i(this.addr,e),t[0]=e)}function Rp(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y)&&(r.uniform2i(this.addr,e.x,e.y),t[0]=e.x,t[1]=e.y);else{if(dt(t,e))return;r.uniform2iv(this.addr,e),pt(t,e)}}function Cp(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y||t[2]!==e.z)&&(r.uniform3i(this.addr,e.x,e.y,e.z),t[0]=e.x,t[1]=e.y,t[2]=e.z);else{if(dt(t,e))return;r.uniform3iv(this.addr,e),pt(t,e)}}function Pp(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y||t[2]!==e.z||t[3]!==e.w)&&(r.uniform4i(this.addr,e.x,e.y,e.z,e.w),t[0]=e.x,t[1]=e.y,t[2]=e.z,t[3]=e.w);else{if(dt(t,e))return;r.uniform4iv(this.addr,e),pt(t,e)}}function Up(r,e){const t=this.cache;t[0]!==e&&(r.uniform1ui(this.addr,e),t[0]=e)}function Dp(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y)&&(r.uniform2ui(this.addr,e.x,e.y),t[0]=e.x,t[1]=e.y);else{if(dt(t,e))return;r.uniform2uiv(this.addr,e),pt(t,e)}}function Ip(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y||t[2]!==e.z)&&(r.uniform3ui(this.addr,e.x,e.y,e.z),t[0]=e.x,t[1]=e.y,t[2]=e.z);else{if(dt(t,e))return;r.uniform3uiv(this.addr,e),pt(t,e)}}function Lp(r,e){const t=this.cache;if(e.x!==void 0)(t[0]!==e.x||t[1]!==e.y||t[2]!==e.z||t[3]!==e.w)&&(r.uniform4ui(this.addr,e.x,e.y,e.z,e.w),t[0]=e.x,t[1]=e.y,t[2]=e.z,t[3]=e.w);else{if(dt(t,e))return;r.uniform4uiv(this.addr,e),pt(t,e)}}function Np(r,e,t){const i=this.cache,n=t.allocateTextureUnit();i[0]!==n&&(r.uniform1i(this.addr,n),i[0]=n);let a;this.type===r.SAMPLER_2D_SHADOW?(us.compareFunction=t.isReversedDepthBuffer()?Ua:Pa,a=us):a=jo,t.setTexture2D(e||a,n)}function Fp(r,e,t){const i=this.cache,n=t.allocateTextureUnit();i[0]!==n&&(r.uniform1i(this.addr,n),i[0]=n),t.setTexture3D(e||Jo,n)}function Op(r,e,t){const i=this.cache,n=t.allocateTextureUnit();i[0]!==n&&(r.uniform1i(this.addr,n),i[0]=n),t.setTextureCube(e||Zo,n)}function Bp(r,e,t){const i=this.cache,n=t.allocateTextureUnit();i[0]!==n&&(r.uniform1i(this.addr,n),i[0]=n),t.setTexture2DArray(e||Ko,n)}function zp(r){switch(r){case 5126:return Mp;case 35664:return Sp;case 35665:return Ep;case 35666:return Tp;case 35674:return yp;case 35675:return bp;case 35676:return Ap;case 5124:case 35670:return wp;case 35667:case 35671:return Rp;case 35668:case 35672:return Cp;case 35669:case 35673:return Pp;case 5125:return Up;case 36294:return Dp;case 36295:return Ip;case 36296:return Lp;case 35678:case 36198:case 36298:case 36306:case 35682:return Np;case 35679:case 36299:case 36307:return Fp;case 35680:case 36300:case 36308:case 36293:return Op;case 36289:case 36303:case 36311:case 36292:return Bp}}function Gp(r,e){r.uniform1fv(this.addr,e)}function Hp(r,e){const t=mr(e,this.size,2);r.uniform2fv(this.addr,t)}function Vp(r,e){const t=mr(e,this.size,3);r.uniform3fv(this.addr,t)}function kp(r,e){const t=mr(e,this.size,4);r.uniform4fv(this.addr,t)}function Wp(r,e){const t=mr(e,this.size,4);r.uniformMatrix2fv(this.addr,!1,t)}function Xp(r,e){const t=mr(e,this.size,9);r.uniformMatrix3fv(this.addr,!1,t)}function qp(r,e){const t=mr(e,this.size,16);r.uniformMatrix4fv(this.addr,!1,t)}function Yp(r,e){r.uniform1iv(this.addr,e)}function jp(r,e){r.uniform2iv(this.addr,e)}function Kp(r,e){r.uniform3iv(this.addr,e)}function Jp(r,e){r.uniform4iv(this.addr,e)}function Zp(r,e){r.uniform1uiv(this.addr,e)}function $p(r,e){r.uniform2uiv(this.addr,e)}function Qp(r,e){r.uniform3uiv(this.addr,e)}function ef(r,e){r.uniform4uiv(this.addr,e)}function tf(r,e,t){const i=this.cache,n=e.length,a=Sn(t,n);dt(i,a)||(r.uniform1iv(this.addr,a),pt(i,a));let s;this.type===r.SAMPLER_2D_SHADOW?s=us:s=jo;for(let o=0;o!==n;++o)t.setTexture2D(e[o]||s,a[o])}function rf(r,e,t){const i=this.cache,n=e.length,a=Sn(t,n);dt(i,a)||(r.uniform1iv(this.addr,a),pt(i,a));for(let s=0;s!==n;++s)t.setTexture3D(e[s]||Jo,a[s])}function nf(r,e,t){const i=this.cache,n=e.length,a=Sn(t,n);dt(i,a)||(r.uniform1iv(this.addr,a),pt(i,a));for(let s=0;s!==n;++s)t.setTextureCube(e[s]||Zo,a[s])}function af(r,e,t){const i=this.cache,n=e.length,a=Sn(t,n);dt(i,a)||(r.uniform1iv(this.addr,a),pt(i,a));for(let s=0;s!==n;++s)t.setTexture2DArray(e[s]||Ko,a[s])}function sf(r){switch(r){case 5126:return Gp;case 35664:return Hp;case 35665:return Vp;case 35666:return kp;case 35674:return Wp;case 35675:return Xp;case 35676:return qp;case 5124:case 35670:return Yp;case 35667:case 35671:return jp;case 35668:case 35672:return Kp;case 35669:case 35673:return Jp;case 5125:return Zp;case 36294:return $p;case 36295:return Qp;case 36296:return ef;case 35678:case 36198:case 36298:case 36306:case 35682:return tf;case 35679:case 36299:case 36307:return rf;case 35680:case 36300:case 36308:case 36293:return nf;case 36289:case 36303:case 36311:case 36292:return af}}class of{constructor(e,t,i){this.id=e,this.addr=i,this.cache=[],this.type=t.type,this.setValue=zp(t.type)}}class lf{constructor(e,t,i){this.id=e,this.addr=i,this.cache=[],this.type=t.type,this.size=t.size,this.setValue=sf(t.type)}}class cf{constructor(e){this.id=e,this.seq=[],this.map={}}setValue(e,t,i){const n=this.seq;for(let a=0,s=n.length;a!==s;++a){const o=n[a];o.setValue(e,t[o.id],i)}}}const hs=/(\w+)(\])?(\[|\.)?/g;function rl(r,e){r.seq.push(e),r.map[e.id]=e}function uf(r,e,t){const i=r.name,n=i.length;for(hs.lastIndex=0;;){const a=hs.exec(i),s=hs.lastIndex;let o=a[1];const c=a[2]==="]",l=a[3];if(c&&(o=o|0),l===void 0||l==="["&&s+2===n){rl(t,l===void 0?new of(o,r,e):new lf(o,r,e));break}else{let d=t.map[o];d===void 0&&(d=new cf(o),rl(t,d)),t=d}}}class En{constructor(e,t){this.seq=[],this.map={};const i=e.getProgramParameter(t,e.ACTIVE_UNIFORMS);for(let s=0;s<i;++s){const o=e.getActiveUniform(t,s),c=e.getUniformLocation(t,o.name);uf(o,c,this)}const n=[],a=[];for(const s of this.seq)s.type===e.SAMPLER_2D_SHADOW||s.type===e.SAMPLER_CUBE_SHADOW||s.type===e.SAMPLER_2D_ARRAY_SHADOW?n.push(s):a.push(s);n.length>0&&(this.seq=n.concat(a))}setValue(e,t,i,n){const a=this.map[t];a!==void 0&&a.setValue(e,i,n)}setOptional(e,t,i){const n=t[i];n!==void 0&&this.setValue(e,i,n)}static upload(e,t,i,n){for(let a=0,s=t.length;a!==s;++a){const o=t[a],c=i[o.id];c.needsUpdate!==!1&&o.setValue(e,c.value,n)}}static seqWithValue(e,t){const i=[];for(let n=0,a=e.length;n!==a;++n){const s=e[n];s.id in t&&i.push(s)}return i}}function nl(r,e,t){const i=r.createShader(e);return r.shaderSource(i,t),r.compileShader(i),i}const hf=37297;let df=0;function pf(r,e){const t=r.split(`
`),i=[],n=Math.max(e-6,0),a=Math.min(e+6,t.length);for(let s=n;s<a;s++){const o=s+1;i.push(`${o===e?">":" "} ${o}: ${t[s]}`)}return i.join(`
`)}const al=new Ce;function ff(r){ze._getMatrix(al,ze.workingColorSpace,r);const e=`mat3( ${al.elements.map(t=>t.toFixed(4))} )`;switch(ze.getTransfer(r)){case qr:return[e,"LinearTransferOETF"];case Xe:return[e,"sRGBTransferOETF"];default:return Ae("WebGLProgram: Unsupported color space: ",r),[e,"LinearTransferOETF"]}}function sl(r,e,t){const i=r.getShaderParameter(e,r.COMPILE_STATUS),n=(r.getShaderInfoLog(e)||"").trim();if(i&&n==="")return"";const a=/ERROR: 0:(\d+)/.exec(n);if(a){const s=parseInt(a[1]);return t.toUpperCase()+`

`+n+`

`+pf(r.getShaderSource(e),s)}else return n}function mf(r,e){const t=ff(e);return[`vec4 ${r}( vec4 value ) {`,`	return ${t[1]}( vec4( value.rgb * ${t[0]}, value.a ) );`,"}"].join(`
`)}const gf={[zs]:"Linear",[Gs]:"Reinhard",[Hs]:"Cineon",[Vs]:"ACESFilmic",[Ws]:"AgX",[Xs]:"Neutral",[ks]:"Custom"};function _f(r,e){const t=gf[e];return t===void 0?(Ae("WebGLProgram: Unsupported toneMapping:",e),"vec3 "+r+"( vec3 color ) { return LinearToneMapping( color ); }"):"vec3 "+r+"( vec3 color ) { return "+t+"ToneMapping( color ); }"}const Tn=new G;function vf(){ze.getLuminanceCoefficients(Tn);const r=Tn.x.toFixed(4),e=Tn.y.toFixed(4),t=Tn.z.toFixed(4);return["float luminance( const in vec3 rgb ) {",`	const vec3 weights = vec3( ${r}, ${e}, ${t} );`,"	return dot( weights, rgb );","}"].join(`
`)}function xf(r){return[r.extensionClipCullDistance?"#extension GL_ANGLE_clip_cull_distance : require":"",r.extensionMultiDraw?"#extension GL_ANGLE_multi_draw : require":""].filter(Pr).join(`
`)}function Mf(r){const e=[];for(const t in r){const i=r[t];i!==!1&&e.push("#define "+t+" "+i)}return e.join(`
`)}function Sf(r,e){const t={},i=r.getProgramParameter(e,r.ACTIVE_ATTRIBUTES);for(let n=0;n<i;n++){const a=r.getActiveAttrib(e,n),s=a.name;let o=1;a.type===r.FLOAT_MAT2&&(o=2),a.type===r.FLOAT_MAT3&&(o=3),a.type===r.FLOAT_MAT4&&(o=4),t[s]={type:a.type,location:r.getAttribLocation(e,s),locationSize:o}}return t}function Pr(r){return r!==""}function ol(r,e){const t=e.numSpotLightShadows+e.numSpotLightMaps-e.numSpotLightShadowsWithMaps;return r.replace(/NUM_DIR_LIGHTS/g,e.numDirLights).replace(/NUM_SPOT_LIGHTS/g,e.numSpotLights).replace(/NUM_SPOT_LIGHT_MAPS/g,e.numSpotLightMaps).replace(/NUM_SPOT_LIGHT_COORDS/g,t).replace(/NUM_RECT_AREA_LIGHTS/g,e.numRectAreaLights).replace(/NUM_POINT_LIGHTS/g,e.numPointLights).replace(/NUM_HEMI_LIGHTS/g,e.numHemiLights).replace(/NUM_DIR_LIGHT_SHADOWS/g,e.numDirLightShadows).replace(/NUM_SPOT_LIGHT_SHADOWS_WITH_MAPS/g,e.numSpotLightShadowsWithMaps).replace(/NUM_SPOT_LIGHT_SHADOWS/g,e.numSpotLightShadows).replace(/NUM_POINT_LIGHT_SHADOWS/g,e.numPointLightShadows)}function ll(r,e){return r.replace(/NUM_CLIPPING_PLANES/g,e.numClippingPlanes).replace(/UNION_CLIPPING_PLANES/g,e.numClippingPlanes-e.numClipIntersection)}const Ef=/^[ \t]*#include +<([\w\d./]+)>/gm;function ds(r){return r.replace(Ef,yf)}const Tf=new Map;function yf(r,e){let t=De[e];if(t===void 0){const i=Tf.get(e);if(i!==void 0)t=De[i],Ae('WebGLRenderer: Shader chunk "%s" has been deprecated. Use "%s" instead.',e,i);else throw new Error("Can not resolve #include <"+e+">")}return ds(t)}const bf=/#pragma unroll_loop_start\s+for\s*\(\s*int\s+i\s*=\s*(\d+)\s*;\s*i\s*<\s*(\d+)\s*;\s*i\s*\+\+\s*\)\s*{([\s\S]+?)}\s+#pragma unroll_loop_end/g;function cl(r){return r.replace(bf,Af)}function Af(r,e,t,i){let n="";for(let a=parseInt(e);a<parseInt(t);a++)n+=i.replace(/\[\s*i\s*\]/g,"[ "+a+" ]").replace(/UNROLLED_LOOP_INDEX/g,a);return n}function ul(r){let e=`precision ${r.precision} float;
	precision ${r.precision} int;
	precision ${r.precision} sampler2D;
	precision ${r.precision} samplerCube;
	precision ${r.precision} sampler3D;
	precision ${r.precision} sampler2DArray;
	precision ${r.precision} sampler2DShadow;
	precision ${r.precision} samplerCubeShadow;
	precision ${r.precision} sampler2DArrayShadow;
	precision ${r.precision} isampler2D;
	precision ${r.precision} isampler3D;
	precision ${r.precision} isamplerCube;
	precision ${r.precision} isampler2DArray;
	precision ${r.precision} usampler2D;
	precision ${r.precision} usampler3D;
	precision ${r.precision} usamplerCube;
	precision ${r.precision} usampler2DArray;
	`;return r.precision==="highp"?e+=`
#define HIGH_PRECISION`:r.precision==="mediump"?e+=`
#define MEDIUM_PRECISION`:r.precision==="lowp"&&(e+=`
#define LOW_PRECISION`),e}const wf={[Fr]:"SHADOWMAP_TYPE_PCF",[vr]:"SHADOWMAP_TYPE_VSM"};function Rf(r){return wf[r.shadowMapType]||"SHADOWMAP_TYPE_BASIC"}const Cf={[Li]:"ENVMAP_TYPE_CUBE",[Ji]:"ENVMAP_TYPE_CUBE",[Or]:"ENVMAP_TYPE_CUBE_UV"};function Pf(r){return r.envMap===!1?"ENVMAP_TYPE_CUBE":Cf[r.envMapMode]||"ENVMAP_TYPE_CUBE"}const Uf={[Ji]:"ENVMAP_MODE_REFRACTION"};function Df(r){return r.envMap===!1?"ENVMAP_MODE_REFLECTION":Uf[r.envMapMode]||"ENVMAP_MODE_REFLECTION"}const If={[Bs]:"ENVMAP_BLENDING_MULTIPLY",[Ec]:"ENVMAP_BLENDING_MIX",[Tc]:"ENVMAP_BLENDING_ADD"};function Lf(r){return r.envMap===!1?"ENVMAP_BLENDING_NONE":If[r.combine]||"ENVMAP_BLENDING_NONE"}function Nf(r){const e=r.envMapCubeUVHeight;if(e===null)return null;const t=Math.log2(e)-2,i=1/e;return{texelWidth:1/(3*Math.max(Math.pow(2,t),7*16)),texelHeight:i,maxMip:t}}function Ff(r,e,t,i){const n=r.getContext(),a=t.defines;let s=t.vertexShader,o=t.fragmentShader;const c=Rf(t),l=Pf(t),d=Df(t),m=Lf(t),u=Nf(t),g=xf(t),x=Mf(a),E=n.createProgram();let p,h,S=t.glslVersion?"#version "+t.glslVersion+`
`:"";t.isRawShaderMaterial?(p=["#define SHADER_TYPE "+t.shaderType,"#define SHADER_NAME "+t.shaderName,x].filter(Pr).join(`
`),p.length>0&&(p+=`
`),h=["#define SHADER_TYPE "+t.shaderType,"#define SHADER_NAME "+t.shaderName,x].filter(Pr).join(`
`),h.length>0&&(h+=`
`)):(p=[ul(t),"#define SHADER_TYPE "+t.shaderType,"#define SHADER_NAME "+t.shaderName,x,t.extensionClipCullDistance?"#define USE_CLIP_DISTANCE":"",t.batching?"#define USE_BATCHING":"",t.batchingColor?"#define USE_BATCHING_COLOR":"",t.instancing?"#define USE_INSTANCING":"",t.instancingColor?"#define USE_INSTANCING_COLOR":"",t.instancingMorph?"#define USE_INSTANCING_MORPH":"",t.useFog&&t.fog?"#define USE_FOG":"",t.useFog&&t.fogExp2?"#define FOG_EXP2":"",t.map?"#define USE_MAP":"",t.envMap?"#define USE_ENVMAP":"",t.envMap?"#define "+d:"",t.lightMap?"#define USE_LIGHTMAP":"",t.aoMap?"#define USE_AOMAP":"",t.bumpMap?"#define USE_BUMPMAP":"",t.normalMap?"#define USE_NORMALMAP":"",t.normalMapObjectSpace?"#define USE_NORMALMAP_OBJECTSPACE":"",t.normalMapTangentSpace?"#define USE_NORMALMAP_TANGENTSPACE":"",t.displacementMap?"#define USE_DISPLACEMENTMAP":"",t.emissiveMap?"#define USE_EMISSIVEMAP":"",t.anisotropy?"#define USE_ANISOTROPY":"",t.anisotropyMap?"#define USE_ANISOTROPYMAP":"",t.clearcoatMap?"#define USE_CLEARCOATMAP":"",t.clearcoatRoughnessMap?"#define USE_CLEARCOAT_ROUGHNESSMAP":"",t.clearcoatNormalMap?"#define USE_CLEARCOAT_NORMALMAP":"",t.iridescenceMap?"#define USE_IRIDESCENCEMAP":"",t.iridescenceThicknessMap?"#define USE_IRIDESCENCE_THICKNESSMAP":"",t.specularMap?"#define USE_SPECULARMAP":"",t.specularColorMap?"#define USE_SPECULAR_COLORMAP":"",t.specularIntensityMap?"#define USE_SPECULAR_INTENSITYMAP":"",t.roughnessMap?"#define USE_ROUGHNESSMAP":"",t.metalnessMap?"#define USE_METALNESSMAP":"",t.alphaMap?"#define USE_ALPHAMAP":"",t.alphaHash?"#define USE_ALPHAHASH":"",t.transmission?"#define USE_TRANSMISSION":"",t.transmissionMap?"#define USE_TRANSMISSIONMAP":"",t.thicknessMap?"#define USE_THICKNESSMAP":"",t.sheenColorMap?"#define USE_SHEEN_COLORMAP":"",t.sheenRoughnessMap?"#define USE_SHEEN_ROUGHNESSMAP":"",t.mapUv?"#define MAP_UV "+t.mapUv:"",t.alphaMapUv?"#define ALPHAMAP_UV "+t.alphaMapUv:"",t.lightMapUv?"#define LIGHTMAP_UV "+t.lightMapUv:"",t.aoMapUv?"#define AOMAP_UV "+t.aoMapUv:"",t.emissiveMapUv?"#define EMISSIVEMAP_UV "+t.emissiveMapUv:"",t.bumpMapUv?"#define BUMPMAP_UV "+t.bumpMapUv:"",t.normalMapUv?"#define NORMALMAP_UV "+t.normalMapUv:"",t.displacementMapUv?"#define DISPLACEMENTMAP_UV "+t.displacementMapUv:"",t.metalnessMapUv?"#define METALNESSMAP_UV "+t.metalnessMapUv:"",t.roughnessMapUv?"#define ROUGHNESSMAP_UV "+t.roughnessMapUv:"",t.anisotropyMapUv?"#define ANISOTROPYMAP_UV "+t.anisotropyMapUv:"",t.clearcoatMapUv?"#define CLEARCOATMAP_UV "+t.clearcoatMapUv:"",t.clearcoatNormalMapUv?"#define CLEARCOAT_NORMALMAP_UV "+t.clearcoatNormalMapUv:"",t.clearcoatRoughnessMapUv?"#define CLEARCOAT_ROUGHNESSMAP_UV "+t.clearcoatRoughnessMapUv:"",t.iridescenceMapUv?"#define IRIDESCENCEMAP_UV "+t.iridescenceMapUv:"",t.iridescenceThicknessMapUv?"#define IRIDESCENCE_THICKNESSMAP_UV "+t.iridescenceThicknessMapUv:"",t.sheenColorMapUv?"#define SHEEN_COLORMAP_UV "+t.sheenColorMapUv:"",t.sheenRoughnessMapUv?"#define SHEEN_ROUGHNESSMAP_UV "+t.sheenRoughnessMapUv:"",t.specularMapUv?"#define SPECULARMAP_UV "+t.specularMapUv:"",t.specularColorMapUv?"#define SPECULAR_COLORMAP_UV "+t.specularColorMapUv:"",t.specularIntensityMapUv?"#define SPECULAR_INTENSITYMAP_UV "+t.specularIntensityMapUv:"",t.transmissionMapUv?"#define TRANSMISSIONMAP_UV "+t.transmissionMapUv:"",t.thicknessMapUv?"#define THICKNESSMAP_UV "+t.thicknessMapUv:"",t.vertexTangents&&t.flatShading===!1?"#define USE_TANGENT":"",t.vertexNormals?"#define HAS_NORMAL":"",t.vertexColors?"#define USE_COLOR":"",t.vertexAlphas?"#define USE_COLOR_ALPHA":"",t.vertexUv1s?"#define USE_UV1":"",t.vertexUv2s?"#define USE_UV2":"",t.vertexUv3s?"#define USE_UV3":"",t.pointsUvs?"#define USE_POINTS_UV":"",t.flatShading?"#define FLAT_SHADED":"",t.skinning?"#define USE_SKINNING":"",t.morphTargets?"#define USE_MORPHTARGETS":"",t.morphNormals&&t.flatShading===!1?"#define USE_MORPHNORMALS":"",t.morphColors?"#define USE_MORPHCOLORS":"",t.morphTargetsCount>0?"#define MORPHTARGETS_TEXTURE_STRIDE "+t.morphTextureStride:"",t.morphTargetsCount>0?"#define MORPHTARGETS_COUNT "+t.morphTargetsCount:"",t.doubleSided?"#define DOUBLE_SIDED":"",t.flipSided?"#define FLIP_SIDED":"",t.shadowMapEnabled?"#define USE_SHADOWMAP":"",t.shadowMapEnabled?"#define "+c:"",t.sizeAttenuation?"#define USE_SIZEATTENUATION":"",t.numLightProbes>0?"#define USE_LIGHT_PROBES":"",t.logarithmicDepthBuffer?"#define USE_LOGARITHMIC_DEPTH_BUFFER":"",t.reversedDepthBuffer?"#define USE_REVERSED_DEPTH_BUFFER":"","uniform mat4 modelMatrix;","uniform mat4 modelViewMatrix;","uniform mat4 projectionMatrix;","uniform mat4 viewMatrix;","uniform mat3 normalMatrix;","uniform vec3 cameraPosition;","uniform bool isOrthographic;","#ifdef USE_INSTANCING","	attribute mat4 instanceMatrix;","#endif","#ifdef USE_INSTANCING_COLOR","	attribute vec3 instanceColor;","#endif","#ifdef USE_INSTANCING_MORPH","	uniform sampler2D morphTexture;","#endif","attribute vec3 position;","attribute vec3 normal;","attribute vec2 uv;","#ifdef USE_UV1","	attribute vec2 uv1;","#endif","#ifdef USE_UV2","	attribute vec2 uv2;","#endif","#ifdef USE_UV3","	attribute vec2 uv3;","#endif","#ifdef USE_TANGENT","	attribute vec4 tangent;","#endif","#if defined( USE_COLOR_ALPHA )","	attribute vec4 color;","#elif defined( USE_COLOR )","	attribute vec3 color;","#endif","#ifdef USE_SKINNING","	attribute vec4 skinIndex;","	attribute vec4 skinWeight;","#endif",`
`].filter(Pr).join(`
`),h=[ul(t),"#define SHADER_TYPE "+t.shaderType,"#define SHADER_NAME "+t.shaderName,x,t.useFog&&t.fog?"#define USE_FOG":"",t.useFog&&t.fogExp2?"#define FOG_EXP2":"",t.alphaToCoverage?"#define ALPHA_TO_COVERAGE":"",t.map?"#define USE_MAP":"",t.matcap?"#define USE_MATCAP":"",t.envMap?"#define USE_ENVMAP":"",t.envMap?"#define "+l:"",t.envMap?"#define "+d:"",t.envMap?"#define "+m:"",u?"#define CUBEUV_TEXEL_WIDTH "+u.texelWidth:"",u?"#define CUBEUV_TEXEL_HEIGHT "+u.texelHeight:"",u?"#define CUBEUV_MAX_MIP "+u.maxMip+".0":"",t.lightMap?"#define USE_LIGHTMAP":"",t.aoMap?"#define USE_AOMAP":"",t.bumpMap?"#define USE_BUMPMAP":"",t.normalMap?"#define USE_NORMALMAP":"",t.normalMapObjectSpace?"#define USE_NORMALMAP_OBJECTSPACE":"",t.normalMapTangentSpace?"#define USE_NORMALMAP_TANGENTSPACE":"",t.packedNormalMap?"#define USE_PACKED_NORMALMAP":"",t.emissiveMap?"#define USE_EMISSIVEMAP":"",t.anisotropy?"#define USE_ANISOTROPY":"",t.anisotropyMap?"#define USE_ANISOTROPYMAP":"",t.clearcoat?"#define USE_CLEARCOAT":"",t.clearcoatMap?"#define USE_CLEARCOATMAP":"",t.clearcoatRoughnessMap?"#define USE_CLEARCOAT_ROUGHNESSMAP":"",t.clearcoatNormalMap?"#define USE_CLEARCOAT_NORMALMAP":"",t.dispersion?"#define USE_DISPERSION":"",t.iridescence?"#define USE_IRIDESCENCE":"",t.iridescenceMap?"#define USE_IRIDESCENCEMAP":"",t.iridescenceThicknessMap?"#define USE_IRIDESCENCE_THICKNESSMAP":"",t.specularMap?"#define USE_SPECULARMAP":"",t.specularColorMap?"#define USE_SPECULAR_COLORMAP":"",t.specularIntensityMap?"#define USE_SPECULAR_INTENSITYMAP":"",t.roughnessMap?"#define USE_ROUGHNESSMAP":"",t.metalnessMap?"#define USE_METALNESSMAP":"",t.alphaMap?"#define USE_ALPHAMAP":"",t.alphaTest?"#define USE_ALPHATEST":"",t.alphaHash?"#define USE_ALPHAHASH":"",t.sheen?"#define USE_SHEEN":"",t.sheenColorMap?"#define USE_SHEEN_COLORMAP":"",t.sheenRoughnessMap?"#define USE_SHEEN_ROUGHNESSMAP":"",t.transmission?"#define USE_TRANSMISSION":"",t.transmissionMap?"#define USE_TRANSMISSIONMAP":"",t.thicknessMap?"#define USE_THICKNESSMAP":"",t.vertexTangents&&t.flatShading===!1?"#define USE_TANGENT":"",t.vertexColors||t.instancingColor?"#define USE_COLOR":"",t.vertexAlphas||t.batchingColor?"#define USE_COLOR_ALPHA":"",t.vertexUv1s?"#define USE_UV1":"",t.vertexUv2s?"#define USE_UV2":"",t.vertexUv3s?"#define USE_UV3":"",t.pointsUvs?"#define USE_POINTS_UV":"",t.gradientMap?"#define USE_GRADIENTMAP":"",t.flatShading?"#define FLAT_SHADED":"",t.doubleSided?"#define DOUBLE_SIDED":"",t.flipSided?"#define FLIP_SIDED":"",t.shadowMapEnabled?"#define USE_SHADOWMAP":"",t.shadowMapEnabled?"#define "+c:"",t.premultipliedAlpha?"#define PREMULTIPLIED_ALPHA":"",t.numLightProbes>0?"#define USE_LIGHT_PROBES":"",t.numLightProbeGrids>0?"#define USE_LIGHT_PROBES_GRID":"",t.decodeVideoTexture?"#define DECODE_VIDEO_TEXTURE":"",t.decodeVideoTextureEmissive?"#define DECODE_VIDEO_TEXTURE_EMISSIVE":"",t.logarithmicDepthBuffer?"#define USE_LOGARITHMIC_DEPTH_BUFFER":"",t.reversedDepthBuffer?"#define USE_REVERSED_DEPTH_BUFFER":"","uniform mat4 viewMatrix;","uniform vec3 cameraPosition;","uniform bool isOrthographic;",t.toneMapping!==qt?"#define TONE_MAPPING":"",t.toneMapping!==qt?De.tonemapping_pars_fragment:"",t.toneMapping!==qt?_f("toneMapping",t.toneMapping):"",t.dithering?"#define DITHERING":"",t.opaque?"#define OPAQUE":"",De.colorspace_pars_fragment,mf("linearToOutputTexel",t.outputColorSpace),vf(),t.useDepthPacking?"#define DEPTH_PACKING "+t.depthPacking:"",`
`].filter(Pr).join(`
`)),s=ds(s),s=ol(s,t),s=ll(s,t),o=ds(o),o=ol(o,t),o=ll(o,t),s=cl(s),o=cl(o),t.isRawShaderMaterial!==!0&&(S=`#version 300 es
`,p=[g,"#define attribute in","#define varying out","#define texture2D texture"].join(`
`)+`
`+p,h=["#define varying in",t.glslVersion===ro?"":"layout(location = 0) out highp vec4 pc_fragColor;",t.glslVersion===ro?"":"#define gl_FragColor pc_fragColor","#define gl_FragDepthEXT gl_FragDepth","#define texture2D texture","#define textureCube texture","#define texture2DProj textureProj","#define texture2DLodEXT textureLod","#define texture2DProjLodEXT textureProjLod","#define textureCubeLodEXT textureLod","#define texture2DGradEXT textureGrad","#define texture2DProjGradEXT textureProjGrad","#define textureCubeGradEXT textureGrad"].join(`
`)+`
`+h);const A=S+p+s,T=S+h+o,U=nl(n,n.VERTEX_SHADER,A),y=nl(n,n.FRAGMENT_SHADER,T);n.attachShader(E,U),n.attachShader(E,y),t.index0AttributeName!==void 0?n.bindAttribLocation(E,0,t.index0AttributeName):t.morphTargets===!0&&n.bindAttribLocation(E,0,"position"),n.linkProgram(E);function C(w){if(r.debug.checkShaderErrors){const N=n.getProgramInfoLog(E)||"",W=n.getShaderInfoLog(U)||"",q=n.getShaderInfoLog(y)||"",L=N.trim(),V=W.trim(),H=q.trim();let Z=!0,Q=!0;if(n.getProgramParameter(E,n.LINK_STATUS)===!1)if(Z=!1,typeof r.debug.onShaderError=="function")r.debug.onShaderError(n,E,U,y);else{const re=sl(n,U,"vertex"),ve=sl(n,y,"fragment");He("THREE.WebGLProgram: Shader Error "+n.getError()+" - VALIDATE_STATUS "+n.getProgramParameter(E,n.VALIDATE_STATUS)+`

Material Name: `+w.name+`
Material Type: `+w.type+`

Program Info Log: `+L+`
`+re+`
`+ve)}else L!==""?Ae("WebGLProgram: Program Info Log:",L):(V===""||H==="")&&(Q=!1);Q&&(w.diagnostics={runnable:Z,programLog:L,vertexShader:{log:V,prefix:p},fragmentShader:{log:H,prefix:h}})}n.deleteShader(U),n.deleteShader(y),v=new En(n,E),b=Sf(n,E)}let v;this.getUniforms=function(){return v===void 0&&C(this),v};let b;this.getAttributes=function(){return b===void 0&&C(this),b};let F=t.rendererExtensionParallelShaderCompile===!1;return this.isReady=function(){return F===!1&&(F=n.getProgramParameter(E,hf)),F},this.destroy=function(){i.releaseStatesOfProgram(this),n.deleteProgram(E),this.program=void 0},this.type=t.shaderType,this.name=t.shaderName,this.id=df++,this.cacheKey=e,this.usedTimes=1,this.program=E,this.vertexShader=U,this.fragmentShader=y,this}let Of=0;class Bf{constructor(){this.shaderCache=new Map,this.materialCache=new Map}update(e){const t=e.vertexShader,i=e.fragmentShader,n=this._getShaderStage(t),a=this._getShaderStage(i),s=this._getShaderCacheForMaterial(e);return s.has(n)===!1&&(s.add(n),n.usedTimes++),s.has(a)===!1&&(s.add(a),a.usedTimes++),this}remove(e){const t=this.materialCache.get(e);for(const i of t)i.usedTimes--,i.usedTimes===0&&this.shaderCache.delete(i.code);return this.materialCache.delete(e),this}getVertexShaderID(e){return this._getShaderStage(e.vertexShader).id}getFragmentShaderID(e){return this._getShaderStage(e.fragmentShader).id}dispose(){this.shaderCache.clear(),this.materialCache.clear()}_getShaderCacheForMaterial(e){const t=this.materialCache;let i=t.get(e);return i===void 0&&(i=new Set,t.set(e,i)),i}_getShaderStage(e){const t=this.shaderCache;let i=t.get(e);return i===void 0&&(i=new zf(e),t.set(e,i)),i}}class zf{constructor(e){this.id=Of++,this.code=e,this.usedTimes=0}}function Gf(r){return r===Oi||r===kr||r===Wr}function Hf(r,e,t,i,n,a){const s=new fo,o=new Bf,c=new Set,l=[],d=new Map,m=i.logarithmicDepthBuffer;let u=i.precision;const g={MeshDepthMaterial:"depth",MeshDistanceMaterial:"distance",MeshNormalMaterial:"normal",MeshBasicMaterial:"basic",MeshLambertMaterial:"lambert",MeshPhongMaterial:"phong",MeshToonMaterial:"toon",MeshStandardMaterial:"physical",MeshPhysicalMaterial:"physical",MeshMatcapMaterial:"matcap",LineBasicMaterial:"basic",LineDashedMaterial:"dashed",PointsMaterial:"points",ShadowMaterial:"shadow",SpriteMaterial:"sprite"};function x(v){return c.add(v),v===0?"uv":`uv${v}`}function E(v,b,F,w,N,W){const q=w.fog,L=N.geometry,V=v.isMeshStandardMaterial||v.isMeshLambertMaterial||v.isMeshPhongMaterial?w.environment:null,H=v.isMeshStandardMaterial||v.isMeshLambertMaterial&&!v.envMap||v.isMeshPhongMaterial&&!v.envMap,Z=e.get(v.envMap||V,H),Q=Z&&Z.mapping===Or?Z.image.height:null,re=g[v.type];v.precision!==null&&(u=i.getMaxPrecision(v.precision),u!==v.precision&&Ae("WebGLProgram.getParameters:",v.precision,"not supported, using",u,"instead."));const ve=L.morphAttributes.position||L.morphAttributes.normal||L.morphAttributes.color,we=ve!==void 0?ve.length:0;let Ge=0;L.morphAttributes.position!==void 0&&(Ge=1),L.morphAttributes.normal!==void 0&&(Ge=2),L.morphAttributes.color!==void 0&&(Ge=3);let Ye,Ue,j,oe;if(re){const ye=ei[re];Ye=ye.vertexShader,Ue=ye.fragmentShader}else Ye=v.vertexShader,Ue=v.fragmentShader,o.update(v),j=o.getVertexShaderID(v),oe=o.getFragmentShaderID(v);const ne=r.getRenderTarget(),Te=r.state.buffers.depth.getReversed(),Pe=N.isInstancedMesh===!0,fe=N.isBatchedMesh===!0,Ve=!!v.map,ke=!!v.matcap,Le=!!Z,gt=!!v.aoMap,ft=!!v.lightMap,St=!!v.bumpMap,tt=!!v.normalMap,Rt=!!v.displacementMap,P=!!v.emissiveMap,ct=!!v.metalnessMap,Ne=!!v.roughnessMap,Ze=v.anisotropy>0,le=v.clearcoat>0,rt=v.dispersion>0,M=v.iridescence>0,f=v.sheen>0,O=v.transmission>0,Y=Ze&&!!v.anisotropyMap,K=le&&!!v.clearcoatMap,ae=le&&!!v.clearcoatNormalMap,se=le&&!!v.clearcoatRoughnessMap,D=M&&!!v.iridescenceMap,ie=M&&!!v.iridescenceThicknessMap,ce=f&&!!v.sheenColorMap,pe=f&&!!v.sheenRoughnessMap,J=!!v.specularMap,Se=!!v.specularColorMap,Re=!!v.specularIntensityMap,Oe=O&&!!v.transmissionMap,We=O&&!!v.thicknessMap,R=!!v.gradientMap,X=!!v.alphaMap,ee=v.alphaTest>0,xe=!!v.alphaHash,ue=!!v.extensions;let $=qt;v.toneMapped&&(ne===null||ne.isXRRenderTarget===!0)&&($=r.toneMapping);const Me={shaderID:re,shaderType:v.type,shaderName:v.name,vertexShader:Ye,fragmentShader:Ue,defines:v.defines,customVertexShaderID:j,customFragmentShaderID:oe,isRawShaderMaterial:v.isRawShaderMaterial===!0,glslVersion:v.glslVersion,precision:u,batching:fe,batchingColor:fe&&N._colorsTexture!==null,instancing:Pe,instancingColor:Pe&&N.instanceColor!==null,instancingMorph:Pe&&N.morphTexture!==null,outputColorSpace:ne===null?r.outputColorSpace:ne.isXRRenderTarget===!0?ne.texture.colorSpace:ze.workingColorSpace,alphaToCoverage:!!v.alphaToCoverage,map:Ve,matcap:ke,envMap:Le,envMapMode:Le&&Z.mapping,envMapCubeUVHeight:Q,aoMap:gt,lightMap:ft,bumpMap:St,normalMap:tt,displacementMap:Rt,emissiveMap:P,normalMapObjectSpace:tt&&v.normalMapType===Ac,normalMapTangentSpace:tt&&v.normalMapType===eo,packedNormalMap:tt&&v.normalMapType===eo&&Gf(v.normalMap.format),metalnessMap:ct,roughnessMap:Ne,anisotropy:Ze,anisotropyMap:Y,clearcoat:le,clearcoatMap:K,clearcoatNormalMap:ae,clearcoatRoughnessMap:se,dispersion:rt,iridescence:M,iridescenceMap:D,iridescenceThicknessMap:ie,sheen:f,sheenColorMap:ce,sheenRoughnessMap:pe,specularMap:J,specularColorMap:Se,specularIntensityMap:Re,transmission:O,transmissionMap:Oe,thicknessMap:We,gradientMap:R,opaque:v.transparent===!1&&v.blending===ji&&v.alphaToCoverage===!1,alphaMap:X,alphaTest:ee,alphaHash:xe,combine:v.combine,mapUv:Ve&&x(v.map.channel),aoMapUv:gt&&x(v.aoMap.channel),lightMapUv:ft&&x(v.lightMap.channel),bumpMapUv:St&&x(v.bumpMap.channel),normalMapUv:tt&&x(v.normalMap.channel),displacementMapUv:Rt&&x(v.displacementMap.channel),emissiveMapUv:P&&x(v.emissiveMap.channel),metalnessMapUv:ct&&x(v.metalnessMap.channel),roughnessMapUv:Ne&&x(v.roughnessMap.channel),anisotropyMapUv:Y&&x(v.anisotropyMap.channel),clearcoatMapUv:K&&x(v.clearcoatMap.channel),clearcoatNormalMapUv:ae&&x(v.clearcoatNormalMap.channel),clearcoatRoughnessMapUv:se&&x(v.clearcoatRoughnessMap.channel),iridescenceMapUv:D&&x(v.iridescenceMap.channel),iridescenceThicknessMapUv:ie&&x(v.iridescenceThicknessMap.channel),sheenColorMapUv:ce&&x(v.sheenColorMap.channel),sheenRoughnessMapUv:pe&&x(v.sheenRoughnessMap.channel),specularMapUv:J&&x(v.specularMap.channel),specularColorMapUv:Se&&x(v.specularColorMap.channel),specularIntensityMapUv:Re&&x(v.specularIntensityMap.channel),transmissionMapUv:Oe&&x(v.transmissionMap.channel),thicknessMapUv:We&&x(v.thicknessMap.channel),alphaMapUv:X&&x(v.alphaMap.channel),vertexTangents:!!L.attributes.tangent&&(tt||Ze),vertexNormals:!!L.attributes.normal,vertexColors:v.vertexColors,vertexAlphas:v.vertexColors===!0&&!!L.attributes.color&&L.attributes.color.itemSize===4,pointsUvs:N.isPoints===!0&&!!L.attributes.uv&&(Ve||X),fog:!!q,useFog:v.fog===!0,fogExp2:!!q&&q.isFogExp2,flatShading:v.wireframe===!1&&(v.flatShading===!0||L.attributes.normal===void 0&&tt===!1&&(v.isMeshLambertMaterial||v.isMeshPhongMaterial||v.isMeshStandardMaterial||v.isMeshPhysicalMaterial)),sizeAttenuation:v.sizeAttenuation===!0,logarithmicDepthBuffer:m,reversedDepthBuffer:Te,skinning:N.isSkinnedMesh===!0,morphTargets:L.morphAttributes.position!==void 0,morphNormals:L.morphAttributes.normal!==void 0,morphColors:L.morphAttributes.color!==void 0,morphTargetsCount:we,morphTextureStride:Ge,numDirLights:b.directional.length,numPointLights:b.point.length,numSpotLights:b.spot.length,numSpotLightMaps:b.spotLightMap.length,numRectAreaLights:b.rectArea.length,numHemiLights:b.hemi.length,numDirLightShadows:b.directionalShadowMap.length,numPointLightShadows:b.pointShadowMap.length,numSpotLightShadows:b.spotShadowMap.length,numSpotLightShadowsWithMaps:b.numSpotLightShadowsWithMaps,numLightProbes:b.numLightProbes,numLightProbeGrids:W.length,numClippingPlanes:a.numPlanes,numClipIntersection:a.numIntersection,dithering:v.dithering,shadowMapEnabled:r.shadowMap.enabled&&F.length>0,shadowMapType:r.shadowMap.type,toneMapping:$,decodeVideoTexture:Ve&&v.map.isVideoTexture===!0&&ze.getTransfer(v.map.colorSpace)===Xe,decodeVideoTextureEmissive:P&&v.emissiveMap.isVideoTexture===!0&&ze.getTransfer(v.emissiveMap.colorSpace)===Xe,premultipliedAlpha:v.premultipliedAlpha,doubleSided:v.side===ai,flipSided:v.side===bt,useDepthPacking:v.depthPacking>=0,depthPacking:v.depthPacking||0,index0AttributeName:v.index0AttributeName,extensionClipCullDistance:ue&&v.extensions.clipCullDistance===!0&&t.has("WEBGL_clip_cull_distance"),extensionMultiDraw:(ue&&v.extensions.multiDraw===!0||fe)&&t.has("WEBGL_multi_draw"),rendererExtensionParallelShaderCompile:t.has("KHR_parallel_shader_compile"),customProgramCacheKey:v.customProgramCacheKey()};return Me.vertexUv1s=c.has(1),Me.vertexUv2s=c.has(2),Me.vertexUv3s=c.has(3),c.clear(),Me}function p(v){const b=[];if(v.shaderID?b.push(v.shaderID):(b.push(v.customVertexShaderID),b.push(v.customFragmentShaderID)),v.defines!==void 0)for(const F in v.defines)b.push(F),b.push(v.defines[F]);return v.isRawShaderMaterial===!1&&(h(b,v),S(b,v),b.push(r.outputColorSpace)),b.push(v.customProgramCacheKey),b.join()}function h(v,b){v.push(b.precision),v.push(b.outputColorSpace),v.push(b.envMapMode),v.push(b.envMapCubeUVHeight),v.push(b.mapUv),v.push(b.alphaMapUv),v.push(b.lightMapUv),v.push(b.aoMapUv),v.push(b.bumpMapUv),v.push(b.normalMapUv),v.push(b.displacementMapUv),v.push(b.emissiveMapUv),v.push(b.metalnessMapUv),v.push(b.roughnessMapUv),v.push(b.anisotropyMapUv),v.push(b.clearcoatMapUv),v.push(b.clearcoatNormalMapUv),v.push(b.clearcoatRoughnessMapUv),v.push(b.iridescenceMapUv),v.push(b.iridescenceThicknessMapUv),v.push(b.sheenColorMapUv),v.push(b.sheenRoughnessMapUv),v.push(b.specularMapUv),v.push(b.specularColorMapUv),v.push(b.specularIntensityMapUv),v.push(b.transmissionMapUv),v.push(b.thicknessMapUv),v.push(b.combine),v.push(b.fogExp2),v.push(b.sizeAttenuation),v.push(b.morphTargetsCount),v.push(b.morphAttributeCount),v.push(b.numDirLights),v.push(b.numPointLights),v.push(b.numSpotLights),v.push(b.numSpotLightMaps),v.push(b.numHemiLights),v.push(b.numRectAreaLights),v.push(b.numDirLightShadows),v.push(b.numPointLightShadows),v.push(b.numSpotLightShadows),v.push(b.numSpotLightShadowsWithMaps),v.push(b.numLightProbes),v.push(b.shadowMapType),v.push(b.toneMapping),v.push(b.numClippingPlanes),v.push(b.numClipIntersection),v.push(b.depthPacking)}function S(v,b){s.disableAll(),b.instancing&&s.enable(0),b.instancingColor&&s.enable(1),b.instancingMorph&&s.enable(2),b.matcap&&s.enable(3),b.envMap&&s.enable(4),b.normalMapObjectSpace&&s.enable(5),b.normalMapTangentSpace&&s.enable(6),b.clearcoat&&s.enable(7),b.iridescence&&s.enable(8),b.alphaTest&&s.enable(9),b.vertexColors&&s.enable(10),b.vertexAlphas&&s.enable(11),b.vertexUv1s&&s.enable(12),b.vertexUv2s&&s.enable(13),b.vertexUv3s&&s.enable(14),b.vertexTangents&&s.enable(15),b.anisotropy&&s.enable(16),b.alphaHash&&s.enable(17),b.batching&&s.enable(18),b.dispersion&&s.enable(19),b.batchingColor&&s.enable(20),b.gradientMap&&s.enable(21),b.packedNormalMap&&s.enable(22),b.vertexNormals&&s.enable(23),v.push(s.mask),s.disableAll(),b.fog&&s.enable(0),b.useFog&&s.enable(1),b.flatShading&&s.enable(2),b.logarithmicDepthBuffer&&s.enable(3),b.reversedDepthBuffer&&s.enable(4),b.skinning&&s.enable(5),b.morphTargets&&s.enable(6),b.morphNormals&&s.enable(7),b.morphColors&&s.enable(8),b.premultipliedAlpha&&s.enable(9),b.shadowMapEnabled&&s.enable(10),b.doubleSided&&s.enable(11),b.flipSided&&s.enable(12),b.useDepthPacking&&s.enable(13),b.dithering&&s.enable(14),b.transmission&&s.enable(15),b.sheen&&s.enable(16),b.opaque&&s.enable(17),b.pointsUvs&&s.enable(18),b.decodeVideoTexture&&s.enable(19),b.decodeVideoTextureEmissive&&s.enable(20),b.alphaToCoverage&&s.enable(21),b.numLightProbeGrids>0&&s.enable(22),v.push(s.mask)}function A(v){const b=g[v.type];let F;if(b){const w=ei[b];F=uu.clone(w.uniforms)}else F=v.uniforms;return F}function T(v,b){let F=d.get(b);return F!==void 0?++F.usedTimes:(F=new Ff(r,b,v,n),l.push(F),d.set(b,F)),F}function U(v){if(--v.usedTimes===0){const b=l.indexOf(v);l[b]=l[l.length-1],l.pop(),d.delete(v.cacheKey),v.destroy()}}function y(v){o.remove(v)}function C(){o.dispose()}return{getParameters:E,getProgramCacheKey:p,getUniforms:A,acquireProgram:T,releaseProgram:U,releaseShaderCache:y,programs:l,dispose:C}}function Vf(){let r=new WeakMap;function e(s){return r.has(s)}function t(s){let o=r.get(s);return o===void 0&&(o={},r.set(s,o)),o}function i(s){r.delete(s)}function n(s,o,c){r.get(s)[o]=c}function a(){r=new WeakMap}return{has:e,get:t,remove:i,update:n,dispose:a}}function kf(r,e){return r.groupOrder!==e.groupOrder?r.groupOrder-e.groupOrder:r.renderOrder!==e.renderOrder?r.renderOrder-e.renderOrder:r.material.id!==e.material.id?r.material.id-e.material.id:r.materialVariant!==e.materialVariant?r.materialVariant-e.materialVariant:r.z!==e.z?r.z-e.z:r.id-e.id}function hl(r,e){return r.groupOrder!==e.groupOrder?r.groupOrder-e.groupOrder:r.renderOrder!==e.renderOrder?r.renderOrder-e.renderOrder:r.z!==e.z?e.z-r.z:r.id-e.id}function dl(){const r=[];let e=0;const t=[],i=[],n=[];function a(){e=0,t.length=0,i.length=0,n.length=0}function s(u){let g=0;return u.isInstancedMesh&&(g+=2),u.isSkinnedMesh&&(g+=1),g}function o(u,g,x,E,p,h){let S=r[e];return S===void 0?(S={id:u.id,object:u,geometry:g,material:x,materialVariant:s(u),groupOrder:E,renderOrder:u.renderOrder,z:p,group:h},r[e]=S):(S.id=u.id,S.object=u,S.geometry=g,S.material=x,S.materialVariant=s(u),S.groupOrder=E,S.renderOrder=u.renderOrder,S.z=p,S.group=h),e++,S}function c(u,g,x,E,p,h){const S=o(u,g,x,E,p,h);x.transmission>0?i.push(S):x.transparent===!0?n.push(S):t.push(S)}function l(u,g,x,E,p,h){const S=o(u,g,x,E,p,h);x.transmission>0?i.unshift(S):x.transparent===!0?n.unshift(S):t.unshift(S)}function d(u,g){t.length>1&&t.sort(u||kf),i.length>1&&i.sort(g||hl),n.length>1&&n.sort(g||hl)}function m(){for(let u=e,g=r.length;u<g;u++){const x=r[u];if(x.id===null)break;x.id=null,x.object=null,x.geometry=null,x.material=null,x.group=null}}return{opaque:t,transmissive:i,transparent:n,init:a,push:c,unshift:l,finish:m,sort:d}}function Wf(){let r=new WeakMap;function e(i,n){const a=r.get(i);let s;return a===void 0?(s=new dl,r.set(i,[s])):n>=a.length?(s=new dl,a.push(s)):s=a[n],s}function t(){r=new WeakMap}return{get:e,dispose:t}}function Xf(){const r={};return{get:function(e){if(r[e.id]!==void 0)return r[e.id];let t;switch(e.type){case"DirectionalLight":t={direction:new G,color:new qe};break;case"SpotLight":t={position:new G,direction:new G,color:new qe,distance:0,coneCos:0,penumbraCos:0,decay:0};break;case"PointLight":t={position:new G,color:new qe,distance:0,decay:0};break;case"HemisphereLight":t={direction:new G,skyColor:new qe,groundColor:new qe};break;case"RectAreaLight":t={color:new qe,position:new G,halfWidth:new G,halfHeight:new G};break}return r[e.id]=t,t}}}function qf(){const r={};return{get:function(e){if(r[e.id]!==void 0)return r[e.id];let t;switch(e.type){case"DirectionalLight":t={shadowIntensity:1,shadowBias:0,shadowNormalBias:0,shadowRadius:1,shadowMapSize:new Ke};break;case"SpotLight":t={shadowIntensity:1,shadowBias:0,shadowNormalBias:0,shadowRadius:1,shadowMapSize:new Ke};break;case"PointLight":t={shadowIntensity:1,shadowBias:0,shadowNormalBias:0,shadowRadius:1,shadowMapSize:new Ke,shadowCameraNear:1,shadowCameraFar:1e3};break}return r[e.id]=t,t}}}let Yf=0;function jf(r,e){return(e.castShadow?2:0)-(r.castShadow?2:0)+(e.map?1:0)-(r.map?1:0)}function Kf(r){const e=new Xf,t=qf(),i={version:0,hash:{directionalLength:-1,pointLength:-1,spotLength:-1,rectAreaLength:-1,hemiLength:-1,numDirectionalShadows:-1,numPointShadows:-1,numSpotShadows:-1,numSpotMaps:-1,numLightProbes:-1},ambient:[0,0,0],probe:[],directional:[],directionalShadow:[],directionalShadowMap:[],directionalShadowMatrix:[],spot:[],spotLightMap:[],spotShadow:[],spotShadowMap:[],spotLightMatrix:[],rectArea:[],rectAreaLTC1:null,rectAreaLTC2:null,point:[],pointShadow:[],pointShadowMap:[],pointShadowMatrix:[],hemi:[],numSpotLightShadowsWithMaps:0,numLightProbes:0};for(let l=0;l<9;l++)i.probe.push(new G);const n=new G,a=new ht,s=new ht;function o(l){let d=0,m=0,u=0;for(let b=0;b<9;b++)i.probe[b].set(0,0,0);let g=0,x=0,E=0,p=0,h=0,S=0,A=0,T=0,U=0,y=0,C=0;l.sort(jf);for(let b=0,F=l.length;b<F;b++){const w=l[b],N=w.color,W=w.intensity,q=w.distance;let L=null;if(w.shadow&&w.shadow.map&&(w.shadow.map.texture.format===Oi?L=w.shadow.map.texture:L=w.shadow.map.depthTexture||w.shadow.map.texture),w.isAmbientLight)d+=N.r*W,m+=N.g*W,u+=N.b*W;else if(w.isLightProbe){for(let V=0;V<9;V++)i.probe[V].addScaledVector(w.sh.coefficients[V],W);C++}else if(w.isDirectionalLight){const V=e.get(w);if(V.color.copy(w.color).multiplyScalar(w.intensity),w.castShadow){const H=w.shadow,Z=t.get(w);Z.shadowIntensity=H.intensity,Z.shadowBias=H.bias,Z.shadowNormalBias=H.normalBias,Z.shadowRadius=H.radius,Z.shadowMapSize=H.mapSize,i.directionalShadow[g]=Z,i.directionalShadowMap[g]=L,i.directionalShadowMatrix[g]=w.shadow.matrix,S++}i.directional[g]=V,g++}else if(w.isSpotLight){const V=e.get(w);V.position.setFromMatrixPosition(w.matrixWorld),V.color.copy(N).multiplyScalar(W),V.distance=q,V.coneCos=Math.cos(w.angle),V.penumbraCos=Math.cos(w.angle*(1-w.penumbra)),V.decay=w.decay,i.spot[E]=V;const H=w.shadow;if(w.map&&(i.spotLightMap[U]=w.map,U++,H.updateMatrices(w),w.castShadow&&y++),i.spotLightMatrix[E]=H.matrix,w.castShadow){const Z=t.get(w);Z.shadowIntensity=H.intensity,Z.shadowBias=H.bias,Z.shadowNormalBias=H.normalBias,Z.shadowRadius=H.radius,Z.shadowMapSize=H.mapSize,i.spotShadow[E]=Z,i.spotShadowMap[E]=L,T++}E++}else if(w.isRectAreaLight){const V=e.get(w);V.color.copy(N).multiplyScalar(W),V.halfWidth.set(w.width*.5,0,0),V.halfHeight.set(0,w.height*.5,0),i.rectArea[p]=V,p++}else if(w.isPointLight){const V=e.get(w);if(V.color.copy(w.color).multiplyScalar(w.intensity),V.distance=w.distance,V.decay=w.decay,w.castShadow){const H=w.shadow,Z=t.get(w);Z.shadowIntensity=H.intensity,Z.shadowBias=H.bias,Z.shadowNormalBias=H.normalBias,Z.shadowRadius=H.radius,Z.shadowMapSize=H.mapSize,Z.shadowCameraNear=H.camera.near,Z.shadowCameraFar=H.camera.far,i.pointShadow[x]=Z,i.pointShadowMap[x]=L,i.pointShadowMatrix[x]=w.shadow.matrix,A++}i.point[x]=V,x++}else if(w.isHemisphereLight){const V=e.get(w);V.skyColor.copy(w.color).multiplyScalar(W),V.groundColor.copy(w.groundColor).multiplyScalar(W),i.hemi[h]=V,h++}}p>0&&(r.has("OES_texture_float_linear")===!0?(i.rectAreaLTC1=he.LTC_FLOAT_1,i.rectAreaLTC2=he.LTC_FLOAT_2):(i.rectAreaLTC1=he.LTC_HALF_1,i.rectAreaLTC2=he.LTC_HALF_2)),i.ambient[0]=d,i.ambient[1]=m,i.ambient[2]=u;const v=i.hash;(v.directionalLength!==g||v.pointLength!==x||v.spotLength!==E||v.rectAreaLength!==p||v.hemiLength!==h||v.numDirectionalShadows!==S||v.numPointShadows!==A||v.numSpotShadows!==T||v.numSpotMaps!==U||v.numLightProbes!==C)&&(i.directional.length=g,i.spot.length=E,i.rectArea.length=p,i.point.length=x,i.hemi.length=h,i.directionalShadow.length=S,i.directionalShadowMap.length=S,i.pointShadow.length=A,i.pointShadowMap.length=A,i.spotShadow.length=T,i.spotShadowMap.length=T,i.directionalShadowMatrix.length=S,i.pointShadowMatrix.length=A,i.spotLightMatrix.length=T+U-y,i.spotLightMap.length=U,i.numSpotLightShadowsWithMaps=y,i.numLightProbes=C,v.directionalLength=g,v.pointLength=x,v.spotLength=E,v.rectAreaLength=p,v.hemiLength=h,v.numDirectionalShadows=S,v.numPointShadows=A,v.numSpotShadows=T,v.numSpotMaps=U,v.numLightProbes=C,i.version=Yf++)}function c(l,d){let m=0,u=0,g=0,x=0,E=0;const p=d.matrixWorldInverse;for(let h=0,S=l.length;h<S;h++){const A=l[h];if(A.isDirectionalLight){const T=i.directional[m];T.direction.setFromMatrixPosition(A.matrixWorld),n.setFromMatrixPosition(A.target.matrixWorld),T.direction.sub(n),T.direction.transformDirection(p),m++}else if(A.isSpotLight){const T=i.spot[g];T.position.setFromMatrixPosition(A.matrixWorld),T.position.applyMatrix4(p),T.direction.setFromMatrixPosition(A.matrixWorld),n.setFromMatrixPosition(A.target.matrixWorld),T.direction.sub(n),T.direction.transformDirection(p),g++}else if(A.isRectAreaLight){const T=i.rectArea[x];T.position.setFromMatrixPosition(A.matrixWorld),T.position.applyMatrix4(p),s.identity(),a.copy(A.matrixWorld),a.premultiply(p),s.extractRotation(a),T.halfWidth.set(A.width*.5,0,0),T.halfHeight.set(0,A.height*.5,0),T.halfWidth.applyMatrix4(s),T.halfHeight.applyMatrix4(s),x++}else if(A.isPointLight){const T=i.point[u];T.position.setFromMatrixPosition(A.matrixWorld),T.position.applyMatrix4(p),u++}else if(A.isHemisphereLight){const T=i.hemi[E];T.direction.setFromMatrixPosition(A.matrixWorld),T.direction.transformDirection(p),E++}}}return{setup:o,setupView:c,state:i}}function pl(r){const e=new Kf(r),t=[],i=[],n=[];function a(u){m.camera=u,t.length=0,i.length=0,n.length=0}function s(u){t.push(u)}function o(u){i.push(u)}function c(u){n.push(u)}function l(){e.setup(t)}function d(u){e.setupView(t,u)}const m={lightsArray:t,shadowsArray:i,lightProbeGridArray:n,camera:null,lights:e,transmissionRenderTarget:{},textureUnits:0};return{init:a,state:m,setupLights:l,setupLightsView:d,pushLight:s,pushShadow:o,pushLightProbeGrid:c}}function Jf(r){let e=new WeakMap;function t(n,a=0){const s=e.get(n);let o;return s===void 0?(o=new pl(r),e.set(n,[o])):a>=s.length?(o=new pl(r),s.push(o)):o=s[a],o}function i(){e=new WeakMap}return{get:t,dispose:i}}const Zf=`void main() {
	gl_Position = vec4( position, 1.0 );
}`,$f=`uniform sampler2D shadow_pass;
uniform vec2 resolution;
uniform float radius;
void main() {
	const float samples = float( VSM_SAMPLES );
	float mean = 0.0;
	float squared_mean = 0.0;
	float uvStride = samples <= 1.0 ? 0.0 : 2.0 / ( samples - 1.0 );
	float uvStart = samples <= 1.0 ? 0.0 : - 1.0;
	for ( float i = 0.0; i < samples; i ++ ) {
		float uvOffset = uvStart + i * uvStride;
		#ifdef HORIZONTAL_PASS
			vec2 distribution = texture2D( shadow_pass, ( gl_FragCoord.xy + vec2( uvOffset, 0.0 ) * radius ) / resolution ).rg;
			mean += distribution.x;
			squared_mean += distribution.y * distribution.y + distribution.x * distribution.x;
		#else
			float depth = texture2D( shadow_pass, ( gl_FragCoord.xy + vec2( 0.0, uvOffset ) * radius ) / resolution ).r;
			mean += depth;
			squared_mean += depth * depth;
		#endif
	}
	mean = mean / samples;
	squared_mean = squared_mean / samples;
	float std_dev = sqrt( max( 0.0, squared_mean - mean * mean ) );
	gl_FragColor = vec4( mean, std_dev, 0.0, 1.0 );
}`,Qf=[new G(1,0,0),new G(-1,0,0),new G(0,1,0),new G(0,-1,0),new G(0,0,1),new G(0,0,-1)],em=[new G(0,-1,0),new G(0,-1,0),new G(0,0,1),new G(0,0,-1),new G(0,-1,0),new G(0,-1,0)],fl=new ht,Ur=new G,ps=new G;function tm(r,e,t){let i=new Ro;const n=new Ke,a=new Ke,s=new ot,o=new pu,c=new fu,l={},d=t.maxTextureSize,m={[ni]:bt,[bt]:ni,[ai]:ai},u=new $t({defines:{VSM_SAMPLES:8},uniforms:{shadow_pass:{value:null},resolution:{value:new Ke},radius:{value:4}},vertexShader:Zf,fragmentShader:$f}),g=u.clone();g.defines.HORIZONTAL_PASS=1;const x=new Vt;x.setAttribute("position",new Nt(new Float32Array([-1,-1,.5,3,-1,.5,-1,3,.5]),3));const E=new Zt(x,u),p=this;this.enabled=!1,this.autoUpdate=!0,this.needsUpdate=!1,this.type=Fr;let h=this.type;this.render=function(y,C,v){if(p.enabled===!1||p.autoUpdate===!1&&p.needsUpdate===!1||y.length===0)return;this.type===rc&&(Ae("WebGLShadowMap: PCFSoftShadowMap has been deprecated. Using PCFShadowMap instead."),this.type=Fr);const b=r.getRenderTarget(),F=r.getActiveCubeFace(),w=r.getActiveMipmapLevel(),N=r.state;N.setBlending(si),N.buffers.depth.getReversed()===!0?N.buffers.color.setClear(0,0,0,0):N.buffers.color.setClear(1,1,1,1),N.buffers.depth.setTest(!0),N.setScissorTest(!1);const W=h!==this.type;W&&C.traverse(function(q){q.material&&(Array.isArray(q.material)?q.material.forEach(L=>L.needsUpdate=!0):q.material.needsUpdate=!0)});for(let q=0,L=y.length;q<L;q++){const V=y[q],H=V.shadow;if(H===void 0){Ae("WebGLShadowMap:",V,"has no shadow.");continue}if(H.autoUpdate===!1&&H.needsUpdate===!1)continue;n.copy(H.mapSize);const Z=H.getFrameExtents();n.multiply(Z),a.copy(H.mapSize),(n.x>d||n.y>d)&&(n.x>d&&(a.x=Math.floor(d/Z.x),n.x=a.x*Z.x,H.mapSize.x=a.x),n.y>d&&(a.y=Math.floor(d/Z.y),n.y=a.y*Z.y,H.mapSize.y=a.y));const Q=r.state.buffers.depth.getReversed();if(H.camera._reversedDepth=Q,H.map===null||W===!0){if(H.map!==null&&(H.map.depthTexture!==null&&(H.map.depthTexture.dispose(),H.map.depthTexture=null),H.map.dispose()),this.type===vr){if(V.isPointLight){Ae("WebGLShadowMap: VSM shadow maps are not supported for PointLights. Use PCF or BasicShadowMap instead.");continue}H.map=new Jt(n.x,n.y,{format:Oi,type:li,minFilter:vt,magFilter:vt,generateMipmaps:!1}),H.map.texture.name=V.name+".shadowMap",H.map.depthTexture=new ur(n.x,n.y,jt),H.map.depthTexture.name=V.name+".shadowMapDepth",H.map.depthTexture.format=ci,H.map.depthTexture.compareFunction=null,H.map.depthTexture.minFilter=_t,H.map.depthTexture.magFilter=_t}else V.isPointLight?(H.map=new Yo(n.x),H.map.depthTexture=new lu(n.x,Yt)):(H.map=new Jt(n.x,n.y),H.map.depthTexture=new ur(n.x,n.y,Yt)),H.map.depthTexture.name=V.name+".shadowMap",H.map.depthTexture.format=ci,this.type===Fr?(H.map.depthTexture.compareFunction=Q?Ua:Pa,H.map.depthTexture.minFilter=vt,H.map.depthTexture.magFilter=vt):(H.map.depthTexture.compareFunction=null,H.map.depthTexture.minFilter=_t,H.map.depthTexture.magFilter=_t);H.camera.updateProjectionMatrix()}const re=H.map.isWebGLCubeRenderTarget?6:1;for(let ve=0;ve<re;ve++){if(H.map.isWebGLCubeRenderTarget)r.setRenderTarget(H.map,ve),r.clear();else{ve===0&&(r.setRenderTarget(H.map),r.clear());const we=H.getViewport(ve);s.set(a.x*we.x,a.y*we.y,a.x*we.z,a.y*we.w),N.viewport(s)}if(V.isPointLight){const we=H.camera,Ge=H.matrix,Ye=V.distance||we.far;Ye!==we.far&&(we.far=Ye,we.updateProjectionMatrix()),Ur.setFromMatrixPosition(V.matrixWorld),we.position.copy(Ur),ps.copy(we.position),ps.add(Qf[ve]),we.up.copy(em[ve]),we.lookAt(ps),we.updateMatrixWorld(),Ge.makeTranslation(-Ur.x,-Ur.y,-Ur.z),fl.multiplyMatrices(we.projectionMatrix,we.matrixWorldInverse),H._frustum.setFromProjectionMatrix(fl,we.coordinateSystem,we.reversedDepth)}else H.updateMatrices(V);i=H.getFrustum(),T(C,v,H.camera,V,this.type)}H.isPointLightShadow!==!0&&this.type===vr&&S(H,v),H.needsUpdate=!1}h=this.type,p.needsUpdate=!1,r.setRenderTarget(b,F,w)};function S(y,C){const v=e.update(E);u.defines.VSM_SAMPLES!==y.blurSamples&&(u.defines.VSM_SAMPLES=y.blurSamples,g.defines.VSM_SAMPLES=y.blurSamples,u.needsUpdate=!0,g.needsUpdate=!0),y.mapPass===null&&(y.mapPass=new Jt(n.x,n.y,{format:Oi,type:li})),u.uniforms.shadow_pass.value=y.map.depthTexture,u.uniforms.resolution.value=y.mapSize,u.uniforms.radius.value=y.radius,r.setRenderTarget(y.mapPass),r.clear(),r.renderBufferDirect(C,null,v,u,E,null),g.uniforms.shadow_pass.value=y.mapPass.texture,g.uniforms.resolution.value=y.mapSize,g.uniforms.radius.value=y.radius,r.setRenderTarget(y.map),r.clear(),r.renderBufferDirect(C,null,v,g,E,null)}function A(y,C,v,b){let F=null;const w=v.isPointLight===!0?y.customDistanceMaterial:y.customDepthMaterial;if(w!==void 0)F=w;else if(F=v.isPointLight===!0?c:o,r.localClippingEnabled&&C.clipShadows===!0&&Array.isArray(C.clippingPlanes)&&C.clippingPlanes.length!==0||C.displacementMap&&C.displacementScale!==0||C.alphaMap&&C.alphaTest>0||C.map&&C.alphaTest>0||C.alphaToCoverage===!0){const N=F.uuid,W=C.uuid;let q=l[N];q===void 0&&(q={},l[N]=q);let L=q[W];L===void 0&&(L=F.clone(),q[W]=L,C.addEventListener("dispose",U)),F=L}if(F.visible=C.visible,F.wireframe=C.wireframe,b===vr?F.side=C.shadowSide!==null?C.shadowSide:C.side:F.side=C.shadowSide!==null?C.shadowSide:m[C.side],F.alphaMap=C.alphaMap,F.alphaTest=C.alphaToCoverage===!0?.5:C.alphaTest,F.map=C.map,F.clipShadows=C.clipShadows,F.clippingPlanes=C.clippingPlanes,F.clipIntersection=C.clipIntersection,F.displacementMap=C.displacementMap,F.displacementScale=C.displacementScale,F.displacementBias=C.displacementBias,F.wireframeLinewidth=C.wireframeLinewidth,F.linewidth=C.linewidth,v.isPointLight===!0&&F.isMeshDistanceMaterial===!0){const N=r.properties.get(F);N.light=v}return F}function T(y,C,v,b,F){if(y.visible===!1)return;if(y.layers.test(C.layers)&&(y.isMesh||y.isLine||y.isPoints)&&(y.castShadow||y.receiveShadow&&F===vr)&&(!y.frustumCulled||i.intersectsObject(y))){y.modelViewMatrix.multiplyMatrices(v.matrixWorldInverse,y.matrixWorld);const N=e.update(y),W=y.material;if(Array.isArray(W)){const q=N.groups;for(let L=0,V=q.length;L<V;L++){const H=q[L],Z=W[H.materialIndex];if(Z&&Z.visible){const Q=A(y,Z,b,F);y.onBeforeShadow(r,y,C,v,N,Q,H),r.renderBufferDirect(v,null,N,Q,y,H),y.onAfterShadow(r,y,C,v,N,Q,H)}}}else if(W.visible){const q=A(y,W,b,F);y.onBeforeShadow(r,y,C,v,N,q,null),r.renderBufferDirect(v,null,N,q,y,null),y.onAfterShadow(r,y,C,v,N,q,null)}}const w=y.children;for(let N=0,W=w.length;N<W;N++)T(w[N],C,v,b,F)}function U(y){y.target.removeEventListener("dispose",U);for(const C in l){const v=l[C],b=y.target.uuid;b in v&&(v[b].dispose(),delete v[b])}}}function im(r,e){function t(){let R=!1;const X=new ot;let ee=null;const xe=new ot(0,0,0,0);return{setMask:function(ue){ee!==ue&&!R&&(r.colorMask(ue,ue,ue,ue),ee=ue)},setLocked:function(ue){R=ue},setClear:function(ue,$,Me,ye,Et){Et===!0&&(ue*=ye,$*=ye,Me*=ye),X.set(ue,$,Me,ye),xe.equals(X)===!1&&(r.clearColor(ue,$,Me,ye),xe.copy(X))},reset:function(){R=!1,ee=null,xe.set(-1,0,0,0)}}}function i(){let R=!1,X=!1,ee=null,xe=null,ue=null;return{setReversed:function($){if(X!==$){const Me=e.get("EXT_clip_control");$?Me.clipControlEXT(Me.LOWER_LEFT_EXT,Me.ZERO_TO_ONE_EXT):Me.clipControlEXT(Me.LOWER_LEFT_EXT,Me.NEGATIVE_ONE_TO_ONE_EXT),X=$;const ye=ue;ue=null,this.setClear(ye)}},getReversed:function(){return X},setTest:function($){$?ne(r.DEPTH_TEST):Te(r.DEPTH_TEST)},setMask:function($){ee!==$&&!R&&(r.depthMask($),ee=$)},setFunc:function($){if(X&&($=Fc[$]),xe!==$){switch($){case Fn:r.depthFunc(r.NEVER);break;case On:r.depthFunc(r.ALWAYS);break;case Bn:r.depthFunc(r.LESS);break;case Ki:r.depthFunc(r.LEQUAL);break;case zn:r.depthFunc(r.EQUAL);break;case Gn:r.depthFunc(r.GEQUAL);break;case Hn:r.depthFunc(r.GREATER);break;case Vn:r.depthFunc(r.NOTEQUAL);break;default:r.depthFunc(r.LEQUAL)}xe=$}},setLocked:function($){R=$},setClear:function($){ue!==$&&(ue=$,X&&($=1-$),r.clearDepth($))},reset:function(){R=!1,ee=null,xe=null,ue=null,X=!1}}}function n(){let R=!1,X=null,ee=null,xe=null,ue=null,$=null,Me=null,ye=null,Et=null;return{setTest:function(et){R||(et?ne(r.STENCIL_TEST):Te(r.STENCIL_TEST))},setMask:function(et){X!==et&&!R&&(r.stencilMask(et),X=et)},setFunc:function(et,ri,Wt){(ee!==et||xe!==ri||ue!==Wt)&&(r.stencilFunc(et,ri,Wt),ee=et,xe=ri,ue=Wt)},setOp:function(et,ri,Wt){($!==et||Me!==ri||ye!==Wt)&&(r.stencilOp(et,ri,Wt),$=et,Me=ri,ye=Wt)},setLocked:function(et){R=et},setClear:function(et){Et!==et&&(r.clearStencil(et),Et=et)},reset:function(){R=!1,X=null,ee=null,xe=null,ue=null,$=null,Me=null,ye=null,Et=null}}}const a=new t,s=new i,o=new n,c=new WeakMap,l=new WeakMap;let d={},m={},u={},g=new WeakMap,x=[],E=null,p=!1,h=null,S=null,A=null,T=null,U=null,y=null,C=null,v=new qe(0,0,0),b=0,F=!1,w=null,N=null,W=null,q=null,L=null;const V=r.getParameter(r.MAX_COMBINED_TEXTURE_IMAGE_UNITS);let H=!1,Z=0;const Q=r.getParameter(r.VERSION);Q.indexOf("WebGL")!==-1?(Z=parseFloat(/^WebGL (\d)/.exec(Q)[1]),H=Z>=1):Q.indexOf("OpenGL ES")!==-1&&(Z=parseFloat(/^OpenGL ES (\d)/.exec(Q)[1]),H=Z>=2);let re=null,ve={};const we=r.getParameter(r.SCISSOR_BOX),Ge=r.getParameter(r.VIEWPORT),Ye=new ot().fromArray(we),Ue=new ot().fromArray(Ge);function j(R,X,ee,xe){const ue=new Uint8Array(4),$=r.createTexture();r.bindTexture(R,$),r.texParameteri(R,r.TEXTURE_MIN_FILTER,r.NEAREST),r.texParameteri(R,r.TEXTURE_MAG_FILTER,r.NEAREST);for(let Me=0;Me<ee;Me++)R===r.TEXTURE_3D||R===r.TEXTURE_2D_ARRAY?r.texImage3D(X,0,r.RGBA,1,1,xe,0,r.RGBA,r.UNSIGNED_BYTE,ue):r.texImage2D(X+Me,0,r.RGBA,1,1,0,r.RGBA,r.UNSIGNED_BYTE,ue);return $}const oe={};oe[r.TEXTURE_2D]=j(r.TEXTURE_2D,r.TEXTURE_2D,1),oe[r.TEXTURE_CUBE_MAP]=j(r.TEXTURE_CUBE_MAP,r.TEXTURE_CUBE_MAP_POSITIVE_X,6),oe[r.TEXTURE_2D_ARRAY]=j(r.TEXTURE_2D_ARRAY,r.TEXTURE_2D_ARRAY,1,1),oe[r.TEXTURE_3D]=j(r.TEXTURE_3D,r.TEXTURE_3D,1,1),a.setClear(0,0,0,1),s.setClear(1),o.setClear(0),ne(r.DEPTH_TEST),s.setFunc(Ki),St(!1),tt(Ls),ne(r.CULL_FACE),gt(si);function ne(R){d[R]!==!0&&(r.enable(R),d[R]=!0)}function Te(R){d[R]!==!1&&(r.disable(R),d[R]=!1)}function Pe(R,X){return u[R]!==X?(r.bindFramebuffer(R,X),u[R]=X,R===r.DRAW_FRAMEBUFFER&&(u[r.FRAMEBUFFER]=X),R===r.FRAMEBUFFER&&(u[r.DRAW_FRAMEBUFFER]=X),!0):!1}function fe(R,X){let ee=x,xe=!1;if(R){ee=g.get(X),ee===void 0&&(ee=[],g.set(X,ee));const ue=R.textures;if(ee.length!==ue.length||ee[0]!==r.COLOR_ATTACHMENT0){for(let $=0,Me=ue.length;$<Me;$++)ee[$]=r.COLOR_ATTACHMENT0+$;ee.length=ue.length,xe=!0}}else ee[0]!==r.BACK&&(ee[0]=r.BACK,xe=!0);xe&&r.drawBuffers(ee)}function Ve(R){return E!==R?(r.useProgram(R),E=R,!0):!1}const ke={[Ii]:r.FUNC_ADD,[ac]:r.FUNC_SUBTRACT,[sc]:r.FUNC_REVERSE_SUBTRACT};ke[oc]=r.MIN,ke[lc]=r.MAX;const Le={[cc]:r.ZERO,[uc]:r.ONE,[hc]:r.SRC_COLOR,[Ln]:r.SRC_ALPHA,[_c]:r.SRC_ALPHA_SATURATE,[mc]:r.DST_COLOR,[pc]:r.DST_ALPHA,[dc]:r.ONE_MINUS_SRC_COLOR,[Nn]:r.ONE_MINUS_SRC_ALPHA,[gc]:r.ONE_MINUS_DST_COLOR,[fc]:r.ONE_MINUS_DST_ALPHA,[vc]:r.CONSTANT_COLOR,[xc]:r.ONE_MINUS_CONSTANT_COLOR,[Mc]:r.CONSTANT_ALPHA,[Sc]:r.ONE_MINUS_CONSTANT_ALPHA};function gt(R,X,ee,xe,ue,$,Me,ye,Et,et){if(R===si){p===!0&&(Te(r.BLEND),p=!1);return}if(p===!1&&(ne(r.BLEND),p=!0),R!==nc){if(R!==h||et!==F){if((S!==Ii||U!==Ii)&&(r.blendEquation(r.FUNC_ADD),S=Ii,U=Ii),et)switch(R){case ji:r.blendFuncSeparate(r.ONE,r.ONE_MINUS_SRC_ALPHA,r.ONE,r.ONE_MINUS_SRC_ALPHA);break;case Ns:r.blendFunc(r.ONE,r.ONE);break;case Fs:r.blendFuncSeparate(r.ZERO,r.ONE_MINUS_SRC_COLOR,r.ZERO,r.ONE);break;case Os:r.blendFuncSeparate(r.DST_COLOR,r.ONE_MINUS_SRC_ALPHA,r.ZERO,r.ONE);break;default:He("WebGLState: Invalid blending: ",R);break}else switch(R){case ji:r.blendFuncSeparate(r.SRC_ALPHA,r.ONE_MINUS_SRC_ALPHA,r.ONE,r.ONE_MINUS_SRC_ALPHA);break;case Ns:r.blendFuncSeparate(r.SRC_ALPHA,r.ONE,r.ONE,r.ONE);break;case Fs:He("WebGLState: SubtractiveBlending requires material.premultipliedAlpha = true");break;case Os:He("WebGLState: MultiplyBlending requires material.premultipliedAlpha = true");break;default:He("WebGLState: Invalid blending: ",R);break}A=null,T=null,y=null,C=null,v.set(0,0,0),b=0,h=R,F=et}return}ue=ue||X,$=$||ee,Me=Me||xe,(X!==S||ue!==U)&&(r.blendEquationSeparate(ke[X],ke[ue]),S=X,U=ue),(ee!==A||xe!==T||$!==y||Me!==C)&&(r.blendFuncSeparate(Le[ee],Le[xe],Le[$],Le[Me]),A=ee,T=xe,y=$,C=Me),(ye.equals(v)===!1||Et!==b)&&(r.blendColor(ye.r,ye.g,ye.b,Et),v.copy(ye),b=Et),h=R,F=!1}function ft(R,X){R.side===ai?Te(r.CULL_FACE):ne(r.CULL_FACE);let ee=R.side===bt;X&&(ee=!ee),St(ee),R.blending===ji&&R.transparent===!1?gt(si):gt(R.blending,R.blendEquation,R.blendSrc,R.blendDst,R.blendEquationAlpha,R.blendSrcAlpha,R.blendDstAlpha,R.blendColor,R.blendAlpha,R.premultipliedAlpha),s.setFunc(R.depthFunc),s.setTest(R.depthTest),s.setMask(R.depthWrite),a.setMask(R.colorWrite);const xe=R.stencilWrite;o.setTest(xe),xe&&(o.setMask(R.stencilWriteMask),o.setFunc(R.stencilFunc,R.stencilRef,R.stencilFuncMask),o.setOp(R.stencilFail,R.stencilZFail,R.stencilZPass)),P(R.polygonOffset,R.polygonOffsetFactor,R.polygonOffsetUnits),R.alphaToCoverage===!0?ne(r.SAMPLE_ALPHA_TO_COVERAGE):Te(r.SAMPLE_ALPHA_TO_COVERAGE)}function St(R){w!==R&&(R?r.frontFace(r.CW):r.frontFace(r.CCW),w=R)}function tt(R){R!==tc?(ne(r.CULL_FACE),R!==N&&(R===Ls?r.cullFace(r.BACK):R===ic?r.cullFace(r.FRONT):r.cullFace(r.FRONT_AND_BACK))):Te(r.CULL_FACE),N=R}function Rt(R){R!==W&&(H&&r.lineWidth(R),W=R)}function P(R,X,ee){R?(ne(r.POLYGON_OFFSET_FILL),(q!==X||L!==ee)&&(q=X,L=ee,s.getReversed()&&(X=-X),r.polygonOffset(X,ee))):Te(r.POLYGON_OFFSET_FILL)}function ct(R){R?ne(r.SCISSOR_TEST):Te(r.SCISSOR_TEST)}function Ne(R){R===void 0&&(R=r.TEXTURE0+V-1),re!==R&&(r.activeTexture(R),re=R)}function Ze(R,X,ee){ee===void 0&&(re===null?ee=r.TEXTURE0+V-1:ee=re);let xe=ve[ee];xe===void 0&&(xe={type:void 0,texture:void 0},ve[ee]=xe),(xe.type!==R||xe.texture!==X)&&(re!==ee&&(r.activeTexture(ee),re=ee),r.bindTexture(R,X||oe[R]),xe.type=R,xe.texture=X)}function le(){const R=ve[re];R!==void 0&&R.type!==void 0&&(r.bindTexture(R.type,null),R.type=void 0,R.texture=void 0)}function rt(){try{r.compressedTexImage2D(...arguments)}catch(R){He("WebGLState:",R)}}function M(){try{r.compressedTexImage3D(...arguments)}catch(R){He("WebGLState:",R)}}function f(){try{r.texSubImage2D(...arguments)}catch(R){He("WebGLState:",R)}}function O(){try{r.texSubImage3D(...arguments)}catch(R){He("WebGLState:",R)}}function Y(){try{r.compressedTexSubImage2D(...arguments)}catch(R){He("WebGLState:",R)}}function K(){try{r.compressedTexSubImage3D(...arguments)}catch(R){He("WebGLState:",R)}}function ae(){try{r.texStorage2D(...arguments)}catch(R){He("WebGLState:",R)}}function se(){try{r.texStorage3D(...arguments)}catch(R){He("WebGLState:",R)}}function D(){try{r.texImage2D(...arguments)}catch(R){He("WebGLState:",R)}}function ie(){try{r.texImage3D(...arguments)}catch(R){He("WebGLState:",R)}}function ce(R){return m[R]!==void 0?m[R]:r.getParameter(R)}function pe(R,X){m[R]!==X&&(r.pixelStorei(R,X),m[R]=X)}function J(R){Ye.equals(R)===!1&&(r.scissor(R.x,R.y,R.z,R.w),Ye.copy(R))}function Se(R){Ue.equals(R)===!1&&(r.viewport(R.x,R.y,R.z,R.w),Ue.copy(R))}function Re(R,X){let ee=l.get(X);ee===void 0&&(ee=new WeakMap,l.set(X,ee));let xe=ee.get(R);xe===void 0&&(xe=r.getUniformBlockIndex(X,R.name),ee.set(R,xe))}function Oe(R,X){const ee=l.get(X).get(R);c.get(X)!==ee&&(r.uniformBlockBinding(X,ee,R.__bindingPointIndex),c.set(X,ee))}function We(){r.disable(r.BLEND),r.disable(r.CULL_FACE),r.disable(r.DEPTH_TEST),r.disable(r.POLYGON_OFFSET_FILL),r.disable(r.SCISSOR_TEST),r.disable(r.STENCIL_TEST),r.disable(r.SAMPLE_ALPHA_TO_COVERAGE),r.blendEquation(r.FUNC_ADD),r.blendFunc(r.ONE,r.ZERO),r.blendFuncSeparate(r.ONE,r.ZERO,r.ONE,r.ZERO),r.blendColor(0,0,0,0),r.colorMask(!0,!0,!0,!0),r.clearColor(0,0,0,0),r.depthMask(!0),r.depthFunc(r.LESS),s.setReversed(!1),r.clearDepth(1),r.stencilMask(4294967295),r.stencilFunc(r.ALWAYS,0,4294967295),r.stencilOp(r.KEEP,r.KEEP,r.KEEP),r.clearStencil(0),r.cullFace(r.BACK),r.frontFace(r.CCW),r.polygonOffset(0,0),r.activeTexture(r.TEXTURE0),r.bindFramebuffer(r.FRAMEBUFFER,null),r.bindFramebuffer(r.DRAW_FRAMEBUFFER,null),r.bindFramebuffer(r.READ_FRAMEBUFFER,null),r.useProgram(null),r.lineWidth(1),r.scissor(0,0,r.canvas.width,r.canvas.height),r.viewport(0,0,r.canvas.width,r.canvas.height),r.pixelStorei(r.PACK_ALIGNMENT,4),r.pixelStorei(r.UNPACK_ALIGNMENT,4),r.pixelStorei(r.UNPACK_FLIP_Y_WEBGL,!1),r.pixelStorei(r.UNPACK_PREMULTIPLY_ALPHA_WEBGL,!1),r.pixelStorei(r.UNPACK_COLORSPACE_CONVERSION_WEBGL,r.BROWSER_DEFAULT_WEBGL),r.pixelStorei(r.PACK_ROW_LENGTH,0),r.pixelStorei(r.PACK_SKIP_PIXELS,0),r.pixelStorei(r.PACK_SKIP_ROWS,0),r.pixelStorei(r.UNPACK_ROW_LENGTH,0),r.pixelStorei(r.UNPACK_IMAGE_HEIGHT,0),r.pixelStorei(r.UNPACK_SKIP_PIXELS,0),r.pixelStorei(r.UNPACK_SKIP_ROWS,0),r.pixelStorei(r.UNPACK_SKIP_IMAGES,0),d={},m={},re=null,ve={},u={},g=new WeakMap,x=[],E=null,p=!1,h=null,S=null,A=null,T=null,U=null,y=null,C=null,v=new qe(0,0,0),b=0,F=!1,w=null,N=null,W=null,q=null,L=null,Ye.set(0,0,r.canvas.width,r.canvas.height),Ue.set(0,0,r.canvas.width,r.canvas.height),a.reset(),s.reset(),o.reset()}return{buffers:{color:a,depth:s,stencil:o},enable:ne,disable:Te,bindFramebuffer:Pe,drawBuffers:fe,useProgram:Ve,setBlending:gt,setMaterial:ft,setFlipSided:St,setCullFace:tt,setLineWidth:Rt,setPolygonOffset:P,setScissorTest:ct,activeTexture:Ne,bindTexture:Ze,unbindTexture:le,compressedTexImage2D:rt,compressedTexImage3D:M,texImage2D:D,texImage3D:ie,pixelStorei:pe,getParameter:ce,updateUBOMapping:Re,uniformBlockBinding:Oe,texStorage2D:ae,texStorage3D:se,texSubImage2D:f,texSubImage3D:O,compressedTexSubImage2D:Y,compressedTexSubImage3D:K,scissor:J,viewport:Se,reset:We}}function rm(r,e,t,i,n,a,s){const o=e.has("WEBGL_multisampled_render_to_texture")?e.get("WEBGL_multisampled_render_to_texture"):null,c=typeof navigator>"u"?!1:/OculusBrowser/g.test(navigator.userAgent),l=new Ke,d=new WeakMap,m=new Set;let u;const g=new WeakMap;let x=!1;try{x=typeof OffscreenCanvas<"u"&&new OffscreenCanvas(1,1).getContext("2d")!==null}catch{}function E(M,f){return x?new OffscreenCanvas(M,f):Kr("canvas")}function p(M,f,O){let Y=1;const K=rt(M);if((K.width>O||K.height>O)&&(Y=O/Math.max(K.width,K.height)),Y<1)if(typeof HTMLImageElement<"u"&&M instanceof HTMLImageElement||typeof HTMLCanvasElement<"u"&&M instanceof HTMLCanvasElement||typeof ImageBitmap<"u"&&M instanceof ImageBitmap||typeof VideoFrame<"u"&&M instanceof VideoFrame){const ae=Math.floor(Y*K.width),se=Math.floor(Y*K.height);u===void 0&&(u=E(ae,se));const D=f?E(ae,se):u;return D.width=ae,D.height=se,D.getContext("2d").drawImage(M,0,0,ae,se),Ae("WebGLRenderer: Texture has been resized from ("+K.width+"x"+K.height+") to ("+ae+"x"+se+")."),D}else return"data"in M&&Ae("WebGLRenderer: Image in DataTexture is too big ("+K.width+"x"+K.height+")."),M;return M}function h(M){return M.generateMipmaps}function S(M){r.generateMipmap(M)}function A(M){return M.isWebGLCubeRenderTarget?r.TEXTURE_CUBE_MAP:M.isWebGL3DRenderTarget?r.TEXTURE_3D:M.isWebGLArrayRenderTarget||M.isCompressedArrayTexture?r.TEXTURE_2D_ARRAY:r.TEXTURE_2D}function T(M,f,O,Y,K,ae=!1){if(M!==null){if(r[M]!==void 0)return r[M];Ae("WebGLRenderer: Attempt to use non-existing WebGL internal format '"+M+"'")}let se;Y&&(se=e.get("EXT_texture_norm16"),se||Ae("WebGLRenderer: Unable to use normalized textures without EXT_texture_norm16 extension"));let D=f;if(f===r.RED&&(O===r.FLOAT&&(D=r.R32F),O===r.HALF_FLOAT&&(D=r.R16F),O===r.UNSIGNED_BYTE&&(D=r.R8),O===r.UNSIGNED_SHORT&&se&&(D=se.R16_EXT),O===r.SHORT&&se&&(D=se.R16_SNORM_EXT)),f===r.RED_INTEGER&&(O===r.UNSIGNED_BYTE&&(D=r.R8UI),O===r.UNSIGNED_SHORT&&(D=r.R16UI),O===r.UNSIGNED_INT&&(D=r.R32UI),O===r.BYTE&&(D=r.R8I),O===r.SHORT&&(D=r.R16I),O===r.INT&&(D=r.R32I)),f===r.RG&&(O===r.FLOAT&&(D=r.RG32F),O===r.HALF_FLOAT&&(D=r.RG16F),O===r.UNSIGNED_BYTE&&(D=r.RG8),O===r.UNSIGNED_SHORT&&se&&(D=se.RG16_EXT),O===r.SHORT&&se&&(D=se.RG16_SNORM_EXT)),f===r.RG_INTEGER&&(O===r.UNSIGNED_BYTE&&(D=r.RG8UI),O===r.UNSIGNED_SHORT&&(D=r.RG16UI),O===r.UNSIGNED_INT&&(D=r.RG32UI),O===r.BYTE&&(D=r.RG8I),O===r.SHORT&&(D=r.RG16I),O===r.INT&&(D=r.RG32I)),f===r.RGB_INTEGER&&(O===r.UNSIGNED_BYTE&&(D=r.RGB8UI),O===r.UNSIGNED_SHORT&&(D=r.RGB16UI),O===r.UNSIGNED_INT&&(D=r.RGB32UI),O===r.BYTE&&(D=r.RGB8I),O===r.SHORT&&(D=r.RGB16I),O===r.INT&&(D=r.RGB32I)),f===r.RGBA_INTEGER&&(O===r.UNSIGNED_BYTE&&(D=r.RGBA8UI),O===r.UNSIGNED_SHORT&&(D=r.RGBA16UI),O===r.UNSIGNED_INT&&(D=r.RGBA32UI),O===r.BYTE&&(D=r.RGBA8I),O===r.SHORT&&(D=r.RGBA16I),O===r.INT&&(D=r.RGBA32I)),f===r.RGB&&(O===r.UNSIGNED_SHORT&&se&&(D=se.RGB16_EXT),O===r.SHORT&&se&&(D=se.RGB16_SNORM_EXT),O===r.UNSIGNED_INT_5_9_9_9_REV&&(D=r.RGB9_E5),O===r.UNSIGNED_INT_10F_11F_11F_REV&&(D=r.R11F_G11F_B10F)),f===r.RGBA){const ie=ae?qr:ze.getTransfer(K);O===r.FLOAT&&(D=r.RGBA32F),O===r.HALF_FLOAT&&(D=r.RGBA16F),O===r.UNSIGNED_BYTE&&(D=ie===Xe?r.SRGB8_ALPHA8:r.RGBA8),O===r.UNSIGNED_SHORT&&se&&(D=se.RGBA16_EXT),O===r.SHORT&&se&&(D=se.RGBA16_SNORM_EXT),O===r.UNSIGNED_SHORT_4_4_4_4&&(D=r.RGBA4),O===r.UNSIGNED_SHORT_5_5_5_1&&(D=r.RGB5_A1)}return(D===r.R16F||D===r.R32F||D===r.RG16F||D===r.RG32F||D===r.RGBA16F||D===r.RGBA32F)&&e.get("EXT_color_buffer_float"),D}function U(M,f){let O;return M?f===null||f===Yt||f===Mr?O=r.DEPTH24_STENCIL8:f===jt?O=r.DEPTH32F_STENCIL8:f===xr&&(O=r.DEPTH24_STENCIL8,Ae("DepthTexture: 16 bit depth attachment is not supported with stencil. Using 24-bit attachment.")):f===null||f===Yt||f===Mr?O=r.DEPTH_COMPONENT24:f===jt?O=r.DEPTH_COMPONENT32F:f===xr&&(O=r.DEPTH_COMPONENT16),O}function y(M,f){return h(M)===!0||M.isFramebufferTexture&&M.minFilter!==_t&&M.minFilter!==vt?Math.log2(Math.max(f.width,f.height))+1:M.mipmaps!==void 0&&M.mipmaps.length>0?M.mipmaps.length:M.isCompressedTexture&&Array.isArray(M.image)?f.mipmaps.length:1}function C(M){const f=M.target;f.removeEventListener("dispose",C),b(f),f.isVideoTexture&&d.delete(f),f.isHTMLTexture&&m.delete(f)}function v(M){const f=M.target;f.removeEventListener("dispose",v),w(f)}function b(M){const f=i.get(M);if(f.__webglInit===void 0)return;const O=M.source,Y=g.get(O);if(Y){const K=Y[f.__cacheKey];K.usedTimes--,K.usedTimes===0&&F(M),Object.keys(Y).length===0&&g.delete(O)}i.remove(M)}function F(M){const f=i.get(M);r.deleteTexture(f.__webglTexture);const O=M.source,Y=g.get(O);delete Y[f.__cacheKey],s.memory.textures--}function w(M){const f=i.get(M);if(M.depthTexture&&(M.depthTexture.dispose(),i.remove(M.depthTexture)),M.isWebGLCubeRenderTarget)for(let Y=0;Y<6;Y++){if(Array.isArray(f.__webglFramebuffer[Y]))for(let K=0;K<f.__webglFramebuffer[Y].length;K++)r.deleteFramebuffer(f.__webglFramebuffer[Y][K]);else r.deleteFramebuffer(f.__webglFramebuffer[Y]);f.__webglDepthbuffer&&r.deleteRenderbuffer(f.__webglDepthbuffer[Y])}else{if(Array.isArray(f.__webglFramebuffer))for(let Y=0;Y<f.__webglFramebuffer.length;Y++)r.deleteFramebuffer(f.__webglFramebuffer[Y]);else r.deleteFramebuffer(f.__webglFramebuffer);if(f.__webglDepthbuffer&&r.deleteRenderbuffer(f.__webglDepthbuffer),f.__webglMultisampledFramebuffer&&r.deleteFramebuffer(f.__webglMultisampledFramebuffer),f.__webglColorRenderbuffer)for(let Y=0;Y<f.__webglColorRenderbuffer.length;Y++)f.__webglColorRenderbuffer[Y]&&r.deleteRenderbuffer(f.__webglColorRenderbuffer[Y]);f.__webglDepthRenderbuffer&&r.deleteRenderbuffer(f.__webglDepthRenderbuffer)}const O=M.textures;for(let Y=0,K=O.length;Y<K;Y++){const ae=i.get(O[Y]);ae.__webglTexture&&(r.deleteTexture(ae.__webglTexture),s.memory.textures--),i.remove(O[Y])}i.remove(M)}let N=0;function W(){N=0}function q(){return N}function L(M){N=M}function V(){const M=N;return M>=n.maxTextures&&Ae("WebGLTextures: Trying to use "+M+" texture units while this GPU supports only "+n.maxTextures),N+=1,M}function H(M){const f=[];return f.push(M.wrapS),f.push(M.wrapT),f.push(M.wrapR||0),f.push(M.magFilter),f.push(M.minFilter),f.push(M.anisotropy),f.push(M.internalFormat),f.push(M.format),f.push(M.type),f.push(M.generateMipmaps),f.push(M.premultiplyAlpha),f.push(M.flipY),f.push(M.unpackAlignment),f.push(M.colorSpace),f.join()}function Z(M,f){const O=i.get(M);if(M.isVideoTexture&&Ze(M),M.isRenderTargetTexture===!1&&M.isExternalTexture!==!0&&M.version>0&&O.__version!==M.version){const Y=M.image;if(Y===null)Ae("WebGLRenderer: Texture marked for update but no image data found.");else if(Y.complete===!1)Ae("WebGLRenderer: Texture marked for update but image is incomplete");else{Te(O,M,f);return}}else M.isExternalTexture&&(O.__webglTexture=M.sourceTexture?M.sourceTexture:null);t.bindTexture(r.TEXTURE_2D,O.__webglTexture,r.TEXTURE0+f)}function Q(M,f){const O=i.get(M);if(M.isRenderTargetTexture===!1&&M.version>0&&O.__version!==M.version){Te(O,M,f);return}else M.isExternalTexture&&(O.__webglTexture=M.sourceTexture?M.sourceTexture:null);t.bindTexture(r.TEXTURE_2D_ARRAY,O.__webglTexture,r.TEXTURE0+f)}function re(M,f){const O=i.get(M);if(M.isRenderTargetTexture===!1&&M.version>0&&O.__version!==M.version){Te(O,M,f);return}t.bindTexture(r.TEXTURE_3D,O.__webglTexture,r.TEXTURE0+f)}function ve(M,f){const O=i.get(M);if(M.isCubeDepthTexture!==!0&&M.version>0&&O.__version!==M.version){Pe(O,M,f);return}t.bindTexture(r.TEXTURE_CUBE_MAP,O.__webglTexture,r.TEXTURE0+f)}const we={[Xn]:r.REPEAT,[oi]:r.CLAMP_TO_EDGE,[qn]:r.MIRRORED_REPEAT},Ge={[_t]:r.NEAREST,[yc]:r.NEAREST_MIPMAP_NEAREST,[Br]:r.NEAREST_MIPMAP_LINEAR,[vt]:r.LINEAR,[Yn]:r.LINEAR_MIPMAP_NEAREST,[Ni]:r.LINEAR_MIPMAP_LINEAR},Ye={[wc]:r.NEVER,[Dc]:r.ALWAYS,[Rc]:r.LESS,[Pa]:r.LEQUAL,[Cc]:r.EQUAL,[Ua]:r.GEQUAL,[Pc]:r.GREATER,[Uc]:r.NOTEQUAL};function Ue(M,f){if(f.type===jt&&e.has("OES_texture_float_linear")===!1&&(f.magFilter===vt||f.magFilter===Yn||f.magFilter===Br||f.magFilter===Ni||f.minFilter===vt||f.minFilter===Yn||f.minFilter===Br||f.minFilter===Ni)&&Ae("WebGLRenderer: Unable to use linear filtering with floating point textures. OES_texture_float_linear not supported on this device."),r.texParameteri(M,r.TEXTURE_WRAP_S,we[f.wrapS]),r.texParameteri(M,r.TEXTURE_WRAP_T,we[f.wrapT]),(M===r.TEXTURE_3D||M===r.TEXTURE_2D_ARRAY)&&r.texParameteri(M,r.TEXTURE_WRAP_R,we[f.wrapR]),r.texParameteri(M,r.TEXTURE_MAG_FILTER,Ge[f.magFilter]),r.texParameteri(M,r.TEXTURE_MIN_FILTER,Ge[f.minFilter]),f.compareFunction&&(r.texParameteri(M,r.TEXTURE_COMPARE_MODE,r.COMPARE_REF_TO_TEXTURE),r.texParameteri(M,r.TEXTURE_COMPARE_FUNC,Ye[f.compareFunction])),e.has("EXT_texture_filter_anisotropic")===!0){if(f.magFilter===_t||f.minFilter!==Br&&f.minFilter!==Ni||f.type===jt&&e.has("OES_texture_float_linear")===!1)return;if(f.anisotropy>1||i.get(f).__currentAnisotropy){const O=e.get("EXT_texture_filter_anisotropic");r.texParameterf(M,O.TEXTURE_MAX_ANISOTROPY_EXT,Math.min(f.anisotropy,n.getMaxAnisotropy())),i.get(f).__currentAnisotropy=f.anisotropy}}}function j(M,f){let O=!1;M.__webglInit===void 0&&(M.__webglInit=!0,f.addEventListener("dispose",C));const Y=f.source;let K=g.get(Y);K===void 0&&(K={},g.set(Y,K));const ae=H(f);if(ae!==M.__cacheKey){K[ae]===void 0&&(K[ae]={texture:r.createTexture(),usedTimes:0},s.memory.textures++,O=!0),K[ae].usedTimes++;const se=K[M.__cacheKey];se!==void 0&&(K[M.__cacheKey].usedTimes--,se.usedTimes===0&&F(f)),M.__cacheKey=ae,M.__webglTexture=K[ae].texture}return O}function oe(M,f,O){return Math.floor(Math.floor(M/O)/f)}function ne(M,f,O,Y){const K=M.updateRanges;if(K.length===0)t.texSubImage2D(r.TEXTURE_2D,0,0,0,f.width,f.height,O,Y,f.data);else{K.sort((ce,pe)=>ce.start-pe.start);let ae=0;for(let ce=1;ce<K.length;ce++){const pe=K[ae],J=K[ce],Se=pe.start+pe.count,Re=oe(J.start,f.width,4),Oe=oe(pe.start,f.width,4);J.start<=Se+1&&Re===Oe&&oe(J.start+J.count-1,f.width,4)===Re?pe.count=Math.max(pe.count,J.start+J.count-pe.start):(++ae,K[ae]=J)}K.length=ae+1;const se=t.getParameter(r.UNPACK_ROW_LENGTH),D=t.getParameter(r.UNPACK_SKIP_PIXELS),ie=t.getParameter(r.UNPACK_SKIP_ROWS);t.pixelStorei(r.UNPACK_ROW_LENGTH,f.width);for(let ce=0,pe=K.length;ce<pe;ce++){const J=K[ce],Se=Math.floor(J.start/4),Re=Math.ceil(J.count/4),Oe=Se%f.width,We=Math.floor(Se/f.width),R=Re;t.pixelStorei(r.UNPACK_SKIP_PIXELS,Oe),t.pixelStorei(r.UNPACK_SKIP_ROWS,We),t.texSubImage2D(r.TEXTURE_2D,0,Oe,We,R,1,O,Y,f.data)}M.clearUpdateRanges(),t.pixelStorei(r.UNPACK_ROW_LENGTH,se),t.pixelStorei(r.UNPACK_SKIP_PIXELS,D),t.pixelStorei(r.UNPACK_SKIP_ROWS,ie)}}function Te(M,f,O){let Y=r.TEXTURE_2D;(f.isDataArrayTexture||f.isCompressedArrayTexture)&&(Y=r.TEXTURE_2D_ARRAY),f.isData3DTexture&&(Y=r.TEXTURE_3D);const K=j(M,f),ae=f.source;t.bindTexture(Y,M.__webglTexture,r.TEXTURE0+O);const se=i.get(ae);if(ae.version!==se.__version||K===!0){if(t.activeTexture(r.TEXTURE0+O),!(typeof ImageBitmap<"u"&&f.image instanceof ImageBitmap)){const X=ze.getPrimaries(ze.workingColorSpace),ee=f.colorSpace===Mi?null:ze.getPrimaries(f.colorSpace),xe=f.colorSpace===Mi||X===ee?r.NONE:r.BROWSER_DEFAULT_WEBGL;t.pixelStorei(r.UNPACK_FLIP_Y_WEBGL,f.flipY),t.pixelStorei(r.UNPACK_PREMULTIPLY_ALPHA_WEBGL,f.premultiplyAlpha),t.pixelStorei(r.UNPACK_COLORSPACE_CONVERSION_WEBGL,xe)}t.pixelStorei(r.UNPACK_ALIGNMENT,f.unpackAlignment);let D=p(f.image,!1,n.maxTextureSize);D=le(f,D);const ie=a.convert(f.format,f.colorSpace),ce=a.convert(f.type);let pe=T(f.internalFormat,ie,ce,f.normalized,f.colorSpace,f.isVideoTexture);Ue(Y,f);let J;const Se=f.mipmaps,Re=f.isVideoTexture!==!0,Oe=se.__version===void 0||K===!0,We=ae.dataReady,R=y(f,D);if(f.isDepthTexture)pe=U(f.format===Fi,f.type),Oe&&(Re?t.texStorage2D(r.TEXTURE_2D,1,pe,D.width,D.height):t.texImage2D(r.TEXTURE_2D,0,pe,D.width,D.height,0,ie,ce,null));else if(f.isDataTexture)if(Se.length>0){Re&&Oe&&t.texStorage2D(r.TEXTURE_2D,R,pe,Se[0].width,Se[0].height);for(let X=0,ee=Se.length;X<ee;X++)J=Se[X],Re?We&&t.texSubImage2D(r.TEXTURE_2D,X,0,0,J.width,J.height,ie,ce,J.data):t.texImage2D(r.TEXTURE_2D,X,pe,J.width,J.height,0,ie,ce,J.data);f.generateMipmaps=!1}else Re?(Oe&&t.texStorage2D(r.TEXTURE_2D,R,pe,D.width,D.height),We&&ne(f,D,ie,ce)):t.texImage2D(r.TEXTURE_2D,0,pe,D.width,D.height,0,ie,ce,D.data);else if(f.isCompressedTexture)if(f.isCompressedArrayTexture){Re&&Oe&&t.texStorage3D(r.TEXTURE_2D_ARRAY,R,pe,Se[0].width,Se[0].height,D.depth);for(let X=0,ee=Se.length;X<ee;X++)if(J=Se[X],f.format!==Ot)if(ie!==null)if(Re){if(We)if(f.layerUpdates.size>0){const xe=Bo(J.width,J.height,f.format,f.type);for(const ue of f.layerUpdates){const $=J.data.subarray(ue*xe/J.data.BYTES_PER_ELEMENT,(ue+1)*xe/J.data.BYTES_PER_ELEMENT);t.compressedTexSubImage3D(r.TEXTURE_2D_ARRAY,X,0,0,ue,J.width,J.height,1,ie,$)}f.clearLayerUpdates()}else t.compressedTexSubImage3D(r.TEXTURE_2D_ARRAY,X,0,0,0,J.width,J.height,D.depth,ie,J.data)}else t.compressedTexImage3D(r.TEXTURE_2D_ARRAY,X,pe,J.width,J.height,D.depth,0,J.data,0,0);else Ae("WebGLRenderer: Attempt to load unsupported compressed texture format in .uploadTexture()");else Re?We&&t.texSubImage3D(r.TEXTURE_2D_ARRAY,X,0,0,0,J.width,J.height,D.depth,ie,ce,J.data):t.texImage3D(r.TEXTURE_2D_ARRAY,X,pe,J.width,J.height,D.depth,0,ie,ce,J.data)}else{Re&&Oe&&t.texStorage2D(r.TEXTURE_2D,R,pe,Se[0].width,Se[0].height);for(let X=0,ee=Se.length;X<ee;X++)J=Se[X],f.format!==Ot?ie!==null?Re?We&&t.compressedTexSubImage2D(r.TEXTURE_2D,X,0,0,J.width,J.height,ie,J.data):t.compressedTexImage2D(r.TEXTURE_2D,X,pe,J.width,J.height,0,J.data):Ae("WebGLRenderer: Attempt to load unsupported compressed texture format in .uploadTexture()"):Re?We&&t.texSubImage2D(r.TEXTURE_2D,X,0,0,J.width,J.height,ie,ce,J.data):t.texImage2D(r.TEXTURE_2D,X,pe,J.width,J.height,0,ie,ce,J.data)}else if(f.isDataArrayTexture)if(Re){if(Oe&&t.texStorage3D(r.TEXTURE_2D_ARRAY,R,pe,D.width,D.height,D.depth),We)if(f.layerUpdates.size>0){const X=Bo(D.width,D.height,f.format,f.type);for(const ee of f.layerUpdates){const xe=D.data.subarray(ee*X/D.data.BYTES_PER_ELEMENT,(ee+1)*X/D.data.BYTES_PER_ELEMENT);t.texSubImage3D(r.TEXTURE_2D_ARRAY,0,0,0,ee,D.width,D.height,1,ie,ce,xe)}f.clearLayerUpdates()}else t.texSubImage3D(r.TEXTURE_2D_ARRAY,0,0,0,0,D.width,D.height,D.depth,ie,ce,D.data)}else t.texImage3D(r.TEXTURE_2D_ARRAY,0,pe,D.width,D.height,D.depth,0,ie,ce,D.data);else if(f.isData3DTexture)Re?(Oe&&t.texStorage3D(r.TEXTURE_3D,R,pe,D.width,D.height,D.depth),We&&t.texSubImage3D(r.TEXTURE_3D,0,0,0,0,D.width,D.height,D.depth,ie,ce,D.data)):t.texImage3D(r.TEXTURE_3D,0,pe,D.width,D.height,D.depth,0,ie,ce,D.data);else if(f.isFramebufferTexture){if(Oe)if(Re)t.texStorage2D(r.TEXTURE_2D,R,pe,D.width,D.height);else{let X=D.width,ee=D.height;for(let xe=0;xe<R;xe++)t.texImage2D(r.TEXTURE_2D,xe,pe,X,ee,0,ie,ce,null),X>>=1,ee>>=1}}else if(f.isHTMLTexture){if("texElementImage2D"in r){const X=r.canvas;if(X.hasAttribute("layoutsubtree")||X.setAttribute("layoutsubtree","true"),D.parentNode!==X){X.appendChild(D),m.add(f),X.onpaint=Me=>{const ye=Me.changedElements;for(const Et of m)ye.includes(Et.image)&&(Et.needsUpdate=!0)},X.requestPaint();return}const ee=0,xe=r.RGBA,ue=r.RGBA,$=r.UNSIGNED_BYTE;r.texElementImage2D(r.TEXTURE_2D,ee,xe,ue,$,D),r.texParameteri(r.TEXTURE_2D,r.TEXTURE_MIN_FILTER,r.LINEAR),r.texParameteri(r.TEXTURE_2D,r.TEXTURE_WRAP_S,r.CLAMP_TO_EDGE),r.texParameteri(r.TEXTURE_2D,r.TEXTURE_WRAP_T,r.CLAMP_TO_EDGE)}}else if(Se.length>0){if(Re&&Oe){const X=rt(Se[0]);t.texStorage2D(r.TEXTURE_2D,R,pe,X.width,X.height)}for(let X=0,ee=Se.length;X<ee;X++)J=Se[X],Re?We&&t.texSubImage2D(r.TEXTURE_2D,X,0,0,ie,ce,J):t.texImage2D(r.TEXTURE_2D,X,pe,ie,ce,J);f.generateMipmaps=!1}else if(Re){if(Oe){const X=rt(D);t.texStorage2D(r.TEXTURE_2D,R,pe,X.width,X.height)}We&&t.texSubImage2D(r.TEXTURE_2D,0,0,0,ie,ce,D)}else t.texImage2D(r.TEXTURE_2D,0,pe,ie,ce,D);h(f)&&S(Y),se.__version=ae.version,f.onUpdate&&f.onUpdate(f)}M.__version=f.version}function Pe(M,f,O){if(f.image.length!==6)return;const Y=j(M,f),K=f.source;t.bindTexture(r.TEXTURE_CUBE_MAP,M.__webglTexture,r.TEXTURE0+O);const ae=i.get(K);if(K.version!==ae.__version||Y===!0){t.activeTexture(r.TEXTURE0+O);const se=ze.getPrimaries(ze.workingColorSpace),D=f.colorSpace===Mi?null:ze.getPrimaries(f.colorSpace),ie=f.colorSpace===Mi||se===D?r.NONE:r.BROWSER_DEFAULT_WEBGL;t.pixelStorei(r.UNPACK_FLIP_Y_WEBGL,f.flipY),t.pixelStorei(r.UNPACK_PREMULTIPLY_ALPHA_WEBGL,f.premultiplyAlpha),t.pixelStorei(r.UNPACK_ALIGNMENT,f.unpackAlignment),t.pixelStorei(r.UNPACK_COLORSPACE_CONVERSION_WEBGL,ie);const ce=f.isCompressedTexture||f.image[0].isCompressedTexture,pe=f.image[0]&&f.image[0].isDataTexture,J=[];for(let $=0;$<6;$++)!ce&&!pe?J[$]=p(f.image[$],!0,n.maxCubemapSize):J[$]=pe?f.image[$].image:f.image[$],J[$]=le(f,J[$]);const Se=J[0],Re=a.convert(f.format,f.colorSpace),Oe=a.convert(f.type),We=T(f.internalFormat,Re,Oe,f.normalized,f.colorSpace),R=f.isVideoTexture!==!0,X=ae.__version===void 0||Y===!0,ee=K.dataReady;let xe=y(f,Se);Ue(r.TEXTURE_CUBE_MAP,f);let ue;if(ce){R&&X&&t.texStorage2D(r.TEXTURE_CUBE_MAP,xe,We,Se.width,Se.height);for(let $=0;$<6;$++){ue=J[$].mipmaps;for(let Me=0;Me<ue.length;Me++){const ye=ue[Me];f.format!==Ot?Re!==null?R?ee&&t.compressedTexSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,Me,0,0,ye.width,ye.height,Re,ye.data):t.compressedTexImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,Me,We,ye.width,ye.height,0,ye.data):Ae("WebGLRenderer: Attempt to load unsupported compressed texture format in .setTextureCube()"):R?ee&&t.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,Me,0,0,ye.width,ye.height,Re,Oe,ye.data):t.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,Me,We,ye.width,ye.height,0,Re,Oe,ye.data)}}}else{if(ue=f.mipmaps,R&&X){ue.length>0&&xe++;const $=rt(J[0]);t.texStorage2D(r.TEXTURE_CUBE_MAP,xe,We,$.width,$.height)}for(let $=0;$<6;$++)if(pe){R?ee&&t.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,0,0,0,J[$].width,J[$].height,Re,Oe,J[$].data):t.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,0,We,J[$].width,J[$].height,0,Re,Oe,J[$].data);for(let Me=0;Me<ue.length;Me++){const ye=ue[Me].image[$].image;R?ee&&t.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,Me+1,0,0,ye.width,ye.height,Re,Oe,ye.data):t.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,Me+1,We,ye.width,ye.height,0,Re,Oe,ye.data)}}else{R?ee&&t.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,0,0,0,Re,Oe,J[$]):t.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,0,We,Re,Oe,J[$]);for(let Me=0;Me<ue.length;Me++){const ye=ue[Me];R?ee&&t.texSubImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,Me+1,0,0,Re,Oe,ye.image[$]):t.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+$,Me+1,We,Re,Oe,ye.image[$])}}}h(f)&&S(r.TEXTURE_CUBE_MAP),ae.__version=K.version,f.onUpdate&&f.onUpdate(f)}M.__version=f.version}function fe(M,f,O,Y,K,ae){const se=a.convert(O.format,O.colorSpace),D=a.convert(O.type),ie=T(O.internalFormat,se,D,O.normalized,O.colorSpace),ce=i.get(f),pe=i.get(O);if(pe.__renderTarget=f,!ce.__hasExternalTextures){const J=Math.max(1,f.width>>ae),Se=Math.max(1,f.height>>ae);K===r.TEXTURE_3D||K===r.TEXTURE_2D_ARRAY?t.texImage3D(K,ae,ie,J,Se,f.depth,0,se,D,null):t.texImage2D(K,ae,ie,J,Se,0,se,D,null)}t.bindFramebuffer(r.FRAMEBUFFER,M),Ne(f)?o.framebufferTexture2DMultisampleEXT(r.FRAMEBUFFER,Y,K,pe.__webglTexture,0,ct(f)):(K===r.TEXTURE_2D||K>=r.TEXTURE_CUBE_MAP_POSITIVE_X&&K<=r.TEXTURE_CUBE_MAP_NEGATIVE_Z)&&r.framebufferTexture2D(r.FRAMEBUFFER,Y,K,pe.__webglTexture,ae),t.bindFramebuffer(r.FRAMEBUFFER,null)}function Ve(M,f,O){if(r.bindRenderbuffer(r.RENDERBUFFER,M),f.depthBuffer){const Y=f.depthTexture,K=Y&&Y.isDepthTexture?Y.type:null,ae=U(f.stencilBuffer,K),se=f.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT;Ne(f)?o.renderbufferStorageMultisampleEXT(r.RENDERBUFFER,ct(f),ae,f.width,f.height):O?r.renderbufferStorageMultisample(r.RENDERBUFFER,ct(f),ae,f.width,f.height):r.renderbufferStorage(r.RENDERBUFFER,ae,f.width,f.height),r.framebufferRenderbuffer(r.FRAMEBUFFER,se,r.RENDERBUFFER,M)}else{const Y=f.textures;for(let K=0;K<Y.length;K++){const ae=Y[K],se=a.convert(ae.format,ae.colorSpace),D=a.convert(ae.type),ie=T(ae.internalFormat,se,D,ae.normalized,ae.colorSpace);Ne(f)?o.renderbufferStorageMultisampleEXT(r.RENDERBUFFER,ct(f),ie,f.width,f.height):O?r.renderbufferStorageMultisample(r.RENDERBUFFER,ct(f),ie,f.width,f.height):r.renderbufferStorage(r.RENDERBUFFER,ie,f.width,f.height)}}r.bindRenderbuffer(r.RENDERBUFFER,null)}function ke(M,f,O){const Y=f.isWebGLCubeRenderTarget===!0;if(t.bindFramebuffer(r.FRAMEBUFFER,M),!(f.depthTexture&&f.depthTexture.isDepthTexture))throw new Error("renderTarget.depthTexture must be an instance of THREE.DepthTexture");const K=i.get(f.depthTexture);if(K.__renderTarget=f,(!K.__webglTexture||f.depthTexture.image.width!==f.width||f.depthTexture.image.height!==f.height)&&(f.depthTexture.image.width=f.width,f.depthTexture.image.height=f.height,f.depthTexture.needsUpdate=!0),Y){if(K.__webglInit===void 0&&(K.__webglInit=!0,f.depthTexture.addEventListener("dispose",C)),K.__webglTexture===void 0){K.__webglTexture=r.createTexture(),t.bindTexture(r.TEXTURE_CUBE_MAP,K.__webglTexture),Ue(r.TEXTURE_CUBE_MAP,f.depthTexture);const ce=a.convert(f.depthTexture.format),pe=a.convert(f.depthTexture.type);let J;f.depthTexture.format===ci?J=r.DEPTH_COMPONENT24:f.depthTexture.format===Fi&&(J=r.DEPTH24_STENCIL8);for(let Se=0;Se<6;Se++)r.texImage2D(r.TEXTURE_CUBE_MAP_POSITIVE_X+Se,0,J,f.width,f.height,0,ce,pe,null)}}else Z(f.depthTexture,0);const ae=K.__webglTexture,se=ct(f),D=Y?r.TEXTURE_CUBE_MAP_POSITIVE_X+O:r.TEXTURE_2D,ie=f.depthTexture.format===Fi?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT;if(f.depthTexture.format===ci)Ne(f)?o.framebufferTexture2DMultisampleEXT(r.FRAMEBUFFER,ie,D,ae,0,se):r.framebufferTexture2D(r.FRAMEBUFFER,ie,D,ae,0);else if(f.depthTexture.format===Fi)Ne(f)?o.framebufferTexture2DMultisampleEXT(r.FRAMEBUFFER,ie,D,ae,0,se):r.framebufferTexture2D(r.FRAMEBUFFER,ie,D,ae,0);else throw new Error("Unknown depthTexture format")}function Le(M){const f=i.get(M),O=M.isWebGLCubeRenderTarget===!0;if(f.__boundDepthTexture!==M.depthTexture){const Y=M.depthTexture;if(f.__depthDisposeCallback&&f.__depthDisposeCallback(),Y){const K=()=>{delete f.__boundDepthTexture,delete f.__depthDisposeCallback,Y.removeEventListener("dispose",K)};Y.addEventListener("dispose",K),f.__depthDisposeCallback=K}f.__boundDepthTexture=Y}if(M.depthTexture&&!f.__autoAllocateDepthBuffer)if(O)for(let Y=0;Y<6;Y++)ke(f.__webglFramebuffer[Y],M,Y);else{const Y=M.texture.mipmaps;Y&&Y.length>0?ke(f.__webglFramebuffer[0],M,0):ke(f.__webglFramebuffer,M,0)}else if(O){f.__webglDepthbuffer=[];for(let Y=0;Y<6;Y++)if(t.bindFramebuffer(r.FRAMEBUFFER,f.__webglFramebuffer[Y]),f.__webglDepthbuffer[Y]===void 0)f.__webglDepthbuffer[Y]=r.createRenderbuffer(),Ve(f.__webglDepthbuffer[Y],M,!1);else{const K=M.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT,ae=f.__webglDepthbuffer[Y];r.bindRenderbuffer(r.RENDERBUFFER,ae),r.framebufferRenderbuffer(r.FRAMEBUFFER,K,r.RENDERBUFFER,ae)}}else{const Y=M.texture.mipmaps;if(Y&&Y.length>0?t.bindFramebuffer(r.FRAMEBUFFER,f.__webglFramebuffer[0]):t.bindFramebuffer(r.FRAMEBUFFER,f.__webglFramebuffer),f.__webglDepthbuffer===void 0)f.__webglDepthbuffer=r.createRenderbuffer(),Ve(f.__webglDepthbuffer,M,!1);else{const K=M.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT,ae=f.__webglDepthbuffer;r.bindRenderbuffer(r.RENDERBUFFER,ae),r.framebufferRenderbuffer(r.FRAMEBUFFER,K,r.RENDERBUFFER,ae)}}t.bindFramebuffer(r.FRAMEBUFFER,null)}function gt(M,f,O){const Y=i.get(M);f!==void 0&&fe(Y.__webglFramebuffer,M,M.texture,r.COLOR_ATTACHMENT0,r.TEXTURE_2D,0),O!==void 0&&Le(M)}function ft(M){const f=M.texture,O=i.get(M),Y=i.get(f);M.addEventListener("dispose",v);const K=M.textures,ae=M.isWebGLCubeRenderTarget===!0,se=K.length>1;if(se||(Y.__webglTexture===void 0&&(Y.__webglTexture=r.createTexture()),Y.__version=f.version,s.memory.textures++),ae){O.__webglFramebuffer=[];for(let D=0;D<6;D++)if(f.mipmaps&&f.mipmaps.length>0){O.__webglFramebuffer[D]=[];for(let ie=0;ie<f.mipmaps.length;ie++)O.__webglFramebuffer[D][ie]=r.createFramebuffer()}else O.__webglFramebuffer[D]=r.createFramebuffer()}else{if(f.mipmaps&&f.mipmaps.length>0){O.__webglFramebuffer=[];for(let D=0;D<f.mipmaps.length;D++)O.__webglFramebuffer[D]=r.createFramebuffer()}else O.__webglFramebuffer=r.createFramebuffer();if(se)for(let D=0,ie=K.length;D<ie;D++){const ce=i.get(K[D]);ce.__webglTexture===void 0&&(ce.__webglTexture=r.createTexture(),s.memory.textures++)}if(M.samples>0&&Ne(M)===!1){O.__webglMultisampledFramebuffer=r.createFramebuffer(),O.__webglColorRenderbuffer=[],t.bindFramebuffer(r.FRAMEBUFFER,O.__webglMultisampledFramebuffer);for(let D=0;D<K.length;D++){const ie=K[D];O.__webglColorRenderbuffer[D]=r.createRenderbuffer(),r.bindRenderbuffer(r.RENDERBUFFER,O.__webglColorRenderbuffer[D]);const ce=a.convert(ie.format,ie.colorSpace),pe=a.convert(ie.type),J=T(ie.internalFormat,ce,pe,ie.normalized,ie.colorSpace,M.isXRRenderTarget===!0),Se=ct(M);r.renderbufferStorageMultisample(r.RENDERBUFFER,Se,J,M.width,M.height),r.framebufferRenderbuffer(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0+D,r.RENDERBUFFER,O.__webglColorRenderbuffer[D])}r.bindRenderbuffer(r.RENDERBUFFER,null),M.depthBuffer&&(O.__webglDepthRenderbuffer=r.createRenderbuffer(),Ve(O.__webglDepthRenderbuffer,M,!0)),t.bindFramebuffer(r.FRAMEBUFFER,null)}}if(ae){t.bindTexture(r.TEXTURE_CUBE_MAP,Y.__webglTexture),Ue(r.TEXTURE_CUBE_MAP,f);for(let D=0;D<6;D++)if(f.mipmaps&&f.mipmaps.length>0)for(let ie=0;ie<f.mipmaps.length;ie++)fe(O.__webglFramebuffer[D][ie],M,f,r.COLOR_ATTACHMENT0,r.TEXTURE_CUBE_MAP_POSITIVE_X+D,ie);else fe(O.__webglFramebuffer[D],M,f,r.COLOR_ATTACHMENT0,r.TEXTURE_CUBE_MAP_POSITIVE_X+D,0);h(f)&&S(r.TEXTURE_CUBE_MAP),t.unbindTexture()}else if(se){for(let D=0,ie=K.length;D<ie;D++){const ce=K[D],pe=i.get(ce);let J=r.TEXTURE_2D;(M.isWebGL3DRenderTarget||M.isWebGLArrayRenderTarget)&&(J=M.isWebGL3DRenderTarget?r.TEXTURE_3D:r.TEXTURE_2D_ARRAY),t.bindTexture(J,pe.__webglTexture),Ue(J,ce),fe(O.__webglFramebuffer,M,ce,r.COLOR_ATTACHMENT0+D,J,0),h(ce)&&S(J)}t.unbindTexture()}else{let D=r.TEXTURE_2D;if((M.isWebGL3DRenderTarget||M.isWebGLArrayRenderTarget)&&(D=M.isWebGL3DRenderTarget?r.TEXTURE_3D:r.TEXTURE_2D_ARRAY),t.bindTexture(D,Y.__webglTexture),Ue(D,f),f.mipmaps&&f.mipmaps.length>0)for(let ie=0;ie<f.mipmaps.length;ie++)fe(O.__webglFramebuffer[ie],M,f,r.COLOR_ATTACHMENT0,D,ie);else fe(O.__webglFramebuffer,M,f,r.COLOR_ATTACHMENT0,D,0);h(f)&&S(D),t.unbindTexture()}M.depthBuffer&&Le(M)}function St(M){const f=M.textures;for(let O=0,Y=f.length;O<Y;O++){const K=f[O];if(h(K)){const ae=A(M),se=i.get(K).__webglTexture;t.bindTexture(ae,se),S(ae),t.unbindTexture()}}}const tt=[],Rt=[];function P(M){if(M.samples>0){if(Ne(M)===!1){const f=M.textures,O=M.width,Y=M.height;let K=r.COLOR_BUFFER_BIT;const ae=M.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT,se=i.get(M),D=f.length>1;if(D)for(let ce=0;ce<f.length;ce++)t.bindFramebuffer(r.FRAMEBUFFER,se.__webglMultisampledFramebuffer),r.framebufferRenderbuffer(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0+ce,r.RENDERBUFFER,null),t.bindFramebuffer(r.FRAMEBUFFER,se.__webglFramebuffer),r.framebufferTexture2D(r.DRAW_FRAMEBUFFER,r.COLOR_ATTACHMENT0+ce,r.TEXTURE_2D,null,0);t.bindFramebuffer(r.READ_FRAMEBUFFER,se.__webglMultisampledFramebuffer);const ie=M.texture.mipmaps;ie&&ie.length>0?t.bindFramebuffer(r.DRAW_FRAMEBUFFER,se.__webglFramebuffer[0]):t.bindFramebuffer(r.DRAW_FRAMEBUFFER,se.__webglFramebuffer);for(let ce=0;ce<f.length;ce++){if(M.resolveDepthBuffer&&(M.depthBuffer&&(K|=r.DEPTH_BUFFER_BIT),M.stencilBuffer&&M.resolveStencilBuffer&&(K|=r.STENCIL_BUFFER_BIT)),D){r.framebufferRenderbuffer(r.READ_FRAMEBUFFER,r.COLOR_ATTACHMENT0,r.RENDERBUFFER,se.__webglColorRenderbuffer[ce]);const pe=i.get(f[ce]).__webglTexture;r.framebufferTexture2D(r.DRAW_FRAMEBUFFER,r.COLOR_ATTACHMENT0,r.TEXTURE_2D,pe,0)}r.blitFramebuffer(0,0,O,Y,0,0,O,Y,K,r.NEAREST),c===!0&&(tt.length=0,Rt.length=0,tt.push(r.COLOR_ATTACHMENT0+ce),M.depthBuffer&&M.resolveDepthBuffer===!1&&(tt.push(ae),Rt.push(ae),r.invalidateFramebuffer(r.DRAW_FRAMEBUFFER,Rt)),r.invalidateFramebuffer(r.READ_FRAMEBUFFER,tt))}if(t.bindFramebuffer(r.READ_FRAMEBUFFER,null),t.bindFramebuffer(r.DRAW_FRAMEBUFFER,null),D)for(let ce=0;ce<f.length;ce++){t.bindFramebuffer(r.FRAMEBUFFER,se.__webglMultisampledFramebuffer),r.framebufferRenderbuffer(r.FRAMEBUFFER,r.COLOR_ATTACHMENT0+ce,r.RENDERBUFFER,se.__webglColorRenderbuffer[ce]);const pe=i.get(f[ce]).__webglTexture;t.bindFramebuffer(r.FRAMEBUFFER,se.__webglFramebuffer),r.framebufferTexture2D(r.DRAW_FRAMEBUFFER,r.COLOR_ATTACHMENT0+ce,r.TEXTURE_2D,pe,0)}t.bindFramebuffer(r.DRAW_FRAMEBUFFER,se.__webglMultisampledFramebuffer)}else if(M.depthBuffer&&M.resolveDepthBuffer===!1&&c){const f=M.stencilBuffer?r.DEPTH_STENCIL_ATTACHMENT:r.DEPTH_ATTACHMENT;r.invalidateFramebuffer(r.DRAW_FRAMEBUFFER,[f])}}}function ct(M){return Math.min(n.maxSamples,M.samples)}function Ne(M){const f=i.get(M);return M.samples>0&&e.has("WEBGL_multisampled_render_to_texture")===!0&&f.__useRenderToTexture!==!1}function Ze(M){const f=s.render.frame;d.get(M)!==f&&(d.set(M,f),M.update())}function le(M,f){const O=M.colorSpace,Y=M.format,K=M.type;return M.isCompressedTexture===!0||M.isVideoTexture===!0||O!==Xr&&O!==Mi&&(ze.getTransfer(O)===Xe?(Y!==Ot||K!==Lt)&&Ae("WebGLTextures: sRGB encoded textures have to use RGBAFormat and UnsignedByteType."):He("WebGLTextures: Unsupported texture color space:",O)),f}function rt(M){return typeof HTMLImageElement<"u"&&M instanceof HTMLImageElement?(l.width=M.naturalWidth||M.width,l.height=M.naturalHeight||M.height):typeof VideoFrame<"u"&&M instanceof VideoFrame?(l.width=M.displayWidth,l.height=M.displayHeight):(l.width=M.width,l.height=M.height),l}this.allocateTextureUnit=V,this.resetTextureUnits=W,this.getTextureUnits=q,this.setTextureUnits=L,this.setTexture2D=Z,this.setTexture2DArray=Q,this.setTexture3D=re,this.setTextureCube=ve,this.rebindTextures=gt,this.setupRenderTarget=ft,this.updateRenderTargetMipmap=St,this.updateMultisampleRenderTarget=P,this.setupDepthRenderbuffer=Le,this.setupFrameBufferTexture=fe,this.useMultisampledRTT=Ne,this.isReversedDepthBuffer=function(){return t.buffers.depth.getReversed()}}function nm(r,e){function t(i,n=Mi){let a;const s=ze.getTransfer(n);if(i===Lt)return r.UNSIGNED_BYTE;if(i===Kn)return r.UNSIGNED_SHORT_4_4_4_4;if(i===Jn)return r.UNSIGNED_SHORT_5_5_5_1;if(i===Ks)return r.UNSIGNED_INT_5_9_9_9_REV;if(i===Js)return r.UNSIGNED_INT_10F_11F_11F_REV;if(i===Ys)return r.BYTE;if(i===js)return r.SHORT;if(i===xr)return r.UNSIGNED_SHORT;if(i===jn)return r.INT;if(i===Yt)return r.UNSIGNED_INT;if(i===jt)return r.FLOAT;if(i===li)return r.HALF_FLOAT;if(i===Zs)return r.ALPHA;if(i===$s)return r.RGB;if(i===Ot)return r.RGBA;if(i===ci)return r.DEPTH_COMPONENT;if(i===Fi)return r.DEPTH_STENCIL;if(i===Qs)return r.RED;if(i===Zn)return r.RED_INTEGER;if(i===Oi)return r.RG;if(i===$n)return r.RG_INTEGER;if(i===Qn)return r.RGBA_INTEGER;if(i===zr||i===Gr||i===Hr||i===Vr)if(s===Xe)if(a=e.get("WEBGL_compressed_texture_s3tc_srgb"),a!==null){if(i===zr)return a.COMPRESSED_SRGB_S3TC_DXT1_EXT;if(i===Gr)return a.COMPRESSED_SRGB_ALPHA_S3TC_DXT1_EXT;if(i===Hr)return a.COMPRESSED_SRGB_ALPHA_S3TC_DXT3_EXT;if(i===Vr)return a.COMPRESSED_SRGB_ALPHA_S3TC_DXT5_EXT}else return null;else if(a=e.get("WEBGL_compressed_texture_s3tc"),a!==null){if(i===zr)return a.COMPRESSED_RGB_S3TC_DXT1_EXT;if(i===Gr)return a.COMPRESSED_RGBA_S3TC_DXT1_EXT;if(i===Hr)return a.COMPRESSED_RGBA_S3TC_DXT3_EXT;if(i===Vr)return a.COMPRESSED_RGBA_S3TC_DXT5_EXT}else return null;if(i===ea||i===ta||i===ia||i===ra)if(a=e.get("WEBGL_compressed_texture_pvrtc"),a!==null){if(i===ea)return a.COMPRESSED_RGB_PVRTC_4BPPV1_IMG;if(i===ta)return a.COMPRESSED_RGB_PVRTC_2BPPV1_IMG;if(i===ia)return a.COMPRESSED_RGBA_PVRTC_4BPPV1_IMG;if(i===ra)return a.COMPRESSED_RGBA_PVRTC_2BPPV1_IMG}else return null;if(i===na||i===aa||i===sa||i===oa||i===la||i===kr||i===ca)if(a=e.get("WEBGL_compressed_texture_etc"),a!==null){if(i===na||i===aa)return s===Xe?a.COMPRESSED_SRGB8_ETC2:a.COMPRESSED_RGB8_ETC2;if(i===sa)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ETC2_EAC:a.COMPRESSED_RGBA8_ETC2_EAC;if(i===oa)return a.COMPRESSED_R11_EAC;if(i===la)return a.COMPRESSED_SIGNED_R11_EAC;if(i===kr)return a.COMPRESSED_RG11_EAC;if(i===ca)return a.COMPRESSED_SIGNED_RG11_EAC}else return null;if(i===ua||i===ha||i===da||i===pa||i===fa||i===ma||i===ga||i===_a||i===va||i===xa||i===Ma||i===Sa||i===Ea||i===Ta)if(a=e.get("WEBGL_compressed_texture_astc"),a!==null){if(i===ua)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_4x4_KHR:a.COMPRESSED_RGBA_ASTC_4x4_KHR;if(i===ha)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_5x4_KHR:a.COMPRESSED_RGBA_ASTC_5x4_KHR;if(i===da)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_5x5_KHR:a.COMPRESSED_RGBA_ASTC_5x5_KHR;if(i===pa)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_6x5_KHR:a.COMPRESSED_RGBA_ASTC_6x5_KHR;if(i===fa)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_6x6_KHR:a.COMPRESSED_RGBA_ASTC_6x6_KHR;if(i===ma)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_8x5_KHR:a.COMPRESSED_RGBA_ASTC_8x5_KHR;if(i===ga)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_8x6_KHR:a.COMPRESSED_RGBA_ASTC_8x6_KHR;if(i===_a)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_8x8_KHR:a.COMPRESSED_RGBA_ASTC_8x8_KHR;if(i===va)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_10x5_KHR:a.COMPRESSED_RGBA_ASTC_10x5_KHR;if(i===xa)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_10x6_KHR:a.COMPRESSED_RGBA_ASTC_10x6_KHR;if(i===Ma)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_10x8_KHR:a.COMPRESSED_RGBA_ASTC_10x8_KHR;if(i===Sa)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_10x10_KHR:a.COMPRESSED_RGBA_ASTC_10x10_KHR;if(i===Ea)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_12x10_KHR:a.COMPRESSED_RGBA_ASTC_12x10_KHR;if(i===Ta)return s===Xe?a.COMPRESSED_SRGB8_ALPHA8_ASTC_12x12_KHR:a.COMPRESSED_RGBA_ASTC_12x12_KHR}else return null;if(i===ya||i===ba||i===Aa)if(a=e.get("EXT_texture_compression_bptc"),a!==null){if(i===ya)return s===Xe?a.COMPRESSED_SRGB_ALPHA_BPTC_UNORM_EXT:a.COMPRESSED_RGBA_BPTC_UNORM_EXT;if(i===ba)return a.COMPRESSED_RGB_BPTC_SIGNED_FLOAT_EXT;if(i===Aa)return a.COMPRESSED_RGB_BPTC_UNSIGNED_FLOAT_EXT}else return null;if(i===wa||i===Ra||i===Wr||i===Ca)if(a=e.get("EXT_texture_compression_rgtc"),a!==null){if(i===wa)return a.COMPRESSED_RED_RGTC1_EXT;if(i===Ra)return a.COMPRESSED_SIGNED_RED_RGTC1_EXT;if(i===Wr)return a.COMPRESSED_RED_GREEN_RGTC2_EXT;if(i===Ca)return a.COMPRESSED_SIGNED_RED_GREEN_RGTC2_EXT}else return null;return i===Mr?r.UNSIGNED_INT_24_8:r[i]!==void 0?r[i]:null}return{convert:t}}const am=`
void main() {

	gl_Position = vec4( position, 1.0 );

}`,sm=`
uniform sampler2DArray depthColor;
uniform float depthWidth;
uniform float depthHeight;

void main() {

	vec2 coord = vec2( gl_FragCoord.x / depthWidth, gl_FragCoord.y / depthHeight );

	if ( coord.x >= 1.0 ) {

		gl_FragDepth = texture( depthColor, vec3( coord.x - 1.0, coord.y, 1 ) ).r;

	} else {

		gl_FragDepth = texture( depthColor, vec3( coord.x, coord.y, 0 ) ).r;

	}

}`;class om{constructor(){this.texture=null,this.mesh=null,this.depthNear=0,this.depthFar=0}init(e,t){if(this.texture===null){const i=new Po(e.texture);(e.depthNear!==t.depthNear||e.depthFar!==t.depthFar)&&(this.depthNear=e.depthNear,this.depthFar=e.depthFar),this.texture=i}}getMesh(e){if(this.texture!==null&&this.mesh===null){const t=e.cameras[0].viewport,i=new $t({vertexShader:am,fragmentShader:sm,uniforms:{depthColor:{value:this.texture},depthWidth:{value:t.z},depthHeight:{value:t.w}}});this.mesh=new Zt(new An(20,20),i)}return this.mesh}reset(){this.texture=null,this.mesh=null}getDepthTexture(){return this.texture}}class lm extends Bi{constructor(e,t){super();const i=this;let n=null,a=1,s=null,o="local-floor",c=1,l=null,d=null,m=null,u=null,g=null,x=null;const E=typeof XRWebGLBinding<"u",p=new om,h={},S=t.getContextAttributes();let A=null,T=null;const U=[],y=[],C=new Ke;let v=null;const b=new Ht;b.viewport=new ot;const F=new Ht;F.viewport=new ot;const w=[b,F],N=new _u;let W=null,q=null;this.cameraAutoUpdate=!0,this.enabled=!1,this.isPresenting=!1,this.getController=function(j){let oe=U[j];return oe===void 0&&(oe=new Va,U[j]=oe),oe.getTargetRaySpace()},this.getControllerGrip=function(j){let oe=U[j];return oe===void 0&&(oe=new Va,U[j]=oe),oe.getGripSpace()},this.getHand=function(j){let oe=U[j];return oe===void 0&&(oe=new Va,U[j]=oe),oe.getHandSpace()};function L(j){const oe=y.indexOf(j.inputSource);if(oe===-1)return;const ne=U[oe];ne!==void 0&&(ne.update(j.inputSource,j.frame,l||s),ne.dispatchEvent({type:j.type,data:j.inputSource}))}function V(){n.removeEventListener("select",L),n.removeEventListener("selectstart",L),n.removeEventListener("selectend",L),n.removeEventListener("squeeze",L),n.removeEventListener("squeezestart",L),n.removeEventListener("squeezeend",L),n.removeEventListener("end",V),n.removeEventListener("inputsourceschange",H);for(let j=0;j<U.length;j++){const oe=y[j];oe!==null&&(y[j]=null,U[j].disconnect(oe))}W=null,q=null,p.reset();for(const j in h)delete h[j];e.setRenderTarget(A),g=null,u=null,m=null,n=null,T=null,Ue.stop(),i.isPresenting=!1,e.setPixelRatio(v),e.setSize(C.width,C.height,!1),i.dispatchEvent({type:"sessionend"})}this.setFramebufferScaleFactor=function(j){a=j,i.isPresenting===!0&&Ae("WebXRManager: Cannot change framebuffer scale while presenting.")},this.setReferenceSpaceType=function(j){o=j,i.isPresenting===!0&&Ae("WebXRManager: Cannot change reference space type while presenting.")},this.getReferenceSpace=function(){return l||s},this.setReferenceSpace=function(j){l=j},this.getBaseLayer=function(){return u!==null?u:g},this.getBinding=function(){return m===null&&E&&(m=new XRWebGLBinding(n,t)),m},this.getFrame=function(){return x},this.getSession=function(){return n},this.setSession=async function(j){if(n=j,n!==null){if(A=e.getRenderTarget(),n.addEventListener("select",L),n.addEventListener("selectstart",L),n.addEventListener("selectend",L),n.addEventListener("squeeze",L),n.addEventListener("squeezestart",L),n.addEventListener("squeezeend",L),n.addEventListener("end",V),n.addEventListener("inputsourceschange",H),S.xrCompatible!==!0&&await t.makeXRCompatible(),v=e.getPixelRatio(),e.getSize(C),E&&"createProjectionLayer"in XRWebGLBinding.prototype){let oe=null,ne=null,Te=null;S.depth&&(Te=S.stencil?t.DEPTH24_STENCIL8:t.DEPTH_COMPONENT24,oe=S.stencil?Fi:ci,ne=S.stencil?Mr:Yt);const Pe={colorFormat:t.RGBA8,depthFormat:Te,scaleFactor:a};m=this.getBinding(),u=m.createProjectionLayer(Pe),n.updateRenderState({layers:[u]}),e.setPixelRatio(1),e.setSize(u.textureWidth,u.textureHeight,!1),T=new Jt(u.textureWidth,u.textureHeight,{format:Ot,type:Lt,depthTexture:new ur(u.textureWidth,u.textureHeight,ne,void 0,void 0,void 0,void 0,void 0,void 0,oe),stencilBuffer:S.stencil,colorSpace:e.outputColorSpace,samples:S.antialias?4:0,resolveDepthBuffer:u.ignoreDepthValues===!1,resolveStencilBuffer:u.ignoreDepthValues===!1})}else{const oe={antialias:S.antialias,alpha:!0,depth:S.depth,stencil:S.stencil,framebufferScaleFactor:a};g=new XRWebGLLayer(n,t,oe),n.updateRenderState({baseLayer:g}),e.setPixelRatio(1),e.setSize(g.framebufferWidth,g.framebufferHeight,!1),T=new Jt(g.framebufferWidth,g.framebufferHeight,{format:Ot,type:Lt,colorSpace:e.outputColorSpace,stencilBuffer:S.stencil,resolveDepthBuffer:g.ignoreDepthValues===!1,resolveStencilBuffer:g.ignoreDepthValues===!1})}T.isXRRenderTarget=!0,this.setFoveation(c),l=null,s=await n.requestReferenceSpace(o),Ue.setContext(n),Ue.start(),i.isPresenting=!0,i.dispatchEvent({type:"sessionstart"})}},this.getEnvironmentBlendMode=function(){if(n!==null)return n.environmentBlendMode},this.getDepthTexture=function(){return p.getDepthTexture()};function H(j){for(let oe=0;oe<j.removed.length;oe++){const ne=j.removed[oe],Te=y.indexOf(ne);Te>=0&&(y[Te]=null,U[Te].disconnect(ne))}for(let oe=0;oe<j.added.length;oe++){const ne=j.added[oe];let Te=y.indexOf(ne);if(Te===-1){for(let fe=0;fe<U.length;fe++)if(fe>=y.length){y.push(ne),Te=fe;break}else if(y[fe]===null){y[fe]=ne,Te=fe;break}if(Te===-1)break}const Pe=U[Te];Pe&&Pe.connect(ne)}}const Z=new G,Q=new G;function re(j,oe,ne){Z.setFromMatrixPosition(oe.matrixWorld),Q.setFromMatrixPosition(ne.matrixWorld);const Te=Z.distanceTo(Q),Pe=oe.projectionMatrix.elements,fe=ne.projectionMatrix.elements,Ve=Pe[14]/(Pe[10]-1),ke=Pe[14]/(Pe[10]+1),Le=(Pe[9]+1)/Pe[5],gt=(Pe[9]-1)/Pe[5],ft=(Pe[8]-1)/Pe[0],St=(fe[8]+1)/fe[0],tt=Ve*ft,Rt=Ve*St,P=Te/(-ft+St),ct=P*-ft;if(oe.matrixWorld.decompose(j.position,j.quaternion,j.scale),j.translateX(ct),j.translateZ(P),j.matrixWorld.compose(j.position,j.quaternion,j.scale),j.matrixWorldInverse.copy(j.matrixWorld).invert(),Pe[10]===-1)j.projectionMatrix.copy(oe.projectionMatrix),j.projectionMatrixInverse.copy(oe.projectionMatrixInverse);else{const Ne=Ve+P,Ze=ke+P,le=tt-ct,rt=Rt+(Te-ct),M=Le*ke/Ze*Ne,f=gt*ke/Ze*Ne;j.projectionMatrix.makePerspective(le,rt,M,f,Ne,Ze),j.projectionMatrixInverse.copy(j.projectionMatrix).invert()}}function ve(j,oe){oe===null?j.matrixWorld.copy(j.matrix):j.matrixWorld.multiplyMatrices(oe.matrixWorld,j.matrix),j.matrixWorldInverse.copy(j.matrixWorld).invert()}this.updateCamera=function(j){if(n===null)return;let oe=j.near,ne=j.far;p.texture!==null&&(p.depthNear>0&&(oe=p.depthNear),p.depthFar>0&&(ne=p.depthFar)),N.near=F.near=b.near=oe,N.far=F.far=b.far=ne,(W!==N.near||q!==N.far)&&(n.updateRenderState({depthNear:N.near,depthFar:N.far}),W=N.near,q=N.far),N.layers.mask=j.layers.mask|6,b.layers.mask=N.layers.mask&-5,F.layers.mask=N.layers.mask&-3;const Te=j.parent,Pe=N.cameras;ve(N,Te);for(let fe=0;fe<Pe.length;fe++)ve(Pe[fe],Te);Pe.length===2?re(N,b,F):N.projectionMatrix.copy(b.projectionMatrix),we(j,N,Te)};function we(j,oe,ne){ne===null?j.matrix.copy(oe.matrixWorld):(j.matrix.copy(ne.matrixWorld),j.matrix.invert(),j.matrix.multiply(oe.matrixWorld)),j.matrix.decompose(j.position,j.quaternion,j.scale),j.updateMatrixWorld(!0),j.projectionMatrix.copy(oe.projectionMatrix),j.projectionMatrixInverse.copy(oe.projectionMatrixInverse),j.isPerspectiveCamera&&(j.fov=La*2*Math.atan(1/j.projectionMatrix.elements[5]),j.zoom=1)}this.getCamera=function(){return N},this.getFoveation=function(){if(!(u===null&&g===null))return c},this.setFoveation=function(j){c=j,u!==null&&(u.fixedFoveation=j),g!==null&&g.fixedFoveation!==void 0&&(g.fixedFoveation=j)},this.hasDepthSensing=function(){return p.texture!==null},this.getDepthSensingMesh=function(){return p.getMesh(N)},this.getCameraTexture=function(j){return h[j]};let Ge=null;function Ye(j,oe){if(d=oe.getViewerPose(l||s),x=oe,d!==null){const ne=d.views;g!==null&&(e.setRenderTargetFramebuffer(T,g.framebuffer),e.setRenderTarget(T));let Te=!1;ne.length!==N.cameras.length&&(N.cameras.length=0,Te=!0);for(let fe=0;fe<ne.length;fe++){const Ve=ne[fe];let ke=null;if(g!==null)ke=g.getViewport(Ve);else{const gt=m.getViewSubImage(u,Ve);ke=gt.viewport,fe===0&&(e.setRenderTargetTextures(T,gt.colorTexture,gt.depthStencilTexture),e.setRenderTarget(T))}let Le=w[fe];Le===void 0&&(Le=new Ht,Le.layers.enable(fe),Le.viewport=new ot,w[fe]=Le),Le.matrix.fromArray(Ve.transform.matrix),Le.matrix.decompose(Le.position,Le.quaternion,Le.scale),Le.projectionMatrix.fromArray(Ve.projectionMatrix),Le.projectionMatrixInverse.copy(Le.projectionMatrix).invert(),Le.viewport.set(ke.x,ke.y,ke.width,ke.height),fe===0&&(N.matrix.copy(Le.matrix),N.matrix.decompose(N.position,N.quaternion,N.scale)),Te===!0&&N.cameras.push(Le)}const Pe=n.enabledFeatures;if(Pe&&Pe.includes("depth-sensing")&&n.depthUsage=="gpu-optimized"&&E){m=i.getBinding();const fe=m.getDepthInformation(ne[0]);fe&&fe.isValid&&fe.texture&&p.init(fe,n.renderState)}if(Pe&&Pe.includes("camera-access")&&E){e.state.unbindTexture(),m=i.getBinding();for(let fe=0;fe<ne.length;fe++){const Ve=ne[fe].camera;if(Ve){let ke=h[Ve];ke||(ke=new Po,h[Ve]=ke);const Le=m.getCameraImage(Ve);ke.sourceTexture=Le}}}}for(let ne=0;ne<U.length;ne++){const Te=y[ne],Pe=U[ne];Te!==null&&Pe!==void 0&&Pe.update(Te,oe,l||s)}Ge&&Ge(j,oe),oe.detectedPlanes&&i.dispatchEvent({type:"planesdetected",data:oe}),x=null}const Ue=new zo;Ue.setAnimationLoop(Ye),this.setAnimationLoop=function(j){Ge=j},this.dispose=function(){}}}const cm=new ht,ml=new Ce;ml.set(-1,0,0,0,1,0,0,0,1);function um(r,e){function t(p,h){p.matrixAutoUpdate===!0&&p.updateMatrix(),h.value.copy(p.matrix)}function i(p,h){h.color.getRGB(p.fogColor.value,Do(r)),h.isFog?(p.fogNear.value=h.near,p.fogFar.value=h.far):h.isFogExp2&&(p.fogDensity.value=h.density)}function n(p,h,S,A,T){h.isNodeMaterial?h.uniformsNeedUpdate=!1:h.isMeshBasicMaterial?a(p,h):h.isMeshLambertMaterial?(a(p,h),h.envMap&&(p.envMapIntensity.value=h.envMapIntensity)):h.isMeshToonMaterial?(a(p,h),m(p,h)):h.isMeshPhongMaterial?(a(p,h),d(p,h),h.envMap&&(p.envMapIntensity.value=h.envMapIntensity)):h.isMeshStandardMaterial?(a(p,h),u(p,h),h.isMeshPhysicalMaterial&&g(p,h,T)):h.isMeshMatcapMaterial?(a(p,h),x(p,h)):h.isMeshDepthMaterial?a(p,h):h.isMeshDistanceMaterial?(a(p,h),E(p,h)):h.isMeshNormalMaterial?a(p,h):h.isLineBasicMaterial?(s(p,h),h.isLineDashedMaterial&&o(p,h)):h.isPointsMaterial?c(p,h,S,A):h.isSpriteMaterial?l(p,h):h.isShadowMaterial?(p.color.value.copy(h.color),p.opacity.value=h.opacity):h.isShaderMaterial&&(h.uniformsNeedUpdate=!1)}function a(p,h){p.opacity.value=h.opacity,h.color&&p.diffuse.value.copy(h.color),h.emissive&&p.emissive.value.copy(h.emissive).multiplyScalar(h.emissiveIntensity),h.map&&(p.map.value=h.map,t(h.map,p.mapTransform)),h.alphaMap&&(p.alphaMap.value=h.alphaMap,t(h.alphaMap,p.alphaMapTransform)),h.bumpMap&&(p.bumpMap.value=h.bumpMap,t(h.bumpMap,p.bumpMapTransform),p.bumpScale.value=h.bumpScale,h.side===bt&&(p.bumpScale.value*=-1)),h.normalMap&&(p.normalMap.value=h.normalMap,t(h.normalMap,p.normalMapTransform),p.normalScale.value.copy(h.normalScale),h.side===bt&&p.normalScale.value.negate()),h.displacementMap&&(p.displacementMap.value=h.displacementMap,t(h.displacementMap,p.displacementMapTransform),p.displacementScale.value=h.displacementScale,p.displacementBias.value=h.displacementBias),h.emissiveMap&&(p.emissiveMap.value=h.emissiveMap,t(h.emissiveMap,p.emissiveMapTransform)),h.specularMap&&(p.specularMap.value=h.specularMap,t(h.specularMap,p.specularMapTransform)),h.alphaTest>0&&(p.alphaTest.value=h.alphaTest);const S=e.get(h),A=S.envMap,T=S.envMapRotation;A&&(p.envMap.value=A,p.envMapRotation.value.setFromMatrix4(cm.makeRotationFromEuler(T)).transpose(),A.isCubeTexture&&A.isRenderTargetTexture===!1&&p.envMapRotation.value.premultiply(ml),p.reflectivity.value=h.reflectivity,p.ior.value=h.ior,p.refractionRatio.value=h.refractionRatio),h.lightMap&&(p.lightMap.value=h.lightMap,p.lightMapIntensity.value=h.lightMapIntensity,t(h.lightMap,p.lightMapTransform)),h.aoMap&&(p.aoMap.value=h.aoMap,p.aoMapIntensity.value=h.aoMapIntensity,t(h.aoMap,p.aoMapTransform))}function s(p,h){p.diffuse.value.copy(h.color),p.opacity.value=h.opacity,h.map&&(p.map.value=h.map,t(h.map,p.mapTransform))}function o(p,h){p.dashSize.value=h.dashSize,p.totalSize.value=h.dashSize+h.gapSize,p.scale.value=h.scale}function c(p,h,S,A){p.diffuse.value.copy(h.color),p.opacity.value=h.opacity,p.size.value=h.size*S,p.scale.value=A*.5,h.map&&(p.map.value=h.map,t(h.map,p.uvTransform)),h.alphaMap&&(p.alphaMap.value=h.alphaMap,t(h.alphaMap,p.alphaMapTransform)),h.alphaTest>0&&(p.alphaTest.value=h.alphaTest)}function l(p,h){p.diffuse.value.copy(h.color),p.opacity.value=h.opacity,p.rotation.value=h.rotation,h.map&&(p.map.value=h.map,t(h.map,p.mapTransform)),h.alphaMap&&(p.alphaMap.value=h.alphaMap,t(h.alphaMap,p.alphaMapTransform)),h.alphaTest>0&&(p.alphaTest.value=h.alphaTest)}function d(p,h){p.specular.value.copy(h.specular),p.shininess.value=Math.max(h.shininess,1e-4)}function m(p,h){h.gradientMap&&(p.gradientMap.value=h.gradientMap)}function u(p,h){p.metalness.value=h.metalness,h.metalnessMap&&(p.metalnessMap.value=h.metalnessMap,t(h.metalnessMap,p.metalnessMapTransform)),p.roughness.value=h.roughness,h.roughnessMap&&(p.roughnessMap.value=h.roughnessMap,t(h.roughnessMap,p.roughnessMapTransform)),h.envMap&&(p.envMapIntensity.value=h.envMapIntensity)}function g(p,h,S){p.ior.value=h.ior,h.sheen>0&&(p.sheenColor.value.copy(h.sheenColor).multiplyScalar(h.sheen),p.sheenRoughness.value=h.sheenRoughness,h.sheenColorMap&&(p.sheenColorMap.value=h.sheenColorMap,t(h.sheenColorMap,p.sheenColorMapTransform)),h.sheenRoughnessMap&&(p.sheenRoughnessMap.value=h.sheenRoughnessMap,t(h.sheenRoughnessMap,p.sheenRoughnessMapTransform))),h.clearcoat>0&&(p.clearcoat.value=h.clearcoat,p.clearcoatRoughness.value=h.clearcoatRoughness,h.clearcoatMap&&(p.clearcoatMap.value=h.clearcoatMap,t(h.clearcoatMap,p.clearcoatMapTransform)),h.clearcoatRoughnessMap&&(p.clearcoatRoughnessMap.value=h.clearcoatRoughnessMap,t(h.clearcoatRoughnessMap,p.clearcoatRoughnessMapTransform)),h.clearcoatNormalMap&&(p.clearcoatNormalMap.value=h.clearcoatNormalMap,t(h.clearcoatNormalMap,p.clearcoatNormalMapTransform),p.clearcoatNormalScale.value.copy(h.clearcoatNormalScale),h.side===bt&&p.clearcoatNormalScale.value.negate())),h.dispersion>0&&(p.dispersion.value=h.dispersion),h.iridescence>0&&(p.iridescence.value=h.iridescence,p.iridescenceIOR.value=h.iridescenceIOR,p.iridescenceThicknessMinimum.value=h.iridescenceThicknessRange[0],p.iridescenceThicknessMaximum.value=h.iridescenceThicknessRange[1],h.iridescenceMap&&(p.iridescenceMap.value=h.iridescenceMap,t(h.iridescenceMap,p.iridescenceMapTransform)),h.iridescenceThicknessMap&&(p.iridescenceThicknessMap.value=h.iridescenceThicknessMap,t(h.iridescenceThicknessMap,p.iridescenceThicknessMapTransform))),h.transmission>0&&(p.transmission.value=h.transmission,p.transmissionSamplerMap.value=S.texture,p.transmissionSamplerSize.value.set(S.width,S.height),h.transmissionMap&&(p.transmissionMap.value=h.transmissionMap,t(h.transmissionMap,p.transmissionMapTransform)),p.thickness.value=h.thickness,h.thicknessMap&&(p.thicknessMap.value=h.thicknessMap,t(h.thicknessMap,p.thicknessMapTransform)),p.attenuationDistance.value=h.attenuationDistance,p.attenuationColor.value.copy(h.attenuationColor)),h.anisotropy>0&&(p.anisotropyVector.value.set(h.anisotropy*Math.cos(h.anisotropyRotation),h.anisotropy*Math.sin(h.anisotropyRotation)),h.anisotropyMap&&(p.anisotropyMap.value=h.anisotropyMap,t(h.anisotropyMap,p.anisotropyMapTransform))),p.specularIntensity.value=h.specularIntensity,p.specularColor.value.copy(h.specularColor),h.specularColorMap&&(p.specularColorMap.value=h.specularColorMap,t(h.specularColorMap,p.specularColorMapTransform)),h.specularIntensityMap&&(p.specularIntensityMap.value=h.specularIntensityMap,t(h.specularIntensityMap,p.specularIntensityMapTransform))}function x(p,h){h.matcap&&(p.matcap.value=h.matcap)}function E(p,h){const S=e.get(h).light;p.referencePosition.value.setFromMatrixPosition(S.matrixWorld),p.nearDistance.value=S.shadow.camera.near,p.farDistance.value=S.shadow.camera.far}return{refreshFogUniforms:i,refreshMaterialUniforms:n}}function hm(r,e,t,i){let n={},a={},s=[];const o=r.getParameter(r.MAX_UNIFORM_BUFFER_BINDINGS);function c(S,A){const T=A.program;i.uniformBlockBinding(S,T)}function l(S,A){let T=n[S.id];T===void 0&&(x(S),T=d(S),n[S.id]=T,S.addEventListener("dispose",p));const U=A.program;i.updateUBOMapping(S,U);const y=e.render.frame;a[S.id]!==y&&(u(S),a[S.id]=y)}function d(S){const A=m();S.__bindingPointIndex=A;const T=r.createBuffer(),U=S.__size,y=S.usage;return r.bindBuffer(r.UNIFORM_BUFFER,T),r.bufferData(r.UNIFORM_BUFFER,U,y),r.bindBuffer(r.UNIFORM_BUFFER,null),r.bindBufferBase(r.UNIFORM_BUFFER,A,T),T}function m(){for(let S=0;S<o;S++)if(s.indexOf(S)===-1)return s.push(S),S;return He("WebGLRenderer: Maximum number of simultaneously usable uniforms groups reached."),0}function u(S){const A=n[S.id],T=S.uniforms,U=S.__cache;r.bindBuffer(r.UNIFORM_BUFFER,A);for(let y=0,C=T.length;y<C;y++){const v=Array.isArray(T[y])?T[y]:[T[y]];for(let b=0,F=v.length;b<F;b++){const w=v[b];if(g(w,y,b,U)===!0){const N=w.__offset,W=Array.isArray(w.value)?w.value:[w.value];let q=0;for(let L=0;L<W.length;L++){const V=W[L],H=E(V);typeof V=="number"||typeof V=="boolean"?(w.__data[0]=V,r.bufferSubData(r.UNIFORM_BUFFER,N+q,w.__data)):V.isMatrix3?(w.__data[0]=V.elements[0],w.__data[1]=V.elements[1],w.__data[2]=V.elements[2],w.__data[3]=0,w.__data[4]=V.elements[3],w.__data[5]=V.elements[4],w.__data[6]=V.elements[5],w.__data[7]=0,w.__data[8]=V.elements[6],w.__data[9]=V.elements[7],w.__data[10]=V.elements[8],w.__data[11]=0):ArrayBuffer.isView(V)?w.__data.set(new V.constructor(V.buffer,V.byteOffset,w.__data.length)):(V.toArray(w.__data,q),q+=H.storage/Float32Array.BYTES_PER_ELEMENT)}r.bufferSubData(r.UNIFORM_BUFFER,N,w.__data)}}}r.bindBuffer(r.UNIFORM_BUFFER,null)}function g(S,A,T,U){const y=S.value,C=A+"_"+T;if(U[C]===void 0)return typeof y=="number"||typeof y=="boolean"?U[C]=y:ArrayBuffer.isView(y)?U[C]=y.slice():U[C]=y.clone(),!0;{const v=U[C];if(typeof y=="number"||typeof y=="boolean"){if(v!==y)return U[C]=y,!0}else{if(ArrayBuffer.isView(y))return!0;if(v.equals(y)===!1)return v.copy(y),!0}}return!1}function x(S){const A=S.uniforms;let T=0;const U=16;for(let C=0,v=A.length;C<v;C++){const b=Array.isArray(A[C])?A[C]:[A[C]];for(let F=0,w=b.length;F<w;F++){const N=b[F],W=Array.isArray(N.value)?N.value:[N.value];for(let q=0,L=W.length;q<L;q++){const V=W[q],H=E(V),Z=T%U,Q=Z%H.boundary,re=Z+Q;T+=Q,re!==0&&U-re<H.storage&&(T+=U-re),N.__data=new Float32Array(H.storage/Float32Array.BYTES_PER_ELEMENT),N.__offset=T,T+=H.storage}}}const y=T%U;return y>0&&(T+=U-y),S.__size=T,S.__cache={},this}function E(S){const A={boundary:0,storage:0};return typeof S=="number"||typeof S=="boolean"?(A.boundary=4,A.storage=4):S.isVector2?(A.boundary=8,A.storage=8):S.isVector3||S.isColor?(A.boundary=16,A.storage=12):S.isVector4?(A.boundary=16,A.storage=16):S.isMatrix3?(A.boundary=48,A.storage=48):S.isMatrix4?(A.boundary=64,A.storage=64):S.isTexture?Ae("WebGLRenderer: Texture samplers can not be part of an uniforms group."):ArrayBuffer.isView(S)?(A.boundary=16,A.storage=S.byteLength):Ae("WebGLRenderer: Unsupported uniform value type.",S),A}function p(S){const A=S.target;A.removeEventListener("dispose",p);const T=s.indexOf(A.__bindingPointIndex);s.splice(T,1),r.deleteBuffer(n[A.id]),delete n[A.id],delete a[A.id]}function h(){for(const S in n)r.deleteBuffer(n[S]);s=[],n={},a={}}return{bind:c,update:l,dispose:h}}const dm=new Uint16Array([12469,15057,12620,14925,13266,14620,13807,14376,14323,13990,14545,13625,14713,13328,14840,12882,14931,12528,14996,12233,15039,11829,15066,11525,15080,11295,15085,10976,15082,10705,15073,10495,13880,14564,13898,14542,13977,14430,14158,14124,14393,13732,14556,13410,14702,12996,14814,12596,14891,12291,14937,11834,14957,11489,14958,11194,14943,10803,14921,10506,14893,10278,14858,9960,14484,14039,14487,14025,14499,13941,14524,13740,14574,13468,14654,13106,14743,12678,14818,12344,14867,11893,14889,11509,14893,11180,14881,10751,14852,10428,14812,10128,14765,9754,14712,9466,14764,13480,14764,13475,14766,13440,14766,13347,14769,13070,14786,12713,14816,12387,14844,11957,14860,11549,14868,11215,14855,10751,14825,10403,14782,10044,14729,9651,14666,9352,14599,9029,14967,12835,14966,12831,14963,12804,14954,12723,14936,12564,14917,12347,14900,11958,14886,11569,14878,11247,14859,10765,14828,10401,14784,10011,14727,9600,14660,9289,14586,8893,14508,8533,15111,12234,15110,12234,15104,12216,15092,12156,15067,12010,15028,11776,14981,11500,14942,11205,14902,10752,14861,10393,14812,9991,14752,9570,14682,9252,14603,8808,14519,8445,14431,8145,15209,11449,15208,11451,15202,11451,15190,11438,15163,11384,15117,11274,15055,10979,14994,10648,14932,10343,14871,9936,14803,9532,14729,9218,14645,8742,14556,8381,14461,8020,14365,7603,15273,10603,15272,10607,15267,10619,15256,10631,15231,10614,15182,10535,15118,10389,15042,10167,14963,9787,14883,9447,14800,9115,14710,8665,14615,8318,14514,7911,14411,7507,14279,7198,15314,9675,15313,9683,15309,9712,15298,9759,15277,9797,15229,9773,15166,9668,15084,9487,14995,9274,14898,8910,14800,8539,14697,8234,14590,7790,14479,7409,14367,7067,14178,6621,15337,8619,15337,8631,15333,8677,15325,8769,15305,8871,15264,8940,15202,8909,15119,8775,15022,8565,14916,8328,14804,8009,14688,7614,14569,7287,14448,6888,14321,6483,14088,6171,15350,7402,15350,7419,15347,7480,15340,7613,15322,7804,15287,7973,15229,8057,15148,8012,15046,7846,14933,7611,14810,7357,14682,7069,14552,6656,14421,6316,14251,5948,14007,5528,15356,5942,15356,5977,15353,6119,15348,6294,15332,6551,15302,6824,15249,7044,15171,7122,15070,7050,14949,6861,14818,6611,14679,6349,14538,6067,14398,5651,14189,5311,13935,4958,15359,4123,15359,4153,15356,4296,15353,4646,15338,5160,15311,5508,15263,5829,15188,6042,15088,6094,14966,6001,14826,5796,14678,5543,14527,5287,14377,4985,14133,4586,13869,4257,15360,1563,15360,1642,15358,2076,15354,2636,15341,3350,15317,4019,15273,4429,15203,4732,15105,4911,14981,4932,14836,4818,14679,4621,14517,4386,14359,4156,14083,3795,13808,3437,15360,122,15360,137,15358,285,15355,636,15344,1274,15322,2177,15281,2765,15215,3223,15120,3451,14995,3569,14846,3567,14681,3466,14511,3305,14344,3121,14037,2800,13753,2467,15360,0,15360,1,15359,21,15355,89,15346,253,15325,479,15287,796,15225,1148,15133,1492,15008,1749,14856,1882,14685,1886,14506,1783,14324,1608,13996,1398,13702,1183]);let ti=null;function pm(){return ti===null&&(ti=new nu(dm,16,16,Oi,li),ti.name="DFG_LUT",ti.minFilter=vt,ti.magFilter=vt,ti.wrapS=oi,ti.wrapT=oi,ti.generateMipmaps=!1,ti.needsUpdate=!0),ti}class fm{constructor(e={}){const{canvas:t=Lc(),context:i=null,depth:n=!0,stencil:a=!1,alpha:s=!1,antialias:o=!1,premultipliedAlpha:c=!0,preserveDrawingBuffer:l=!1,powerPreference:d="default",failIfMajorPerformanceCaveat:m=!1,reversedDepthBuffer:u=!1,outputBufferType:g=Lt}=e;this.isWebGLRenderer=!0;let x;if(i!==null){if(typeof WebGLRenderingContext<"u"&&i instanceof WebGLRenderingContext)throw new Error("THREE.WebGLRenderer: WebGL 1 is not supported since r163.");x=i.getContextAttributes().alpha}else x=s;const E=g,p=new Set([Qn,$n,Zn]),h=new Set([Lt,Yt,xr,Mr,Kn,Jn]),S=new Uint32Array(4),A=new Int32Array(4),T=new G;let U=null,y=null;const C=[],v=[];let b=null;this.domElement=t,this.debug={checkShaderErrors:!0,onShaderError:null},this.autoClear=!0,this.autoClearColor=!0,this.autoClearDepth=!0,this.autoClearStencil=!0,this.sortObjects=!0,this.clippingPlanes=[],this.localClippingEnabled=!1,this.toneMapping=qt,this.toneMappingExposure=1,this.transmissionResolutionScale=1;const F=this;let w=!1,N=null;this._outputColorSpace=At;let W=0,q=0,L=null,V=-1,H=null;const Z=new ot,Q=new ot;let re=null;const ve=new qe(0);let we=0,Ge=t.width,Ye=t.height,Ue=1,j=null,oe=null;const ne=new ot(0,0,Ge,Ye),Te=new ot(0,0,Ge,Ye);let Pe=!1;const fe=new Ro;let Ve=!1,ke=!1;const Le=new ht,gt=new G,ft=new ot,St={background:null,fog:null,environment:null,overrideMaterial:null,isScene:!0};let tt=!1;function Rt(){return L===null?Ue:1}let P=i;function ct(_,I){return t.getContext(_,I)}try{const _={alpha:!0,depth:n,stencil:a,antialias:o,premultipliedAlpha:c,preserveDrawingBuffer:l,powerPreference:d,failIfMajorPerformanceCaveat:m};if("setAttribute"in t&&t.setAttribute("data-engine",`three.js r${In}`),t.addEventListener("webglcontextlost",$,!1),t.addEventListener("webglcontextrestored",Me,!1),t.addEventListener("webglcontextcreationerror",ye,!1),P===null){const I="webgl2";if(P=ct(I,_),P===null)throw ct(I)?new Error("Error creating WebGL context with your selected attributes."):new Error("Error creating WebGL context.")}}catch(_){throw He("WebGLRenderer: "+_.message),_}let Ne,Ze,le,rt,M,f,O,Y,K,ae,se,D,ie,ce,pe,J,Se,Re,Oe,We,R,X,ee;function xe(){Ne=new dp(P),Ne.init(),R=new nm(P,Ne),Ze=new np(P,Ne,e,R),le=new im(P,Ne),Ze.reversedDepthBuffer&&u&&le.buffers.depth.setReversed(!0),rt=new mp(P),M=new Vf,f=new rm(P,Ne,le,M,Ze,R,rt),O=new hp(F),Y=new xu(P),X=new ip(P,Y),K=new pp(P,Y,rt,X),ae=new _p(P,K,Y,X,rt),Re=new gp(P,Ze,f),pe=new ap(M),se=new Hf(F,O,Ne,Ze,X,pe),D=new um(F,M),ie=new Wf,ce=new Jf(Ne),Se=new tp(F,O,le,ae,x,c),J=new tm(F,ae,Ze),ee=new hm(P,rt,Ze,le),Oe=new rp(P,Ne,rt),We=new fp(P,Ne,rt),rt.programs=se.programs,F.capabilities=Ze,F.extensions=Ne,F.properties=M,F.renderLists=ie,F.shadowMap=J,F.state=le,F.info=rt}xe(),E!==Lt&&(b=new xp(E,t.width,t.height,n,a));const ue=new lm(F,P);this.xr=ue,this.getContext=function(){return P},this.getContextAttributes=function(){return P.getContextAttributes()},this.forceContextLoss=function(){const _=Ne.get("WEBGL_lose_context");_&&_.loseContext()},this.forceContextRestore=function(){const _=Ne.get("WEBGL_lose_context");_&&_.restoreContext()},this.getPixelRatio=function(){return Ue},this.setPixelRatio=function(_){_!==void 0&&(Ue=_,this.setSize(Ge,Ye,!1))},this.getSize=function(_){return _.set(Ge,Ye)},this.setSize=function(_,I,k=!0){if(ue.isPresenting){Ae("WebGLRenderer: Can't change size while VR device is presenting.");return}Ge=_,Ye=I,t.width=Math.floor(_*Ue),t.height=Math.floor(I*Ue),k===!0&&(t.style.width=_+"px",t.style.height=I+"px"),b!==null&&b.setSize(t.width,t.height),this.setViewport(0,0,_,I)},this.getDrawingBufferSize=function(_){return _.set(Ge*Ue,Ye*Ue).floor()},this.setDrawingBufferSize=function(_,I,k){Ge=_,Ye=I,Ue=k,t.width=Math.floor(_*k),t.height=Math.floor(I*k),this.setViewport(0,0,_,I)},this.setEffects=function(_){if(E===Lt){He("THREE.WebGLRenderer: setEffects() requires outputBufferType set to HalfFloatType or FloatType.");return}if(_){for(let I=0;I<_.length;I++)if(_[I].isOutputPass===!0){Ae("THREE.WebGLRenderer: OutputPass is not needed in setEffects(). Tone mapping and color space conversion are applied automatically.");break}}b.setEffects(_||[])},this.getCurrentViewport=function(_){return _.copy(Z)},this.getViewport=function(_){return _.copy(ne)},this.setViewport=function(_,I,k,z){_.isVector4?ne.set(_.x,_.y,_.z,_.w):ne.set(_,I,k,z),le.viewport(Z.copy(ne).multiplyScalar(Ue).round())},this.getScissor=function(_){return _.copy(Te)},this.setScissor=function(_,I,k,z){_.isVector4?Te.set(_.x,_.y,_.z,_.w):Te.set(_,I,k,z),le.scissor(Q.copy(Te).multiplyScalar(Ue).round())},this.getScissorTest=function(){return Pe},this.setScissorTest=function(_){le.setScissorTest(Pe=_)},this.setOpaqueSort=function(_){j=_},this.setTransparentSort=function(_){oe=_},this.getClearColor=function(_){return _.copy(Se.getClearColor())},this.setClearColor=function(){Se.setClearColor(...arguments)},this.getClearAlpha=function(){return Se.getClearAlpha()},this.setClearAlpha=function(){Se.setClearAlpha(...arguments)},this.clear=function(_=!0,I=!0,k=!0){let z=0;if(_){let B=!1;if(L!==null){const te=L.texture.format;B=p.has(te)}if(B){const te=L.texture.type,de=h.has(te),me=Se.getClearColor(),ge=Se.getClearAlpha(),be=me.r,Ie=me.g,Fe=me.b;de?(S[0]=be,S[1]=Ie,S[2]=Fe,S[3]=ge,P.clearBufferuiv(P.COLOR,0,S)):(A[0]=be,A[1]=Ie,A[2]=Fe,A[3]=ge,P.clearBufferiv(P.COLOR,0,A))}else z|=P.COLOR_BUFFER_BIT}I&&(z|=P.DEPTH_BUFFER_BIT,this.state.buffers.depth.setMask(!0)),k&&(z|=P.STENCIL_BUFFER_BIT,this.state.buffers.stencil.setMask(4294967295)),z!==0&&P.clear(z)},this.clearColor=function(){this.clear(!0,!1,!1)},this.clearDepth=function(){this.clear(!1,!0,!1)},this.clearStencil=function(){this.clear(!1,!1,!0)},this.setNodesHandler=function(_){_.setRenderer(this),N=_},this.dispose=function(){t.removeEventListener("webglcontextlost",$,!1),t.removeEventListener("webglcontextrestored",Me,!1),t.removeEventListener("webglcontextcreationerror",ye,!1),Se.dispose(),ie.dispose(),ce.dispose(),M.dispose(),O.dispose(),ae.dispose(),X.dispose(),ee.dispose(),se.dispose(),ue.dispose(),ue.removeEventListener("sessionstart",xs),ue.removeEventListener("sessionend",Ms),Pi.stop()};function $(_){_.preventDefault(),ao("WebGLRenderer: Context Lost."),w=!0}function Me(){ao("WebGLRenderer: Context Restored."),w=!1;const _=rt.autoReset,I=J.enabled,k=J.autoUpdate,z=J.needsUpdate,B=J.type;xe(),rt.autoReset=_,J.enabled=I,J.autoUpdate=k,J.needsUpdate=z,J.type=B}function ye(_){He("WebGLRenderer: A WebGL context could not be created. Reason: ",_.statusMessage)}function Et(_){const I=_.target;I.removeEventListener("dispose",Et),et(I)}function et(_){ri(_),M.remove(_)}function ri(_){const I=M.get(_).programs;I!==void 0&&(I.forEach(function(k){se.releaseProgram(k)}),_.isShaderMaterial&&se.releaseShaderCache(_))}this.renderBufferDirect=function(_,I,k,z,B,te){I===null&&(I=St);const de=B.isMesh&&B.matrixWorld.determinant()<0,me=Tl(_,I,k,z,B);le.setMaterial(z,de);let ge=k.index,be=1;if(z.wireframe===!0){if(ge=K.getWireframeAttribute(k),ge===void 0)return;be=2}const Ie=k.drawRange,Fe=k.attributes.position;let Ee=Ie.start*be,$e=(Ie.start+Ie.count)*be;te!==null&&(Ee=Math.max(Ee,te.start*be),$e=Math.min($e,(te.start+te.count)*be)),ge!==null?(Ee=Math.max(Ee,0),$e=Math.min($e,ge.count)):Fe!=null&&(Ee=Math.max(Ee,0),$e=Math.min($e,Fe.count));const at=$e-Ee;if(at<0||at===1/0)return;X.setup(B,z,me,k,ge);let it,Qe=Oe;if(ge!==null&&(it=Y.get(ge),Qe=We,Qe.setIndex(it)),B.isMesh)z.wireframe===!0?(le.setLineWidth(z.wireframeLinewidth*Rt()),Qe.setMode(P.LINES)):Qe.setMode(P.TRIANGLES);else if(B.isLine){let nt=z.linewidth;nt===void 0&&(nt=1),le.setLineWidth(nt*Rt()),B.isLineSegments?Qe.setMode(P.LINES):B.isLineLoop?Qe.setMode(P.LINE_LOOP):Qe.setMode(P.LINE_STRIP)}else B.isPoints?Qe.setMode(P.POINTS):B.isSprite&&Qe.setMode(P.TRIANGLES);if(B.isBatchedMesh)if(Ne.get("WEBGL_multi_draw"))Qe.renderMultiDraw(B._multiDrawStarts,B._multiDrawCounts,B._multiDrawCount);else{const nt=B._multiDrawStarts,_e=B._multiDrawCounts,Ct=B._multiDrawCount,Ui=ge?Y.get(ge).bytesPerElement:1,It=M.get(z).currentProgram.getUniforms();for(let Xt=0;Xt<Ct;Xt++)It.setValue(P,"_gl_DrawID",Xt),Qe.render(nt[Xt]/Ui,_e[Xt])}else if(B.isInstancedMesh)Qe.renderInstances(Ee,at,B.count);else if(k.isInstancedBufferGeometry){const nt=k._maxInstanceCount!==void 0?k._maxInstanceCount:1/0,_e=Math.min(k.instanceCount,nt);Qe.renderInstances(Ee,at,_e)}else Qe.render(Ee,at)};function Wt(_,I,k){_.transparent===!0&&_.side===ai&&_.forceSinglePass===!1?(_.side=bt,_.needsUpdate=!0,Lr(_,I,k),_.side=ni,_.needsUpdate=!0,Lr(_,I,k),_.side=ai):Lr(_,I,k)}this.compile=function(_,I,k=null){k===null&&(k=_),y=ce.get(k),y.init(I),v.push(y),k.traverseVisible(function(B){B.isLight&&B.layers.test(I.layers)&&(y.pushLight(B),B.castShadow&&y.pushShadow(B))}),_!==k&&_.traverseVisible(function(B){B.isLight&&B.layers.test(I.layers)&&(y.pushLight(B),B.castShadow&&y.pushShadow(B))}),y.setupLights();const z=new Set;return _.traverse(function(B){if(!(B.isMesh||B.isPoints||B.isLine||B.isSprite))return;const te=B.material;if(te)if(Array.isArray(te))for(let de=0;de<te.length;de++){const me=te[de];Wt(me,k,B),z.add(me)}else Wt(te,k,B),z.add(te)}),y=v.pop(),z},this.compileAsync=function(_,I,k=null){const z=this.compile(_,I,k);return new Promise(B=>{function te(){if(z.forEach(function(de){M.get(de).currentProgram.isReady()&&z.delete(de)}),z.size===0){B(_);return}setTimeout(te,10)}Ne.get("KHR_parallel_shader_compile")!==null?te():setTimeout(te,10)})};let Rn=null;function Sl(_){Rn&&Rn(_)}function xs(){Pi.stop()}function Ms(){Pi.start()}const Pi=new zo;Pi.setAnimationLoop(Sl),typeof self<"u"&&Pi.setContext(self),this.setAnimationLoop=function(_){Rn=_,ue.setAnimationLoop(_),_===null?Pi.stop():Pi.start()},ue.addEventListener("sessionstart",xs),ue.addEventListener("sessionend",Ms),this.render=function(_,I){if(I!==void 0&&I.isCamera!==!0){He("WebGLRenderer.render: camera is not an instance of THREE.Camera.");return}if(w===!0)return;N!==null&&N.renderStart(_,I);const k=ue.enabled===!0&&ue.isPresenting===!0,z=b!==null&&(L===null||k)&&b.begin(F,L);if(_.matrixWorldAutoUpdate===!0&&_.updateMatrixWorld(),I.parent===null&&I.matrixWorldAutoUpdate===!0&&I.updateMatrixWorld(),ue.enabled===!0&&ue.isPresenting===!0&&(b===null||b.isCompositing()===!1)&&(ue.cameraAutoUpdate===!0&&ue.updateCamera(I),I=ue.getCamera()),_.isScene===!0&&_.onBeforeRender(F,_,I,L),y=ce.get(_,v.length),y.init(I),y.state.textureUnits=f.getTextureUnits(),v.push(y),Le.multiplyMatrices(I.projectionMatrix,I.matrixWorldInverse),fe.setFromProjectionMatrix(Le,Kt,I.reversedDepth),ke=this.localClippingEnabled,Ve=pe.init(this.clippingPlanes,ke),U=ie.get(_,C.length),U.init(),C.push(U),ue.enabled===!0&&ue.isPresenting===!0){const te=F.xr.getDepthSensingMesh();te!==null&&Cn(te,I,-1/0,F.sortObjects)}Cn(_,I,0,F.sortObjects),U.finish(),F.sortObjects===!0&&U.sort(j,oe),tt=ue.enabled===!1||ue.isPresenting===!1||ue.hasDepthSensing()===!1,tt&&Se.addToRenderList(U,_),this.info.render.frame++,Ve===!0&&pe.beginShadows();const B=y.state.shadowsArray;if(J.render(B,_,I),Ve===!0&&pe.endShadows(),this.info.autoReset===!0&&this.info.reset(),(z&&b.hasRenderPass())===!1){const te=U.opaque,de=U.transmissive;if(y.setupLights(),I.isArrayCamera){const me=I.cameras;if(de.length>0)for(let ge=0,be=me.length;ge<be;ge++){const Ie=me[ge];Es(te,de,_,Ie)}tt&&Se.render(_);for(let ge=0,be=me.length;ge<be;ge++){const Ie=me[ge];Ss(U,_,Ie,Ie.viewport)}}else de.length>0&&Es(te,de,_,I),tt&&Se.render(_),Ss(U,_,I)}L!==null&&q===0&&(f.updateMultisampleRenderTarget(L),f.updateRenderTargetMipmap(L)),z&&b.end(F),_.isScene===!0&&_.onAfterRender(F,_,I),X.resetDefaultState(),V=-1,H=null,v.pop(),v.length>0?(y=v[v.length-1],f.setTextureUnits(y.state.textureUnits),Ve===!0&&pe.setGlobalState(F.clippingPlanes,y.state.camera)):y=null,C.pop(),C.length>0?U=C[C.length-1]:U=null,N!==null&&N.renderEnd()};function Cn(_,I,k,z){if(_.visible===!1)return;if(_.layers.test(I.layers)){if(_.isGroup)k=_.renderOrder;else if(_.isLOD)_.autoUpdate===!0&&_.update(I);else if(_.isLightProbeGrid)y.pushLightProbeGrid(_);else if(_.isLight)y.pushLight(_),_.castShadow&&y.pushShadow(_);else if(_.isSprite){if(!_.frustumCulled||fe.intersectsSprite(_)){z&&ft.setFromMatrixPosition(_.matrixWorld).applyMatrix4(Le);const te=ae.update(_),de=_.material;de.visible&&U.push(_,te,de,k,ft.z,null)}}else if((_.isMesh||_.isLine||_.isPoints)&&(!_.frustumCulled||fe.intersectsObject(_))){const te=ae.update(_),de=_.material;if(z&&(_.boundingSphere!==void 0?(_.boundingSphere===null&&_.computeBoundingSphere(),ft.copy(_.boundingSphere.center)):(te.boundingSphere===null&&te.computeBoundingSphere(),ft.copy(te.boundingSphere.center)),ft.applyMatrix4(_.matrixWorld).applyMatrix4(Le)),Array.isArray(de)){const me=te.groups;for(let ge=0,be=me.length;ge<be;ge++){const Ie=me[ge],Fe=de[Ie.materialIndex];Fe&&Fe.visible&&U.push(_,te,Fe,k,ft.z,Ie)}}else de.visible&&U.push(_,te,de,k,ft.z,null)}}const B=_.children;for(let te=0,de=B.length;te<de;te++)Cn(B[te],I,k,z)}function Ss(_,I,k,z){const{opaque:B,transmissive:te,transparent:de}=_;y.setupLightsView(k),Ve===!0&&pe.setGlobalState(F.clippingPlanes,k),z&&le.viewport(Z.copy(z)),B.length>0&&Ir(B,I,k),te.length>0&&Ir(te,I,k),de.length>0&&Ir(de,I,k),le.buffers.depth.setTest(!0),le.buffers.depth.setMask(!0),le.buffers.color.setMask(!0),le.setPolygonOffset(!1)}function Es(_,I,k,z){if((k.isScene===!0?k.overrideMaterial:null)!==null)return;if(y.state.transmissionRenderTarget[z.id]===void 0){const Fe=Ne.has("EXT_color_buffer_half_float")||Ne.has("EXT_color_buffer_float");y.state.transmissionRenderTarget[z.id]=new Jt(1,1,{generateMipmaps:!0,type:Fe?li:Lt,minFilter:Ni,samples:Math.max(4,Ze.samples),stencilBuffer:a,resolveDepthBuffer:!1,resolveStencilBuffer:!1,colorSpace:ze.workingColorSpace})}const B=y.state.transmissionRenderTarget[z.id],te=z.viewport||Z;B.setSize(te.z*F.transmissionResolutionScale,te.w*F.transmissionResolutionScale);const de=F.getRenderTarget(),me=F.getActiveCubeFace(),ge=F.getActiveMipmapLevel();F.setRenderTarget(B),F.getClearColor(ve),we=F.getClearAlpha(),we<1&&F.setClearColor(16777215,.5),F.clear(),tt&&Se.render(k);const be=F.toneMapping;F.toneMapping=qt;const Ie=z.viewport;if(z.viewport!==void 0&&(z.viewport=void 0),y.setupLightsView(z),Ve===!0&&pe.setGlobalState(F.clippingPlanes,z),Ir(_,k,z),f.updateMultisampleRenderTarget(B),f.updateRenderTargetMipmap(B),Ne.has("WEBGL_multisampled_render_to_texture")===!1){let Fe=!1;for(let Ee=0,$e=I.length;Ee<$e;Ee++){const at=I[Ee],{object:it,geometry:Qe,material:nt,group:_e}=at;if(nt.side===ai&&it.layers.test(z.layers)){const Ct=nt.side;nt.side=bt,nt.needsUpdate=!0,Ts(it,k,z,Qe,nt,_e),nt.side=Ct,nt.needsUpdate=!0,Fe=!0}}Fe===!0&&(f.updateMultisampleRenderTarget(B),f.updateRenderTargetMipmap(B))}F.setRenderTarget(de,me,ge),F.setClearColor(ve,we),Ie!==void 0&&(z.viewport=Ie),F.toneMapping=be}function Ir(_,I,k){const z=I.isScene===!0?I.overrideMaterial:null;for(let B=0,te=_.length;B<te;B++){const de=_[B],{object:me,geometry:ge,group:be}=de;let Ie=de.material;Ie.allowOverride===!0&&z!==null&&(Ie=z),me.layers.test(k.layers)&&Ts(me,I,k,ge,Ie,be)}}function Ts(_,I,k,z,B,te){_.onBeforeRender(F,I,k,z,B,te),_.modelViewMatrix.multiplyMatrices(k.matrixWorldInverse,_.matrixWorld),_.normalMatrix.getNormalMatrix(_.modelViewMatrix),B.onBeforeRender(F,I,k,z,_,te),B.transparent===!0&&B.side===ai&&B.forceSinglePass===!1?(B.side=bt,B.needsUpdate=!0,F.renderBufferDirect(k,I,z,B,_,te),B.side=ni,B.needsUpdate=!0,F.renderBufferDirect(k,I,z,B,_,te),B.side=ai):F.renderBufferDirect(k,I,z,B,_,te),_.onAfterRender(F,I,k,z,B,te)}function Lr(_,I,k){I.isScene!==!0&&(I=St);const z=M.get(_),B=y.state.lights,te=y.state.shadowsArray,de=B.state.version,me=se.getParameters(_,B.state,te,I,k,y.state.lightProbeGridArray),ge=se.getProgramCacheKey(me);let be=z.programs;z.environment=_.isMeshStandardMaterial||_.isMeshLambertMaterial||_.isMeshPhongMaterial?I.environment:null,z.fog=I.fog;const Ie=_.isMeshStandardMaterial||_.isMeshLambertMaterial&&!_.envMap||_.isMeshPhongMaterial&&!_.envMap;z.envMap=O.get(_.envMap||z.environment,Ie),z.envMapRotation=z.environment!==null&&_.envMap===null?I.environmentRotation:_.envMapRotation,be===void 0&&(_.addEventListener("dispose",Et),be=new Map,z.programs=be);let Fe=be.get(ge);if(Fe!==void 0){if(z.currentProgram===Fe&&z.lightsStateVersion===de)return bs(_,me),Fe}else me.uniforms=se.getUniforms(_),N!==null&&_.isNodeMaterial&&N.build(_,k,me),_.onBeforeCompile(me,F),Fe=se.acquireProgram(me,ge),be.set(ge,Fe),z.uniforms=me.uniforms;const Ee=z.uniforms;return(!_.isShaderMaterial&&!_.isRawShaderMaterial||_.clipping===!0)&&(Ee.clippingPlanes=pe.uniform),bs(_,me),z.needsLights=bl(_),z.lightsStateVersion=de,z.needsLights&&(Ee.ambientLightColor.value=B.state.ambient,Ee.lightProbe.value=B.state.probe,Ee.directionalLights.value=B.state.directional,Ee.directionalLightShadows.value=B.state.directionalShadow,Ee.spotLights.value=B.state.spot,Ee.spotLightShadows.value=B.state.spotShadow,Ee.rectAreaLights.value=B.state.rectArea,Ee.ltc_1.value=B.state.rectAreaLTC1,Ee.ltc_2.value=B.state.rectAreaLTC2,Ee.pointLights.value=B.state.point,Ee.pointLightShadows.value=B.state.pointShadow,Ee.hemisphereLights.value=B.state.hemi,Ee.directionalShadowMatrix.value=B.state.directionalShadowMatrix,Ee.spotLightMatrix.value=B.state.spotLightMatrix,Ee.spotLightMap.value=B.state.spotLightMap,Ee.pointShadowMatrix.value=B.state.pointShadowMatrix),z.lightProbeGrid=y.state.lightProbeGridArray.length>0,z.currentProgram=Fe,z.uniformsList=null,Fe}function ys(_){if(_.uniformsList===null){const I=_.currentProgram.getUniforms();_.uniformsList=En.seqWithValue(I.seq,_.uniforms)}return _.uniformsList}function bs(_,I){const k=M.get(_);k.outputColorSpace=I.outputColorSpace,k.batching=I.batching,k.batchingColor=I.batchingColor,k.instancing=I.instancing,k.instancingColor=I.instancingColor,k.instancingMorph=I.instancingMorph,k.skinning=I.skinning,k.morphTargets=I.morphTargets,k.morphNormals=I.morphNormals,k.morphColors=I.morphColors,k.morphTargetsCount=I.morphTargetsCount,k.numClippingPlanes=I.numClippingPlanes,k.numIntersection=I.numClipIntersection,k.vertexAlphas=I.vertexAlphas,k.vertexTangents=I.vertexTangents,k.toneMapping=I.toneMapping}function El(_,I){if(_.length===0)return null;if(_.length===1)return _[0].texture!==null?_[0]:null;T.setFromMatrixPosition(I.matrixWorld);for(let k=0,z=_.length;k<z;k++){const B=_[k];if(B.texture!==null&&B.boundingBox.containsPoint(T))return B}return null}function Tl(_,I,k,z,B){I.isScene!==!0&&(I=St),f.resetTextureUnits();const te=I.fog,de=z.isMeshStandardMaterial||z.isMeshLambertMaterial||z.isMeshPhongMaterial?I.environment:null,me=L===null?F.outputColorSpace:L.isXRRenderTarget===!0?L.texture.colorSpace:ze.workingColorSpace,ge=z.isMeshStandardMaterial||z.isMeshLambertMaterial&&!z.envMap||z.isMeshPhongMaterial&&!z.envMap,be=O.get(z.envMap||de,ge),Ie=z.vertexColors===!0&&!!k.attributes.color&&k.attributes.color.itemSize===4,Fe=!!k.attributes.tangent&&(!!z.normalMap||z.anisotropy>0),Ee=!!k.morphAttributes.position,$e=!!k.morphAttributes.normal,at=!!k.morphAttributes.color;let it=qt;z.toneMapped&&(L===null||L.isXRRenderTarget===!0)&&(it=F.toneMapping);const Qe=k.morphAttributes.position||k.morphAttributes.normal||k.morphAttributes.color,nt=Qe!==void 0?Qe.length:0,_e=M.get(z),Ct=y.state.lights;if(Ve===!0&&(ke===!0||_!==H)){const je=_===H&&z.id===V;pe.setState(z,_,je)}let Ui=!1;z.version===_e.__version?(_e.needsLights&&_e.lightsStateVersion!==Ct.state.version||_e.outputColorSpace!==me||B.isBatchedMesh&&_e.batching===!1||!B.isBatchedMesh&&_e.batching===!0||B.isBatchedMesh&&_e.batchingColor===!0&&B.colorTexture===null||B.isBatchedMesh&&_e.batchingColor===!1&&B.colorTexture!==null||B.isInstancedMesh&&_e.instancing===!1||!B.isInstancedMesh&&_e.instancing===!0||B.isSkinnedMesh&&_e.skinning===!1||!B.isSkinnedMesh&&_e.skinning===!0||B.isInstancedMesh&&_e.instancingColor===!0&&B.instanceColor===null||B.isInstancedMesh&&_e.instancingColor===!1&&B.instanceColor!==null||B.isInstancedMesh&&_e.instancingMorph===!0&&B.morphTexture===null||B.isInstancedMesh&&_e.instancingMorph===!1&&B.morphTexture!==null||_e.envMap!==be||z.fog===!0&&_e.fog!==te||_e.numClippingPlanes!==void 0&&(_e.numClippingPlanes!==pe.numPlanes||_e.numIntersection!==pe.numIntersection)||_e.vertexAlphas!==Ie||_e.vertexTangents!==Fe||_e.morphTargets!==Ee||_e.morphNormals!==$e||_e.morphColors!==at||_e.toneMapping!==it||_e.morphTargetsCount!==nt||!!_e.lightProbeGrid!=y.state.lightProbeGridArray.length>0)&&(Ui=!0):(Ui=!0,_e.__version=z.version);let It=_e.currentProgram;Ui===!0&&(It=Lr(z,I,B),N&&z.isNodeMaterial&&N.onUpdateProgram(z,It,_e));let Xt=!1,_i=!1,qi=!1;const Je=It.getUniforms(),st=_e.uniforms;if(le.useProgram(It.program)&&(Xt=!0,_i=!0,qi=!0),z.id!==V&&(V=z.id,_i=!0),_e.needsLights){const je=El(y.state.lightProbeGridArray,B);_e.lightProbeGrid!==je&&(_e.lightProbeGrid=je,_i=!0)}if(Xt||H!==_){le.buffers.depth.getReversed()&&_.reversedDepth!==!0&&(_._reversedDepth=!0,_.updateProjectionMatrix()),Je.setValue(P,"projectionMatrix",_.projectionMatrix),Je.setValue(P,"viewMatrix",_.matrixWorldInverse);const je=Je.map.cameraPosition;je!==void 0&&je.setValue(P,gt.setFromMatrixPosition(_.matrixWorld)),Ze.logarithmicDepthBuffer&&Je.setValue(P,"logDepthBufFC",2/(Math.log(_.far+1)/Math.LN2)),(z.isMeshPhongMaterial||z.isMeshToonMaterial||z.isMeshLambertMaterial||z.isMeshBasicMaterial||z.isMeshStandardMaterial||z.isShaderMaterial)&&Je.setValue(P,"isOrthographic",_.isOrthographicCamera===!0),H!==_&&(H=_,_i=!0,qi=!0)}if(_e.needsLights&&(Ct.state.directionalShadowMap.length>0&&Je.setValue(P,"directionalShadowMap",Ct.state.directionalShadowMap,f),Ct.state.spotShadowMap.length>0&&Je.setValue(P,"spotShadowMap",Ct.state.spotShadowMap,f),Ct.state.pointShadowMap.length>0&&Je.setValue(P,"pointShadowMap",Ct.state.pointShadowMap,f)),B.isSkinnedMesh){Je.setOptional(P,B,"bindMatrix"),Je.setOptional(P,B,"bindMatrixInverse");const je=B.skeleton;je&&(je.boneTexture===null&&je.computeBoneTexture(),Je.setValue(P,"boneTexture",je.boneTexture,f))}B.isBatchedMesh&&(Je.setOptional(P,B,"batchingTexture"),Je.setValue(P,"batchingTexture",B._matricesTexture,f),Je.setOptional(P,B,"batchingIdTexture"),Je.setValue(P,"batchingIdTexture",B._indirectTexture,f),Je.setOptional(P,B,"batchingColorTexture"),B._colorsTexture!==null&&Je.setValue(P,"batchingColorTexture",B._colorsTexture,f));const vi=k.morphAttributes;if((vi.position!==void 0||vi.normal!==void 0||vi.color!==void 0)&&Re.update(B,k,It),(_i||_e.receiveShadow!==B.receiveShadow)&&(_e.receiveShadow=B.receiveShadow,Je.setValue(P,"receiveShadow",B.receiveShadow)),(z.isMeshStandardMaterial||z.isMeshLambertMaterial||z.isMeshPhongMaterial)&&z.envMap===null&&I.environment!==null&&(st.envMapIntensity.value=I.environmentIntensity),st.dfgLUT!==void 0&&(st.dfgLUT.value=pm()),_i){if(Je.setValue(P,"toneMappingExposure",F.toneMappingExposure),_e.needsLights&&yl(st,qi),te&&z.fog===!0&&D.refreshFogUniforms(st,te),D.refreshMaterialUniforms(st,z,Ue,Ye,y.state.transmissionRenderTarget[_.id]),_e.needsLights&&_e.lightProbeGrid){const je=_e.lightProbeGrid;st.probesSH.value=je.texture,st.probesMin.value.copy(je.boundingBox.min),st.probesMax.value.copy(je.boundingBox.max),st.probesResolution.value.copy(je.resolution)}En.upload(P,ys(_e),st,f)}if(z.isShaderMaterial&&z.uniformsNeedUpdate===!0&&(En.upload(P,ys(_e),st,f),z.uniformsNeedUpdate=!1),z.isSpriteMaterial&&Je.setValue(P,"center",B.center),Je.setValue(P,"modelViewMatrix",B.modelViewMatrix),Je.setValue(P,"normalMatrix",B.normalMatrix),Je.setValue(P,"modelMatrix",B.matrixWorld),z.uniformsGroups!==void 0){const je=z.uniformsGroups;for(let gr=0,Yi=je.length;gr<Yi;gr++){const As=je[gr];ee.update(As,It),ee.bind(As,It)}}return It}function yl(_,I){_.ambientLightColor.needsUpdate=I,_.lightProbe.needsUpdate=I,_.directionalLights.needsUpdate=I,_.directionalLightShadows.needsUpdate=I,_.pointLights.needsUpdate=I,_.pointLightShadows.needsUpdate=I,_.spotLights.needsUpdate=I,_.spotLightShadows.needsUpdate=I,_.rectAreaLights.needsUpdate=I,_.hemisphereLights.needsUpdate=I}function bl(_){return _.isMeshLambertMaterial||_.isMeshToonMaterial||_.isMeshPhongMaterial||_.isMeshStandardMaterial||_.isShadowMaterial||_.isShaderMaterial&&_.lights===!0}this.getActiveCubeFace=function(){return W},this.getActiveMipmapLevel=function(){return q},this.getRenderTarget=function(){return L},this.setRenderTargetTextures=function(_,I,k){const z=M.get(_);z.__autoAllocateDepthBuffer=_.resolveDepthBuffer===!1,z.__autoAllocateDepthBuffer===!1&&(z.__useRenderToTexture=!1),M.get(_.texture).__webglTexture=I,M.get(_.depthTexture).__webglTexture=z.__autoAllocateDepthBuffer?void 0:k,z.__hasExternalTextures=!0},this.setRenderTargetFramebuffer=function(_,I){const k=M.get(_);k.__webglFramebuffer=I,k.__useDefaultFramebuffer=I===void 0};const Al=P.createFramebuffer();this.setRenderTarget=function(_,I=0,k=0){L=_,W=I,q=k;let z=null,B=!1,te=!1;if(_){const de=M.get(_);if(de.__useDefaultFramebuffer!==void 0){le.bindFramebuffer(P.FRAMEBUFFER,de.__webglFramebuffer),Z.copy(_.viewport),Q.copy(_.scissor),re=_.scissorTest,le.viewport(Z),le.scissor(Q),le.setScissorTest(re),V=-1;return}else if(de.__webglFramebuffer===void 0)f.setupRenderTarget(_);else if(de.__hasExternalTextures)f.rebindTextures(_,M.get(_.texture).__webglTexture,M.get(_.depthTexture).__webglTexture);else if(_.depthBuffer){const be=_.depthTexture;if(de.__boundDepthTexture!==be){if(be!==null&&M.has(be)&&(_.width!==be.image.width||_.height!==be.image.height))throw new Error("WebGLRenderTarget: Attached DepthTexture is initialized to the incorrect size.");f.setupDepthRenderbuffer(_)}}const me=_.texture;(me.isData3DTexture||me.isDataArrayTexture||me.isCompressedArrayTexture)&&(te=!0);const ge=M.get(_).__webglFramebuffer;_.isWebGLCubeRenderTarget?(Array.isArray(ge[I])?z=ge[I][k]:z=ge[I],B=!0):_.samples>0&&f.useMultisampledRTT(_)===!1?z=M.get(_).__webglMultisampledFramebuffer:Array.isArray(ge)?z=ge[k]:z=ge,Z.copy(_.viewport),Q.copy(_.scissor),re=_.scissorTest}else Z.copy(ne).multiplyScalar(Ue).floor(),Q.copy(Te).multiplyScalar(Ue).floor(),re=Pe;if(k!==0&&(z=Al),le.bindFramebuffer(P.FRAMEBUFFER,z)&&le.drawBuffers(_,z),le.viewport(Z),le.scissor(Q),le.setScissorTest(re),B){const de=M.get(_.texture);P.framebufferTexture2D(P.FRAMEBUFFER,P.COLOR_ATTACHMENT0,P.TEXTURE_CUBE_MAP_POSITIVE_X+I,de.__webglTexture,k)}else if(te){const de=I;for(let me=0;me<_.textures.length;me++){const ge=M.get(_.textures[me]);P.framebufferTextureLayer(P.FRAMEBUFFER,P.COLOR_ATTACHMENT0+me,ge.__webglTexture,k,de)}}else if(_!==null&&k!==0){const de=M.get(_.texture);P.framebufferTexture2D(P.FRAMEBUFFER,P.COLOR_ATTACHMENT0,P.TEXTURE_2D,de.__webglTexture,k)}V=-1},this.readRenderTargetPixels=function(_,I,k,z,B,te,de,me=0){if(!(_&&_.isWebGLRenderTarget)){He("WebGLRenderer.readRenderTargetPixels: renderTarget is not THREE.WebGLRenderTarget.");return}let ge=M.get(_).__webglFramebuffer;if(_.isWebGLCubeRenderTarget&&de!==void 0&&(ge=ge[de]),ge){le.bindFramebuffer(P.FRAMEBUFFER,ge);try{const be=_.textures[me],Ie=be.format,Fe=be.type;if(_.textures.length>1&&P.readBuffer(P.COLOR_ATTACHMENT0+me),!Ze.textureFormatReadable(Ie)){He("WebGLRenderer.readRenderTargetPixels: renderTarget is not in RGBA or implementation defined format.");return}if(!Ze.textureTypeReadable(Fe)){He("WebGLRenderer.readRenderTargetPixels: renderTarget is not in UnsignedByteType or implementation defined type.");return}I>=0&&I<=_.width-z&&k>=0&&k<=_.height-B&&P.readPixels(I,k,z,B,R.convert(Ie),R.convert(Fe),te)}finally{const be=L!==null?M.get(L).__webglFramebuffer:null;le.bindFramebuffer(P.FRAMEBUFFER,be)}}},this.readRenderTargetPixelsAsync=async function(_,I,k,z,B,te,de,me=0){if(!(_&&_.isWebGLRenderTarget))throw new Error("THREE.WebGLRenderer.readRenderTargetPixels: renderTarget is not THREE.WebGLRenderTarget.");let ge=M.get(_).__webglFramebuffer;if(_.isWebGLCubeRenderTarget&&de!==void 0&&(ge=ge[de]),ge)if(I>=0&&I<=_.width-z&&k>=0&&k<=_.height-B){le.bindFramebuffer(P.FRAMEBUFFER,ge);const be=_.textures[me],Ie=be.format,Fe=be.type;if(_.textures.length>1&&P.readBuffer(P.COLOR_ATTACHMENT0+me),!Ze.textureFormatReadable(Ie))throw new Error("THREE.WebGLRenderer.readRenderTargetPixelsAsync: renderTarget is not in RGBA or implementation defined format.");if(!Ze.textureTypeReadable(Fe))throw new Error("THREE.WebGLRenderer.readRenderTargetPixelsAsync: renderTarget is not in UnsignedByteType or implementation defined type.");const Ee=P.createBuffer();P.bindBuffer(P.PIXEL_PACK_BUFFER,Ee),P.bufferData(P.PIXEL_PACK_BUFFER,te.byteLength,P.STREAM_READ),P.readPixels(I,k,z,B,R.convert(Ie),R.convert(Fe),0);const $e=L!==null?M.get(L).__webglFramebuffer:null;le.bindFramebuffer(P.FRAMEBUFFER,$e);const at=P.fenceSync(P.SYNC_GPU_COMMANDS_COMPLETE,0);return P.flush(),await Nc(P,at,4),P.bindBuffer(P.PIXEL_PACK_BUFFER,Ee),P.getBufferSubData(P.PIXEL_PACK_BUFFER,0,te),P.deleteBuffer(Ee),P.deleteSync(at),te}else throw new Error("THREE.WebGLRenderer.readRenderTargetPixelsAsync: requested read bounds are out of range.")},this.copyFramebufferToTexture=function(_,I=null,k=0){const z=Math.pow(2,-k),B=Math.floor(_.image.width*z),te=Math.floor(_.image.height*z),de=I!==null?I.x:0,me=I!==null?I.y:0;f.setTexture2D(_,0),P.copyTexSubImage2D(P.TEXTURE_2D,k,0,0,de,me,B,te),le.unbindTexture()};const wl=P.createFramebuffer(),Rl=P.createFramebuffer();this.copyTextureToTexture=function(_,I,k=null,z=null,B=0,te=0){let de,me,ge,be,Ie,Fe,Ee,$e,at;const it=_.isCompressedTexture?_.mipmaps[te]:_.image;if(k!==null)de=k.max.x-k.min.x,me=k.max.y-k.min.y,ge=k.isBox3?k.max.z-k.min.z:1,be=k.min.x,Ie=k.min.y,Fe=k.isBox3?k.min.z:0;else{const st=Math.pow(2,-B);de=Math.floor(it.width*st),me=Math.floor(it.height*st),_.isDataArrayTexture?ge=it.depth:_.isData3DTexture?ge=Math.floor(it.depth*st):ge=1,be=0,Ie=0,Fe=0}z!==null?(Ee=z.x,$e=z.y,at=z.z):(Ee=0,$e=0,at=0);const Qe=R.convert(I.format),nt=R.convert(I.type);let _e;I.isData3DTexture?(f.setTexture3D(I,0),_e=P.TEXTURE_3D):I.isDataArrayTexture||I.isCompressedArrayTexture?(f.setTexture2DArray(I,0),_e=P.TEXTURE_2D_ARRAY):(f.setTexture2D(I,0),_e=P.TEXTURE_2D),le.activeTexture(P.TEXTURE0),le.pixelStorei(P.UNPACK_FLIP_Y_WEBGL,I.flipY),le.pixelStorei(P.UNPACK_PREMULTIPLY_ALPHA_WEBGL,I.premultiplyAlpha),le.pixelStorei(P.UNPACK_ALIGNMENT,I.unpackAlignment);const Ct=le.getParameter(P.UNPACK_ROW_LENGTH),Ui=le.getParameter(P.UNPACK_IMAGE_HEIGHT),It=le.getParameter(P.UNPACK_SKIP_PIXELS),Xt=le.getParameter(P.UNPACK_SKIP_ROWS),_i=le.getParameter(P.UNPACK_SKIP_IMAGES);le.pixelStorei(P.UNPACK_ROW_LENGTH,it.width),le.pixelStorei(P.UNPACK_IMAGE_HEIGHT,it.height),le.pixelStorei(P.UNPACK_SKIP_PIXELS,be),le.pixelStorei(P.UNPACK_SKIP_ROWS,Ie),le.pixelStorei(P.UNPACK_SKIP_IMAGES,Fe);const qi=_.isDataArrayTexture||_.isData3DTexture,Je=I.isDataArrayTexture||I.isData3DTexture;if(_.isDepthTexture){const st=M.get(_),vi=M.get(I),je=M.get(st.__renderTarget),gr=M.get(vi.__renderTarget);le.bindFramebuffer(P.READ_FRAMEBUFFER,je.__webglFramebuffer),le.bindFramebuffer(P.DRAW_FRAMEBUFFER,gr.__webglFramebuffer);for(let Yi=0;Yi<ge;Yi++)qi&&(P.framebufferTextureLayer(P.READ_FRAMEBUFFER,P.COLOR_ATTACHMENT0,M.get(_).__webglTexture,B,Fe+Yi),P.framebufferTextureLayer(P.DRAW_FRAMEBUFFER,P.COLOR_ATTACHMENT0,M.get(I).__webglTexture,te,at+Yi)),P.blitFramebuffer(be,Ie,de,me,Ee,$e,de,me,P.DEPTH_BUFFER_BIT,P.NEAREST);le.bindFramebuffer(P.READ_FRAMEBUFFER,null),le.bindFramebuffer(P.DRAW_FRAMEBUFFER,null)}else if(B!==0||_.isRenderTargetTexture||M.has(_)){const st=M.get(_),vi=M.get(I);le.bindFramebuffer(P.READ_FRAMEBUFFER,wl),le.bindFramebuffer(P.DRAW_FRAMEBUFFER,Rl);for(let je=0;je<ge;je++)qi?P.framebufferTextureLayer(P.READ_FRAMEBUFFER,P.COLOR_ATTACHMENT0,st.__webglTexture,B,Fe+je):P.framebufferTexture2D(P.READ_FRAMEBUFFER,P.COLOR_ATTACHMENT0,P.TEXTURE_2D,st.__webglTexture,B),Je?P.framebufferTextureLayer(P.DRAW_FRAMEBUFFER,P.COLOR_ATTACHMENT0,vi.__webglTexture,te,at+je):P.framebufferTexture2D(P.DRAW_FRAMEBUFFER,P.COLOR_ATTACHMENT0,P.TEXTURE_2D,vi.__webglTexture,te),B!==0?P.blitFramebuffer(be,Ie,de,me,Ee,$e,de,me,P.COLOR_BUFFER_BIT,P.NEAREST):Je?P.copyTexSubImage3D(_e,te,Ee,$e,at+je,be,Ie,de,me):P.copyTexSubImage2D(_e,te,Ee,$e,be,Ie,de,me);le.bindFramebuffer(P.READ_FRAMEBUFFER,null),le.bindFramebuffer(P.DRAW_FRAMEBUFFER,null)}else Je?_.isDataTexture||_.isData3DTexture?P.texSubImage3D(_e,te,Ee,$e,at,de,me,ge,Qe,nt,it.data):I.isCompressedArrayTexture?P.compressedTexSubImage3D(_e,te,Ee,$e,at,de,me,ge,Qe,it.data):P.texSubImage3D(_e,te,Ee,$e,at,de,me,ge,Qe,nt,it):_.isDataTexture?P.texSubImage2D(P.TEXTURE_2D,te,Ee,$e,de,me,Qe,nt,it.data):_.isCompressedTexture?P.compressedTexSubImage2D(P.TEXTURE_2D,te,Ee,$e,it.width,it.height,Qe,it.data):P.texSubImage2D(P.TEXTURE_2D,te,Ee,$e,de,me,Qe,nt,it);le.pixelStorei(P.UNPACK_ROW_LENGTH,Ct),le.pixelStorei(P.UNPACK_IMAGE_HEIGHT,Ui),le.pixelStorei(P.UNPACK_SKIP_PIXELS,It),le.pixelStorei(P.UNPACK_SKIP_ROWS,Xt),le.pixelStorei(P.UNPACK_SKIP_IMAGES,_i),te===0&&I.generateMipmaps&&P.generateMipmap(_e),le.unbindTexture()},this.initRenderTarget=function(_){M.get(_).__webglFramebuffer===void 0&&f.setupRenderTarget(_)},this.initTexture=function(_){_.isCubeTexture?f.setTextureCube(_,0):_.isData3DTexture?f.setTexture3D(_,0):_.isDataArrayTexture||_.isCompressedArrayTexture?f.setTexture2DArray(_,0):f.setTexture2D(_,0),le.unbindTexture()},this.resetState=function(){W=0,q=0,L=null,le.reset(),X.reset()},typeof __THREE_DEVTOOLS__<"u"&&__THREE_DEVTOOLS__.dispatchEvent(new CustomEvent("observe",{detail:this}))}get coordinateSystem(){return Kt}get outputColorSpace(){return this._outputColorSpace}set outputColorSpace(e){this._outputColorSpace=e;const t=this.getContext();t.drawingBufferColorSpace=ze._getDrawingBufferColorSpace(e),t.unpackColorSpace=ze._getUnpackColorSpace()}}const mm=.8,gm=`
uniform mat4 projectionMatrix;
uniform mat4 modelViewMatrix;

attribute vec2 position;
attribute vec4 instanceRect;  // x, y, w, h in world space
attribute vec3 instanceColor;

varying vec3 vColor;

void main() {
  // position is unit quad: [(-0.5,-0.5), (0.5,-0.5), (-0.5,0.5), (0.5,0.5)]
  vec2 world = position * instanceRect.zw + instanceRect.xy + instanceRect.zw * 0.5;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(world, 0.0, 1.0);
  vColor = instanceColor;
}
`,_m=`
precision mediump float;
uniform float uOpacity;
varying vec3 vColor;

void main() {
  gl_FragColor = vec4(vColor, uOpacity);
}
`;function vm(){const r=new Vt;return r.setAttribute("position",new Nt(new Float32Array([-.5,-.5,.5,-.5,-.5,.5,.5,.5]),2)),r.setIndex([0,1,2,1,3,2]),r.boundingSphere=new wr,r}function xm(){return new Io({vertexShader:gm,fragmentShader:_m,side:ni,transparent:!0,uniforms:{uOpacity:{value:mm}}})}function Mm(){return{unitQuad:vm(),sharedMaterial:xm()}}function Sm(r){r.unitQuad.dispose(),r.sharedMaterial.dispose()}const yn=700*(Cl-1);function Em(r){const e=new Float32Array(yn*4),t=new Float32Array(yn*3),i=new mn(e,4),n=new mn(t,3);i.setUsage(Yr),n.setUsage(Yr);const a=new mu;a.index=r.unitQuad.index,a.setAttribute("position",r.unitQuad.getAttribute("position")),a.setAttribute("instanceRect",i),a.setAttribute("instanceColor",n),a.instanceCount=0,a.boundingSphere=new wr;const s=new Zt(a,r.sharedMaterial);return s.frustumCulled=!1,{mesh:s,rectArray:e,colorArray:t,rectAttr:i,colorAttr:n,capacity:yn,count:0}}function Tm(r,e){if(e<=r.capacity)return;let t=r.capacity||yn;for(;t<e;)t*=2;const i=new Float32Array(t*4),n=new Float32Array(t*3);i.set(r.rectArray),n.set(r.colorArray),r.rectArray=i,r.colorArray=n,r.rectAttr=new mn(i,4),r.colorAttr=new mn(n,3),r.rectAttr.setUsage(Yr),r.colorAttr.setUsage(Yr),r.capacity=t;const a=r.mesh.geometry;a.setAttribute("instanceRect",r.rectAttr),a.setAttribute("instanceColor",r.colorAttr)}function ym(r,e,t,i,n,a,s){const o=e*4;r.rectArray[o]=t,r.rectArray[o+1]=i,r.rectArray[o+2]=n,r.rectArray[o+3]=a;const c=e*3;r.colorArray[c]=s[0],r.colorArray[c+1]=s[1],r.colorArray[c+2]=s[2]}function bm(r,e){r.count=e,r.mesh.geometry.instanceCount=e,r.rectAttr.needsUpdate=!0,r.colorAttr.needsUpdate=!0}const gl=new qe,bn={r:0,g:0,b:0};function Ri(r){return gl.setHex(parseInt(r.replace("#",""),16),At),gl.getRGB(bn,At),[bn.r,bn.g,bn.b]}const ii=Fl(),Am=10,wm=24*60*60*1e3,_l=new Map,Rm=2,Ci={skipped:Ri(Xl),repairRequested:Ri(Wl),receivedTurbine:Ri(kl),receivedRepair:Ri(Vl),replayedRepair:Ri(Hl),replayedTurbine:Ri(Gl),replayedNothing:Ri(zl),published:Ri(Bl)};function Cm(r,e){var l,d;const t=ii.get(Rs);if(t==null)return;const i=(d=(l=ii.get(ws))==null?void 0:l.slotsShreds)==null?void 0:d.referenceTs;if(i==null)return;const n=t-Un-Ps-i,a=n+365*wm,s=[n,a],o=new Zc,c=new as(0,0,0,0,.5,10);c.position.z=1;try{const m=new fm({antialias:!0,alpha:!0});m.setPixelRatio(Math.min(window.devicePixelRatio,Rm)),m.setSize(r,e),m.setClearColor(0,0);const u=new Map,g=[],x=Mm();return m.render(o,c),{renderer:m,camera:c,scene:o,meshes:u,availableMeshes:g,worldTsRange:s,resources:x}}catch{ii.set(Cs,!1)}}function vl(r,e,t,i,n,a,s,o){const{slotsShreds:c,range:l,minCompletedSlot:d}=ii.get(ws)??{},m=ii.get(Pl),u=ii.get(Ul),g=ii.get(Rs);if(!c||!l||ii.get(Dl)||d==null||!u||g==null)return;const x=Il(g,e.current)-c.referenceTs,E=[x-Un*a,x],p={minDeltaTs:E[0],maxDeltaTs:E[1],minCanvasPos:0,maxCanvasPos:0,minCssPos:o[0],maxCssPos:o[1]},h=Math.max(l.min,d??l.min),S=l.max,{maxShreds:A,orderedSlotNumbers:T}=Ll(h,S,c,p),U=Pm(i,E,t.camera,A);let y=!1;const C=ii.get(Pn).get(r);for(const w of T){const N=c.slots.get(w);if(!(N!=null&&N.shreds))continue;let W=t.meshes.get(w);const q=!W;if(W||(W=t.availableMeshes.pop()??Em(t.resources),t.meshes.set(w,W),t.scene.add(W.mesh)),!q&&C!=null&&w<C)continue;const L=m.has(w);let V=0;for(let H=0;H<N.shreds.length;H++){const Z=N.shreds[H];if(!Z)continue;_l.clear();const Q=Um({tempEventPositions:_l,slotMesh:W,startRectangleIdx:V,eventTsDeltas:Z,slotCompletionTsDelta:N.completionTsDelta,isSlotSkipped:L,y:-H,visibleTsRange:E});V+=Q,Q&&(y=!0)}bm(W,V)}ii.set(Pn,w=>(w.set(r,1/0),w));const v=new Set(T);for(const[w,N]of t.meshes.entries())v.has(w)||(t.scene.remove(N.mesh),t.meshes.delete(w),t.availableMeshes.push(N));(s||y||U)&&t.renderer.render(t.scene,t.camera);const{prevLabels:b,tempNewLabels:F}=n.current;Nl(u,c.slots,m,p,b,F),n.current={prevLabels:F,tempNewLabels:b},b.groups.clear(),b.slots.clear()}function Pm(r,e,t,i){const n=r.current;return n&&n[0]===e[0]&&n[1]===e[1]&&t.bottom===-i?!1:(r.current=e,t.left=e[0],t.right=e[1],t.top=0,t.bottom=-i,t.updateProjectionMatrix(),!0)}function Um({tempEventPositions:r,slotMesh:e,startRectangleIdx:t,eventTsDeltas:i,slotCompletionTsDelta:n,isSlotSkipped:a,y:s,visibleTsRange:o}){let c=n??o[1]+Ps;for(const d of Ol){const m=i[d];m!=null&&(m>=c||(r.set(d,{x:m,w:a?Am:c-m}),c=m))}let l=0;for(const[d,{x:m,w:u}]of r.entries()){const g=Dm(a,d,r);if(g==null)continue;const x=t+l;Tm(e,x+1),ym(e,x,m,s,u,1,g),l++}return l}function Dm(r,e,t){if(r)return Ci.skipped;switch(e){case Di.shred_repair_request:return Ci.repairRequested;case Di.shred_received_turbine:return Ci.receivedTurbine;case Di.shred_received_repair:return Ci.receivedRepair;case Di.shred_replayed:return t.has(Di.shred_received_repair)?Ci.replayedRepair:t.has(Di.shred_received_turbine)?Ci.replayedTurbine:Ci.replayedNothing;case Di.shred_published:return Ci.published}}const xl=30,Im=ut.memo(function({chartId:r,scale:e,containerWidth:t,containerHeight:i}){const n=t+2*_r,a=ut.useRef(),s=ut.useCallback(d=>{a.current=d},[]),[o,c]=ut.useMemo(()=>[[[Math.trunc(e*-Un),0],new Array(2)],ql(e)],[e]);ut.useEffect(()=>{a.current&&(a.current.axes[0].incrs=()=>c,a.current.setData(o,!0))},[o,c]);const l=ut.useMemo(()=>({padding:[0,_r,0,_r],width:0,height:0,scales:{[Nr]:{time:!1},y:{time:!1,range:[0,1]}},series:[{scale:Nr},{}],cursor:{show:!1,drag:{[Nr]:!1,y:!1}},legend:{show:!1},axes:[{scale:Nr,incrs:c,size:xl,ticks:{opacity:.2,stroke:jl,size:5,width:1/devicePixelRatio},values:(d,m)=>m.map(u=>u===0?"now":`${(u/1e3).toFixed(1)}s`),grid:{stroke:Yl,width:1/devicePixelRatio},stroke:Us},{size:0,grid:{filter:()=>[0],stroke:Us,width:1}}]}),[c]);return l.width=n,l.height=i,xi.jsx(Dn,{position:"absolute",left:`-${_r}px`,right:`-${_r}px`,top:"0",bottom:"0",style:{zIndex:0},children:xi.jsx(Kl,{id:r,options:l,data:o,onCreate:s,setSizeDebounceMs:0})})}),Lm=15,Nm=1e4;function Fm(r){const[e,t]=ut.useState(0),i=ut.useCallback(()=>{t(n=>n+1)},[t]);return xi.jsx(Ml,{...r,triggerRemount:i},e)}function Ml({chartId:r,triggerRemount:e,...t}){const i=Ds(Pn),n=Ds(Cs),a=ut.useRef([]),s=ut.useRef(0),[o,{width:c,height:l}]=Jl(),d=l-xl,m=ut.useRef(null),u=ut.useRef(),g=ut.useRef(),x=ut.useRef({prevLabels:Is(),tempNewLabels:Is()}),E=ut.useRef(),p=Zl(),h=ut.useCallback(A=>{A.preventDefault(),clearTimeout(E.current),E.current=setTimeout(()=>{n(!1)},Nm)},[n]),S=ut.useCallback(()=>{clearTimeout(E.current),E.current=void 0,e()},[e]);return ut.useLayoutEffect(()=>(i(A=>(A.set(r,-1/0),A)),()=>{i(U=>(U.delete(r),U));const A=E.current!=null;clearTimeout(E.current);const T=u.current;if(T){if(T.renderer.domElement.removeEventListener("webglcontextlost",h),T.renderer.domElement.removeEventListener("webglcontextrestored",S),!A){for(const U of T.meshes.values())U.mesh.geometry.dispose();for(const U of T.availableMeshes)U.mesh.geometry.dispose();Sm(T.resources),T.renderer.dispose(),T.renderer.forceContextLoss()}T.renderer.domElement.remove(),u.current=void 0}}),[r,h,S,i]),ut.useLayoutEffect(()=>{if(!u.current||E.current!=null||c<=0||d<=0)return;const{renderer:A}=u.current;A.setSize(c,d),vl(r,a,u.current,g,x,p,!0,[0,c])},[p,c,d,r]),$l(function(A){var T;if(E.current==null&&!(c<=0||d<=0)&&(s.current==null||A-s.current>=Lm))if(s.current=A,u.current)vl(r,a,u.current,g,x,p,!1,[0,c]);else{const U=Cm(c,d);if(!U)return;u.current=U;const y=U.renderer.domElement;y.addEventListener("webglcontextlost",h),y.addEventListener("webglcontextrestored",S),(T=m.current)==null||T.replaceChildren(y)}}),xi.jsxs(Ql,{direction:"column",gap:"2px",...t,children:[xi.jsx(ec,{}),xi.jsxs(Dn,{flexGrow:"1",minHeight:"0",position:"relative",ref:o,children:[xi.jsx(Im,{chartId:`${r}-axes`,scale:p,containerWidth:c,containerHeight:l+1}),xi.jsx(Dn,{ref:m,position:"relative",style:{zIndex:1}})]})]})}export{Ml as ShredsChartInner,Fm as default};
