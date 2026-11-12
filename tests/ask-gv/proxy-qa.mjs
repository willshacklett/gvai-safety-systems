// Optional actual Nginx test: ASK_GV_NGINX=/path/to/extracted/nginx node tests/ask-gv/proxy-qa.mjs
// No services installed; all TLS, ports, credentials and provider calls are disposable.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import {spawn,execFileSync} from 'node:child_process';
import {createApp} from '../../ask-gv/server.mjs';
const binary=process.env.ASK_GV_NGINX;if(!binary)throw Error('ASK_GV_NGINX required; no silent skip');
globalThis.fetch=()=>{throw Error('unmocked_provider_disabled');};
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ask-proxy-qa-'));
const credentials={apiKey:'FAKE-proxy-test-provider',ipSalt:'a'.repeat(64),ingressToken:'b'.repeat(64)};
let calls=0,attempts=0,child,app;
const envelope={object:'response',id:'resp_mock',model:'test-model',status:'completed',output:[{id:'msg_mock',type:'message',role:'assistant',status:'completed',content:[{type:'output_text',text:'{"fact_ids":["status"]}'}]}]};
async function freePort(){return new Promise(r=>{const s=http.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>r(p));});});}
try {
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(dir,'key.pem'),'-out',path.join(dir,'cert.pem'),'-days','1','-subj','/CN=ask.gvaisafety.com','-addext','subjectAltName=DNS:ask.gvaisafety.com'],{stdio:'ignore'});
 fs.writeFileSync(path.join(dir,'identity.conf'),`proxy_set_header X-Ask-GV-Ingress "${credentials.ingressToken}";`,{mode:0o400});
 app=createApp({env:{ASK_GV_ENABLED:'1',ASK_GV_TRUSTED_INGRESS:'loopback-token-v1',OPENAI_MODEL:'test-model'},credentials,store:{reserve(){attempts++;},peek(){return {remaining:100-attempts};}},now:()=>Date.parse('2026-11-12'),operatorDisabled:()=>false,fetchImpl:async()=>{calls++;return new Response(JSON.stringify(envelope));}});
 await new Promise(r=>app.listen(0,'127.0.0.1',r));const port=await freePort();
 let template=fs.readFileSync('deploy/ask-gv/nginx.conf.template','utf8').replaceAll('/run/gvai-ask-gv-ingress',dir).replace('APPROVED_IPV4:APPROVED_TLS_PORT',`127.0.0.1:${port}`).replace('/etc/gvai-ask-gv-ingress/server-chain.pem',path.join(dir,'cert.pem')).replace('/etc/gvai-ask-gv-ingress/server-key.pem',path.join(dir,'key.pem')).replace('/run/credentials/gvai-ask-gv-ingress.service/proxy-identity.conf',path.join(dir,'identity.conf')).replace('127.0.0.1:8787',`127.0.0.1:${app.address().port}`);
 // Keep production proposals closed; only this disposable fixture is later opened.
 const config=path.join(dir,'nginx.conf');fs.writeFileSync(config,template);
 execFileSync(binary,['-t','-p',dir+'/', '-c',config],{stdio:'pipe'});
 const start=async()=>{child=spawn(binary,['-p',dir+'/', '-c',config,'-g','daemon off;'],{stdio:['ignore','pipe','pipe']});let errors='';child.stderr.on('data',d=>errors+=d);for(let i=0;i<100;i++){try{await request('127.0.0.2');return;}catch{await new Promise(r=>setTimeout(r,10));}}throw Error('nginx startup: '+errors);};
 const stop=async()=>{child.kill('SIGQUIT');await new Promise(r=>child.once('exit',r));child=null;};
 const request=(localAddress='127.0.0.2',extra={},body='{"message":"status","history":[]}',url='/v1/ask-gv')=>new Promise((resolve,reject)=>{
  const req=https.request({host:'127.0.0.1',port,path:url,method:'POST',localAddress,servername:'ask.gvaisafety.com',ca:fs.readFileSync(path.join(dir,'cert.pem')),agent:false,headers:{Host:'ask.gvaisafety.com',Origin:'https://gvaisafety.com','Content-Type':'application/json',...extra}},res=>{let data='';res.on('data',d=>data+=d);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,data}));});req.on('error',reject);req.end(body);
 });
 await start();let response=await request();assert.equal(response.status,503);assert.equal(calls,0);assert.equal(response.headers['access-control-allow-origin'],'https://gvaisafety.com');await stop();
 // High edge rates in this variant isolate backend visitor buckets; original rates tested below.
 fs.writeFileSync(config,template.replace('set $ask_gv_open 0;','set $ask_gv_open 1;').replace('rate=6r/m','rate=1000r/s').replace('rate=30r/m','rate=1000r/s'));
 await start(); // startup request consumes one visitor-A allowance
 for(let i=0;i<5;i++)assert.equal((await request()).status,200);
 assert.equal((await request()).status,429);
 response=await request('127.0.0.3',{'X-Ask-GV-Ingress':'forged','X-Ask-GV-Client-IP':'203.0.113.99','X-Forwarded-For':'203.0.113.99','Forwarded':'for=evil'});assert.equal(response.status,200);
 for(let i=0;i<5;i++)assert.equal((await request('127.0.0.3',{'X-Ask-GV-Client-IP':`203.0.113.${i}`})).status,200);
 assert.equal((await request('127.0.0.3',{'X-Ask-GV-Client-IP':'203.0.113.90'})).status,429);
 response=await request('127.0.0.4',{},'x'.repeat(12001));assert.equal(response.status,413);assert.equal(response.headers['access-control-allow-origin'],'https://gvaisafety.com');
 assert.equal((await request('127.0.0.4',{},'{}','/readyz')).status,404);
 assert.equal((await request('127.0.0.4',{},'{}','/v1/ask-gv?key=FAKE')).status,404);
 assert.equal((await request('127.0.0.4',{Origin:'https://evil.example'})).status,403);
 assert.equal((await request('127.0.0.4',{Host:'unapproved.example'})).status,404);
 assert.equal((await request('127.0.0.4',{'Content-Encoding':'gzip'})).status,415);
 assert.equal((await request('127.0.0.4',{'Content-Type':'text/plain'})).status,415);
 const beforeSlow=calls, slowStart=Date.now();
 await new Promise(resolve=>{
   let timer;
   const req=https.request({host:'127.0.0.1',port,method:'POST',path:'/v1/ask-gv',localAddress:'127.0.0.6',servername:'ask.gvaisafety.com',ca:fs.readFileSync(path.join(dir,'cert.pem')),agent:false,headers:{Host:'ask.gvaisafety.com',Origin:'https://gvaisafety.com','Content-Type':'application/json','Content-Length':'100'}},res=>{res.resume();res.on('end',()=>{clearInterval(timer);resolve();});});
   req.on('error',()=>{clearInterval(timer);resolve();});req.on('close',()=>{clearInterval(timer);resolve();});req.write('{');timer=setInterval(()=>req.write(' '),250);
 });
 assert.ok(Date.now()-slowStart>=4900 && Date.now()-slowStart<7500,'trickling must not extend absolute body deadline');assert.equal(calls,beforeSlow);
 // A raw duplicate Content-Length request must be rejected before any provider call.
 const tls=await import('node:tls');const beforeBad=calls;
 const framing=await new Promise((resolve,reject)=>{const socket=tls.connect({host:'127.0.0.1',port,servername:'ask.gvaisafety.com',ca:fs.readFileSync(path.join(dir,'cert.pem'))},()=>socket.write('POST /v1/ask-gv HTTP/1.1\r\nHost: ask.gvaisafety.com\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx'));let data='';socket.on('data',d=>data+=d);socket.on('end',()=>resolve(data));socket.on('error',reject);});
 assert.match(framing,/HTTP\/1\.1 400/);assert.equal(calls,beforeBad);await stop();
 const prior=calls;fs.writeFileSync(config,template.replace('set $ask_gv_open 0;','set $ask_gv_open 1;'));
 await start();let limited=false;for(let i=0;i<5;i++){response=await request('127.0.0.5');if(response.status===429){limited=true;break;}}
 assert.equal(limited,true);assert.equal(response.headers['retry-after'],'60');assert.equal(response.headers['access-control-allow-origin'],'https://gvaisafety.com');assert.ok(calls-prior<=3);
 await stop();console.log('PASS actual Nginx TLS template syntax; disabled ingress; authenticated identity overwrite; two visitor quotas; Origin/query/private-path rejection; body cap; edge 429/CORS; absolute trickled upload deadline; ambiguous framing rejected; no provider networking');
}finally {if(child){child.kill('SIGTERM');await new Promise(r=>child.once('exit',r));}if(app){app.beginDrain();await new Promise(r=>{app.close(r);app.closeAllConnections();});}fs.rmSync(dir,{recursive:true,force:true});}
