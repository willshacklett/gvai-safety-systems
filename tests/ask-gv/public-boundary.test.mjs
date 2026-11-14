// Resource-free only: VM HTTP factory never binds; provider is a synthetic callback.
// No test-module imports, native fetch, child spawning, credentials or temp custody.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import * as urlModule from 'node:url';
import * as crypto from 'node:crypto';
import * as net from 'node:net';
import {EventEmitter} from 'node:events';
const root=new URL('../../',import.meta.url);
const read=p=>fs.readFileSync(new URL(p,root),'utf8');
const sources={server:read('ask-gv/server.mjs'),ui:read('ask-gv.js'),fetch:read('ask-gv-fetch.js'),hardening:read('tests/ask-gv/hardening.test.mjs')};
const deny=()=>{throw Error('forbidden_external_effect');};
const selected=()=>new Response(JSON.stringify({object:'response',id:'resp_mock',model:'test-model',status:'completed',output:[{id:'msg_mock',type:'message',role:'assistant',status:'completed',content:[{type:'output_text',text:'{"fact_ids":["status"]}'}]}]}));
async function serverModule() {
 let handler;
 const app={closeIdleConnections(){},closeAllConnections(){},listen:deny};
 const context=vm.createContext({URL,Buffer,TextDecoder,AbortController,setTimeout,clearTimeout,
  process:{argv:[]},fetch:deny,SOURCE_URL:new URL('ask-gv/server.mjs',root).href,
  http:{createServer(_options,fn){handler=fn;return app;}},
  fs:{readFileSync(p){assert.equal(String(p),new URL('ask-gv/facts.json',root).href);return read('ask-gv/facts.json');}},
  path,fileURLToPath:urlModule.fileURLToPath,createHmac:crypto.createHmac,timingSafeEqual:crypto.timingSafeEqual,isIP:net.isIP,budgetStore:deny,loadCredentials:deny});
 // Exact import fence, not a second handler implementation. Any changed/new import
 // fails before evaluating source; every function body remains the actual source.
 let code=sources.server;
 const imports=[
  "import http from 'node:http';", "import fs from 'node:fs';", "import path from 'node:path';",
  "import { fileURLToPath } from 'node:url';", "import { createHmac, timingSafeEqual } from 'node:crypto';",
  "import { isIP } from 'node:net';", "import { budgetStore, loadCredentials } from './custody.mjs';",
  "export { budgetStore } from './custody.mjs';"
 ];
 for(const declaration of imports){assert.equal(code.split(declaration).length,2,'exact import fence');code=code.replace(declaration,'');}
 code=code.replace(/export (?=function |const )/g,'').replaceAll('import.meta.url','SOURCE_URL');
 assert.ok(!/\b(?:import|export)\b/.test(code),'unexpected module syntax');
 vm.runInContext("'use strict';\n"+code+';globalThis.boundaryExports={createApp};',context,{timeout:1000});
 return {ns:context.boundaryExports,app,get handler(){return handler;}};
}

async function scenario(mode) {
 const loaded=await serverModule();let disabled=false,n=99,calls=0,checks=0;
 const req=new EventEmitter();Object.assign(req,{method:'POST',url:'/v1/ask-gv',socket:{remoteAddress:'127.0.0.1'},headers:{origin:'https://gvaisafety.com','content-type':'application/json','x-ask-gv-ingress':'b'.repeat(64),'x-ask-gv-client-ip':'198.51.100.20'},complete:true,aborted:false});
 req[Symbol.asyncIterator]=async function*(){yield Buffer.from('{"message":"status","history":[]}');};req.destroy=()=>{req.aborted=true;};
 const res=new EventEmitter();Object.assign(res,{destroyed:false,headersSent:false});res.writeHead=(code,headers)=>{res.code=code;res.headers=headers;res.headersSent=true;};res.end=text=>{res.body=JSON.parse(text);};
 const store={peek(){if(mode==='custody' && n===100)throw Error('synthetic_private_custody');return {remaining:100-n};},reserve(){n++;if(mode==='disabled')disabled=true;if(mode==='cancelled'){res.destroyed=true;res.emit('close');}if(mode==='aborted')req.aborted=true;if(mode==='drain')loaded.app.beginDrain();}};
 loaded.ns.createApp({env:{ASK_GV_ENABLED:'1',ASK_GV_TRUSTED_INGRESS:'loopback-token-v1',OPENAI_MODEL:'test-model'},credentials:{apiKey:'FAKE-private-boundary-canary',ipSalt:'a'.repeat(64),ingressToken:'b'.repeat(64)},now:()=>Date.parse('2026-11-12'),operatorDisabled:()=>{checks++;return disabled || (mode==='final-check' && checks>=4);},store,fetchImpl:async(target,options)=>{calls++;assert.equal(target,'https://api.openai.com/v1/responses');assert.equal(options.redirect,'error');const body=JSON.parse(options.body);assert.equal(body.store,false);assert.equal(body.max_output_tokens,256);assert.equal(body.tools,undefined);assert.ok(!options.body.includes('FAKE-private-boundary-canary'));return selected();}});
 await loaded.handler(req,res);
 assert.equal(n,100);assert.equal(calls,mode==='final'?1:0);
 if(mode==='final'){assert.equal(res.code,200);assert.match(res.body.answer,/experimental/);}else if(mode!=='cancelled')assert.equal(res.code,503);
 assert.ok(!JSON.stringify(res.body||{}).includes('FAKE-private-boundary-canary'));
 // Both admission slots and active controllers must be cleaned, even on denial.
 const ready=new EventEmitter();ready.writeHead=()=>{};ready.end=text=>{assert.equal(JSON.parse(text).active,0);};
 await loaded.handler({method:'GET',url:'/readyz',socket:req.socket,headers:req.headers},ready);
 if(mode==='final') {
  const again=new EventEmitter();Object.assign(again,{destroyed:false,headersSent:false});again.writeHead=code=>{again.code=code;again.headersSent=true;};again.end=()=>{};
  await loaded.handler(req,again);assert.equal(again.code,503);assert.equal(n,100);assert.equal(calls,1);
 }
}
for(const mode of ['final','disabled','cancelled','aborted','drain','final-check','custody'])test('in-memory real dispatch handler: '+mode,{timeout:2000},()=>scenario(mode));
function browserContext(fetch=deny) {
 const context=vm.createContext({URL,AbortController,TextDecoder,Uint8Array,Buffer,Request,Response,setTimeout,clearTimeout,fetch});
 vm.runInContext(sources.fetch,context,{timeout:1000});return context;
}
test('no origin has been approved; endpoint configuration remains empty',{timeout:2000},()=>{
 const c=browserContext();vm.runInContext(read('ask-gv-config.js'),vm.createContext({window:c}),{timeout:1000});assert.equal(c.ASK_GV_ENDPOINT,'');assert.equal(c.ASK_GV_APPROVED_ORIGIN,undefined);
 for(const endpoint of ['',undefined,null,'/v1/ask-gv','https://gvaisafety.com/v1/ask-gv','http://gvaisafety.com/v1/ask-gv','https://gvaisafety.com/v1/evaluations'])for(const origin of [undefined,null,'','https://gvaisafety.com/','http://gvaisafety.com','https://gvaisafety.com/?approval=not-granted'])assert.equal(c.GVAI.isApprovedAskGVEndpoint(endpoint,origin),false);
 // No successful configuration, invented hostname or configured endpoint tested.
});
test('fetch rejects redirect policy overrides and redirected mocked responses',{timeout:2000},async()=>{
 let calls=0;const c=browserContext(async(target,options)=>{calls++;assert.equal(target,'');assert.equal(options.redirect,'error');return {ok:true,status:200,redirected:true};});
 await assert.rejects(c.GVAI.fetchJSON('',{redirect:'follow',timeoutMs:100,maxBytes:16}),error=>error.kind==='http');assert.equal(calls,1);
});
test('fetch abort/deadline and byte limits are bounded mocked failures',{timeout:2000},async()=>{
 let calls=0;const c=browserContext(async()=>{calls++;return new Response('x'.repeat(17),{headers:{'content-type':'application/json'}});});
 await assert.rejects(c.GVAI.fetchJSON('',{timeoutMs:100,maxBytes:16}),error=>error.kind==='json');assert.equal(calls,1);
 const signal=new AbortController();signal.abort();await assert.rejects(c.GVAI.fetchJSON('',{signal:signal.signal,timeoutMs:100}),error=>error.kind==='aborted');assert.equal(calls,1);
 const stalled=browserContext(()=>new Promise(()=>{}));await assert.rejects(stalled.GVAI.fetchJSON('',{timeoutMs:10}),error=>error.kind==='timeout');
});
function dom() {
 class Element {constructor(){this.children=[];this.events={};this.attrs={};this.value='';this.hidden=false;}append(...nodes){for(const n of nodes){n.parent=this;this.children.push(n);}}get firstElementChild(){return this.children[0];}remove(){this.parent.children.splice(this.parent.children.indexOf(this),1);}replaceChildren(){this.children=[];}addEventListener(k,fn){this.events[k]=fn;}setAttribute(k,v){this.attrs[k]=v;}focus(){}select(){}}
 const nodes=new Map();return {nodes,document:{getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement(){return new Element();},querySelectorAll(){return [];}}};
}
test('actual disabled UI never sends; reset remains available and clears local DOM',{timeout:2000},async()=>{
 const d=dom();let calls=0;const c=browserContext(()=>{calls++;throw Error('must_not_fetch');});c.window=c;c.document=d.document;c.navigator={};
 vm.runInContext(read('ask-gv-config.js'),c,{timeout:1000});vm.runInContext(sources.ui,c,{timeout:1000});
 assert.equal(d.nodes.get('ask-send').disabled,true);assert.equal(d.nodes.get('ask-question').disabled,true);
 d.nodes.get('ask-question').value='private synthetic input';await d.nodes.get('ask-form').events.submit({preventDefault(){}});assert.equal(calls,0);
 d.nodes.get('ask-log').append(d.document.createElement());d.nodes.get('ask-summary').value='synthetic';d.nodes.get('ask-reset').events.click();assert.equal(d.nodes.get('ask-log').children.length,0);assert.equal(d.nodes.get('ask-summary').value,'');assert.equal(d.nodes.get('ask-send').disabled,true);
});
test('visible message routine caps real DOM operations without enabling chat',{timeout:2000},()=>{
 const d=dom();const start=sources.ui.indexOf('  function message('),end=sources.ui.indexOf('  async function copy(',start);assert.ok(start>0&&end>start);
 const c=vm.createContext({document:d.document,log:d.document.getElementById('ask-log'),MAX_VISIBLE_MESSAGES:24});
 vm.runInContext(sources.ui.slice(start,end)+';globalThis.appendMessage=message;',c,{timeout:1000});
 for(let i=0;i<100;i++)c.appendMessage('user','synthetic-'+i);
 assert.equal(d.nodes.get('ask-log').children.length,24);assert.equal(d.nodes.get('ask-log').children[0].children[1].textContent,'synthetic-76');
 assert.match(sources.ui,/generation!==epoch/);assert.match(sources.ui,/epoch\+\+;controller\?\.abort\(\)/);
});
test('public artifacts contain no provider credential machinery or commercial calls',{timeout:2000},()=>{
 for(const p of ['index.html','ask-gv.js','ask-gv-fetch.js','ask-gv-config.js']){const s=read(p);assert.ok(!s.includes('api.openai.com'));if(p.endsWith('.js'))assert.ok(!/decision-client|ASK_GV_DECISION|\/v1\/evaluations/.test(s));assert.ok(!/sk-[A-Za-z0-9_-]{20,}/.test(s));}
 assert.ok(!/decision-client|ASK_GV_ADVISORY|commercial_|postgres|child_process/.test(sources.server));
 const html=read('index.html');assert.match(html,/id="feedback"/);assert.ok(!/mailto:[^"\s]*[?&]body=/i.test(html));
});
function fakeClock() {let id=0;const pending=new Map();return {setTimeout(fn){pending.set(++id,fn);return id;},clearTimeout(id){pending.delete(id);},tick(){const entry=pending.entries().next().value;assert.ok(entry,'expected bounded timer');pending.delete(entry[0]);entry[1]();},get size(){return pending.size;}};}
function supervisor(spawnImpl,clock) {
 const begin=sources.hardening.indexOf('export function supervisedChild('),end=sources.hardening.indexOf("\ntest('CLI disabled startup",begin);assert.ok(begin>0&&end>begin);
 const c=vm.createContext({spawn:deny,process:{execPath:'inert-node'},Buffer,Error,...clock});
 // Explicit method binding; getter size is not part of the helper API.
 c.setTimeout=clock.setTimeout;c.clearTimeout=clock.clearTimeout;
 vm.runInContext(sources.hardening.slice(begin,end).replace('export function','function')+';globalThis.own=supervisedChild;',c,{timeout:1000});
 return c.own([],{}, {spawnImpl,deadlineMs:10,maxBytes:8,graceMs:5,reapMs:5});
}
function fakeChild(){const c=new EventEmitter();c.stdout=new EventEmitter();c.stderr=new EventEmitter();c.stdout.destroy=c.stderr.destroy=()=>{};c.exitCode=null;c.signalCode=null;c.signals=[];c.kill=signal=>{c.signals.push(signal);};c.finish=(code=0)=>{c.exitCode=code;c.emit('close',code,null);};return c;}
test('owned CLI helper: normal exit and synchronous spawn/setup failures',{timeout:2000},async()=>{
 let clock=fakeClock(),child=fakeChild(),own=supervisor(()=>child,clock);child.stdout.emit('data',Buffer.from('ok'));child.finish();assert.equal((await own.done).output,'ok');await own.dispose();assert.equal(clock.size,0);
 clock=fakeClock();own=supervisor(()=>{throw Error('private');},clock);await assert.rejects(own.done,/^Error: child_spawn$/);await own.dispose();assert.equal(clock.size,0);
 clock=fakeClock();child=fakeChild();child.stdout.on=()=>{throw Error('private');};own=supervisor(()=>child,clock);assert.deepEqual(child.signals,['SIGTERM']);child.finish();await assert.rejects(own.done,/child_setup/);await own.dispose();assert.equal(clock.size,0);
});
for(const fault of ['deadline','output','cancel','error','io'])test('owned CLI helper: '+fault+' closes and reaps fake child',{timeout:2000},async()=>{
 const clock=fakeClock(),child=fakeChild(),own=supervisor(()=>child,clock);
 if(fault==='deadline')clock.tick();if(fault==='output')child.stdout.emit('data',Buffer.alloc(9));if(fault==='error')child.emit('error',Error('private'));if(fault==='io')child.stderr.emit('error',Error('private'));
 const pending=fault==='cancel'?own.dispose():null;
 assert.deepEqual(child.signals,['SIGTERM']);clock.tick();assert.deepEqual(child.signals,['SIGTERM','SIGKILL']);child.finish();
 await assert.rejects(own.done,new RegExp('child_'+({deadline:'deadline',output:'output',cancel:'cancelled',error:'spawn',io:'io'}[fault])));if(pending)await pending;await own.dispose();assert.equal(clock.size,0);
});
test('owned CLI helper reports cleanup uncertainty instead of guessed success',{timeout:2000},async()=>{
 const clock=fakeClock(),child=fakeChild(),own=supervisor(()=>child,clock);clock.tick();clock.tick();clock.tick();await assert.rejects(own.done,/child_cleanup_unverified/);await assert.rejects(own.dispose(),/child_cleanup_unverified/);assert.equal(clock.size,0);
 // Never signal again after observed child exit, even when pipes would stay open.
 const other=fakeChild(),time=fakeClock(),owned=supervisor(()=>other,time);other.exitCode=0;time.tick();time.tick();time.tick();assert.equal(other.signals.length,0);await assert.rejects(owned.done,/child_cleanup_unverified/);
});
