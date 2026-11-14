import {test} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import {spawn} from 'node:child_process';
import {createApp,ingressIdentity,validateCorpus,validateEnvelope} from '../../ask-gv/server.mjs';
const requestFetch=globalThis.fetch;globalThis.fetch=()=>{throw Error('No unmocked provider networking');};
const credentials={apiKey:'FAKE-provider-test-only',ipSalt:'a'.repeat(64),ingressToken:'b'.repeat(64)};
const env={ASK_GV_ENABLED:'1',ASK_GV_TRUSTED_INGRESS:'loopback-token-v1',OPENAI_MODEL:'test-model'};
const envelope=()=>({object:'response',id:'resp_mock',model:'test-model',status:'completed',output:[{id:'msg_mock',type:'message',role:'assistant',status:'completed',content:[{type:'output_text',text:'{"fact_ids":["status"]}',annotations:[]}]}]});
async function fixture(t,options={}){
 let attempts=0,calls=0,disabled=false;
 const store={reserve(){attempts++;},peek(){return {remaining:100-attempts};}};
 const app=createApp({env,credentials,store,now:()=>Date.parse('2026-11-12'),operatorDisabled:()=>disabled,fetchImpl:async()=>{calls++;return new Response(JSON.stringify(envelope()));},...options});
 await new Promise(r=>app.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>{app.beginDrain();app.close(r);app.closeAllConnections();}));
 const request=(ip='198.51.100.10',headers={},route='/v1/ask-gv',method='POST')=>requestFetch(`http://127.0.0.1:${app.address().port}${route}`,{method,headers:{Origin:'https://gvaisafety.com','Content-Type':'application/json','X-Ask-GV-Ingress':credentials.ingressToken,'X-Ask-GV-Client-IP':ip,...headers},...(method==='POST'?{body:'{"message":"status","history":[]}'}:{})});
 return {app,request,disable(){disabled=true;},get attempts(){return attempts;},get calls(){return calls;}};
}
test('two visitors have separate quotas, global cap stays finite, spoofing denied',async t=>{
 const f=await fixture(t);for(let i=0;i<6;i++)assert.equal((await f.request()).status,200);assert.equal((await f.request()).status,429);
 assert.equal((await f.request('198.51.100.11')).status,200);
 assert.equal((await f.request('198.51.100.12',{'X-Ask-GV-Ingress':'c'.repeat(64)})).status,403);
 assert.equal((await f.request('198.51.100.12',{'X-Forwarded-For':'evil'})).status,403);
 assert.equal((await f.request('198.51.100.12, 198.51.100.13')).status,403);
 for(let i=0;i<23;i++)assert.equal((await f.request(`198.51.100.${20+i}`)).status,200);
 assert.equal((await f.request('198.51.100.99')).status,429);assert.equal(f.attempts,30);
});
test('proxy identity requires exact loopback, token and one normalized address',()=>{
 const req=(peer,ip,token=credentials.ingressToken)=>({socket:{remoteAddress:peer},headers:{'x-ask-gv-ingress':token,'x-ask-gv-client-ip':ip}});
 assert.throws(()=>ingressIdentity(req('192.0.2.1','198.51.100.1'),credentials.ingressToken));
 assert.throws(()=>ingressIdentity(req('127.0.0.1','198.51.100.1','é'.repeat(64)),credentials.ingressToken));
 for(const ip of ['host.example','127.0.0.1, 1.2.3.4','fe80::1%eth0',''])assert.throws(()=>ingressIdentity(req('127.0.0.1',ip),credentials.ingressToken));
 assert.equal(ingressIdentity(req('127.0.0.1','::ffff:198.51.100.1'),credentials.ingressToken),'198.51.100.1');
 assert.equal(ingressIdentity(req('127.0.0.1','2001:0DB8:0:0:0:0:0:1'),credentials.ingressToken),'2001:db8::1');
});
test('busy rejections do not consume visitor allowance',async t=>{
 let enter=0,release;const wait=new Promise(r=>release=r);
 const f=await fixture(t,{fetchImpl:async()=>{enter++;await wait;return new Response(JSON.stringify(envelope()));}});
 const a=f.request('198.51.100.1'),b=f.request('198.51.100.2');while(enter<2)await new Promise(r=>setTimeout(r,5));
 for(let i=0;i<8;i++)assert.equal((await f.request('198.51.100.3')).status,429);
 release();assert.equal((await a).status,200);assert.equal((await b).status,200);
 for(let i=0;i<6;i++)assert.equal((await f.request('198.51.100.3')).status,200);
 assert.equal((await f.request('198.51.100.3')).status,429);
});
test('local health/private readiness are provider-free and do not consume quota',async t=>{
 const f=await fixture(t);
 for(let i=0;i<8;i++){assert.equal((await f.request('',{},'/healthz','GET')).status,200);assert.equal((await f.request('',{},'/readyz','GET')).status,200);}
 assert.equal(f.attempts,0);assert.equal(f.calls,0);
 assert.equal((await f.request('',{'X-Ask-GV-Ingress':'wrong'},'/readyz','GET')).status,403);
 f.disable();const response=await f.request('',{},'/readyz','GET');assert.equal(response.status,503);const text=await response.text();assert.ok(!text.includes(credentials.apiKey));assert.match(text,/"disabled":true/);
 assert.equal((await f.request()).status,503);assert.equal(f.attempts,0);
});
test('last reserved attempt still returns its answer, then readiness fails',async t=>{
 let n=99;const f=await fixture(t,{store:{peek(){return {remaining:100-n};},reserve(){n++;}}});
 assert.equal((await f.request()).status,200);assert.equal(n,100);assert.equal((await f.request()).status,503);
 assert.equal((await f.request('',{},'/readyz','GET')).status,503);
});
test('provider failures open a safe manual-review circuit and reveal fixed counters only',async t=>{
 const f=await fixture(t,{fetchImpl:async()=>{throw Error(credentials.apiKey);}});
 for(let i=0;i<4;i++)assert.equal((await f.request()).status,503);assert.equal(f.attempts,3);
 const response=await f.request('',{},'/readyz','GET');const state=await response.json();assert.equal(state.circuitOpen,true);assert.equal(state.counters.provider,3);assert.ok(!JSON.stringify(state).includes(credentials.apiKey));
});
test('drain aborts in-flight work and prevents new reservations',async t=>{
 let entered=false,aborted=false;
 const f=await fixture(t,{fetchImpl:async(_url,{signal})=>new Promise((_resolve,reject)=>{entered=true;signal.addEventListener('abort',()=>{aborted=true;reject(Error('aborted'));});})});
 const pending=f.request();while(!entered)await new Promise(r=>setTimeout(r,5));f.app.beginDrain();assert.equal((await pending).status,503);assert.equal(aborted,true);assert.equal((await f.request()).status,503);assert.equal(f.attempts,1);
});
test('strict calendars/horizon and malformed provider envelopes fail closed',()=>{
 for(const date of ['2027-02-30','2027-13-01','2028-02-29']){const c=JSON.parse(fs.readFileSync(new URL('../../ask-gv/facts.json',import.meta.url)));c.reviewBy=date;assert.throws(()=>validateCorpus(c));}
 for(const change of [r=>r.status='incomplete',r=>r.model='other',r=>r.output[0].role='user',r=>r.output[0].status='incomplete',r=>r.output.push({type:'function_call'}),r=>r.output[0].content.push({type:'refusal'}),r=>r.output[0].content[0].annotations=[{url:'https://evil.example'}],r=>r.tools=[{type:'web_search'}],r=>r.tools=0,r=>r.output[0].phase='commentary',r=>r.output[0].content[0].annotations='',r=>r.output[0].content[0].refusal='hidden']){const r=envelope();change(r);assert.throws(()=>validateEnvelope(r,'test-model'));}
 assert.match(validateEnvelope(envelope(),'test-model').answer,/experimental/);
});
// Owned direct-child supervision. These CLI fixtures spawn no descendants.
// No process-group or name-based kills; an external supervisor owns whole-job failure.
export function supervisedChild(args, env, {spawnImpl=spawn, deadlineMs=5000, maxBytes=16384, graceMs=250, reapMs=1000}={}) {
 for(const n of [deadlineMs,maxBytes,graceMs,reapMs])if(!Number.isSafeInteger(n)||n<1||n>65536)throw Error('child_configuration');
 let child,closed=false,failure=null,output='',bytes=0,termTimer,killTimer,deadline;
 let resolveDone,rejectDone;
 const done=new Promise((resolve,reject)=>{resolveDone=resolve;rejectDone=reject;});
 done.catch(()=>{}); // The owning caller still awaits done; no early unhandled rejection.
 const clear=()=>{clearTimeout(deadline);clearTimeout(termTimer);clearTimeout(killTimer);};
 const kill=signal=>{if(!closed && child?.exitCode===null && child?.signalCode===null)try{child.kill(signal);}catch{failure||='child_cleanup';}};
 const stop=reason=>{
  if(closed)return;
  failure||=reason;clearTimeout(deadline);
  if(termTimer || killTimer)return;
  kill('SIGTERM');
  termTimer=setTimeout(()=>{termTimer=null;kill('SIGKILL');killTimer=setTimeout(()=>{
   clear();child?.stdout?.destroy();child?.stderr?.destroy();rejectDone(Error('child_cleanup_unverified'));
  },reapMs);},graceMs);
 };
 try {
  child=spawnImpl(process.execPath,args,{env,stdio:['ignore','pipe','pipe']});
  child.once('error',()=>stop('child_spawn'));
  child.once('close',(code,signal)=>{closed=true;clear();if(failure)rejectDone(Error(failure));else resolveDone({code,signal,output});});
  const capture=data=>{bytes+=Buffer.byteLength(data);if(bytes>maxBytes){stop('child_output');return;}output+=data.toString();};
  child.stdout.on('data',capture);child.stderr.on('data',capture);
  child.stdout.on('error',()=>stop('child_io'));child.stderr.on('error',()=>stop('child_io'));
  deadline=setTimeout(()=>stop('child_deadline'),deadlineMs);
 } catch {
  if(child)stop('child_setup');else {closed=true;clear();rejectDone(Error('child_spawn'));}
 }
 return {child,done,async dispose(){if(!closed)stop('child_cancelled');try{await done;}catch(error){if(!closed)throw Error('child_cleanup_unverified');}}};
}
test('CLI disabled startup, provider-free liveness and signal shutdown use no keys',{timeout:8000},async t=>{
 const port=await new Promise(r=>{const s=http.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>r(p));});});
 const owned=supervisedChild(['ask-gv/server.mjs'],{PATH:process.env.PATH,PORT:String(port),ASK_GV_ENABLED:'0'});
 t.after(()=>owned.dispose());
 let response;for(let i=0;i<20;i++){try{response=await requestFetch(`http://127.0.0.1:${port}/healthz`,{signal:AbortSignal.timeout(200)});break;}catch{await new Promise(r=>setTimeout(r,10));}}
 assert.equal(response?.status,200);owned.child.kill('SIGTERM');const result=await owned.done;assert.equal(result.code,0);assert.equal(result.output,'');
});
test('CLI enabled startup refuses missing credentials without printing environment secrets',{timeout:8000},async t=>{
 const owned=supervisedChild(['ask-gv/server.mjs'],{PATH:process.env.PATH,ASK_GV_ENABLED:'1',ASK_GV_DISABLE_FILE:'/nonexistent/disabled',OPENAI_API_KEY:'FAKE-must-not-be-printed'});
 t.after(()=>owned.dispose());const result=await owned.done;assert.equal(result.code,1);assert.equal(result.output,'Ask GV startup refused.\n');
});

test('provider response-body deadline is bounded after headers arrive',async t=>{
 const f=await fixture(t,{fetchImpl:async(_url,{signal})=>new Response(new ReadableStream({start(controller){signal.addEventListener('abort',()=>controller.error(Error('timeout')));}}))});
 const res=await f.request();assert.equal(res.status,503);assert.equal(f.attempts,1);
 const ready=await (await f.request('',{},'/readyz','GET')).json();assert.equal(ready.counters.timeout,1);
});
