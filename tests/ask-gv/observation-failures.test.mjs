import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Readable,Writable} from 'node:stream';
import {EventEmitter} from 'node:events';
import {spawn} from 'node:child_process';
import {createObservationWriter} from '../../ask-gv/decision-client.mjs';
import {createApp} from '../../ask-gv/server.mjs';

// Invoke the actual HTTP callback with disposable streams: no network listener needed.
async function exercise({observe=()=>{},onReserve=()=>{},lastUnit=false}={}) {
 let app,reserves=0,providers=0,disabled=false;const signals=[];
 const credentials={apiKey:'FAKE-provider-key',ipSalt:'a'.repeat(64),ingressToken:'b'.repeat(64),decisionKey:'FAKE-decision-key'};
 const env={ASK_GV_ENABLED:'1',ASK_GV_TRUSTED_INGRESS:'loopback-token-v1',OPENAI_MODEL:'test-model',ASK_GV_ADVISORY_ENABLED:'1',ASK_GV_DECISION_ENDPOINT:'http://127.0.0.1:8080/v1/evaluations',ASK_GV_DECISION_PROJECT:'internal'};
 const answer=()=>Response.json({object:'response',id:'resp_mock',model:'test-model',status:'completed',output:[{type:'message',id:'msg_mock',role:'assistant',status:'completed',content:[{type:'output_text',text:'{"fact_ids":["status"]}'}]}]});
 const make=(method='POST',url='/v1/ask-gv')=>{
  const req=Readable.from([Buffer.from('{"message":"hello","history":[]}')]);
  Object.assign(req,{method,url,complete:true,aborted:false,headers:{origin:'https://gvaisafety.com','content-type':'application/json','x-ask-gv-ingress':credentials.ingressToken,'x-ask-gv-client-ip':'198.51.100.1'},socket:{remoteAddress:'127.0.0.1'}});
  const res=new EventEmitter();Object.assign(res,{destroyed:false,headersSent:false,status:0,body:'',setHeader(){},writeHead(code){this.status=code;this.headersSent=true;},end(text){this.body=text;}});
  return {req,res};
 };
 let request=make();
 app=createApp({env,credentials,now:()=>Date.parse('2026-11-12'),operatorDisabled:()=>disabled,
  store:{peek:()=>({remaining:(lastUnit?1:100)-reserves}),reserve(){reserves++;onReserve({disable:()=>{disabled=true;},drain:()=>app.beginDrain(),disconnect:()=>{request.res.destroyed=true;request.res.emit('close');}});}},
  observeDecision:observe,decisionFetch:async(_u,o)=>{signals.push(o.signal);return Response.json({outcome:'evaluated',reason:'evaluated',evaluation:{version:'gvai-evaluation-v1',request_id:JSON.parse(o.body).request_id,decision:'ALLOW',risk_score:0,risk_band:'green',explanation:'ok',evaluation_status:'ok',advisory_only:true,enforcement_applied:false}});},
  fetchImpl:async(_u,o)=>{signals.push(o.signal);providers++;return answer();}});
 const handler=app.listeners('request')[0];await handler(request.req,request.res);
 const closedListeners=request.res.listenerCount('close'),status=request.res.status;
 const ready=make('GET','/readyz');await handler(ready.req,ready.res);
 const active=JSON.parse(ready.res.body).active;
 assert.equal(active,0);assert.equal(closedListeners,0);assert.ok(signals.every(s=>s.aborted));
 return {status,reserves,providers,active};
}

test('reserve-time disable/drain/disconnect retains charge and prevents dispatch; final unit remains usable',async()=>{
 for(const action of ['disable','drain','disconnect']){
  const result=await exercise({onReserve:controls=>controls[action]()});assert.equal(result.reserves,1);assert.equal(result.providers,0);assert.equal(result.active,0);
 }
 const final=await exercise({lastUnit:true});assert.equal(final.status,200);assert.equal(final.providers,1);assert.equal(final.reserves,1);
});

test('sync/async observer failures plus diagnostic failure cannot skip cleanup or change admission',async()=>{
 const write=process.stderr.write;process.stderr.write=()=>{throw Error('PRIVATE-diagnostic');};
 try {
  for(const asyncFailure of [false,true])for(const phase of ['pre_dispatch','attempted','completed']){
   const result=await exercise({observe:r=>{if(r.phase===phase || r.provider_outcome===phase){if(asyncFailure)return Promise.reject(Error('PRIVATE-observer'));throw Error('PRIVATE-observer');}}});
   await new Promise(r=>setImmediate(r));assert.equal(result.status,200);assert.equal(result.reserves,1);assert.equal(result.providers,1);assert.equal(result.active,0);
  }
 }finally {process.stderr.write=write;}
});

test('bounded writer handles callback/event failures and never queues beyond limit',async()=>{
 let written=0;const output=new Writable({write(_c,_e,callback){written++;callback(Error('PRIVATE-output'));}});
 const diagnostics=new Writable({write(_c,_e,callback){callback(Error('PRIVATE-diagnostic'));}});
 const writer=createObservationWriter({output,diagnostics});writer({phase:'first'});await new Promise(r=>setImmediate(r));writer({phase:'second'});assert.equal(written,1);
 let calls=0;const blocked=new Writable({write(){calls++;}});blocked.write('x'.repeat(65536));const drop=createObservationWriter({output:blocked,diagnostics});drop({phase:'drop'});assert.equal(blocked.writableLength,65536);assert.equal(calls,1);blocked.destroy();
});

test('child survives broken stdout before/during provider work and failing diagnostic stream',async()=>{
 for(const phase of ['before','attempted','completed']) {
  const code=`import assert from 'node:assert/strict';import {Readable,Writable} from 'node:stream';import {EventEmitter} from 'node:events';import {createApp} from ${JSON.stringify(new URL('../../ask-gv/server.mjs',import.meta.url).href)};import {createObservationWriter} from ${JSON.stringify(new URL('../../ask-gv/decision-client.mjs',import.meta.url).href)};
  const exercise=${exercise.toString()};
  const diagnostics=new Writable({write(c,e,cb){cb(Error('PRIVATE-diagnostic'));}});
  const writer=createObservationWriter({output:process.stdout,diagnostics});
  const failed=new Promise(resolve=>process.stdout.once('error',resolve));
  process.send('ready');await new Promise(resolve=>process.once('message',resolve));
  if(${JSON.stringify(phase)}==='before'){writer({phase:'before'});await failed;}
  const result=await exercise({observe:r=>{if(${JSON.stringify(phase)}==='before' || r.provider_outcome===${JSON.stringify(phase)})writer(r);}});
  await failed;await new Promise(resolve=>setImmediate(resolve));process.send(result);process.disconnect();`;
  const child=spawn(process.execPath,['--input-type=module','-e',code],{stdio:['ignore','pipe','pipe','ipc']});
  let stderr='',result;child.stderr.on('data',b=>stderr+=b);
  const exited=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
  const timer=setTimeout(()=>child.kill('SIGKILL'),5000);
  child.on('message',message=>{if(message==='ready'){child.stdout.destroy();child.send('go');}else result=message;});
  const exit=await exited;clearTimeout(timer);assert.equal(exit.code,0,stderr);assert.equal(exit.signal,null);assert.equal(stderr,'');assert.deepEqual(result,{status:200,reserves:1,providers:1,active:0});
 }
});
