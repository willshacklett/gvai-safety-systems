import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createApp} from '../../ask-gv/server.mjs';
const realFetch=globalThis.fetch;
globalThis.fetch=()=>{throw Error('Unmocked outbound network forbidden');};
const response=id=>Response.json({outcome:'evaluated',reason:'evaluated',evaluation:{version:'gvai-evaluation-v1',request_id:id,decision:'BLOCK',risk_score:80,risk_band:'red',explanation:'test',evaluation_status:'ok',advisory_only:true,enforcement_applied:false}});
async function fixture(t,{enabled=true,decision,provider,budgetFailure=false}={}) {
 let reserves=0,providers=0,evaluations=0,disabled=false;const records=[];
 const app=createApp({env:{ASK_GV_ENABLED:'1',ASK_GV_TRUSTED_INGRESS:'loopback-token-v1',OPENAI_MODEL:'test-model',...(enabled?{ASK_GV_ADVISORY_ENABLED:'1',ASK_GV_DECISION_ENDPOINT:'http://127.0.0.1:8080/v1/evaluations',ASK_GV_DECISION_PROJECT:'internal-project'}:{})},credentials:{apiKey:'FAKE-provider-only-key',ipSalt:'a'.repeat(64),ingressToken:'b'.repeat(64),decisionKey:'FAKE-decision-only-key'},now:()=>Date.parse('2026-11-12'),operatorDisabled:()=>disabled,store:{peek:()=>({remaining:100-reserves}),reserve(){if(budgetFailure)throw Error('budget');reserves++;}},observeDecision:r=>records.push(r),decisionFetch:async(u,o)=>{evaluations++;return decision?decision(u,o):response(JSON.parse(o.body).request_id);},fetchImpl:async()=>{providers++;if(provider)return provider();return Response.json({object:'response',id:'resp_test',model:'test-model',status:'completed',output:[{type:'message',id:'msg_test',role:'assistant',status:'completed',content:[{type:'output_text',text:JSON.stringify({fact_ids:['status']})}]}]});}});
 await new Promise(r=>app.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>{app.close(r);app.closeAllConnections();}));
 const request=(data={message:'Suggest a feature',history:[]},signal)=>realFetch(`http://127.0.0.1:${app.address().port}/v1/ask-gv`,{method:'POST',signal,headers:{Origin:'https://gvaisafety.com','Content-Type':'application/json','X-Ask-GV-Ingress':'b'.repeat(64),'X-Ask-GV-Client-IP':'198.51.100.1'},body:JSON.stringify(data)});
 return {app,request,records,disable:()=>{disabled=true;},counts:()=>({reserves,providers,evaluations})};
}
test('disabled by default performs no evaluation and preserves feedback',async t=>{
 const f=await fixture(t,{enabled:false});const r=await f.request();assert.equal(r.status,200);assert.equal((await r.json()).sources[0].id,'feedback');assert.deepEqual(f.counts(),{reserves:1,providers:1,evaluations:0});assert.equal(f.records.length,0);
});
test('all advisory recommendations and service failures preserve admission and exactly one budget reservation',async t=>{
 for(const kind of ['ALLOW','QUALIFY','BLOCK',401,409,429,500,503,'network']){
  const f=await fixture(t,{decision:async(_u,o)=>{if(kind==='network')throw Error('SECRET');if(typeof kind==='number')return new Response('{}',{status:kind});const v=await response(JSON.parse(o.body).request_id).json();Object.assign(v.evaluation,{decision:kind,risk_score:{ALLOW:0,QUALIFY:40,BLOCK:80}[kind],risk_band:{ALLOW:'green',QUALIFY:'yellow',BLOCK:'red'}[kind]});return Response.json(v);}});
  assert.equal((await f.request()).status,200);assert.deepEqual(f.counts(),{reserves:1,providers:1,evaluations:1});assert.deepEqual(f.records.slice(1).map(r=>r.provider_outcome),['attempted','completed']);assert.equal(new Set(f.records.map(r=>r.request_id)).size,1);assert.ok(!JSON.stringify(f.records).includes('SECRET'));
 }
});
test('invalid input never evaluates; budget denial remains authoritative',async t=>{
 const f=await fixture(t,{budgetFailure:true});assert.equal((await f.request({message:'x',history:[],project:'forged'})).status,400);assert.equal(f.counts().evaluations,0);assert.equal((await f.request()).status,503);assert.deepEqual(f.counts(),{reserves:0,providers:0,evaluations:1});assert.equal(f.records.at(-1).provider_outcome,'not_attempted');
});
test('disable, drain and caller disconnect while evaluating prevent provider dispatch',async t=>{
 for(const kind of ['disable','drain','disconnect']){
  let started,release,signal;const entered=new Promise(r=>{started=r;});
  const f=await fixture(t,{decision:async(_u,o)=>{signal=o.signal;started();await new Promise(r=>{release=r;});return response(JSON.parse(o.body).request_id);}});
  const controller=new AbortController();const pending=f.request(undefined,controller.signal).catch(()=>null);await entered;
  if(kind==='disable')f.disable();if(kind==='drain')f.app.beginDrain();if(kind==='disconnect')controller.abort();
  if(kind==='disconnect')await new Promise(r=>setTimeout(r,30));release();const result=await pending;
  if(result)assert.equal(result.status,503);await new Promise(r=>setTimeout(r,30));assert.equal(f.counts().reserves,0);assert.equal(f.counts().providers,0);if(kind!=='disable')assert.equal(signal.aborted,true);
 }
});
test('provider failure remains charged and correlated',async t=>{
 const f=await fixture(t,{provider:()=>{throw Error('PRIVATE-provider');}});assert.equal((await f.request()).status,503);assert.equal(f.counts().reserves,1);assert.equal(f.records.at(-1).provider_outcome,'failed');assert.ok(!JSON.stringify(f.records).includes('PRIVATE'));
});

test('decision timeout is advisory and consumes no extra provider budget',async t=>{
 const f=await fixture(t,{decision:()=>new Promise(()=>{})});assert.equal((await f.request()).status,200);assert.deepEqual(f.counts(),{reserves:1,providers:1,evaluations:1});assert.equal(f.records[0].status,'timeout');
});
