import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createDecisionClient,validateDecision,validateDecisionConfig,parseDecisionJson} from '../../ask-gv/decision-client.mjs';
export const envelope=(id,decision='ALLOW')=>({outcome:'evaluated',reason:'evaluated',evaluation:{version:'gvai-evaluation-v1',request_id:id,decision,risk_score:{ALLOW:0,QUALIFY:40,BLOCK:80}[decision],risk_band:{ALLOW:'green',QUALIFY:'yellow',BLOCK:'red'}[decision],explanation:'maintained explanation',evaluation_status:'ok',advisory_only:true,enforcement_applied:false}});
const config={endpoint:'http://127.0.0.1:8080/v1/evaluations',project:'ask-gv-self-protection',key:'FAKE-decision-only-key'};
test('exact authenticated contract and sanitized correlated observations',async()=>{
 const records=[];let calls=0;
 const client=createDecisionClient({...config,observe:r=>records.push(r),fetchImpl:async(url,o)=>{
  calls++;assert.equal(url,config.endpoint);assert.equal(o.redirect,'error');assert.equal(o.headers.Authorization,'Bearer '+config.key);
  assert.equal(o.headers['Content-Length'],String(Buffer.byteLength(o.body)));
  const b=JSON.parse(o.body);assert.deepEqual(Object.keys(b),['version','request_id','resource_id','telemetry','reported_effects']);assert.match(b.request_id,/^askgv-[a-f0-9-]{36}$/);assert.equal(b.resource_id,config.project);assert.deepEqual(b.reported_effects,[]);assert.deepEqual(b.telemetry,{token_delta:0,tool_calls_delta:0,error_delta:0,repeated_action_delta:0,recursion_depth:0,latency_ms:null});
  return Response.json(envelope(b.request_id),{headers:{'Content-Type':'application/json; charset=utf-8'}});
 }});
 const op=await client.evaluate();op.provider('completed',10);assert.equal(calls,1);assert.equal(records[0].status,'evaluated');assert.equal(records[0].request_id,records[1].request_id);assert.equal(records[0].enforcement_applied,false);assert.ok(!JSON.stringify(records).includes(config.key));assert.ok(!JSON.stringify(records).includes('maintained explanation'));
});
test('strict response identity, flags, scores and status',()=>{
 for(const patch of [{request_id:'wrong'},{advisory_only:false},{enforcement_applied:true},{evaluation_status:'error'},{risk_score:null},{risk_score:NaN},{risk_score:true},{risk_score:101},{risk_band:'red'},{decision:'BLOCK'},{explanation:''}]){
  const v=envelope('id');Object.assign(v.evaluation,patch);assert.throws(()=>validateDecision(v,'id'));
 }
 const extra=envelope('id');extra.tenant='forged';assert.throws(()=>validateDecision(extra,'id'));
 for(const d of ['ALLOW','QUALIFY','BLOCK'])assert.equal(validateDecision(envelope('id',d),'id').decision,d);
});
test('configuration denies arbitrary HTTP, redirect paths, identity fields and malformed key',()=>{
 for(const endpoint of ['http://example.com/v1/evaluations','http://localhost/v1/evaluations','https://user:pass@example.com/v1/evaluations','https://example.com/v1/evaluations?q=1','https://example.com/other','https://example.com/v1/evaluations#x'])assert.throws(()=>validateDecisionConfig(endpoint,config.project,config.key));
 assert.throws(()=>validateDecisionConfig(config.endpoint,'bad<id>',config.key));assert.throws(()=>validateDecisionConfig(config.endpoint,config.project,'bad key'));
});
test('HTTP errors, invalid UTF8/JSON, oversized bodies, redirects and network failures never retry',async()=>{
 for(const kind of [400,401,403,409,429,500,503,'json','utf8','large','redirect','network']){
  let calls=0;const records=[];
  const client=createDecisionClient({...config,observe:r=>records.push(r),fetchImpl:async()=>{calls++;if(kind==='network')throw Error('SECRET-error');if(kind==='redirect')return new Response('',{status:302});return new Response(kind==='large'?'x'.repeat(16385):kind==='utf8'?new Uint8Array([255]):'{',{status:typeof kind==='number'?kind:200,headers:{'Content-Type':'application/json'}});}});
  await client.evaluate();assert.equal(calls,1);assert.equal(records[0].status,'unavailable');assert.ok(!JSON.stringify(records).includes('SECRET'));
 }
});
test('500ms deadline covers stalled headers and stalled body, even an uncooperative transport',async()=>{
 for(const body of [false,true]){
  const records=[];let signal;const start=performance.now();
  const client=createDecisionClient({...config,observe:r=>records.push(r),fetchImpl:async(_u,o)=>{signal=o.signal;return body?new Response(new ReadableStream({start(){}}),{headers:{'Content-Type':'application/json'}}):new Promise(()=>{});}});
  await client.evaluate();assert.equal(records[0].status,'timeout');assert.equal(signal.aborted,true);assert.ok(performance.now()-start<1500);
 }
});
test('pre-aborted caller performs no transport request',async()=>{
 const c=new AbortController();c.abort();let calls=0;const records=[];
 await createDecisionClient({...config,observe:r=>records.push(r),fetchImpl:()=>{calls++;}}).evaluate({signal:c.signal});assert.equal(calls,0);assert.equal(records[0].status,'cancelled');
});

test('unavailable observation sink cannot change advisory result or leak exceptions',async()=>{
 const original=process.stderr.write;let diagnostic='';process.stderr.write=(text)=>{diagnostic+=text;return true;};
 try {
  const client=createDecisionClient({...config,observe:()=>{throw Error('SECRET-sink');},fetchImpl:async(_u,o)=>Response.json(envelope(JSON.parse(o.body).request_id))});
  const op=await client.evaluate();op.provider('completed');assert.equal(diagnostic,'Ask GV advisory observation unavailable.\n');
 }finally {process.stderr.write=original;}
});


test('bounded structural parser rejects duplicate decoded names in every object',async()=>{
 const invalid=[
  '{"outcome":"denied","outcome":"evaluated"}',
  '{"evaluation":{"request_id":"a","request_id":"b"}}',
  '{"evaluation":{"advisory_only":false,"advisory_only":true}}',
  '{"evaluation":{"advisory_only":true,"advisory_only":false}}',
  '{"evaluation":{"enforcement_applied":true,"enforcement_applied":false}}',
  '{"evaluation":{"risk_score":80,"risk_score":0}}',
  '{"evaluation":{"advisory_only":false,"advisory_\\u006fnly":true}}',
  '{"array":[{"unrelated":{"x":1,"\\u0078":2}}]}',
  '{"__proto__":1,"__proto__":2}',
  '['.repeat(34)+'0'+']'.repeat(34), ' '.repeat(16385), '{', '{"x":1,}'
 ];
 for(const text of invalid)assert.throws(()=>parseDecisionJson(text),text);
 for(const value of [null,true,1,-2.5,'quote" and slash\\',[],{}, {a:[{a:1}, {a:2}],b:{a:3}}, {'__safe__':'雪'}])assert.deepEqual(parseDecisionJson(JSON.stringify(value)),value);
 assert.deepEqual(parseDecisionJson(' { "a" : [1,true,null,{"b":"\\u0061"}] } '),{a:[1,true,null,{b:'a'}]});
 const records=[];
 await createDecisionClient({...config,observe:r=>records.push(r),fetchImpl:async(_u,o)=>new Response(JSON.stringify(envelope(JSON.parse(o.body).request_id)).replace('"advisory_only":true','"advisory_only":false,"advisory_\\u006fnly":true'),{headers:{'Content-Type':'application/json'}})}).evaluate();
 assert.equal(records[0].status,'unavailable');
});
