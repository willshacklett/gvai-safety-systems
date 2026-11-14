// Test-only adapter around the unchanged client. Importing this module performs no I/O.
import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createDecisionClient,parseDecisionJson} from '../../ask-gv/decision-client.mjs';

export const ZERO=Object.freeze({token_delta:0,tool_calls_delta:0,error_delta:0,repeated_action_delta:0,recursion_depth:0,latency_ms:null});
const ID=/^askgv-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST=/^[0-9a-f]{64}$/;
const exact=(value,keys)=>value && typeof value==='object' && !Array.isArray(value) && Object.keys(value).sort().join() === [...keys].sort().join();
const need=condition=>{if(!condition)throw Error('HOLD: smoke invariant');};

export async function runSmoke(config,{fetchImpl,signal,evidence='mocked-contract'}={}) {
  need(exact(config,['endpoint','project','key']) && typeof fetchImpl==='function');
  need(['mocked-contract','disposable-connectivity-only'].includes(evidence));
  const records=[];let requests=0,requestId,violation=false,httpStatus=null;
  const client=createDecisionClient({...config,observe:record=>{need(records.length<2);records.push(record);},fetchImpl:async(url,options)=>{
    try {
      need(++requests===1 && url===config.endpoint && options.method==='POST' && options.redirect==='error');
      need(options.headers.Authorization==='Bearer '+config.key && options.headers['Content-Type']==='application/json');
      need(options.headers['Content-Length']===String(Buffer.byteLength(options.body)) && options.signal instanceof AbortSignal);
      const body=parseDecisionJson(options.body);
      need(exact(body,['version','request_id','resource_id','telemetry','reported_effects']));
      need(body.version==='v1' && ID.test(body.request_id) && body.resource_id===config.project);
      assert.deepEqual(body.telemetry,ZERO);assert.deepEqual(body.reported_effects,[]);requestId=body.request_id;
    }catch {violation=true;throw Error('HOLD: request contract');}
    const response=await fetchImpl(url,options);
    if(Number.isInteger(response?.status) && response.status>=100 && response.status<=599)httpStatus=response.status;
    return response;
  }});
  const operation=await client.evaluate({signal});operation.provider('not_attempted');
  need(!violation && requests===(signal?.aborted && requestId===undefined?0:1));
  need(records.length===2 && ID.test(operation.requestId));
  const [pre,provider]=records;
  for(const record of records)need(record.request_id===operation.requestId && record.mode==='advisory' && record.enforcement_applied===false && record.version==='ask-gv-advisory-v1' && record.operation==='ask_gv.openai.responses');
  need(pre.phase==='pre_dispatch' && ['evaluated','unavailable','timeout','cancelled'].includes(pre.status));
  need(provider.phase==='provider' && provider.provider_outcome==='not_attempted');
  assert.deepEqual(pre.telemetry,ZERO);
  if(requestId!==undefined)need(requestId===operation.requestId);
  // Rebuild an allowlist; no response text, explanation, key, body or exceptions leave here.
  const clean=records.map(record=>({request_id:record.request_id,phase:record.phase,mode:'advisory',enforcement_applied:false,
    ...(record.phase==='pre_dispatch'?{status:record.status,...(record.status==='evaluated'?{decision:record.decision,risk_score:record.risk_score,risk_band:record.risk_band}: {})}:{provider_outcome:'not_attempted'})}));
  const result={version:'customer-zero-advisory-smoke-v1',evidence,requests,request_id:operation.requestId,http_status:httpStatus,
    accepted_advisory_only:pre.status==='evaluated'?true:null,enforcement_applied:false,observations:clean};
  need(Buffer.byteLength(JSON.stringify(result))<=4096);return result;
}

// Pure policy over sanitized client observations; a mock label is not native evidence.
export function disposableSmokeAccepted(result) {
  const pre=result?.observations?.[0], provider=result?.observations?.[1];
  return exact(result,['version','evidence','requests','request_id','http_status','accepted_advisory_only','enforcement_applied','observations']) &&
    result.version==='customer-zero-advisory-smoke-v1' && result.evidence==='disposable-connectivity-only' &&
    result.requests===1 && typeof result.request_id==='string' && ID.test(result.request_id) &&
    result.http_status===200 && result.accepted_advisory_only===true && result.enforcement_applied===false &&
    Array.isArray(result.observations) && result.observations.length===2 &&
    pre?.phase==='pre_dispatch' && pre.status==='evaluated' && pre.decision==='ALLOW' && pre.risk_band==='green' && pre.risk_score===0 &&
    pre.request_id===result.request_id && pre.mode==='advisory' && pre.enforcement_applied===false &&
    provider?.phase==='provider' && provider.request_id===result.request_id && provider.mode==='advisory' &&
    provider.enforcement_applied===false && provider.provider_outcome==='not_attempted';
}
export function completionFrame(result,mode) {
  if(mode==='disposable' && !disposableSmokeAccepted(result)) {
    const pre=result?.observations?.[0];
    return {exitCode:2,frame:{type:'hold',reason:'disposable_smoke_not_accepted',
      ...(typeof result?.request_id==='string' && ID.test(result.request_id)?{request_id:result.request_id}:{}),
      ...(['evaluated','unavailable','timeout','cancelled'].includes(pre?.status)?{status:pre.status}:{})}};
  }
  need(mode==='contract' || mode==='disposable');
  return {exitCode:0,frame:{type:'result',result}};
}
export function requireExternalNativeBoundary() {
  // No environment flag or self-supplied approval record enables native execution.
  throw Error('HOLD: external_execution_boundary_required');
}

// This is an admission check for a separately reviewed caller, NOT an authorization issuer.
export function validateDisposableInput(input) {
  need(exact(input,['mode','config','authorization']) && input.mode==='disposable');
  need(exact(input.authorization,['fixture_id','approval_sha256','candidate_sha256','scope']));
  const a=input.authorization;
  need(process.env.GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED==='one-disposable-advisory-smoke');
  need(process.env.GVAI_CUSTOMER_ZERO_APPROVAL_SHA256===a.approval_sha256);
  need(/^customer-zero-[a-z0-9-]{1,64}$/.test(a.fixture_id) && DIGEST.test(a.approval_sha256) && DIGEST.test(a.candidate_sha256));
  need(a.scope==='one-disposable-advisory-smoke');
  need(exact(input.config,['endpoint','project','key']));
  const u=new URL(input.config.endpoint);
  need(u.protocol==='http:' && u.hostname==='127.0.0.1' && Number(u.port)>0 && u.pathname==='/v1/evaluations' && !u.username && !u.password && !u.search && !u.hash);
  need(/^customer-zero-[a-z0-9-]{1,64}$/.test(input.config.project));
}

function frameReader(stream) {
  let pending=Buffer.alloc(0),total=0,closed=false;
  return {async next() {
    need(!closed);
    for(;;) {
      const newline=pending.indexOf(10);
      if(newline>=0){const line=pending.subarray(0,newline);pending=pending.subarray(newline+1);return parseDecisionJson(new TextDecoder('utf-8',{fatal:true}).decode(line));}
      const chunk=await new Promise((resolveChunk,reject)=>{
        const clean=()=>{clearTimeout(timer);stream.pause();stream.removeListener('data',data);stream.removeListener('end',end);stream.removeListener('error',error);};
        const data=chunk=>{clean();resolveChunk(chunk);};
        const end=()=>{clean();reject(Error('HOLD: input closed'));};
        const error=()=>{clean();reject(Error('HOLD: input unavailable'));};
        const timer=setTimeout(()=>{clean();reject(Error('HOLD: input deadline'));},3000);
        stream.once('data',data);stream.once('end',end);stream.once('error',error);stream.resume();
      });
      total+=chunk.length;need(total<=32768);pending=Buffer.concat([pending,chunk]);need(pending.length<=16385);
    }
  },close(){closed=true;stream.destroy();}};
}
function send(frame) {
  const line=JSON.stringify(frame)+'\n';need(Buffer.byteLength(line)<=8192);
  return new Promise((resolveWrite,reject)=>{
    const timer=setTimeout(()=>reject(Error('HOLD: output deadline')),1000);
    process.stdout.write(line,error=>{clearTimeout(timer);error?reject(Error('HOLD: output unavailable')):resolveWrite();});
  });
}
async function main() {
  const reader=frameReader(process.stdin);
  try {
    const input=await reader.next();let result;
    if(input.mode==='contract') {
      need(exact(input,['mode','config']));
      result=await runSmoke(input.config,{fetchImpl:async(_url,options)=>{
        // Synthetic fixed-body request only, over private local pipes; no transport call.
        await send({type:'request',body:parseDecisionJson(options.body)});
        const response=await reader.next();need(exact(response,['status','body']));
        return new Response(JSON.stringify(response.body),{status:response.status,headers:{'Content-Type':'application/json'}});
      }});
    }else {
      validateDisposableInput(input);
      requireExternalNativeBoundary();
      need(process.version==='v24.22.2');
      result=await runSmoke(input.config,{fetchImpl:globalThis.fetch,evidence:'disposable-connectivity-only'});
    }
    const completed=completionFrame(result,input.mode);
    process.exitCode=completed.exitCode;await send(completed.frame);
  }catch {await send({type:'hold',reason:'smoke_prerequisite_or_contract_failed'});process.exitCode=2;}
  finally {reader.close();}
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  process.stdout.on('error',()=>{process.exitCode=2;});
  main().catch(()=>{process.exitCode=2;});
}
