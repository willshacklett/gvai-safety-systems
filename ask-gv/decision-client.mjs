// Advisory observations only. No execution grants, retries or accounting repair.
import {randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';

// One permanent error listener per trusted stream: errors can arrive after write returns.
const streams=new WeakMap();
function streamState(stream) {
  let state=streams.get(stream);
  if(!state) {
    state={failed:false};streams.set(stream,state);
    try {stream.on('error',()=>{state.failed=true;});}catch {state.failed=true;}
  }
  return state;
}
function diagnosticWriter(stream=process.stderr) {
  const state=streamState(stream);let reported=false;
  return ()=>{
    if(reported)return;reported=true;
    try {
      const message='Ask GV advisory observation unavailable.\n';
      if(state.failed || stream.destroyed || stream.writableLength+Buffer.byteLength(message)>65536)return;
      stream.write(message,error=>{if(error)state.failed=true;});
    }catch {state.failed=true;}
  };
}
export function createObservationWriter({output=process.stdout,diagnostics=process.stderr}={}) {
  const state=streamState(output),diagnostic=diagnosticWriter(diagnostics);
  return record=>{
    try {
      const line=JSON.stringify(record)+'\n',size=Buffer.byteLength(line);
      if(state.failed || output.destroyed || size>2048 || output.writableLength+size>65536){diagnostic();return;}
      output.write(line,error=>{if(error){state.failed=true;diagnostic();}});
    }catch {state.failed=true;diagnostic();}
  };
}

// JSON.parse supplies grammar validation; a bounded structural walk rejects duplicate
// decoded names in EVERY object, including names containing escapes. No regex parser.
export function parseDecisionJson(text) {
  if(typeof text!=='string' || Buffer.byteLength(text)>16384)throw Error('decision_json');
  const result=JSON.parse(text);let i=0;
  const space=()=>{while(i<text.length && [' ','\t','\r','\n'].includes(text[i]))i++;};
  const string=()=>{
    const start=i++;
    while(i<text.length) {
      if(text[i]==='\\'){i+=2;continue;}
      if(text[i++]==='"')return JSON.parse(text.slice(start,i));
    }
    throw Error('decision_json');
  };
  const value=depth=>{
    if(depth>32)throw Error('decision_json');
    space();const c=text[i];
    if(c==='"'){string();return;}
    if(c==='{' || c==='[') {
      const object=c==='{',end=object?'}':']',names=new Set();i++;space();
      if(text[i]===end){i++;return;}
      for(;;) {
        if(object) {
          const name=string();if(names.has(name))throw Error('decision_json');names.add(name);
          space();if(text[i++]!==':')throw Error('decision_json');
        }
        value(depth+1);space();if(text[i]===end){i++;return;}
        if(text[i++]!==',')throw Error('decision_json');space();
      }
    }
    const start=i;
    while(i<text.length && ![',',']','}',' ','\t','\r','\n'].includes(text[i]))i++;
    if(i===start)throw Error('decision_json');
  };
  value(0);space();if(i!==text.length)throw Error('decision_json');return result;
}

const exact=(v,keys)=>v && typeof v==='object' && !Array.isArray(v) && Object.keys(v).sort().join()===keys.sort().join();
export function validateDecisionConfig(endpoint, project, key) {
  const url=new URL(endpoint);
  if(url.username || url.password || url.search || url.hash || url.pathname!=='/v1/evaluations' ||
    !(url.protocol==='https:' || (url.protocol==='http:' && ['127.0.0.1','[::1]'].includes(url.hostname))) ||
    typeof project!=='string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(project) ||
    typeof key!=='string' || !/^[\x21-\x7e]{16,4096}$/.test(key))throw Error('decision_configuration');
  return url.href;
}
export function validateDecision(value, requestId) {
  if(!exact(value,['outcome','reason','evaluation']) || value.outcome!=='evaluated' || value.reason!=='evaluated')throw Error('decision_response');
  const e=value.evaluation;
  if(!exact(e,['version','request_id','decision','risk_score','risk_band','explanation','evaluation_status','advisory_only','enforcement_applied']) ||
    e.version!=='gvai-evaluation-v1' || e.request_id!==requestId || e.evaluation_status!=='ok' || e.advisory_only!==true || e.enforcement_applied!==false ||
    typeof e.explanation!=='string' || !e.explanation.trim() || e.explanation.length>4096 || typeof e.risk_score!=='number' || !Number.isFinite(e.risk_score) || e.risk_score<0 || e.risk_score>100)throw Error('decision_response');
  const band=e.risk_score<35?'green':e.risk_score<70?'yellow':'red';
  if(e.risk_band!==band || e.decision!==({green:'ALLOW',yellow:'QUALIFY',red:'BLOCK'}[band]))throw Error('decision_response');
  return {decision:e.decision,risk_score:e.risk_score,risk_band:e.risk_band};
}
export function createDecisionClient({endpoint,project,key,fetchImpl=globalThis.fetch,observe=()=>{}}) {
  const target=validateDecisionConfig(endpoint,project,key);
  // Never forward caller-controlled objects, explanations or exceptions to the sink.
  const diagnostic=diagnosticWriter();
  const emit=record=>{try {Promise.resolve(observe(Object.freeze(record))).catch(diagnostic);}catch {diagnostic();}};
  return {
    async evaluate({signal}={}) {
      const requestId='askgv-'+randomUUID(), started=performance.now();
      const base={version:'ask-gv-advisory-v1',timestamp_utc:new Date().toISOString(),request_id:requestId,operation:'ask_gv.openai.responses',mode:'advisory',phase:'pre_dispatch',enforcement_applied:false};
      const telemetry={token_delta:0,tool_calls_delta:0,error_delta:0,repeated_action_delta:0,recursion_depth:0,latency_ms:null};
      const controller=new AbortController();let timeout=false, rejectStop;
      const stopped=new Promise((_,reject)=>{rejectStop=reject;});
      const stop=()=>{controller.abort();rejectStop(Error('cancelled'));};
      signal?.addEventListener('abort',stop,{once:true});
      const timer=setTimeout(()=>{timeout=true;stop();},500);
      let result={status:'unavailable'};
      try {
        if(signal?.aborted)stop();
        const work=(async()=>{
          if(controller.signal.aborted)throw Error('cancelled');
          const body=JSON.stringify({version:'v1',request_id:requestId,resource_id:project,telemetry,reported_effects:[]});
          const response=await fetchImpl(target,{method:'POST',redirect:'error',signal:controller.signal,headers:{Authorization:'Bearer '+key,'Content-Type':'application/json','Content-Length':String(Buffer.byteLength(body))},body});
          if(response.status!==200 || response.redirected || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type') || ''))throw Error('response');
          const parts=[];let size=0;
          if(!response.body)throw Error('response');
          for await(const part of response.body){size+=part.length;if(size>16384)throw Error('response');parts.push(part);}
          return validateDecision(parseDecisionJson(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts))),requestId);
        })();
        result={status:'evaluated',...await Promise.race([work,stopped])};
      }catch {result={status:timeout?'timeout':signal?.aborted?'cancelled':'unavailable'};}
      finally {clearTimeout(timer);signal?.removeEventListener('abort',stop);controller.abort();}
      emit({...base,telemetry:Object.freeze(telemetry),...result,elapsed_ms:Math.round(performance.now()-started)});
      return {requestId, provider(outcome,elapsedMs=0) {
        emit({...base,phase:'provider',provider_outcome:['attempted','completed','failed','cancelled','not_attempted'].includes(outcome)?outcome:'failed',elapsed_ms:Math.max(0,Math.round(Number.isFinite(elapsedMs)?elapsedMs:0))});
      }};
    }
  };
}
