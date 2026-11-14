// Pure candidate policy. No imports, clock reads, I/O, RNG, hashing or state mutation.
// Supplied positive evidence is NOT authenticated; outputs never authorize execution.
export const POLICY_LIMITS=Object.freeze({invites:32,sessions:32,inviteLifetimeMs:86400000,sessionLifetimeMs:900000,forwards:5,evidenceAgeMs:1000,clockDivergenceMs:1000,jsonBytes:32768,jsonDepth:8,jsonNodes:2048,idChars:64,pathChars:64,originChars:128,methodChars:8});
const V='ask-gv-invite-policy-';
const ORIGINS=Object.freeze(['https://gvaisafety.com','https://www.gvaisafety.com']);
const REASONS=new Set(['input_invalid','policy_ambiguous','clock_uncertain','clock_rollback','clock_divergence','external_missing','external_uncertain','evidence_stale','release_closed','credential_mismatch','policy_disabled','policy_stale','origin_mismatch','route_mismatch','invite_missing','invite_inactive','invite_not_yet_valid','invite_expired','generation_changed','consumption_uncertain','consumption_conflict','invite_replay','consumption_missing','session_missing','session_inactive','session_not_yet_valid','session_expired','capacity_exhausted','attempts_exhausted','eligible_for_atomic_claim','eligible_for_single_forward','eligible_for_local_logout']);
function fail(reason='input_invalid'){throw reason;}
function need(condition,reason){if(!condition)fail(reason);}
function exact(value,keys){need(value!==null && typeof value==='object' && !Array.isArray(value));const got=Object.keys(value);need(got.length===keys.length && keys.every(k=>Object.hasOwn(value,k)));}
function integer(n,min=0,max=Number.MAX_SAFE_INTEGER){need(Number.isSafeInteger(n) && !Object.is(n,-0) && n>=min && n<=max);}
function choice(value,values){need(typeof value==='string' && values.includes(value));}
function text(value,max){need(typeof value==='string' && value.length<=max && /^[\x20-\x7e]*$/.test(value));}
function id(value){need(typeof value==='string' && /^[a-z][a-z0-9-]{0,63}$/.test(value));}
function digest(value){need(typeof value==='string' && /^[0-9a-f]{64}$/.test(value));}
function interval(start,end,max){integer(start);integer(end);need(end>start && end-start<=max);}
function unique(values){need(new Set(values).size===values.length,'policy_ambiguous');}
function credential(value,bearer){need(typeof value==='string');const token=bearer ? (value.startsWith('Bearer ')?value.slice(7):'') : value;need((!bearer || value==='Bearer '+token) && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(token));}

// Text-only boundary prevents getters/proxies, inherited data and duplicate-name loss
// from an object API. ASCII transport may use JSON escapes; decoded schemas are ASCII.
function parse(textValue){
 need(typeof textValue==='string' && textValue.length>0 && textValue.length<=POLICY_LIMITS.jsonBytes && /^[\x00-\x7f]*$/.test(textValue));
 const result=JSON.parse(textValue); // Grammar only; no supplied callbacks/reviver.
 let i=0,nodes=0;
 const space=()=>{while([' ','\t','\r','\n'].includes(textValue[i]))i++;};
 const string=()=>{const start=i++;while(i<textValue.length){if(textValue[i]==='\\'){i+=2;continue;}if(textValue[i++]==='"')return JSON.parse(textValue.slice(start,i));}fail();};
 const value=depth=>{
  need(depth<=POLICY_LIMITS.jsonDepth && ++nodes<=POLICY_LIMITS.jsonNodes);space();const c=textValue[i];
  if(c==='"'){string();return;}
  if(c==='{' || c==='['){const object=c==='{',end=object?'}':']',names=new Set();i++;space();if(textValue[i]===end){i++;return;}
   for(;;){if(object){const key=string();need(!names.has(key));names.add(key);space();need(textValue[i++]===':');}value(depth+1);space();if(textValue[i]===end){i++;return;}need(textValue[i++]===',');space();}
  }
  const start=i;while(i<textValue.length && ![',',']','}',' ','\t','\r','\n'].includes(textValue[i]))i++;
  const token=textValue.slice(start,i);need(['true','false','null'].includes(token) || /^(0|[1-9][0-9]*)$/.test(token));
 };
 value(0);space();need(i===textValue.length);return result;
}
function schema(x){
 exact(x,['version','action','invite_id','policy','consumption','session','capacity','clock','request','external']);need(x.version===V+'input-v1');choice(x.action,['redeem','forward','logout']);id(x.invite_id);
 const p=x.policy;exact(p,['version','generation','state','issued_at_ms','expires_at_ms','origins','invites']);need(p.version===V+'metadata-v1');integer(p.generation,1);choice(p.state,['enabled','disabled']);interval(p.issued_at_ms,p.expires_at_ms,POLICY_LIMITS.inviteLifetimeMs);
 need(Array.isArray(p.origins) && p.origins.length>=1 && p.origins.length<=2);for(const origin of p.origins)choice(origin,ORIGINS);unique(p.origins);
 need(Array.isArray(p.invites) && p.invites.length<=POLICY_LIMITS.invites);
 for(const v of p.invites){exact(v,['version','id','code_digest','generation','state','issued_at_ms','expires_at_ms']);need(v.version===V+'invite-v1');id(v.id);digest(v.code_digest);integer(v.generation,1);choice(v.state,['active','revoked','disabled']);interval(v.issued_at_ms,v.expires_at_ms,POLICY_LIMITS.inviteLifetimeMs);}
 unique(p.invites.map(v=>v.id));unique(p.invites.map(v=>v.code_digest));
 const u=x.consumption;exact(u,['version','invite_id','invite_generation','state','revision','expected_revision']);need(u.version===V+'consumption-v1');id(u.invite_id);integer(u.invite_generation,1);choice(u.state,['unused','consumed','uncertain']);integer(u.revision);integer(u.expected_revision);need(u.state!=='consumed' || u.revision>=1);
 const c=x.clock;exact(c,['version','now_ms','mono_ms','previous_ms','previous_mono_ms','certain']);need(c.version===V+'clock-v1');for(const k of ['now_ms','mono_ms','previous_ms','previous_mono_ms'])integer(c[k]);need(typeof c.certain==='boolean');
 const a=x.capacity;exact(a,['version','active_session_ids']);need(a.version===V+'capacity-v1');need(Array.isArray(a.active_session_ids) && a.active_session_ids.length<=POLICY_LIMITS.sessions);for(const v of a.active_session_ids)id(v);unique(a.active_session_ids);
 const r=x.request;exact(r,['version','method','path','origin','credential']);need(r.version===V+'request-v1');text(r.method,POLICY_LIMITS.methodChars);text(r.path,POLICY_LIMITS.pathChars);text(r.origin,POLICY_LIMITS.originChars);credential(r.credential,x.action!=='redeem');
 const e=x.external;exact(e,['version','policy_generation','observed_at_ms','observed_mono_ms','gateway','operator','storage','revocation','release','credential_match']);need(e.version===V+'external-v1');integer(e.policy_generation,1);integer(e.observed_at_ms);integer(e.observed_mono_ms);
 for(const k of ['gateway','operator','storage','revocation'])choice(e[k],['supplied_ok','missing','uncertain']);choice(e.release,['supplied_open','closed','missing','uncertain']);choice(e.credential_match,['supplied_match','mismatch','missing','uncertain']);
 if(x.session!==null){const s=x.session;exact(s,['version','id','token_digest','invite_id','invite_generation','policy_generation','state','created_at_ms','expires_at_ms','created_mono_ms','expires_mono_ms','forwarded_attempts']);need(s.version===V+'session-v1');id(s.id);digest(s.token_digest);id(s.invite_id);integer(s.invite_generation,1);integer(s.policy_generation,1);choice(s.state,['active','revoked','logged_out']);interval(s.created_at_ms,s.expires_at_ms,POLICY_LIMITS.sessionLifetimeMs);interval(s.created_mono_ms,s.expires_mono_ms,POLICY_LIMITS.sessionLifetimeMs);integer(s.forwarded_attempts,0,POLICY_LIMITS.forwards);need(s.expires_at_ms-s.created_at_ms===s.expires_mono_ms-s.created_mono_ms);}
}
function result(decision,reason){return Object.freeze({version:V+'result-v1',decision,reason,external_evidence_verified:false,credential_issued:false,request_executed:false,storage_authenticated:false,durable_atomicity_proven:false});}
const hold=reason=>result('hold',reason),deny=reason=>result('deny',reason);

// Consumes no state. Repeat evaluations can agree: only a future trusted adapter can
// perform real exclusive consumption, authenticate matches or issue a credential.
export function evaluateInvitePolicy(asciiJsonText){
 try {
  const x=parse(asciiJsonText);schema(x);
  const {policy:p,clock:c,external:e,request:r,consumption:u,session:s,capacity:a}=x;
  if(!c.certain)return hold('clock_uncertain');
  if(c.now_ms<c.previous_ms || c.mono_ms<c.previous_mono_ms)return hold('clock_rollback');
  if(Math.abs((c.now_ms-c.previous_ms)-(c.mono_ms-c.previous_mono_ms))>POLICY_LIMITS.clockDivergenceMs)return hold('clock_divergence');
  const gates=[e.gateway,e.operator,e.storage,e.revocation,e.release,e.credential_match];
  if(gates.includes('missing'))return hold('external_missing');
  if(gates.includes('uncertain'))return hold('external_uncertain');
  if(e.release==='closed')return deny('release_closed');
  if(e.credential_match==='mismatch')return deny('credential_mismatch');
  const wallAge=c.now_ms-e.observed_at_ms,monoAge=c.mono_ms-e.observed_mono_ms;
  if(wallAge<0 || monoAge<0 || wallAge>POLICY_LIMITS.evidenceAgeMs || monoAge>POLICY_LIMITS.evidenceAgeMs)return hold('evidence_stale');
  if(e.policy_generation!==p.generation)return hold('evidence_stale');
  if(p.state==='disabled')return deny('policy_disabled');
  if(c.now_ms<p.issued_at_ms || c.now_ms>=p.expires_at_ms)return hold('policy_stale');
  if(!p.origins.includes(r.origin))return deny('origin_mismatch');
  const route={redeem:['POST','/v1/ask-gv/session'],forward:['POST','/v1/ask-gv'],logout:['DELETE','/v1/ask-gv/session']}[x.action];
  if(r.method!==route[0] || r.path!==route[1])return deny('route_mismatch');
  const v=p.invites.find(v=>v.id===x.invite_id);
  if(!v)return deny('invite_missing');
  if(v.state!=='active')return deny('invite_inactive');
  if(c.now_ms<v.issued_at_ms)return deny('invite_not_yet_valid');
  if(c.now_ms>=v.expires_at_ms)return deny('invite_expired');
  if(u.invite_id!==v.id || u.invite_generation!==v.generation)return deny('generation_changed');
  if(u.state==='uncertain')return hold('consumption_uncertain');
  if(u.revision!==u.expected_revision)return hold('consumption_conflict');
  if(x.action==='redeem'){
   if(s!==null)return hold('input_invalid');
   if(u.state==='consumed')return deny('invite_replay');
   if(a.active_session_ids.length>=POLICY_LIMITS.sessions)return deny('capacity_exhausted');
   return result('conditional_allow','eligible_for_atomic_claim');
  }
  if(u.state!=='consumed')return hold('consumption_missing');
  if(s===null || !a.active_session_ids.includes(s.id))return hold('session_missing');
  if(s.invite_id!==v.id || s.invite_generation!==v.generation || s.policy_generation!==p.generation)return deny('generation_changed');
  if(s.state!=='active')return deny('session_inactive');
  // Temporal consistency is not a signature of a real consumed record/session.
  if(s.created_at_ms<v.issued_at_ms || s.expires_at_ms>v.expires_at_ms || s.created_at_ms<p.issued_at_ms)return hold('input_invalid');
  if(c.now_ms<s.created_at_ms || c.mono_ms<s.created_mono_ms)return deny('session_not_yet_valid');
  if(c.now_ms>=s.expires_at_ms || c.mono_ms>=s.expires_mono_ms)return deny('session_expired');
  if(x.action==='forward' && s.forwarded_attempts>=POLICY_LIMITS.forwards)return deny('attempts_exhausted');
  return result('conditional_allow',x.action==='forward'?'eligible_for_single_forward':'eligible_for_local_logout');
 }catch(reason){return hold(typeof reason==='string' && REASONS.has(reason)?reason:'input_invalid');}
}
