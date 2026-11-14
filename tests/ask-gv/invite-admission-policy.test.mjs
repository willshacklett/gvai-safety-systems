// Selected pure tests only: no I/O, clock reads, RNG, secrets, services or child APIs.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {evaluateInvitePolicy,POLICY_LIMITS} from '../../ask-gv/invite-admission-policy.mjs';
const V='ask-gv-invite-policy-';
// PUBLIC SYNTHETIC STRINGS ONLY; not actual codes, tokens, hashes or authorizations.
const CODE='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const DUMMY_DIGEST='1111111111111111111111111111111111111111111111111111111111111111';
function fixture(action='redeem'){
 const now=1800000000000,mono=100000;
 return {version:V+'input-v1',action,invite_id:'invite-example',
  policy:{version:V+'metadata-v1',generation:1,state:'enabled',issued_at_ms:now-1000,expires_at_ms:now+3600000,origins:['https://gvaisafety.com'],invites:[{version:V+'invite-v1',id:'invite-example',code_digest:DUMMY_DIGEST,generation:1,state:'active',issued_at_ms:now-1000,expires_at_ms:now+3600000}]},
  consumption:{version:V+'consumption-v1',invite_id:'invite-example',invite_generation:1,state:action==='redeem'?'unused':'consumed',revision:1,expected_revision:1},
  session:action==='redeem'?null:{version:V+'session-v1',id:'session-example',token_digest:'2'.repeat(64),invite_id:'invite-example',invite_generation:1,policy_generation:1,state:'active',created_at_ms:now-1000,expires_at_ms:now+899000,created_mono_ms:mono-1000,expires_mono_ms:mono+899000,forwarded_attempts:0},
  capacity:{version:V+'capacity-v1',active_session_ids:action==='redeem'?[]:['session-example']},
  clock:{version:V+'clock-v1',now_ms:now,mono_ms:mono,previous_ms:now-100,previous_mono_ms:mono-100,certain:true},
  request:{version:V+'request-v1',method:action==='logout'?'DELETE':'POST',path:action==='forward'?'/v1/ask-gv':'/v1/ask-gv/session',origin:'https://gvaisafety.com',credential:action==='redeem'?CODE:'Bearer '+CODE},
  external:{version:V+'external-v1',policy_generation:1,observed_at_ms:now,observed_mono_ms:mono,gateway:'supplied_ok',operator:'supplied_ok',storage:'supplied_ok',revocation:'supplied_ok',release:'supplied_open',credential_match:'supplied_match'}};
}
const run=x=>evaluateInvitePolicy(JSON.stringify(x));
function expect(x,decision,reason){const r=typeof x==='string'?evaluateInvitePolicy(x):run(x);assert.equal(r.decision,decision);assert.equal(r.reason,reason);assert.deepEqual(Object.keys(r).sort(),['version','decision','reason','external_evidence_verified','credential_issued','request_executed','storage_authenticated','durable_atomicity_proven'].sort());for(const k of ['external_evidence_verified','credential_issued','request_executed','storage_authenticated','durable_atomicity_proven'])assert.equal(r[k],false);assert.equal(r.version,V+'result-v1');assert.equal(Object.isFrozen(r),true);return r;}
const mutate=(action,fn)=>{const x=fixture(action);fn(x);return x;};

test('candidate constants are frozen and not operational approval',()=>{
 assert.equal(Object.isFrozen(POLICY_LIMITS),true);assert.equal(POLICY_LIMITS.invites,32);assert.equal(POLICY_LIMITS.inviteLifetimeMs,24*60*60*1000);assert.equal(POLICY_LIMITS.sessionLifetimeMs,15*60*1000);assert.equal(POLICY_LIMITS.forwards,5);
});
test('three conditional decisions are nonexecuting and externally unverified',()=>{
 for(const [action,reason]of [['redeem','eligible_for_atomic_claim'],['forward','eligible_for_single_forward'],['logout','eligible_for_local_logout']])expect(fixture(action),'conditional_allow',reason);
});
test('pure input remains unchanged and repeated evaluation is deterministic',()=>{
 const x=fixture(),text=JSON.stringify(x),first=evaluateInvitePolicy(text);assert.deepEqual(evaluateInvitePolicy(text),first);assert.equal(JSON.stringify(x),text);
});
test('text-only boundary never reads object getters or serializes private objects',()=>{
 const x={get secret(){throw Error('PRIVATE-NEVER-READ');}};for(const value of [x,null,undefined,42,()=>{}]){const r=evaluateInvitePolicy(value);assert.equal(r.decision,'hold');assert.equal(r.reason,'input_invalid');}
});
test('every record has exact versioned keys; unknown and missing fields HOLD',()=>{
 const select=[x=>x,x=>x.policy,x=>x.policy.invites[0],x=>x.consumption,x=>x.session,x=>x.capacity,x=>x.clock,x=>x.request,x=>x.external];
 for(const pick of select){expect(mutate('forward',x=>{pick(x).extra='PRIVATE';}),'hold','input_invalid');expect(mutate('forward',x=>{delete pick(x).version;}),'hold','input_invalid');expect(mutate('forward',x=>{pick(x).version='v2';}),'hold','input_invalid');}
});
test('malformed grammar, noncanonical integer encodings and nonfinite values HOLD',()=>{
 for(const value of ['', 'null','[]','{','{"x":NaN}', JSON.stringify(fixture()).replace('1800000000000','1.8e12'),JSON.stringify(fixture()).replace('1800000000000','1800000000000.0'),JSON.stringify(fixture()).replace('"revision":1','"revision":-0'),JSON.stringify(fixture()).replace('"revision":1','"revision":9007199254740992')])expect(value,'hold','input_invalid');
});
test('duplicate decoded JSON members rejected before parsed value can conceal denial',()=>{
 const x=JSON.stringify(fixture());
 for(const value of [x.replace('"state":"enabled"','"state":"disabled","state":"enabled"'),x.replace('"state":"unused"','"state":"consumed","state":"unused"'),x.replace('"generation":1','"generation":2,"\\u0067eneration":1'),x.replace('"version":','"version":"ignored","version":')])expect(value,'hold','input_invalid');
 const forward=JSON.stringify(fixture('forward'));expect(forward.replace('"forwarded_attempts":0','"forwarded_attempts":5,"forwarded_attempts":0'),'hold','input_invalid');
});
test('bounded JSON transport, nesting, node count and ASCII reject excess',()=>{
 expect(' '.repeat(POLICY_LIMITS.jsonBytes+1),'hold','input_invalid');expect('['.repeat(10)+'0'+']'.repeat(10),'hold','input_invalid');expect(JSON.stringify(Array(2100).fill(0)),'hold','input_invalid');expect('{"private":"é"}','hold','input_invalid');
});
test('numeric fields reject strings, negatives, fractions and booleans',()=>{
 for(const bad of ['1',-1,0.5,true,null])expect(mutate('forward',x=>{x.clock.now_ms=bad;}),'hold','input_invalid');
 for(const bad of [0,-1,1.5])expect(mutate('redeem',x=>{x.policy.generation=bad;}),'hold','input_invalid');
});
test('candidate record limits reject ambiguous IDs, hashes, origins and sessions',()=>{
 for(const fn of [x=>x.policy.invites.push({...x.policy.invites[0]}),x=>x.policy.invites.push({...x.policy.invites[0],id:'other-example'}),x=>x.policy.origins.push(x.policy.origins[0]),x=>x.capacity.active_session_ids.push('session-example')])expect(mutate('forward',fn),'hold','policy_ambiguous');
 for(const fn of [x=>x.policy.invites[0].id='Upper',x=>x.policy.invites[0].code_digest='A'.repeat(64),x=>x.policy.invites[0].id='x'.repeat(65),x=>x.session.token_digest='not-a-hash'])expect(mutate('forward',fn),'hold','input_invalid');
});
test('32 invitation records accepted but 33 or zero-time lifetimes HOLD',()=>{
 const x=fixture();x.policy.invites=Array.from({length:32},(_,i)=>({...x.policy.invites[0],id:i===0?'invite-example':'invite-'+i,code_digest:i.toString(16).padStart(64,'0')}));expect(x,'conditional_allow','eligible_for_atomic_claim');x.policy.invites.push({...x.policy.invites[0],id:'overflow'});expect(x,'hold','input_invalid');
 expect(mutate('redeem',x=>{x.policy.invites[0].expires_at_ms=x.policy.invites[0].issued_at_ms;}),'hold','input_invalid');
});
test('24-hour invitation and policy durations are exact inclusive maxima',()=>{
 const x=fixture();for(const v of [x.policy,x.policy.invites[0]])v.expires_at_ms=v.issued_at_ms+POLICY_LIMITS.inviteLifetimeMs;expect(x,'conditional_allow','eligible_for_atomic_claim');x.policy.invites[0].expires_at_ms++;expect(x,'hold','input_invalid');
 expect(mutate('redeem',x=>{x.policy.expires_at_ms=x.policy.issued_at_ms+POLICY_LIMITS.inviteLifetimeMs+1;}),'hold','input_invalid');
});
test('invite starts inclusive and expires exclusive at exact UTC millisecond',()=>{
 const x=fixture();x.policy.invites[0].issued_at_ms=x.clock.now_ms;expect(x,'conditional_allow','eligible_for_atomic_claim');x.policy.invites[0].issued_at_ms++;expect(x,'deny','invite_not_yet_valid');
 x.policy.invites[0].issued_at_ms=x.clock.now_ms-1000;x.policy.invites[0].expires_at_ms=x.clock.now_ms;expect(x,'deny','invite_expired');x.policy.invites[0].expires_at_ms++;expect(x,'conditional_allow','eligible_for_atomic_claim');
});
test('policy expiry/future is stale evidence HOLD; disabled is deny',()=>{
 expect(mutate('redeem',x=>{x.policy.expires_at_ms=x.clock.now_ms;}),'hold','policy_stale');expect(mutate('redeem',x=>{x.policy.issued_at_ms=x.clock.now_ms+1;}),'hold','policy_stale');expect(mutate('redeem',x=>{x.policy.state='disabled';}),'deny','policy_disabled');
});
test('clock uncertainty, UTC rollback and monotonic rollback HOLD',()=>{
 expect(mutate('redeem',x=>{x.clock.certain=false;}),'hold','clock_uncertain');expect(mutate('redeem',x=>{x.clock.previous_ms=x.clock.now_ms+1;}),'hold','clock_rollback');expect(mutate('redeem',x=>{x.clock.previous_mono_ms=x.clock.mono_ms+1;}),'hold','clock_rollback');
});
test('clock drift threshold bounded at exactly 1000ms, not a health attestation',()=>{
 const x=fixture();x.clock.previous_ms=x.clock.now_ms-1100;expect(x,'conditional_allow','eligible_for_atomic_claim');x.clock.previous_ms--;expect(x,'hold','clock_divergence');
});
test('external freshness has inclusive 1000ms age and rejects future/stale data',()=>{
 const x=fixture();x.external.observed_at_ms-=1000;x.external.observed_mono_ms-=1000;expect(x,'conditional_allow','eligible_for_atomic_claim');x.external.observed_at_ms--;expect(x,'hold','evidence_stale');
 for(const field of ['observed_at_ms','observed_mono_ms'])expect(mutate('redeem',x=>{x.external[field]++;}),'hold','evidence_stale');expect(mutate('redeem',x=>{x.external.policy_generation++;}),'hold','evidence_stale');
});
test('missing/uncertain gateway/operator/storage/revocation/release/match never bypassed',()=>{
 for(const field of ['gateway','operator','storage','revocation','release','credential_match'])for(const state of ['missing','uncertain'])expect(mutate('redeem',x=>{x.external[field]=state;}),'hold',state==='missing'?'external_missing':'external_uncertain');
 expect(mutate('redeem',x=>{x.external.release='closed';}),'deny','release_closed');expect(mutate('redeem',x=>{x.external.credential_match='mismatch';}),'deny','credential_mismatch');
});
test('origins are exact existing public page origins, not backend approval',()=>{
 for(const origin of ['', 'https://gvaisafety.com/','https://gvaisafety.com:443','http://gvaisafety.com','null','https://www.gvaisafety.com'])expect(mutate('redeem',x=>{x.request.origin=origin;}),'deny','origin_mismatch');
 const x=fixture();x.policy.origins.push('https://www.gvaisafety.com');x.request.origin='https://www.gvaisafety.com';expect(x,'conditional_allow','eligible_for_atomic_claim');
 expect(mutate('redeem',x=>{x.policy.origins=['https://gvaisafety.com/'];}),'hold','input_invalid');
});
test('exact action-method-route mapping rejects queries, normalization and preflight',()=>{
 for(const fn of [x=>x.request.method='GET',x=>x.request.method='OPTIONS',x=>x.request.method='post',x=>x.request.path+='?x=1',x=>x.request.path+='/',x=>x.request.path='/v1/evaluations'])expect(mutate('redeem',fn),'deny','route_mismatch');
 expect(mutate('forward',x=>{x.request.method='DELETE';}),'deny','route_mismatch');
});
test('credential and bearer encoding canonical: no padding, aliases, whitespace or extra headers',()=>{
 for(const token of ['',CODE+'=',CODE.slice(1),CODE+'A','A'.repeat(42)+'B','+'.repeat(43),'/'.repeat(43),' '+CODE,CODE+'\n'])expect(mutate('redeem',x=>{x.request.credential=token;}),'hold','input_invalid');
 for(const value of [CODE,'bearer '+CODE,'Bearer  '+CODE,'Bearer\t'+CODE,'Bearer '+CODE+', Bearer '+CODE,'Bearer '+CODE+'\r\nX: y',['Bearer '+CODE]])expect(mutate('forward',x=>{x.request.credential=value;}),'hold','input_invalid');
});
test('no hashing/constant-time authentication claimed from a supplied match flag',()=>{
 const x=fixture();x.request.credential='E'.repeat(42)+'A';expect(x,'conditional_allow','eligible_for_atomic_claim');
 // Same syntactic code with a mismatch report must deny; the pure module has no
 // cryptographic proof that either supplied assertion is truthful.
 x.external.credential_match='mismatch';expect(x,'deny','credential_mismatch');
});
test('missing/inactive invitation denied; all consumption identities/generations correlate',()=>{
 expect(mutate('redeem',x=>{x.policy.invites=[];}),'deny','invite_missing');for(const state of ['disabled','revoked'])expect(mutate('redeem',x=>{x.policy.invites[0].state=state;}),'deny','invite_inactive');
 for(const fn of [x=>x.consumption.invite_id='other',x=>x.consumption.invite_generation++,x=>x.policy.invites[0].generation++])expect(mutate('redeem',fn),'deny','generation_changed');
});
test('consumed invitation is replay denial; uncertain/conflicting revision HOLD',()=>{
 expect(mutate('redeem',x=>{x.consumption.state='consumed';}),'deny','invite_replay');expect(mutate('redeem',x=>{x.consumption.state='uncertain';}),'hold','consumption_uncertain');expect(mutate('redeem',x=>{x.consumption.expected_revision++;}),'hold','consumption_conflict');
});
test('simulated concurrency explicitly cannot prove exclusive or durable redemption',()=>{
 const unused=fixture(),snapshot=JSON.stringify(unused);expect(snapshot,'conditional_allow','eligible_for_atomic_claim');expect(snapshot,'conditional_allow','eligible_for_atomic_claim');
 const consumed=structuredClone(unused);consumed.consumption.state='consumed';consumed.consumption.revision++;consumed.consumption.expected_revision++;expect(consumed,'deny','invite_replay');
 const stale=structuredClone(unused);stale.consumption.revision++;expect(stale,'hold','consumption_conflict');assert.equal(unused.consumption.state,'unused');
});
test('32 live sessions exhaust new capacity; 31 permits only claim eligibility',()=>{
 const x=fixture();x.capacity.active_session_ids=Array.from({length:31},(_,i)=>'session-'+i);expect(x,'conditional_allow','eligible_for_atomic_claim');x.capacity.active_session_ids.push('session-last');expect(x,'deny','capacity_exhausted');x.capacity.active_session_ids.push('overflow');expect(x,'hold','input_invalid');
});
test('forward/logout require supplied consumed record and existing live session',()=>{
 expect(mutate('forward',x=>{x.consumption.state='unused';}),'hold','consumption_missing');expect(mutate('forward',x=>{x.consumption.revision=0;x.consumption.expected_revision=0;}),'hold','input_invalid');expect(mutate('forward',x=>{x.session=null;}),'hold','session_missing');expect(mutate('forward',x=>{x.capacity.active_session_ids=[];}),'hold','session_missing');
 for(const state of ['revoked','logged_out'])expect(mutate('forward',x=>{x.session.state=state;}),'deny','session_inactive');
 expect(mutate('redeem',x=>{x.session=fixture('forward').session;}),'hold','input_invalid');
});
test('session must match invite and policy generations',()=>{
 for(const fn of [x=>x.session.invite_id='other',x=>x.session.invite_generation++,x=>x.session.policy_generation++])expect(mutate('forward',fn),'deny','generation_changed');
});
test('15min session max, equal dual-clock durations, invite-bound lifetime',()=>{
 const x=fixture('forward');expect(x,'conditional_allow','eligible_for_single_forward');x.session.expires_at_ms++;x.session.expires_mono_ms++;expect(x,'hold','input_invalid');
 expect(mutate('forward',x=>{x.session.expires_mono_ms--;}),'hold','input_invalid');expect(mutate('forward',x=>{x.policy.invites[0].expires_at_ms=x.clock.now_ms+1;}),'hold','input_invalid');expect(mutate('forward',x=>{x.session.created_at_ms=x.policy.invites[0].issued_at_ms-1;x.session.expires_at_ms--;}),'hold','input_invalid');
});
test('session exact expiry on either clock denies; starts inclusive',()=>{
 const x=fixture('forward');x.session.expires_at_ms=x.clock.now_ms;x.session.expires_mono_ms=x.clock.mono_ms;expect(x,'deny','session_expired');x.session.expires_at_ms++;x.session.expires_mono_ms++;expect(x,'conditional_allow','eligible_for_single_forward');
 const y=fixture('forward');y.session.created_at_ms=y.clock.now_ms;y.session.created_mono_ms=y.clock.mono_ms;y.session.expires_at_ms=y.clock.now_ms+1000;y.session.expires_mono_ms=y.clock.mono_ms+1000;expect(y,'conditional_allow','eligible_for_single_forward');y.session.created_mono_ms++;y.session.expires_mono_ms++;expect(y,'deny','session_not_yet_valid');
 const z=fixture('forward');z.session.expires_mono_ms=z.clock.mono_ms;z.session.created_mono_ms=z.clock.mono_ms-(z.session.expires_at_ms-z.session.created_at_ms);expect(z,'hold','input_invalid');
 // A valid interval can expire monotonically while UTC still looks usable.
 const m=fixture('forward');m.session.created_mono_ms=0;m.session.expires_mono_ms=900000;m.clock.mono_ms=900000;m.clock.previous_mono_ms=899900;m.external.observed_mono_ms=900000;expect(m,'deny','session_expired');
});
test('forward limit denies at5 but local logout may still be recommended',()=>{
 for(const n of [0,4])expect(mutate('forward',x=>{x.session.forwarded_attempts=n;}),'conditional_allow','eligible_for_single_forward');expect(mutate('forward',x=>{x.session.forwarded_attempts=5;}),'deny','attempts_exhausted');expect(mutate('forward',x=>{x.session.forwarded_attempts=6;}),'hold','input_invalid');expect(mutate('logout',x=>{x.session.forwarded_attempts=5;}),'conditional_allow','eligible_for_local_logout');
});
test('redacted results/errors never echo codes, bearers, hashes, IDs or private fields',()=>{
 for(const action of ['redeem','forward','logout']){
  const x=fixture(action);for(const changed of [x,mutate(action,y=>{y.request.extra='PRIVATE-ERROR-CANARY';}),mutate(action,y=>{y.external.gateway='missing';})]){const r=run(changed),serialized=JSON.stringify(r);for(const privateValue of [CODE,DUMMY_DIGEST,'2'.repeat(64),'invite-example','session-example','PRIVATE-ERROR-CANARY'])assert.equal(serialized.includes(privateValue),false);}
 }
});
