import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import {budgetStore,loadCredentials,directory,readPrivate} from '../../ask-gv/custody.mjs';
function fixture(t,n=0) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ask-custody-'));
  const state=path.join(root,'state'),guard=path.join(root,'guard'),creds=path.join(root,'creds');
  for(const p of [state,guard,creds])fs.mkdirSync(p,{mode:0o700});
  const ledger_id=randomBytes(16).toString('hex');const file=path.join(state,'reservations.json');
  const initial={version:1,ledger_id,reserved:n};fs.writeFileSync(file,JSON.stringify(initial),{mode:0o600});fs.writeFileSync(path.join(guard,'high-water.json'),JSON.stringify(initial),{mode:0o600});
  const permit=()=>({version:1,ledger_id,reserved:JSON.parse(fs.readFileSync(file)).reserved,state_dev:fs.statSync(state).dev,state_ino:fs.statSync(state).ino,permit_id:randomBytes(16).toString('hex'),boot_id:fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim()});
  const open=(p=permit(),io)=>budgetStore(state,{guardDir:guard,permit:p,allowSticky:true,io});
  const write=(name,value)=>fs.writeFileSync(path.join(creds,name),value,{mode:0o400});
  write('openai_key','FAKE-test-only-provider-credential');write('ip_salt','a'.repeat(64));write('ingress_token','b'.repeat(64));write('budget_permit',JSON.stringify(permit()));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return {root,state,guard,creds,file,permit,open,initial,write};
}
test('one-use boot-bound custody, durable finite reservations and reviewed restart',t=>{
 const f=fixture(t,98),p=f.permit();let store=f.open(p);store.reserve();assert.equal(store.peek().remaining,1);assert.throws(()=>f.open());store.close();
 assert.throws(()=>f.open({...p,reserved:99})); // consumed permit fails closed and leaves lock
 fs.unlinkSync(path.join(f.state,'process.lock')); // synthetic operator recovery, never production automatic cleanup
 store=f.open();store.reserve();assert.equal(store.peek().remaining,0);assert.throws(()=>store.reserve());assert.throws(()=>store.close());
 assert.equal(JSON.parse(fs.readFileSync(f.file)).reserved,100);
});
test('live rollback, external count changes and missing state poison custody',t=>{
 for(const kind of ['rollback','missing','malformed']){
  const f=fixture(t);const store=f.open();store.reserve();
  if(kind==='rollback')fs.writeFileSync(f.file,JSON.stringify(f.initial));
  if(kind==='missing')fs.unlinkSync(f.file);
  if(kind==='malformed')fs.writeFileSync(f.file,'{');
  assert.throws(()=>store.peek());assert.throws(()=>store.reserve());assert.throws(()=>store.close());
 }
});
test('startup rejects symlinks, hardlinks, modes, owners, nonregular and oversized state',t=>{
 for(const kind of ['symlink','hardlink','mode','special','fifo','directory','oversize','owner','parent','guard']){
  const f=fixture(t);
  if(kind==='symlink'){fs.renameSync(f.file,f.file+'.real');fs.symlinkSync(f.file+'.real',f.file);}
  if(kind==='hardlink')fs.linkSync(f.file,f.file+'.link');
  if(kind==='mode')fs.chmodSync(f.file,0o644);
  if(kind==='special')fs.chmodSync(f.file,0o4600);
  if(kind==='fifo'){fs.unlinkSync(f.file);execFileSync('mkfifo',[f.file]);}
  if(kind==='directory'){fs.unlinkSync(f.file);fs.mkdirSync(f.file);}
  if(kind==='oversize')fs.writeFileSync(f.file,'x'.repeat(257));
  if(kind==='owner'){assert.throws(()=>readPrivate(f.file,{owner:process.geteuid()+1}));continue;}
  if(kind==='parent')fs.chmodSync(f.root,0o777);
  if(kind==='guard')fs.chmodSync(f.guard,0o755);
  const permit={version:1,ledger_id:f.initial.ledger_id,reserved:0,state_dev:fs.statSync(f.state).dev,state_ino:fs.statSync(f.state).ino,permit_id:'f'.repeat(32),boot_id:fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim()};
  assert.throws(()=>f.open(permit));
 }
});
test('owner-attested high-water, state identity and boot mismatch fail at startup',t=>{
 for(const field of ['reserved','state_ino','ledger_id','boot_id']){
  const f=fixture(t),p=f.permit();p[field]=typeof p[field]==='number'?p[field]+1:'0'.repeat(field==='boot_id'?36:32);
  assert.throws(()=>f.open(p));
 }
 const f=fixture(t);assert.throws(()=>budgetStore(f.state,{guardDir:f.state,permit:f.permit(),allowSticky:true}));
 assert.throws(()=>directory(f.state)); // production never accepts sticky /tmp ancestors
});
test('write/fsync/rename failures poison state and cannot be retried',t=>{
 for(const method of ['openSync','writeFileSync','fsyncSync','renameSync']){
  const f=fixture(t);const io={...fs,[method](){throw Error('FAKE-sensitive-IO-error');}};
  const store=f.open(undefined,io);assert.throws(()=>store.reserve(),/^Error: budget$/);assert.throws(()=>store.reserve());assert.throws(()=>store.peek());assert.throws(()=>store.close());
 }
});
test('systemd credential files load in-process; no environment-secret fallback',t=>{
 const f=fixture(t);const env={CREDENTIALS_DIRECTORY:f.creds};
 const c=loadCredentials(env,{allowSticky:true});assert.equal(c.apiKey,'FAKE-test-only-provider-credential');
 assert.equal(Object.hasOwn(c,'OPENAI_API_KEY'),false);
 for(const name of ['OPENAI_API_KEY','ASK_GV_IP_SALT','ASK_GV_INGRESS_TOKEN'])assert.throws(()=>loadCredentials({...env,[name]:'FAKE-not-allowed'},{allowSticky:true}));
 fs.chmodSync(path.join(f.creds,'openai_key'),0o644);assert.throws(()=>loadCredentials(env,{allowSticky:true}));
 fs.chmodSync(path.join(f.creds,'openai_key'),0o400);fs.unlinkSync(path.join(f.creds,'openai_key'));fs.symlinkSync(path.join(f.creds,'ip_salt'),path.join(f.creds,'openai_key'));assert.throws(()=>loadCredentials(env,{allowSticky:true}));
});
test('forced process crash leaves lock and consumed permit; startup cannot recover automatically',async t=>{
 const f=fixture(t);const p=f.permit();
 const code=`import {budgetStore} from ${JSON.stringify(new URL('../../ask-gv/custody.mjs',import.meta.url).href)};const s=budgetStore(${JSON.stringify(f.state)},{guardDir:${JSON.stringify(f.guard)},permit:${JSON.stringify(p)},allowSticky:true});s.reserve();process.stdout.write('reserved\\n');setInterval(()=>{},1000);`;
 const child=spawn(process.execPath,['--input-type=module','-e',code],{stdio:['ignore','pipe','pipe']});
 await new Promise((resolve,reject)=>{child.stdout.once('data',resolve);child.once('exit',code=>reject(Error('child exit '+code)));});
 child.kill('SIGKILL');await new Promise(r=>child.once('exit',r));
 assert.equal(JSON.parse(fs.readFileSync(f.file)).reserved,1);assert.throws(()=>f.open());assert.ok(fs.existsSync(path.join(f.state,'process.lock')));
});
test('real CLI credential-file startup, provider-free readiness, disable marker and clean shutdown',async t=>{
 // Private test directory under the user's secure home, never under a permissive ancestor.
 const root=fs.mkdtempSync(path.join(os.homedir(),'.ask-gv-startup-test-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const state=path.join(root,'state'),guard=path.join(root,'guard'),creds=path.join(root,'credentials');
 for(const p of [state,guard,creds])fs.mkdirSync(p,{mode:0o700});
 const id='d'.repeat(32);for(const file of [path.join(state,'reservations.json'),path.join(guard,'high-water.json')])fs.writeFileSync(file,JSON.stringify({version:1,ledger_id:id,reserved:0}),{mode:0o600});
 const permit={version:1,ledger_id:id,reserved:0,state_dev:fs.statSync(state).dev,state_ino:fs.statSync(state).ino,permit_id:'e'.repeat(32),boot_id:fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim()};
 for(const [name,value]of Object.entries({openai_key:'FAKE-cli-key-must-never-leak',ip_salt:'a'.repeat(64),ingress_token:'b'.repeat(64),budget_permit:JSON.stringify(permit)}))fs.writeFileSync(path.join(creds,name),value,{mode:0o400});
 const http=await import('node:http');const port=await new Promise(r=>{const s=http.createServer();s.listen(0,'127.0.0.1',()=>{const n=s.address().port;s.close(()=>r(n));});});
 const marker=path.join(root,'disabled');fs.writeFileSync(marker,'disabled',{mode:0o600});
 const child=spawn(process.execPath,['--import','./tests/ask-gv/no-provider.mjs','ask-gv/server.mjs'],{env:{PATH:process.env.PATH,CREDENTIALS_DIRECTORY:creds,PORT:String(port),ASK_GV_ENABLED:'1',ASK_GV_TRUSTED_INGRESS:'loopback-token-v1',OPENAI_MODEL:'test-model',ASK_GV_STATE_DIR:state,ASK_GV_GUARD_DIR:guard,ASK_GV_DISABLE_FILE:marker},stdio:['ignore','pipe','pipe']});
 t.after(()=>child.kill('SIGKILL'));let out='';child.stdout.on('data',d=>out+=d);child.stderr.on('data',d=>out+=d);
 const httpGet=route=>new Promise((resolve,reject)=>http.get({host:'127.0.0.1',port,path:route,headers:{'X-Ask-GV-Ingress':'b'.repeat(64)}},res=>{let data='';res.on('data',d=>data+=d);res.on('end',()=>resolve({status:res.statusCode,data:JSON.parse(data)}));}).on('error',reject));
 let response;for(let i=0;i<100;i++){try{response=await httpGet('/readyz');break;}catch{await new Promise(r=>setTimeout(r,10));}}
 assert.equal(response?.status,503);assert.equal(response.data.disabled,true);
 fs.unlinkSync(marker);const ready=await httpGet('/readyz');assert.equal(ready.data.configured,true);
 // Corpus expiration is a safe, time-dependent readiness condition; never extend it in a test.
 assert.equal(ready.data.remaining,100);assert.equal(ready.data.counters.success,0);
 child.kill('SIGTERM');assert.equal(await new Promise(r=>child.once('exit',r)),0);assert.equal(out,'');
 assert.equal(fs.existsSync(path.join(state,'process.lock')),false);assert.equal(fs.existsSync(path.join(guard,permit.permit_id+'.used')),true);
 assert.equal(JSON.parse(fs.readFileSync(path.join(state,'reservations.json'))).reserved,0);
});

test('directory fsync failure after rename remains uncertain and leaves custody locked',t=>{
 const f=fixture(t);let syncs=0;const io={...fs,fsyncSync(fd){if(++syncs===2)throw Error('directory-sync-failure');return fs.fsyncSync(fd);}};
 const store=f.open(undefined,io);assert.throws(()=>store.reserve());assert.equal(JSON.parse(fs.readFileSync(path.join(f.guard,'high-water.json'))).reserved,1);assert.equal(JSON.parse(fs.readFileSync(f.file)).reserved,0);
 assert.throws(()=>store.peek());assert.throws(()=>store.close());assert.throws(()=>f.open());
});

test('independent high-water rejects a restored lower ledger even with a fresh lower permit',t=>{
 const f=fixture(t);const store=f.open();store.reserve();store.close();fs.writeFileSync(f.file,JSON.stringify(f.initial));
 assert.throws(()=>f.open());assert.equal(JSON.parse(fs.readFileSync(path.join(f.guard,'high-water.json'))).reserved,1);
});
test('leftover reservation files or missing guard high-water deny startup',t=>{
 for(const kind of ['missing','state-temp','guard-temp']){
 const f=fixture(t);if(kind==='missing')fs.unlinkSync(path.join(f.guard,'high-water.json'));
 if(kind==='state-temp')fs.writeFileSync(path.join(f.state,'reservation.tmp'),'uncertain',{mode:0o600});
 if(kind==='guard-temp')fs.writeFileSync(path.join(f.guard,'high-water.tmp'),'uncertain',{mode:0o600});
 assert.throws(()=>f.open());
 }
});
