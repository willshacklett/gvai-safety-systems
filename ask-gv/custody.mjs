// Linux-only private file custody. No initialization or recovery is performed here.
import fs from 'node:fs';
import path from 'node:path';
const uid = () => process.geteuid();
const fail = () => { throw Error('custody'); };
function same(a,b) { return a.dev===b.dev && a.ino===b.ino; }
export function directory(name, {owner=uid(), mode=0o700, allowSticky=false}={}) {
  if (!path.isAbsolute(name) || path.normalize(name)!==name) fail();
  let current='/';
  for (const part of name.split('/').filter(Boolean)) {
    current=path.join(current,part);
    const s=fs.lstatSync(current);
    if (!s.isDirectory() || s.isSymbolicLink() || (![0,uid()].includes(s.uid) && !(allowSticky && current==='/tmp' && (s.mode&0o1000)))) fail();
    if (s.mode & 0o022) {
      // Only /tmp is allowed as a sticky ancestor for disposable tests, never production.
      if (!(allowSticky && current==='/tmp' && (s.mode & 0o1000))) fail();
    }
  }
  const s=fs.lstatSync(name);
  if (s.uid!==owner || !(Array.isArray(mode)?mode:[mode]).includes(s.mode&0o7777)) fail();
  return s;
}
export function readPrivate(file, {owner=uid(), modes=[0o600], max=4096}={}) {
  const before=fs.lstatSync(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink!==1 || before.uid!==owner || !modes.includes(before.mode&0o7777) || before.size>max) fail();
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try {
    const s=fs.fstatSync(fd);
    if (!same(before,s) || !s.isFile() || s.nlink!==1 || s.size>max) fail();
    const buffer=Buffer.alloc(max+1);const count=fs.readSync(fd,buffer,0,max+1,0);
    if(count>max)fail();
    return {text:new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,count)), stat:s};
  } finally {fs.closeSync(fd);}
}
function syncDirectory(name, io) {const fd=io.openSync(name,'r');try {io.fsyncSync(fd);}finally {io.closeSync(fd);}}
function exact(obj,keys) {return obj && typeof obj==='object' && !Array.isArray(obj) && Object.keys(obj).sort().join()===keys.sort().join();}
export function budgetStore(stateDir, {guardDir, permit, allowSticky=false, io=fs}={}) {
  const stateStat=directory(stateDir,{allowSticky});
  const guardStat=directory(guardDir,{allowSticky});
  if (same(stateStat,guardStat) || stateDir.startsWith(guardDir+'/') || guardDir.startsWith(stateDir+'/')) fail();
  if (!exact(permit,['version','ledger_id','reserved','state_dev','state_ino','permit_id','boot_id']) || permit.version!==1 || typeof permit.ledger_id!=='string' || typeof permit.permit_id!=='string' || permit.boot_id!==fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim() || !/^[a-f0-9]{32}$/.test(permit.ledger_id) || !/^[a-f0-9]{32}$/.test(permit.permit_id) || !Number.isSafeInteger(permit.reserved) || permit.reserved<0 || permit.reserved>100 || permit.state_dev!==stateStat.dev || permit.state_ino!==stateStat.ino) fail();
  const file=path.join(stateDir,'reservations.json'), lock=path.join(stateDir,'process.lock');
  const highWater=path.join(guardDir,'high-water.json');
  const pending=[path.join(stateDir,'reservation.tmp'),path.join(guardDir,'high-water.tmp')];
  let count=permit.reserved, poisoned=false, closed=false;
  const check=()=>{
    if (closed || poisoned || !same(stateStat,directory(stateDir,{allowSticky})) || !same(guardStat,directory(guardDir,{allowSticky}))) fail();
    for(const name of pending){try {fs.lstatSync(name);fail();}catch(error){if(error.code!=='ENOENT')throw error;}}
    for(const name of [file,highWater]) {
      const data=JSON.parse(readPrivate(name,{max:256}).text);
      if(!exact(data,['version','ledger_id','reserved']) || data.version!==1 || data.ledger_id!==permit.ledger_id || data.reserved!==count)fail();
    }
  };
  check();
  const lockFd=fs.openSync(lock,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  const lockStat=fs.fstatSync(lockFd);
  // A failed startup intentionally leaves the lock: uncertainty never auto-recovers.
  fs.writeFileSync(lockFd,permit.permit_id);fs.fsyncSync(lockFd);syncDirectory(stateDir,fs);fs.closeSync(lockFd);
  const consumed=path.join(guardDir,permit.permit_id+'.used');
  const guardFd=fs.openSync(consumed,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try {fs.writeFileSync(guardFd,JSON.stringify({ledger_id:permit.ledger_id,reserved:count}));fs.fsyncSync(guardFd);}finally {fs.closeSync(guardFd);}
  syncDirectory(guardDir,fs);
  const checkLock=()=>{const entry=readPrivate(lock,{max:64});if(!same(lockStat,entry.stat) || entry.text!==permit.permit_id)fail();};
  return {
    peek() {try {check();checkLock();return {reserved:count,remaining:100-count};}catch {poisoned=true;throw Error('budget');}},
    reserve() {
      try {
        check();checkLock();if(count>=100)throw Error('budget');
        const update=(destination,tmp,parent)=>{
          const fd=io.openSync(tmp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
          try {io.writeFileSync(fd,JSON.stringify({version:1,ledger_id:permit.ledger_id,reserved:count+1}));io.fsyncSync(fd);}finally {io.closeSync(fd);}
          io.renameSync(tmp,destination);syncDirectory(parent,io);
        };
        // The independent high-water moves FIRST. Any partial pair stays unavailable.
        update(highWater,pending[1],guardDir);update(file,pending[0],stateDir);count++;
      }catch {poisoned=true;throw Error('budget');}
    },
    close() {try {check();checkLock();fs.unlinkSync(lock);syncDirectory(stateDir,fs);}finally {closed=true;}}
  };
}
export function loadCredentials(env=process.env, {allowSticky=false}={}) {
  // Never import legacy environment secrets into the application.
  if (env.OPENAI_API_KEY || env.ASK_GV_IP_SALT || env.ASK_GV_INGRESS_TOKEN) fail();
  const dir=env.CREDENTIALS_DIRECTORY;
  directory(dir,{mode:[0o500,0o700],allowSticky});
  const read=name=>readPrivate(path.join(dir,name),{modes:[0o400],max:4096}).text.trim();
  const apiKey=read('openai_key'), ipSalt=read('ip_salt'), ingressToken=read('ingress_token');
  if (!/^[\x21-\x7e]{16,256}$/.test(apiKey) || !/^[a-f0-9]{64}$/.test(ipSalt) || !/^[a-f0-9]{64}$/.test(ingressToken) || new Set([apiKey,ipSalt,ingressToken]).size!==3)fail();
  return {apiKey,ipSalt,ingressToken,permit:JSON.parse(read('budget_permit'))};
}
