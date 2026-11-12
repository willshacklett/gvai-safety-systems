/* Ask GV UI. MIT fetch helper provenance: docs/ask_gv_v1.md. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const form=byId('ask-form'), input=byId('ask-question'), send=byId('ask-send');
  const status=byId('ask-status'), log=byId('ask-log'), summary=byId('ask-summary');
  const endpoint=window.ASK_GV_ENDPOINT;
  let configured=false;
  try {const url=new URL(endpoint);configured=url.protocol==='https:' && !url.username && !url.password && !url.search && !url.hash && url.pathname==='/v1/ask-gv';} catch {}
  let history=[], facts=new Map(), controller=null, epoch=0;
  const notice=text=>{status.textContent=text;};
  function message(role,text) {
    const article=document.createElement('article');article.className='ask-message';
    const heading=document.createElement('h3');heading.textContent=role==='user'?'You':'Ask GV';
    const p=document.createElement('p');p.textContent=text;
    article.append(heading,p);log.append(article);return article;
  }
  async function copy(text) {
    try {await navigator.clipboard.writeText(text);notice('Copied. Paste wherever you choose.');}
    catch {summary.hidden=false;summary.value=text;summary.focus();summary.select();notice('Select and copy the text below.');}
  }
  byId('ask-reset').addEventListener('click',()=>{
    epoch++;controller?.abort();controller=null;history=[];facts.clear();log.replaceChildren();summary.value='';summary.hidden=true;log.setAttribute('aria-busy','false');
    send.disabled=!configured;input.disabled=!configured;notice(configured?'Conversation cleared.':'Ask GV is unavailable until secure backend hosting is configured.');
    if(configured) input.focus();
  });
  for(const button of document.querySelectorAll('[data-ask]')) button.addEventListener('click',()=>{
    input.value=button.dataset.ask;if(configured) input.focus();
  });
  byId('ask-export').addEventListener('click',()=>{
    summary.hidden=false;summary.value='GVAI approved factual summary — AI-selected excerpts, verify with sources.\n'+[...facts.values()].join('\n\n');
    if(!facts.size) summary.value='No approved answers yet. Visit https://gvaisafety.com/#documentation for published research and https://gvaisafety.com/#contact for verification.';
    summary.focus();summary.select();notice('Review this factual summary, then copy and paste it into ChatGPT. Nothing is sent automatically.');
  });
  byId('ask-copy-summary').addEventListener('click',()=>copy(summary.value || 'No approved answers yet.'));
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(!configured || controller || !input.value.trim()) return;
    const question=input.value.trim();if(question.length>1600) return notice('Please use 1,600 characters or fewer.');
    const generation=epoch;controller=new AbortController();send.disabled=true;
    message('user',question);input.value='';notice('Finding approved GVAI facts…');log.setAttribute('aria-busy','true');
    try {
      const response=await window.GVAI.fetchJSON(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'omit',referrerPolicy:'no-referrer',timeoutMs:20000,maxBytes:16384,signal:controller.signal,body:JSON.stringify({message:question,history:history.slice(-4)})});
      const data=await response.json();if(generation!==epoch)return;
      if(typeof data.answer!=='string' || data.answer.length>6000 || typeof data.version!=='string' || !/^\d{4}-\d{2}-\d{2}\.v\d{1,3}$/.test(data.version) || !Array.isArray(data.sources) || data.sources.length>3)throw Error();
      for(const source of data.sources) {
        if(!source || typeof source.id!=='string' || !/^[a-z]{1,32}$/.test(source.id || '') || typeof source.title!=='string' || source.title.length>128 || !source.title.trim() || typeof source.url!=='string' || source.url.length>512)throw Error();
        const url=new URL(source.url);
        if(url.protocol!=='https:' || !(url.hostname==='gvaisafety.com' || (url.hostname==='github.com' && url.pathname.startsWith('/willshacklett/gvai-safety-systems/'))) || url.port || url.username || url.password)throw Error();
      }
      if(new Set(data.sources.map(s=>s.id)).size!==data.sources.length)throw Error();
      const article=message('assistant',data.answer);
      for(const source of data.sources) {const a=document.createElement('a');a.href=source.url;a.textContent=source.title;a.target='_blank';a.rel='noopener noreferrer';article.append(a);}
      const version=document.createElement('small');version.textContent='Fact set '+data.version;article.append(version);
      const button=document.createElement('button');button.type='button';button.textContent='Copy answer';button.addEventListener('click',()=>copy(data.answer+'\n'+data.sources.map(s=>s.url).join('\n')));article.append(button);
      if(data.sources.length) {
        const key=data.sources.map(s=>s.id).sort().join('|');
        facts.set(key,`${data.answer}\nFact set ${data.version}\n${data.sources.map(s=>s.url).join('\n')}`);
        if(facts.size>12)facts.delete(facts.keys().next().value);
      }
      history=[...history,{role:'user',content:question.slice(0,800)},{role:'assistant',content:data.answer.slice(0,800)}].slice(-4);
      notice('Answer ready. AI-generated selection may be inaccurate; check the sources.');
    } catch(error) {if(generation===epoch)notice(error.status===429?'Too many requests. Please wait a minute and try again.':'Ask GV is temporarily unavailable. Please use the documentation or contact GVAI.');}
    finally {if(generation===epoch){controller=null;send.disabled=false;log.setAttribute('aria-busy','false');}}
  });
  input.disabled=!configured;send.disabled=!configured;
  notice(configured?'Ready for questions about approved GVAI facts.':'Ask GV is unavailable until secure backend hosting is configured.');
})();
