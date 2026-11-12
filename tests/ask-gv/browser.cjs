// npm ci --ignore-scripts; npx --no-install playwright install chromium
// NODE_PATH=/tmp/ask-gv-browser/node_modules PLAYWRIGHT_BROWSERS_PATH=/tmp/ask-gv-browser/browsers node tests/ask-gv/browser.cjs
const { chromium } = require('playwright');
const { default:AxeBuilder } = require('@axe-core/playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname,'../..');
(async()=>{
 const artifact=fs.mkdtempSync('/tmp/ask-gv-static-');
 execFileSync('python',['scripts/prepare_public_site.py','--output',artifact],{cwd:root});
 const server=http.createServer((req,res)=>{
   const name=req.url==='/'?'index.html':req.url.slice(1);
   if(!['index.html','site.css','ask-gv.css','ask-gv.js','ask-gv-config.js','ask-gv-fetch.js','assets/gvai-mark.svg','examples/gv_geometry_map.png'].includes(name)){res.writeHead(404);return res.end();}
   const mime=name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':name.endsWith('.svg')?'image/svg+xml':name.endsWith('.png')?'image/png':'text/html';
   res.writeHead(200,{'Content-Type':mime});res.end(fs.readFileSync(path.join(artifact,name)));
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 let browser;
 try {
 browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 const context=await browser.newContext({viewport:{width:1440,height:1000}});
 const page=await context.newPage(),errors=[],requests=[];
 page.on('pageerror',e=>errors.push(e.message));
 await context.route('**/*',route=>{
   const url=route.request().url();requests.push(url);
   if(url.startsWith(`http://127.0.0.1:${server.address().port}/`))return route.continue();
   return route.abort(); // Never contact any external service, including OpenAI.
 });
 const url=`http://127.0.0.1:${server.address().port}/`;
 await page.goto(url);await page.locator('#ask-gv').scrollIntoViewIfNeeded();
 assert.equal(await page.locator('#ask-send').isDisabled(),true);
 assert.match(await page.locator('#ask-status').textContent(),/unavailable/);
 assert.equal(requests.some(url=>url.includes('openai')),false);
 let audit=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
 assert.deepEqual(audit.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
 console.log('PASS disabled homepage, no external requests, full-page WCAG A/AA axe audit');
 await page.screenshot({path:'/tmp/ask-gv-disabled-desktop.png',fullPage:true});
 await page.locator('#ask-gv').screenshot({path:'/tmp/ask-gv-disabled-panel.png'});
 const feedbackHref='mailto:contact@gvaisafety.com?subject=GVAI%20Feature%20Idea%20or%20Feedback';
 assert.equal(await page.locator('#feedback-email').getAttribute('href'),feedbackHref);
 await page.locator('#feedback-email').focus();
 assert.equal(await page.locator('#feedback-email').evaluate(el=>document.activeElement===el),true);
 const noScript=await browser.newContext({javaScriptEnabled:false});
 await noScript.route('**/*',route=>route.request().url().startsWith(url)?route.continue():route.abort());
 const staticPage=await noScript.newPage();await staticPage.goto(url);
 assert.equal(await staticPage.locator('#feedback-email').isVisible(),true);
 assert.equal(await staticPage.locator('#feedback-email').getAttribute('href'),feedbackHref);
 assert.equal(await staticPage.locator('#ask-send').isDisabled(),true);await noScript.close();
 console.log('PASS permanent feedback without JavaScript or backend; fixed subject-only mailto and keyboard focus');
 let posted=[],mode='success',pending;
 await context.route('**/ask-gv-config.js',route=>route.fulfill({contentType:'text/javascript',body:"window.ASK_GV_ENDPOINT = 'https://ask-gv.test/v1/ask-gv';"}));
 const {render,feedbackIntent}=await import(path.join(root,'ask-gv/server.mjs'));
 const result=render({fact_ids:['status','docs']});
 await context.route('https://ask-gv.test/v1/ask-gv',async route=>{
   posted.push(route.request().postDataJSON());
   if(mode==='delay')await new Promise(r=>pending=r);
   if(mode==='error')return route.fulfill({status:503,contentType:'application/json',body:'{"error":"unavailable"}'});
   if(mode==='rate')return route.fulfill({status:429,contentType:'application/json',body:'{"error":"rate"}'});
   let body=feedbackIntent(posted.at(-1).message)?render({fact_ids:['status']},{requireFeedback:true}):result;
   if(mode==='malicious')body={...result,sources:[{id:'x',title:'x',url:'javascript:alert(1)'}]};
   if(mode==='oversize')body={...result,answer:'x'.repeat(20000)};
   if(mode==='badtitle')body={...result,sources:[{...result.sources[0],title:{bad:'type'}}]};
   if(mode==='badpath')body={...result,sources:[{...result.sources[0],url:'https://github.com/evil/repo'}]};
   if(mode==='badid')body={...result,sources:[{...result.sources[0],id:['status']}]};
   if(mode==='badversion')body={...result,version:['2026-11-12.v1']};
   return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(body)});
 });
 await page.reload();
 await page.getByRole('button',{name:'What is available today?',exact:true}).focus();
 await page.keyboard.press('Enter');
 assert.equal(await page.locator('#ask-question').inputValue(),'What is available today?');
 assert.equal(await page.locator('#ask-question').evaluate(el=>document.activeElement===el),true);
 await page.keyboard.press('Enter');assert.equal(posted.length,0); // textarea newline does not submit
 await page.locator('#ask-send').focus();await page.keyboard.press('Enter');
 await page.waitForFunction(()=>document.querySelector('#ask-status').textContent.startsWith('Answer ready'));
 assert.equal(posted.length,1);assert.deepEqual(posted[0].history,[]);
 assert.equal(await page.getByRole('button',{name:'Copy answer',exact:true}).count(),1);
 await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.copiedAnswer=text;}}}));
 await page.getByRole('button',{name:'Copy answer',exact:true}).click();
 assert.match(await page.evaluate(()=>window.copiedAnswer),/experimental/);
 assert.match(await page.locator('#ask-status').textContent(),/Copied/);
 // Clipboard denial path must allow keyboard selection and manual copy.
 await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw Error('denied');}}}));
 await page.getByRole('button',{name:'Copy answer',exact:true}).click();
 assert.match(await page.locator('#ask-summary').inputValue(),/experimental/);
 await page.getByRole('button',{name:'Prepare summary for ChatGPT'}).click();
 assert.match(await page.locator('#ask-summary').inputValue(),/https:\/\/gvaisafety.com/);
 assert.equal((await page.locator('#ask-summary').inputValue()).split('Runtime governance').length-1,1,'multiple sources must not duplicate the answer in summary');
 audit=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
 assert.deepEqual(audit.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
 console.log('PASS keyboard starters/send/newline, answer sources/copy fallback/summary, enabled full-page axe audit');
 for(const width of [320,375,768,1440]){
   await page.setViewportSize({width,height:900});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`horizontal overflow at ${width}`);
 }
 await page.setViewportSize({width:375,height:900});await page.locator('#ask-gv').scrollIntoViewIfNeeded();
 audit=await new AxeBuilder({page}).include('#ask-gv').withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();assert.equal(audit.violations.length,0);
 await page.screenshot({path:'/tmp/ask-gv-enabled-mobile.png',fullPage:true});
 await page.locator('#ask-gv').screenshot({path:'/tmp/ask-gv-enabled-panel-mobile.png'});
 console.log('PASS 320/375/768/1440 responsive overflow and mobile axe audit');
 for(const failure of ['error','rate','malicious','oversize','badtitle','badpath','badid','badversion']){
   mode=failure;await page.locator('#ask-question').fill('<img src=x onerror=alert(1)>');await page.locator('#ask-send').click();
   await page.waitForFunction(()=>!document.querySelector('#ask-send').disabled);
   assert.match(await page.locator('#ask-status').textContent(),failure==='rate'?/Too many requests/:/temporarily unavailable/);
   assert.equal(await page.locator('#ask-log img').count(),0);
 }
 assert.equal(posted[1].history.length,2);
 assert.equal(await page.getByRole('button',{name:'Copy answer',exact:true}).count(),1,'invalid responses cannot add answers');
 mode='delay';await page.locator('#ask-question').fill('Question in flight');await page.locator('#ask-send').click();
 await page.waitForFunction(()=>document.querySelector('#ask-log').getAttribute('aria-busy')==='true');
 while(!pending)await new Promise(r=>setTimeout(r,5));
 await page.getByRole('button',{name:'Reset conversation'}).click();pending();
 await page.waitForTimeout(100);
 assert.equal(await page.locator('#ask-log article').count(),0);
 assert.equal(await page.locator('#ask-log').getAttribute('aria-busy'),'false');
 assert.equal(await page.locator('#ask-question').evaluate(el=>document.activeElement===el),true);
 assert.equal(await page.locator('#ask-summary').inputValue(),'');
 assert.equal(errors.length,0,JSON.stringify(errors));
 assert.equal(requests.some(url=>url.includes('api.openai.com')),false);
 console.log('PASS errors/rate/malicious links/XSS text, bounded history, in-flight reset, no JS errors or OpenAI networking');
 mode='success';
 await page.getByRole('button',{name:'Suggest a feature',exact:true}).focus();await page.keyboard.press('Enter');
 assert.equal(await page.locator('#ask-question').inputValue(),'How can I suggest a feature?');
 await page.locator('#ask-question').fill('Suggest a feature MY_PRIVATE_CHAT_SHOULD_NOT_BE_IN_EMAIL');
 await page.locator('#ask-send').focus();await page.keyboard.press('Enter');
 await page.waitForFunction(()=>document.querySelector('#ask-status').textContent.startsWith('Answer ready'));
 assert.match(await page.locator('#ask-log').textContent(),/contact@gvaisafety.com/);
 assert.match(await page.locator('#ask-log').textContent(),/not a promise/);
 assert.equal(await page.locator('#ask-log a[href="https://gvaisafety.com/#feedback"]').count(),1);
 assert.equal(await page.locator('#feedback-email').getAttribute('href'),feedbackHref);
 assert.equal(requests.some(target=>target.startsWith('mailto:')),false);
 audit=await new AxeBuilder({page}).include('#feedback').withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();assert.equal(audit.violations.length,0);
 await page.locator('#feedback').screenshot({path:'/tmp/ask-gv-feedback-mobile.png'});
 await page.setViewportSize({width:1440,height:1000});await page.locator('#feedback').screenshot({path:'/tmp/ask-gv-feedback-desktop.png'});
 mode='error';await page.locator('#ask-question').fill('Suggest a feature');await page.locator('#ask-send').click();
 await page.waitForFunction(()=>!document.querySelector('#ask-send').disabled);
 assert.equal(await page.locator('#feedback-email').isVisible(),true);
 assert.equal(await page.locator('#feedback-email').getAttribute('href'),feedbackHref);
 console.log('PASS feedback starter/routing, no transcript in email, accessible mobile feedback and provider-unavailable independence');
 await context.close();
 } finally {await browser?.close();await new Promise(r=>server.close(r));fs.rmSync(artifact,{recursive:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
