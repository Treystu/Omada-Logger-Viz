const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {spawn} = require("node:child_process");
const {setTimeout: sleep} = require("node:timers/promises");

const html = fs.readFileSync("viz.html","utf8");
const ts = i => "2026-11-03T12:" + String(i).padStart(2,"0") + ":00Z";
const row = (id,order,minute) => ({id,order,version:1,type:"flow",ts:ts(minute),src:"192.0.2.1",dst:"198.51.100.1",dpt:80,dir:"outbound"});
const entries = [
  {id:"tally",order:0,version:1,type:"flow",src:"192.0.2.1",dst:"198.51.100.1",dpt:80,first:ts(0),last:ts(50),count:3,occurrences:[ts(10)],dir:"outbound"},
  {id:"msg",order:1,version:1,type:"msg",from:"192.0.2.2",first:ts(0),last:ts(10),count:2,template:"login <IP>",dir:"other",activity:{id:"login",label:"Logins",sample_only:true}},
  {id:"msg2",order:2,version:1,type:"msg",from:"192.0.2.3",first:ts(5),count:9,template:"AP <MAC> changed",dir:"other",activity:{id:"ap",label:"Access points",sample_only:true}}
];
const raw = [row("raw1",0,10),row("raw2",1,20)];
const extra = row("raw3",2,15);
const sources = {condensed:{available:true,entries:2},raw:{available:true,records:2}};
let revision = 1, held = null, holdSnapshot = false;
const server = http.createServer((req,res) => {
  const url = new URL(req.url,"http://127.0.0.1");
  const send = payload => { res.setHeader("Content-Type","application/json"); res.end(JSON.stringify(payload)); };
  const head = {schema:1,epoch:"test",revision};
  if (url.pathname === "/") { res.setHeader("Content-Type","text/html; charset=utf-8"); res.end(html); }
  else if (url.pathname === "/api/chart/snapshot") {
    const answer = () => send({...head,entries,raw:revision === 1 ? raw : [...raw,extra],sources,detail_available:true});
    if (holdSnapshot) held = answer; else answer();
  }
  else if (url.pathname === "/api/chart/changes") {
    const base = Number(url.searchParams.get("since"));
    send({...head,base,changes:base === revision ? [] : [{layer:"raw",upserts:[extra],deletes:[]}]});
  }
  else if (url.pathname === "/api/chart/detail") {
    send({...head,id:url.searchParams.get("id"),version:1,record:{sample:"private detail"}});
  }
  else if (url.pathname === "/api/chart/search" || url.pathname === "/api/chart/details") {
    let body = "";
    req.on("data",b => body += b); req.on("end",() => {
      const data = JSON.parse(body);
      send(url.pathname === "/api/chart/search" ? {...head,matches:{pattern:[],variables:["msg"],variable_values:["msg"],candidates:[]}} :
        {...head,results:data.refs.map(ref => ({...ref,record:{...entries[1],sample:"private sample",activity:{id:"login",label:"Logins",sample_only:true,variables:{ip:"203.0.113.10"}}}}))});
    });
  }
  else { res.writeHead(404); res.end(); }
});
function until(label, operation){
  return (async () => {
    for (let i=0;i<150;i++) { const value = await operation(); if (value) return value; await sleep(80); }
    throw Error("Timed out: " + label);
  })();
}
async function main(){
  await new Promise(resolve => server.listen(0,"127.0.0.1",resolve));
  const profile = fs.mkdtempSync(path.join(os.tmpdir(),"omada-viz-fixture-"));
  const chrome = spawn("C:/Program Files/Google/Chrome/Application/chrome.exe",[
    "--headless=new","--no-first-run","--disable-background-networking","--remote-debugging-port=0",
    "--user-data-dir="+profile,"--window-size=1450,950","about:blank"
  ],{windowsHide:true,stdio:"ignore"});
  let ws;
  try {
    const debug = await until("Chrome CDP port",() => {
      try { return fs.readFileSync(path.join(profile,"DevToolsActivePort"),"utf8").split("\n")[0]; } catch {}
    });
    const targets = await (await fetch("http://127.0.0.1:"+debug+"/json/list")).json();
    ws = new WebSocket(targets.find(item => item.type === "page").webSocketDebuggerUrl);
    await new Promise((resolve,reject) => { ws.addEventListener("open",resolve,{once:true}); ws.addEventListener("error",reject,{once:true}); });
    let lastId = 0;
    const pending = new Map(), runtimeErrors = [];
    ws.addEventListener("message",ev => {
      const data = JSON.parse(ev.data);
      if (data.method === "Runtime.exceptionThrown") runtimeErrors.push(data.params.exceptionDetails.text);
      if (pending.has(data.id)) { pending.get(data.id)(data); pending.delete(data.id); }
    });
    async function cdp(method,params){
      const id = ++lastId;
      const reply = await new Promise(resolve => { pending.set(id,resolve); ws.send(JSON.stringify({id,method,params})); });
      if (reply.error) throw Error(JSON.stringify(reply.error));
      return reply.result;
    }
    async function evaluate(expression){
      const reply = await cdp("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true});
      if (reply.exceptionDetails) throw Error(reply.exceptionDetails.exception?.description || reply.exceptionDetails.text);
      return reply.result.value;
    }
    await cdp("Runtime.enable");
    await cdp("Page.enable");
    await cdp("Page.navigate",{url:"http://127.0.0.1:"+server.address().port});
    await until("live first frame",() => evaluate('typeof chartDataReady !== "undefined" && chartDataReady'));
    assert.equal(await evaluate('$("fType").value'),"flow");
    assert.equal(await evaluate("drawn.length"),5,"default scatter contains only flow marks");
    await evaluate('setView("messages")');
    await until("default Messages view",() => evaluate('$("messageBubbles").querySelectorAll("button").length === 2'));
    assert.equal(await evaluate('$("fType").value'),"flow","opening Messages does not mutate the scatter selector");
    await evaluate('setView("scatter")');
    assert.equal(await evaluate("drawn.length"),5,"returning to scatter keeps messages out");
    await evaluate("openPointChartDetail(drawn[0].p)");
    assert.match(await evaluate('$("detailBody").textContent'),/private detail/);
    await evaluate('closeChartDetail(); $("selS").value = "const"; controlChange()');
    revision = 2;
    assert.equal(await evaluate('var usedPartial = false; var originalStrips = scatterDirtyStrips; scatterDirtyStrips = function(...a){ const result=originalStrips(...a); usedPartial=!!result; return result; }; refresh(false).then(()=>usedPartial)'),true);
    assert.equal(await evaluate('var partialRaster=canvas.toDataURL(); draw(); partialRaster === canvas.toDataURL()'),true,"incremental and full pixels agree");
    await evaluate('setView("messages"); $("msgSearch").value="203.0.113.10"; renderMessageBubbles()');
    await until("details-only message search result",() => evaluate('!!$("messageBubbles").querySelector("button")'));
    await evaluate('$("messageBubbles").querySelector("button").click()');
    await until("message details",() => evaluate('$("detailBody").textContent.includes("private sample")'));
    await evaluate('$("msgSearch").value=""; renderMessageBubbles()');
    const liveBubbles = await evaluate('Array.from($("messageBubbles").querySelectorAll("button"),button=>[button.getAttribute("aria-label").includes("login <IP>")?"msg":"msg2",parseFloat(button.style.left)+parseFloat(button.style.width)/2,parseFloat(button.style.top)+parseFloat(button.style.height)/2,parseFloat(button.style.width)/2])');
    assert.equal(liveBubbles.length,2);
    const savedBubbles = await until("persisted message image",() => evaluate('chartCacheRead("messages").then(x => x && x.hits.length === 2 && x)'));
    assert.equal(savedBubbles.kind,"messages");
    assert.equal(savedBubbles.labelSchema,1);
    assert.equal(savedBubbles.hits.length,liveBubbles.length,"cached geometry retains every live bubble");
    for(const hit of savedBubbles.hits){
      const live=liveBubbles.find(row=>row[0]===hit[0]);
      assert.ok(live,"cached hit geometry preserves a live row ID");
      assert.equal(hit[1],1,"cached hit geometry preserves the live row version");
      assert.equal(hit[2],0,"cached hit geometry keeps the expected row ordinal");
      for(let axis=0;axis<3;axis++)assert.ok(Math.abs(hit[3+axis]-live[1+axis])<=0.0011,"cached subpixel geometry matches the live mark within CSS serialization precision");
    }
    assert.deepEqual(Object.keys(savedBubbles).sort(),["access","epoch","height","hits","image","key","kind","labelSchema","revision","savedAt","width"]);
    assert.equal(JSON.stringify(savedBubbles).includes("login <IP>"),false);
    assert.equal(JSON.stringify(savedBubbles).includes("private sample"),false);
    await evaluate('$("selS").value="count"; controlChange(); setView("scatter"); saveCachedChart()');
    const cached = await evaluate('chartCacheRead().then(x => ({revision:x.revision,width:x.width,hits:x.hits.length,keys:Object.keys(x).sort(),view:chartCacheView()}))');
    assert.equal(cached.revision,2);
    assert.equal(cached.hits,6);
    assert.deepEqual(cached.keys,["access","epoch","height","hits","image","key","revision","savedAt","width"]);
    const currentRaster = await evaluate("canvas.toDataURL()");
    holdSnapshot = true;
    await cdp("Page.reload",{ignoreCache:true});
    await until("delayed snapshot pending",() => held);
    await until("cached stale image",() => evaluate('chartStaleImage'));
    assert.equal(await evaluate('hitGrid === null && legendHits.length === 0 && !chartDataReady'),true);
    assert.equal(await evaluate("canvas.toDataURL()"),currentRaster);
    holdSnapshot = false; held();
    await until("live replacement",() => evaluate("chartDataReady && !chartStaleImage && drawn.length === 6"));
    holdSnapshot = true; held = null;
    await cdp("Page.reload",{ignoreCache:true});
    await until("second delayed snapshot pending",() => held);
    await evaluate('setView("messages")');
    await until("cached message bubbles after reopening",() => evaluate('!!messagePreview'));
    assert.equal(await evaluate('$("messageBubbles").querySelectorAll("button").length'),0);
    assert.match(await evaluate('$("messageCoverage").textContent'),/Cached message bubbles/);
    assert.equal(await evaluate('chartCacheRead("messages").then(x => { let c=messagePreview.image, p=c.getContext("2d"); return x.hits.every(h=>p.getImageData(Math.round(h[3]*devicePixelRatio),Math.round(h[4]*devicePixelRatio),1,1).data[3] > 0); })'),true);
    assert.equal(await evaluate('$("msgPrev").disabled && $("msgNext").disabled'),true);
    await evaluate('$("fSrc").value="unmatched"; filterChange()');
    assert.equal(await evaluate('!!messagePreview'),false,"changing filters invalidates the saved geometry");
    await evaluate('setView("scatter"); setView("messages")');
    await until("different filter checked",() => evaluate('!messageOpening'));
    assert.equal(await evaluate('!!messagePreview'),false,"the filtered key cannot restore an unfiltered image");
    await evaluate('$("fSrc").value=""; setView("scatter"); setView("messages")');
    await until("exact filter restored",() => evaluate('!!messagePreview'));
    await cdp("Emulation.setDeviceMetricsOverride",{width:1100,height:800,deviceScaleFactor:1,mobile:false});
    await until("resize invalidates preview",() => evaluate('!messagePreview'));
    await evaluate('setView("scatter"); setView("messages")');
    await until("different viewport checked",() => evaluate('!messageOpening'));
    assert.equal(await evaluate('!!messagePreview'),false);
    await cdp("Emulation.clearDeviceMetricsOverride");
    await evaluate('setView("scatter"); setView("messages")');
    await until("same viewport preview",() => evaluate('!!messagePreview'));
    holdSnapshot = false; held();
    await until("fresh clickable message bubbles",() => evaluate('!messagePreview && $("messageBubbles").querySelectorAll("button").length === 2'));
    await evaluate('Array.from($("messageBubbles").querySelectorAll("button")).find(el => el.getAttribute("aria-label").includes("Logins")).click()');
    await until("fresh message detail click",() => evaluate('$("detailBody").textContent.includes("private sample")'));
    await evaluate('setView("scatter"); var sawWarmBubble = false; var observer = new MutationObserver(records=>{sawWarmBubble ||= records.some(r=>Array.from(r.addedNodes).some(n=>n.className==="cachedMessageBubbles"));}); observer.observe($("messageBubbles"),{childList:true}); setView("messages")');
    await until("warm switch with live data",() => evaluate('sawWarmBubble && !messagePreview && $("messageBubbles").querySelectorAll("button").length === 2'));
    assert.deepEqual(runtimeErrors,[]);
    console.log("Headless Chrome fixture passed: live plot, lazy details, delta pixels, metadata search, persistent warm image, inert stale hits, fresh geometry, message warm reload and switch, message layout, filter and viewport matching");
  } finally {
    if (ws) ws.close();
    chrome.kill();
    server.closeAllConnections();
    server.close();
    const tempRoot = path.resolve(os.tmpdir());
    const resolved = path.resolve(profile);
    if (path.dirname(resolved) === tempRoot && path.basename(resolved).startsWith("omada-viz-fixture-")) {
      await sleep(300);
      // Chrome can leave lock handles temporarily open on Windows.
      try { fs.rmSync(resolved,{recursive:true,force:true,maxRetries:3}); } catch {}
    }
  }
}
main().catch(e => { console.error(e); process.exitCode=1; server.close(); });
