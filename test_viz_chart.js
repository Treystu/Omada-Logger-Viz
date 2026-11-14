"use strict";
// Run with node test_viz_chart.js.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const html = fs.readFileSync("viz.html", "utf8");
const script = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"))
  .replace(/\r?\nfit\(\);\r?\nrestoreCachedChart\(\);\r?\nrefresh\(true\);\s*$/, "");
const plain = value => JSON.parse(JSON.stringify(value));
const stamp = minute => "2026-11-03T12:" + String(minute).padStart(2, "0") + ":00Z";
const raw = (id, order, minute, version = 1) => ({
  id, order, version, type:"flow", ts:stamp(minute), src:"192.0.2.1", dst:"198.51.100.1", dpt:80, dir:"outbound"
});
const tally = {
  id:"tally",order:0,version:1,type:"flow",first:stamp(0),last:stamp(1),occurrences:[stamp(1)],
  count:7,src:"192.0.2.1",dst:"198.51.100.1",dpt:80,dir:"outbound"
};
const message = {
  id:"message",order:1,version:1,type:"msg",first:stamp(1),last:stamp(2),occurrences:[],
  count:4,from:"sender",dir:"other",template:"login <IP>",activity:{id:"login",label:"Logins",sample_only:true}
};
const messageRaw = (id, order, src, sev, minute) => ({id,order,version:1,type:"msg",ts:stamp(minute),src,dst:"198.51.100.9",sev,dir:"inbound",label:"authentication failed",activity:{id:"auth",label:"Authentication"}});
const sources = {condensed:{available:true},raw:{available:true}};
const snapshot = {schema:1,epoch:"alpha",revision:1,detail_available:true,sources,
  entries:[tally,message],raw:[raw("first",0,2),raw("duplicate",1,2)]};

function fixture(){
  const elements = new Map();
  function element(){
    return {style:{}, classList:{toggle(){}}, textContent:"", value:"", checked:true,
      children:[], appendChild(child){ this.children.push(child); },
      addEventListener(){}, setAttribute(){}, querySelector(){ return {focus(){}}; },
      getContext(){ return {}; }, clientWidth:1000,clientHeight:600};
  }
  function $(id){
    if (!elements.has(id)) elements.set(id,element());
    return elements.get(id);
  }
  const context = {
    document:{getElementById:$,createElement:element,addEventListener(){},hidden:false},
    window:{addEventListener(){}},navigator:{language:"en"},localStorage:{getItem(){return "1";}},
    setTimeout(){},clearTimeout(){},setInterval(){}, console
  };
  vm.createContext(context);
  vm.runInContext(script,context);
  return context;
}

async function run(){
  const chart = fixture();
  const state = chart.chartSnapshot(snapshot);
  assert.equal(state.raw.size,2,"overlapping raw events keep separate IDs");
  chart.data = state.data;
  const initialPoints = chart.buildAllPoints();
  assert.equal(initialPoints.length,6,"tally timestamp duplicates are merged per aggregate");
  const updated = chart.chartApplyChanges(state,{
    schema:1,epoch:"alpha",base:1,revision:2,changes:[{layer:"raw",deletes:["first","already-expired"],
      upserts:[raw("new",2,3,2),raw("duplicate",1,2,2)]}]
  });
  chart.data = updated.data;
  const updatedPoints = chart.buildAllPoints();
  assert.strictEqual(updatedPoints[0],initialPoints[0],"unchanged rows reuse timestamp projections");
  assert.deepEqual(Array.from(updated.data.raw,row => row.id),["duplicate","new"]);
  assert.equal(state.raw.get("duplicate").version,1,"a delta does not mutate an existing frame");
  assert.throws(() => chart.chartApplyChanges(updated,{schema:1,epoch:"alpha",base:1,revision:2,changes:[]}),/revision/);
  assert.throws(() => chart.chartApplyChanges(updated,{schema:1,epoch:"beta",base:2,revision:3,changes:[]}),/revision/);
  assert.strictEqual(chart.chartApplyChanges(updated,{schema:1,epoch:"alpha",base:2,revision:2,changes:[]}),updated);
  const failedSource = chart.chartApplyChanges(updated,{schema:1,epoch:"alpha",base:2,revision:3,
    sources:{condensed:sources.condensed,raw:{available:false,error:"offline"}},
    changes:[{layer:"raw",deletes:["duplicate","new"],upserts:[]}]});
  assert.equal(failedSource.data.raw.length,0);
  assert.equal(failedSource.data.sources.raw.available,false);

  const old = {p:{},x:70,y:20,r:4,color:"red"};
  const same = {p:{},x:820,y:40,r:4,color:"blue"};
  const shifted = {...old,x:120,y:40};
  const previous = {signature:"grid",marks:[old,same]};
  assert.deepEqual(plain(chart.scatterDirtyStrips(previous,"grid",[shifted,same],1000,1,826)),
    [[64,76],[114,126],[826,1000]],"both old and new regions and the legend are invalidated");
  assert.equal(chart.scatterDirtyStrips(previous,"changed axes",[shifted,same],1000,1,1000),null);
  assert.equal(chart.scatterDirtyStrips(previous,"grid",[same,shifted],1000,1,1000),null,
    "a different compositing order falls back to a full render");

  const cache = {key:"digest",access:"loopback",width:100,height:50,epoch:"alpha",revision:2,savedAt:Date.now(),
    image:{type:"image/png",size:1},hits:[[tally.id,tally.version,0,30,40]]};
  assert.equal(chart.chartCacheRecordValid(cache,"digest",100,50),true);
  assert.equal(chart.chartCacheRecordValid(cache,"different view",100,50),false);
  assert.equal(chart.chartCacheRecordValid(cache,"digest",100,49),false);
  assert.equal(chart.chartCacheRecordValid({...cache,savedAt:0},"digest",100,50),false);
  assert.equal(chart.chartCacheRecordValid({...cache,access:"remote"},"digest",100,50),false);
  assert.match(html,/id="fType"><option value="flow" selected>/,"the default scatter filter keeps messages out until explicitly included");
  const hit = chart.chartCacheIdentity({p:{ref:{...tally,sample:"private"},ordinal:1,message:"body"},x:20,y:30});
  assert.deepEqual(plain(hit),["tally",1,1,20,30],"hit geometry does not persist record contents");

  chart.chartState = state;
  const pending = [];
  chart.chartJson = (url,payload) => new Promise((resolve,reject) => pending.push({url,payload,resolve,reject}));
  const first = chart.openPointChartDetail({ds:"raw",ref:snapshot.raw[0]});
  const second = chart.openPointChartDetail({ds:"raw",ref:snapshot.raw[1]});
  pending[1].resolve({schema:1,epoch:"alpha",id:"duplicate",version:1,record:{sample:"second"}});
  await second;
  pending[0].resolve({schema:1,epoch:"alpha",id:"first",version:1,record:{sample:"first"}});
  await first;
  assert.match(chart.$("detailBody").textContent,/second/,"slower click responses cannot overwrite the current drawer");
  const stale = chart.openPointChartDetail({ds:"raw",ref:snapshot.raw[0]});
  chart.chartState = updated;
  pending[2].resolve({schema:1,epoch:"alpha",id:"first",version:1,record:{sample:"no longer visible"}});
  await stale;
  assert.match(chart.$("detailBody").textContent,/changed or left/);
  chart.chartState = chart.chartSnapshot({...snapshot,detail_available:false});
  await chart.openPointChartDetail({ds:"raw",ref:snapshot.raw[0]});
  assert.equal(pending.length,3,"redacted views do not send detail requests");
  assert.match(chart.$("detailBody").textContent,/restricted/);

  chart.activeView = "scatter";
  chart.chartState = state;
  const olderSearch = chart.getChartSearch("first query");
  const newerSearch = chart.getChartSearch("second query");
  pending[3].resolve({schema:1,epoch:"alpha",revision:1,matches:{
    pattern:[],variables:[],variable_values:["first"],candidates:[]}});
  pending[4].resolve({schema:1,epoch:"alpha",revision:1,matches:{
    pattern:["message"],variables:[],variable_values:[],candidates:[]}});
  await Promise.resolve(); await Promise.resolve();
  assert.strictEqual(chart.chartSearch,newerSearch);
  assert.equal(olderSearch.matches.variable_values.has("first"),true);
  assert.equal(newerSearch.matches.pattern.has("message"),true);

  const redacted = chart.chartSnapshot({...snapshot,detail_available:false,redacted_detail_available:true});
  chart.chartState = redacted;
  const redactedDetail = chart.openPointChartDetail({ds:"raw",ref:snapshot.raw[0]});
  pending[5].resolve({schema:1,epoch:"alpha",id:"first",version:1,record:{src:"192.0.2.1",dpt:80}});
  await redactedDetail;
  assert.match(chart.$("detailBody").textContent,/192\.0\.2\.1/,"authorized remote views can retrieve server-redacted detail");

  const batchSizes = [];
  chart.chartJson = async (url, payload) => {
    batchSizes.push(payload.refs.length);
    if (payload.refs.length > 1) throw Object.assign(Error("bounded"),{status:413});
    return {schema:1,epoch:"alpha",results:payload.refs.map(ref => ({...ref,record:{}}))};
  };
  const refs = snapshot.raw.map(({id,version}) => ({id,version}));
  assert.deepEqual((await chart.fetchChartDetailRows("alpha",refs,chart.chartDetailRequest)).map(row => row.id),["first","duplicate"]);
  assert.deepEqual(batchSizes,[2,1,1],"detail pages recover from a response-size limit");

  const quota = fixture();
  quota.chartState = state;
  quota.data = state.data;
  quota.chartPaint = {};
  quota.drawn = [{p:{ref:tally,ordinal:0},x:20,y:30}];
  quota.canvas.width = quota.canvas.clientWidth;
  quota.canvas.height = quota.canvas.clientHeight;
  quota.canvas.toBlob = cb => cb({size:1,type:"image/png"});
  quota.chartCacheSupported = () => true;
  quota.chartCacheView = () => "view";
  quota.chartCacheKey = async () => "digest";
  quota.chartCacheWrite = async () => { throw Error("Quota exceeded"); };
  await quota.saveCachedChart();
  assert.equal(quota.chartCacheDisabled,true,"quota failures disable the cache for this tab");
  assert.strictEqual(quota.chartState,state,"cache failure leaves the live chart usable");

  const clearing=fixture(),stored=new Map([["last",{savedAt:1}],["messages",{savedAt:1}]]),writeOrder=[];
  clearing.chartCacheDb=async()=>({transaction(){const tx={objectStore(){return {delete(key){stored.delete(key);}};}};setTimeout(()=>tx.oncomplete(),0);return tx;}});
  let releaseQueuedWrite,releaseFlowBlob,releaseMessageBlob,saveWrites=0;
  const queuedWrite=clearing.chartCacheSerial(()=>new Promise(resolve=>{releaseQueuedWrite=()=>{stored.set("last",{savedAt:2});writeOrder.push("in-flight write");resolve();};}));
  await Promise.resolve();
  clearing.chartState=state;clearing.data=state.data;clearing.chartPaint={};clearing.chartFrame=3;clearing.messageFrame=4;
  clearing.drawn=[{p:{ref:tally,ordinal:0},x:10,y:20}];clearing.scatterCanCache=()=>true;clearing.canvasSynced=()=>true;
  clearing.canvas.width=100;clearing.canvas.height=50;clearing.canvas.clientWidth=100;clearing.canvas.clientHeight=50;
  clearing.canvas.toBlob=callback=>{releaseFlowBlob=()=>callback({type:"image/png",size:1});};
  clearing.chartCacheView=()=>"view";clearing.chartCacheKey=async()=>"digest";
  clearing.chartCanCache=()=>true;clearing.messageCacheView=()=>"view";
  clearing.chartCacheWrite=async()=>{saveWrites++;};
  clearing.document.createElement=()=>({width:0,height:0,toBlob(callback){releaseMessageBlob=()=>callback({type:"image/png",size:1});},getContext(){return {scale(){}};}});
  const flowSaving=clearing.saveCachedChart();
  const messageSaving=clearing.saveCachedMessage(4,state,"view",100,50,1,[]);
  await Promise.resolve();
  let previewRemoved=false;
  clearing.chartCacheTimer=101;clearing.messageCacheTimer=102;clearing.messageOpening={timer:103};clearing.messagePreview={image:{remove(){previewRemoved=true;}}};
  const clearPending=clearing.clearChartCache();
  assert.equal(clearing.chartCacheGeneration,1,"clearing increments the save generation immediately");
  assert.equal(clearing.chartCacheTimer,null);assert.equal(clearing.messageCacheTimer,null);
  assert.equal(clearing.chartFrame,4);assert.equal(clearing.messageFrame,5);
  assert.equal(clearing.messageOpening,null);assert.equal(clearing.messagePreview,null);assert.equal(previewRemoved,true,"clear invalidates an in-flight warm preview");
  releaseQueuedWrite();
  await Promise.all([queuedWrite,clearPending]);
  releaseFlowBlob({type:"image/png",size:1});releaseMessageBlob();
  await Promise.all([flowSaving,messageSaving]);
  assert.deepEqual(writeOrder,["in-flight write"]);
  assert.equal(stored.size,0,"clear waits for an already-running IndexedDB write, then removes both cache slots");
  assert.equal(saveWrites,0,"asynchronous scatter and message encodes cannot repopulate the cache after clear");

  const bubbles = fixture();
  const group = {key:"auth\u0000authentication failed",pattern:"authentication failed <IP>",activity:{id:"auth",label:"Authentication"},count:4,severity:{5:4},records:[{...messageRaw("message",0,"192.0.2.7",5,2),sample:"private sample"}]};
  const productionItems=bubbles.messageSliceItems({variant:group},["variant"],"",false,"source","severity");
  const productionLayout=bubbles.messageGridLayout(productionItems,1000,600);
  const packed=productionLayout.points[0];
  assert.equal(Object.hasOwn(packed.item,"label"),false,"messageSliceItems returns production-shaped items without a render-only label field");
  const bubble = bubbles.messageCacheMark(packed,group);
  assert.equal(bubble.label,"authentication failed <IP>","cache mark derives the same truncated pattern label as live rendering");
  assert.deepEqual(plain(bubble.hit.slice(0,3)),["message",1,0]);
  assert.equal(JSON.stringify(bubble).includes("private sample"),false);
  assert.equal(JSON.stringify(bubble.hit).includes("authentication failed"),false,"persisted hit geometry contains IDs and coordinates, not labels or bodies");
  const text = [];
  const paint = {scale(){},beginPath(){},arc(){},fill(){},stroke(){},save(){},clip(){},restore(){},
    fillText(value,x,y){ text.push([value,x,y]); }};
  bubbles.paintCachedMessage({getContext(){ return paint; }},[bubble],1);
  assert.deepEqual(text,[["authentication failed <IP>",packed.x+8,packed.y]],"message raster shows the production pattern label instead of count or undefined");
  bubbles.chartState={data:{detail_available:true,redacted_detail_available:false}};bubbles.window.innerWidth=1280;bubbles.window.innerHeight=800;
  bubbles.showMessageHover({getBoundingClientRect(){return {left:20,right:80,top:20,bottom:60};}},group,4,"",{},false,false);
  assert.match(bubbles.$("messageHoverDetails").textContent,/authentication failed <IP>/,"hover retains the full message label");
  assert.match(bubbles.$("messageHoverDetails").textContent,/displayed_count\": 4/,"hover provides the full count");
  const sliced = bubbles.messageSliceItems({variant:{...group,count:2,severity:{5:1},records:[
    messageRaw("m1",1,"192.0.2.1",4,1),messageRaw("m2",2,"192.0.2.2",5,2)
  ]}},["variant"],"",false,"source","severity");
  assert.equal(sliced.length,2,"a pattern is split across its actual source and severity values");
  assert.deepEqual(plain(sliced.map(item=>[item.xValue,item.yValue,item.count]).sort()),[["192.0.2.1","4",1],["192.0.2.2","5",1]]);
  assert.equal(sliced.reduce((sum,item)=>sum+item.count,0),2,"slicing assigns each raw record once");
  const agg = bubbles.messageSliceItems({variant:{...group,count:12,records:[
    {...message,id:"aggregate",count:12,first:stamp(1),last:stamp(2),activity:{id:"auth",label:"Authentication",variables:{user:["alice","bob"]}}}
  ]}},["variant"],"",true,"timestamp","activity");
  assert.equal(agg.length,1,"aggregate count is placed at one last-observed date, even when samples are multivalued");
  assert.equal(agg[0].count,12,"lifetime aggregate count is preserved without duplication");
  assert.equal(agg[0].xValue,stamp(2).slice(0,10));
  assert.equal(bubbles.messageRecordAxisValue(agg[0].records[0],"var:user",group).value,"(multiple)","multi-valued examples stay explicit instead of duplicating a lifetime count");
  function gridFixture(rows){
    const groups={};
    rows.forEach((row,index)=>{const key="variant-"+index;groups[key]={pattern:"pattern "+index,activity:{id:"auth",label:"Authentication"},count:row.n,severity:{[row.sev]:row.n},records:[{...messageRaw("grid-"+index,index,row.src,row.sev,index+1),count:row.n}]};});
    const keys=Object.keys(groups),items=bubbles.messageSliceItems(groups,keys,"",false,"source","severity");
    return {groups,items,grid:bubbles.messageGridLayout(items,800,500)};
  }
  const onePerCell=gridFixture([{src:"192.0.2.1",sev:4,n:1},{src:"192.0.2.2",sev:4,n:1},{src:"192.0.2.1",sev:5,n:1},{src:"192.0.2.2",sev:5,n:1}]);
  for(const point of onePerCell.grid.points){
    const xTick=onePerCell.grid.xLabels.find(tick=>tick.value===point.item.xValue),yTick=onePerCell.grid.yLabels.find(tick=>tick.value===point.item.yValue);
    assert.ok(Math.abs(point.x-xTick.x)<1e-9,"a single bubble is centered on its categorical X tick");
    assert.ok(Math.abs(point.y-yTick.y)<1e-9,"a single bubble is centered on its categorical Y tick");
  }
  const uneven=gridFixture([
    {src:"192.0.2.1",sev:4,n:1},{src:"192.0.2.1",sev:4,n:1},{src:"192.0.2.1",sev:4,n:1},{src:"192.0.2.1",sev:4,n:1},{src:"192.0.2.1",sev:4,n:1},
    {src:"192.0.2.2",sev:4,n:1},{src:"192.0.2.2",sev:4,n:1},{src:"192.0.2.1",sev:5,n:1},{src:"192.0.2.2",sev:5,n:1},{src:"192.0.2.2",sev:5,n:1},{src:"192.0.2.2",sev:5,n:1}
  ]);
  for(const xTick of uneven.grid.xLabels)for(const yTick of uneven.grid.yLabels){
    const cellPoints=uneven.grid.points.filter(point=>point.item.xValue===xTick.value&&point.item.yValue===yTick.value);
    if(!cellPoints.length)continue;
    const centerX=(Math.min(...cellPoints.map(point=>point.x))+Math.max(...cellPoints.map(point=>point.x)))/2;
    const centerY=(Math.min(...cellPoints.map(point=>point.y))+Math.max(...cellPoints.map(point=>point.y)))/2;
    assert.ok(Math.abs(centerX-xTick.x)<1e-9,"odd and sparse rows stay centered on their category X tick");
    assert.ok(Math.abs(centerY-yTick.y)<1e-9,"fewer bubbles than global columns stay centered on their category Y tick");
  }
  assert.equal(uneven.items.reduce((sum,item)=>sum+item.count,0),11,"balanced and sparse layout preserves all slice counts");
  assert.ok(uneven.grid.points.every(point=>point.r>0),"multiple bubbles in a category cell retain visible sizes");
  for(let i=0;i<uneven.grid.points.length;i++)for(let j=i+1;j<uneven.grid.points.length;j++){
    const a=uneven.grid.points[i],b=uneven.grid.points[j],distance=Math.hypot(a.x-b.x,a.y-b.y);
    assert.ok(distance+1e-9>=a.r+b.r,"bubble circles do not overlap across balanced or sparse bins");
  }
  const bubbleCache = {...cache,kind:"messages",labelSchema:1,width:1000,height:600,hits:[bubble.hit]};
  assert.equal(bubbles.chartCacheRecordValid(bubbleCache,"digest",1000,600,"messages"),true);
  assert.equal(bubbles.chartCacheRecordValid({...bubbleCache,labelSchema:undefined},"digest",1000,600,"messages"),false,"old count-only previews are rejected after the label change");
  assert.equal(bubbles.chartCacheRecordValid(bubbleCache,"digest",1000,600),false);
  assert.equal(bubbles.chartCacheRecordValid({...bubbleCache,hits:[hit]},"digest",1000,600,"messages"),false);

  let releaseRead;
  bubbles.messageOpening={view:"view"};
  bubbles.messageCacheView=()=>"view";
  bubbles.chartCacheRead=()=>new Promise(resolve=>{releaseRead=resolve;});
  bubbles.chartCacheKey=async()=>"digest";
  bubbles.chartCacheRecordValid=()=>true;
  const opening=bubbles.messageOpening;
  const openingAttempt=bubbles.restoreCachedMessage(opening);
  bubbles.cancelMessagePreview();
  releaseRead(bubbleCache);
  assert.equal(await openingAttempt,false,"switching away while a warm cache is loading prevents stale preview restore");
  assert.match(html,/\.cachedMessageBubbles\{[^}]*pointer-events:none/s,"a stale raster preview cannot receive clicks");
  assert.match(html,/id="clearChartCache"/,"the user can clear locally saved previews");
  const warm = fixture();
  warm.messageOpening={view:"view"};warm.messageCacheView=()=>"view";warm.chartCacheRead=async()=>bubbleCache;warm.chartCacheKey=async()=>"digest";
  warm.createImageBitmap=async()=>({width:1000,height:600,close(){}});
  const host=warm.$("messageBubbles");host.clientWidth=1000;host.clientHeight=600;host.appendChild=function(child){this.children.push(child);};
  warm.document.createElement=function(){return {style:{},setAttribute(){},getContext(){return {drawImage(){}};}};};
  assert.equal(await warm.restoreCachedMessage(warm.messageOpening),true,"a matching local message raster restores as a warm preview");
  assert.equal(warm.messagePreview.image.className,"cachedMessageBubbles");
  const initialAxes=fixture();initialAxes.activeView="messages";
  const emptyAxesKey=initialAxes.messageCacheView();
  initialAxes.$("msgXAxis").value="timestamp";initialAxes.$("msgYAxis").value="activity";
  assert.equal(initialAxes.messageCacheView(),emptyAxesKey,"an early cache lookup uses the same default axis values as the first live render");

  console.log("chart cache and delta UI regressions passed");
}

run().catch(error => { console.error(error); process.exitCode = 1; });
