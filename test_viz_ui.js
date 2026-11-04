"use strict";
// Focused UI regressions. Run with: node test_viz_ui.js
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
process.env.TZ = "America/New_York";

const html = fs.readFileSync("viz.html", "utf8");
function functionSource(name) {
  const start = html.indexOf("function " + name + "(");
  assert.notEqual(start, -1, "missing function " + name);
  const brace = html.indexOf("{", start);
  let depth = 0, quote = null, escaped = false;
  for (let i = brace; i < html.length; i++) {
    const c = html[i];
    if (quote) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === "\"" || c === "'" || c === "`") { quote = c; continue; }
    if (c === "{") depth++;
    if (c === "}" && --depth === 0) return html.slice(start, i + 1);
  }
  throw new Error("unterminated function " + name);
}

assert.match(html, /fill\("selY", AXES, "dpt"\)/, "initial Y axis is destination port");
assert.match(html, /\$\("selY"\)\.value = "dpt";/, "reset restores destination port");
assert.match(html, /function setView\(view\)/, "scatter and message views are switchable");
assert.match(html, /MESSAGE_BUBBLE_LIMIT = 250/, "the bubble view bounds its rendered pattern count");
assert.match(html, /id="msgSearch"/, "all patterns can be searched");
assert.match(html, /id="msgSeverity"/, "patterns can be filtered by severity");
assert.match(html, /item\.setAttribute\("aria-label",g\.activity\.label/, "untrusted pattern text is exposed as an accessible label");
for (const controlId of ["selX","selY","selYS","chkFlipY","selC","selS","fSrc","fSrcNot","fDst","fDstNot","fPortIn","fPortNot","fType","fDs","fMin","fFrom","fTo","fCap","chkAuto"])
  assert.match(html, new RegExp('<label for="' + controlId + '">'), "main filter label is associated with " + controlId);
assert.match(html, /panel\.textContent=JSON\.stringify\(details,null,2\)/, "full hover details are inserted as text");
assert.match(html, /label\.textContent=a\.label/, "activity legend labels are inserted as text");
assert.match(functionSource("messageDetailData"), /activity_observed_in_recent_raw_records/, "details label raw values as activity-wide observations");
assert.match(functionSource("messageDetailData"), /raw_observed_values_for_variant:g\.rawValues/, "variant raw observations remain distinct from activity-wide observations");
assert.match(functionSource("messageDetailData"), /sample_candidates:g\.sampleCandidates/, "sample-derived candidates remain in full details");
assert.match(html, /Aggregate samples show examples, not complete historical variance/, "aggregate examples do not claim full history");
assert.match(html, /Condensed aggregates provide lifetime counts/, "tally counts are explicitly labeled lifetime counts");
assert.match(html, /do not calculate exact in-range event counts/, "time filtering does not imply exact in-range aggregate counts");
assert.match(html, /Circle area is proportional to/, "bubble encoding states that circle area follows record count");
assert.match(html, /no time or causal axis/i, "packed positions disclose their non-temporal meaning");
assert.match(html, /up to \" \+ MESSAGE_BUBBLE_LIMIT \+ \" variants per page/, "coverage states the current page limit");
assert.match(html, /raw_observed_values_for_variant:g\.rawValues/, "hover details include all available variant raw values");
assert.match(html, /records:g\.records/, "hover details include the underlying records");
assert.match(html, /messageHoverDetails.*role=\"region\"/s, "hover detail panel is an accessible region");
assert.match(html, /if\(focusPanel&&hoverOwner\).*hoverOwner\.focus\(\)/s, "Escape closes the hover panel and restores mark focus");
assert.match(functionSource("setView"), /closeMessageHover\(\);/, "leaving Messages closes the hover detail panel");
assert.match(html, /tabindex=\"0\"/, "full hover details can receive keyboard focus");
assert.match(html, /ev\.key===\"ArrowDown\".*messageHoverDetails.*\.focus\(\)/s, "ArrowDown moves from a mark into the scrollable hover details");
assert.match(html, /messageHoverDetails\{[^}]*box-sizing:border-box/s, "hover panel sizing includes padding and border");
assert.match(html, /showMessageDetails\(g,count,sevSelect\.value,grouped,useTally,rawRedacted\);/, "activating a bubble retains the full drawer action");
assert.match(html, /querySelector\(\"button\"\)\.focus\(\)/, "opening the drawer focuses its close control");
assert.doesNotMatch(functionSource("renderMessageBubbles"), /item\.title=/, "native title does not compete with the detail panel");
assert.match(html, /messagePackLayout\(packItems,hostWidth,hostHeight\)/, "packed marks use measured responsive dimensions");
assert.match(html, /activityLegend.*slice\(0,10\)/s, "activity legend caps visible categories and summarizes the rest");
assert.match(html, /messagePackLayout/, "bubbles use packed positions instead of rows");
assert.match(html, /addEventListener\("mouseenter",function\(\)\{showMessageHover/, "pointer hover opens the full details panel");
assert.match(html, /addEventListener\("focus",function\(\)\{if\(!messageHoverSuppressFocus\)showMessageHover/, "keyboard focus opens the full details panel");
assert.match(html, /addEventListener\("click",function\(\)\{showMessageDetails/, "click keeps the existing details drawer action");
assert.match(functionSource("showMessageHover"), /panel\.textContent=JSON\.stringify/, "hover content uses a safe text sink");
assert.doesNotMatch(functionSource("showMessageHover"), /innerHTML/, "untrusted message data is never inserted as markup in the hover panel");
assert.match(html, /setAttribute\("aria-label",g\.activity\.label/, "bubble detail buttons have readable keyboard labels");
assert.match(html, /Exact timestamps from raw message events/, "time view labels itself as raw timestamp data");
assert.match(html, /up to 20,000 raw log lines by default/, "time view states the retained raw-tail coverage");
assert.match(html, /Historical tallies do not contain complete per-event times/, "time view does not infer event times from aggregates");
assert.match(html, /cell\.setAttribute\("role","img"\); cell\.setAttribute\("tabindex","0"\)/, "time buckets can be inspected with the keyboard");
assert.match(html, /box-sizing:border-box;border:1px solid rgba\(255,255,255,\.58\);border-radius:50%/, "packed circle diameter includes its border");
assert.match(html, /messageTimeBucket:focus-visible \.messageTimeTip\{display:block\}/, "focused time buckets show their value tooltip");
assert.match(html, /id="msgModeRanked"/, "ranked view is exposed beside bubbles");
assert.match(html, /id="msgModeTime"/, "time view is exposed beside bubbles");
assert.match(functionSource("renderMessageBubbles"), /messagePageSlice\(keys, messagePage, MESSAGE_BUBBLE_LIMIT\)/, "all presentations share the same variant pagination");
assert.match(functionSource("renderMessageBubbles"), /renderMessageTimeSeries\(timeHost, groups, keys, sevSelect\.value/, "time mode uses the same groups, page, and severity measure");
assert.match(html, /detailBody"\)\.textContent = JSON\.stringify/, "details use textContent");
assert.doesNotMatch(functionSource("buildMessageGroups"), /(?:data\.(?:entries|raw)|g\.records)\.indexOf\(/, "message grouping avoids repeated array identity scans");

const sourceEntryA = {type:"msg", template:"<img src=x onerror=alert(1)>", sev:3, count:4, sample:"full A", occurrences:["t1"],activity:{id:"dhcp",label:"DHCP allocation",variables:{ip:"192.0.2.10"},sample_only:true,coverage:"single_sample"},candidates:[{kind:"ip",value:"192.0.2.10"}],candidates_provenance:{sample_only:true,coverage:"single_sample"}};
const sourceEntryB = {type:"msg", template:"<img src=x onerror=alert(1)>", sev:6, count:2, sample:"full B", occurrences:["t2"],activity:{id:"dhcp",label:"DHCP allocation",variables:{ip:"192.0.2.11"},sample_only:true,coverage:"single_sample"},candidates:[{kind:"ip",value:"192.0.2.11"}],candidates_provenance:{sample_only:true,coverage:"single_sample"}};
const raw = {type:"msg", ts:"t3", src:"sender", sev:3, label:"<script>literal</script>", message:"<script>literal</script>",activity:{id:"dhcp",label:"DHCP allocation",variables:{ip:"192.0.2.12",mac:"aa:bb:cc:dd:ee:ff"},sample_only:false,coverage:"observed_message"},candidates:[{kind:"ip",value:"192.0.2.12"},{kind:"mac",value:"00:11:22:33:44:55"}]};
const tallyPoints = [
  {type:"msg", ds:"tally", ref:sourceEntryA}, {type:"msg", ds:"tally", ref:sourceEntryA},
  {type:"msg", ds:"tally", ref:sourceEntryB}, {type:"msg", ds:"raw", ref:raw, message:raw.message}
];
const context = {data:{entries:[sourceEntryA,sourceEntryB],raw:[raw]}, $(id){ return {value:"both"}; }};
context.messageIndexCache = new WeakMap();
vm.createContext(context);
vm.runInContext(functionSource("firstMessageIndexMap"), context);
vm.runInContext(functionSource("activityForMessage"), context);
vm.runInContext(functionSource("addActivityValue"), context);
vm.runInContext(functionSource("buildMessageGroups"), context);
vm.runInContext(functionSource("messageRawSupplement"), context);
let grouped = context.buildMessageGroups(tallyPoints, true, [tallyPoints[3],tallyPoints[3]]);
let sameTemplate = grouped.groups["dhcp\u0000" + sourceEntryA.template];
assert.equal(grouped.total, 6, "condensed is authoritative and raw overlap is not double counted");
assert.equal(sameTemplate.count, 6, "each condensed aggregate contributes once despite expanded timestamps");
assert.deepEqual(JSON.parse(JSON.stringify(sameTemplate.severity)), {"3":4,"6":2}, "severity remains independently visible");
assert.equal(sameTemplate.records.length, 2, "full condensed records remain available for drilldown");
assert.deepEqual(Object.keys(sameTemplate.rawValues.ip), ["192.0.2.12"], "overlapping raw records add an observed value once without changing tally count");
assert.deepEqual(Object.keys(sameTemplate.rawValues["candidate mac"]), ["00:11:22:33:44:55"], "unknown candidate roles are labeled as candidates");
assert.equal(sameTemplate.rawValues["candidate ip"], undefined, "candidate values already shown under a labeled activity field are not duplicated");
assert.equal(sameTemplate.activity.sampleOnly, true, "aggregate variables retain sample-only provenance");
assert.deepEqual(Object.keys(sameTemplate.sampleValues.ip).sort(), ["192.0.2.10","192.0.2.11"], "same-template aggregate rows expose distinct sample values");
assert.equal(Object.keys(sameTemplate.sampleCandidates).length, 0, "sample candidates already shown under a labeled activity variable are not duplicated");

const datasetControl = {value:"tally"}; let rawFilterCalls = 0;
const tallyOnlyRaw = context.messageRawSupplement(datasetControl, function(){ rawFilterCalls++; return tallyPoints.filter(p => p.ds === "raw"); });
assert.equal(rawFilterCalls, 0, "tally-only mode does not run a raw supplemental query");
assert.deepEqual(Array.from(tallyOnlyRaw), [], "tally-only mode has no raw observations to search");
const tallyOnlyGroups = context.buildMessageGroups(tallyPoints.filter(p => p.ds === "tally"), true, tallyOnlyRaw);
const tallyOnlyVariant = tallyOnlyGroups.groups["dhcp\u0000" + sourceEntryA.template];
assert.equal(Object.keys(tallyOnlyVariant.rawValues).length, 0, "tally-only groups do not expose raw-tail values");
datasetControl.value = "both";
const bothRaw = context.messageRawSupplement(datasetControl, function(){ rawFilterCalls++; return tallyPoints.filter(p => p.ds === "raw"); });
assert.equal(datasetControl.value, "both", "supplement query restores the selected dataset");
assert.equal(rawFilterCalls, 1, "tallies + raw mode queries the raw supplement once");
assert.equal(bothRaw.length, 1, "tallies + raw mode includes recent raw observations");
const bothGroups = context.buildMessageGroups(tallyPoints.filter(p => p.ds === "tally"), true, bothRaw);

const roamA = {type:"msg",template:"roaming client <MAC>",sev:4,count:3,activity:{id:"client_roaming",label:"Client roaming",variables:{client:"11:22"},sample_only:true}};
const roamB = {type:"msg",template:"roaming client <MAC> to AP <MAC>",sev:4,count:2,activity:{id:"client_roaming",label:"Client roaming",variables:{client:"33:44"},sample_only:true}};
const roamRaw = {type:"msg",message:"roaming client 55:66",activity:{id:"client_roaming",label:"Client roaming",variables:{client:"55:66",ssid:"guest"}}};
context.data = {entries:[roamA,roamB],raw:[roamRaw]};
const splitActivities = context.buildMessageGroups([{type:"msg",ds:"tally",ref:roamA},{type:"msg",ds:"tally",ref:roamB}],true,[{type:"msg",ds:"raw",ref:roamRaw,message:roamRaw.message}]);
assert.equal(Object.keys(splitActivities.groups).length, 2, "activity ID and template define each variant");
assert.equal(splitActivities.total, 5, "supplemental raw records never change condensed counts");
assert.equal(splitActivities.activityRawValues.client_roaming.client["55:66"], 1, "raw activity values are counted once across multiple template variants");
assert.equal(splitActivities.activityRawValues.client_roaming.ssid.guest, 1, "raw activity-wide frequencies count raw records, not variant matches");
const unknownOne = {type:"msg",template:"unknown line A",sev:3,count:2,activity:{id:"unknown",label:"Unknown activity",sample_only:true,coverage:"single_sample",variables:{}},candidates:[{kind:"ip",value:"203.0.113.77"}],candidates_provenance:{sample_only:true,coverage:"single_sample"}};
const unknownTwo = {type:"msg",template:"unknown line B",sev:3,count:1,activity:{id:"unknown",label:"Unknown activity"}};
context.data = {entries:[unknownOne,unknownTwo],raw:[]};
const unknownGroups = context.buildMessageGroups([{type:"msg",ds:"tally",ref:unknownOne},{type:"msg",ds:"tally",ref:unknownTwo}],true);
assert.equal(Object.keys(unknownGroups.groups).length, 2, "unknown events fall back to separate conservative template clusters");
assert.deepEqual(Object.keys(unknownGroups.groups["unknown:unknown line A\u0000unknown line A"].sampleCandidates["candidate ip"]), ["203.0.113.77"], "unknown aggregate samples retain candidate values with sample-only provenance");

// Scale regression: precomputed maps preserve first-index and duplicate-reference semantics.
const scaleEntries = Array.from({length:50000}, (_,i) => ({type:"msg",template:"same <IP>",count:1,sev:3,activity:{id:"large_activity",label:"Large activity",sample_only:true,variables:{ip:"192.0.2." + (i % 254 + 1)}}}));
scaleEntries.push(scaleEntries[0]);
const scaleRaw = Array.from({length:20000}, (_,i) => ({type:"msg",message:"raw " + i,sev:3,activity:{id:"large_activity",label:"Large activity",variables:{ip:"203.0.113." + (i % 254 + 1)}}}));
scaleRaw.push(scaleRaw[0]);
scaleEntries.indexOf = () => { throw new Error("linear entry index scan"); };
scaleRaw.indexOf = () => { throw new Error("linear raw index scan"); };
const scaleContext = {data:{entries:scaleEntries,raw:scaleRaw},messageIndexCache:new WeakMap(),$(id){return {value:"both"};}};
vm.createContext(scaleContext);
for (const helper of ["firstMessageIndexMap","activityForMessage","addActivityValue","buildMessageGroups"]) vm.runInContext(functionSource(helper), scaleContext);
assert.equal(scaleContext.firstMessageIndexMap(scaleEntries).get(scaleEntries[0]), 0, "duplicate entry ref resolves to its first array index");
assert.equal(scaleContext.firstMessageIndexMap(scaleRaw).get(scaleRaw[0]), 0, "duplicate raw ref resolves to its first array index");
const scaleTallyPoints = [];
for (let i=0;i<50000;i+=50) scaleTallyPoints.push({type:"msg",ds:"tally",ref:scaleEntries[i]});
scaleTallyPoints.push(scaleTallyPoints[0]);
const scaleSupplement = [];
for (let i=0;i<20000;i+=20){ const point={type:"msg",ds:"raw",ref:scaleRaw[i],message:scaleRaw[i].message}; scaleSupplement.push(point,point); }
const scaleGrouped = scaleContext.buildMessageGroups(scaleTallyPoints,true,scaleSupplement);
const scaleVariant = scaleGrouped.groups["large_activity\u0000same <IP>"];
assert.equal(scaleGrouped.total, 1000, "large tally set counts each selected aggregate once");
assert.equal(scaleVariant.records.length, 1000, "large group retains one record per unique aggregate reference");
assert.equal(Object.values(scaleGrouped.activityRawValues.large_activity.ip).reduce((n,count)=>n+count,0), 1000, "duplicated raw supplement refs count once across variants");

context.$ = () => ({value:"both"});
grouped = context.buildMessageGroups([{type:"msg",ds:"raw",ref:raw,message:raw.message}], false);
assert.equal(grouped.total, 1, "raw-only fallback counts each raw record once");
assert.ok(grouped.groups["dhcp\u0000" + raw.message], "raw fallback groups by activity and literal message text");

vm.runInContext(functionSource("filterMessagePatternKeys"), context);
assert.deepEqual(Array.from(context.filterMessagePatternKeys(Object.keys(tallyOnlyGroups.groups), tallyOnlyGroups.groups, "192.0.2.12", "")), [], "tally-only search excludes raw-only observed values");
assert.equal(context.filterMessagePatternKeys(Object.keys(bothGroups.groups), bothGroups.groups, "192.0.2.12", "").length, 1, "both-source search includes supplemental raw observations");
vm.runInContext(functionSource("messagePageSlice"), context);
vm.runInContext(functionSource("messageCountFor"), context);
vm.runInContext(functionSource("messageActivitySummary"), context);
const manyGroups = Object.create(null), manyKeys = [];
let expectedCount = 0;
for (let i = 0; i < 503; i++) {
  const key = "pattern-" + String(i).padStart(3, "0");
  manyKeys.push(key);
  manyGroups[key] = {pattern:key,activity:{label:"Activity",id:"activity",variables:{}},count:i + 1, severity:{[i % 2 ? "3" : "6"]:i + 1}};
  expectedCount += i + 1;
}
assert.equal(expectedCount, 126756, "all 503 grouped totals are retained");
const searched = context.filterMessagePatternKeys(manyKeys, manyGroups, "pattern-49", "3");
assert.deepEqual(Array.from(searched), ["pattern-491", "pattern-493", "pattern-495", "pattern-497", "pattern-499"]);
assert.equal(Array.from(searched).reduce((n,key) => n + manyGroups[key].count, 0), 2480,
  "search and severity filtering preserve exact counts for matching patterns");
const allPages = [];
const firstPageKeys = context.messagePageSlice(manyKeys,0,250).keys;
const secondPageKeys = context.messagePageSlice(manyKeys,1,250).keys;
const firstActivitySummary = context.messageActivitySummary(manyGroups,manyKeys,firstPageKeys,"").activity;
const secondActivitySummary = context.messageActivitySummary(manyGroups,manyKeys,secondPageKeys,"").activity;
assert.equal(firstActivitySummary.total, expectedCount, "bubble activity total includes matching variants on every page");
assert.equal(secondActivitySummary.total, expectedCount, "ranked activity total remains consistent on later pages");
assert.equal(firstActivitySummary.variants,503);
assert.equal(firstActivitySummary.pageVariants,250);
assert.equal(secondActivitySummary.pageVariants,250);
for (let page = 0; page < 3; page++) {
  const slice = context.messagePageSlice(manyKeys, page, 250);
  allPages.push(...Array.from(slice.keys));
}
assert.equal(allPages.length, 503, "paging makes every pattern reachable");
assert.equal(new Set(allPages).size, 503, "paging has no repeated or skipped pattern keys");
assert.equal(context.messagePageSlice(manyKeys, 99, 250).page, 2, "page index clamps after filtering shrinks results");
const mixedSeverity = {count:6,severity:{"3":4,"6":2}};
assert.equal(context.messageCountFor(mixedSeverity, "3"), 4, "severity selection counts only severity 3 records");
assert.equal(context.messageCountFor(mixedSeverity, "6"), 2, "severity selection counts only severity 6 records");

// Reproduce scatter cap state followed by the message view's cap bypass.
const controls = {};
const filterValues = {fSrc:"",fDst:"",fSrcNot:"",fDstNot:"",fPortIn:"",fPortNot:"",fMin:"0",fType:"both",fDs:"both",fFrom:"",fTo:"",fCap:"1",
  chkDirInt:true,chkDirOut:true,chkDirIn:true,chkDirOth:true};
const capContext = {
  allPoints:[1,2,3].map(i => ({src:"a",dst:"b",dpt:1,dir:"other",count:i,type:"msg",ds:"tally",ts:"2026-01-01",ref:{}})),
  legendDrill:null,capped:false,$(id){return {value:filterValues[id] === undefined ? "" : filterValues[id],checked:filterValues[id] === true};},
  parsePortList(){return [];},parseIPFilter(){return null;},portMatch(){return false;}
};
vm.createContext(capContext);
vm.runInContext(functionSource("parseLocalDateTime"), capContext);
vm.runInContext(functionSource("applyFilters"), capContext);
assert.equal(capContext.applyFilters(false).length, 1, "scatter respects the point cap");
assert.equal(capContext.capped, true);
assert.equal(capContext.applyFilters(true).length, 3, "message grouping bypasses the scatter point cap");
assert.equal(capContext.capped, true, "message cap bypass leaves scatter cap status untouched");
capContext.allPoints.push({src:"a",dst:null,dpt:null,dir:"other",count:1,type:"msg",ds:"raw",ts:"2026-01-01",ref:{}});
filterValues.fMin = "2";
filterValues.fCap = "500000";
const minCountPoints = capContext.applyFilters(false);
assert.deepEqual(Array.from(minCountPoints, p => p.ds + ":" + p.count), ["tally:2", "tally:3", "raw:1"],
  "minimum count filters tally records only and keeps raw records");

// Local datetime filters compare actual instants, include their displayed end precision,
// and are shared by scatter and message-count filtering.
const timeValues = {fSrc:"",fDst:"",fSrcNot:"",fDstNot:"",fPortIn:"",fPortNot:"",fMin:"0",fType:"both",fDs:"both",fFrom:"",fTo:"",fCap:"500000",
  chkDirInt:true,chkDirOut:true,chkDirIn:true,chkDirOth:true};
const timeError = {textContent:""};
let fromBadInput=false;
const timeContext = {allPoints:[],legendDrill:null,capped:false,$(id){return id === "fTimeError" ? timeError : {value:timeValues[id] === undefined ? "" : timeValues[id],checked:timeValues[id] === true,validity:{badInput:id === "fFrom" && fromBadInput}};},
  parsePortList(){return [];},parseIPFilter(){return null;},portMatch(){return false;}};
vm.createContext(timeContext);
vm.runInContext(functionSource("parseLocalDateTime"), timeContext);
vm.runInContext(functionSource("applyFilters"), timeContext);
const sameInstant = Date.parse("2026-11-03T12:34:00Z");
const localParts = new Date(sameInstant);
const localMinute = [localParts.getFullYear(),String(localParts.getMonth()+1).padStart(2,"0"),String(localParts.getDate()).padStart(2,"0")].join("-") +
  "T" + String(localParts.getHours()).padStart(2,"0") + ":" + String(localParts.getMinutes()).padStart(2,"0");
timeContext.allPoints = [
  {id:"start",ts:"2026-11-03T12:34:00+00:00",ds:"raw",count:1,type:"msg",dir:"other"},
  {id:"offset-equivalent",ts:"2026-11-03T07:34:00-05:00",ds:"tally",count:9,type:"msg",dir:"other"},
  {id:"last-ms",ts:"2026-11-03T12:34:59.999Z",ds:"raw",count:1,type:"msg",dir:"other"},
  {id:"next-minute",ts:"2026-11-03T12:35:00Z",ds:"raw",count:1,type:"msg",dir:"other"},
  {id:"invalid-event",ts:"not-a-time",ds:"raw",count:1,type:"msg",dir:"other"}
];
timeValues.fFrom = localMinute; timeValues.fTo = localMinute;
assert.deepEqual(Array.from(timeContext.applyFilters(true), p => p.id), ["start","offset-equivalent","last-ms"],
  "inclusive minute end includes :00 and :59.999, matches equivalent offsets, and excludes next minute and invalid event times");
assert.equal(timeError.textContent, "", "valid inclusive minute range has no error");
timeValues.fFrom = "";
assert.deepEqual(Array.from(timeContext.applyFilters(false), p => p.id), ["start","offset-equivalent","last-ms"],
  "one-sided end filtering remains inclusive through the selected minute");
timeValues.fTo = ""; timeValues.fFrom = localMinute;
assert.deepEqual(Array.from(timeContext.applyFilters(true), p => p.id), ["start","offset-equivalent","last-ms","next-minute"],
  "one-sided start includes events at or after the chosen minute");
timeValues.fFrom = "2026-02-30T12:34";
assert.deepEqual(Array.from(timeContext.applyFilters(true)), [], "an invalid active filter excludes results instead of broadening the range");
assert.match(timeError.textContent, /invalid|does not exist/i, "invalid filter is surfaced beside the controls");
timeValues.fFrom = "";
assert.equal(timeContext.applyFilters(true).length, 5, "no date filters preserve existing behavior, including invalid event timestamps");
timeValues.fFrom = localMinute; timeValues.fTo = localMinute;
const filteredScatter = timeContext.applyFilters(false);
const filteredMessageCount = timeContext.applyFilters(true).filter(p => p.ds === "raw" || p.ds === "tally").length;
assert.equal(filteredScatter.length, 3, "scatter uses the date-filtered point set");
assert.equal(filteredMessageCount, 3, "message count filtering uses the same date-filtered point set");
assert.equal(timeContext.parseLocalDateTime("2026-03-08T02:30", false).error !== undefined, true,
  "a nonexistent local time during the spring DST jump is rejected");
assert.equal(timeContext.parseLocalDateTime("2025-11-02T01:30", false).error !== undefined, true,
  "a repeated local time during the fall DST transition is rejected as ambiguous");
assert.equal(timeContext.parseLocalDateTime("2025-11-02T00:30", false).error, undefined,
  "an unambiguous time before the fall transition remains valid");
assert.equal(timeContext.parseLocalDateTime("2025-11-02T02:30", false).error, undefined,
  "an unambiguous time after the fall transition remains valid");
fromBadInput=true; timeValues.fFrom="";
assert.deepEqual(Array.from(timeContext.applyFilters(true)), [], "an incomplete native date input does not silently clear the filter");
assert.match(timeError.textContent, /complete local date and time/i, "incomplete native date input is surfaced");
fromBadInput=false;
timeValues.fFrom = ""; timeValues.fTo = localMinute + ":00.12";
timeContext.allPoints = [
  {id:"fraction-start",ts:new Date(new Date(sameInstant).setMilliseconds(120)).toISOString(),ds:"raw",count:1,type:"msg",dir:"other"},
  {id:"fraction-last-ms",ts:new Date(new Date(sameInstant).setMilliseconds(129)).toISOString(),ds:"raw",count:1,type:"msg",dir:"other"},
  {id:"fraction-next-ms",ts:new Date(new Date(sameInstant).setMilliseconds(130)).toISOString(),ds:"raw",count:1,type:"msg",dir:"other"}
];
assert.deepEqual(Array.from(timeContext.applyFilters(true), p => p.id), ["fraction-start","fraction-last-ms"],
  "fractional-second end is inclusive through its displayed hundredth-second precision");

// Verify switching hides/shows the correct view while retaining scatter controls.
const elements = {};
function element(id) {
  return elements[id] || (elements[id] = {style:{}, classList:{toggle(){}}, value:"unchanged"});
}
element("selX");
element("supportRibbon").style.display="block";
const switchContext = {activeView:"scatter", messageSupportRibbonDisplay:null, $:element, rendered:false, fitted:false,
  closeMessageHover(){switchContext.hoverClosed=true;},
  renderMessageBubbles(){switchContext.rendered = true;}, fit(){switchContext.fitted = true;}};
vm.createContext(switchContext);
vm.runInContext(functionSource("setView"), switchContext);
switchContext.setView("messages");
assert.equal(switchContext.activeView, "messages");
assert.equal(switchContext.hoverClosed,true,"view changes close transient hover details");
assert.equal(elements.plot.style.display, "none");
assert.equal(elements.messageView.style.display, "block");
assert.equal(elements.supportRibbon.style.display,"none","support ribbon hides while it could cover packed marks");
assert.equal(elements.selX.value, "unchanged", "view switching preserves scatter configuration");
switchContext.setView("scatter");
assert.equal(elements.plot.style.display, "block");
assert.equal(elements.supportRibbon.style.display,"block","support ribbon restores when returning to scatter");
assert.equal(switchContext.fitted, true);

const resetEls = {};
function resetElement(id) {
  return resetEls[id] || (resetEls[id] = {value:"changed", checked:false, style:{}, classList:{toggle(){}}});
}
const resetContext = {activeView:"messages", $:resetElement, redrawn:false, clearFitCaches(){},
  setView(view){resetContext.activeView=view;}, redrawFromPoints(){resetContext.redrawn=true;},
  related:{}, legendDrill:{}, zoomX:{}, zoomY:{}};
vm.createContext(resetContext);
vm.runInContext(functionSource("resetFilters"), resetContext);
resetContext.resetFilters();
assert.equal(resetEls.selY.value, "dpt", "reset restores the original Y default");
assert.equal(resetContext.activeView, "scatter", "reset all returns to the default scatter view");
assert.equal(resetEls.selX.value, "ts");
assert.equal(resetEls.selC.value, "src");
assert.equal(resetEls.selS.value, "count");

// Raw syslog labels can become the selected spotlight label. Exercise the real
// stats renderer with markup that would execute if inserted as a live element.
const maliciousLabel = '<img src=x onerror=alert(1)>';
let renderedStats = "";
const statsPanel = {style:{}, set innerHTML(value){ renderedStats = value; }};
const statsContext = {
  statsOpen:true,
  points:[{ref:{},count:1,src:"192.0.2.1",dst:null,dpt:null,spt:null,ds:"raw",ap:null,proto:null,dir:"other",type:"msg"}],
  related:{type:"message",label:maliciousLabel}, zoomX:null, zoomY:null, legendDrill:null,
  data:{entries:[],raw:[]},
  $(id){ assert.equal(id,"statsPanel"); return statsPanel; },
  relationOf(){ return 1; }
};
vm.createContext(statsContext);
vm.runInContext(functionSource("escapeHtml"), statsContext);
vm.runInContext(functionSource("fmtInt"), statsContext);
vm.runInContext(functionSource("renderStats"), statsContext);
statsContext.renderStats();
assert.match(renderedStats, /spotlight: &#60;img src=x onerror=alert\(1\)&#62;/,
  "spotlight labels are encoded before entering the stats HTML sink");
assert.doesNotMatch(renderedStats, /<img\b[^>]*onerror/i,
  "raw syslog spotlight labels cannot create an executable image element");

const vizMath = {};
vm.createContext(vizMath);
vm.runInContext(functionSource("messageBubbleDiameter"), vizMath);
vm.runInContext(functionSource("messagePackLayout"), vizMath);
vm.runInContext(functionSource("messageActivityColor"), vizMath);
vm.runInContext(functionSource("messageDetailData"), vizMath);
vm.runInContext(functionSource("messageTimeSeries"), vizMath);
assert.equal(vizMath.messageBubbleDiameter(100,100), 128, "largest bubble gets the shared reference diameter");
assert.equal(vizMath.messageBubbleDiameter(25,100), 64, "quarter count has half the diameter and one quarter the circle area");
const pack250Items=Array.from({length:250},(_,i)=>({key:"k"+i,count:i+1,activityId:"activity-"+Math.floor(i/25)}));
const packed250=vizMath.messagePackLayout(pack250Items,900,520);
assert.equal(packed250.length,250,"the full current 250-variant page is laid out");
assert.deepEqual(JSON.parse(JSON.stringify(packed250)),JSON.parse(JSON.stringify(vizMath.messagePackLayout(pack250Items,900,520))),"packed layout is deterministic");
for(let i=0;i<packed250.length;i++){
  const a=packed250[i];
  assert.ok(a.x-a.r>=-1e-7 && a.y-a.r>=-1e-7 && a.x+a.r<=900+1e-7 && a.y+a.r<=520+1e-7,"packed circle stays within the field");
  for(let j=0;j<i;j++){const b=packed250[j],gap=Math.hypot(a.x-b.x,a.y-b.y)-(a.r+b.r);assert.ok(gap>=-1e-6,"packed circles do not overlap: "+i+" / "+j+" gap="+gap);}
}
const scaledPack=vizMath.messagePackLayout([{key:"large",count:100,activityId:"a"},{key:"small",count:25,activityId:"b"}],900,520);
const radii=Object.fromEntries(scaledPack.map(p=>[p.item.key,p.r]));
assert.ok(Math.abs(radii.small/radii.large-.5)<1e-9,"uniform fit keeps circle area proportional to count");
const mobilePack=vizMath.messagePackLayout(pack250Items.slice(0,40),180,300);
for(const point of mobilePack)assert.ok(point.x-point.r>=-1e-7&&point.x+point.r<=180+1e-7&&point.y-point.r>=-1e-7&&point.y+point.r<=300+1e-7,"packed circles fit a narrow field");
function bounds(layout){const xs=layout.flatMap(p=>[p.x-p.r,p.x+p.r]),ys=layout.flatMap(p=>[p.y-p.r,p.y+p.r]);return {w:Math.max(...xs)-Math.min(...xs),h:Math.max(...ys)-Math.min(...ys)};}
const equalDesktop=vizMath.messagePackLayout(Array.from({length:250},(_,i)=>({key:"equal"+i,count:1,activityId:"same"})),900,520),desktopBounds=bounds(equalDesktop);
assert.ok(desktopBounds.w>900*.7&&desktopBounds.h>520*.5,"equal-count 250-mark page uses a compact field on desktop: "+JSON.stringify(desktopBounds));
const equalMobile=vizMath.messagePackLayout(Array.from({length:250},(_,i)=>({key:"mobile"+i,count:1,activityId:"same"})),350,300),mobileBounds=bounds(equalMobile);
assert.ok(mobileBounds.w>350*.7&&mobileBounds.h>300*.5,"equal-count 250-mark page remains compact on mobile");
for(const layout of [equalDesktop,equalMobile])for(let i=0;i<layout.length;i++)for(let j=0;j<i;j++)assert.ok(Math.hypot(layout[i].x-layout[j].x,layout[i].y-layout[j].y)+1e-6>=layout[i].r+layout[j].r,"equal-count marks stay non-overlapping");
const skewItems=Array.from({length:250},(_,i)=>({key:"skew"+i,count:i===0?10000:i===1?9000:1+(i*37)%100,activityId:i<220?"large-activity":"other-activity"}));
const skewStart=process.hrtime.bigint(),skewPack=vizMath.messagePackLayout(skewItems,900,520),skewMs=Number(process.hrtime.bigint()-skewStart)/1e6,skewBounds=bounds(skewPack);
assert.ok(skewBounds.w>900*.55&&skewBounds.h>520*.45,"skewed counts fill a meaningful two-dimensional area: "+JSON.stringify(skewBounds));
for(let i=0;i<skewPack.length;i++)for(let j=0;j<i;j++)assert.ok(Math.hypot(skewPack[i].x-skewPack[j].x,skewPack[i].y-skewPack[j].y)+1e-6>=skewPack[i].r+skewPack[j].r,"skewed marks stay non-overlapping");
const skewRadiuses=Object.fromEntries(skewPack.map(p=>[p.item.key,p.r]));
assert.ok(Math.abs(skewRadiuses.skew1/skewRadiuses.skew0-Math.sqrt(.9))<1e-9,"skewed areas remain proportional to record counts");
assert.ok(skewMs<1500,"skewed 250-mark page packs within a bounded time ("+skewMs.toFixed(1)+" ms)");
console.log("250-circle skew pack benchmark: "+skewMs.toFixed(1)+" ms · bounds "+skewBounds.w.toFixed(0)+"×"+skewBounds.h.toFixed(0));
const clusteredPack=vizMath.messagePackLayout(Array.from({length:20},(_,i)=>({key:"g"+i,count:1,activityId:i<10?"a":"b"})),900,520);
const means={};for(const p of clusteredPack){const id=p.item.activityId;(means[id]||(means[id]={x:0,n:0})).x+=p.x;means[id].n++;}const delta=Math.abs(means.a.x/means.a.n-means.b.x/means.b.n);
assert.ok(delta>20,"activity clusters have distinct spatial centers");
const benchmarkStart=process.hrtime.bigint();
vizMath.messagePackLayout(Array.from({length:250},(_,i)=>({key:"same"+i,count:(i%9)+1,activityId:"one-activity"})),900,520);
const packMs=Number(process.hrtime.bigint()-benchmarkStart)/1e6;
assert.ok(packMs<1500,"250 same-activity circles pack within a bounded interactive time ("+packMs.toFixed(1)+" ms)");
console.log("250-circle pack benchmark: "+packMs.toFixed(1)+" ms");
const longPayload="<img src=x onerror=alert(1)>"+"x".repeat(6000), detailRecord={message:longPayload,parsed:{field:longPayload}};
const hoverDetails=vizMath.messageDetailData({activity:{id:"test",label:"<script>bad()</script>",variables:{ip:"192.0.2.1"},sampleOnly:true},pattern:longPayload,count:2,rawValues:{value:{[longPayload]:1}},sampleValues:{ip:{"192.0.2.1":1}},sampleCandidates:{},severity:{"3":2},records:[detailRecord]},2,"",{activityRawValues:{test:{ip:{"192.0.2.1":1}}}},true,false);
assert.equal(hoverDetails.records[0].message,longPayload,"hover data retains complete long underlying payloads");
assert.equal(hoverDetails.raw_observed_values_for_variant.value[longPayload],1,"hover data retains complete raw observations");
assert.equal(JSON.stringify(hoverDetails).includes("<img src=x onerror=alert(1)>"),true,"XSS-like input remains literal data in hover details");
const timeGroups = {
  a:{activity:{id:"dhcp",label:"DHCP"},records:[
    {sev:3,ts:"2026-11-02T10:15:00Z"},{sev:6,ts:"2026-11-02T10:20:00Z"},{sev:3,ts:"invalid"}]},
  b:{activity:{id:"roaming",label:"Roaming"},records:[
    {sev:3,ts:"2026-11-02T11:10:00Z"},{sev:3,ts:"2026-11-02T11:35:00Z"}]}
};
const series = vizMath.messageTimeSeries(timeGroups,["a","b"],"3");
assert.equal(series.events,3,"raw time buckets count exact raw records matching selected severity");
assert.equal(series.missing,1,"unparseable timestamps are reported separately instead of assigned a fake time");
assert.equal(series.activities.dhcp.total,1);
assert.equal(series.activities.roaming.total,2);
assert.deepEqual(Array.from(series.buckets),[Date.parse("2026-11-02T10:00:00Z"),Date.parse("2026-11-02T11:00:00Z")]);
const emptySeries = vizMath.messageTimeSeries({empty:{activity:{id:"empty",label:"Empty"},records:[]}},["empty"],"");
assert.equal(emptySeries.events,0,"time mode has a distinct explicit empty state when no timestamped raw events match");

console.log("viz UI regressions passed");
