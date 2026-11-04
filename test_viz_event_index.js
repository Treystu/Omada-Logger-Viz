"use strict";
// Focused browser fixture for the event-index UI. Run with: node test_viz_event_index.js
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const html = fs.readFileSync("viz.html", "utf8");
process.env.TZ = "America/New_York";

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

for (const id of ["btnEventIndex", "eventIndexPanel", "eventIdxAll", "eventIdxDhcp", "eventIdxQ", "eventIdxIp", "eventIdxMac", "eventIdxActivity", "eventIdxSender", "eventIdxSince", "eventIdxUntil", "eventIdxSort", "eventIdxOlder"])
  assert.match(html, new RegExp('id="' + id + '"'), "event index includes " + id);
assert.match(html, /function openEvents\(\)/, "legacy retained raw browser remains available");
assert.match(html, /fetch\("\/api\/events"/, "legacy raw browser keeps its existing endpoint");
assert.match(html, /fetch\("\/api\/recorded-events\?"/, "search index uses the local recorded-event endpoint");
assert.match(html, /Historical coverage begins at the oldest retained backfill record/, "coverage boundary is explicit");
assert.match(html, /observed allocation events, not a view of current leases/, "DHCP view avoids claiming current lease state");
assert.match(html, /does not add them to dashboard aggregates/, "event browsing is explicitly excluded from aggregate counts");
assert.match(functionSource("renderEventIndexRows"), /\.textContent\s*=/, "untrusted event data uses textContent");
assert.doesNotMatch(functionSource("renderEventIndexRows"), /\.innerHTML\s*=/, "event payloads are never inserted as HTML");

const controls = Object.create(null);
function control(id, value) {
  if (!controls[id]) controls[id] = {value: value || "", disabled: false, validity:{badInput:false}, style: {}, classList: {toggle(){}}, textContent: ""};
  return controls[id];
}
control("eventIdxQ", "DHCP <script>"); control("eventIdxIp", "192.0.2.9");
control("eventIdxMac", "AA:BB:CC:DD:EE:FF"); control("eventIdxActivity", "dhcp_allocation");
control("eventIdxSender", "gateway"); control("eventIdxSince", "2026-11-01T10:00");
control("eventIdxUntil", "2026-11-02T10:00"); control("eventIdxSort", "received_at_asc"); control("eventIdxTimeError", "");
const filterCtx = {$:control, eventIndexKind:"dhcp", URLSearchParams, Date};
vm.createContext(filterCtx);
vm.runInContext(functionSource("parseLocalDateTime"), filterCtx);
vm.runInContext(functionSource("localDateTimeIso"), filterCtx);
vm.runInContext(functionSource("eventIndexFilterQuery"), filterCtx);
const filterParams = new URLSearchParams(filterCtx.eventIndexFilterQuery().toString());
assert.equal(filterParams.get("type"), "dhcp");
assert.equal(filterParams.get("ip"), "192.0.2.9");
assert.equal(filterParams.get("mac"), "AA:BB:CC:DD:EE:FF");
assert.equal(filterParams.get("activity"), "dhcp_allocation");
assert.equal(filterParams.get("sender"), "gateway");
assert.equal(filterParams.get("since"), new Date(2026,10,1,10,0).toISOString());
assert.equal(filterParams.get("until"), new Date(2026,10,2,10,0,59,999).toISOString().replace(/Z$/, "999Z"));
assert.match(filterParams.get("since"), /Z$/, "local history start is serialized as an absolute UTC instant");
assert.match(filterParams.get("until"), /\.999999Z$/, "inclusive history end covers the final SQLite microsecond");
assert.equal(filterParams.get("sort"), "received_at_asc");
control("eventIdxSince").value = "2025-11-02T01:30";
control("eventIdxUntil").value = "";
assert.equal(filterCtx.eventIndexFilterQuery(), null, "ambiguous fall-back wall time blocks event-index serialization");
assert.match(control("eventIdxTimeError").textContent, /occurs twice/i, "ambiguous history bound is explained");
control("eventIdxSince").value = "";
control("eventIdxSince").validity.badInput = true;
assert.equal(filterCtx.eventIndexFilterQuery(), null, "incomplete native history time blocks the request");
assert.match(control("eventIdxTimeError").textContent, /complete local date and time/i, "incomplete history bound is explained");
control("eventIdxSince").validity.badInput = false;
control("eventIdxSince").value = "2026-02-30T10:00";
assert.equal(filterCtx.eventIndexFilterQuery(), null, "invalid event-index local time blocks the request instead of broadening it");
assert.match(control("eventIdxTimeError").textContent, /invalid|does not exist/i, "invalid event-index time is explained beside the control");

const statusCtx = {};
vm.createContext(statusCtx);
vm.runInContext(functionSource("eventIndexBytes"), statusCtx);
vm.runInContext(functionSource("eventIndexStatusText"), statusCtx);
assert.match(statusCtx.eventIndexStatusText({state:"unavailable"}, 0), /does not mean there are no events/);
assert.match(statusCtx.eventIndexStatusText({state:"backfilling",oldest_retained_at:"2026-10-31T00:00:00Z",legacy_state:"running",legacy_imported_bytes:1024,legacy_total_bytes:2048}, 0), /backfilling/i);
const retainedStatus = statusCtx.eventIndexStatusText({state:"ready",oldest_retained_at:"2026-10-31T00:00:00Z",evicted_count:4,retention_target_bytes:500*1024*1024}, 7);
assert.match(retainedStatus, /coverage begins at the oldest retained backfill record/);
assert.match(retainedStatus, /500\.0 MiB.*not a hard disk cap.*WAL files and backfill snapshots/);
assert.match(statusCtx.eventIndexStatusText({state:"ready"}, 1), /retention target is unavailable/);
assert.match(statusCtx.eventIndexStatusText({state:"degraded",write_error:"disk full"}, 2), /degraded.*disk full/i);

class FixtureNode {
  constructor(tag) { this.tagName = tag; this.children = []; this._text = ""; this.className = ""; }
  set textContent(value) { this.children = []; this._text = String(value); }
  get textContent() { return this._text + this.children.map(n => n.textContent).join(""); }
  appendChild(child) { this.children.push(child); return child; }
}
const list = new FixtureNode("div");
const renderCtx = {$(id){ assert.equal(id,"eventIndexList"); return list; }, document:{createElement(tag){ return new FixtureNode(tag); }},
  eventIndexTime(e){return e.timestamp || e.received_at || "time unavailable";},
  eventIndexActivity(e){return typeof e.activity === "string" ? e.activity : e.activity && (e.activity.label || e.activity.id) || "unknown activity";},
  eventIndexRaw(e){const r=e.raw !== undefined ? e.raw : e.source_event; return typeof r === "string" ? r : JSON.stringify(r,null,2);}};
vm.createContext(renderCtx);
vm.runInContext(functionSource("renderEventIndexRows"), renderCtx);
renderCtx.renderEventIndexRows([{id:"1",timestamp:"2026-11-02T10:00:00Z",sender:"<img src=x>",activity:"unknown",ip:"not an IP",mac:"bad",parse_status:"malformed",raw:"<script>literal record</script>"}]);
assert.equal(list.children.length, 1, "malformed and unknown records remain visible");
assert.match(list.textContent, /<script>literal record<\/script>/, "original payload is preserved literally");
assert.match(list.textContent, /<img src=x>/, "hostile sender text is rendered as text");
assert.equal(list.children[0].tagName, "article");

async function verifyAvailabilityState(state, expected) {
  control("eventIdxSince").value = ""; control("eventIdxUntil").value = "";
  const statusHost = {firstChild:{textContent:""}};
  const note = {textContent:""};
  const resultList = new FixtureNode("div");
  const apiCtx = {
    eventIndexKind:"all", eventIndexCursor:null, eventIndexLoading:false, URLSearchParams, Date,
    $ (id) {
      if (id === "eventIndexStatus") return statusHost;
      if (id === "eventIndexNote") return note;
      if (id === "eventIndexList") return resultList;
      if (id === "eventIdxTimeError") return {textContent:""};
      return control(id);
    },
    document:{createElement(tag){ return new FixtureNode(tag); }},
    fetch(){ return Promise.resolve({ok:true,status:200,json(){return Promise.resolve({status:{state},events:[]});}}); }
  };
  vm.createContext(apiCtx);
  for (const name of ["parseLocalDateTime", "localDateTimeIso", "eventIndexFilterQuery", "eventIndexBytes", "eventIndexStatusText", "eventIndexTime", "eventIndexActivity", "eventIndexRaw", "renderEventIndexRows", "setEventIndexBusy", "loadEventIndex"])
    vm.runInContext(functionSource(name), apiCtx);
  apiCtx.loadEventIndex(null);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(statusHost.firstChild.textContent, expected, state + " remains visibly distinct from an empty result");
  assert.equal(resultList.children.length, 0);
  assert.doesNotMatch(statusHost.firstChild.textContent, /0 matching records/);
}

(async () => {
  await verifyAvailabilityState("unavailable", /unavailable.*does not mean there are no events/i);
  await verifyAvailabilityState("backfilling", /backfilling.*results may be incomplete/i);
  console.log("event-index UI fixture passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
