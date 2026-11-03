"use strict";
const assert=require("node:assert/strict");
const {matches,eventLabel,actorLabel}=require("../src/rabbitwall/static/audit-view.js");
const entry={event:"domain-request",id:"a".repeat(32),source:"10.1.0.10",domains:["EXAMPLE.com"],purpose:"依存取得",actor:{channel:"agent"}};
assert(matches(entry,"example.COM","",false));
assert(matches(entry,"依存","",false));
assert(matches(entry,"エージェント","",false));
assert(!matches(entry,"other.example","",false));
assert(!matches(entry,"","domain-revoke",false));
assert(!matches(entry,"","",true));
assert(matches({event:"control-operation",action:"revoke_domain_request",outcome:"failure"},"自己取消し","",true));
for(const excluded of [{event:"controller-failure"},{event:"controller-start"},{event:"save_nodes"},
  {event:"control-operation",action:"save_nodes",outcome:"failure"},
  {event:"control-operation",action:"revoke_domain_request",outcome:"started"},
  {event:"control-operation",action:"revoke_domain_request",outcome:"success"}]) assert(!matches(excluded,"","",false));
for(const event of ["domain-request-decision","domain-revoke","domain-ended","enable","disable","gate-ended"]) assert(matches({event},"","",false));
assert.equal(actorLabel({}),"システム");
assert.equal(eventLabel({event:"domain-revoke"}),"取消し");
console.log("Audit filtering and labels passed");
