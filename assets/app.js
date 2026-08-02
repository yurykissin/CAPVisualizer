/* CAPVisualizer offline viewer. Vanilla JS, no external dependencies. */
(function () {
  "use strict";
  var DATA = window.__CAP_DATA__ || { policies: [], summary: {}, findings: [], delta: null, riskFindings: [], audit: null, compliance: null, test: null, authMethods: null, nameMap: {} };
  function arr(v) { return Array.isArray(v) ? v : (v === null || v === undefined || v === "" ? [] : [v]); }
  var policies = arr(DATA.policies);
  var selected = null;
  var pfilter = { effect: "all", principal: "all", app: "all", cond: "all", grant: "all" };
  var NAMES = DATA.nameMap || {};
  // Resolve a directory GUID (or "type:guid" pair) to a friendly name when known.
  function nm(v) {
    if (v === null || v === undefined || v === "") return v;
    var s = String(v);
    var m = s.match(/^([a-zA-Z]+):(.+)$/);
    if (m && NAMES[m[2]]) return m[1] + ": " + NAMES[m[2]];
    return NAMES[s] || s;
  }

  function el(id) { return document.getElementById(id); }
  // Format an ISO 8601 / UTC timestamp in the viewer's local time zone. Returns
  // the original string unchanged when it is empty or not a parseable date.
  function fmtLocal(iso) {
    if (iso === null || iso === undefined || iso === "") return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toLocaleString();
  }
  // Convert any server-injected timestamp (elements with class "ts" and a
  // data-utc attribute) into local time once the DOM is ready.
  function localizeStamps() {
    document.querySelectorAll(".ts[data-utc]").forEach(function (n) {
      var v = n.getAttribute("data-utc");
      if (v) n.textContent = fmtLocal(v);
    });
  }
  // Localize a value that looks like a single ISO 8601 timestamp; otherwise
  // return it unchanged (used for field-level diff values).
  function fmtMaybeDate(v) {
    if (v !== null && v !== undefined && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(String(v))) {
      return fmtLocal(v);
    }
    return v;
  }
  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function list(v) {
    var a = arr(v).filter(function (x) { return x !== null && x !== undefined && x !== ""; });
    return a.length ? a.map(esc).join("<br>") : '<span class="muted">-</span>';
  }
  // Like list(), but resolves each entry through the name map first.
  function listNames(v) {
    var a = arr(v).filter(function (x) { return x !== null && x !== undefined && x !== ""; });
    return a.length ? a.map(function (x) { return esc(nm(x)); }).join("<br>") : '<span class="muted">-</span>';
  }
  // Collapsible name list: shows a few entries, hides the rest behind a toggle.
  function listNamesCollapsible(v, shown) {
    var a = arr(v).filter(function (x) { return x !== null && x !== undefined && x !== ""; });
    if (!a.length) return '<span class="muted">-</span>';
    var n = shown || 5;
    var names = a.map(function (x) { return esc(nm(x)); });
    if (names.length <= n) return names.join("<br>");
    var head = names.slice(0, n).join("<br>");
    var rest = names.slice(n).join("<br>");
    return head + '<details class="affmore"><summary>Show ' + (names.length - n) +
      ' more</summary>' + rest + "</details>";
  }
  function stateClass(s) {
    if (s === "enabled") return "enabled";
    if (s === "enabledForReportingButNotEnforced") return "report";
    return "disabled";
  }
  function stateLabel(s) {
    if (s === "enabledForReportingButNotEnforced") return "report-only";
    return s;
  }

  // ---- Per-policy faceted filtering ----------------------------------------
  var PRINC_MAP = {
    User: ["includeUsers", "excludeUsers"],
    Group: ["includeGroups", "excludeGroups"],
    Role: ["includeRoles", "excludeRoles"]
  };
  var SEP = "\u0000";
  function princRefs(p, type, side) { return arr(p[PRINC_MAP[type][side === "inc" ? 0 : 1]]); }
  function princAll(p, side) {
    return princRefs(p, "User", side).concat(princRefs(p, "Group", side), princRefs(p, "Role", side));
  }
  function condMatch(p, c) {
    if (c === "location") return !!(arr(p.includeLocations).length || arr(p.excludeLocations).length);
    if (c === "platform") return !!(arr(p.includePlatforms).length || arr(p.excludePlatforms).length);
    if (c === "risk") return !!(arr(p.signInRiskLevels).length || arr(p.userRiskLevels).length);
    if (c === "devicefilter") return !!(p.deviceFilter && String(p.deviceFilter).length);
    if (c === "legacy") return arr(p.clientAppTypes).some(function (x) { return /Exchange ActiveSync|Other legacy/i.test(x); });
    return true;
  }
  function policyMatches(p, ft) {
    if (pfilter.effect === "block" && !p.isBlock) return false;
    if (pfilter.effect === "grant" && p.isBlock) return false;
    if (pfilter.principal !== "all") {
      var parts = pfilter.principal.split(SEP), type = parts[0], name = parts[1];
      if (princRefs(p, type, "inc").indexOf(name) === -1 && princRefs(p, type, "exc").indexOf(name) === -1) return false;
    }
    if (pfilter.app !== "all") {
      if (arr(p.includeApplications).indexOf(pfilter.app) === -1 && arr(p.excludeApplications).indexOf(pfilter.app) === -1) return false;
    }
    if (pfilter.cond !== "all" && !condMatch(p, pfilter.cond)) return false;
    if (pfilter.grant !== "all") {
      var has = arr(p.grantControlLabels).indexOf(pfilter.grant) !== -1 ||
        (pfilter.grant === "Authentication strength" && !!p.authenticationStrength);
      if (!has) return false;
    }
    if (ft) {
      var hay = (p.displayName || "") + " " + princAll(p, "inc").join(" ") + " " + princAll(p, "exc").join(" ") +
        " " + arr(p.includeApplications).join(" ") + " " + arr(p.excludeApplications).join(" ");
      if (hay.toLowerCase().indexOf(ft) === -1) return false;
    }
    return true;
  }
  function matchBadge(p) {
    var b = {};
    if (pfilter.principal !== "all") {
      var parts = pfilter.principal.split(SEP), type = parts[0], name = parts[1];
      if (princRefs(p, type, "inc").indexOf(name) !== -1) b.targets = 1;
      if (princRefs(p, type, "exc").indexOf(name) !== -1) b.excluded = 1;
    }
    if (pfilter.app !== "all") {
      if (arr(p.includeApplications).indexOf(pfilter.app) !== -1) b.targets = 1;
      if (arr(p.excludeApplications).indexOf(pfilter.app) !== -1) b.excluded = 1;
    }
    var out = "";
    if (b.targets) out += ' <span class="pill ok mbadge">targets</span>';
    if (b.excluded) out += ' <span class="pill block mbadge">excluded</span>';
    return out;
  }

  function populateFacets() {
    var princ = {}, apps = {}, grants = {};
    policies.forEach(function (p) {
      ["User", "Group", "Role"].forEach(function (type) {
        princRefs(p, type, "inc").concat(princRefs(p, type, "exc")).forEach(function (n) {
          if (n) princ[type + SEP + n] = { type: type, name: n };
        });
      });
      arr(p.includeApplications).concat(arr(p.excludeApplications)).forEach(function (n) { if (n) apps[n] = 1; });
      arr(p.grantControlLabels).forEach(function (l) { if (l) grants[l] = 1; });
      if (p.authenticationStrength) grants["Authentication strength"] = 1;
    });
    var psel = el("fprincipal");
    if (psel) {
      var pkeys = Object.keys(princ).sort(function (a, b) {
        var x = princ[a], y = princ[b];
        if (x.type !== y.type) return x.type < y.type ? -1 : 1;
        return x.name.toLowerCase() < y.name.toLowerCase() ? -1 : 1;
      });
      pkeys.forEach(function (k) {
        var o = document.createElement("option");
        o.value = k; o.textContent = princ[k].type + ": " + nm(princ[k].name);
        psel.appendChild(o);
      });
    }
    var asel = el("fapp");
    if (asel) {
      Object.keys(apps).sort(function (a, b) { return String(nm(a)).toLowerCase() < String(nm(b)).toLowerCase() ? -1 : 1; })
        .forEach(function (n) { var o = document.createElement("option"); o.value = n; o.textContent = nm(n); asel.appendChild(o); });
    }
    var gsel = el("fgrant");
    if (gsel) {
      Object.keys(grants).sort().forEach(function (g) {
        var o = document.createElement("option"); o.value = g; o.textContent = g; gsel.appendChild(o);
      });
    }
  }

  function clearFilters() {
    pfilter = { effect: "all", principal: "all", app: "all", cond: "all", grant: "all" };
    ["feffect", "fprincipal", "fapp", "fcond", "fgrant", "fstate"].forEach(function (id) { if (el(id)) el(id).value = "all"; });
    if (el("q")) el("q").value = "";
    renderList("", "all");
  }

  function renderList(filterText, filterState) {
    var ul = el("plist");
    ul.innerHTML = "";
    var ft = (filterText || "").toLowerCase();
    var shown = 0;
    policies.forEach(function (p, i) {
      if (filterState && filterState !== "all" && p.state !== filterState) return;
      if (!policyMatches(p, ft)) return;
      shown++;
      var li = document.createElement("li");
      if (selected === i) li.className = "active";
      li.innerHTML = '<span class="dot ' + stateClass(p.state) + '"></span>' +
        '<span>' + esc(p.displayName || "(no name)") + '</span>' + matchBadge(p);
      li.onclick = function () { selected = i; renderList(filterText, filterState); renderDetail(p); };
      ul.appendChild(li);
    });
    if (!shown) {
      var empty = document.createElement("li");
      empty.className = "muted"; empty.style.cursor = "default";
      empty.textContent = "No policies match the filters.";
      ul.appendChild(empty);
    }
    var cnt = el("filterCount");
    if (cnt) cnt.textContent = "Showing " + shown + " of " + policies.length;
  }

  function controlPills(p) {
    var out = [];
    if (p.isBlock) out.push('<span class="pill block">Block access</span>');
    var labels = arr(p.grantControlLabels);
    if (!labels.length) labels = arr(p.grantControls);
    labels.forEach(function (c) {
      if (c === "block" || c === "Block access") return;
      var isMfa = /mfa|multifactor/i.test(c);
      out.push('<span class="' + (isMfa ? "pill mfa" : "pill") + '">' + esc(c) + "</span>");
    });
    if (p.authenticationStrength) out.push('<span class="pill mfa">Strength: ' + esc(p.authenticationStrength) + "</span>");
    arr(p.customAuthenticationFactors).forEach(function (c) { out.push('<span class="pill">Custom: ' + esc(c) + "</span>"); });
    if (!out.length) out.push('<span class="muted">none</span>');
    return out.join(" ");
  }

  // Build "Include / Exclude" sub-blocks with labelled rows.
  function incExc(includeRows, excludeRows) {
    function block(label, rows) {
      var body = rows.filter(function (r) { return r; }).join("");
      if (!body) return "";
      return "<div class=\"ie\"><span class=\"ie-h\">" + label + "</span>" + body + "</div>";
    }
    var out = "";
    out += block("&#10003; Include", includeRows);
    out += block("&#128683; Exclude", excludeRows);
    if (!out) out = '<span class="muted">Not configured</span>';
    return out;
  }
  function row(label, v) {
    var a = arr(v).filter(function (x) { return x !== null && x !== undefined && x !== ""; });
    if (!a.length) return "";
    return "<div class=\"kv\"><span class=\"k\">" + label + "</span><span class=\"v\">" + a.map(esc).join("<br>") + "</span></div>";
  }
  // Like row(), but always renders (shows "Not configured" when empty) so the
  // condition list is consistent across every policy.
  function condRow(label, v) {
    var a = arr(v).filter(function (x) { return x !== null && x !== undefined && x !== ""; });
    var val = a.length ? a.map(esc).join("<br>") : '<span class="muted">Not configured</span>';
    return "<div class=\"kv\"><span class=\"k\">" + label + "</span><span class=\"v\">" + val + "</span></div>";
  }
  function flag(label, on) { return on ? "<div class=\"kv\"><span class=\"k\">" + label + "</span><span class=\"v\">Yes</span></div>" : ""; }

  // Build the four per-policy card bodies (Users / Target / Conditions / Access
  // controls). Shared by the Per-policy tab and the Compare-policies tab.
  // A guest selector can name specific partner organisations. Saying only
  // "external users" leaves a policy that admits one managed provider looking
  // identical to one that admits every tenant in the world.
  function tenantLabel(t) {
    if (!t) { return null; }
    return t.label || null;
  }

  function policyCardBodies(p) {
    var userInc = [
      row("Users", p.includeUsers),
      row("Groups", p.includeGroups),
      row("Directory roles", p.includeRoles),
      flag("Guests / external users", p.includeGuestsExternal),
      row("Guest/external types", p.includeGuestTypes),
      row("Partner tenants", tenantLabel(p.includeGuestTenants)),
      row("Service principals", p.includeServicePrincipals),
      row("Agent identities", p.includeAgentIdentities)
    ];
    var userExc = [
      row("Users", p.excludeUsers),
      row("Groups", p.excludeGroups),
      row("Directory roles", p.excludeRoles),
      flag("Guests / external users", p.excludeGuestsExternal),
      row("Guest/external types", p.excludeGuestTypes),
      row("Partner tenants", tenantLabel(p.excludeGuestTenants)),
      row("Service principals", p.excludeServicePrincipals),
      row("Agent identities", p.excludeAgentIdentities)
    ];

    var appInc = [
      row("Cloud apps", p.includeApplications),
      row("User actions", p.includeUserActions),
      row("Authentication context", p.authenticationContext),
      (p.applicationFilter ? row("App filter", p.applicationFilter) : ""),
      row("Traffic profiles", p.trafficProfiles)
    ];
    var appExc = [ row("Cloud apps", p.excludeApplications) ];

    var conditions = [
      condRow("Client apps", p.clientAppTypes),
      condRow("Device platforms (include)", p.includePlatforms),
      condRow("Device platforms (exclude)", p.excludePlatforms),
      condRow("Locations (include)", p.includeLocations),
      condRow("Locations (exclude)", p.excludeLocations),
      condRow("Sign-in risk", p.signInRiskLevels),
      condRow("User risk", p.userRiskLevels),
      condRow("Service principal risk", p.servicePrincipalRiskLevels),
      condRow("Insider risk", p.insiderRiskLevels),
      condRow("Agent risk", p.agentRiskLevels),
      condRow("Authentication flows", p.authenticationFlows),
      condRow("Filter for devices", p.deviceFilter)
    ].join("");

    var controls = "<div class=\"kv\"><span class=\"k\">Grant (" + esc(p.grantOperator || "-") + ")</span><span class=\"v\">" + controlPills(p) + "</span></div>";
    controls += row("Terms of use", p.termsOfUse);
    var sess = arr(p.sessionControls);
    controls += sess.length ? "<div class=\"kv\"><span class=\"k\">Session</span><span class=\"v\">" + sess.map(esc).join("<br>") + "</span></div>" : "";

    return {
      usersTitle: p.isWorkloadIdentity ? "Workload identities" : "Users",
      blockCls: p.isBlock ? " block" : "",
      users: incExc(userInc, userExc),
      target: incExc(appInc, appExc),
      conditions: conditions,
      controls: controls
    };
  }

  function policyHeadHtml(p) {
    var link = p.portalLink ? ' &nbsp;·&nbsp; <a href="' + esc(p.portalLink) + '" target="_blank" rel="noopener">open in Entra portal &#8599;</a>' : "";
    return '<h2>' + esc(p.displayName) + ' <span class="pill ' + (p.state === "enabled" ? "ok" : "") + '">' + esc(stateLabel(p.state)) + "</span></h2>" +
      '<div class="muted" style="margin-bottom:12px">id: <code>' + esc(p.id) + "</code>" +
      (p.modifiedDateTime ? " &nbsp;·&nbsp; modified: " + esc(fmtLocal(p.modifiedDateTime)) : "") + link + "</div>";
  }

  function renderDetail(p) {
    var b = policyCardBodies(p);
    var html = policyHeadHtml(p) +
      '<div class="flow">' +
        '<div class="flowcol"><h3>' + b.usersTitle + "</h3>" + b.users + "</div>" +
        '<div class="arrow">&rarr;</div>' +
        '<div class="flowcol"><h3>Target resources</h3>' + b.target + "</div>" +
        '<div class="arrow">&rarr;</div>' +
        '<div class="flowcol"><h3>Conditions</h3>' + b.conditions + "</div>" +
        '<div class="arrow">&rArr;</div>' +
        '<div class="flowcol controls' + b.blockCls + '"><h3>Access controls</h3>' + b.controls + "</div>" +
      "</div>";
    el("detail").innerHTML = html;
  }

  function renderSummaryCards() {
    var s = DATA.summary || {};
    var cards = [
      ["Policies", s.totalPolicies || 0],
      ["Enabled", (s.byState && s.byState.enabled) || 0],
      ["Report-only", (s.byState && s.byState.enabledForReportingButNotEnforced) || 0],
      ["Disabled", (s.byState && s.byState.disabled) || 0],
      ["Block", s.blockPolicies || 0],
      ["MFA / strength", s.mfaPolicies || 0],
      ["Findings", (s.findingCounts && (s.findingCounts.warning + s.findingCounts.info)) || 0]
    ];
    el("cards").innerHTML = cards.map(function (c) {
      return '<div class="card"><div class="n">' + c[1] + '</div><div class="l">' + c[0] + "</div></div>";
    }).join("");
  }

  function renderFindings() {
    var f = arr(DATA.findings);
    if (!f.length) { el("findings").innerHTML = '<p class="muted">No hygiene findings.</p>'; return; }
    var rows = f.map(function (x) {
      return "<tr><td class=\"sev-" + esc(x.severity) + "\">" + esc(x.severity) + "</td><td>" + esc(x.code) +
        "</td><td>" + esc(x.policyName || "-") + "</td><td>" + esc(x.message) + "</td></tr>";
    }).join("");
    el("findings").innerHTML = '<table><thead><tr><th>Severity</th><th>Code</th><th>Policy</th><th>Detail</th></tr></thead><tbody>' + rows + "</tbody></table>";
  }

  function renderAllTable() {
    var rows = policies.map(function (p) {
      return "<tr><td><span class=\"dot " + stateClass(p.state) + "\"></span> " + esc(p.displayName) + "</td>" +
        "<td>" + esc(stateLabel(p.state)) + "</td>" +
        "<td>" + list(arr(p.includeUsers).concat(arr(p.includeGroups), arr(p.includeRoles))) + "</td>" +
        "<td>" + list(p.includeApplications) + "</td>" +
        "<td>" + controlPills(p) + "</td></tr>";
    }).join("");
    el("alltable").innerHTML = '<table><thead><tr><th>Policy</th><th>State</th><th>Included principals</th><th>Apps</th><th>Controls</th></tr></thead><tbody>' + rows + "</tbody></table>";
  }

  function renderDelta() {
    var d = DATA.delta;
    if (!d) { el("deltaTab").classList.add("hidden"); return; }
    var h = "<p>Compared against baseline <code>" + esc(fmtLocal(d.baselineUtc)) + "</code></p>" +
      '<p><span class="badge-add">+' + d.addedCount + " added</span> &nbsp; " +
      '<span class="badge-remove">-' + d.removedCount + " removed</span> &nbsp; " +
      '<span class="badge-mod">~' + d.modifiedCount + " modified</span></p>";
    function tbl(title, items, cls) {
      items = arr(items);
      if (!items.length) return "";
      return "<h3>" + title + "</h3><table><tbody>" + items.map(function (x) {
        return '<tr><td class="' + cls + '">' + esc(x.displayName) + "</td><td>" + esc(x.state || "") + "</td></tr>";
      }).join("") + "</tbody></table>";
    }
    h += tbl("Added", d.added, "badge-add");
    h += tbl("Removed", d.removed, "badge-remove");
    var mods = arr(d.modified);
    if (mods.length) {
      h += "<h3>Modified</h3>";
      mods.forEach(function (m) {
        h += "<b class=\"badge-mod\">" + esc(m.displayName) + "</b> (" + m.changeCount + " changes)" +
          "<table><thead><tr><th>Field</th><th>From</th><th>To</th></tr></thead><tbody>" +
          arr(m.changes).map(function (c) {
            return "<tr><td>" + esc(c.field) + "</td><td>" + esc(fmtMaybeDate(c.from)) + "</td><td>" + esc(fmtMaybeDate(c.to)) + "</td></tr>";
          }).join("") + "</tbody></table>";
      });
    }
    el("delta").innerHTML = h;
  }

  function showTab(name) {
    ["overview", "detailview", "riskfindings", "contradictions", "compliance", "tests", "authmethods", "delta", "compare", "cmppolicies"].forEach(function (t) {
      var pane = el("pane-" + t);
      if (pane) pane.classList.toggle("hidden", t !== name);
    });
    document.querySelectorAll(".tab").forEach(function (t) {
      t.classList.toggle("active", t.getAttribute("data-tab") === name);
    });
  }

  // ---- In-browser export comparison (mirrors CapDelta semantics) ----
  var cmpSourceData = null, cmpTargetData = null;

  // Flatten a nested object into dotted-path -> scalar. Arrays are sorted and
  // joined so element ordering does not register as a change.
  function cmpFlatten(obj, prefix, out) {
    out = out || {};
    prefix = prefix || "";
    if (obj === null || obj === undefined) { out[prefix] = null; return out; }
    if (Array.isArray(obj)) {
      out[prefix] = obj.map(function (x) {
        return (x !== null && typeof x === "object") ? JSON.stringify(x) : String(x);
      }).sort().join("|");
      return out;
    }
    if (typeof obj === "object") {
      Object.keys(obj).forEach(function (k) {
        cmpFlatten(obj[k], prefix ? prefix + "." + k : k, out);
      });
      return out;
    }
    out[prefix] = String(obj);
    return out;
  }

  function cmpComparePolicy(base, cur) {
    var b = cmpFlatten(base), c = cmpFlatten(cur);
    var keys = {}, out = [];
    Object.keys(b).forEach(function (k) { keys[k] = 1; });
    Object.keys(c).forEach(function (k) { keys[k] = 1; });
    Object.keys(keys).sort().forEach(function (k) {
      var bv = k in b ? b[k] : null;
      var cv = k in c ? c[k] : null;
      if (String(bv) !== String(cv)) out.push({ field: k, from: bv, to: cv });
    });
    return out;
  }

  function cmpCompareExport(baseline, current) {
    var bList = arr(baseline.policies), cList = arr(current.policies);
    var bMap = {}, cMap = {};
    bList.forEach(function (p) { bMap[p.id] = p; });
    cList.forEach(function (p) { cMap[p.id] = p; });
    var added = [], removed = [], modified = [];
    Object.keys(cMap).forEach(function (id) {
      if (!(id in bMap)) added.push({ id: id, displayName: cMap[id].displayName, state: cMap[id].state });
    });
    Object.keys(bMap).forEach(function (id) {
      if (!(id in cMap)) removed.push({ id: id, displayName: bMap[id].displayName, state: bMap[id].state });
    });
    Object.keys(cMap).forEach(function (id) {
      if (!(id in bMap)) return;
      var changes = cmpComparePolicy(bMap[id], cMap[id]);
      if (changes.length) {
        modified.push({
          id: id, displayName: cMap[id].displayName,
          stateFrom: bMap[id].state, stateTo: cMap[id].state,
          changeCount: changes.length, changes: changes
        });
      }
    });
    return {
      baselineUtc: (baseline.metadata || {}).generatedUtc || "",
      currentUtc: (current.metadata || {}).generatedUtc || "",
      addedCount: added.length, removedCount: removed.length, modifiedCount: modified.length,
      added: added, removed: removed, modified: modified
    };
  }

  function renderCompareResult(d) {
    var h = "<p>Source <code>" + esc(fmtLocal(d.baselineUtc)) + "</code> &rarr; Target <code>" +
      esc(fmtLocal(d.currentUtc)) + "</code></p>" +
      '<p><span class="badge-add">+' + d.addedCount + " added</span> &nbsp; " +
      '<span class="badge-remove">-' + d.removedCount + " removed</span> &nbsp; " +
      '<span class="badge-mod">~' + d.modifiedCount + " modified</span></p>";
    if (!d.addedCount && !d.removedCount && !d.modifiedCount) {
      h += '<p class="muted">The two exports are identical (by policy).</p>';
      el("cmpResult").innerHTML = h;
      return;
    }
    function tbl(title, items, cls) {
      items = arr(items);
      if (!items.length) return "";
      return "<h3>" + title + "</h3><table><tbody>" + items.map(function (x) {
        return '<tr><td class="' + cls + '">' + esc(x.displayName || x.id) +
          "</td><td>" + esc(x.state || "") + "</td></tr>";
      }).join("") + "</tbody></table>";
    }
    h += tbl("Added (only in target)", d.added, "badge-add");
    h += tbl("Removed (only in source)", d.removed, "badge-remove");
    var mods = arr(d.modified);
    if (mods.length) {
      h += "<h3>Modified</h3>";
      mods.forEach(function (m) {
        h += "<b class=\"badge-mod\">" + esc(m.displayName || m.id) + "</b> (" + m.changeCount + " changes)" +
          "<table><thead><tr><th>Field</th><th>Source</th><th>Target</th></tr></thead><tbody>" +
          arr(m.changes).map(function (c) {
            return "<tr><td>" + esc(c.field) + "</td><td>" + esc(fmtMaybeDate(c.from)) + "</td><td>" + esc(fmtMaybeDate(c.to)) + "</td></tr>";
          }).join("") + "</tbody></table>";
      });
    }
    el("cmpResult").innerHTML = h;
  }

  function cmpUpdateButton() {
    var btn = el("cmpRun");
    if (btn) btn.disabled = !(cmpSourceData && cmpTargetData);
  }

  function cmpLoadFile(input, which, infoEl) {
    var file = input.files && input.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      try {
        var data = JSON.parse(reader.result);
        if (!data || !Array.isArray(data.policies)) {
          throw new Error("not a CAPVisualizer export (no policies array)");
        }
        if (which === "source") cmpSourceData = data; else cmpTargetData = data;
        var meta = data.metadata || {};
        if (infoEl) infoEl.textContent = file.name + " - " + (data.policies.length) +
          " policies" + (meta.generatedUtc ? ", generated " + fmtLocal(meta.generatedUtc) : "");
      } catch (e) {
        if (which === "source") cmpSourceData = null; else cmpTargetData = null;
        if (infoEl) infoEl.textContent = "Could not read this file: " + e.message;
      }
      cmpUpdateButton();
    };
    reader.onerror = function () {
      if (infoEl) infoEl.textContent = "Could not read this file.";
      if (which === "source") cmpSourceData = null; else cmpTargetData = null;
      cmpUpdateButton();
    };
    reader.readAsText(file);
  }


  function sevRank(s) { return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] || 0; }

  // Collapse findings that share a checkId (e.g. "User is not capable of MFA"
  // raised once per user) into a single row, unioning the affected objects.
  function groupFindings(f) {
    var map = {}, order = [];
    f.forEach(function (x) {
      var k = x.checkId || x.title;
      if (!map[k]) {
        map[k] = {
          checkId: x.checkId, title: x.title, severity: x.severity, riskScore: x.riskScore,
          description: x.description, summary: x.summary, logic: x.logic, threat: x.threat,
          remediation: x.remediation, references: x.references,
          affectedObjects: [], count: 0
        };
        order.push(k);
      }
      var g = map[k];
      g.count++;
      arr(x.affectedObjects).forEach(function (o) { if (g.affectedObjects.indexOf(o) === -1) g.affectedObjects.push(o); });
      if (sevRank(x.severity) > sevRank(g.severity)) g.severity = x.severity;
      if ((x.riskScore || 0) > (g.riskScore || 0)) g.riskScore = x.riskScore;
    });
    return order.map(function (k) { return map[k]; });
  }

  function renderRiskFindings(filterText, filterSev) {
    var f = arr(DATA.riskFindings);
    var tab = el("findingsTab");
    if (!f.length) { if (tab) tab.classList.add("hidden"); return; }
    if (tab) tab.classList.remove("hidden");
    var ft = (filterText || "").toLowerCase();
    var filtered = f.filter(function (x) {
      if (filterSev && filterSev !== "all" && x.severity !== filterSev) return false;
      if (ft) {
        var hay = (x.title + " " + x.description + " " + arr(x.affectedObjects).map(nm).join(" ")).toLowerCase();
        if (hay.indexOf(ft) === -1) return false;
      }
      return true;
    });
    var rows = groupFindings(filtered).map(function (x) {
      var refs = arr(x.references).map(esc).join(", ");
      // Always show a meaningful description. When several objects share a
      // finding, prefer the generic summary (per-object detail is in Affected);
      // otherwise fall back to the per-object description.
      var descText = x.count > 1 ? (x.summary || x.description) : (x.description || x.summary);
      var desc = descText ? "<div class=\"muted\">" + esc(descText) + "</div>" : "";
      var affNote = x.count > 1
        ? "<div class=\"muted\"><i>" + esc(x.count + " objects affected - see the Affected column.") + "</i></div>"
        : "";
      var badge = x.count > 1 ? ' <span class="pill">x' + x.count + "</span>" : "";
      var why = x.threat ? "<div class=\"muted\"><i>Why it matters:</i> " + esc(x.threat) + "</div>" : "";
      var how = x.logic ? "<div class=\"muted\"><i>How detected:</i> " + esc(x.logic) + "</div>" : "";
      return "<tr>" +
        "<td class=\"sev-" + esc(x.severity) + "\">" + esc(x.severity) + "</td>" +
        "<td style=\"text-align:center\">" + esc(x.riskScore) + "</td>" +
        "<td><b>" + esc(x.title) + "</b>" + badge + desc + affNote + why + how +
        (x.remediation ? "<div class=\"muted\"><i>Fix:</i> " + esc(x.remediation) + "</div>" : "") +
        (refs ? "<div class=\"muted\"><i>Refs:</i> " + refs + "</div>" : "") + "</td>" +
        "<td>" + listNamesCollapsible(x.affectedObjects, 5) + "</td></tr>";
    }).join("");
    el("riskfindings").innerHTML = '<table><thead><tr><th>Severity</th><th>Risk</th><th>Finding</th><th>Affected</th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="4" class="muted">No findings match the filter.</td></tr>') + "</tbody></table>";
  }

  function renderContradictions() {
    var a = DATA.audit;
    var tab = el("contraTab");
    if (!a) { if (tab) tab.classList.add("hidden"); return; }
    if (tab) tab.classList.remove("hidden");
    var issues = arr(a.issues);
    if (!issues.length) {
      el("contradictions").innerHTML = '<p class="muted">No contradictions detected.</p>';
    } else {
      var rows = issues.map(function (x) {
        return "<tr><td class=\"sev-" + esc(x.severity) + "\">" + esc(x.severity) + "</td>" +
          "<td>" + esc(x.category) + "</td>" +
          "<td><b>" + esc(x.title) + "</b><div class=\"muted\">" + esc(x.detail) + "</div></td>" +
          "<td>" + esc(x.policyName || "-") + "</td></tr>";
      }).join("");
      el("contradictions").innerHTML = '<table><thead><tr><th>Severity</th><th>Category</th><th>Issue</th><th>Policy</th></tr></thead><tbody>' + rows + "</tbody></table>";
    }
    var exp = arr(a.exemptionExposure);
    if (!exp.length) {
      el("exemptions").innerHTML = '<p class="muted">No exclusions configured.</p>';
    } else {
      var er = exp.map(function (x) {
        return "<tr><td>" + esc(x.displayName || nm(x.id)) + "</td><td>" + esc(x.type) + "</td>" +
          "<td style=\"text-align:center\">" + esc(x.policyCount) + "</td>" +
          "<td>" + listNames(x.excludedFromPolicies) + "</td></tr>";
      }).join("");
      el("exemptions").innerHTML = '<table><thead><tr><th>Principal</th><th>Type</th><th># policies</th><th>Excluded from</th></tr></thead><tbody>' + er + "</tbody></table>";
    }
  }

  function renderCompliance() {
    var c = DATA.compliance;
    var tab = el("complianceTab");
    if (!c) { if (tab) tab.classList.add("hidden"); return; }
    if (tab) tab.classList.remove("hidden");
    var s = c.summary || {};
    el("complianceMeta").innerHTML = esc(c.baseline) + " (" + esc(c.baselineVersion) + ")<br>" +
      "Pass " + (s.pass || 0) + " / Fail " + (s.fail || 0) + " / Manual " + (s.manual || 0) +
      " of " + (s.total || 0) + " controls &nbsp;·&nbsp; " +
      "pass rate " + (s.passRate || 0) + "% over " + (s.automatable || 0) + " Conditional-Access controls evaluated automatically" +
      " &nbsp;·&nbsp; the remaining " + ((s.total || 0) - (s.automatable || 0)) + " live outside Conditional Access (manual review, guidance shown).";
    // Group controls by SCuBA section (MS.AAD.<section>.*) so the full baseline
    // reads as a structured matrix rather than a flat list.
    var groups = {}, order = [];
    arr(c.controls).forEach(function (x) {
      var m = /MS\.AAD\.(\d+)/.exec(x.id);
      var g = m ? "MS.AAD." + m[1] : "Other";
      if (!groups[g]) { groups[g] = []; order.push(g); }
      groups[g].push(x);
    });
    var sectionTitles = {
      "MS.AAD.1": "Legacy authentication", "MS.AAD.2": "Risk-based policies",
      "MS.AAD.3": "Strong authentication", "MS.AAD.4": "Centralized log collection",
      "MS.AAD.5": "Application registration and consent", "MS.AAD.6": "Passwords",
      "MS.AAD.7": "Highly privileged access", "MS.AAD.8": "Guest / external users",
      "MS.AAD.9": "AI agents"
    };
    var html = order.map(function (g) {
      var rows = groups[g].map(function (x) {
        var isCa = x.scope === "conditional-access";
        var refs = arr(x.nist).concat(arr(x.mitre)).map(esc).join(", ");
        var scopeCell = isCa ? '<span class="pill ok">CA</span>'
          : '<span class="pill">manual</span><div class="muted">' + esc(x.scope || "") + "</div>";
        return "<tr><td><code>" + esc(x.id) + "</code></td>" +
          "<td><span class=\"pill " + (x.result === "pass" ? "ok" : (x.result === "fail" ? "block" : "")) + "\">" + esc(x.result) + "</span></td>" +
          "<td>" + esc(x.criticality) + "</td>" +
          "<td>" + scopeCell + "</td>" +
          "<td>" + esc(x.statement) + "<div class=\"muted\">" + esc(x.rationale) + "</div>" +
          (refs ? "<div class=\"muted\"><i>Refs:</i> " + refs + "</div>" : "") + "</td>" +
          "<td>" + listNames(x.evidence) + "</td></tr>";
      }).join("");
      return "<h3 style=\"margin:18px 0 6px\">" + esc(g) + (sectionTitles[g] ? " - " + esc(sectionTitles[g]) : "") + "</h3>" +
        '<table><thead><tr><th>Control</th><th>Result</th><th>Level</th><th>Scope</th><th>Statement</th><th>Evidence</th></tr></thead><tbody>' + rows + "</tbody></table>";
    }).join("");
    el("compliance").innerHTML = html;
  }

  function renderTests() {
    var t = DATA.test;
    var tab = el("testsTab");
    if (!t) { if (tab) tab.classList.add("hidden"); return; }
    if (tab) tab.classList.remove("hidden");
    var s = t.summary || {};
    el("testsMeta").innerHTML = esc(t.name) + " &nbsp;·&nbsp; " +
      "Passed " + (s.passed || 0) + " / Failed " + (s.failed || 0) + " / Errored " + (s.errored || 0) +
      " &nbsp;·&nbsp; overall " + (t.passed ? "<span class=\"pill ok\">PASS</span>" : "<span class=\"pill block\">FAIL</span>");
    var rows = arr(t.assertions).map(function (x) {
      var cls = x.result === "pass" ? "ok" : (x.result === "fail" ? "sev-high" : "muted");
      return "<tr><td class=\"" + cls + "\">" + esc(x.result) + "</td>" +
        "<td>" + esc(x.name) + "</td><td>" + esc(x.type) + "</td>" +
        "<td>" + esc(x.message) + "</td></tr>";
    }).join("");
    el("tests").innerHTML = '<table><thead><tr><th>Result</th><th>Assertion</th><th>Type</th><th>Detail</th></tr></thead><tbody>' + rows + "</tbody></table>";
  }

  function renderAuthMethods() {
    var a = DATA.authMethods;
    var tab = el("authMethodsTab");
    if (!a) { if (tab) tab.classList.add("hidden"); return; }
    if (tab) tab.classList.remove("hidden");
    var meta = el("authMethodsMeta");
    var host = el("authMethods");
    if (!a.available) {
      meta.innerHTML = "";
      host.innerHTML = '<p class="muted">' + esc(a.reason || "Authentication method registration data was not collected.") + "</p>";
      return;
    }
    var s = a.summary || {};
    meta.innerHTML = "Source: aggregate authentication method registration report" +
      (a.collectedUtc ? " &nbsp;·&nbsp; collected <span class=\"ts\" data-utc=\"" + esc(a.collectedUtc) + "\">" + esc(a.collectedUtc) + "</span>" : "") +
      " &nbsp;·&nbsp; " + (s.totalUsers || 0) + " users";

    function card(n, l) { return '<div class="card"><div class="n">' + n + '</div><div class="l">' + esc(l) + "</div></div>"; }
    var cards = '<div class="cards">' +
      card((s.mfaRegisteredPct || 0) + "%", "MFA registered (" + (s.mfaRegistered || 0) + "/" + (s.totalUsers || 0) + ")") +
      card((s.mfaCapablePct || 0) + "%", "MFA capable (" + (s.mfaCapable || 0) + ")") +
      card((s.passwordlessCapablePct || 0) + "%", "Passwordless capable (" + (s.passwordlessCapable || 0) + ")") +
      card((s.phishResistantPct || 0) + "%", "Phishing-resistant (" + (s.phishResistant || 0) + ")") +
      card((s.ssprRegisteredPct || 0) + "%", "SSPR registered (" + (s.ssprRegistered || 0) + ")") +
      card((s.smsVoiceUsers || 0) + "", "SMS/voice MFA \u26a0 (" + (s.adminsSmsVoice || 0) + " admins) - retiring") +
      card((s.admins || 0) + "", "Admins (" + (s.adminsMfaRegistered || 0) + " MFA, " + (s.adminsPhishResistant || 0) + " phish-resistant)") +
      "</div>";

    // Method registration breakdown.
    var mb = arr(s.methodBreakdown);
    var breakdown = "";
    if (mb.length) {
      var brows = mb.map(function (x) {
        return "<tr><td>" + esc(x.label || x.method) + "</td><td style=\"text-align:center\">" + (x.count || 0) + "</td></tr>";
      }).join("");
      breakdown = "<h3 style=\"margin:18px 0 6px\">Registered methods</h3>" +
        '<table><thead><tr><th>Method</th><th># users</th></tr></thead><tbody>' + brows + "</tbody></table>";
    }

    // Gap findings grouped by severity.
    var gaps = arr(a.gaps);
    var gapsHtml;
    if (!gaps.length) {
      gapsHtml = '<h3 style="margin:18px 0 6px">Gaps</h3><p class="muted">No authentication-method gaps detected.</p>';
    } else {
      var sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      gaps = gaps.slice().sort(function (x, y) {
        return (sevRank[x.severity] === undefined ? 9 : sevRank[x.severity]) -
               (sevRank[y.severity] === undefined ? 9 : sevRank[y.severity]);
      });
      var grows = gaps.map(function (x) {
        var names = arr(x.users).map(function (u) { return esc(nm(u.displayName || u.userPrincipalName || u.id)); });
        var affected = names.length ? listNamesCollapsible(arr(x.users).map(function (u) { return u.displayName || u.userPrincipalName || u.id; }), 5) : '<span class="muted">-</span>';
        return "<tr><td class=\"sev-" + esc(x.severity) + "\">" + esc(x.severity) + "</td>" +
          "<td><b>" + esc(x.title) + "</b> <span class=\"pill\">x" + (x.count || 0) + "</span>" +
          "<div class=\"muted\">" + esc(x.detail) + "</div></td>" +
          "<td>" + affected + "</td></tr>";
      }).join("");
      gapsHtml = "<h3 style=\"margin:18px 0 6px\">Gaps</h3>" +
        '<table><thead><tr><th>Severity</th><th>Gap</th><th>Affected users</th></tr></thead><tbody>' + grows + "</tbody></table>";
    }

    // Per-user table (collapsible behind a details block, since it is sensitive).
    var methodLabel = {};
    mb.forEach(function (x) { methodLabel[x.method] = x.label || x.method; });
    amMethodLabel = methodLabel;
    amUsers = arr(a.users).map(function (u) {
      return {
        row: u,
        displayName: String(nm(u.displayName || u.userPrincipalName || "")),
        upn: String(u.userPrincipalName || ""),
        methodsText: arr(u.methodsRegistered).map(function (m) { return methodLabel[m] || m; }).join(", ")
      };
    });
    var users = arr(a.users);
    var perUser = "<h3 style=\"margin:18px 0 6px\">Per-user registration (" + users.length + ")</h3>" +
      '<details class="affmore"' + (users.length <= 25 ? " open" : "") + '><summary>Show per-user table</summary>' +
      '<div class="am-controls">' +
        '<input id="amq" type="text" placeholder="Filter users by name, UPN or method...">' +
        '<label>Show only <select id="amcol">' +
          '<option value="all">Any attribute</option>' +
          '<option value="isMfaRegistered">MFA registered</option>' +
          '<option value="isMfaCapable">MFA capable</option>' +
          '<option value="hasPhishResistant">Phishing-resistant</option>' +
          '<option value="isPasswordlessCapable">Passwordless capable</option>' +
          '<option value="isSsprRegistered">SSPR registered</option>' +
          '<option value="usesTelephonyMfa">Uses SMS/voice MFA</option>' +
          '<option value="isAdmin">Admin</option>' +
        '</select></label>' +
        '<select id="amval"><option value="yes">= Yes</option><option value="no">= No</option></select>' +
        '<span id="amCount" class="muted"></span>' +
        '<button type="button" id="amCsv" class="cmp-btn">Export CSV</button>' +
      '</div>' +
      '<div id="amUserTable"></div></details>';

    host.innerHTML = cards + gapsHtml + breakdown + perUser;
    renderAuthUserTable();
    var amq = el("amq");
    if (amq) amq.addEventListener("input", function () { amState.q = amq.value; renderAuthUserTable(); });
    var amcol = el("amcol");
    if (amcol) amcol.addEventListener("change", function () { amState.col = amcol.value; renderAuthUserTable(); });
    var amval = el("amval");
    if (amval) amval.addEventListener("change", function () { amState.val = amval.value; renderAuthUserTable(); });
    var amCsv = el("amCsv");
    if (amCsv) amCsv.addEventListener("click", exportAuthUsersCsv);
    localizeStamps();
  }

  // State + column model for the sortable/searchable per-user table.
  var amUsers = [], amMethodLabel = {}, amFiltered = [];
  var amState = { sort: "displayName", dir: 1, q: "", col: "all", val: "yes" };
  var AM_COLS = [
    { key: "displayName", label: "User", type: "user" },
    { key: "isMfaRegistered", label: "MFA reg.", type: "bool" },
    { key: "isMfaCapable", label: "MFA capable", type: "bool" },
    { key: "hasPhishResistant", label: "Phish-resistant", type: "bool" },
    { key: "isPasswordlessCapable", label: "Passwordless", type: "bool" },
    { key: "isSsprRegistered", label: "SSPR reg.", type: "bool" },
    { key: "usesTelephonyMfa", label: "SMS/voice", type: "bool" },
    { key: "methodsText", label: "Methods", type: "methods" }
  ];

  function amSortVal(u, key) {
    if (key === "displayName") return u.displayName.toLowerCase();
    if (key === "methodsText") return u.row.methodCount || arr(u.row.methodsRegistered).length;
    return u.row[key] ? 1 : 0;
  }

  function renderAuthUserTable() {
    var host = el("amUserTable");
    if (!host) return;
    function yn(b) { return b ? '<span class="ok">Yes</span>' : '<span class="muted">No</span>'; }
    var q = (amState.q || "").trim().toLowerCase();
    var rows = amUsers.filter(function (u) {
      if (q && (u.displayName + " " + u.upn + " " + u.methodsText).toLowerCase().indexOf(q) === -1) return false;
      if (amState.col !== "all") {
        var want = amState.val === "yes";
        if (!!u.row[amState.col] !== want) return false;
      }
      return true;
    });
    rows = rows.slice().sort(function (a, b) {
      var av = amSortVal(a, amState.sort), bv = amSortVal(b, amState.sort);
      if (av < bv) return -1 * amState.dir;
      if (av > bv) return 1 * amState.dir;
      return a.displayName.toLowerCase() < b.displayName.toLowerCase() ? -1 : 1;
    });
    amFiltered = rows;
    var cnt = el("amCount");
    if (cnt) cnt.textContent = "Showing " + rows.length + " of " + amUsers.length;
    var heads = AM_COLS.map(function (c) {
      var active = amState.sort === c.key;
      var arrow = active ? (amState.dir === 1 ? " \u25B2" : " \u25BC") : "";
      return '<th class="amsort" data-key="' + esc(c.key) + '" style="cursor:pointer">' + esc(c.label) + arrow + "</th>";
    }).join("");
    var body = rows.map(function (u) {
      var r = u.row;
      return "<tr>" +
        "<td>" + esc(u.displayName) + (r.isAdmin ? ' <span class="pill">admin</span>' : "") +
        (u.upn && u.displayName !== u.upn ? "<div class=\"muted\">" + esc(u.upn) + "</div>" : "") + "</td>" +
        "<td>" + yn(r.isMfaRegistered) + "</td>" +
        "<td>" + yn(r.isMfaCapable) + "</td>" +
        "<td>" + yn(r.hasPhishResistant) + "</td>" +
        "<td>" + yn(r.isPasswordlessCapable) + "</td>" +
        "<td>" + yn(r.isSsprRegistered) + "</td>" +
        "<td>" + (r.usesTelephonyMfa ? '<span class="warn">Yes \u26a0</span>' : '<span class="muted">No</span>') + "</td>" +
        "<td>" + (u.methodsText ? esc(u.methodsText) : '<span class="muted">-</span>') + "</td></tr>";
    }).join("");
    host.innerHTML = '<table><thead><tr>' + heads + "</tr></thead><tbody>" +
      (body || '<tr><td colspan="8" class="muted">No users match the filter.</td></tr>') + "</tbody></table>";
    host.querySelectorAll(".amsort").forEach(function (th) {
      th.onclick = function () {
        var k = th.getAttribute("data-key");
        if (amState.sort === k) { amState.dir = -amState.dir; }
        else { amState.sort = k; amState.dir = (k === "displayName" || k === "methodsText") ? 1 : -1; }
        renderAuthUserTable();
      };
    });
  }

  function csvCell(v) {
    var s = (v === null || v === undefined) ? "" : String(v);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
  function downloadCsv(filename, header, rows) {
    var lines = [header.map(csvCell).join(",")];
    rows.forEach(function (r) { lines.push(r.map(csvCell).join(",")); });
    var blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8;" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }
  function exportAuthUsersCsv() {
    var header = ["Display name", "User principal name", "User type", "Admin",
      "MFA registered", "MFA capable", "Phishing-resistant", "Passwordless capable",
      "SSPR registered", "Uses SMS/voice MFA", "Methods registered"];
    var yn = function (b) { return b ? "Yes" : "No"; };
    var rows = amFiltered.map(function (u) {
      var r = u.row;
      return [u.displayName, u.upn, r.userType || "", yn(r.isAdmin),
        yn(r.isMfaRegistered), yn(r.isMfaCapable), yn(r.hasPhishResistant),
        yn(r.isPasswordlessCapable), yn(r.isSsprRegistered), yn(r.usesTelephonyMfa), u.methodsText];
    });
    var stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    downloadCsv("authentication-methods-" + stamp + ".csv", header, rows);
  }

  function selectPolicy(i) {
    if (i < 0 || i >= policies.length) return;
    selected = i;
    renderList(el("q") ? el("q").value : "", el("fstate") ? el("fstate").value : "all");
    renderDetail(policies[i]);
    showTab("detailview");
  }

  // Flatten everything into a searchable index so a single box finds a term
  // (e.g. "device code flow", a user, a control id) anywhere in the report.
  function buildSearchIndex() {
    var idx = [];
    function push(cat, label, tokens, go) {
      var hay = tokens.filter(function (t) { return t !== null && t !== undefined && t !== ""; })
        .map(function (t) { return String(nm(t)); }).join(" ").toLowerCase();
      idx.push({ cat: cat, label: label, hay: hay + " " + String(label).toLowerCase(), go: go });
    }
    policies.forEach(function (p, i) {
      var tokens = [p.displayName, p.id, stateLabel(p.state)]
        .concat(arr(p.includeUsers), arr(p.includeGroups), arr(p.includeRoles),
          arr(p.excludeUsers), arr(p.excludeGroups), arr(p.excludeRoles),
          arr(p.includeApplications), arr(p.excludeApplications), arr(p.includeUserActions),
          arr(p.authenticationContext), arr(p.clientAppTypes), arr(p.includePlatforms),
          arr(p.excludePlatforms), arr(p.includeLocations), arr(p.excludeLocations),
          arr(p.signInRiskLevels), arr(p.userRiskLevels), arr(p.servicePrincipalRiskLevels),
          arr(p.insiderRiskLevels), arr(p.agentRiskLevels), arr(p.authenticationFlows),
          arr(p.grantControlLabels || p.grantControls), arr(p.sessionControls),
          arr(p.customAuthenticationFactors), [p.deviceFilter, p.authenticationStrength]);
      push("Policy", p.displayName, tokens, (function (k) { return function () { selectPolicy(k); }; })(i));
    });
    arr(DATA.riskFindings).forEach(function (x) {
      push("Finding", x.title, [x.title, x.description, x.remediation, x.checkId].concat(arr(x.affectedObjects)),
        function () { showTab("riskfindings"); });
    });
    arr(DATA.findings).forEach(function (x) {
      push("Hygiene", x.title || x.code, [x.title, x.code, x.detail, x.policy], function () { showTab("overview"); });
    });
    if (DATA.audit) arr(DATA.audit.issues).forEach(function (x) {
      push("Contradiction", x.title, [x.title, x.detail, x.category, x.policyName], function () { showTab("contradictions"); });
    });
    if (DATA.compliance) arr(DATA.compliance.controls).forEach(function (x) {
      push("Compliance", x.id + " " + x.statement, [x.id, x.statement, x.rationale, x.result].concat(arr(x.nist), arr(x.mitre), arr(x.evidence).map(nm)),
        function () { showTab("compliance"); });
    });
    if (DATA.test) arr(DATA.test.assertions).forEach(function (x) {
      push("Test", x.name, [x.name, x.message, x.type, x.result], function () { showTab("tests"); });
    });
    if (DATA.authMethods && DATA.authMethods.available) arr(DATA.authMethods.gaps).forEach(function (x) {
      push("Auth methods", x.title, [x.title, x.detail, x.severity].concat(arr(x.users).map(function (u) { return u.displayName || u.userPrincipalName; })),
        function () { showTab("authmethods"); });
    });
    return idx;
  }

  var SEARCH_INDEX = null;
  function renderGlobalSearch(term) {
    var box = el("gresults");
    if (!box) return;
    var t = (term || "").trim().toLowerCase();
    if (t.length < 2) { box.classList.add("hidden"); box.innerHTML = ""; return; }
    if (!SEARCH_INDEX) SEARCH_INDEX = buildSearchIndex();
    var hits = SEARCH_INDEX.filter(function (r) { return r.hay.indexOf(t) !== -1; });
    if (!hits.length) { box.classList.remove("hidden"); box.innerHTML = '<div class="gr-empty muted">No matches for "' + esc(term) + '".</div>'; return; }
    var byCat = {}, order = [];
    hits.forEach(function (h) { if (!byCat[h.cat]) { byCat[h.cat] = []; order.push(h.cat); } byCat[h.cat].push(h); });
    var html = order.map(function (cat) {
      var items = byCat[cat].slice(0, 12).map(function (h, i) {
        return '<div class="gr-item" data-cat="' + esc(cat) + '" data-i="' + i + '">' + esc(h.label) + "</div>";
      }).join("");
      var more = byCat[cat].length > 12 ? '<div class="gr-more muted">+' + (byCat[cat].length - 12) + " more</div>" : "";
      return '<div class="gr-cat"><div class="gr-cat-h">' + esc(cat) + " (" + byCat[cat].length + ")</div>" + items + more + "</div>";
    }).join("");
    box.innerHTML = html;
    box.classList.remove("hidden");
    order.forEach(function (cat) {
      byCat[cat].slice(0, 12).forEach(function (h, i) {
        var node = box.querySelector('.gr-item[data-cat="' + cat + '"][data-i="' + i + '"]');
        if (node) node.onclick = function () { box.classList.add("hidden"); h.go(); };
      });
    });
  }

  // ---- In-browser two-policy comparison (within a single export) ----
  // Curated field set mirroring the per-policy cards, so the diff table reads the
  // same way as the config panels and matches on resolved names (GUID vs name
  // never registers as a difference).
  var CMP_POL_FIELDS = [
    ["Users", "Include users", function (p) { return p.includeUsers; }],
    ["Users", "Include groups", function (p) { return p.includeGroups; }],
    ["Users", "Include directory roles", function (p) { return p.includeRoles; }],
    ["Users", "Include guests / external", function (p) { return !!p.includeGuestsExternal; }],
    ["Users", "Include guest/external types", function (p) { return p.includeGuestTypes; }],
    ["Users", "Include partner tenants", function (p) { return tenantLabel(p.includeGuestTenants); }],
    ["Users", "Include service principals", function (p) { return p.includeServicePrincipals; }],
    ["Users", "Exclude users", function (p) { return p.excludeUsers; }],
    ["Users", "Exclude groups", function (p) { return p.excludeGroups; }],
    ["Users", "Exclude directory roles", function (p) { return p.excludeRoles; }],
    ["Users", "Exclude guests / external", function (p) { return !!p.excludeGuestsExternal; }],
    ["Users", "Exclude guest/external types", function (p) { return p.excludeGuestTypes; }],
    ["Users", "Exclude partner tenants", function (p) { return tenantLabel(p.excludeGuestTenants); }],
    ["Users", "Exclude service principals", function (p) { return p.excludeServicePrincipals; }],
    ["Target resources", "Cloud apps (include)", function (p) { return p.includeApplications; }],
    ["Target resources", "User actions", function (p) { return p.includeUserActions; }],
    ["Target resources", "Authentication context", function (p) { return p.authenticationContext; }],
    ["Target resources", "App filter", function (p) { return p.applicationFilter; }],
    ["Target resources", "Traffic profiles", function (p) { return p.trafficProfiles; }],
    ["Target resources", "Cloud apps (exclude)", function (p) { return p.excludeApplications; }],
    ["Conditions", "Client apps", function (p) { return p.clientAppTypes; }],
    ["Conditions", "Device platforms (include)", function (p) { return p.includePlatforms; }],
    ["Conditions", "Device platforms (exclude)", function (p) { return p.excludePlatforms; }],
    ["Conditions", "Locations (include)", function (p) { return p.includeLocations; }],
    ["Conditions", "Locations (exclude)", function (p) { return p.excludeLocations; }],
    ["Conditions", "Sign-in risk", function (p) { return p.signInRiskLevels; }],
    ["Conditions", "User risk", function (p) { return p.userRiskLevels; }],
    ["Conditions", "Service principal risk", function (p) { return p.servicePrincipalRiskLevels; }],
    ["Conditions", "Insider risk", function (p) { return p.insiderRiskLevels; }],
    ["Conditions", "Agent risk", function (p) { return p.agentRiskLevels; }],
    ["Conditions", "Authentication flows", function (p) { return p.authenticationFlows; }],
    ["Conditions", "Filter for devices", function (p) { return p.deviceFilter; }],
    ["Access controls", "Effect", function (p) { return p.isBlock ? "Block" : "Grant"; }],
    ["Access controls", "Grant operator", function (p) { return p.grantOperator; }],
    ["Access controls", "Grant controls", function (p) { return arr(p.grantControlLabels || p.grantControls).concat(arr(p.customAuthenticationFactors)); }],
    ["Access controls", "Authentication strength", function (p) { return p.authenticationStrength; }],
    ["Access controls", "Terms of use", function (p) { return p.termsOfUse; }],
    ["Access controls", "Session controls", function (p) { return p.sessionControls; }],
    ["Policy", "State", function (p) { return stateLabel(p.state); }]
  ];

  // Normalized key for equality (order-independent, name-resolved).
  function cmpValKey(v) {
    if (typeof v === "boolean") return v ? "1" : "0";
    var a = arr(v).filter(function (x) { return x !== null && x !== undefined && x !== ""; });
    return a.map(function (x) { return String(nm(x)); }).sort().join("|");
  }
  // Human display (names, Yes/No), "-" when empty.
  function cmpValDisplay(v) {
    if (typeof v === "boolean") return v ? "Yes" : "No";
    var a = arr(v).filter(function (x) { return x !== null && x !== undefined && x !== ""; });
    return a.length ? a.map(function (x) { return esc(nm(x)); }).join("<br>") : '<span class="muted">-</span>';
  }

  var cmpPolState = { left: null, right: null, open: "users", diffOnly: false, sameUsers: false };

  // Normalized signature of who a policy targets (include side): used to find
  // policies that target the same users - a strong duplicate/overlap signal.
  function cmpPolUserKey(p) {
    if (!p) return "";
    return [
      "u:" + cmpValKey(p.includeUsers),
      "g:" + cmpValKey(p.includeGroups),
      "r:" + cmpValKey(p.includeRoles),
      "x:" + cmpValKey(!!p.includeGuestsExternal),
      "t:" + cmpValKey(p.includeGuestTypes),
      "pt:" + cmpValKey(tenantLabel(p.includeGuestTenants)),
      "s:" + cmpValKey(p.includeServicePrincipals)
    ].join("||");
  }
  var CMP_POL_SECTIONS = [
    { key: "users", title: function (b) { return b.usersTitle; }, body: function (b) { return b.users; } },
    { key: "target", title: function () { return "Target resources"; }, body: function (b) { return b.target; } },
    { key: "conditions", title: function () { return "Conditions"; }, body: function (b) { return b.conditions; } },
    { key: "controls", title: function () { return "Access controls"; }, body: function (b) { return b.controls; } }
  ];

  function cmpPolFilteredOptions(filter, refUserKey, excludeIdx) {
    var f = (filter || "").trim().toLowerCase();
    var out = [];
    policies.forEach(function (p, i) {
      if (f && (String(p.displayName) + " " + String(p.id)).toLowerCase().indexOf(f) === -1) return;
      if (refUserKey !== null && refUserKey !== undefined) {
        if (i === excludeIdx) return;
        if (cmpPolUserKey(p) !== refUserKey) return;
      }
      out.push(i);
    });
    return out;
  }

  function cmpPolPopulate(sel, filter, current, refUserKey, excludeIdx) {
    if (!sel) return;
    var idxs = cmpPolFilteredOptions(filter, refUserKey, excludeIdx);
    var html = '<option value="">&mdash; select a policy &mdash;</option>';
    idxs.forEach(function (i) {
      var p = policies[i];
      html += '<option value="' + i + '">' + esc(p.displayName) + " (" + esc(stateLabel(p.state)) + ")</option>";
    });
    sel.innerHTML = html;
    if (current !== null && current !== undefined && idxs.indexOf(current) !== -1) sel.value = String(current);
    else if (idxs.length === 1) sel.value = String(idxs[0]);
  }

  // The right dropdown is optionally restricted to policies targeting the same
  // users as the left policy. Returns the reference key (or null when off).
  function cmpPolRightRefKey() {
    if (!cmpPolState.sameUsers) return null;
    if (cmpPolState.left === null || cmpPolState.left === undefined) return null;
    return cmpPolUserKey(policies[cmpPolState.left]);
  }
  function cmpPolRepopulateRight() {
    var rs = el("cmpPolRight"), rq = el("cmpPolRightQ"), hint = el("cmpPolSameHint");
    if (!rs) return;
    var ref = cmpPolRightRefKey();
    cmpPolPopulate(rs, rq ? rq.value : "", cmpPolState.right, ref, cmpPolState.left);
    cmpPolState.right = rs.value === "" ? null : parseInt(rs.value, 10);
    if (hint) {
      if (ref === null) { hint.textContent = ""; }
      else {
        var n = cmpPolFilteredOptions("", ref, cmpPolState.left).length;
        hint.textContent = n + " other policy(ies) target the same users.";
      }
    }
  }

  function cmpPolColumn(p, side) {
    if (!p) return '<div class="cmppol-col"><p class="muted">Select a policy above.</p></div>';
    var b = policyCardBodies(p);
    var secs = CMP_POL_SECTIONS.map(function (s) {
      var open = cmpPolState.open === s.key;
      return '<div class="acc' + (open ? " open" : "") + '">' +
        '<button type="button" class="acc-h" data-sec="' + s.key + '">' + esc(s.title(b)) + "</button>" +
        (open ? '<div class="acc-b">' + s.body(b) + "</div>" : "") + "</div>";
    }).join("");
    return '<div class="cmppol-col ' + side + '">' + policyHeadHtml(p) + secs + "</div>";
  }

  function cmpPolTable(l, r) {
    var groups = {}, order = [], nDiff = 0, nCmp = 0;
    CMP_POL_FIELDS.forEach(function (f) {
      var sec = f[0], label = f[1], get = f[2];
      var lv = get(l), rv = get(r);
      var diff = cmpValKey(lv) !== cmpValKey(rv);
      nCmp++; if (diff) nDiff++;
      if (cmpPolState.diffOnly && !diff) return;
      if (!groups[sec]) { groups[sec] = []; order.push(sec); }
      groups[sec].push(
        '<tr class="' + (diff ? "row-diff" : "row-same") + '">' +
          "<td>" + esc(label) + "</td>" +
          "<td>" + cmpValDisplay(lv) + "</td>" +
          "<td>" + cmpValDisplay(rv) + "</td></tr>"
      );
    });
    var head = '<thead><tr><th>Field</th><th>' + esc(l.displayName) + "</th><th>" + esc(r.displayName) + "</th></tr></thead>";
    var body = order.map(function (sec) {
      return '<tr class="cmp-sec"><td colspan="3">' + esc(sec) + "</td></tr>" + groups[sec].join("");
    }).join("");
    if (!body) body = '<tr><td colspan="3" class="muted">No fields to show.</td></tr>';
    var summary = '<p class="cmppol-summary"><b>' + nDiff + "</b> of " + nCmp +
      " comparable fields differ. <span class=\"muted\">Differences are highlighted.</span></p>";
    return summary + "<table>" + head + "<tbody>" + body + "</tbody></table>";
  }

  function renderCmpPolicies() {
    var host = el("cmpPolCards"), tbl = el("cmpPolTable");
    if (!host) return;
    var l = (cmpPolState.left !== null) ? policies[cmpPolState.left] : null;
    var r = (cmpPolState.right !== null) ? policies[cmpPolState.right] : null;
    host.innerHTML = '<div class="cmppol-cols">' + cmpPolColumn(l, "left") + cmpPolColumn(r, "right") + "</div>";
    // Section headers act as a synced accordion across both columns.
    host.querySelectorAll(".acc-h").forEach(function (btn) {
      btn.onclick = function () { cmpPolState.open = btn.getAttribute("data-sec"); renderCmpPolicies(); };
    });
    if (tbl) {
      if (l && r) tbl.innerHTML = cmpPolTable(l, r);
      else tbl.innerHTML = '<p class="muted">Pick a policy on the left and right to see a field-by-field comparison.</p>';
    }
    localizeStamps();
  }

  function initComparePolicies() {
    var ls = el("cmpPolLeft"), rs = el("cmpPolRight");
    if (!ls || !rs) return;
    if (policies.length) cmpPolState.left = 0;
    if (policies.length > 1) cmpPolState.right = 1;
    cmpPolPopulate(ls, "", cmpPolState.left);
    cmpPolPopulate(rs, "", cmpPolState.right);
    var lq = el("cmpPolLeftQ"), rq = el("cmpPolRightQ");
    if (lq) lq.addEventListener("input", function () {
      cmpPolPopulate(ls, lq.value, cmpPolState.left);
      cmpPolState.left = ls.value === "" ? null : parseInt(ls.value, 10);
      cmpPolRepopulateRight();
      renderCmpPolicies();
    });
    if (rq) rq.addEventListener("input", function () {
      cmpPolRepopulateRight();
      renderCmpPolicies();
    });
    ls.addEventListener("change", function () {
      cmpPolState.left = ls.value === "" ? null : parseInt(ls.value, 10);
      cmpPolRepopulateRight();
      renderCmpPolicies();
    });
    rs.addEventListener("change", function () { cmpPolState.right = rs.value === "" ? null : parseInt(rs.value, 10); renderCmpPolicies(); });
    var swap = el("cmpPolSwap");
    if (swap) swap.addEventListener("click", function () {
      var t = cmpPolState.left; cmpPolState.left = cmpPolState.right; cmpPolState.right = t;
      cmpPolPopulate(ls, lq ? lq.value : "", cmpPolState.left);
      cmpPolRepopulateRight();
      renderCmpPolicies();
    });
    var diffOnly = el("cmpPolDiffOnly");
    if (diffOnly) diffOnly.addEventListener("change", function () { cmpPolState.diffOnly = diffOnly.checked; renderCmpPolicies(); });
    var sameUsers = el("cmpPolSameUsers");
    if (sameUsers) sameUsers.addEventListener("change", function () {
      cmpPolState.sameUsers = sameUsers.checked;
      cmpPolRepopulateRight();
      renderCmpPolicies();
    });
    renderCmpPolicies();
  }

  // --- Export safely -------------------------------------------------------
  // The payload was built and leak-tested by PowerShell and embedded verbatim.
  // Nothing is masked here on purpose: masking in the browser could not be
  // verified, and a silent miss would be worse than no button at all.
  function setupSafeExport() {
    var btn = el("safeExportBtn"), modal = el("safeModal");
    if (!btn || !modal) return;
    var payload = window.__CAP_SAFE__;
    if (!payload) return;  // no verified bundle -> no button

    var hint = el("safeExportHint");
    btn.classList.remove("hidden");
    if (hint) hint.classList.remove("hidden");

    var snap = window.__CAP_SNAPSHOT__ || "export";
    var fileName = "cap-safe-review-" + snap + ".json";
    var errBox = el("safeModalErr");

    function close() { modal.classList.add("hidden"); }
    function fail(msg) {
      if (!errBox) return;
      errBox.textContent = msg;
      errBox.classList.remove("hidden");
    }

    btn.addEventListener("click", function () {
      if (errBox) errBox.classList.add("hidden");
      modal.classList.remove("hidden");
    });
    el("safeCancel").addEventListener("click", close);
    modal.addEventListener("click", function (e) { if (e.target === modal) close(); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !modal.classList.contains("hidden")) close();
    });

    // Plain download to the browser's download folder. Always available, so it
    // doubles as the recovery path when the location picker is unavailable.
    function saveViaDownload(blob) {
      try {
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url; a.download = fileName;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
        close();
      } catch (e) {
        fail("Could not save the file: " + e.message);
      }
    }

    el("safeConfirm").addEventListener("click", function () {
      var blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });

      // Prefer a real "choose a location" dialog. It is Chromium-only and can
      // be blocked by policy or by the page's origin, so any failure other than
      // the user cancelling falls back rather than leaving them stuck.
      if (window.showSaveFilePicker) {
        var picker;
        try {
          picker = window.showSaveFilePicker({
            suggestedName: fileName,
            types: [{ description: "JSON file", accept: { "application/json": [".json"] } }]
          });
        } catch (e) {
          saveViaDownload(blob);
          return;
        }
        picker.then(function (handle) {
          return handle.createWritable().then(function (w) {
            return w.write(blob).then(function () { return w.close(); });
          }).then(close);
        }).catch(function (e) {
          if (e && e.name === "AbortError") return;  // user cancelled - do nothing
          saveViaDownload(blob);
        });
        return;
      }

      saveViaDownload(blob);
    });
  }

  window.addEventListener("DOMContentLoaded", function () {
    localizeStamps();
    renderSummaryCards();
    renderFindings();
    renderAllTable();
    renderDelta();
    renderRiskFindings("", "all");
    renderContradictions();
    renderCompliance();
    renderTests();
    renderAuthMethods();
    populateFacets();
    renderList("", "all");
    initComparePolicies();
    if (policies.length) { selected = 0; renderDetail(policies[0]); }

    el("q").addEventListener("input", function () { renderList(el("q").value, el("fstate").value); });
    el("fstate").addEventListener("change", function () { renderList(el("q").value, el("fstate").value); });
    [["feffect", "effect"], ["fprincipal", "principal"], ["fapp", "app"], ["fcond", "cond"], ["fgrant", "grant"]].forEach(function (pair) {
      var node = el(pair[0]);
      if (node) node.addEventListener("change", function () { pfilter[pair[1]] = node.value; renderList(el("q").value, el("fstate").value); });
    });
    if (el("filterClear")) el("filterClear").addEventListener("click", clearFilters);
    if (el("fq")) el("fq").addEventListener("input", function () { renderRiskFindings(el("fq").value, el("fsev").value); });
    if (el("fsev")) el("fsev").addEventListener("change", function () { renderRiskFindings(el("fq").value, el("fsev").value); });
    document.querySelectorAll(".tab").forEach(function (t) {
      t.onclick = function () { showTab(t.getAttribute("data-tab")); };
    });
    if (el("gsearch")) {
      el("gsearch").addEventListener("input", function () { renderGlobalSearch(el("gsearch").value); });
      el("gsearch").addEventListener("focus", function () { if (el("gsearch").value) renderGlobalSearch(el("gsearch").value); });
    }
    if (el("cmpSource")) {
      el("cmpSource").addEventListener("change", function () { cmpLoadFile(this, "source", el("cmpSourceInfo")); });
      el("cmpTarget").addEventListener("change", function () { cmpLoadFile(this, "target", el("cmpTargetInfo")); });
      el("cmpRun").addEventListener("click", function () {
        if (!cmpSourceData || !cmpTargetData) return;
        el("cmpMsg").textContent = "";
        try {
          renderCompareResult(cmpCompareExport(cmpSourceData, cmpTargetData));
        } catch (e) {
          el("cmpMsg").textContent = "Comparison failed: " + e.message;
        }
      });
      el("cmpSwap").addEventListener("click", function () {
        var s = cmpSourceData; cmpSourceData = cmpTargetData; cmpTargetData = s;
        var si = el("cmpSourceInfo").textContent;
        el("cmpSourceInfo").textContent = el("cmpTargetInfo").textContent;
        el("cmpTargetInfo").textContent = si;
        el("cmpSource").value = ""; el("cmpTarget").value = "";
        cmpUpdateButton();
        if (cmpSourceData && cmpTargetData) el("cmpRun").click();
      });
    }
    setupSafeExport();

    document.addEventListener("click", function (e) {
      var g = el("gresults");
      if (g && !g.classList.contains("hidden") && !e.target.closest(".gsearch")) g.classList.add("hidden");
    });
    showTab("overview");
  });
})();
