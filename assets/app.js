/* CAPVisualizer offline viewer. Vanilla JS, no external dependencies. */
(function () {
  "use strict";
  var DATA = window.__CAP_DATA__ || { policies: [], summary: {}, findings: [], delta: null };
  function arr(v) { return Array.isArray(v) ? v : (v === null || v === undefined || v === "" ? [] : [v]); }
  var policies = arr(DATA.policies);
  var selected = null;

  function el(id) { return document.getElementById(id); }
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
  function stateClass(s) {
    if (s === "enabled") return "enabled";
    if (s === "enabledForReportingButNotEnforced") return "report";
    return "disabled";
  }
  function stateLabel(s) {
    if (s === "enabledForReportingButNotEnforced") return "report-only";
    return s;
  }

  function renderList(filterText, filterState) {
    var ul = el("plist");
    ul.innerHTML = "";
    var ft = (filterText || "").toLowerCase();
    policies.forEach(function (p, i) {
      if (filterState && filterState !== "all" && p.state !== filterState) return;
      if (ft && (p.displayName || "").toLowerCase().indexOf(ft) === -1) return;
      var li = document.createElement("li");
      if (selected === i) li.className = "active";
      li.innerHTML = '<span class="dot ' + stateClass(p.state) + '"></span>' +
        '<span>' + esc(p.displayName || "(no name)") + '</span>';
      li.onclick = function () { selected = i; renderList(filterText, filterState); renderDetail(p); };
      ul.appendChild(li);
    });
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
  function flag(label, on) { return on ? "<div class=\"kv\"><span class=\"k\">" + label + "</span><span class=\"v\">Yes</span></div>" : ""; }

  function renderDetail(p) {
    var blockCls = p.isBlock ? " block" : "";
    var usersTitle = p.isWorkloadIdentity ? "Workload identities" : "Users";

    var userInc = [
      row("Users", p.includeUsers),
      row("Groups", p.includeGroups),
      row("Directory roles", p.includeRoles),
      flag("Guests / external users", p.includeGuestsExternal),
      row("Guest/external types", p.includeGuestTypes),
      row("Service principals", p.includeServicePrincipals)
    ];
    var userExc = [
      row("Users", p.excludeUsers),
      row("Groups", p.excludeGroups),
      row("Directory roles", p.excludeRoles),
      flag("Guests / external users", p.excludeGuestsExternal),
      row("Guest/external types", p.excludeGuestTypes),
      row("Service principals", p.excludeServicePrincipals)
    ];

    var appInc = [
      row("Cloud apps", p.includeApplications),
      row("User actions", p.includeUserActions),
      row("Authentication context", p.authenticationContext),
      (p.applicationFilter ? row("App filter", p.applicationFilter) : "")
    ];
    var appExc = [ row("Cloud apps", p.excludeApplications) ];

    var conditions = [
      row("Client apps", p.clientAppTypes),
      row("Device platforms (include)", p.includePlatforms),
      row("Device platforms (exclude)", p.excludePlatforms),
      row("Locations (include)", p.includeLocations),
      row("Locations (exclude)", p.excludeLocations),
      row("Sign-in risk", p.signInRiskLevels),
      row("User risk", p.userRiskLevels),
      row("Service principal risk", p.servicePrincipalRiskLevels),
      (p.deviceFilter ? row("Filter for devices", p.deviceFilter) : "")
    ].join("");
    if (!conditions) conditions = '<span class="muted">Not configured</span>';

    var controls = "<div class=\"kv\"><span class=\"k\">Grant (" + esc(p.grantOperator || "-") + ")</span><span class=\"v\">" + controlPills(p) + "</span></div>";
    controls += row("Terms of use", p.termsOfUse);
    var sess = arr(p.sessionControls);
    controls += sess.length ? "<div class=\"kv\"><span class=\"k\">Session</span><span class=\"v\">" + sess.map(esc).join("<br>") + "</span></div>" : "";

    var link = p.portalLink ? ' &nbsp;·&nbsp; <a href="' + esc(p.portalLink) + '" target="_blank" rel="noopener">open in Entra portal &#8599;</a>' : "";

    var html = "" +
      '<h2>' + esc(p.displayName) + ' <span class="pill ' + (p.state === "enabled" ? "ok" : "") + '">' + esc(stateLabel(p.state)) + "</span></h2>" +
      '<div class="muted" style="margin-bottom:12px">id: <code>' + esc(p.id) + "</code>" +
      (p.modifiedDateTime ? " &nbsp;·&nbsp; modified: " + esc(p.modifiedDateTime) : "") + link + "</div>" +
      '<div class="flow">' +
        '<div class="flowcol"><h3>' + usersTitle + "</h3>" + incExc(userInc, userExc) + "</div>" +
        '<div class="arrow">&rarr;</div>' +
        '<div class="flowcol"><h3>Target resources</h3>' + incExc(appInc, appExc) + "</div>" +
        '<div class="arrow">&rarr;</div>' +
        '<div class="flowcol"><h3>Conditions</h3>' + conditions + "</div>" +
        '<div class="arrow">&rArr;</div>' +
        '<div class="flowcol controls' + blockCls + '"><h3>Access controls</h3>' + controls + "</div>" +
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
    var h = "<p>Compared against baseline <code>" + esc(d.baselineUtc) + "</code></p>" +
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
            return "<tr><td>" + esc(c.field) + "</td><td>" + esc(c.from) + "</td><td>" + esc(c.to) + "</td></tr>";
          }).join("") + "</tbody></table>";
      });
    }
    el("delta").innerHTML = h;
  }

  function showTab(name) {
    ["overview", "detailview", "delta"].forEach(function (t) {
      var pane = el("pane-" + t);
      if (pane) pane.classList.toggle("hidden", t !== name);
    });
    document.querySelectorAll(".tab").forEach(function (t) {
      t.classList.toggle("active", t.getAttribute("data-tab") === name);
    });
  }

  window.addEventListener("DOMContentLoaded", function () {
    renderSummaryCards();
    renderFindings();
    renderAllTable();
    renderDelta();
    renderList("", "all");
    if (policies.length) { selected = 0; renderDetail(policies[0]); }

    el("q").addEventListener("input", function () { renderList(el("q").value, el("fstate").value); });
    el("fstate").addEventListener("change", function () { renderList(el("q").value, el("fstate").value); });
    document.querySelectorAll(".tab").forEach(function (t) {
      t.onclick = function () { showTab(t.getAttribute("data-tab")); };
    });
    showTab("overview");
  });
})();
