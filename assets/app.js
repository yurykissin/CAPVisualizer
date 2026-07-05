/* CAPVisualizer offline viewer. Vanilla JS, no external dependencies. */
(function () {
  "use strict";
  var DATA = window.__CAP_DATA__ || { policies: [], summary: {}, findings: [], delta: null };
  var policies = DATA.policies || [];
  var selected = null;

  function el(id) { return document.getElementById(id); }
  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function arr(v) { return Array.isArray(v) ? v : (v === null || v === undefined || v === "" ? [] : [v]); }
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
    if (p.isBlock) out.push('<span class="pill block">BLOCK</span>');
    (p.grantControls || []).forEach(function (c) {
      if (c === "block") return;
      var cls = (c === "mfa") ? "pill mfa" : "pill";
      out.push('<span class="' + cls + '">' + esc(c) + "</span>");
    });
    if (p.authenticationStrength) out.push('<span class="pill mfa">strength: ' + esc(p.authenticationStrength) + "</span>");
    if (!out.length) out.push('<span class="muted">none</span>');
    return out.join(" ");
  }

  function renderDetail(p) {
    var blockCls = p.isBlock ? " block" : "";
    var html = "" +
      '<h2>' + esc(p.displayName) + ' <span class="pill ' + (p.state === "enabled" ? "ok" : "") + '">' + esc(stateLabel(p.state)) + "</span></h2>" +
      '<div class="muted" style="margin-bottom:12px">id: <code>' + esc(p.id) + "</code>" +
      (p.modifiedDateTime ? " &nbsp;·&nbsp; modified: " + esc(p.modifiedDateTime) : "") + "</div>" +
      '<div class="flow">' +
        '<div class="flowcol"><h3>Users</h3>' +
          "<b>Include</b>" + list(p.includeUsers.concat(p.includeGroups, p.includeRoles)) +
          "<br><b>Exclude</b>" + list(p.excludeUsers.concat(p.excludeGroups, p.excludeRoles)) + "</div>" +
        '<div class="arrow">&rarr;</div>' +
        '<div class="flowcol"><h3>Target resources</h3>' +
          "<b>Include apps</b>" + list(p.includeApplications) +
          "<br><b>Exclude apps</b>" + list(p.excludeApplications) +
          (arr(p.includeUserActions).length ? "<br><b>User actions</b>" + list(p.includeUserActions) : "") + "</div>" +
        '<div class="arrow">&rarr;</div>' +
        '<div class="flowcol"><h3>Conditions</h3>' +
          "<b>Client apps</b>" + list(p.clientAppTypes) +
          "<br><b>Platforms</b>" + list(p.includePlatforms) +
          "<br><b>Locations</b>" + list(p.includeLocations) +
          (arr(p.excludeLocations).length ? " (excl: " + list(p.excludeLocations) + ")" : "") +
          "<br><b>Sign-in risk</b>" + list(p.signInRiskLevels) +
          "<br><b>User risk</b>" + list(p.userRiskLevels) +
          (p.deviceFilter ? "<br><b>Device filter</b><br>" + esc(p.deviceFilter) : "") + "</div>" +
        '<div class="arrow">&rArr;</div>' +
        '<div class="flowcol controls' + blockCls + '"><h3>Access controls</h3>' +
          "<b>Grant (" + esc(p.grantOperator || "-") + ")</b><br>" + controlPills(p) +
          (arr(p.sessionControls).length ? "<br><br><b>Session</b>" + list(p.sessionControls) : "") +
          (arr(p.termsOfUse).length ? "<br><b>Terms of use</b>" + list(p.termsOfUse) : "") + "</div>" +
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
    var f = DATA.findings || [];
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
        "<td>" + list(p.includeUsers.concat(p.includeGroups, p.includeRoles)) + "</td>" +
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
      if (!items || !items.length) return "";
      return "<h3>" + title + "</h3><table><tbody>" + items.map(function (x) {
        return '<tr><td class="' + cls + '">' + esc(x.displayName) + "</td><td>" + esc(x.state || "") + "</td></tr>";
      }).join("") + "</tbody></table>";
    }
    h += tbl("Added", d.added, "badge-add");
    h += tbl("Removed", d.removed, "badge-remove");
    if (d.modified && d.modified.length) {
      h += "<h3>Modified</h3>";
      d.modified.forEach(function (m) {
        h += "<b class=\"badge-mod\">" + esc(m.displayName) + "</b> (" + m.changeCount + " changes)" +
          "<table><thead><tr><th>Field</th><th>From</th><th>To</th></tr></thead><tbody>" +
          m.changes.map(function (c) {
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
