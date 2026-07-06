#!/usr/bin/env python3
"""Generate the 'Jira Audit Events' dashboard NDJSON for OpenSearch Dashboards 2.19.

Scope: dashboard-level filter pins data.jira_integration:jira so every panel inherits it.
Source: wazuh-jira integration (/var/ossec/integrations/jira_events.py, polled every
5 minutes) -> jira-json decoder -> ruleset 126000-126099.

Flat fields emitted by the poller power the panels:
  data.jira_summary           human-readable audit summary (what the rules match on)
  data.jira_category          Jira audit category (e.g. "user management", "permissions")
  data.jira_author_name       display name of the acting user
  data.jira_author_key        actor key (Data Center; Cloud may only carry account_id)
  data.jira_author_account_id actor account id (Cloud)
  data.jira_src_ip            source IP when the audit record carries one
  data.jira_object_type/name  primary object acted on
  data.jira_site_host         Jira site host

Index pattern: wazuh-alerts-*  (saved-object id == title).
Import: OpenSearch Dashboards -> Dashboards Management -> Saved objects -> Import.
"""
import json
import os

IDX = "wazuh-alerts-*"
IDXREF = "kibanaSavedObjectMeta.searchSourceJSON.index"
D = "data."
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jira-audit-dashboard.ndjson")
objects = []

def idx_reference():
    return [{"name": IDXREF, "type": "index-pattern", "id": IDX}]

def viz(vid, title, vis_state, extra_filters=None):
    refs = idx_reference()
    filters = []
    if extra_filters:
        for i, (f, _field) in enumerate(extra_filters):
            ref_name = f"kibanaSavedObjectMeta.searchSourceJSON.filter[{i}].meta.index"
            f = json.loads(json.dumps(f))
            f["meta"]["indexRefName"] = ref_name
            filters.append(f)
            refs.append({"name": ref_name, "type": "index-pattern", "id": IDX})
    ss = {"query": {"query": "", "language": "kuery"}, "filter": filters, "indexRefName": IDXREF}
    objects.append({
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title, "visState": json.dumps(vis_state), "uiStateJSON": "{}",
            "description": "", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(ss)},
        },
        "references": refs,
    })

# ---- filters ----------------------------------------------------------------
def level_gte(n, alias):
    return ({"meta": {"alias": alias, "disabled": False, "negate": False, "type": "range",
                      "key": "rule.level", "params": {"gte": n}},
             "range": {"rule.level": {"gte": n}}, "$state": {"store": "appState"}}, "rule.level")

def phrase(field, value, alias=None, negate=False):
    return ({"meta": {"alias": alias or value, "disabled": False, "negate": negate, "type": "phrase",
                      "key": field, "params": {"query": value}},
             "query": {"match_phrase": {field: value}}, "$state": {"store": "appState"}}, field)

def kql(query, alias):
    return ({"meta": {"alias": alias, "disabled": False, "negate": False, "type": "custom", "key": "query"},
             "query": {"query_string": {"query": query}}, "$state": {"store": "appState"}}, "query")

# ---- agg builders -----------------------------------------------------------
def count_metric():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}

def cardinality(field, label, gid="1"):
    return {"id": gid, "enabled": True, "type": "cardinality", "schema": "metric",
            "params": {"field": field, "customLabel": label}}

def terms(field, size, schema="segment", label=None, gid="2", order_field="1"):
    p = {"field": field, "orderBy": order_field, "order": "desc", "size": size,
         "otherBucket": False, "otherBucketLabel": "Other",
         "missingBucket": False, "missingBucketLabel": "Missing"}
    if label:
        p["customLabel"] = label
    return {"id": gid, "enabled": True, "type": "terms", "schema": schema, "params": p}

def bucket(field, size, label, gid, order_field="1"):
    return terms(field, size, "bucket", label, gid, order_field)

def filters_agg(buckets, schema="segment", gid="2"):
    return {"id": gid, "enabled": True, "type": "filters", "schema": schema,
            "params": {"filters": [{"input": {"language": "kuery", "query": q}, "label": lab}
                                    for lab, q in buckets]}}

# ---- viz factories ----------------------------------------------------------
def metric(vid, title, agg, color_to=2000000, filt=None):
    viz(vid, title, {
        "title": title, "type": "metric",
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                              "metricColorMode": "None", "colorsRange": [{"from": 0, "to": color_to}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgColor": False, "labelColor": False, "subText": "", "fontSize": 36}}},
        "aggs": [agg]}, extra_filters=filt)

def pie(vid, title, field, label, size=10, filt=None):
    viz(vid, title, {
        "title": title, "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
        "aggs": [count_metric(), terms(field, size, "segment", label)]}, extra_filters=filt)

def pie_filters(vid, title, buckets, filt=None):
    viz(vid, title, {
        "title": title, "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
        "aggs": [count_metric(), filters_agg(buckets, "segment")]}, extra_filters=filt)

def table(vid, title, bucket_aggs, perPage=10, filt=None, metric_agg=None):
    viz(vid, title, {
        "title": title, "type": "table",
        "params": {"perPage": perPage, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "showTotal": True, "totalFunc": "sum", "percentageCol": "", "showToolbar": True},
        "aggs": [metric_agg or count_metric()] + bucket_aggs}, extra_filters=filt)

def _bar_axes(pos_cat, pos_val):
    return {"grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": pos_cat,
                              "show": True, "scale": {"type": "linear"},
                              "labels": {"show": True, "filter": False, "truncate": 200}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": pos_val,
                           "show": True, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100},
                           "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True}],
            "addTooltip": True, "addLegend": False, "legendPosition": "right",
            "times": [], "addTimeMarker": False, "labels": {}}

def hbar(vid, title, field, label, size=15, filt=None):
    p = _bar_axes("left", "bottom"); p["type"] = "horizontal_bar"
    viz(vid, title, {"title": title, "type": "horizontal_bar", "params": p,
                     "aggs": [count_metric(), terms(field, size, "segment", label)]}, extra_filters=filt)

def timeline_filters(vid, title, buckets, filt=None):
    p = _bar_axes("bottom", "left"); p["type"] = "histogram"
    p["addLegend"] = True
    viz(vid, title, {"title": title, "type": "histogram", "params": p,
                     "aggs": [count_metric(),
                              {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                               "params": {"field": "timestamp", "useNormalizedEsInterval": True,
                                          "interval": "auto", "drop_partials": False,
                                          "min_doc_count": 1, "extended_bounds": {}}},
                              filters_agg(buckets, "group", gid="3")]}, extra_filters=filt)

def markdown(vid, title, md):
    viz(vid, title, {"title": title, "type": "markdown",
                     "params": {"fontSize": 12, "openLinksInNewTab": False, "markdown": md},
                     "aggs": []})

# ---- shared bucket sets -----------------------------------------------------
SEVERITY = [("Critical/High (L≥10)", "rule.level >= 10"),
            ("Medium (L6-9)", "rule.level >= 6 and rule.level < 10"),
            ("Low/Informational (L<6)", "rule.level < 6")]

DETECTIONS = [("Admin granted (126020/1)", "rule.id:(126020 or 126021)"),
              ("MFA/SSO disabled (126016)", "rule.id:126016"),
              ("Auth config changed (126017)", "rule.id:126017"),
              ("Public access enabled (126023)", "rule.id:126023"),
              ("Scheme/global perm changed (126027)", "rule.id:126027"),
              ("App/webhook trust (126040)", "rule.id:126040"),
              ("API token created (126042)", "rule.id:126042"),
              ("Websudo granted (126011)", "rule.id:126011"),
              ("Audit log tampering (126060)", "rule.id:126060"),
              ("Full export/backup (126070)", "rule.id:126070"),
              ("Brute force (126013/4)", "rule.id:(126013 or 126014)"),
              ("Bulk export (126074)", "rule.id:126074")]

AUTH = [("Success/session (126015)", "rule.id:126015"),
        ("Failed login (126012)", "rule.id:126012"),
        ("Brute force (126013/4)", "rule.id:(126013 or 126014)"),
        ("Websudo failed (126010)", "rule.id:126010"),
        ("Websudo granted (126011)", "rule.id:126011")]

PERMS = [("Public access enabled (126023)", "rule.id:126023"),
         ("Exposure removed (126024)", "rule.id:126024"),
         ("Portal/KB changed (126025)", "rule.id:126025"),
         ("Scheme changed (126026/7)", "rule.id:(126026 or 126027)"),
         ("App access changed (126028)", "rule.id:126028"),
         ("Role membership (126029)", "rule.id:126029"),
         ("Permission changed (126030)", "rule.id:126030"),
         ("Repeated changes (126031/2)", "rule.id:(126031 or 126032)")]

EXPORTS = [("Full export/backup (126070)", "rule.id:126070"),
           ("Assets/Insight export (126071)", "rule.id:126071"),
           ("Restore/import (126072)", "rule.id:126072"),
           ("Issue/object export (126073)", "rule.id:126073"),
           ("Bulk export corr (126074)", "rule.id:126074")]

AUDIT = [("Config/retention changed (126060)", "rule.id:126060"),
         ("Exported (126061)", "rule.id:126061"),
         ("Viewed/searched (126062)", "rule.id:126062")]

USERS = [("Group changed (126045)", "rule.id:126045"),
         ("User lifecycle (126046)", "rule.id:126046"),
         ("Added to admin group (126021)", "rule.id:126021")]

FALLBACK = [("Security/identity fallback (126090)", "rule.id:126090"),
            ("Admin/config fallback (126091)", "rule.id:126091")]

EXPORT_IDS = "rule.id:(126070 or 126071 or 126073 or 126074)"
PERM_IDS = ("rule.id:(126023 or 126024 or 126025 or 126026 or 126027 or "
            "126028 or 126029 or 126030 or 126031 or 126032)")
CORR_IDS = "rule.id:(126013 or 126014 or 126031 or 126032 or 126074)"

# ============================================================================
# PANELS
# ============================================================================
markdown("jira-header", "JIRA — Header",
         "## 🟦 Jira Audit Events\n"
         "Jira audit records from `/rest/api/3/auditing/record`, collected by the "
         "`jira_events.py` integration (command wodle, polled every 5 minutes) → `jira-json` "
         "decoder → ruleset **126000-126099** (`wazuh-alerts-*`, scoped to "
         "`data.jira_integration:jira`). Every audit record is flattened to collision-safe "
         "`jira_*` fields; rules classify the free-text `jira_summary` into layered "
         "severity tiers with correlation rules for brute force, repeated permission "
         "changes, and bulk export.")

# ---- Overview / KPIs -------------------------------------------------------
markdown("jira-md-overview", "JIRA — md Overview", "### 📊 Overview")
metric("jira-total", "JIRA — Total Events", count_metric())
metric("jira-actors", "JIRA — Distinct Actors", cardinality(f"{D}jira_author_name", "Actors"), color_to=500)
metric("jira-categories", "JIRA — Distinct Categories", cardinality(f"{D}jira_category", "Categories"), color_to=50)
metric("jira-high", "JIRA — High Severity (L≥10)", count_metric(), color_to=50,
       filt=[level_gte(10, "L>=10")])
metric("jira-corr", "JIRA — Correlation Alerts", count_metric(), color_to=25,
       filt=[kql(CORR_IDS, "correlations")])
metric("jira-fallback", "JIRA — Fallback Hits (126090/1)", count_metric(), color_to=100,
       filt=[kql("rule.id:(126090 or 126091)", "fallback")])
timeline_filters("jira-timeline", "JIRA — Events Over Time (by severity)", SEVERITY)
pie_filters("jira-severity", "JIRA — Severity Distribution", SEVERITY)
hbar("jira-category", "JIRA — Category Distribution", f"{D}jira_category", "Category", 20)
hbar("jira-rules-bar", "JIRA — Top Rules Fired", "rule.description", "Rule", 15)

# ---- Activity detail -------------------------------------------------------
markdown("jira-md-activity", "JIRA — md Activity",
         "### 🧭 Activity Detail  \n_Who did what: most frequent audit summaries and actors, "
         "which rules fired, and which objects and sites were touched._")
table("jira-top-actions", "JIRA — Top Audit Summaries (summary · category)",
      [bucket(f"{D}jira_summary", 30, "Summary", "2"),
       bucket(f"{D}jira_category", 1, "Category", "3")], 15)
table("jira-top-actors", "JIRA — Top Actors (name · key)",
      [bucket(f"{D}jira_author_name", 25, "Actor", "2"),
       bucket(f"{D}jira_author_key", 1, "Key", "3")], 15)
hbar("jira-actor-bar", "JIRA — Most Active Actors", f"{D}jira_author_name", "Actor", 15)
table("jira-rules", "JIRA — Rules Fired (ID · Description · Level)",
      [bucket("rule.id", 40, "Rule ID", "2"),
       bucket("rule.description", 1, "Description", "3"),
       bucket("rule.level", 1, "Level", "4")], 15)
table("jira-objects", "JIRA — Objects Acted On (type · name)",
      [bucket(f"{D}jira_object_type", 15, "Object type", "2"),
       bucket(f"{D}jira_object_name", 3, "Top objects", "3")], 10)
table("jira-sites", "JIRA — Sites (data.jira_site_host)",
      [bucket(f"{D}jira_site_host", 10, "Site host", "2"),
       bucket(f"{D}jira_event_source", 1, "Event source", "3")], 10)

# ---- Security & detections -------------------------------------------------
markdown("jira-md-sec", "JIRA — md Security",
         "### 🚨 Security & Detections  \n_High-signal detections from Layer 1 (summary-specific) "
         "and Layer 3 (correlation). The KPI row counts each detection family; the table lists "
         "every event at **level ≥ 8**; the MITRE table maps alerts to ATT&CK techniques._")
metric("jira-sec-admin", "Admin granted (126020/1)", count_metric(), color_to=10,
       filt=[kql("rule.id:(126020 or 126021)", "admin granted")])
metric("jira-sec-mfa", "MFA/SSO disabled (126016)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "126016", "mfa disabled")])
metric("jira-sec-public", "Public access enabled (126023)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "126023", "public enabled")])
metric("jira-sec-app", "App/webhook trust (126040)", count_metric(), color_to=25,
       filt=[phrase("rule.id", "126040", "app trust")])
metric("jira-sec-token", "API token created (126042)", count_metric(), color_to=25,
       filt=[phrase("rule.id", "126042", "api token")])
metric("jira-sec-audit", "Audit log tampering (126060)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "126060", "audit tampering")])
timeline_filters("jira-sec-timeline", "JIRA — Detections Over Time", DETECTIONS)
pie_filters("jira-sec-pie", "JIRA — Detection Mix", DETECTIONS)
table("jira-sec-table", "JIRA — High-Severity Events (L≥8): actor · summary · detection",
      [bucket(f"{D}jira_author_name", 30, "Actor", "2"),
       bucket(f"{D}jira_summary", 1, "Summary", "3"),
       bucket("rule.description", 1, "Detection", "4"),
       bucket("rule.level", 1, "Level", "5")], 20, filt=[level_gte(8, "L>=8")])
table("jira-mitre", "JIRA — MITRE ATT&CK (technique · tactic)",
      [bucket("rule.mitre.id", 20, "Technique ID", "2"),
       bucket("rule.mitre.technique", 1, "Technique", "3"),
       bucket("rule.mitre.tactic", 1, "Tactic", "4")], 10)

# ---- Authentication --------------------------------------------------------
markdown("jira-md-auth", "JIRA — md Auth",
         "### 🔑 Authentication & Privileged Access  \n_Login successes vs failures, secure-admin "
         "(websudo) sessions, and the brute-force correlations (126013 per-account, 126014 "
         "per-source-IP). Source IP is only present when the audit record carries one._")
timeline_filters("jira-auth-timeline", "JIRA — Authentication Over Time", AUTH)
metric("jira-auth-bf-acct", "Brute force: account (126013)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "126013", "bf account")])
metric("jira-auth-bf-ip", "Brute force: source IP (126014)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "126014", "bf source ip")])
table("jira-auth-fail", "JIRA — Failed Logins (actor · src IP)",
      [bucket(f"{D}jira_author_name", 20, "Actor", "2"),
       bucket(f"{D}jira_src_ip", 1, "Source IP", "3")], 10,
      filt=[kql("rule.id:(126010 or 126012)", "failed auth")])
table("jira-src-ip", "JIRA — Source IPs (when present)",
      [bucket(f"{D}jira_src_ip", 20, "Source IP", "2"),
       bucket(f"{D}jira_author_name", 1, "Top actor", "3")], 10)

# ---- Permissions & exposure ------------------------------------------------
markdown("jira-md-perms", "JIRA — md Permissions",
         "### 🛡️ Permissions & Public Exposure  \n_Permission/security-scheme changes, portal and "
         "application access, and public/anonymous exposure toggles. Correlation 126031/126032 "
         "fires on repeated changes by one actor (≥5 in 10 min)._")
timeline_filters("jira-perm-timeline", "JIRA — Permission & Exposure Changes Over Time", PERMS)
table("jira-perm-actor", "JIRA — Permission Changes by Actor (actor · summary)",
      [bucket(f"{D}jira_author_name", 20, "Actor", "2"),
       bucket(f"{D}jira_summary", 2, "Top changes", "3")], 10,
      filt=[kql(PERM_IDS, "perm changes")])

# ---- Export / backup -------------------------------------------------------
markdown("jira-md-export", "JIRA — md Export",
         "### 📤 Export, Backup & Data Collection  \n_Full exports and XML backups (126070), "
         "Assets exports (126071), issue/object exports (126073), and the bulk-export "
         "correlation 126074 that fires on ≥5 exports by one actor in 10 minutes._")
metric("jira-export-full", "Full export/backup (126070)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "126070", "full export")])
metric("jira-export-bulk", "Bulk export corr (126074)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "126074", "bulk export")])
timeline_filters("jira-export-timeline", "JIRA — Export/Backup Over Time", EXPORTS)
table("jira-export-actor", "JIRA — Export Activity by Actor (actor · summary)",
      [bucket(f"{D}jira_author_name", 20, "Actor", "2"),
       bucket(f"{D}jira_summary", 2, "Top exports", "3")], 10,
      filt=[kql(EXPORT_IDS, "exports")])

# ---- Audit log integrity ---------------------------------------------------
markdown("jira-md-audit", "JIRA — md Audit Integrity",
         "### 🧾 Audit Log Integrity  \n_Who touches the audit trail itself. Retention/coverage "
         "changes and purges (126060) can hide later activity — treat any hit as significant. "
         "Exports (126061) and views (126062) are normal admin behavior at low volume._")
metric("jira-audit-cfg", "Audit config changed (126060)", count_metric(), color_to=5,
       filt=[phrase("rule.id", "126060", "audit config")])
metric("jira-audit-export", "Audit log exported (126061)", count_metric(), color_to=10,
       filt=[phrase("rule.id", "126061", "audit export")])
metric("jira-audit-view", "Audit log viewed (126062)", count_metric(), color_to=100,
       filt=[phrase("rule.id", "126062", "audit viewed")])
timeline_filters("jira-audit-timeline", "JIRA — Audit Log Activity Over Time", AUDIT)
table("jira-audit-actor", "JIRA — Audit Log Activity by Actor (actor · summary)",
      [bucket(f"{D}jira_author_name", 15, "Actor", "2"),
       bucket(f"{D}jira_summary", 2, "Activity", "3")], 10,
      filt=[kql("rule.id:(126060 or 126061 or 126062)", "audit log activity")])

# ---- Users & groups --------------------------------------------------------
markdown("jira-md-users", "JIRA — md Users",
         "### 👥 Users & Groups  \n_User lifecycle and group membership changes. Additions to "
         "admin groups escalate to 126021 (level 12) and appear in the Security section._")
timeline_filters("jira-users-timeline", "JIRA — User & Group Changes Over Time", USERS)
table("jira-users-table", "JIRA — User/Group Changes (summary · actor)",
      [bucket(f"{D}jira_summary", 20, "Change", "2"),
       bucket(f"{D}jira_author_name", 1, "Actor", "3")], 10,
      filt=[kql("rule.id:(126021 or 126045 or 126046)", "user/group changes")])

# ---- Fallback canary -------------------------------------------------------
markdown("jira-md-fallback", "JIRA — md Fallback",
         "### 🕵️ Category Fallback (Canary)  \n_Events no Layer 1 rule claimed, caught by the "
         "category tiers 126090 (security/identity) and 126091 (admin/config). A sustained spike "
         "of one summary here means Jira introduced an event the ruleset should classify — "
         "review and add a Layer 1 rule._")
timeline_filters("jira-fallback-timeline", "JIRA — Fallback Hits Over Time", FALLBACK)
table("jira-fallback-table", "JIRA — Unclassified Summaries (summary · category)",
      [bucket(f"{D}jira_summary", 30, "Summary", "2"),
       bucket(f"{D}jira_category", 1, "Category", "3")], 15,
      filt=[kql("rule.id:(126090 or 126091)", "fallback")])

# ---- Coverage reference ----------------------------------------------------
markdown("jira-coverage", "JIRA — Coverage Reference",
         "### 🗺️ Rule & Coverage Reference\n"
         "Layered ruleset — base rule 126000 guarantees **no event is missed**; the most "
         "specific rule in each family wins (file order); category tiers backstop the long tail.\n\n"
         "| Rule | Level | Meaning |\n|---|---|---|\n"
         "| **126000** | 3 | Base — every Jira audit event (no-miss catch-all) |\n"
         "| **126010 / 126011** | 8 / 9 | Websudo (secure admin) failed / granted |\n"
         "| **126012** | 5 | Single failed login |\n"
         "| **126013 / 126014** | **10** | Brute force: same account / same source IP |\n"
         "| **126015** | 3 | Successful login / logout |\n"
         "| **126016** | **11** | MFA/2FA/SSO/SAML disabled or removed |\n"
         "| **126017** | 10 | Authentication/password config changed |\n"
         "| **126020 / 126021** | **12** | Admin privilege granted / added to admin group |\n"
         "| **126022** | 7 | Admin privilege removed |\n"
         "| **126023 / 126024** | **11** / 5 | Public/anonymous exposure enabled / removed |\n"
         "| **126025** | 8 | Portal / help center / knowledge base access changed |\n"
         "| **126026 / 126027** | 6 / 10 | Permission scheme reduced / changed or broadened |\n"
         "| **126028** | 8 | Application access changed |\n"
         "| **126029 / 126030** | 6 / 7 | Project role membership / generic permission changed |\n"
         "| **126031 / 126032** | 10 | Repeated permission / public-access changes (corr) |\n"
         "| **126040 / 126041** | 10 / 6 | App/webhook/OAuth trust added / removed |\n"
         "| **126042 / 126043** | 10 / 5 | API token created / revoked |\n"
         "| **126045 / 126046** | 6 / 5 | Group membership / user lifecycle |\n"
         "| **126050-126056** | 5-7 | Workflow, schemes, boards, projects, dark features, mail |\n"
         "| **126053** | 10 | Project deleted or archived |\n"
         "| **126060 / 126061 / 126062** | **11** / 7 / 5 | Audit log config changed / exported / viewed |\n"
         "| **126070 / 126071** | **12** / 8 | Full data export or backup / Assets export |\n"
         "| **126072 / 126073** | 8 / 6 | Restore or import / issue export |\n"
         "| **126074** | **12** | Bulk export by one actor (corr, ≥5 in 10 min) |\n"
         "| **126090 / 126091** | 6 / 5 | Category fallback tiers (security / admin) |\n\n"
         "**Notes:**\n"
         "- Correlation `frequency=\"N\"` fires on the (N+2)th event; `ignore` suppresses per-rule, "
         "not per-actor (anti-storm trade-off).\n"
         "- `jira_author_key` is emitted on Data Center; Cloud events may only carry "
         "`jira_author_account_id` — swap `same_field` in `126-jira_rules.xml` if needed.\n"
         "- Source IP panels populate only when audit records carry an address (mostly "
         "login events).")

# ============================================================================
# DASHBOARD LAYOUT  (48-col grid; rows expand to absolute y coordinates)
# ============================================================================
rows = [
    (5,  [("jira-header", 0, 48)]),
    # Overview
    (2,  [("jira-md-overview", 0, 48)]),
    (8,  [("jira-total", 0, 8), ("jira-actors", 8, 8), ("jira-categories", 16, 8),
          ("jira-high", 24, 8), ("jira-corr", 32, 8), ("jira-fallback", 40, 8)]),
    (13, [("jira-timeline", 0, 32), ("jira-severity", 32, 16)]),
    (14, [("jira-category", 0, 24), ("jira-rules-bar", 24, 24)]),
    # Activity
    (2,  [("jira-md-activity", 0, 48)]),
    (15, [("jira-top-actions", 0, 24), ("jira-top-actors", 24, 24)]),
    (13, [("jira-actor-bar", 0, 24), ("jira-rules", 24, 24)]),
    (11, [("jira-objects", 0, 24), ("jira-sites", 24, 24)]),
    # Security
    (3,  [("jira-md-sec", 0, 48)]),
    (8,  [("jira-sec-admin", 0, 8), ("jira-sec-mfa", 8, 8), ("jira-sec-public", 16, 8),
          ("jira-sec-app", 24, 8), ("jira-sec-token", 32, 8), ("jira-sec-audit", 40, 8)]),
    (13, [("jira-sec-timeline", 0, 32), ("jira-sec-pie", 32, 16)]),
    (16, [("jira-sec-table", 0, 24), ("jira-mitre", 24, 24)]),
    # Authentication
    (3,  [("jira-md-auth", 0, 48)]),
    (12, [("jira-auth-timeline", 0, 24), ("jira-auth-bf-acct", 24, 12), ("jira-auth-bf-ip", 36, 12)]),
    (12, [("jira-auth-fail", 0, 24), ("jira-src-ip", 24, 24)]),
    # Permissions
    (3,  [("jira-md-perms", 0, 48)]),
    (13, [("jira-perm-timeline", 0, 24), ("jira-perm-actor", 24, 24)]),
    # Export
    (3,  [("jira-md-export", 0, 48)]),
    (11, [("jira-export-full", 0, 12), ("jira-export-bulk", 12, 12), ("jira-export-timeline", 24, 24)]),
    (12, [("jira-export-actor", 0, 48)]),
    # Audit integrity
    (3,  [("jira-md-audit", 0, 48)]),
    (8,  [("jira-audit-cfg", 0, 16), ("jira-audit-export", 16, 16), ("jira-audit-view", 32, 16)]),
    (12, [("jira-audit-timeline", 0, 24), ("jira-audit-actor", 24, 24)]),
    # Users & groups
    (3,  [("jira-md-users", 0, 48)]),
    (12, [("jira-users-timeline", 0, 24), ("jira-users-table", 24, 24)]),
    # Fallback canary
    (3,  [("jira-md-fallback", 0, 48)]),
    (12, [("jira-fallback-timeline", 0, 24), ("jira-fallback-table", 24, 24)]),
    # Coverage
    (24, [("jira-coverage", 0, 48)]),
]

layout, y = [], 0
for height, row in rows:
    for vid, x, w in row:
        layout.append((vid, x, y, w, height))
    y += height

panels, references = [], []
for i, (vid, x, py, w, h) in enumerate(layout, start=1):
    pid = str(i)
    panels.append({"version": "2.19.5", "gridData": {"x": x, "y": py, "w": w, "h": h, "i": pid},
                   "panelIndex": pid, "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
    references.append({"name": f"panel_{i}", "type": "visualization", "id": vid})

# dashboard-level scope filter: data.jira_integration:jira
scope_filter = {
    "meta": {"alias": "jira", "disabled": False, "negate": False, "type": "phrase",
             "key": f"{D}jira_integration", "params": {"query": "jira"},
             "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index"},
    "query": {"match_phrase": {f"{D}jira_integration": "jira"}},
    "$state": {"store": "appState"}}
references.append({"name": "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index",
                   "type": "index-pattern", "id": IDX})

objects.append({
    "id": "jira-audit-events-dashboard", "type": "dashboard",
    "attributes": {
        "title": "Jira Audit Events",
        "hits": 0,
        "description": "Jira audit-log monitoring (data.jira_integration:jira): volume, "
                       "category and severity trends, top actors/summaries, security detections "
                       "(admin grants, MFA-disable, public exposure, app trust, API tokens), "
                       "authentication and brute-force correlations, permission changes, "
                       "export/backup collection, audit-log integrity, user/group lifecycle, "
                       "fallback canary, and a rule/coverage reference. Ruleset 126000-126099.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1, "timeRestore": True, "timeTo": "now", "timeFrom": "now-7d",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": [scope_filter]})},
    },
    "references": references,
})

with open(OUT, "w") as f:
    for o in objects:
        f.write(json.dumps(o) + "\n")
nv = sum(1 for o in objects if o["type"] == "visualization")
print(f"Wrote {len(objects)} saved objects ({nv} visualizations + 1 dashboard), "
      f"{len(layout)} panels -> {OUT}")
