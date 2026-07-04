# wazuh-jira

Ingest Jira audit events into Wazuh through the Jira audit API endpoint
`/rest/api/3/auditing/record` for Jira Cloud.

- Integration: dependency-free Python poller run by the Wazuh `command` wodle.
- Schedule: Wazuh runs it every 5 minutes.
- Incremental import: the poller stores a high-water mark and recent event IDs in
  `/var/ossec/queue/jira/jira-events-state.json`, so only new audit records are
  written after the initial backfill.
- Decoder/rules: flat `jira_*` fields, decoder `jira-json`, rule IDs `126000-126099`.

## How it works

```text
Jira /rest/api/3/auditing/record
        |
        |  Basic auth or Bearer/PAT auth, offset pagination
        v
jira_events.py  --->  /var/ossec/logs/jira/jira-events.json
   (command wodle, 5 min)       |
                                v
                         jira-json decoder  --->  rules 126000-126099
```

The script writes one JSON object per line. It flattens nested Jira audit fields
into collision-safe scalar fields such as `jira_summary`, `jira_category`,
`jira_author_key`, `jira_object_name`, and `jira_changed_fields`.

Jira Cloud uses `/rest/api/3/auditing/record`. Some older Jira/Data Center
deployments expose `/rest/auditing/1.0/events`; use that only if your instance
returns `200 OK` for it.

```bash
JIRA_AUDIT_PATH=/rest/api/3/auditing/record
```

## Requirements

- Wazuh 4.x manager.
- A Jira account with the global **Administer Jira** permission.
- Network access from the Wazuh manager to the Jira base URL.
- One supported auth method:
  - Jira Cloud: email address plus Atlassian API token using Basic auth.
  - Jira Data Center: personal access token using Bearer auth, or Basic auth if
    your environment allows it.

Quick API test:

```bash
curl -s -u '<email-or-user>:<api-token>' \
  -H 'Accept: application/json' \
  'https://<jira-host>/rest/api/3/auditing/record?limit=1'
```

Bearer/PAT test:

```bash
curl -s -H 'Authorization: Bearer <pat-or-token>' \
  -H 'Accept: application/json' \
  'https://<jira-host>/rest/api/3/auditing/record?limit=1'
```

## Installation

Run these commands on the Wazuh manager from this `wazuh-jira` directory.

### 1. Install the integration script

```bash
sudo install -o root -g wazuh -m 0750 integration/jira_events.py \
  /var/ossec/integrations/jira_events.py

sudo install -d -o wazuh -g wazuh -m 0750 \
  /var/ossec/logs/jira \
  /var/ossec/queue/jira
```

### 2. Install configuration and secrets

```bash
sudo cp config/jira-events.env.example /var/ossec/etc/jira-events.env
sudo chown root:wazuh /var/ossec/etc/jira-events.env
sudo chmod 0640 /var/ossec/etc/jira-events.env
sudo -e /var/ossec/etc/jira-events.env
```

For Jira Cloud Basic auth:

```text
JIRA_BASE_URL=https://your-site.atlassian.net
JIRA_AUDIT_PATH=/rest/api/3/auditing/record
JIRA_AUTH_MODE=basic
JIRA_USERNAME=admin@example.com
JIRA_API_TOKEN=<atlassian-api-token>
```

For Jira Data Center PAT/Bearer auth:

```text
JIRA_BASE_URL=https://jira.example.com
JIRA_AUDIT_PATH=/rest/auditing/1.0/events
JIRA_AUTH_MODE=bearer
JIRA_BEARER_TOKEN=<jira-personal-access-token>
```

### 3. Install decoder and rules

```bash
sudo cp ruleset/126-jira_decoders.xml /var/ossec/etc/decoders/
sudo cp ruleset/126-jira_rules.xml    /var/ossec/etc/rules/

sudo chown wazuh:wazuh \
  /var/ossec/etc/decoders/126-jira_decoders.xml \
  /var/ossec/etc/rules/126-jira_rules.xml

sudo chmod 0660 \
  /var/ossec/etc/decoders/126-jira_decoders.xml \
  /var/ossec/etc/rules/126-jira_rules.xml
```

### 4. Add ossec.conf blocks

Add the two blocks from `config/ossec.conf.snippet` inside the top-level
`<ossec_config>` element in `/var/ossec/etc/ossec.conf`.

The important schedule setting is:

```xml
<interval>5m</interval>
```

That means Wazuh runs the poller every 5 minutes. The poller itself exits after
one incremental import.

### 5. Test and restart

```bash
sudo -u wazuh JIRA_DEBUG=true /var/ossec/integrations/jira_events.py

tail -n1 /var/ossec/logs/jira/jira-events.json | sudo /var/ossec/bin/wazuh-logtest

sudo systemctl restart wazuh-manager
```

## Configuration Reference

All settings live in `/var/ossec/etc/jira-events.env`.

| Variable | Default | Description |
|---|---:|---|
| `JIRA_BASE_URL` | required | Jira base URL, no trailing slash. |
| `JIRA_AUDIT_PATH` | `/rest/api/3/auditing/record` | Audit API path. Use `/rest/auditing/1.0/events` only for Jira instances that expose that legacy/Data Center path. |
| `JIRA_AUTH_MODE` | `auto` | `auto`, `basic`, or `bearer`. |
| `JIRA_USERNAME` | empty | Username or email for Basic auth. |
| `JIRA_API_TOKEN` | empty | API token/password for Basic auth. |
| `JIRA_API_TOKEN_FILE` | empty | File containing the API token. |
| `JIRA_BEARER_TOKEN` / `JIRA_PAT` | empty | Bearer/PAT token. |
| `JIRA_BEARER_TOKEN_FILE` | empty | File containing the bearer token. |
| `JIRA_BACKFILL_HOURS` | `24` | Initial backfill window. |
| `JIRA_LOOKBACK_SECONDS` | `300` | Query overlap for late-arriving events. |
| `JIRA_SEEN_RETENTION_HOURS` | `48` | How long to retain dedupe IDs. |
| `JIRA_LIMIT` | `1000` | Records per page. |
| `JIRA_MAX_PAGES` | `10` | Maximum pages per run. |
| `JIRA_TIME_FORMAT` | `jira` | `jira`, `iso`, or `epoch_ms` for `from`/`to`. |
| `JIRA_INCLUDE_TO` | `true` | Include a bounded `to` query parameter. |
| `JIRA_EXTRA_QUERY` | empty | Optional extra query string, such as `filter=permission`. |
| `JIRA_DEBUG` | `false` | Verbose stderr logging. |

## Event Fields

| Field | Notes |
|---|---|
| `jira_integration` | Always `jira`; used by the decoder and base rule. |
| `jira_event_id` | API event ID or stable hash fallback. |
| `jira_created`, `jira_created_utc` | Original and normalized event time. |
| `jira_summary`, `jira_action` | Human-readable summary and normalized action slug. |
| `jira_category`, `jira_event_source` | Jira audit category/source. |
| `jira_author_key`, `jira_author_account_id`, `jira_author_name` | Actor fields when present. |
| `jira_src_ip` | Remote address when present. |
| `jira_object_*` | Primary audited object from `objectItem`. |
| `jira_changed_fields`, `jira_changed_values` | Scalar summary of `changedValues`. |
| `jira_associated_items`, `jira_associated_types` | Scalar summary of `associatedItems`. |

## Ruleset Design

Rule IDs are `126000-126099`.

| Rule | Level | Meaning |
|---|---:|---|
| `126000` | 3 | Base rule for every Jira audit event. |
| `126010` / `126011` | 8 / 4 | Failed/successful authentication. |
| `126020` | 10 | Authentication, SSO, MFA, or password policy changed. |
| `126030` | 12 | Administrative privilege granted. |
| `126031` | 10 | Permission or issue security scheme changed. |
| `126032` | 8 | Project role membership changed. |
| `126040` | 10 | App, plugin, webhook, OAuth, or token trust changed. |
| `126050` / `126051` | 6 / 6 | User and group lifecycle changes. |
| `126060` | 6 | Workflow, field, screen, issue type, or scheme changed. |
| `126061` | 10 | Project, board, or filter deleted/archived. |
| `126070` | 10 | Export, backup, restore, import, or download activity. |
| `126080` | 8 | Audit logging configuration or audit access event. |
| `126090` / `126091` | 10 / 6 | Security/identity and administrative category tiers. |
| `126081` | 12 | Repeated export/backup activity by the same actor in 5 minutes. |

## Operational Notes

- The first run imports up to `JIRA_BACKFILL_HOURS` of history.
- Later runs query from the saved high-water mark minus `JIRA_LOOKBACK_SECONDS`.
- Recent event IDs are retained so the lookback window catches late events
  without duplicating already imported records.
- If the initial backfill has more records than `JIRA_LIMIT * JIRA_MAX_PAGES`,
  increase `JIRA_MAX_PAGES` temporarily and run the poller manually before
  enabling the Wazuh schedule.
- Keep `/var/ossec/etc/jira-events.env` owned by `root:wazuh` and mode `0640`.
- Keep `/var/ossec/logs/jira` and `/var/ossec/queue/jira` owned by `wazuh:wazuh`
  or writable by the Wazuh user.

## Troubleshooting

- `HTTP 401`: credentials are wrong or the auth mode does not match your Jira.
- `HTTP 403`: the account does not have Administer Jira permission.
- `HTTP 400`: check `JIRA_AUDIT_PATH` and `JIRA_TIME_FORMAT`.
- No alerts: confirm the localfile path, run `wazuh-logtest`, and restart
  `wazuh-manager` after installing the decoder/rules.
- Duplicate lines after a crash: remove only the duplicate log lines if needed;
  do not delete the state file unless you intentionally want to backfill again.
