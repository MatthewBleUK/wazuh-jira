#!/usr/bin/env python3
"""
Jira audit events -> Wazuh local JSON ingestion

Polls a Jira audit endpoint and appends one flat JSON record per new audit
event to a local file that Wazuh ingests via a <localfile> block.

  Default API: GET {JIRA_BASE_URL}/rest/api/3/auditing/record
  Auth:        Basic user:api_token, or Bearer token/PAT

Writes JSON lines to:
  /var/ossec/logs/jira/jira-events.json

State file:
  /var/ossec/queue/jira/jira-events-state.json

Config (KEY=VALUE) is read from:
  /var/ossec/etc/jira-events.env

Recommended execution:
  sudo -u wazuh /var/ossec/integrations/jira_events.py

Design notes
------------
Every emitted event is flattened into collision-safe top-level "jira_*" scalar
fields. Nested Jira audit structures such as objectItem, changedValues, and
associatedItems are summarized into scalar fields only. This avoids shared
wazuh-alerts-* index mapping conflicts caused by object/scalar collisions.
"""

import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------

DEFAULT_ENV_FILE = "/var/ossec/etc/jira-events.env"
DEFAULT_STATE_FILE = "/var/ossec/queue/jira/jira-events-state.json"
DEFAULT_OUTPUT_FILE = "/var/ossec/logs/jira/jira-events.json"
DEFAULT_AUDIT_PATH = "/rest/api/3/auditing/record"

DEFAULT_BACKFILL_HOURS = 24
DEFAULT_LIMIT = 1000
DEFAULT_MAX_PAGES = 10
DEFAULT_HTTP_TIMEOUT = 60
DEFAULT_SLEEP_BETWEEN_PAGES = 0.5
DEFAULT_LOOKBACK_SECONDS = 300
DEFAULT_SEEN_RETENTION_HOURS = 48

INTEGRATION_NAME = "jira"
EVENT_TYPE = "audit"


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def to_epoch_millis(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def jira_timestamp(dt: datetime) -> str:
    utc = dt.astimezone(timezone.utc)
    millis = int(utc.microsecond / 1000)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}" + utc.strftime("%z")


def format_query_time(dt: datetime, mode: str) -> str:
    if mode == "epoch_ms":
        return str(to_epoch_millis(dt))
    if mode == "iso":
        utc = dt.astimezone(timezone.utc)
        millis = int(utc.microsecond / 1000)
        return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{millis:03d}Z"
    return jira_timestamp(dt)


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def parse_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "yes", "true", "on", "enabled"}


def parse_int(value: Optional[str], default: int, minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    try:
        result = int(str(value).strip()) if value is not None else default
    except ValueError:
        result = default

    if minimum is not None:
        result = max(minimum, result)
    if maximum is not None:
        result = min(maximum, result)

    return result


def parse_float(value: Optional[str], default: float, minimum: Optional[float] = None) -> float:
    try:
        result = float(str(value).strip()) if value is not None else default
    except ValueError:
        result = default

    if minimum is not None:
        result = max(minimum, result)

    return result


def parse_epoch_millis(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        parsed = int(str(value))
        return parsed if parsed > 0 else None
    except (TypeError, ValueError):
        return None


def load_env_file(path: str) -> None:
    """Load simple KEY=VALUE lines into os.environ if not already present."""
    env_path = Path(path)
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')

        if key and key not in os.environ:
            os.environ[key] = value


def read_secret(value_name: str, file_name: str) -> str:
    value = os.environ.get(value_name, "").strip()
    file_path = os.environ.get(file_name, "").strip()
    if value:
        return value
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    return ""


def strip_bearer(token: str) -> str:
    token = token.strip()
    if token.lower().startswith("bearer "):
        return token[7:].strip()
    return token


def normalize_path(path: str) -> str:
    if not path:
        return DEFAULT_AUDIT_PATH
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return "/" + path.lstrip("/")


def get_config() -> Dict[str, Any]:
    env_file = os.environ.get("JIRA_ENV_FILE", DEFAULT_ENV_FILE)
    load_env_file(env_file)

    api_token = read_secret("JIRA_API_TOKEN", "JIRA_API_TOKEN_FILE")
    bearer_token = read_secret("JIRA_BEARER_TOKEN", "JIRA_BEARER_TOKEN_FILE") or read_secret("JIRA_PAT", "JIRA_PAT_FILE")
    bearer_token = strip_bearer(bearer_token)

    auth_mode = os.environ.get("JIRA_AUTH_MODE", "auto").strip().lower()
    if auth_mode == "auto":
        if bearer_token:
            auth_mode = "bearer"
        elif os.environ.get("JIRA_USERNAME", "").strip() and api_token:
            auth_mode = "basic"
        elif api_token:
            auth_mode = "bearer"
            bearer_token = strip_bearer(api_token)
            api_token = ""

    time_format = os.environ.get("JIRA_TIME_FORMAT", "jira").strip().lower()
    if time_format not in {"jira", "iso", "epoch_ms"}:
        time_format = "jira"

    extra_query = os.environ.get("JIRA_EXTRA_QUERY", "").strip()

    return {
        "env_file": env_file,
        "base_url": os.environ.get("JIRA_BASE_URL", "").strip().rstrip("/"),
        "audit_path": normalize_path(os.environ.get("JIRA_AUDIT_PATH", DEFAULT_AUDIT_PATH).strip()),
        "auth_mode": auth_mode,
        "username": os.environ.get("JIRA_USERNAME", "").strip(),
        "api_token": api_token,
        "bearer_token": bearer_token,
        "state_file": os.environ.get("JIRA_STATE_FILE", DEFAULT_STATE_FILE),
        "output_file": os.environ.get("JIRA_OUTPUT_FILE", DEFAULT_OUTPUT_FILE),
        "backfill_hours": parse_int(
            os.environ.get("JIRA_BACKFILL_HOURS"), DEFAULT_BACKFILL_HOURS, minimum=1, maximum=24 * 90,
        ),
        "limit": parse_int(
            os.environ.get("JIRA_LIMIT"), DEFAULT_LIMIT, minimum=1, maximum=1000,
        ),
        "max_pages": parse_int(
            os.environ.get("JIRA_MAX_PAGES"), DEFAULT_MAX_PAGES, minimum=1, maximum=100,
        ),
        "http_timeout": parse_int(
            os.environ.get("JIRA_HTTP_TIMEOUT"), DEFAULT_HTTP_TIMEOUT, minimum=5, maximum=300,
        ),
        "sleep_between_pages": parse_float(
            os.environ.get("JIRA_SLEEP_BETWEEN_PAGES"), DEFAULT_SLEEP_BETWEEN_PAGES, minimum=0.0,
        ),
        "lookback_seconds": parse_int(
            os.environ.get("JIRA_LOOKBACK_SECONDS"), DEFAULT_LOOKBACK_SECONDS, minimum=0, maximum=24 * 3600,
        ),
        "seen_retention_hours": parse_int(
            os.environ.get("JIRA_SEEN_RETENTION_HOURS"), DEFAULT_SEEN_RETENTION_HOURS, minimum=1, maximum=24 * 14,
        ),
        "include_to": parse_bool(os.environ.get("JIRA_INCLUDE_TO"), default=True),
        "time_format": time_format,
        "extra_query": extra_query,
        "debug": parse_bool(os.environ.get("JIRA_DEBUG"), default=False),
    }


def chmod_best_effort(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


def ensure_paths(state_file: str, output_file: str) -> None:
    state_parent = Path(state_file).parent
    output_parent = Path(output_file).parent
    state_parent.mkdir(parents=True, exist_ok=True)
    output_parent.mkdir(parents=True, exist_ok=True)
    chmod_best_effort(state_parent, 0o750)
    chmod_best_effort(output_parent, 0o750)
    output_path = Path(output_file)
    if not output_path.exists():
        output_path.touch(mode=0o640, exist_ok=True)
    chmod_best_effort(output_path, 0o640)


def load_state(state_file: str) -> Dict[str, Any]:
    path = Path(state_file)
    if not path.exists():
        return {"version": 1, "stream": {}}
    try:
        with path.open("r", encoding="utf-8") as f:
            state = json.load(f)
        if not isinstance(state, dict):
            return {"version": 1, "stream": {}}
        state.setdefault("version", 1)
        state.setdefault("stream", {})
        return state
    except Exception as exc:
        broken = f"{state_file}.broken.{int(time.time())}"
        try:
            path.rename(broken)
        except Exception:
            pass
        eprint(f"Jira: state file was unreadable, moved aside if possible: {exc}")
        return {"version": 1, "stream": {}}


def save_state(state_file: str, state: Dict[str, Any]) -> None:
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, separators=(",", ":"), sort_keys=True)
            f.write("\n")
        os.chmod(tmp_name, 0o640)
        os.replace(tmp_name, state_file)
    finally:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def auth_header(config: Dict[str, Any]) -> str:
    if config["auth_mode"] == "basic":
        raw = f"{config['username']}:{config['api_token']}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")
    if config["auth_mode"] == "bearer":
        return f"Bearer {config['bearer_token']}"
    return ""


def http_get_json(url: str, config: Dict[str, Any]) -> Tuple[int, Dict[str, Any], str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "wazuh-jira-audit/1.0",
    }
    authorization = auth_header(config)
    if authorization:
        headers["Authorization"] = authorization

    if config["debug"]:
        eprint(f"Jira DEBUG: GET {url}")

    request = urllib.request.Request(url=url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=config["http_timeout"]) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.getcode()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status = exc.code
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error calling {url}: {exc}") from exc

    if not raw.strip():
        return status, {}, raw
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"raw_response": raw}
    return status, parsed, raw


def parse_jira_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number = number / 1000.0
        return datetime.fromtimestamp(number, tz=timezone.utc)

    if not isinstance(value, str):
        return None

    raw = value.strip()
    if not raw:
        return None

    if raw.isdigit():
        number = int(raw)
        if number > 10_000_000_000:
            number = number / 1000.0
        return datetime.fromtimestamp(number, tz=timezone.utc)

    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1] + "+00:00")
    if len(raw) >= 5 and raw[-5] in {"+", "-"} and raw[-4:].isdigit():
        candidates.append(raw[:-5] + raw[-5:-2] + ":" + raw[-2:])

    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass

    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return datetime.strptime(raw, fmt).astimezone(timezone.utc)
        except ValueError:
            pass

    return None


def first_present(item: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return value
    return None


def scalar_string(value: Any, limit: int = 300) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (str, int, float)):
        text = str(value)
    else:
        text = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def slugify_action(value: Any) -> Optional[str]:
    text = scalar_string(value, limit=160)
    if not text:
        return None
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or None


def event_time(item: Dict[str, Any]) -> Optional[datetime]:
    value = first_present(item, ("created", "timestamp", "time", "eventTime", "date"))
    return parse_jira_datetime(value)


def stable_event_id(item: Dict[str, Any]) -> str:
    explicit_id = first_present(item, ("id", "eventId", "eventID", "auditId", "recordId"))
    if explicit_id is not None:
        return str(explicit_id)

    stable = {
        "created": first_present(item, ("created", "timestamp", "time", "eventTime", "date")),
        "summary": first_present(item, ("summary", "action", "eventName", "name")),
        "category": first_present(item, ("category", "eventCategory")),
        "authorKey": first_present(item, ("authorKey", "authorAccountId", "authorName")),
        "remoteAddress": first_present(item, ("remoteAddress", "remote_address", "ipAddress")),
        "objectItem": item.get("objectItem"),
    }
    encoded = json.dumps(stable, separators=(",", ":"), sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:32]


def extract_records(body: Any) -> List[Dict[str, Any]]:
    if isinstance(body, list):
        return [item for item in body if isinstance(item, dict)]

    if not isinstance(body, dict):
        return []

    for key in ("records", "events", "data", "values", "results"):
        value = body.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    data = body.get("data")
    if isinstance(data, dict):
        for key in ("records", "events", "values", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    return []


def extract_total(body: Any) -> Optional[int]:
    if not isinstance(body, dict):
        return None
    for key in ("total", "totalCount", "size", "count"):
        value = parse_epoch_millis(body.get(key))
        if value is not None:
            return value
    return None


def summarize_changed_values(values: Any) -> Dict[str, str]:
    if not isinstance(values, list):
        return {}

    fields: List[str] = []
    changes: List[str] = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        field = scalar_string(first_present(entry, ("fieldName", "field", "name")), limit=100)
        old_value = scalar_string(first_present(entry, ("changedFrom", "from", "oldValue")), limit=80)
        new_value = scalar_string(first_present(entry, ("changedTo", "to", "newValue")), limit=80)
        if field:
            fields.append(field)
        if field and (old_value is not None or new_value is not None):
            changes.append(f"{field}:{old_value or ''}->{new_value or ''}")

    out: Dict[str, str] = {}
    if fields:
        out["jira_changed_fields"] = ",".join(sorted(set(fields)))
    if changes:
        out["jira_changed_values"] = "; ".join(changes[:10])
    out["jira_changed_count"] = str(len(values))
    return out


def summarize_associated_items(values: Any) -> Dict[str, str]:
    if not isinstance(values, list):
        return {}

    types: List[str] = []
    names: List[str] = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        item_type = scalar_string(first_present(entry, ("typeName", "type", "objectType")), limit=80)
        name = scalar_string(first_present(entry, ("name", "objectName", "id")), limit=100)
        if item_type:
            types.append(item_type)
        if name:
            names.append(name)

    out: Dict[str, str] = {}
    if types:
        out["jira_associated_types"] = ",".join(sorted(set(types)))
    if names:
        out["jira_associated_items"] = ",".join(names[:20])
    out["jira_associated_count"] = str(len(values))
    return out


def flatten_event(item: Dict[str, Any], config: Dict[str, Any], event_id: Optional[str] = None) -> Dict[str, Any]:
    """Convert a raw Jira audit event into a flat jira_* record."""
    record_id = event_id or stable_event_id(item)
    created_raw = first_present(item, ("created", "timestamp", "time", "eventTime", "date"))
    created_dt = parse_jira_datetime(created_raw)
    summary = first_present(item, ("summary", "action", "eventName", "name"))
    category = first_present(item, ("category", "eventCategory"))

    out: Dict[str, Any] = {
        "jira_integration": INTEGRATION_NAME,
        "jira_event_type": EVENT_TYPE,
        "jira_ingested_at": to_rfc3339(utc_now()),
        "jira_event_id": record_id,
    }

    host = urllib.parse.urlparse(config["base_url"]).netloc
    if host:
        out["jira_site_host"] = host

    if created_raw is not None:
        out["jira_created"] = scalar_string(created_raw, limit=80)
    if created_dt:
        out["jira_created_utc"] = to_rfc3339(created_dt)
    if summary:
        out["jira_summary"] = scalar_string(summary, limit=300)
        action = slugify_action(summary)
        if action:
            out["jira_action"] = action
    if category:
        out["jira_category"] = scalar_string(category, limit=160)

    for source_key, target_key in (
        ("eventSource", "jira_event_source"),
        ("description", "jira_description"),
        ("remoteAddress", "jira_src_ip"),
        ("remote_address", "jira_src_ip"),
        ("ipAddress", "jira_src_ip"),
        ("authorKey", "jira_author_key"),
        ("authorAccountId", "jira_author_account_id"),
        ("authorName", "jira_author_name"),
        ("authorType", "jira_author_type"),
    ):
        value = item.get(source_key)
        if value is not None and target_key not in out:
            out[target_key] = scalar_string(value, limit=300)

    author = item.get("author")
    if isinstance(author, dict):
        for source_key, target_key in (
            ("key", "jira_author_key"),
            ("accountId", "jira_author_account_id"),
            ("name", "jira_author_name"),
            ("displayName", "jira_author_name"),
            ("emailAddress", "jira_author_email"),
        ):
            value = author.get(source_key)
            if value is not None and target_key not in out:
                out[target_key] = scalar_string(value, limit=300)

    object_item = item.get("objectItem")
    if isinstance(object_item, dict):
        for source_key, target_key in (
            ("id", "jira_object_id"),
            ("name", "jira_object_name"),
            ("typeName", "jira_object_type"),
            ("type", "jira_object_type"),
            ("parentId", "jira_object_parent_id"),
            ("parentName", "jira_object_parent_name"),
        ):
            value = object_item.get(source_key)
            if value is not None and target_key not in out:
                out[target_key] = scalar_string(value, limit=300)

    out.update(summarize_changed_values(item.get("changedValues")))
    out.update(summarize_associated_items(item.get("associatedItems")))

    return {key: value for key, value in out.items() if value is not None and value != ""}


def emit_event(output_file: str, item: Dict[str, Any], config: Dict[str, Any], event_id: str) -> None:
    record = flatten_event(item, config, event_id)
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")


def endpoint_url(config: Dict[str, Any]) -> str:
    path = config["audit_path"]
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return config["base_url"] + path


def build_url(config: Dict[str, Any], offset: int, from_dt: datetime, to_dt: datetime) -> str:
    params: Dict[str, str] = {
        "offset": str(offset),
        "limit": str(config["limit"]),
        "from": format_query_time(from_dt, config["time_format"]),
    }
    if config["include_to"]:
        params["to"] = format_query_time(to_dt, config["time_format"])

    if config["extra_query"]:
        for key, value in urllib.parse.parse_qsl(config["extra_query"], keep_blank_values=False):
            if key not in params:
                params[key] = value

    return endpoint_url(config) + "?" + urllib.parse.urlencode(params)


def prune_seen(seen: Dict[str, Any], cutoff_ms: int) -> Dict[str, int]:
    pruned: Dict[str, int] = {}
    for key, value in seen.items():
        event_ms = parse_epoch_millis(value)
        if event_ms is not None and event_ms >= cutoff_ms:
            pruned[str(key)] = event_ms
    return pruned


def record_sort_key(item: Dict[str, Any]) -> Tuple[int, str]:
    dt = event_time(item)
    millis = to_epoch_millis(dt) if dt else 0
    return millis, stable_event_id(item)


def poll(config: Dict[str, Any], state: Dict[str, Any]) -> int:
    stream_state = state.setdefault("stream", {})
    now = utc_now()

    last_event_ms = parse_epoch_millis(stream_state.get("last_event_ms"))
    if last_event_ms is not None:
        from_dt = datetime.fromtimestamp(max(0, last_event_ms - (config["lookback_seconds"] * 1000)) / 1000.0, tz=timezone.utc)
    else:
        from_dt = now - timedelta(hours=config["backfill_hours"])

    seen_raw = stream_state.get("seen_event_ids")
    seen = seen_raw if isinstance(seen_raw, dict) else {}
    # Keep every dedupe ID that can still appear in this run's query window.
    # This avoids duplicates after a long outage where the high-water mark is
    # older than the normal wall-clock retention cutoff.
    retention_cutoff = min(
        to_epoch_millis(now - timedelta(hours=config["seen_retention_hours"])),
        max(0, to_epoch_millis(from_dt) - 1000),
    )
    seen_ids = prune_seen(seen, retention_cutoff)

    all_records: List[Dict[str, Any]] = []
    offset = 0
    pages = 0
    had_error = False

    while pages < config["max_pages"]:
        pages += 1
        url = build_url(config, offset, from_dt, now)
        status, body, raw = http_get_json(url, config)

        if status == 401:
            eprint("Jira: HTTP 401 Unauthorized. Check Jira credentials and authentication mode.")
            eprint(raw)
            had_error = True
            break
        if status == 403:
            eprint("Jira: HTTP 403 Forbidden. The account needs Administer Jira permission for audit records.")
            eprint(raw)
            had_error = True
            break
        if status == 400:
            eprint("Jira: HTTP 400 Bad Request. Check JIRA_AUDIT_PATH and JIRA_TIME_FORMAT.")
            eprint(f"Jira: URL={url}")
            eprint(raw)
            had_error = True
            break
        if status == 429:
            eprint("Jira: HTTP 429 rate limited. Stopping this run; will retry next interval.")
            had_error = True
            break
        if status < 200 or status >= 300:
            eprint(f"Jira: HTTP {status}: {raw}")
            had_error = True
            break

        records = extract_records(body)
        total = extract_total(body)
        all_records.extend(records)

        if config["debug"]:
            eprint(f"Jira DEBUG: page={pages} offset={offset} items={len(records)} total={total}")

        if not records:
            break
        offset += len(records)
        if total is not None and offset >= total:
            break
        if len(records) < config["limit"]:
            break
        time.sleep(config["sleep_between_pages"])

    emitted = 0
    high_water_ms = last_event_ms or 0

    for item in sorted(all_records, key=record_sort_key):
        event_id = stable_event_id(item)
        if event_id in seen_ids:
            continue

        dt = event_time(item)
        event_ms = to_epoch_millis(dt) if dt else to_epoch_millis(now)
        emit_event(config["output_file"], item, config, event_id)
        seen_ids[event_id] = event_ms
        emitted += 1

        if dt and event_ms > high_water_ms:
            high_water_ms = event_ms

    stream_state["last_attempt_at"] = to_rfc3339(now)
    if not had_error:
        stream_state["last_success_at"] = to_rfc3339(now)
    stream_state["last_query_from"] = to_rfc3339(from_dt)
    stream_state["last_items_count"] = len(all_records)
    stream_state["last_emitted_count"] = emitted
    if high_water_ms:
        stream_state["last_event_ms"] = high_water_ms
        stream_state["last_event_time"] = to_rfc3339(datetime.fromtimestamp(high_water_ms / 1000.0, tz=timezone.utc))
    stream_state["seen_event_ids"] = prune_seen(seen_ids, retention_cutoff)
    save_state(config["state_file"], state)

    return emitted


def validate_config(config: Dict[str, Any]) -> Optional[str]:
    if not config["base_url"] and not str(config["audit_path"]).startswith(("http://", "https://")):
        return f"missing JIRA_BASE_URL in {config['env_file']}."
    if config["auth_mode"] == "basic":
        if not config["username"] or not config["api_token"]:
            return f"JIRA_AUTH_MODE=basic requires JIRA_USERNAME and JIRA_API_TOKEN in {config['env_file']}."
        return None
    if config["auth_mode"] == "bearer":
        if not config["bearer_token"]:
            return f"JIRA_AUTH_MODE=bearer requires JIRA_BEARER_TOKEN or JIRA_PAT in {config['env_file']}."
        return None
    return "JIRA_AUTH_MODE must be auto, basic, or bearer."


def main() -> int:
    config = get_config()
    error = validate_config(config)
    if error:
        eprint(f"Jira: {error}")
        return 2

    ensure_paths(config["state_file"], config["output_file"])
    state = load_state(config["state_file"])

    try:
        total = poll(config, state)
    except Exception as exc:
        eprint(f"Jira: unhandled error: {exc}")
        return 1

    if config["debug"]:
        eprint(f"Jira DEBUG: emitted_total={total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
