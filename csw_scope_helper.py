# csw_scope_helper.py
"""Cisco Secure Workload scope helper, version 1.2.

Commands:
    export         Save the tenant's scope list to a file. Read-only.
    check-labels   Compare a label file with the labels already in the tenant. Read-only.
    apply          Carry out a plan file under a chosen scope: create scopes and, when the
                   plan lists them and you allow them, rename, change, or remove scopes.
    undo           Reverse what one earlier "apply" run did.

Safety:
    "export" and "check-labels" never change anything.
    "apply" and "undo" only show what they would do. They change the tenant
    only when you add --write, and then only after you type the word yes.
    "apply" creates scopes with --write. It renames a scope or changes a query only
    for items approved in the plan and only when you also add --allow-changes. It
    removes a scope only for items approved in the plan and only when you also add
    --allow-removals. For changes and removals you always type yes at a prompt that
    lists each one. --yes does not skip that prompt.
    It never changes or removes a top-level scope, or anything outside the scope
    you are working under.
    "undo" reverses only what the recorded run did.
    This program does not upload labels. Upload the label file yourself in
    Secure Workload under Organize > Label Management > User Defined Label Upload.

How to run it (on Windows, type py in place of python3):
    python3 csw_scope_helper.py
        Asks for your tenant address, API key, and API secret, then runs "export".
    python3 csw_scope_helper.py apply --plan "2026-11-19 Acme - CSW Scope Plan.json" --under "Tenant:Parent"
        Shows what would be created. Add --write to create it.
    python3 csw_scope_helper.py undo --record "2026-11-19 081200 Parent - CSW Apply Record.json"
        Shows what would be removed. Add --write to remove it.
    python3 csw_scope_helper.py undo --find-created --under "Tenant:Parent"
        For when the record file is lost. Lists the scopes under that scope that
        this program created. Add --write to remove them.
    python3 csw_scope_helper.py check-labels --labels "2026-11-19 Acme - CSW Labels.csv"

If a build stops partway:
    Run the same apply command again with --write. It finds the unfinished
    record in the folder, continues it, and does only what is missing.
    Before every change to an existing scope the record is saved with that item
    marked "attempting". If the connection drops, the program reads the scope
    back, records whether the change was made, and stops. The next run, and undo,
    read the tenant again for anything still marked "attempting".

Which key to use:
    This program signs in with a Secure Workload API key and API secret. They
    are a pair of short values: the key is 32 characters and the secret is 40.
    Where the pair is created depends on the tenant.
    The long Security Cloud Control access token (it starts with eyJ) is a
    different thing and will not work here. If pasting does nothing and the
    computer beeps, the text is too long to be the key or the secret.
    To avoid pasting, put the pair in a file like this and use --credentials:
        {"api_key": "32 characters", "api_secret": "40 characters"}

What the API key needs:
    export, check-labels:  user_role_scope_management or app_policy_management
                           (check-labels also needs read access to the top-level scope)
    export also tries to read what depends on each scope, so the plan can say a
    scope is in use before anyone tries to remove it. Each list needs its own
    capability. A list the key cannot read is recorded as "not read" and the
    export still succeeds:
        workspaces          app_policy_management
        inventory filters   app_policy_management or sensor_management
        roles               user_role_scope_management, as a site admin or an owner
                            of the top-level scope
    Only the ID and name of each are saved. No policy content is read.
    apply, undo:           user_role_scope_management

Options:
    --url URL            Tenant address, for example https://example.tetrationcloud.com
    --credentials FILE   A file holding the API key and secret (see above)
    --under "NAME"       The scope to work under (full name or short name)
    --out-dir FOLDER     Where to save files (default: the current folder)
    --ca-file FILE       Certificate file for an on-premises cluster with a private certificate
    --plan FILE          The plan file from the planner page (apply)
    --record FILE        The record file saved by an earlier apply run (undo)
    --find-created       Find this program's scopes without a record file (undo, needs --under)
    --labels FILE        The label file from the planner page (check-labels)
    --write              Make the changes instead of only showing them (apply, undo)
    --allow-changes      With --write, also rename scopes and change queries the plan approves (apply)
    --allow-removals     With --write, also remove scopes the plan approves (apply)
    --no-commit          With --write, make the changes but do not commit them, so you can look at
                         pending query changes in Secure Workload before you commit there (apply)
    --yes                Do not ask for the typed yes before creating scopes. It never covers
                         renames, query changes, removals, or --find-created
    --commit-timeout N   Seconds to wait for a commit of scope changes (default 300)

    The address, key, and secret can also be given in the environment variables
    CSW_URL, CSW_API_KEY, and CSW_API_SECRET. Nothing secret is ever saved.

Needs Python 3.8 or later. Uses only the Python standard library.
"""
import argparse
import base64
import csv
import datetime
import getpass
import hashlib
import hmac
import http.client
import io
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.2"
EXPORT_SCHEMA = "csw-scope-export"
EXPORT_SCHEMA_VERSION = 2
PLAN_SCHEMA = "csw-scope-plan"
PLAN_SCHEMA_VERSIONS = (1, 2, 3)
RECORD_SCHEMA = "csw-scope-apply-record"
RECORD_SCHEMA_VERSION = 3
RECORD_SCHEMA_VERSIONS = (1, 2, 3)
CREATED_MARK = "Created by CSW Scope Builder"
RETRY_WAITS = (2, 5, 10)
COMMIT_POLL_SECONDS = 15
DEFAULT_COMMIT_TIMEOUT = 300
WINDOWS_RESERVED = ("CON", "PRN", "AUX", "NUL") + tuple("COM%d" % n for n in range(1, 10)) + tuple("LPT%d" % n for n in range(1, 10))
SCOPES_PATH = "/openapi/v1/app_scopes"
MAX_SCOPES = 1000
MAX_LABEL_COLUMNS = 32
KEEP_FIELDS = ("id", "short_name", "name", "description", "parent_app_scope_id",
               "root_app_scope_id", "vrf_id", "short_query", "dirty", "dirty_short_query")
READ_RULES = (
    r"^/openapi/v1/app_scopes$",
    r"^/openapi/v1/app_scopes/[A-Za-z0-9]+$",
    r"^/openapi/v1/assets/cmdb/attributenames/[^/?]+$",
    r"^/openapi/v1/assets/cmdb/download/[^/?]+$",
    r"^/openapi/v1/applications$",
    r"^/openapi/v1/filters/inventories$",
    r"^/openapi/v1/roles$",
)
WRITE_RULES = (
    ("POST", r"^/openapi/v1/app_scopes$"),
    ("POST", r"^/openapi/v1/app_scopes/commit_dirty\?root_app_scope_id=[A-Za-z0-9]+&sync=true$"),
    ("DELETE", r"^/openapi/v1/app_scopes/[A-Za-z0-9]+$"),
    ("PUT", r"^/openapi/v1/app_scopes/[A-Za-z0-9]+$"),
)
# What can depend on a scope: (name in the export, read call, capability the API key needs).
DEPENDENT_KINDS = (
    ("workspaces", "/openapi/v1/applications", "app_policy_management"),
    ("inventory_filters", "/openapi/v1/filters/inventories", "app_policy_management or sensor_management"),
    ("roles", "/openapi/v1/roles", "user_role_scope_management, as a site admin or an owner of the top-level scope"),
)
DEPENDENT_WORDS = {"workspaces": "workspaces", "inventory_filters": "inventory filters", "roles": "roles"}
PRIMITIVE_TYPES = ("eq", "ne", "lt", "lte", "gt", "gte", "range", "in", "regex", "contains", "subnet")
ALL_ACTIONS = ("keep", "create", "rename", "requery", "rename_requery", "remove", "leave", "by_hand")
CHANGE_ACTIONS = ("rename", "requery", "rename_requery")


class HelperError(Exception):
    """A problem to show the person running the program, in plain words."""


class NetworkError(HelperError):
    """The connection failed, so the outcome of the call is not known."""


class TenantError(HelperError):
    """The tenant refused a call. Carries the error number and the tenant's own words."""

    def __init__(self, message, code=None, detail=""):
        super().__init__(message)
        self.code, self.detail = code, detail


# ---------------------------------------------------------------- connection

def normalize_url(url):
    """Return https://host[:port] or raise HelperError."""
    url = (url or "").strip()
    if not url:
        raise HelperError("No tenant address was given.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "https":
        raise HelperError("The tenant address must start with https://")
    if not parts.hostname:
        raise HelperError("The tenant address is not valid: " + url)
    return "https://" + parts.netloc


def sign(secret, method, path_url, checksum, content_type, timestamp):
    """Secure Workload request signature (HMAC SHA-256, base64)."""
    message = "\n".join((method, path_url, checksum, content_type, timestamp)) + "\n"
    digest = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def build_headers(key, secret, method, path_url, body=b"", now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%S+0000")
    checksum = hashlib.sha256(body).hexdigest()
    content_type = "application/json"
    return {
        "Id": key,
        "Timestamp": timestamp,
        "X-Tetration-Cksum": checksum,
        "Content-Type": content_type,
        "Authorization": sign(secret, method, path_url, checksum, content_type, timestamp),
        "User-Agent": "csw-scope-helper/" + VERSION,
    }


def is_allowed(method, path, allow_write):
    if method == "GET":
        return any(re.match(rule, path) for rule in READ_RULES)
    if not allow_write:
        return False
    return any(method == m and re.match(rule, path) for m, rule in WRITE_RULES)


class Client:
    """Signed calls to one tenant. Read-only unless allow_write is True.

    Reads are retried on a network error or a 5xx answer. Writes are never retried here.
    """

    def __init__(self, base_url, key, secret, context=None, opener=None, allow_write=False, timeout=90, sleep=time.sleep):
        self.base_url, self.key, self.secret = base_url, key, secret
        self.context, self.opener, self.allow_write, self.timeout = context, opener, allow_write, timeout
        self.sleep = sleep

    def _send(self, method, path, body, timeout):
        request = urllib.request.Request(self.base_url + path, data=body or None, method=method,
                                         headers=build_headers(self.key, self.secret, method, path, body))
        if self.opener is not None:
            response = self.opener(request)
        else:
            response = urllib.request.urlopen(request, timeout=timeout, context=self.context)
        with response:
            return response.read().decode("utf-8")

    def call(self, method, path, payload=None, as_text=False, timeout=None):
        if not is_allowed(method, path, self.allow_write):
            if method != "GET" and not self.allow_write:
                raise HelperError("This run is read-only and will not send %s %s" % (method, path))
            raise HelperError("This program will not call %s %s" % (method, path))
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        waits = RETRY_WAITS if method == "GET" else ()
        tries = 0
        while True:
            try:
                text = self._send(method, path, body, timeout or self.timeout)
                break
            except urllib.error.HTTPError as err:
                detail = ""
                try:
                    detail = err.read().decode("utf-8", "replace")[:20000]
                except Exception:
                    pass
                if 500 <= err.code <= 599 and tries < len(waits):
                    self.sleep(waits[tries])
                    tries += 1
                    continue
                if err.code == 401:
                    raise TenantError("The tenant did not accept the API key or secret (error 401). Check that the key and "
                                      "secret belong to the same pair, that both were copied in full, and that this "
                                      "computer's clock is correct.", code=401, detail=detail)
                if err.code == 403:
                    raise TenantError("The API key is not allowed to do this (error 403 on %s %s). It needs the capability "
                                      "user_role_scope_management, and reading scopes also works with app_policy_management."
                                      % (method, path.split("?")[0]), code=403, detail=detail)
                raise TenantError("The tenant answered with error %s on %s %s. %s" % (err.code, method, path.split("?")[0], detail[:300]),
                                  code=err.code, detail=detail)
            except (urllib.error.URLError, OSError, http.client.HTTPException) as err:
                reason = getattr(err, "reason", err)
                if isinstance(reason, ssl.SSLError) or isinstance(err, ssl.SSLError):
                    raise HelperError("The tenant's certificate could not be verified. For an on-premises cluster with a "
                                      "private certificate, run again with --ca-file and the certificate file. (%s)" % reason)
                if tries < len(waits):
                    self.sleep(waits[tries])
                    tries += 1
                    continue
                raise NetworkError("Could not reach the tenant at %s. Check the address and your network. (%s)" % (self.base_url, reason))
        if as_text:
            return text
        if not text.strip():
            return None
        try:
            return json.loads(text)
        except ValueError:
            raise HelperError("The tenant's answer to %s could not be read." % path.split("?")[0])

    def scopes(self):
        data = self.call("GET", SCOPES_PATH)
        if not isinstance(data, list) or not all(isinstance(s, dict) and s.get("id") for s in data):
            raise HelperError("The tenant's answer was not a scope list.")
        return data


def api_get(base_url, key, secret, path, context=None, timeout=90, opener=None):
    """Send one read-only request and return the parsed JSON."""
    return Client(base_url, key, secret, context=context, opener=opener, timeout=timeout).call("GET", path)


def read_credentials(args, env=None, ask=input, ask_secret=getpass.getpass):
    env = os.environ if env is None else env
    url, key, secret = args.url or env.get("CSW_URL"), env.get("CSW_API_KEY"), env.get("CSW_API_SECRET")
    if args.credentials:
        try:
            with open(args.credentials, "r", encoding="utf-8-sig") as handle:
                data = json.load(handle)
            key, secret = data["api_key"], data["api_secret"]
        except (OSError, ValueError, KeyError):
            raise HelperError("The credentials file could not be read. It should be the api_credentials.json "
                              "file downloaded when the API key was created.")
    if not url:
        url = ask("Tenant address (for example https://example.tetrationcloud.com): ")
    if not key or not secret:
        if ask is input:
            print("Use the Secure Workload API key (32 characters) and API secret (40 characters). "
                  "The long Security Cloud Control token will not work.")
    def problem(label, value):
        if not value:
            return ""
        if value.lower().startswith("http") or "/" in value:
            return "That looks like a web address, not the %s." % label
        if value.startswith("eyJ") or "." in value or len(value) > 100:
            return ("The %s looks like a Security Cloud Control token. This program needs the Secure Workload "
                    "API key (32 characters) and API secret (40 characters)." % label)
        return ""

    def prompt(label, question, reader):
        for _ in range(3):
            value = (reader(question) or "").strip()
            trouble = problem(label, value)
            if not trouble:
                return value
            print(trouble + " Try again.")
        raise HelperError(trouble)

    if not key:
        key = prompt("API key", "Secure Workload API key (32 characters): ", ask)
    if not secret:
        secret = prompt("API secret", "Secure Workload API secret (40 characters, not shown as you type or paste): ", ask_secret)
    key, secret = (key or "").strip(), (secret or "").strip()
    if not key or not secret:
        raise HelperError("Both the API key and the API secret are needed.")
    for label, value in (("API key", key), ("API secret", secret)):
        if problem(label, value):
            raise HelperError(problem(label, value))
    return normalize_url(url), key, secret


# ---------------------------------------------------------------- scope tree helpers

def find_scope(scopes, wanted):
    wanted = (wanted or "").strip()
    matches = [s for s in scopes if s.get("name") == wanted]
    if not matches:
        matches = [s for s in scopes if (s.get("short_name") or "").lower() == wanted.lower()]
    if not matches:
        raise HelperError('No scope named "%s" was found. Use the full name as shown in Secure Workload.' % wanted)
    if len(matches) > 1:
        raise HelperError('More than one scope is named "%s". Use the full name, for example: %s'
                          % (wanted, matches[0].get("name")))
    return matches[0]


def children_index(scopes):
    index = {}
    for s in scopes:
        index.setdefault(s.get("parent_app_scope_id"), []).append(s)
    return index


def subtree(scopes, top):
    index, picked, queue = children_index(scopes), [], [top]
    while queue:
        current = queue.pop(0)
        picked.append(current)
        queue.extend(index.get(current["id"], []))
    return picked


def ancestors(scopes, scope):
    by_id, out, current = {s["id"]: s for s in scopes}, [], scope
    while current.get("parent_app_scope_id") in by_id:
        current = by_id[current["parent_app_scope_id"]]
        out.append(current)
    return out


def select_scopes(scopes, under):
    """Return (scopes to export, top scope or None, partial flag)."""
    if not isinstance(scopes, list) or not all(isinstance(s, dict) and s.get("id") for s in scopes):
        raise HelperError("The tenant's answer was not a scope list.")
    if not under:
        tops = [s for s in scopes if not s.get("parent_app_scope_id")]
        return scopes, (tops[0] if len(tops) == 1 else None), False
    top = find_scope(scopes, under)
    return subtree(scopes, top), top, bool(top.get("parent_app_scope_id"))


def trim_scope(scope):
    return {k: scope.get(k) for k in KEEP_FIELDS if k in scope}


def safe_name(text):
    """A file-name-safe version of a scope name, valid on Windows, macOS, and Linux."""
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "", str(text or "")).strip().rstrip(". ")
    if not name:
        return "Tenant"
    if name.split(".")[0].upper() in WINDOWS_RESERVED:
        return name + " scope"
    return name


def command_line(*parts):
    """A copy-and-paste command for the computer this program is running on."""
    args = ["py" if os.name == "nt" else "python3", os.path.basename(__file__) or "csw_scope_helper.py"] + [str(x) for x in parts]
    if os.name == "nt":
        return subprocess.list2cmdline(args)
    return " ".join(shlex.quote(a) for a in args)


def as_query(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def canonical(query):
    """One fixed text form of a query: compact JSON with the keys in order."""
    return json.dumps(query, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def comparable(query):
    """The form two queries are compared in. The planner builds the same form.

    JSON text is read into a structure. The members of "and" and "or" are sorted, and an
    "and" or "or" with one member is replaced by that member. In a "label equals value"
    condition on an uploaded label (a field that starts with user_), capital letters in the
    label name and the value are ignored, because Secure Workload label keys and values are
    not case sensitive. Anything this program does not know is kept exactly as it is.
    """
    query = as_query(query)
    if not isinstance(query, dict):
        return query
    kind = query.get("type")
    if kind in ("and", "or") and set(query) == {"type", "filters"} and isinstance(query["filters"], list):
        members = [comparable(m) for m in query["filters"]]
        if len(members) == 1:
            return members[0]
        return {"type": kind, "filters": sorted(members, key=canonical)}
    if kind == "not" and set(query) == {"type", "filter"}:
        return {"type": "not", "filter": comparable(query["filter"])}
    if (kind == "eq" and set(query) == {"type", "field", "value"} and isinstance(query["field"], str)
            and query["field"].lower().startswith("user_")):
        return {"type": "eq", "field": query["field"].lower(), "value": str(query["value"]).lower()}
    return query


def same_query(a, b):
    """The comparison rule, shared with the planner. Returns (same, exact).

    exact is True only when the two are identical as written. same is True when they are
    equivalent under the rule in comparable().
    """
    a, b = as_query(a), as_query(b)
    if a == b:
        return True, True
    if not (isinstance(a, dict) and isinstance(b, dict)):
        return False, False
    return canonical(comparable(a)) == canonical(comparable(b)), False


def field_words(field):
    field = str(field)
    if field.lower().startswith("user_"):
        return field[5:]
    return {"ip": "address", "os": "operating system", "vrf_id": "VRF ID"}.get(field, field)


def describe_query(query):
    """One plain-English line for a query. The planner writes the same line."""
    query = as_query(query)

    def value_words(v):
        return v if isinstance(v, str) else canonical(v)

    def walk(q, nested):
        if not isinstance(q, dict):
            return None
        kind, keys = q.get("type"), set(q)
        if kind in ("and", "or") and keys == {"type", "filters"} and isinstance(q["filters"], list) and q["filters"]:
            parts = [walk(m, True) for m in q["filters"]]
            if any(p is None for p in parts):
                return None
            text = (" %s " % kind).join(parts)
            return "(" + text + ")" if nested and len(parts) > 1 else text
        if kind == "not" and keys == {"type", "filter"}:
            inner = walk(q["filter"], False)
            return None if inner is None else "not (" + inner + ")"
        if kind in ("in", "range") and keys == {"type", "field", "values"} and isinstance(q["values"], list):
            values = [value_words(v) for v in q["values"]]
            if kind == "range":
                return None if len(values) != 2 else "%s is between %s and %s" % (field_words(q["field"]), values[0], values[1])
            return "%s is one of %s" % (field_words(q["field"]), ", ".join(values))
        words = {"eq": "is", "ne": "is not", "lt": "is less than", "lte": "is at most", "gt": "is greater than",
                 "gte": "is at least", "regex": "matches the pattern", "contains": "contains", "subnet": "is in"}
        if kind in words and keys == {"type", "field", "value"}:
            return "%s %s %s" % (field_words(q["field"]), words[kind], value_words(q["value"]))
        return None

    text = walk(query, False)
    if text is None:
        return query if isinstance(query, str) else canonical(query)
    return text


def live_query(scope):
    """The query a scope will use once changes are committed."""
    pending = scope.get("dirty_short_query")
    return as_query(pending) if pending else as_query(scope.get("short_query"))


def same_name(a, b):
    """Scope short names. Returns (same, exact). Names differing only in capital letters are one scope."""
    a, b = str(a or ""), str(b or "")
    return a.lower() == b.lower(), a == b


def child_scope_count(scopes, root_id):
    """How many scopes that have a parent sit under one top-level scope."""
    by_id = {s["id"]: s for s in scopes}

    def top_of(scope):
        if scope.get("root_app_scope_id"):
            return scope["root_app_scope_id"]
        seen = set()
        while scope.get("parent_app_scope_id") in by_id and scope["id"] not in seen:
            seen.add(scope["id"])
            scope = by_id[scope["parent_app_scope_id"]]
        return scope["id"]

    return sum(1 for s in scopes if s.get("parent_app_scope_id") and top_of(s) == root_id)


def plan_fingerprint(plan_scopes):
    """SHA-256 of a plan's scope list in a fixed order. The planner computes the same value."""
    rows = []
    for item in sorted(plan_scopes or [], key=lambda x: x.get("order", 0)):
        query = item.get("short_query") or {}
        if "action" in item:
            # Plan format 3: the whole query, the action, the approval, and the scope it applies to.
            cells = (item.get("ref", ""), item.get("parent_ref", ""), item.get("short_name", ""), canonical(query),
                     item.get("action", ""), "approved" if item.get("approved") else "", (item.get("before") or {}).get("id") or "")
        else:
            cells = (item.get("ref", ""), item.get("parent_ref", ""), item.get("short_name", ""),
                     query.get("type", ""), query.get("field", ""), query.get("value", ""))
        rows.append("\x1f".join(str(x) for x in cells))
    return hashlib.sha256("\x1e".join(rows).encode("utf-8")).hexdigest()


def root_scope_of(scopes, scope):
    chain = ancestors(scopes, scope)
    return chain[-1] if chain else scope


# ---------------------------------------------------------------- export

def read_dependents(client, picked):
    """What depends on each exported scope: ID and name only. A list the key cannot read is "not read"."""
    ids = {s["id"] for s in picked}
    status, per_scope = {}, {sid: {} for sid in ids}
    for kind, path, capability in DEPENDENT_KINDS:
        try:
            data = client.call("GET", path)
            if not isinstance(data, list):
                raise HelperError("The tenant's answer was not a list.")
        except HelperError as err:
            reason = ("The API key is not allowed to read this." if isinstance(err, TenantError) and err.code in (401, 403)
                      else str(err).split(" {")[0][:200])
            status[kind] = {"read": False, "reason": reason, "needs": capability}
            for sid in ids:
                per_scope[sid][kind] = "not read"
            continue
        status[kind] = {"read": True}
        for sid in ids:
            per_scope[sid][kind] = []
        for item in data:
            if isinstance(item, dict) and item.get("app_scope_id") in ids:
                per_scope[item["app_scope_id"]][kind].append({"id": item.get("id"), "name": item.get("name")})
    return status, per_scope


def build_export(base_url, scopes, under, now=None, label_columns=None, dependents=None):
    picked, top, partial = select_scopes(scopes, under)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    document = {
        "schema": EXPORT_SCHEMA,
        "schema_version": EXPORT_SCHEMA_VERSION,
        "tool_version": VERSION,
        "exported_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tenant_url": base_url,
        "partial": partial,
        "under": top.get("name") if (under and top) else None,
        "scope_count": len(picked),
        "tenant_scope_count": len(scopes),
        "tenant_child_scope_count": child_scope_count(scopes, root_scope_of(scopes, top)["id"]) if top
        else sum(1 for s in scopes if s.get("parent_app_scope_id")),
        "label_columns": label_columns,
        "dependents": dependents[0] if dependents else {kind: {"read": False, "reason": "Not asked for.", "needs": needs}
                                                        for kind, _path, needs in DEPENDENT_KINDS},
        "scopes": [dict(trim_scope(s), dependents=(dependents[1].get(s["id"]) if dependents
                                                   else {kind: "not read" for kind, _p, _n in DEPENDENT_KINDS})) for s in picked],
    }
    label = safe_name(top.get("short_name") or top.get("name")) if top else "Tenant"
    file_name = "%s %s - CSW Existing Scopes.json" % (datetime.date.today().isoformat(), label)
    return document, file_name


def read_label_columns(client, scopes, near):
    """Label column names already in the tenant, or None if they cannot be read."""
    tops = [s for s in scopes if not s.get("parent_app_scope_id")]
    root = root_scope_of(scopes, near) if near else (tops[0] if len(tops) == 1 else None)
    if not root:
        return None
    try:
        data = client.call("GET", "/openapi/v1/assets/cmdb/attributenames/" + urllib.parse.quote(root.get("name") or "", safe=""))
    except HelperError:
        return None
    return data if isinstance(data, list) else None


def cmd_export(client, args, out=print):
    out("Reading scopes from " + client.base_url + " ...")
    scopes = client.scopes()
    near = find_scope(scopes, args.under) if args.under else None
    picked = select_scopes(scopes, args.under)[0]
    out("Reading what depends on each scope (workspaces, inventory filters, roles) ...")
    dependents = read_dependents(client, picked)
    document, file_name = build_export(client.base_url, scopes, args.under,
                                       label_columns=read_label_columns(client, scopes, near), dependents=dependents)
    path = os.path.join(args.out_dir, file_name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
    for kind, _path, needs in DEPENDENT_KINDS:
        if not dependents[0][kind]["read"]:
            out("  Not read: %s. %s The plan will treat every scope as possibly in use by %s. To include them, use a key with: %s"
                % (DEPENDENT_WORDS[kind], dependents[0][kind]["reason"], DEPENDENT_WORDS[kind], needs))
    out("Saved %d scopes to: %s" % (document["scope_count"], os.path.abspath(path)))
    out("Nothing in the tenant was changed. Send this file to your Cisco contact.")
    return 0


# ---------------------------------------------------------------- apply

def load_json(path, schema, what):
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        raise HelperError("The %s could not be read: %s" % (what, path))
    if not isinstance(data, dict) or data.get("schema") != schema:
        raise HelperError("That file is not a %s: %s" % (what, path))
    return data


def load_plan(path):
    plan = load_json(path, PLAN_SCHEMA, "plan file")
    version = plan.get("schema_version")
    if version not in PLAN_SCHEMA_VERSIONS:
        raise HelperError('The plan file "%s" uses plan format %s. This helper understands formats %s. '
                          "Get the current csw_scope_helper.py from your Cisco contact and run it again."
                          % (os.path.basename(path), version, " and ".join(str(v) for v in PLAN_SCHEMA_VERSIONS)))
    if plan.get("ready") is not True:
        raise HelperError("This plan still has blockers. Fix them and make a new plan before creating scopes.")
    return plan


def resolve_parent(plan, scopes, under):
    by_id = {s["id"]: s for s in scopes}
    if under:
        return find_scope(scopes, under)
    planned = (plan.get("root") or {}).get("existing_id")
    if planned and planned in by_id:
        return by_id[planned]
    tops = [s for s in scopes if not s.get("parent_app_scope_id")]
    if not planned and len(tops) == 1 and len(scopes) == 1:
        return tops[0]
    raise HelperError('Say which scope to build under with --under "full scope name".')


def build_actions(plan, scopes, parent):
    """Decide, scope by scope, what to do. Never plans a change to an existing scope."""
    index = children_index(scopes)
    ids, actions = {"root": parent["id"]}, []
    for item in sorted(plan.get("scopes") or [], key=lambda s: s.get("order", 0)):
        parent_id = ids.get(item["parent_ref"], "missing")
        if parent_id == "missing":
            raise HelperError("The plan file is out of order at scope " + str(item.get("short_name")))
        action = {"ref": item["ref"], "parent_ref": item["parent_ref"], "short_name": item["short_name"],
                  "short_query": item["short_query"], "depth": item.get("depth", 1), "parent_id": parent_id, "id": None}
        found = None
        if parent_id is not None:
            found = next((c for c in index.get(parent_id, []) if same_name(c.get("short_name"), item["short_name"])[0]), None)
        if found is None:
            action["do"] = "create"
        else:
            action["id"] = found["id"]
            same, exact = same_query(found.get("short_query"), item["short_query"])
            action["do"] = "exists" if same else "kept"
            if not same:
                action["existing_query"] = as_query(found.get("short_query"))
            notes = []
            if not same_name(found.get("short_name"), item["short_name"])[1]:
                notes.append('named "%s" in the tenant' % found.get("short_name"))
            if same and not exact:
                notes.append('its query is written "%s" in the tenant' % as_query(found.get("short_query")).get("value"))
            if notes:
                action["spelling"] = "same scope, different capital letters: " + " and ".join(notes)
        ids[item["ref"]] = action["id"]
        actions.append(action)
    creates = sum(1 for a in actions if a["do"] == "create")
    root_id = parent.get("root_app_scope_id") or root_scope_of(scopes, parent)["id"]
    existing_children = child_scope_count(scopes, root_id)
    if existing_children + creates > MAX_SCOPES:
        raise HelperError("Creating %d scopes would bring the tenant to %d child scopes, over the limit of %d."
                          % (creates, existing_children + creates, MAX_SCOPES))
    return actions


def describe_actions(actions, parent, out=print):
    names = {"root": parent.get("short_name")}
    for a in actions:
        names[a["ref"]] = a["short_name"]
    words = {"create": "CREATE", "exists": "already exists, no change", "kept": "exists with a different query, left as it is"}
    for a in actions:
        q = a["short_query"]
        out("  %-44s under %-24s %s = %s   [%s]" % (a["short_name"], names[a["parent_ref"]],
                                                     str(q.get("field", "")).replace("user_", "", 1), q.get("value"), words[a["do"]]))
        if a.get("spelling"):
            out("      note: " + a["spelling"])
    out("")
    out("%d to create, %d already there, %d left as they are."
        % tuple(sum(1 for a in actions if a["do"] == d) for d in ("create", "exists", "kept")))


def confirm(args, question, ask=input, always_ask=False):
    if args.yes and not always_ask:
        return True
    return ask(question + " Type yes to continue: ").strip().lower() == "yes"


def save_record(path, record):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)


def create_scopes(client, actions, parent, record, record_path, out=print, today=None):
    today = today or datetime.date.today().isoformat()
    ids = {"root": parent["id"]}
    for a in actions:
        if a["do"] != "create":
            ids[a["ref"]] = a["id"]
            continue
        payload = {"short_name": a["short_name"], "description": CREATED_MARK + " on " + today,
                   "short_query": a["short_query"], "parent_app_scope_id": ids[a["parent_ref"]]}

        def already_there():
            return next((s for s in client.scopes() if s.get("parent_app_scope_id") == payload["parent_app_scope_id"]
                         and s.get("short_name") == a["short_name"]), None)

        how = "created"
        try:
            made = client.call("POST", SCOPES_PATH, payload)
        except NetworkError:
            # The outcome is unknown. Look before trying again, so a scope is never created twice.
            made = already_there()
            how = "found after the connection dropped"
            if made is None:
                how = "created on the second try"
                try:
                    made = client.call("POST", SCOPES_PATH, payload)
                except NetworkError:
                    made = already_there()
                    how = "found after the connection dropped twice"
                    if made is None:
                        raise HelperError('The connection dropped twice while creating scope "%s", and it is not in the tenant. '
                                          "Nothing further was created. Run the same command again to continue this build."
                                          % a["short_name"])
        if not isinstance(made, dict) or not made.get("id"):
            raise HelperError('The tenant did not confirm scope "%s". Nothing further was created.' % a["short_name"])
        a["id"] = ids[a["ref"]] = made["id"]
        record["created"].append({"id": made["id"], "short_name": a["short_name"], "parent_id": payload["parent_app_scope_id"],
                                  "depth": a["depth"], "ref": a["ref"], "how": how})
        save_record(record_path, record)
        back = client.call("GET", SCOPES_PATH + "/" + made["id"])
        ok = (isinstance(back, dict) and back.get("short_name") == a["short_name"]
              and back.get("parent_app_scope_id") == payload["parent_app_scope_id"]
              and as_query(back.get("short_query")) == a["short_query"])
        if not ok:
            raise HelperError('Scope "%s" was created but does not read back as planned. Stopped. '
                              "Review it in Secure Workload, or remove this run with the undo command." % a["short_name"])
        out("  created and verified: " + a["short_name"] + ("" if how == "created" else " (" + how + ")"))


def commit_if_safe(client, parent, out=print, commit_timeout=DEFAULT_COMMIT_TIMEOUT):
    """Commit scope changes only when every uncommitted scope belongs to this work area.

    Returns True when committed, False when left for the customer because other changes are
    pending, None when no commit was needed, and "still committing" when time ran out.
    """
    def work_area(scopes):
        by_id = {s["id"]: s for s in scopes}
        here = by_id.get(parent["id"], parent)
        return here, {s["id"] for s in subtree(scopes, here)} | {s["id"] for s in ancestors(scopes, here)}

    scopes = client.scopes()
    here, mine = work_area(scopes)
    dirty = [s for s in scopes if s.get("dirty")]
    if not dirty:
        out("No commit is needed.")
        return None
    others = [s.get("name") for s in dirty if s["id"] not in mine]
    if others:
        out("The scope changes are saved but NOT committed, because other scopes in this tenant have uncommitted")
        out("changes that are not part of this work: " + ", ".join(str(n) for n in others[:5]))
        out("Commit from Secure Workload (Organize > Scopes and Inventory > Commit Changes) when ready.")
        return False
    root_id = here.get("root_app_scope_id") or root_scope_of(scopes, here)["id"]
    try:
        client.call("POST", SCOPES_PATH + "/commit_dirty?root_app_scope_id=%s&sync=true" % root_id, timeout=commit_timeout)
    except NetworkError:
        out("The commit did not answer within %d seconds. Checking every %d seconds whether it has finished ..."
            % (commit_timeout, COMMIT_POLL_SECONDS))
        waited = 0
        while waited < commit_timeout:
            client.sleep(COMMIT_POLL_SECONDS)
            waited += COMMIT_POLL_SECONDS
            scopes = client.scopes()
            here, mine = work_area(scopes)
            if not any(s.get("dirty") for s in scopes if s["id"] in mine):
                out("Scope changes committed.")
                return True
        out("Still committing. Check in Secure Workload under Organize > Scopes and Inventory.")
        return "still committing"
    out("Scope changes committed.")
    return True


def commit_or_leave(client, parent, out, args):
    """Commit under the safe-commit rule, or leave the changes uncommitted when --no-commit was given."""
    if getattr(args, "no_commit", False):
        out("Not committed, because --no-commit was given. Look at the pending changes in Secure Workload under Organize > "
            "Scopes and Inventory, and select Commit Changes there when you are ready. A changed query takes effect only then.")
        return "left uncommitted (--no-commit)"
    return commit_if_safe(client, parent, out, args.commit_timeout)


def settle_attempts(record, scopes):
    """Settle every record entry still marked "attempting" by reading the tenant.

    An entry is saved as "attempting" before its call is sent. If it is still marked that way, the run stopped
    without learning whether the tenant made the change. The tenant is the only place that knows.
    """
    by_id = {s["id"]: s for s in scopes}
    settled = "settled by reading the tenant on a later run"

    def is_now(change, side):
        live = by_id.get(change["id"])
        if live is None:
            return False
        if change["kind"] == "rename":
            return live.get("short_name") == change[side]["short_name"]
        return live_query(live) == as_query(change[side]["short_query"])

    for change in record.get("changes") or []:
        if change.get("status") == "attempting":
            change["status"], change["how"] = ("done" if is_now(change, "after") else "not done"), settled
        if change.get("restore") == "attempting":
            if is_now(change, "before"):
                change["restore"], change["restored"] = "done", True
            else:
                change["restore"] = "not done"
    for entry in record.get("removed") or []:
        if entry.get("status") == "attempting":
            entry["status"], entry["how"] = ("removed" if entry["before"]["id"] not in by_id else "not removed"), settled
    for made in record.get("created") or []:
        if made.get("undo") == "attempting":
            made["undo"] = "removed" if made["id"] not in by_id else "not done"


def unsure(err):
    """True when a failed call may still have been applied by the tenant: a dropped connection or a server error."""
    return isinstance(err, NetworkError) or (isinstance(err, TenantError) and (err.code or 0) >= 500)


def why_unsure(err):
    return "error %s" % err.code if isinstance(err, TenantError) else "the connection dropped"


def is_done(change):
    """A change entry from before release 1.2 has no status and was saved only after it was made."""
    return change.get("status") in (None, "done")


def find_unfinished_record(out_dir, tenant_url, parent_id, fingerprint):
    """The newest unfinished record in the folder for the same tenant, parent, and plan."""
    best = None
    for name in sorted(os.listdir(out_dir)):
        if "CSW Apply Record" not in name or not name.lower().endswith(".json"):
            continue
        path = os.path.join(out_dir, name)
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        if (isinstance(data, dict) and data.get("schema") == RECORD_SCHEMA and data.get("schema_version") in (2, 3)
                and data.get("finished") is False and data.get("tenant_url") == tenant_url
                and (data.get("parent") or {}).get("id") == parent_id and data.get("plan_fingerprint") == fingerprint):
            best = (path, data)
    return best


def cmd_apply(client, args, out=print, ask=input, now=None):
    if not args.plan:
        raise HelperError("Give the plan file with --plan.")
    plan = load_plan(args.plan)
    if plan.get("schema_version") == 3:
        return apply_changes(client, args, plan, out, ask, now)
    if args.allow_changes or args.allow_removals:
        raise HelperError("--allow-changes and --allow-removals need a plan file in format 3. This plan file is format %s and only "
                          "creates scopes. Make a new plan with the current planner." % plan.get("schema_version"))
    fingerprint = plan_fingerprint(plan.get("scopes"))
    out("Reading scopes from " + client.base_url + " ...")
    scopes = client.scopes()
    parent = resolve_parent(plan, scopes, args.under)
    actions = build_actions(plan, scopes, parent)
    out('Plan for %s, to be built under "%s":' % ((plan.get("customer") or {}).get("name") or "customer", parent.get("name")))
    describe_actions(actions, parent, out)
    columns = read_label_columns(client, scopes, parent)
    if columns is not None:
        needed = sorted({str(a["short_query"].get("field"))[5:] for a in actions
                         if str(a["short_query"].get("field", "")).startswith("user_")})
        missing = [n for n in needed if n.lower() not in [str(c).lower() for c in columns]]
        if missing:
            out("Note: the tenant has no label named %s yet. Scopes that use it stay empty until the label file is uploaded."
                % ", ".join(missing))
    creates = [a for a in actions if a["do"] == "create"]
    now = now or datetime.datetime.now()
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S")
    unfinished = find_unfinished_record(args.out_dir, client.base_url, parent["id"], fingerprint) if args.write else None

    def closing_lines(record_path):
        out("Record of this run: " + os.path.abspath(record_path))
        out("To remove what this build created: " + command_line("undo", "--record", os.path.basename(record_path)))

    if not creates:
        if unfinished:
            record_path, record = unfinished
            out('An earlier run of this build stopped before it finished. Every scope is in place, so this run completes the record "%s".'
                % os.path.basename(record_path))
            record.setdefault("resumed_at", []).append(stamp)
            record["finished"] = True
            try:
                record["committed"] = commit_or_leave(client, parent, out, args)
            finally:
                save_record(record_path, record)
                closing_lines(record_path)
            return 0
        out("Nothing to create.")
        return 0
    if not args.write:
        if args.no_commit:
            out("--no-commit does nothing without --write.")
        out("This was a preview. Nothing was changed. Run again with --write to create the scopes.")
        return 0
    if unfinished:
        out('This continues the unfinished build recorded in "%s" (%d created so far). Undo will reverse the whole build in one run.'
            % (os.path.basename(unfinished[0]), len(unfinished[1].get("created") or [])))
    if not confirm(args, 'About to create %d %s under "%s".' % (len(creates), "scope" if len(creates) == 1 else "scopes", parent.get("name")), ask):
        out("Stopped. Nothing was changed.")
        return 1
    if unfinished:
        record_path, record = unfinished
        record.setdefault("resumed_at", []).append(stamp)
    else:
        stem = "%s %s - CSW Apply Record" % (now.strftime("%Y-%m-%d %H%M%S"), safe_name(parent.get("short_name")))
        record_path, extra = os.path.join(args.out_dir, stem + ".json"), 1
        while os.path.exists(record_path):
            extra += 1
            record_path = os.path.join(args.out_dir, "%s (%d).json" % (stem, extra))
        record = {"schema": RECORD_SCHEMA, "schema_version": RECORD_SCHEMA_VERSION, "tool_version": VERSION,
                  "tenant_url": client.base_url, "started_at": stamp, "parent": {"id": parent["id"], "name": parent.get("name")},
                  "plan_file": os.path.basename(args.plan), "plan_fingerprint": fingerprint,
                  "created": [], "changes": [], "removed": [], "skipped": [], "resumed_at": [], "finished": False, "committed": None}
    before = len(record["created"])
    save_record(record_path, record)
    try:
        create_scopes(client, actions, parent, record, record_path, out)
        record["finished"] = True
        record["committed"] = commit_or_leave(client, parent, out, args)
    finally:
        save_record(record_path, record)
        closing_lines(record_path)
    made = len(record["created"]) - before
    out("Created %d %s. Upload the label file in Secure Workload so the new scopes fill with workloads."
        % (made, "scope" if made == 1 else "scopes"))
    return 0


# ---------------------------------------------------------------- apply, plan format 3 (changes to existing scopes)

CHANGED_SINCE = ("This scope changed since the plan was made: %s. Nothing was changed. Run export again and make a new plan "
                 "with the current planner.")


def check_changes_plan(plan, scopes, parent, record=None):
    """Read-only checks for a format 3 plan. Returns the work to do. Raises before anything is changed."""
    by_id, index = {s["id"]: s for s in scopes}, children_index(scopes)
    area = {s["id"] for s in subtree(scopes, parent)} - {parent["id"]}
    record = record or {}
    made = {c.get("ref"): c["id"] for c in record.get("created") or []}
    done = {(c.get("kind"), c.get("id")) for c in record.get("changes") or [] if is_done(c)}
    gone = {(r.get("before") or {}).get("id") for r in record.get("removed") or [] if r.get("status") == "removed"}
    items = sorted(plan.get("scopes") or [], key=lambda x: x.get("order", 0))
    work = {"create": [], "rename": [], "requery": [], "remove": [], "skipped": [], "by_hand": [], "keep": 0, "leave": 0,
            "actions": [], "names": {"root": parent.get("short_name")}}
    refs, removing = {"root": parent["id"]}, set()

    for item in items:
        action = item.get("action")
        if action not in ALL_ACTIONS or not item.get("ref"):
            raise HelperError("The plan file has an item this helper does not understand (%s). Make a new plan with the current planner."
                              % str(item.get("action")))
        work["names"][item["ref"]] = item.get("short_name")
        if action == "create":
            continue
        before = item.get("before") or {}
        label = '"%s"' % (before.get("short_name") or item.get("short_name"))
        if not before.get("id"):
            raise HelperError("The plan file does not say which existing scope %s is. Make a new plan with the current planner." % label)
        live = by_id.get(before["id"])
        changing = action in CHANGE_ACTIONS or action == "remove"
        if live is None:
            if action == "remove" and before["id"] in gone:
                refs[item["ref"]] = None
                continue
            raise HelperError(CHANGED_SINCE % (label + " is no longer in the tenant"))
        want_name = (item.get("after") or {}).get("short_name") if ("rename", live["id"]) in done else before.get("short_name")
        want_query = as_query((item.get("after") or {}).get("short_query") if ("requery", live["id"]) in done else before.get("short_query"))
        if live.get("short_name") != want_name:
            raise HelperError(CHANGED_SINCE % ('%s is now named "%s"' % (label, live.get("short_name"))))
        if live.get("parent_app_scope_id") != before.get("parent_id"):
            raise HelperError(CHANGED_SINCE % (label + " now has a different parent"))
        if ("requery", live["id"]) in done:
            if live_query(live) != want_query and as_query(live.get("short_query")) != want_query:
                raise HelperError(CHANGED_SINCE % (label + " has a different query"))
        elif as_query(live.get("short_query")) != want_query or live.get("dirty_short_query"):
            raise HelperError(CHANGED_SINCE % (label + (" has a query change waiting for a commit" if live.get("dirty_short_query")
                                                        else " has a different query")))
        if changing and not live.get("parent_app_scope_id"):
            raise HelperError('%s is a top-level scope. This program never renames, changes, or removes a top-level scope. '
                              "Nothing was changed." % label)
        if changing and live["id"] not in area:
            raise HelperError('%s is not under "%s". This program changes nothing outside the scope it is working under. '
                              "Nothing was changed." % (label, parent.get("name")))
        refs[item["ref"]] = live["id"]
        entry = {"item": item, "live": live, "name": live.get("name"), "depth": len(ancestors(scopes, live))}
        if action == "keep":
            work["keep"] += 1
        elif action == "leave":
            work["leave"] += 1
        elif action == "by_hand":
            work["by_hand"].append(entry)
        elif not item.get("approved"):
            work["skipped"].append(entry)
        elif action == "remove":
            work["remove"].append(entry)
            removing.add(live["id"])
        else:
            after = item.get("after") or {}
            if action in ("rename", "rename_requery"):
                if not str(after.get("short_name") or "").strip():
                    raise HelperError("The plan file gives no new name for %s. Make a new plan with the current planner." % label)
                if ("rename", live["id"]) not in done:
                    clash = [c for c in index.get(live.get("parent_app_scope_id"), [])
                             if c["id"] != live["id"] and same_name(c.get("short_name"), after["short_name"])[0]]
                    if clash:
                        raise HelperError('%s cannot be renamed to "%s" because a scope with that name is already beside it. '
                                          "Nothing was changed." % (label, after["short_name"]))
                    work["rename"].append(entry)
            if action in ("requery", "rename_requery"):
                if not isinstance(as_query(after.get("short_query")), dict):
                    raise HelperError("The plan file gives no new query for %s. Make a new plan with the current planner." % label)
                if ("requery", live["id"]) not in done:
                    work["requery"].append(entry)

    for entry in work["remove"]:
        kept = [c for c in index.get(entry["live"]["id"], []) if c["id"] not in removing]
        if kept:
            raise HelperError('"%s" cannot be removed because the scope "%s" under it is not also being removed. Nothing was changed.'
                              % (entry["live"].get("short_name"), kept[0].get("short_name")))

    for item in items:
        if item.get("action") != "create":
            ref = refs.get(item["ref"])
            work["actions"].append({"do": "exists", "ref": item["ref"], "parent_ref": item.get("parent_ref"), "id": ref,
                                    "short_name": item.get("short_name"), "short_query": item.get("short_query"), "depth": item.get("depth", 1)})
            continue
        if item.get("parent_ref") not in refs:
            raise HelperError("The plan file is out of order at scope " + str(item.get("short_name")))
        query = as_query((item.get("after") or {}).get("short_query") or item.get("short_query"))
        name = (item.get("after") or {}).get("short_name") or item.get("short_name")
        if not isinstance(query, dict) or not str(name or "").strip():
            raise HelperError("The plan file is missing the name or query of a scope to create. Make a new plan with the current planner.")
        parent_id = refs[item["parent_ref"]]
        if parent_id in removing:
            raise HelperError('The plan creates "%s" under a scope it also removes. Nothing was changed. Make a new plan.' % name)
        action = {"do": "create", "ref": item["ref"], "parent_ref": item["parent_ref"], "id": None, "short_name": name,
                  "short_query": query, "depth": item.get("depth", 1)}
        found = None
        if parent_id is not None:
            found = next((c for c in index.get(parent_id, []) if same_name(c.get("short_name"), name)[0]), None)
        if found is not None:
            if not same_query(live_query(found), query)[0]:
                raise HelperError(CHANGED_SINCE % ('a scope named "%s" now exists under "%s" with a different query'
                                                   % (found.get("short_name"), by_id[parent_id].get("short_name"))))
            action.update(do="exists", id=found["id"], was_made=made.get(item["ref"]) == found["id"])
        refs[item["ref"]] = action["id"]
        work["actions"].append(action)
        if action["do"] == "create":
            work["create"].append(action)

    root_id = parent.get("root_app_scope_id") or root_scope_of(scopes, parent)["id"]
    total = child_scope_count(scopes, root_id) + len(work["create"])
    if total > MAX_SCOPES:
        raise HelperError("Creating %d scopes would bring the tenant to %d child scopes, over the limit of %d."
                          % (len(work["create"]), total, MAX_SCOPES))
    work["remove"].sort(key=lambda e: -e["depth"])
    return work


def describe_changes(work, args, out=print):
    """Print the preview for a format 3 plan and return (changes to make, removals to make)."""
    for a in work["actions"]:
        if a["do"] == "create":
            out("  CREATE        %s under %s: %s" % (a["short_name"], work["names"].get(a["parent_ref"]), describe_query(a["short_query"])))
    allowed = {"rename": args.allow_changes, "requery": args.allow_changes, "remove": args.allow_removals}
    flag = {"rename": "--allow-changes", "requery": "--allow-changes", "remove": "--allow-removals"}
    title = {"rename": "RENAME       ", "requery": "CHANGE QUERY ", "remove": "REMOVE       "}

    def line(kind, entry):
        item, live = entry["item"], entry["live"]
        after = item.get("after") or {}
        if kind == "rename":
            return '%s: from "%s" to "%s"' % (entry["name"], live.get("short_name"), after.get("short_name"))
        if kind == "requery":
            return "%s: from [%s] to [%s]" % (entry["name"], describe_query(live.get("short_query")), describe_query(after.get("short_query")))
        return str(entry["name"])

    for kind in ("rename", "requery", "remove"):
        for entry in work[kind]:
            out("  %s %s%s" % (title[kind], line(kind, entry), "" if allowed[kind] else "   [would do with %s]" % flag[kind]))
    for entry in work["skipped"]:
        out("  SKIPPED       %s   [%s is not approved in the plan]"
            % (entry["name"], {"rename": "rename", "requery": "query change", "rename_requery": "rename and query change",
                               "remove": "removal"}[entry["item"]["action"]]))
    for entry in work["by_hand"]:
        out("  BY HAND       %s: %s" % (entry["name"], entry["item"].get("reason") or "a change this program will not make"))
    out("")
    out("%d to create, %d to rename, %d query %s, %d to remove. %d not approved and skipped, %d to do by hand, %d kept, %d left alone."
        % (len(work["create"]), len(work["rename"]), len(work["requery"]), "change" if len(work["requery"]) == 1 else "changes",
           len(work["remove"]), len(work["skipped"]), len(work["by_hand"]), work["keep"], work["leave"]))
    changes = [(k, e) for k in ("rename", "requery") for e in work[k]] if args.allow_changes else []
    removals = list(work["remove"]) if args.allow_removals else []
    return changes, removals, line


def in_use_words(detail):
    """What the tenant says depends on a scope, from its 422 answer, in one line."""
    try:
        data = json.loads(detail)
    except ValueError:
        return detail.strip()[:400] or "The tenant gave no detail."
    parts = []
    details = data.get("details") if isinstance(data, dict) else None
    if isinstance(details, dict):
        for kind, value in sorted(details.items()):
            if isinstance(value, dict):
                parts.append("%s: %s%s" % (kind, value.get("count", "?"),
                                           (" (IDs: %s)" % ", ".join(str(i) for i in value.get("ids"))) if value.get("ids") else ""))
            else:
                parts.append("%s: %s" % (kind, json.dumps(value)))
    said = str(data.get("error") or "") if isinstance(data, dict) else ""
    return "; ".join([p for p in [said] + parts if p])[:1000] or detail.strip()[:400]


def apply_changes(client, args, plan, out=print, ask=input, now=None):
    fingerprint = plan_fingerprint(plan.get("scopes"))
    out("Reading scopes from " + client.base_url + " ...")
    scopes = client.scopes()
    parent = resolve_parent(plan, scopes, args.under)
    unfinished = find_unfinished_record(args.out_dir, client.base_url, parent["id"], fingerprint) if args.write else None
    if unfinished:
        settle_attempts(unfinished[1], scopes)
    work = check_changes_plan(plan, scopes, parent, unfinished[1] if unfinished else None)
    out('Plan for %s, under "%s":' % ((plan.get("customer") or {}).get("name") or "customer", parent.get("name")))
    changes, removals, line = describe_changes(work, args, out)
    creates = work["create"]
    now = now or datetime.datetime.now()
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S")

    def closing_lines(record_path):
        out("Record of this run: " + os.path.abspath(record_path))
        out("To reverse what this build did: " + command_line("undo", "--record", os.path.basename(record_path)))

    if not args.write:
        if args.allow_changes or args.allow_removals or args.no_commit:
            out("--allow-changes, --allow-removals, and --no-commit do nothing without --write.")
        out("This was a preview. Nothing was changed. Run again with --write to create scopes. Add --allow-changes for renames "
            "and query changes, and --allow-removals for removals.")
        return 0
    if not creates and not changes and not removals:
        if unfinished:
            record_path, record = unfinished
            out('An earlier run of this build stopped before it finished. Nothing is left to do, so this run completes the record "%s".'
                % os.path.basename(record_path))
            record.setdefault("resumed_at", []).append(stamp)
            record["finished"] = True
            try:
                record["committed"] = commit_or_leave(client, parent, out, args)
            finally:
                save_record(record_path, record)
                closing_lines(record_path)
            return 0
        out("Nothing to do with the options given.")
        return 0
    if unfinished:
        out('This continues the unfinished build recorded in "%s". Undo will reverse the whole build in one run.'
            % os.path.basename(unfinished[0]))
    if creates and not confirm(args, 'About to create %d %s under "%s".'
                               % (len(creates), "scope" if len(creates) == 1 else "scopes", parent.get("name")), ask):
        out("Stopped. Nothing was changed.")
        return 1
    if changes:
        out("")
        out("Changes to existing scopes:")
        for kind, entry in changes:
            out("  " + ("rename " if kind == "rename" else "change the query of ") + line(kind, entry))
        if not confirm(args, "About to make %d %s to existing scopes, listed above." % (len(changes), "change" if len(changes) == 1 else "changes"),
                       ask, always_ask=True):
            out("Stopped. Nothing was changed.")
            return 1
    if removals:
        out("")
        out("Scopes to remove:")
        for entry in removals:
            out("  " + str(entry["name"]))
        if not confirm(args, "About to REMOVE %d %s, listed above by full name." % (len(removals), "scope" if len(removals) == 1 else "scopes"),
                       ask, always_ask=True):
            out("Stopped. Nothing was changed.")
            return 1

    if unfinished:
        record_path, record = unfinished
        record.setdefault("resumed_at", []).append(stamp)
        for key in ("changes", "removed", "skipped"):
            record.setdefault(key, [])
    else:
        stem = "%s %s - CSW Apply Record" % (now.strftime("%Y-%m-%d %H%M%S"), safe_name(parent.get("short_name")))
        record_path, extra = os.path.join(args.out_dir, stem + ".json"), 1
        while os.path.exists(record_path):
            extra += 1
            record_path = os.path.join(args.out_dir, "%s (%d).json" % (stem, extra))
        record = {"schema": RECORD_SCHEMA, "schema_version": RECORD_SCHEMA_VERSION, "tool_version": VERSION,
                  "tenant_url": client.base_url, "started_at": stamp, "parent": {"id": parent["id"], "name": parent.get("name")},
                  "plan_file": os.path.basename(args.plan), "plan_fingerprint": fingerprint,
                  "created": [], "changes": [], "removed": [], "skipped": [], "resumed_at": [], "finished": False, "committed": None}
    record["skipped"] = ([{"name": e["name"], "action": e["item"]["action"], "why": "not approved in the plan"} for e in work["skipped"]]
                         + [{"name": e["name"], "action": k, "why": "needs --allow-changes"}
                            for k in ("rename", "requery") for e in work[k] if not args.allow_changes]
                         + [{"name": e["name"], "action": "remove", "why": "needs --allow-removals"}
                            for e in work["remove"] if not args.allow_removals])
    counts = (len(record["created"]), len([c for c in record["changes"] if is_done(c)]),
              len([r for r in record["removed"] if r.get("status") == "removed"]))
    in_use = []
    again = "Run the same command again to continue this build. It reads the tenant first and does only what is missing."

    def unreachable(doing, name, err):
        return HelperError('The tenant did not confirm %s "%s" (%s), and it could not be reached to see whether the change was made. '
                           'The record marks it "attempting". When the connection is back: %s' % (doing, name, why_unsure(err), again))
    save_record(record_path, record)
    try:
        create_scopes(client, work["actions"], parent, record, record_path, out)
        for kind, entry in changes:
            item, live, after = entry["item"], entry["live"], entry["item"].get("after") or {}
            # The entry is saved before the call is sent, so a change the tenant made is never missing from the record.
            change = {"kind": kind, "id": live["id"], "ref": item["ref"], "status": "attempting",
                      "before": {"id": live["id"], "short_name": live.get("short_name"), "short_query": as_query(live.get("short_query")),
                                 "parent_id": live.get("parent_app_scope_id")},
                      "after": {"short_name": after["short_name"]} if kind == "rename" else {"short_query": as_query(after["short_query"])}}
            # An earlier try at the same change that the tenant did not make is replaced, so the record holds one entry for it.
            record["changes"] = [c for c in record["changes"]
                                 if not (c.get("kind") == kind and c.get("id") == live["id"] and c.get("status") == "not done")] + [change]
            save_record(record_path, record)

            def as_planned(scope):
                return isinstance(scope, dict) and (scope.get("short_name") == after["short_name"] if kind == "rename"
                                                    else live_query(scope) == as_query(after["short_query"]))

            doing = "renaming" if kind == "rename" else "changing the query of"
            try:
                client.call("PUT", SCOPES_PATH + "/" + live["id"], dict(change["after"]))
            except HelperError as err:
                if not unsure(err):
                    change["status"], change["how"] = "not done", "the tenant refused with error %s" % getattr(err, "code", "?")
                    save_record(record_path, record)
                    raise
                # The outcome is unknown. Read the scope back, record what the tenant shows, and stop.
                try:
                    landed = as_planned(client.call("GET", SCOPES_PATH + "/" + live["id"]))
                except HelperError:
                    raise unreachable(doing, entry["name"], err)
                change["status"], change["how"] = ("done" if landed else "not done"), why_unsure(err) + "; the tenant was read back"
                save_record(record_path, record)
                raise HelperError('The tenant did not confirm %s "%s" (%s). The tenant was read back: the change %s. Stopped. %s'
                                  % (doing, entry["name"], why_unsure(err), "WAS made" if landed else "was NOT made", again))
            change["status"] = "done"
            save_record(record_path, record)
            if not as_planned(client.call("GET", SCOPES_PATH + "/" + live["id"])):
                raise HelperError('The %s of "%s" does not read back as planned. Stopped. Review it in Secure Workload, or reverse this '
                                  "run with the undo command." % ("new name" if kind == "rename" else "new query", entry["name"]))
            out("  %s and verified: %s" % ("renamed" if kind == "rename" else "query changed", line(kind, entry)))
        blocked = set()
        for entry in removals:
            live = entry["live"]
            if live["id"] in blocked:
                record["removed"] = [r for r in record["removed"] if not ((r.get("before") or {}).get("id") == live["id"]
                                                                          and r.get("status") in ("not removed", "in use"))]
                record["removed"].append({"name": entry["name"], "status": "not removed", "why": "a scope under it is in use",
                                          "before": {"id": live["id"]}})
                save_record(record_path, record)
                out("  not removed: %s (a scope under it is in use)" % entry["name"])
                blocked.update(a["id"] for a in ancestors(scopes, live))
                continue
            kept = {"id": live["id"], "short_name": live.get("short_name"), "short_query": as_query(live.get("short_query")),
                    "parent_id": live.get("parent_app_scope_id"), "description": live.get("description")}
            removal = {"name": entry["name"], "status": "attempting", "depth": entry["depth"], "before": kept}
            record["removed"] = [r for r in record["removed"]
                                 if not ((r.get("before") or {}).get("id") == live["id"] and r.get("status") in ("not removed", "in use"))] + [removal]
            save_record(record_path, record)
            try:
                client.call("DELETE", SCOPES_PATH + "/" + live["id"])
            except HelperError as err:
                if isinstance(err, TenantError) and err.code == 422:
                    said = in_use_words(err.detail)
                    removal["status"], removal["tenant_said"] = "in use", said
                    save_record(record_path, record)
                    in_use.append((entry["name"], said))
                    out("  IN USE, not removed: %s. The tenant says: %s" % (entry["name"], said))
                    blocked.update(a["id"] for a in ancestors(scopes, live))
                    continue
                if not unsure(err):
                    removal["status"], removal["why"] = "not removed", "the tenant refused with error %s" % getattr(err, "code", "?")
                    save_record(record_path, record)
                    raise
                try:
                    landed = not any(s["id"] == live["id"] for s in client.scopes())
                except HelperError:
                    raise unreachable("removing", entry["name"], err)
                removal["status"], removal["how"] = ("removed" if landed else "not removed"), why_unsure(err) + "; the tenant was read back"
                save_record(record_path, record)
                raise HelperError('The tenant did not confirm removing "%s" (%s). The tenant was read back: the scope %s. Stopped. %s'
                                  % (entry["name"], why_unsure(err), "IS gone" if landed else "is still there", again))
            removal["status"] = "removed"
            save_record(record_path, record)
            still = any(s["id"] == live["id"] for s in client.scopes())
            out("  removed: %s%s" % (entry["name"], " (still listed until the changes are committed)" if still else " (verified gone)"))
        record["finished"] = True
        record["committed"] = commit_or_leave(client, parent, out, args)
    finally:
        save_record(record_path, record)
        closing_lines(record_path)
    out("Created %d, changed %d, removed %d." % (len(record["created"]) - counts[0],
                                                 len([c for c in record["changes"] if is_done(c)]) - counts[1],
                                                 len([r for r in record["removed"] if r.get("status") == "removed"]) - counts[2]))
    if record["skipped"]:
        out("Skipped, nothing done:")
        for entry in record["skipped"]:
            out("  %s (%s)" % (entry["name"], entry["why"]))
    if in_use:
        out("In use and not removed. Clear what depends on each in Secure Workload first:")
        for name, said in in_use:
            out("  %s: %s" % (name, said))
    if work["by_hand"]:
        out("To do by hand in Secure Workload:")
        for entry in work["by_hand"]:
            out("  %s: %s" % (entry["name"], entry["item"].get("reason") or ""))
    if len(record["created"]) > counts[0]:
        out("Upload the label file in Secure Workload so the new scopes fill with workloads.")
    return 0


# ---------------------------------------------------------------- undo

def plan_undo(record, scopes):
    """Return (scopes to delete deepest first, notes). Refuses anything not created by the recorded run."""
    by_id, index = {s["id"]: s for s in scopes}, children_index(scopes)
    created = {c["id"]: c for c in record.get("created") or []}
    todo, notes = [], []
    for item in sorted(created.values(), key=lambda c: -c.get("depth", 1)):
        live = by_id.get(item["id"])
        if not live:
            notes.append('"%s" is already gone.' % item["short_name"])
            continue
        if live.get("short_name") != item["short_name"] or live.get("parent_app_scope_id") != item["parent_id"]:
            raise HelperError('Scope "%s" has been renamed or moved since it was created. Nothing was removed.' % item["short_name"])
        strangers = [c.get("short_name") for c in index.get(item["id"], []) if c["id"] not in created]
        if strangers:
            raise HelperError('Scope "%s" now has scopes under it that this run did not create (%s). Nothing was removed.'
                              % (item["short_name"], ", ".join(str(n) for n in strangers)))
        todo.append(live)
    return todo, notes


def record_from_marks(client, scopes, top):
    """Stand-in record for a lost record file: this program's scopes under one scope, found by their description."""
    made = [s for s in subtree(scopes, top)[1:] if str(s.get("description") or "").startswith(CREATED_MARK)]
    return {"schema": RECORD_SCHEMA, "schema_version": RECORD_SCHEMA_VERSION, "tool_version": VERSION,
            "tenant_url": client.base_url, "parent": {"id": top["id"], "name": top.get("name")}, "rebuilt_from_descriptions": True,
            "created": [{"id": s["id"], "short_name": s.get("short_name"), "parent_id": s.get("parent_app_scope_id"),
                         "depth": len(ancestors(scopes, s)), "ref": s["id"]} for s in made],
            "finished": True, "committed": None}


def plan_full_undo(record, scopes):
    """Read-only checks for reversing renames, query changes, and removals. Returns the steps. Raises before anything is changed."""
    by_id, index = {s["id"]: s for s in scopes}, children_index(scopes)
    removed = [r for r in record.get("removed") or [] if r.get("status") == "removed"]
    coming_back = {r["before"]["id"] for r in removed}
    known = {r["before"]["id"]: r["recreated_id"] for r in removed if r.get("recreated_id") in by_id}
    steps = {"recreate": [], "requery": [], "rename": [], "notes": []}
    for entry in sorted(removed, key=lambda r: r.get("depth", 1)):
        before = entry["before"]
        if before["id"] in known:
            steps["notes"].append('"%s" was already recreated.' % before.get("short_name"))
            continue
        parent_id = known.get(before.get("parent_id"), before.get("parent_id"))
        if parent_id not in by_id and before.get("parent_id") not in coming_back:
            raise HelperError('The scope that "%s" sat under is no longer in the tenant, so it cannot be recreated. Nothing was changed.'
                              % before.get("short_name"))
        twins = [c for c in index.get(parent_id, []) if same_name(c.get("short_name"), before.get("short_name"))[0]]
        if twins:
            # An undo that lost its connection while recreating this scope may have made it already. Look before trying again.
            if entry.get("recreate") == "attempting" and live_query(twins[0]) == as_query(before.get("short_query")):
                entry["recreated_id"], entry["recreate"] = twins[0]["id"], "done"
                known[before["id"]] = twins[0]["id"]
                steps["notes"].append('"%s" was recreated by an earlier undo that lost its connection. It is not made a second time.'
                                      % before.get("short_name"))
                continue
            raise HelperError('A scope named "%s" is already where the removed one was. This run did not put it there, so nothing was changed.'
                              % before.get("short_name"))
        steps["recreate"].append(entry)
    for change in reversed(record.get("changes") or []):
        if change.get("restored") or not is_done(change):
            continue
        live = by_id.get(change["id"])
        if live is None:
            raise HelperError("A scope this run changed is no longer in the tenant (ID %s). Nothing was changed." % change["id"])
        if change["kind"] == "rename":
            if live.get("short_name") == change["before"]["short_name"]:
                steps["notes"].append('"%s" already has its old name.' % live.get("short_name"))
            elif live.get("short_name") != change["after"]["short_name"]:
                raise HelperError('Scope "%s" has been renamed again since the run renamed it to "%s". Nothing was changed.'
                                  % (live.get("short_name"), change["after"]["short_name"]))
            else:
                steps["rename"].append((change, live))
        else:
            if live_query(live) == as_query(change["before"]["short_query"]):
                steps["notes"].append('"%s" already has its old query.' % live.get("short_name"))
            elif live_query(live) != as_query(change["after"]["short_query"]):
                raise HelperError('The query of scope "%s" has been changed again since the run changed it. Nothing was changed.'
                                  % live.get("short_name"))
            else:
                steps["requery"].append((change, live))
    return steps


def cmd_undo(client, args, out=print, ask=input):
    scopes = None
    if args.find_created:
        if not args.under:
            raise HelperError('Say which scope to look under with --under "full scope name".')
        if args.record:
            raise HelperError("Use either --record or --find-created, not both.")
        scopes = client.scopes()
        top = find_scope(scopes, args.under)
        record = record_from_marks(client, scopes, top)
        out('Scopes under "%s" whose description starts with "%s": %d' % (top.get("name"), CREATED_MARK, len(record["created"])))
    else:
        if not args.record:
            raise HelperError("Give the record file with --record, or use --find-created with --under if the record is lost.")
        record = load_json(args.record, RECORD_SCHEMA, "record file")
        if record.get("schema_version") not in RECORD_SCHEMA_VERSIONS:
            raise HelperError('The record file "%s" uses record format %s. This helper understands formats %s. '
                              "Get the current csw_scope_helper.py from your Cisco contact and run it again."
                              % (os.path.basename(args.record), record.get("schema_version"),
                                 " and ".join(str(v) for v in RECORD_SCHEMA_VERSIONS)))
        if record.get("tenant_url") != client.base_url:
            raise HelperError("That record is for a different tenant: " + str(record.get("tenant_url")))
        scopes = client.scopes()
    settle_attempts(record, scopes)
    todo, notes = plan_undo(record, scopes)
    steps = plan_full_undo(record, scopes)
    reversing = bool(steps["recreate"] or steps["requery"] or steps["rename"])
    for n in notes + steps["notes"]:
        out("  " + n)
    for entry in steps["recreate"]:
        out("  RECREATE " + str(entry.get("name")) + " (it will get a new ID)")
    for change, live in steps["requery"]:
        out("  RESTORE QUERY of %s: from [%s] back to [%s]" % (live.get("name"), describe_query(change["after"]["short_query"]),
                                                               describe_query(change["before"]["short_query"])))
    for change, live in steps["rename"]:
        out('  RESTORE NAME of %s: from "%s" back to "%s"' % (live.get("name"), change["after"]["short_name"], change["before"]["short_name"]))
    for s in todo:
        out("  REMOVE " + str(s.get("name")))
    if not todo and not reversing:
        out("Nothing to remove." if not (record.get("changes") or record.get("removed")) else "Nothing to reverse.")
        begun = (any(c.get("restore") for c in record.get("changes") or []) or any(r.get("recreate") for r in record.get("removed") or [])
                 or any(c.get("undo") for c in record.get("created") or []))
        if args.write and begun and not args.find_created:
            # An earlier undo did the work but stopped before its commit. Finish that part.
            if args.record:
                save_record(args.record, record)
            commit_if_safe(client, record["parent"], out, args.commit_timeout)
        return 0
    count = "%d %s" % (len(todo), "scope" if len(todo) == 1 else "scopes")
    if not args.write:
        if reversing:
            out("This was a preview. Nothing was changed. Run again with --write to reverse the run.")
        else:
            out("This was a preview. Nothing was changed. Run again with --write to remove " + count + ".")
        return 0
    if reversing:
        question = ("About to recreate %d, restore %d %s and %d %s, and remove %s, as listed above."
                    % (len(steps["recreate"]), len(steps["requery"]), "query" if len(steps["requery"]) == 1 else "queries",
                       len(steps["rename"]), "name" if len(steps["rename"]) == 1 else "names", count))
        always = True
    else:
        question = ("About to remove %s found by their description under \"%s\"." % (count, record["parent"]["name"])
                    if args.find_created else "About to remove %s created by the earlier run." % count)
        always = bool(args.find_created)
    if not confirm(args, question, ask, always_ask=always):
        out("Stopped. Nothing was changed.")
        return 1

    def keep():
        # Undo writes its own progress into the record file, so an interrupted undo can be picked up. No file with --find-created.
        if args.record and not args.find_created:
            save_record(args.record, record)

    again = "Run the same undo command again to continue. It reads the tenant first and does only what is missing."

    def unreachable(doing, name, err):
        return HelperError('The tenant did not confirm %s "%s" (%s), and it could not be reached to see whether it was done. '
                           'The record marks it "attempting". When the connection is back: %s' % (doing, name, why_unsure(err), again))

    keep()
    new_ids = {r["before"]["id"]: r["recreated_id"] for r in record.get("removed") or [] if r.get("recreated_id")}
    for entry in steps["recreate"]:
        before = entry["before"]
        payload = {"short_name": before["short_name"], "short_query": before["short_query"], "description": before.get("description") or "",
                   "parent_app_scope_id": new_ids.get(before["parent_id"], before["parent_id"])}
        entry["recreate"] = "attempting"
        keep()

        def already_there():
            return next((s for s in client.scopes() if s.get("parent_app_scope_id") == payload["parent_app_scope_id"]
                         and s.get("short_name") == before["short_name"]), None)

        how = "recreated"
        try:
            made = client.call("POST", SCOPES_PATH, payload)
        except NetworkError:
            # The outcome is unknown. Look before trying again, so a scope is never recreated twice.
            made, how = already_there(), "found after the connection dropped"
            if made is None:
                how = "recreated on the second try"
                try:
                    made = client.call("POST", SCOPES_PATH, payload)
                except NetworkError:
                    made, how = already_there(), "found after the connection dropped twice"
                    if made is None:
                        raise HelperError('The connection dropped twice while recreating scope "%s", and it is not in the tenant. Stopped. %s'
                                          % (before["short_name"], again))
        if not isinstance(made, dict) or not made.get("id"):
            raise HelperError('The tenant did not confirm scope "%s". Stopped.' % before["short_name"])
        new_ids[before["id"]] = entry["recreated_id"] = made["id"]
        entry["recreate"], entry["recreate_how"] = "done", how
        keep()
        back = client.call("GET", SCOPES_PATH + "/" + made["id"])
        if not (isinstance(back, dict) and back.get("short_name") == before["short_name"] and live_query(back) == as_query(before["short_query"])
                and back.get("parent_app_scope_id") == payload["parent_app_scope_id"]):
            raise HelperError('Scope "%s" was recreated but does not read back as it was. Stopped.' % before["short_name"])
        out("  recreated and verified: %s (new ID %s, the old ID was %s)%s"
            % (entry.get("name"), made["id"], before["id"], "" if how == "recreated" else " (" + how + ")"))
    for kind, key in (("requery", "short_query"), ("rename", "short_name")):
        for change, live in steps[kind]:
            what = "name" if kind == "rename" else "query"

            def is_back(scope):
                return isinstance(scope, dict) and (scope.get("short_name") == change["before"]["short_name"] if kind == "rename"
                                                    else live_query(scope) == as_query(change["before"]["short_query"]))

            change["restore"] = "attempting"
            keep()
            try:
                client.call("PUT", SCOPES_PATH + "/" + live["id"], {key: change["before"][key]})
            except HelperError as err:
                if not unsure(err):
                    change["restore"] = "not done"
                    keep()
                    raise
                try:
                    landed = is_back(client.call("GET", SCOPES_PATH + "/" + live["id"]))
                except HelperError:
                    raise unreachable("restoring the %s of" % what, live.get("name"), err)
                change["restore"] = "done" if landed else "not done"
                if landed:
                    change["restored"] = True
                keep()
                raise HelperError('The tenant did not confirm restoring the %s of "%s" (%s). The tenant was read back: the old %s %s. Stopped. %s'
                                  % (what, live.get("name"), why_unsure(err), what, "IS back" if landed else "is NOT back", again))
            change["restore"], change["restored"] = "done", True
            keep()
            if not is_back(client.call("GET", SCOPES_PATH + "/" + live["id"])):
                raise HelperError('The old %s of "%s" does not read back. Stopped.' % (what, live.get("name")))
            out("  restored and verified: the %s of %s" % (what, live.get("name")))
    made_by_id = {c["id"]: c for c in record.get("created") or []}
    blocked, in_use, removed_now = set(), [], []
    for s in todo:
        mark = made_by_id.get(s["id"], {})
        if s["id"] in blocked:
            mark["undo"] = "not removed"
            keep()
            out("  not removed: %s (a scope under it is in use)" % s.get("name"))
            blocked.add(s.get("parent_app_scope_id"))
            continue
        mark["undo"] = "attempting"
        keep()
        try:
            client.call("DELETE", SCOPES_PATH + "/" + s["id"])
        except HelperError as err:
            if isinstance(err, TenantError) and err.code == 422:
                # Something was attached to the scope after it was created. Say so in plain words and leave it.
                said = in_use_words(err.detail)
                mark["undo"], mark["tenant_said"] = "in use", said
                keep()
                in_use.append((s.get("name"), said))
                out("  IN USE, not removed: %s. The tenant says: %s" % (s.get("name"), said))
                blocked.add(s.get("parent_app_scope_id"))
                continue
            if not unsure(err):
                mark["undo"] = "not done"
                keep()
                raise
            try:
                landed = not any(x["id"] == s["id"] for x in client.scopes())
            except HelperError:
                raise unreachable("removing", s.get("name"), err)
            mark["undo"] = "removed" if landed else "not done"
            keep()
            raise HelperError('The tenant did not confirm removing "%s" (%s). The tenant was read back: the scope %s. Stopped. %s'
                              % (s.get("name"), why_unsure(err), "IS gone" if landed else "is still there", again))
        mark["undo"] = "removed"
        keep()
        removed_now.append(s)
        out("  removed: " + str(s.get("name")))
    commit_if_safe(client, record["parent"], out, args.commit_timeout)
    left = {s["id"] for s in client.scopes()}
    still = [s.get("name") for s in removed_now if s["id"] in left]
    if still:
        out("Still present until the changes are committed: " + ", ".join(str(n) for n in still))
    if in_use:
        out("In use and not removed. Something was attached to these after they were created. Clear what depends on each in Secure "
            "Workload, then run the same undo command again:")
        for name, said in in_use:
            out("  %s: %s" % (name, said))
        return 2
    if reversing:
        out("Reversed. Recreated scopes have new IDs, so anything that pointed at the old IDs must be attached again by hand.")
    elif not still:
        out("Verified: " + count + " removed and gone from the tenant.")
    return 0


# ---------------------------------------------------------------- label check

def compare_labels(file_rows, file_columns, tenant_rows, tenant_columns):
    """Compare our label file with the tenant's labels. Returns a summary dict."""
    ours = [c for c in file_columns if c != "IP"]
    existing = {}
    for row in tenant_rows:
        ip = (row.get("IP") or "").strip()
        if ip:
            existing[ip] = row
            if ip.endswith("/32"):
                existing[ip[:-3]] = row
    new, same, conflicts = 0, 0, []
    for row in file_rows:
        ip = (row.get("IP") or "").strip()
        have = existing.get(ip) or existing.get(ip[:-3] if ip.endswith("/32") else ip + "/32")
        if not have:
            new += 1
            continue
        clash = [(c, have.get(c), row.get(c)) for c in ours
                 if (row.get(c) or "") != "" and (have.get(c) or "") != "" and have.get(c) != row.get(c)]
        if clash:
            conflicts.extend({"ip": ip, "label": c, "tenant_has": h, "file_has": f} for c, h, f in clash)
        elif all((row.get(c) or "") == "" or have.get(c) == row.get(c) for c in ours):
            same += 1
        else:
            new += 1
    known = set(tenant_columns or [])
    added = [c for c in ours if c not in known]
    return {"rows": len(file_rows), "new": new, "same": same, "conflicts": conflicts, "new_columns": added,
            "column_total": len(known | set(ours)), "shared_columns": [c for c in ours if c in known]}


def cmd_check_labels(client, args, out=print):
    if not args.labels:
        raise HelperError("Give the label file with --labels.")
    try:
        with open(args.labels, "r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            file_rows, file_columns = list(reader), list(reader.fieldnames or [])
    except OSError:
        raise HelperError("The label file could not be read: " + args.labels)
    if "IP" not in file_columns:
        raise HelperError("The label file has no IP column.")
    scopes = client.scopes()
    near = find_scope(scopes, args.under) if args.under else None
    tops = [s for s in scopes if not s.get("parent_app_scope_id")]
    root = root_scope_of(scopes, near) if near else (tops[0] if len(tops) == 1 else None)
    if not root:
        raise HelperError('Say which scope you are working under with --under "full scope name".')
    name = urllib.parse.quote(root.get("name") or "", safe="")
    tenant_columns = client.call("GET", "/openapi/v1/assets/cmdb/attributenames/" + name) or []
    text = client.call("GET", "/openapi/v1/assets/cmdb/download/" + name, as_text=True) or ""
    tenant_rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
    result = compare_labels(file_rows, file_columns, tenant_rows, tenant_columns)
    out("Label file rows: %d. New: %d. Already in the tenant with the same values: %d."
        % (result["rows"], result["new"], result["same"]))
    if result["shared_columns"]:
        out("The tenant already uses these label names: " + ", ".join(result["shared_columns"]))
    if result["new_columns"]:
        out("Uploading would add these new label names to the tenant: " + ", ".join(result["new_columns"]))
    if result["column_total"] > MAX_LABEL_COLUMNS:
        out("STOP: the tenant would have %d label names. The limit is %d." % (result["column_total"], MAX_LABEL_COLUMNS))
    if result["conflicts"]:
        out("STOP: %d values in the file differ from what the tenant already has. Uploading would replace them:"
            % len(result["conflicts"]))
        for c in result["conflicts"][:20]:
            out('  %s  %s: tenant has "%s", file has "%s"' % (c["ip"], c["label"], c["tenant_has"], c["file_has"]))
        if len(result["conflicts"]) > 20:
            out("  ... and %d more" % (len(result["conflicts"]) - 20))
        out("Do not upload this file until each difference is resolved.")
        return 2
    if result["column_total"] > MAX_LABEL_COLUMNS:
        return 2
    out("No conflicts. When uploading, choose the Merge operation so blank cells never erase existing labels.")
    return 0


# ---------------------------------------------------------------- entry point

def run(argv=None, opener=None, ask=input, ask_secret=getpass.getpass, out=print, env=None, sleep=time.sleep):
    parser = argparse.ArgumentParser(description="Cisco Secure Workload scope helper. Read-only unless --write is given.")
    parser.add_argument("command", nargs="?", default="export", choices=["export", "check-labels", "apply", "undo"])
    parser.add_argument("--url")
    parser.add_argument("--credentials")
    parser.add_argument("--under")
    parser.add_argument("--out-dir", default=".")
    parser.add_argument("--ca-file")
    parser.add_argument("--plan")
    parser.add_argument("--record")
    parser.add_argument("--labels")
    parser.add_argument("--find-created", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--allow-changes", action="store_true")
    parser.add_argument("--allow-removals", action="store_true")
    parser.add_argument("--no-commit", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--commit-timeout", type=int, default=DEFAULT_COMMIT_TIMEOUT)
    parser.add_argument("--version", action="version", version="csw_scope_helper " + VERSION)
    args = parser.parse_args(argv)
    if not os.path.isdir(args.out_dir):
        raise HelperError("The folder does not exist: " + args.out_dir)
    if (args.allow_changes or args.allow_removals) and args.command != "apply":
        raise HelperError("--allow-changes and --allow-removals are only for the apply command.")
    if args.no_commit and args.command != "apply":
        raise HelperError("--no-commit is only for the apply command.")
    if args.commit_timeout < 1:
        raise HelperError("--commit-timeout must be a whole number of seconds, 1 or more.")

    base_url, key, secret = read_credentials(args, env=env, ask=ask, ask_secret=ask_secret)
    try:
        context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else ssl.create_default_context()
    except (OSError, ssl.SSLError):
        raise HelperError("The certificate file could not be read: %s. It should be the certificate of the authority "
                          "that signed your cluster's certificate, in PEM format." % args.ca_file)
    allow_write = args.write and args.command in ("apply", "undo")
    client = Client(base_url, key, secret, context=context, opener=opener, allow_write=allow_write, sleep=sleep)
    if args.command == "export":
        return cmd_export(client, args, out)
    if args.command == "check-labels":
        return cmd_check_labels(client, args, out)
    if args.command == "apply":
        return cmd_apply(client, args, out, ask)
    return cmd_undo(client, args, out, ask)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except Exception:
            pass
    interactive = len(sys.argv) == 1
    try:
        code = run()
    except HelperError as err:
        print("\nCould not finish: " + str(err))
        code = 1
    except KeyboardInterrupt:
        print("\nStopped.")
        code = 1
    if interactive:
        try:
            input("\nPress Enter to close.")
        except EOFError:
            pass
    return code


if __name__ == "__main__":
    sys.exit(main())
