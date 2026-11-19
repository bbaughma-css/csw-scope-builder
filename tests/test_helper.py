# test_helper.py
"""Helper tests. Everything runs against a simulated tenant. No real tenant is ever touched."""
import argparse, base64, copy, datetime, hashlib, hmac, http.server, importlib.util, io, json, os, re, socket, ssl, sys
import shutil, subprocess, tempfile, threading, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
if len(sys.argv) < 2:
    sys.argv.append(os.path.join(HERE, "..", "csw_scope_helper.py"))

spec = importlib.util.spec_from_file_location("helper", sys.argv[1])
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)
RULES = json.load(open(os.path.join(HERE, "rules.json"), encoding="utf-8"))

def raises(fn, text):
    try:
        fn()
    except H.HelperError as e:
        assert text in str(e), str(e)
        return
    raise AssertionError("expected HelperError containing " + text)

# url handling
assert H.normalize_url(" example.tetrationcloud.com/ ") == "https://example.tetrationcloud.com"
assert H.normalize_url("https://csw.corp.local:8443/some/path") == "https://csw.corp.local:8443"
raises(lambda: H.normalize_url("http://example.com"), "https://")
raises(lambda: H.normalize_url(""), "No tenant address")

# signature matches the scheme used by a working lab client
ts = "2026-11-19T12:00:00+0000"; ck = hashlib.sha256(b"").hexdigest()
msg = "GET\n/openapi/v1/app_scopes\n%s\napplication/json\n%s\n" % (ck, ts)
want = base64.b64encode(hmac.new(b"s3cret", msg.encode(), hashlib.sha256).digest()).decode()
assert H.sign("s3cret", "GET", "/openapi/v1/app_scopes", ck, "application/json", ts) == want
hd = H.build_headers("KEY", "s3cret", "GET", "/openapi/v1/app_scopes", now=datetime.datetime(2026, 11, 19, 12, 0, 0, tzinfo=datetime.timezone.utc))
assert hd["Authorization"] == want and hd["Id"] == "KEY" and hd["Timestamp"] == ts and hd["X-Tetration-Cksum"] == ck

# safety rule 2: only allow-listed paths can be called, and nothing but GET without allow_write
raises(lambda: H.api_get("https://x", "k", "s", "/openapi/v1/users"), "will not call")
raises(lambda: H.api_get("https://x", "k", "s", "/openapi/v1/applications/abc"), "will not call")
raises(lambda: H.api_get("https://x", "k", "s", "/openapi/v1/roles/abc"), "will not call")
ro = H.Client("https://x", "k", "s", opener=lambda r: (_ for _ in ()).throw(AssertionError("must not send")))
raises(lambda: ro.call("POST", "/openapi/v1/app_scopes", {"a": 1}), "read-only")
raises(lambda: ro.call("DELETE", "/openapi/v1/app_scopes/abc"), "read-only")
rw = H.Client("https://x", "k", "s", allow_write=True, opener=lambda r: (_ for _ in ()).throw(AssertionError("must not send")))
raises(lambda: ro.call("PUT", "/openapi/v1/app_scopes/abc", {"short_name": "x"}), "read-only")
for m, pth in (("PUT", "/openapi/v1/app_scopes"), ("PUT", "/openapi/v1/app_scopes/abc/x"), ("PUT", "/openapi/v1/applications/abc"),
               ("PUT", "/openapi/v1/filters/inventories/abc"), ("PUT", "/openapi/v1/roles/abc"), ("POST", "/openapi/v1/roles"),
               ("DELETE", "/openapi/v1/applications/abc"), ("DELETE", "/openapi/v1/filters/inventories/abc"), ("DELETE", "/openapi/v1/roles/abc"),
               ("DELETE", "/openapi/v1/app_scopes"), ("POST", "/openapi/v1/applications"),
               ("DELETE", "/openapi/v1/inventory/tags/x"), ("POST", "/openapi/v1/assets/cmdb/upload/x"), ("POST", "/openapi/v1/assets/cmdb/flush/x"),
               ("POST", "/openapi/v1/app_scopes/commit_dirty?root_app_scope_id=a&sync=true&x=1"), ("GET", "/openapi/v1/users"),
               ("PATCH", "/openapi/v1/app_scopes/abc"), ("POST", "/openapi/v1/app_scopes/abc")):
    raises(lambda m=m, pth=pth: rw.call(m, pth, {}), "will not")
src = open(sys.argv[1], encoding="utf-8").read()
assert "cmdb/upload" not in src and "flush" not in src, "no label upload"
assert src.count('"PUT"') == 1 + src.count('client.call("PUT", SCOPES_PATH + "/"'), "PUT is used only on one scope at a time"
assert len(H.READ_RULES) == 7 and len(H.WRITE_RULES) == 4, "a new call needs a deliberate allow-list change"
assert [m for m, _ in H.WRITE_RULES].count("PUT") == 1

# safety rule 7: no way to skip certificate checking, and nothing that saves a secret
for banned in ("CERT_NONE", "check_hostname = False", "_create_unverified_context", "--insecure", "verify=False"):
    assert banned not in src, banned

# reads: one answer, errors in plain words
class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False
seen = {}
def ok(req):
    seen["url"] = req.full_url; seen["method"] = req.get_method(); seen["headers"] = dict(req.header_items())
    return Resp(json.dumps([{"id": "1", "short_name": "Root"}]).encode())
# the secret here holds characters a signature can never contain, so a chance match cannot fail this check
assert H.api_get("https://t", "KEY", "s!cret#value", H.SCOPES_PATH, opener=ok) == [{"id": "1", "short_name": "Root"}]
assert seen["url"] == "https://t/openapi/v1/app_scopes" and seen["method"] == "GET"
assert "s!cret#value" not in json.dumps(seen["headers"]) and "cret#" not in json.dumps(seen["headers"]), "secret must never be sent"
def err(code):
    def f(req): raise urllib.error.HTTPError(req.full_url, code, "x", {}, io.BytesIO(b""))
    return f
def get(opener, waits=None):
    waits = [] if waits is None else waits
    return H.Client("https://t", "k", "s", opener=opener, sleep=waits.append).call("GET", H.SCOPES_PATH)
raises(lambda: get(err(401)), "401")
raises(lambda: get(err(401)), "same pair")
raises(lambda: get(err(403)), "user_role_scope_management")
raises(lambda: get(err(500)), "error 500")
raises(lambda: get(lambda r: Resp(b"<html>")), "could not be read")
def down(req): raise urllib.error.URLError("no route")
raises(lambda: get(down), "Could not reach")

# D13 retries: reads are retried 3 times with waits of 2, 5, and 10 seconds
def flaky(failures, kind):
    state = {"n": 0}
    def f(req):
        state["n"] += 1
        if state["n"] <= failures:
            if kind == "5xx": raise urllib.error.HTTPError(req.full_url, 503, "x", {}, io.BytesIO(b""))
            if kind == "timeout": raise socket.timeout("timed out")
            if kind == "reset": raise ConnectionResetError("reset")
            raise urllib.error.URLError("down")
        return Resp(b'[{"id": "1"}]')
    f.state = state
    return f
for kind in ("5xx", "timeout", "reset", "url"):
    w = []; f = flaky(3, kind)
    assert get(f, w) == [{"id": "1"}] and w == [2, 5, 10] and f.state["n"] == 4, (kind, w)
    w = []; f = flaky(4, kind)
    raises(lambda: get(f, w), "error 503" if kind == "5xx" else "Could not reach")
    assert w == [2, 5, 10] and f.state["n"] == 4
for code in (400, 401, 403, 404, 422, 429):
    w = []; n = {"n": 0}
    def once(req, code=code):
        n["n"] += 1
        raise urllib.error.HTTPError(req.full_url, code, "x", {}, io.BytesIO(b""))
    raises(lambda: get(once, w), str(code))
    assert w == [] and n["n"] == 1, "a 4xx answer is never retried"
# a certificate problem is never retried
w = []; n = {"n": 0}
def badcert(req):
    n["n"] += 1
    raise urllib.error.URLError(ssl.SSLCertVerificationError("self signed"))
raises(lambda: get(badcert, w), "--ca-file")
assert w == [] and n["n"] == 1
# writes are never retried by the client
n = {"n": 0}
def droppost(req):
    n["n"] += 1
    raise urllib.error.URLError("dropped")
wc = H.Client("https://t", "k", "s", opener=droppost, allow_write=True, sleep=lambda s: (_ for _ in ()).throw(AssertionError("no sleep on a write")))
try:
    wc.call("POST", H.SCOPES_PATH, {"a": 1}); raise AssertionError("should raise")
except H.NetworkError:
    pass
assert n["n"] == 1

# shared rule tables (the planner test reads the same file)
for c in RULES["equivalence"]:
    assert H.same_query(c["a"], c["b"]) == (c["same"], c["exact"]) and H.same_query(c["b"], c["a"]) == (c["same"], c["exact"]), c
for c in RULES["describe"]:
    assert H.describe_query(c["q"]) == c["text"], (c, H.describe_query(c["q"]))
assert H.plan_fingerprint(RULES["fingerprint_v3"]["scopes"]) == RULES["fingerprint_v3"]["sha256"]
for c in RULES["comparison"]:
    assert list(H.same_query(c["a"], c["b"])) == [c["same"], c["exact"]], c
    assert list(H.same_query(c["b"], c["a"])) == [c["same"], c["exact"]], c
for c in RULES["names"]:
    assert list(H.same_name(c["a"], c["b"])) == [c["same"], c["exact"]], c
for c in RULES["file_names"]:
    assert H.safe_name(c["in"]) == c["out"], c
assert H.plan_fingerprint(RULES["fingerprint"]["scopes"]) == RULES["fingerprint"]["sha256"]
assert H.plan_fingerprint(list(reversed(RULES["fingerprint"]["scopes"]))) == RULES["fingerprint"]["sha256"], "order comes from the order field"
changed = copy.deepcopy(RULES["fingerprint"]["scopes"]); changed[0]["short_query"]["value"] = "X"
assert H.plan_fingerprint(changed) != RULES["fingerprint"]["sha256"]

# scope selection
S = [
    {"id": "r", "short_name": "Tenant", "name": "Tenant", "parent_app_scope_id": None, "short_query": {"type": "subnet"}, "extra": "dropped"},
    {"id": "a", "short_name": "Internal", "name": "Tenant:Internal", "parent_app_scope_id": "r"},
    {"id": "b", "short_name": "Lab", "name": "Tenant:Internal:Lab", "parent_app_scope_id": "a"},
    {"id": "c", "short_name": "Prod", "name": "Tenant:Internal:Lab:Prod", "parent_app_scope_id": "b"},
    {"id": "d", "short_name": "Other", "name": "Tenant:Other", "parent_app_scope_id": "r"},
    {"id": "e", "short_name": "Prod", "name": "Tenant:Other:Prod", "parent_app_scope_id": "d"},
]
picked, top, partial = H.select_scopes(S, None)
assert len(picked) == 6 and top["id"] == "r" and partial is False
picked, top, partial = H.select_scopes(S, "Tenant:Internal:Lab")
assert [s["id"] for s in picked] == ["b", "c"] and top["id"] == "b" and partial is True
picked, top, partial = H.select_scopes(S, "lab")
assert [s["id"] for s in picked] == ["b", "c"]
raises(lambda: H.select_scopes(S, "Prod"), "More than one")
raises(lambda: H.select_scopes(S, "Nope"), "No scope named")
raises(lambda: H.select_scopes({"error": "x"}, None), "not a scope list")

doc, name = H.build_export("https://t", S, "Tenant:Internal:Lab")
assert doc["schema"] == "csw-scope-export" and doc["partial"] is True and doc["scope_count"] == 2 and doc["under"] == "Tenant:Internal:Lab"
assert doc["schema_version"] == 2 and doc["tool_version"] == H.VERSION and "helper_version" not in doc
assert name == "%s Lab - CSW Existing Scopes.json" % datetime.date.today().isoformat(), name
doc, name = H.build_export("https://t", S, None)
assert doc["partial"] is False and doc["under"] is None and "extra" not in doc["scopes"][0] and doc["scopes"][0]["short_query"] == {"type": "subnet"}
assert name.endswith(" Tenant - CSW Existing Scopes.json")
assert H.safe_name('a/b:c*?"<>|') == "abc"

# D18: child scopes are counted per top-level scope, with no subtract-one shortcut
TWO = S + [{"id": "r2", "short_name": "Second", "name": "Second", "parent_app_scope_id": None},
           {"id": "f", "short_name": "X", "name": "Second:X", "parent_app_scope_id": "r2"}]
assert H.child_scope_count(TWO, "r") == 5 and H.child_scope_count(TWO, "r2") == 1
assert H.build_export("https://t", TWO, "Tenant:Internal:Lab")[0]["tenant_child_scope_count"] == 5
assert H.build_export("https://t", TWO, "Second:X")[0]["tenant_child_scope_count"] == 1
assert H.build_export("https://t", TWO, None)[0]["tenant_child_scope_count"] == 6
assert H.build_export("https://t", TWO, None)[0]["tenant_scope_count"] == 8

# credentials: env, file, prompts
A = lambda **k: argparse.Namespace(url=k.get("url"), credentials=k.get("credentials"))
assert H.read_credentials(A(), env={"CSW_URL": "t.example.com", "CSW_API_KEY": " K ", "CSW_API_SECRET": " S "}) == ("https://t.example.com", "K", "S")
answers = iter(["t2.example.com", "K2"])
assert H.read_credentials(A(), env={}, ask=lambda p: next(answers), ask_secret=lambda p: "S2") == ("https://t2.example.com", "K2", "S2")
raises(lambda: H.read_credentials(A(url="t"), env={}, ask=lambda p: "", ask_secret=lambda p: ""), "Both the API key")
raises(lambda: H.read_credentials(A(), env={"CSW_URL": "t", "CSW_API_KEY": "eyJhbGciOi" + "x" * 900, "CSW_API_SECRET": "a" * 40}), "Security Cloud Control token")
raises(lambda: H.read_credentials(A(), env={"CSW_URL": "t", "CSW_API_KEY": "a" * 32, "CSW_API_SECRET": "abc.def.ghi"}), "API secret looks like")
assert H.read_credentials(A(), env={"CSW_URL": "t", "CSW_API_KEY": "a" * 32, "CSW_API_SECRET": "b" * 40})[1:] == ("a" * 32, "b" * 40)
prompts = []
H.read_credentials(A(url="t"), env={}, ask=lambda p: prompts.append(p) or "K", ask_secret=lambda p: prompts.append(p) or "S")
assert "32 characters" in prompts[0] and "40 characters" in prompts[1]
# a web address or token typed at the key prompt is caught and asked again
seq = iter(["https://t.example.com/", "eyJhbGciOi.abc", "a" * 32])
_stdout = sys.stdout; sys.stdout = io.StringIO()
try:
    assert H.read_credentials(A(url="t"), env={}, ask=lambda p: next(seq), ask_secret=lambda p: "b" * 40)[1] == "a" * 32
    raises(lambda: H.read_credentials(A(url="t"), env={}, ask=lambda p: "https://x/", ask_secret=lambda p: "b" * 40), "web address")
finally:
    sys.stdout = _stdout
raises(lambda: H.read_credentials(A(url="t", credentials="/nonexistent.json"), env={}), "credentials file")
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    json.dump({"api_key": "FK", "api_secret": "FS"}, f)
assert H.read_credentials(A(url="t", credentials=f.name), env={}) == ("https://t", "FK", "FS")
# a credentials file saved by a Windows editor (byte order mark, CRLF line endings) still loads
with open(f.name, "wb") as fb:
    fb.write(b"\xef\xbb\xbf{\r\n  \"api_key\": \"WK\",\r\n  \"api_secret\": \"WS\"\r\n}\r\n")
assert H.read_credentials(A(url="t", credentials=f.name), env={}) == ("https://t", "WK", "WS")
os.unlink(f.name)

assert open(sys.argv[1], encoding="utf-8").readline().strip() == "# csw_scope_helper.py"
assert not any(ch in src for ch in "—–‘’“”…")

# ---------------- simulated tenant ----------------
class Tenant:
    def __init__(self, scopes):
        self.scopes = copy.deepcopy(scopes); self.log = []; self.n = 0; self.fail_on = None; self.corrupt = None
        self.drop_after_create = set(); self.drop_before_create = {}; self.commit_hangs = False; self.clean_after_polls = None
        self.polls = 0; self.get_failures = 0
        self.workspaces = []; self.filters = []; self.roles = []; self.deny = set(); self.in_use = {}
        self.corrupt_put = None; self.fail_put_after = None; self.puts = 0
        self.drops = {}      # (method, scope id) -> "before" (the call never arrives) or "after" (the tenant applies it, the answer is lost)
        self.blind = 0       # how many of the next reads fail with a dropped connection
        self.columns = ["Application", "Location", "Owner"]
        self.labels = "IP,VRF,Application,Location,Owner\r\n10.99.60.71,T,shopapp,east,bob\r\n10.9.0.0/24,T,test,,\r\n"
    def __call__(self, req):
        m, path = req.get_method(), req.full_url.replace("https://t", "")
        self.log.append((m, path))
        body = json.loads(req.data.decode()) if req.data else None
        if m == "GET" and self.blind > 0:
            self.blind -= 1
            raise socket.timeout("timed out")
        if m == "GET" and self.get_failures > 0:
            self.get_failures -= 1
            raise urllib.error.HTTPError(req.full_url, 502, "x", {}, io.BytesIO(b""))
        if m == "GET" and path == "/openapi/v1/app_scopes":
            if self.clean_after_polls is not None:
                self.polls += 1
                if self.polls > self.clean_after_polls:
                    for x in self.scopes: x["dirty"] = False
            return Resp(json.dumps(self.scopes).encode())
        for kind, where, rows in (("workspaces", "/openapi/v1/applications", self.workspaces),
                                  ("inventory_filters", "/openapi/v1/filters/inventories", self.filters), ("roles", "/openapi/v1/roles", self.roles)):
            if m == "GET" and path == where:
                if kind in self.deny: raise urllib.error.HTTPError(req.full_url, 403, "x", {}, io.BytesIO(b'{"error":"forbidden"}'))
                return Resp(json.dumps(rows).encode())
        g = re.match(r"^/openapi/v1/app_scopes/([A-Za-z0-9]+)$", path)
        drop = self.drops.pop((m, g.group(1)), None) if g else None
        if drop == "before": raise socket.timeout("timed out")
        if m == "PUT" and g:
            assert set(body) <= {"short_name", "description", "short_query"} and body, "the update call takes only these three fields"
            self.puts += 1
            if self.fail_put_after is not None and self.puts > self.fail_put_after:
                raise urllib.error.HTTPError(req.full_url, 500, "x", {}, io.BytesIO(b'{"error":"boom"}'))
            sc = [x for x in self.scopes if x["id"] == g.group(1)][0]
            if "short_name" in body:
                sc["short_name"] = body["short_name"] if self.corrupt_put != "name" else body["short_name"] + "x"
                self.rename_tree(sc)
            if "short_query" in body:
                # a changed query is held separately until the changes are committed
                sc["dirty_short_query"] = body["short_query"] if self.corrupt_put != "query" else {"type": "eq", "field": "ip", "value": "9.9.9.9"}
                sc["dirty"] = True
                [x for x in self.scopes if x["id"] == "r"][0]["dirty"] = True
            if drop == "after": raise ConnectionResetError("connection reset after the scope was changed")
            return Resp(json.dumps(sc).encode())
        if m == "GET" and g:
            hit = [x for x in self.scopes if x["id"] == g.group(1)]
            return Resp(json.dumps(hit[0]).encode())
        if m == "POST" and path == "/openapi/v1/app_scopes":
            name = body["short_name"]
            if self.fail_on == name: raise urllib.error.HTTPError(req.full_url, 422, "x", {}, io.BytesIO(b'{"error":"bad"}'))
            if self.drop_before_create.get(name, 0) > 0:
                self.drop_before_create[name] -= 1
                raise socket.timeout("timed out")
            self.n += 1
            par = [x for x in self.scopes if x["id"] == body["parent_app_scope_id"]][0]
            new = {"id": "n%d" % self.n, "short_name": name, "name": par["name"] + ":" + name, "description": body["description"],
                   "parent_app_scope_id": par["id"], "root_app_scope_id": "r", "short_query": body["short_query"], "dirty": False}
            if self.corrupt == name: new["short_query"] = {"type": "eq", "field": "ip", "value": "1.1.1.1"}
            self.scopes.append(new); par["dirty"] = True
            if name in self.drop_after_create:
                self.drop_after_create.discard(name)
                raise ConnectionResetError("connection reset after the scope was made")
            return Resp(json.dumps(new).encode())
        if m == "DELETE" and g:
            if g.group(1) in self.in_use:
                raise urllib.error.HTTPError(req.full_url, 422, "x", {}, io.BytesIO(json.dumps(
                    {"error": "This scope has dependent objects", "details": self.in_use[g.group(1)]}).encode()))
            vic = [x for x in self.scopes if x["id"] == g.group(1)][0]
            assert not [x for x in self.scopes if x.get("parent_app_scope_id") == vic["id"]], "the tenant refuses to delete a scope with children"
            self.scopes.remove(vic)
            [x for x in self.scopes if x["id"] == vic["parent_app_scope_id"]][0]["dirty"] = True
            if drop == "after": raise ConnectionResetError("connection reset after the scope was removed")
            return Resp(b"")
        if m == "POST" and path.startswith("/openapi/v1/app_scopes/commit_dirty?"):
            if self.commit_hangs: raise socket.timeout("timed out")
            for x in self.scopes:
                x["dirty"] = False
                if x.get("dirty_short_query"): x["short_query"] = x["dirty_short_query"]; x["dirty_short_query"] = None
            return Resp(b"{}")
        if m == "GET" and path.startswith("/openapi/v1/assets/cmdb/attributenames/"): return Resp(json.dumps(self.columns).encode())
        if m == "GET" and path.startswith("/openapi/v1/assets/cmdb/download/"): return Resp(self.labels.encode())
        raise AssertionError("unexpected call " + m + " " + path)
    def rename_tree(self, sc):
        par = [x for x in self.scopes if x["id"] == sc.get("parent_app_scope_id")]
        sc["name"] = (par[0]["name"] + ":" if par else "") + sc["short_name"]
        for kid in [x for x in self.scopes if x.get("parent_app_scope_id") == sc["id"]]: self.rename_tree(kid)
    def writes(self): return [c for c in self.log if c[0] != "GET"]
    def shape(self):
        ids = {x["id"]: x for x in self.scopes}
        return sorted((x["name"], json.dumps(x["short_query"], sort_keys=True), ids[x["parent_app_scope_id"]]["name"] if x["parent_app_scope_id"] else "",
                       x.get("description") or "") for x in self.scopes)
    def names(self): return sorted(x["name"] for x in self.scopes)

BASE = [
    {"id": "r", "short_name": "Tenant", "name": "Tenant", "parent_app_scope_id": None, "root_app_scope_id": "r", "short_query": {"type": "subnet", "field": "ip", "value": "0.0.0.0/0"}, "dirty": False},
    {"id": "me", "short_name": "bob", "name": "Tenant:bob", "parent_app_scope_id": "r", "root_app_scope_id": "r", "short_query": {"type": "eq", "field": "user_Owner", "value": "bob"}, "dirty": False},
    {"id": "h", "short_name": "Home", "name": "Tenant:bob:Home", "parent_app_scope_id": "me", "root_app_scope_id": "r", "short_query": {"type": "subnet", "field": "ip", "value": "10.99.1.0/24"}, "dirty": False},
    {"id": "o", "short_name": "other", "name": "Tenant:other", "parent_app_scope_id": "r", "root_app_scope_id": "r", "short_query": {"type": "eq", "field": "user_Owner", "value": "x"}, "dirty": False},
]
def q(label, value): return {"type": "eq", "field": "user_" + label, "value": value}
PLAN = {"schema": "csw-scope-plan", "schema_version": 1, "ready": True, "customer": {"name": "acme"}, "root": {"short_name": "bob", "existing_id": "me"},
        "source": {"existing_tree_loaded": True}, "scopes": [
    {"order": 1, "ref": "s1", "parent_ref": "root", "short_name": "Production", "depth": 1, "short_query": q("Environment", "Production"), "status": "create"},
    {"order": 2, "ref": "s2", "parent_ref": "root", "short_name": "Shared", "depth": 1, "short_query": q("Environment", "Shared"), "status": "create"},
    {"order": 3, "ref": "s3", "parent_ref": "s1", "short_name": "payroll", "depth": 2, "short_query": q("Application", "payroll"), "status": "create"},
    {"order": 4, "ref": "s4", "parent_ref": "s2", "short_name": "DNS", "depth": 2, "short_query": q("Application", "DNS"), "status": "create"}]}
ENV = {"CSW_URL": "https://t", "CSW_API_KEY": "K", "CSW_API_SECRET": "S"}
def folder(plan=PLAN, name="plan.json"):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh: json.dump(plan, fh)
    return d, os.path.join(d, name)
def go(t, argv, answers=(), d=None, waits=None):
    lines, it = [], iter(answers)
    waits = [] if waits is None else waits
    code = H.run(argv + ["--out-dir", d or tempfile.mkdtemp()], opener=t, ask=lambda p: lines.append("PROMPT " + p) or next(it),
                 ask_secret=lambda p: "S", out=lines.append, env=ENV, sleep=waits.append)
    return code, "\n".join(lines)
def records(d): return sorted(os.path.join(d, f) for f in os.listdir(d) if "CSW Apply Record" in f)
def load(path):
    with open(path, encoding="utf-8") as fh: return json.load(fh)

# safety rule 1: preview makes no changes
d, plan_path = folder()
t = Tenant(BASE); code, text = go(t, ["apply", "--plan", plan_path], d=d)
assert code == 0 and t.writes() == [] and "4 to create" in text and "This was a preview" in text and 'under "Tenant:bob"' in text, text
assert "no label named Environment yet" in text and "Application" not in text.split("Note:")[1], text
assert records(d) == [], "a preview saves no record"
# --write but the person does not type yes
for word in ("yes", "Yes", " YES "):
    tw = Tenant(BASE); code, text = go(tw, ["apply", "--plan", plan_path, "--write"], [word])
    assert code == 0 and len(tw.writes()) == 5, (word, text)
for word in ("y", "", "yess", "ok", "no"):
    tw = Tenant(BASE); code, text = go(tw, ["apply", "--plan", plan_path, "--write"], [word])
    assert code == 1 and tw.writes() == [] and "Nothing was changed" in text, word
# --write with yes: creates in order, verifies, commits, writes a record
t = Tenant(BASE); code, text = go(t, ["apply", "--plan", plan_path, "--write"], ["YES"], d=d)
assert code == 0, text
assert t.writes() == [("POST", "/openapi/v1/app_scopes")] * 4 + [("POST", "/openapi/v1/app_scopes/commit_dirty?root_app_scope_id=r&sync=true")], t.writes()
made = {x["short_name"]: x for x in t.scopes if x["id"].startswith("n")}
assert made["payroll"]["parent_app_scope_id"] == made["Production"]["id"] and made["Production"]["parent_app_scope_id"] == "me"
assert made["DNS"]["short_query"] == q("Application", "DNS") and made["DNS"]["description"].startswith("Created by CSW Scope Builder")
assert text.count("created and verified") == 4 and "Scope changes committed." in text
rec_path = records(d)[0]
rec = load(rec_path)
assert rec["finished"] is True and rec["committed"] is True and len(rec["created"]) == 4 and rec["parent"]["id"] == "me"
assert rec["schema_version"] == 3 and rec["changes"] == [] and rec["removed"] == [] and rec["tool_version"] == H.VERSION and rec["plan_fingerprint"] == H.plan_fingerprint(PLAN["scopes"])
# safety rule 7: the record never holds the key or the secret
raw = open(rec_path, encoding="utf-8").read()
assert '"K"' not in raw and '"S"' not in raw and "api_key" not in raw.lower() and "secret" not in raw.lower() and "Authorization" not in raw
# running the same plan again creates nothing
t.log = []; code, text = go(t, ["apply", "--plan", plan_path, "--write", "--yes"], d=d)
assert code == 0 and t.writes() == [] and "4 already there" in text and "Nothing to create" in text
assert len(records(d)) == 1
# safety rule 3: an existing scope with a different query is left alone, children still go under it
t2 = Tenant(BASE + [{"id": "p", "short_name": "production", "name": "Tenant:bob:production", "parent_app_scope_id": "me", "root_app_scope_id": "r", "short_query": {"type": "subnet", "field": "ip", "value": "10.0.0.0/8"}, "dirty": False}])
code, text = go(t2, ["apply", "--plan", plan_path, "--write", "--yes"])
assert code == 0 and "1 left as they are" in text and len([c for c in t2.writes() if c[1] == "/openapi/v1/app_scopes"]) == 3
assert [x for x in t2.scopes if x["short_name"] == "payroll"][0]["parent_app_scope_id"] == "p"
assert [x for x in t2.scopes if x["id"] == "p"][0]["short_query"]["value"] == "10.0.0.0/8"
assert 'named "production" in the tenant' in text
# D3: a query that differs only in capital letters is the same scope in the helper, as it is in the planner
t2b = Tenant(BASE + [{"id": "p", "short_name": "production", "name": "Tenant:bob:production", "parent_app_scope_id": "me", "root_app_scope_id": "r", "short_query": q("environment", "PRODUCTION"), "dirty": False}])
code, text = go(t2b, ["apply", "--plan", plan_path])
assert "3 to create, 1 already there, 0 left as they are" in text and 'its query is written "PRODUCTION" in the tenant' in text, text
# safety rule 6: other people's uncommitted changes mean no commit
t3 = Tenant(BASE); t3.scopes[3]["dirty"] = True
code, text = go(t3, ["apply", "--plan", plan_path, "--write", "--yes"])
assert code == 0 and "NOT committed" in text and "Tenant:other" in text and not any("commit_dirty" in c[1] for c in t3.writes())
# safety rule 5: a failure midway stops and leaves a record of what was made
d4, p4 = folder()
t4 = Tenant(BASE); t4.fail_on = "payroll"
try:
    go(t4, ["apply", "--plan", p4, "--write", "--yes"], d=d4); raise AssertionError("should stop")
except H.HelperError as e:
    assert "422" in str(e)
r4 = load(records(d4)[0])
assert [c["short_name"] for c in r4["created"]] == ["Production", "Shared"] and r4["finished"] is False
# D15: running again continues the same record, and one undo reverses the whole build
t4.fail_on = None; t4.log = []
code, text = go(t4, ["apply", "--plan", p4, "--write"], ["yes"], d=d4)
assert code == 0 and "continues the unfinished build" in text and "(2 created so far)" in text, text
assert text.index("continues the unfinished build") < text.index("PROMPT"), "it says so before asking"
assert len(records(d4)) == 1, "still one record"
r4 = load(records(d4)[0])
assert [c["short_name"] for c in r4["created"]] == ["Production", "Shared", "payroll", "DNS"] and r4["finished"] is True and len(r4["resumed_at"]) == 1
assert "Created 2 scopes" in text
code, text = go(t4, ["undo", "--record", records(d4)[0], "--write", "--yes"], d=d4)
assert code == 0 and "4 scopes removed and gone" in text and t4.names() == sorted(x["name"] for x in BASE)
# a finished record is never continued, and a different plan or parent starts its own record
d5, p5 = folder()
t5 = Tenant(BASE); go(t5, ["apply", "--plan", p5, "--write", "--yes"], d=d5)
other = copy.deepcopy(PLAN); other["scopes"].append({"order": 5, "ref": "s5", "parent_ref": "s1", "short_name": "hr", "depth": 2, "short_query": q("Application", "hr"), "status": "create"})
with open(os.path.join(d5, "plan2.json"), "w") as fh: json.dump(other, fh)
code, text = go(t5, ["apply", "--plan", os.path.join(d5, "plan2.json"), "--write", "--yes"], d=d5)
assert "continues" not in text and len(records(d5)) == 2 and "Created 1 scope." in text
# a run that crashed after the last create is completed, not repeated
d6, p6 = folder()
t6 = Tenant(BASE); go(t6, ["apply", "--plan", p6, "--write", "--yes"], d=d6)
r6 = load(records(d6)[0]); r6["finished"] = False; r6["committed"] = None
with open(records(d6)[0], "w") as fh: json.dump(r6, fh)
t6.log = []; code, text = go(t6, ["apply", "--plan", p6, "--write", "--yes"], d=d6)
assert code == 0 and "completes the record" in text and not any(c[0] == "POST" and c[1] == "/openapi/v1/app_scopes" for c in t6.writes())
assert load(records(d6)[0])["finished"] is True and len(records(d6)) == 1
# safety rule 4: a read-back mismatch stops at the first scope
t5 = Tenant(BASE); t5.corrupt = "Production"
raises(lambda: go(t5, ["apply", "--plan", plan_path, "--write", "--yes"]), "does not read back")
assert len(t5.writes()) == 1

# creates are never blindly retried
# (a) the connection drops after the tenant made the scope: it is found, verified, and not created twice
t = Tenant(BASE); t.drop_after_create = {"Production"}
code, text = go(t, ["apply", "--plan", plan_path, "--write", "--yes"], d=(da := tempfile.mkdtemp()))
assert code == 0 and "created and verified: Production (found after the connection dropped)" in text, text
assert len([x for x in t.scopes if x["short_name"] == "Production"]) == 1
assert len([c for c in t.writes() if c[1] == "/openapi/v1/app_scopes"]) == 4
assert load(records(da)[0])["created"][0]["how"] == "found after the connection dropped"
# (b) the connection drops before the tenant made it: one more try, and only one
t = Tenant(BASE); t.drop_before_create = {"Production": 1}
code, text = go(t, ["apply", "--plan", plan_path, "--write", "--yes"], d=(db := tempfile.mkdtemp()))
assert code == 0 and "created and verified: Production (created on the second try)" in text
assert len([c for c in t.writes() if c[1] == "/openapi/v1/app_scopes"]) == 5 and len([x for x in t.scopes if x["short_name"] == "Production"]) == 1
assert load(records(db)[0])["created"][0]["how"] == "created on the second try"
# (c) it drops twice: stop, with a record, and nothing created twice
t = Tenant(BASE); t.drop_before_create = {"Shared": 2}
dc = tempfile.mkdtemp()
raises(lambda: go(t, ["apply", "--plan", plan_path, "--write", "--yes"], d=dc), "dropped twice")
assert [c["short_name"] for c in load(records(dc)[0])["created"]] == ["Production"] and load(records(dc)[0])["finished"] is False
assert len([c for c in t.writes() if c[1] == "/openapi/v1/app_scopes"]) == 3
# a read that fails in the middle of a build is retried, and the build goes on
t = Tenant(BASE); waits = []
class GetFails:
    def __init__(self, tenant): self.t = tenant; self.armed = False
    def __call__(self, req):
        if req.get_method() == "POST" and not self.armed:
            self.armed = True; self.t.get_failures = 2
        return self.t(req)
code, text = go(GetFails(t), ["apply", "--plan", plan_path, "--write", "--yes"], waits=waits)
assert code == 0 and waits == [2, 5] and text.count("created and verified") == 4

# D14: a commit that times out is polled, not reported as a failure
t = Tenant(BASE); t.commit_hangs = True; t.clean_after_polls = 4; waits = []
code, text = go(t, ["apply", "--plan", plan_path, "--write", "--yes"], waits=waits)
assert code == 0 and "did not answer within 300 seconds" in text and "Scope changes committed." in text and "Still committing" not in text, text
assert waits and set(waits) == {15}
t = Tenant(BASE); t.commit_hangs = True; waits = []
dh = tempfile.mkdtemp()
code, text = go(t, ["apply", "--plan", plan_path, "--write", "--yes", "--commit-timeout", "45"], waits=waits, d=dh)
assert code == 0 and "did not answer within 45 seconds" in text and "Still committing. Check in Secure Workload" in text and waits == [15, 15, 15]
assert load(records(dh)[0])["committed"] == "still committing" and load(records(dh)[0])["finished"] is True
assert len([c for c in t.writes() if "commit_dirty" in c[1]]) == 1, "the commit is sent once"
raises(lambda: go(Tenant(BASE), ["apply", "--plan", plan_path, "--commit-timeout", "0"]), "--commit-timeout")

# D17: the helper checks the plan file's format number
for version in (4, 99, None, "2"):
    newer = dict(PLAN, schema_version=version); dn, pn = folder(newer, "newer.json")
    tn = Tenant(BASE)
    raises(lambda: go(tn, ["apply", "--plan", pn, "--write", "--yes"], d=dn), 'The plan file "newer.json" uses plan format')
    assert tn.log == [], "refused before any call"
v2 = dict(PLAN, schema_version=2, tool_version="1.1", anchors=[], fingerprint=H.plan_fingerprint(PLAN["scopes"])); d2, p2 = folder(v2)
t = Tenant(BASE); code, text = go(t, ["apply", "--plan", p2, "--write", "--yes"], d=d2)
assert code == 0 and text.count("created and verified") == 4
# section 6 rule 5: a version 1 plan builds with this helper exactly as before
t1 = Tenant(BASE); go(t1, ["apply", "--plan", plan_path, "--write", "--yes"])
assert [(x["name"], x["short_query"]) for x in t1.scopes] == [(x["name"], x["short_query"]) for x in t.scopes]
# safety rule 9: a plan with blockers is refused, and so are the wrong files
bad = dict(PLAN, ready=False); dbad, bp = folder(bad, "bad.json")
tb = Tenant(BASE); raises(lambda: go(tb, ["apply", "--plan", bp, "--write", "--yes"]), "blockers")
assert tb.log == []
raises(lambda: go(Tenant(BASE), ["apply", "--plan", rec_path]), "not a plan file")
nop = dict(PLAN, root={"short_name": "x", "existing_id": None}); dnop, npth = folder(nop, "nop.json")
raises(lambda: go(Tenant(BASE), ["apply", "--plan", npth]), "--under")
t6 = Tenant(BASE); code, text = go(t6, ["apply", "--plan", npth, "--under", "Tenant:other"])
assert 'under "Tenant:other"' in text and t6.writes() == []
t7 = Tenant(BASE[:1]); code, text = go(t7, ["apply", "--plan", npth])
assert 'under "Tenant"' in text
# a plan file saved by a Windows editor (byte order mark, CRLF) still loads
with open(os.path.join(dnop, "win.json"), "wb") as fb:
    fb.write(b"\xef\xbb\xbf" + json.dumps(PLAN, indent=2).replace("\n", "\r\n").encode("utf-8"))
code, text = go(Tenant(BASE), ["apply", "--plan", os.path.join(dnop, "win.json")])
assert code == 0 and "4 to create" in text
# scope limit, counted per top-level scope
big = Tenant(BASE + [{"id": "z%d" % i, "short_name": "z%d" % i, "name": "Tenant:other:z%d" % i, "parent_app_scope_id": "o", "root_app_scope_id": "r", "short_query": {}, "dirty": False} for i in range(995)])
raises(lambda: go(big, ["apply", "--plan", plan_path]), "over the limit of 1000")
elsewhere = Tenant(BASE + [{"id": "r2", "short_name": "Second", "name": "Second", "parent_app_scope_id": None, "root_app_scope_id": "r2", "short_query": {}, "dirty": False}]
                   + [{"id": "z%d" % i, "short_name": "z%d" % i, "name": "Second:z%d" % i, "parent_app_scope_id": "r2", "root_app_scope_id": "r2", "short_query": {}, "dirty": False} for i in range(995)])
code, text = go(elsewhere, ["apply", "--plan", plan_path])
assert code == 0 and "4 to create" in text, "scopes under another top-level scope do not count"

# undo: preview, then remove deepest first, refuses strangers
du, pu = folder()
t = Tenant(BASE); go(t, ["apply", "--plan", pu, "--write", "--yes"], d=du)
made = {x["short_name"]: x for x in t.scopes if x["id"].startswith("n")}
rec_u = records(du)[0]
t.log = []; code, text = go(t, ["undo", "--record", rec_u], d=du)
assert code == 0 and t.writes() == [] and text.count("REMOVE") == 4 and "preview" in text
t.scopes.append({"id": "st", "short_name": "stranger", "name": "x", "parent_app_scope_id": made["Production"]["id"], "root_app_scope_id": "r", "short_query": {}, "dirty": False})
raises(lambda: go(t, ["undo", "--record", rec_u, "--write", "--yes"], d=du), "did not create")
assert t.writes() == []
t.scopes = [x for x in t.scopes if x["id"] != "st"]
code, text = go(t, ["undo", "--record", rec_u, "--write"], ["YES"], d=du)
dels = [c[1].rsplit("/", 1)[1] for c in t.writes() if c[0] == "DELETE"]
assert code == 0 and len(dels) == 4 and set(dels[:2]) == {made["payroll"]["id"], made["DNS"]["id"]}, dels
assert [x["id"] for x in t.scopes] == ["r", "me", "h", "o"] and "4 scopes removed and gone" in text
t.log = []; code, text = go(t, ["undo", "--record", rec_u, "--write", "--yes"], d=du)
assert t.writes() == [] and "Nothing to remove" in text and text.count("already gone") == 4
rec2 = dict(load(rec_u), tenant_url="https://elsewhere"); r2p = os.path.join(du, "r2.json")
with open(r2p, "w") as fh: json.dump(rec2, fh)
raises(lambda: go(Tenant(BASE), ["undo", "--record", r2p]), "different tenant")
# a version 1 record (made by helper 1.5) still undoes, and a newer format is refused
tv = Tenant(BASE); go(tv, ["apply", "--plan", pu, "--write", "--yes"], d=(dv := tempfile.mkdtemp()))
old = load(records(dv)[0]); old["schema_version"] = 1
for k in ("tool_version", "plan_fingerprint", "plan_file", "resumed_at"): old.pop(k)
for c in old["created"]: c.pop("how")
with open(os.path.join(dv, "old.json"), "w") as fh: json.dump(old, fh)
code, text = go(tv, ["undo", "--record", os.path.join(dv, "old.json"), "--write", "--yes"], d=dv)
assert code == 0 and "4 scopes removed and gone" in text
with open(os.path.join(dv, "new.json"), "w") as fh: json.dump(dict(old, schema_version=4), fh)
raises(lambda: go(Tenant(BASE), ["undo", "--record", os.path.join(dv, "new.json")]), "uses record format 4")
raises(lambda: go(Tenant(BASE), ["undo"]), "--find-created")

# D16: undo without a record, by the description this program writes on every scope it creates
t = Tenant(BASE); go(t, ["apply", "--plan", plan_path, "--write", "--yes"])
t.scopes.append({"id": "mine2", "short_name": "byhand", "name": "Tenant:bob:byhand", "description": "made by a person", "parent_app_scope_id": "me", "root_app_scope_id": "r", "short_query": {}, "dirty": False})
t.scopes.append({"id": "far", "short_name": "elsewhere", "name": "Tenant:other:elsewhere", "description": "Created by CSW Scope Builder on 2026-01-01", "parent_app_scope_id": "o", "root_app_scope_id": "r", "short_query": {}, "dirty": False})
raises(lambda: go(t, ["undo", "--find-created"]), "--under")
raises(lambda: go(t, ["undo", "--find-created", "--under", "Tenant:bob", "--record", "x.json"]), "not both")
t.log = []; code, text = go(t, ["undo", "--find-created", "--under", "Tenant:bob"])
assert code == 0 and t.writes() == [] and text.count("REMOVE") == 4 and "preview" in text and "byhand" not in text and "elsewhere" not in text, text
# --yes does not skip the typed yes here, and the prompt repeats the count
code, text = go(t, ["undo", "--find-created", "--under", "Tenant:bob", "--write", "--yes"], ["no"])
assert code == 1 and t.writes() == [] and "PROMPT About to remove 4 scopes found by their description" in text
# it refuses a scope that has a child it would not also remove
prod = [x for x in t.scopes if x["short_name"] == "Production"][0]
t.scopes.append({"id": "kid", "short_name": "kid", "name": "x", "description": "", "parent_app_scope_id": prod["id"], "root_app_scope_id": "r", "short_query": {}, "dirty": False})
raises(lambda: go(t, ["undo", "--find-created", "--under", "Tenant:bob", "--write"], ["yes"]), "did not create")
assert t.writes() == []
t.scopes = [x for x in t.scopes if x["id"] != "kid"]
code, text = go(t, ["undo", "--find-created", "--under", "Tenant:bob", "--write"], ["yes"])
dels = [c[1].rsplit("/", 1)[1] for c in t.writes() if c[0] == "DELETE"]
assert code == 0 and len(dels) == 4 and "4 scopes removed and gone" in text
assert sorted(x["id"] for x in t.scopes) == sorted(["r", "me", "h", "o", "mine2", "far"]), "only this program's scopes under the named scope"
code, text = go(t, ["undo", "--find-created", "--under", "Tenant:bob", "--write", "--yes"])
assert code == 0 and "Nothing to remove" in text

# check-labels: finds values an upload would replace
dl = tempfile.mkdtemp(); lab = os.path.join(dl, "labels.csv")
with open(lab, "w", newline="") as fh: fh.write("IP,Environment,Application,Location\r\n10.99.60.71,Production,shop,boston\r\n10.9.0.0/24,Production,test,\r\n10.50.0.0/24,Production,new,\r\n")
t8 = Tenant(BASE); code, text = go(t8, ["check-labels", "--labels", lab, "--under", "Tenant:bob"])
assert code == 2 and t8.writes() == [], text
assert 'Application: tenant has "shopapp", file has "shop"' in text and 'Location: tenant has "east", file has "boston"' in text
assert "already uses these label names: Application, Location" in text and "new label names to the tenant: Environment" in text
res = H.compare_labels([{"IP": "10.9.0.0/24", "Application": "test", "Location": ""}, {"IP": "1.1.1.1", "Application": "a", "Location": ""}], ["IP", "Application", "Location"],
                       [{"IP": "10.9.0.0/24", "Application": "test", "Location": ""}, {"IP": "1.1.1.1/32", "Application": "a"}], ["Application"])
assert res["same"] == 2 and res["new"] == 0 and res["conflicts"] == [] and res["new_columns"] == ["Location"]
with open(lab, "w", newline="") as fh: fh.write("IP,Environment,Application\r\n10.50.0.0/24,Production,new\r\n")
code, text = go(Tenant(BASE), ["check-labels", "--labels", lab, "--under", "bob"])
assert code == 0 and "No conflicts" in text and "Merge" in text
# a label file saved by Excel on Windows (byte order mark) reads the same
with open(lab, "wb") as fb: fb.write(b"\xef\xbb\xbfIP,Environment,Application\r\n10.50.0.0/24,Production,new\r\n")
code, text = go(Tenant(BASE), ["check-labels", "--labels", lab, "--under", "bob"])
assert code == 0 and "Label file rows: 1." in text

# export records label names and the child scope count
de = tempfile.mkdtemp()
t9 = Tenant(BASE); code, text = go(t9, ["export", "--under", "Tenant:bob"], d=de)
ex = load([os.path.join(de, f) for f in os.listdir(de) if f.endswith("Existing Scopes.json")][0])
assert ex["label_columns"] == ["Application", "Location", "Owner"] and ex["scope_count"] == 2 and ex["tenant_scope_count"] == 4 and t9.writes() == []
assert ex["tenant_child_scope_count"] == 3 and ex["tool_version"] == H.VERSION

# ================= Phase 2 (release 1.2): the change plan =================
def sc(i, short, parent, query, desc=""):
    return {"id": i, "short_name": short, "name": "", "parent_app_scope_id": parent, "root_app_scope_id": "r", "short_query": query,
            "dirty": False, "dirty_short_query": None, "description": desc}
def base2():
    rows = [sc("r", "Tenant", None, {"type": "subnet", "field": "ip", "value": "0.0.0.0/0"}), sc("me", "bob", "r", q("Owner", "bob")),
            sc("h", "Home", "me", {"type": "subnet", "field": "ip", "value": "10.99.1.0/24"}, "home net"),
            sc("p", "Production", "me", q("Environment", "Production")), sc("pay", "Payroll", "p", q("Application", "payroll")),
            sc("old", "Legacy", "me", {"type": "eq", "field": "ip", "value": "10.9.9.9"}, "old stuff"),
            sc("kid", "LegacyKid", "old", {"type": "eq", "field": "hostname", "value": "k"}), sc("o", "other", "r", q("Owner", "x"))]
    t = Tenant(rows)
    for x in t.scopes:
        if not x["parent_app_scope_id"]: t.rename_tree(x)
    return t
def bef(t, i):
    x = [y for y in t.scopes if y["id"] == i][0]
    return {"id": i, "short_name": x["short_name"], "short_query": x["short_query"], "parent_id": x["parent_app_scope_id"]}
NEWHOME = {"type": "subnet", "field": "ip", "value": "10.99.0.0/16"}
def plan3(approved=True, **over):
    t = base2()
    items = [
        {"order": 1, "ref": "s1", "parent_ref": "root", "short_name": "Production", "depth": 1, "short_query": q("Environment", "Production"), "action": "keep", "approved": False, "before": bef(t, "p")},
        {"order": 2, "ref": "s2", "parent_ref": "s1", "short_name": "Pay", "depth": 2, "short_query": q("Application", "payroll"), "action": "rename", "approved": approved, "before": bef(t, "pay"), "after": {"short_name": "Pay", "short_query": q("Application", "payroll")}},
        {"order": 3, "ref": "s3", "parent_ref": "root", "short_name": "Home", "depth": 1, "short_query": NEWHOME, "action": "requery", "approved": approved, "before": bef(t, "h"), "after": {"short_name": "Home", "short_query": NEWHOME}},
        {"order": 4, "ref": "s4", "parent_ref": "s1", "short_name": "HR", "depth": 2, "short_query": q("Application", "HR"), "action": "create", "approved": False, "after": {"short_name": "HR", "short_query": q("Application", "HR")}},
        {"order": 5, "ref": "x1", "parent_ref": "root", "short_name": "Legacy", "depth": 1, "short_query": bef(t, "old")["short_query"], "action": "remove", "approved": approved, "before": bef(t, "old")},
        {"order": 6, "ref": "x2", "parent_ref": "x1", "short_name": "LegacyKid", "depth": 2, "short_query": bef(t, "kid")["short_query"], "action": "remove", "approved": approved, "before": bef(t, "kid")}]
    for ref, change in over.items():
        item = [i for i in items if i["ref"] == ref][0]
        if change is None: items.remove(item)
        else: item.update(change)
    return {"schema": "csw-scope-plan", "schema_version": 3, "ready": True, "customer": {"name": "acme"}, "root": {"short_name": "bob", "existing_id": "me"}, "scopes": items}
ALLOW = ["--write", "--allow-changes", "--allow-removals"]
def kinds(t): return [m for m, _ in t.writes()]

# preview: nothing is written, every kind is listed in plain words, and the flags are named
d, pp = folder(plan3())
t = base2(); code, text = go(t, ["apply", "--plan", pp], d=d)
assert code == 0 and t.writes() == [] and records(d) == [], text
assert "CREATE        HR under Production: Application is HR" in text, text
assert 'RENAME        Tenant:bob:Production:Payroll: from "Payroll" to "Pay"   [would do with --allow-changes]' in text, text
assert "CHANGE QUERY  Tenant:bob:Home: from [address is in 10.99.1.0/24] to [address is in 10.99.0.0/16]   [would do with --allow-changes]" in text, text
assert "REMOVE        Tenant:bob:Legacy:LegacyKid   [would do with --allow-removals]" in text and text.index("Legacy:LegacyKid") < text.index("REMOVE        Tenant:bob:Legacy "), text
assert "1 to create, 1 to rename, 1 query change, 2 to remove. 0 not approved and skipped, 0 to do by hand, 1 kept, 0 left alone." in text, text
# the flags alone, without --write, change nothing
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--allow-changes", "--allow-removals"], d=d)
assert t.writes() == [] and "do nothing without --write" in text

# 8.8: each permission flag is required for its kind of change
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--write"], ["yes"])
assert code == 0 and kinds(t) == ["POST", "POST"] and t.writes()[1][1].startswith("/openapi/v1/app_scopes/commit_dirty"), t.writes()
assert "needs --allow-changes" in text and "needs --allow-removals" in text and "Skipped, nothing done:" in text, text
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--write", "--allow-changes"], ["yes", "yes"])
assert code == 0 and kinds(t) == ["POST", "PUT", "PUT", "POST"] and "needs --allow-removals" in text and "needs --allow-changes" not in text, (t.writes(), text)
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--write", "--allow-removals"], ["yes", "yes"])
assert code == 0 and kinds(t) == ["POST", "DELETE", "DELETE", "POST"] and "needs --allow-changes" in text, (t.writes(), text)
# order of work: creates, renames, query changes, removals deepest first, then one commit
t = base2(); code, text = go(t, ["apply", "--plan", pp] + ALLOW, ["yes", "yes", "yes"], d=d)
assert code == 0, text
assert t.writes() == [("POST", "/openapi/v1/app_scopes"), ("PUT", "/openapi/v1/app_scopes/pay"), ("PUT", "/openapi/v1/app_scopes/h"),
                      ("DELETE", "/openapi/v1/app_scopes/kid"), ("DELETE", "/openapi/v1/app_scopes/old"),
                      ("POST", "/openapi/v1/app_scopes/commit_dirty?root_app_scope_id=r&sync=true")], t.writes()
assert "Tenant:bob:Production:Pay" in t.names() and "Tenant:bob:Legacy" not in t.names() and "Tenant:bob:Production:HR" in t.names()
assert [x for x in t.scopes if x["id"] == "h"][0]["short_query"] == NEWHOME, "the query change is committed"
assert "Created 1, changed 2, removed 2." in text and "Scope changes committed." in text
# the three prompts: creates, then every change before and after, then removals with the count and full names
prompts = [l for l in text.split("\n") if l.startswith("PROMPT")]
assert len(prompts) == 3 and "About to create 1 scope" in prompts[0] and "About to make 2 changes to existing scopes" in prompts[1] and "About to REMOVE 2 scopes" in prompts[2], prompts
assert 'rename Tenant:bob:Production:Payroll: from "Payroll" to "Pay"' in text and "change the query of Tenant:bob:Home: from [address is in 10.99.1.0/24] to [address is in 10.99.0.0/16]" in text
assert text.index("Scopes to remove:") < text.index("  Tenant:bob:Legacy:LegacyKid", text.index("Scopes to remove:")) < text.index("About to REMOVE")
# 8.7.7: the record stores before and after for every change, and never the key or secret
rec = load(records(d)[0]); raw = open(records(d)[0]).read()
assert rec["schema_version"] == 3 and rec["finished"] is True and rec["committed"] is True and len(rec["created"]) == 1
# every change entry holds the full before values (ID, name, query, parent), what it changed to, and its status
assert rec["changes"] == [{"kind": "rename", "id": "pay", "ref": "s2", "status": "done", "before": {"id": "pay", "short_name": "Payroll", "short_query": q("Application", "payroll"), "parent_id": "p"}, "after": {"short_name": "Pay"}},
                          {"kind": "requery", "id": "h", "ref": "s3", "status": "done", "before": {"id": "h", "short_name": "Home", "short_query": {"type": "subnet", "field": "ip", "value": "10.99.1.0/24"}, "parent_id": "me"}, "after": {"short_query": NEWHOME}}], rec["changes"]
assert [(r["name"], r["status"], r["before"]["id"], r["before"]["parent_id"]) for r in rec["removed"]] == [("Tenant:bob:Legacy:LegacyKid", "removed", "kid", "old"), ("Tenant:bob:Legacy", "removed", "old", "me")]
assert rec["removed"][1]["before"]["description"] == "old stuff" and '"K"' not in raw and '"S"' not in raw and "secret" not in raw.lower()

# 8.8: full undo of a run that created, renamed, requeried, and removed restores the starting state, apart from new IDs
start = base2().shape()
code, text = go(t, ["undo", "--record", records(d)[0]], d=d)
assert code == 0 and "This was a preview" in text and "RECREATE Tenant:bob:Legacy (it will get a new ID)" in text and 'RESTORE NAME of Tenant:bob:Production:Pay: from "Pay" back to "Payroll"' in text, text
assert "RESTORE QUERY of Tenant:bob:Home: from [address is in 10.99.0.0/16] back to [address is in 10.99.1.0/24]" in text and "REMOVE Tenant:bob:Production:HR" in text
assert t.shape() != start
before_undo = len(t.writes())
code, text = go(t, ["undo", "--record", records(d)[0], "--write", "--yes"], ["no"], d=d)      # --yes does not cover it
assert code == 1 and len(t.writes()) == before_undo and "PROMPT About to recreate 2, restore 1 query and 1 name, and remove 1 scope" in text, text
code, text = go(t, ["undo", "--record", records(d)[0], "--write"], ["yes"], d=d)
assert code == 0 and t.shape() == start, (text, t.shape(), start)
assert kinds(t)[before_undo:] == ["POST", "POST", "PUT", "PUT", "DELETE", "POST"], kinds(t)[before_undo:]      # recreate, query, name, delete, commit
assert "new ID" in text and "the old ID was old" in text and "Recreated scopes have new IDs" in text
assert {x["id"] for x in t.scopes if x["short_name"] in ("Legacy", "LegacyKid")}.isdisjoint({"old", "kid"})
kid = [x for x in t.scopes if x["short_name"] == "LegacyKid"][0]
assert kid["parent_app_scope_id"] == [x for x in t.scopes if x["short_name"] == "Legacy"][0]["id"], "the child goes back under the recreated parent"
# a second undo finds nothing left to do and writes nothing
n = len(t.writes()); code, text = go(t, ["undo", "--record", records(d)[0], "--write"], ["yes"], d=d)
assert code == 0 and len(t.writes()) == n and "Nothing to reverse." in text, text
# undo stops, with nothing written, when something the run changed has been changed again
d2, pp2 = folder(plan3())
t = base2(); go(t, ["apply", "--plan", pp2] + ALLOW, ["yes", "yes", "yes"], d=d2)
[x for x in t.scopes if x["id"] == "pay"][0]["short_name"] = "Someone Else"
n = len(t.writes()); raises(lambda: go(t, ["undo", "--record", records(d2)[0], "--write"], ["yes"], d=d2), "renamed again")
assert len(t.writes()) == n
t = base2(); d2, pp2 = folder(plan3()); go(t, ["apply", "--plan", pp2] + ALLOW, ["yes", "yes", "yes"], d=d2)
t.scopes.append(sc("zz", "Legacy", "me", q("Owner", "z")))
n = len(t.writes()); raises(lambda: go(t, ["undo", "--record", records(d2)[0], "--write"], ["yes"], d=d2), "already where the removed one was")
assert len(t.writes()) == n

# 8.8: unapproved items are skipped and listed, even with every flag
d3, pp3 = folder(plan3(approved=False))
t = base2(); code, text = go(t, ["apply", "--plan", pp3] + ALLOW, ["yes"], d=d3)
assert code == 0 and kinds(t) == ["POST", "POST"], t.writes()
assert text.count("SKIPPED ") == 4 and "[rename is not approved in the plan]" in text and "[query change is not approved in the plan]" in text and "[removal is not approved in the plan]" in text, text
assert "4 not approved and skipped" in text and text.count("(not approved in the plan)") == 4
assert len(load(records(d3)[0])["skipped"]) == 4

# 8.8: --yes never covers changes or removals
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--yes"] + ALLOW, ["no"])
assert code == 1 and t.writes() == [] and "About to create" not in text and "PROMPT About to make 2 changes" in text and "Nothing was changed" in text, text
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--yes"] + ALLOW, ["yes", "nope"])
assert code == 1 and t.writes() == [] and "PROMPT About to REMOVE 2 scopes" in text, text
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--yes"] + ALLOW, ["yes", "yes"])
assert code == 0 and len([l for l in text.split("\n") if l.startswith("PROMPT")]) == 2 and len(t.writes()) == 6

# 8.8: a changed "before" stops the run with nothing written
def spoil(change):
    t = base2(); change(t); return t
def sget(t, i): return [x for x in t.scopes if x["id"] == i][0]
for change, words in ((lambda t: sget(t, "pay").update(short_name="Payroll2"), 'is now named "Payroll2"'),
                      (lambda t: sget(t, "h").update(short_query={"type": "subnet", "field": "ip", "value": "10.1.0.0/16"}), "has a different query"),
                      (lambda t: sget(t, "h").update(dirty_short_query=NEWHOME), "waiting for a commit"),
                      (lambda t: sget(t, "kid").update(parent_app_scope_id="p"), "different parent"),
                      (lambda t: t.scopes.remove(sget(t, "kid")), "no longer in the tenant"),
                      (lambda t: sget(t, "p").update(short_name="Prod"), 'is now named "Prod"'),      # even a scope the plan only keeps
                      (lambda t: t.scopes.append(sc("zz", "hr", "p", q("Application", "other"))), "now exists under"),
                      (lambda t: t.scopes.append(sc("zz", "PAY", "p", q("Application", "x"))), "already beside it"),
                      (lambda t: t.scopes.append(sc("zz", "Stranger", "old", q("Application", "x"))), "is not also being removed")):
    t = spoil(change)
    raises(lambda: go(t, ["apply", "--plan", pp] + ALLOW, ["yes", "yes", "yes"]), words)
    assert t.writes() == [], words
    raises(lambda: go(t, ["apply", "--plan", pp]), words)      # the preview says the same

# 8.8: a 422 on removal is reported with what depends on the scope, nothing is retried, and its ancestors are left
d4, pp4 = folder(plan3())
t = base2(); t.in_use["kid"] = {"workspaces": {"count": 2, "ids": ["w1", "w2"]}, "inventory_filters": {"count": 1, "ids": ["f1"]}}
code, text = go(t, ["apply", "--plan", pp4] + ALLOW, ["yes", "yes", "yes"], d=d4)
assert code == 0 and t.writes().count(("DELETE", "/openapi/v1/app_scopes/kid")) == 1 and ("DELETE", "/openapi/v1/app_scopes/old") not in t.writes(), t.writes()
assert "IN USE, not removed: Tenant:bob:Legacy:LegacyKid. The tenant says: This scope has dependent objects; inventory_filters: 1 (IDs: f1); workspaces: 2 (IDs: w1, w2)" in text, text
assert "not removed: Tenant:bob:Legacy (a scope under it is in use)" in text and "In use and not removed." in text and "removed 0" in text
rec = load(records(d4)[0])
assert [(r["name"], r["status"]) for r in rec["removed"]] == [("Tenant:bob:Legacy:LegacyKid", "in use"), ("Tenant:bob:Legacy", "not removed")] and "workspaces: 2" in rec["removed"][0]["tenant_said"]
assert "Tenant:bob:Legacy:LegacyKid" in t.names() and "Tenant:bob:Legacy" in t.names()
# a removal that is in use does not stop removals elsewhere
both = plan3(); both["scopes"].append({"order": 7, "ref": "x3", "parent_ref": "s1", "short_name": "Payroll", "depth": 2, "short_query": q("Application", "payroll"), "action": "remove", "approved": True, "before": bef(base2(), "pay")})
both["scopes"] = [i for i in both["scopes"] if i["ref"] != "s2"]
d5b, pp5 = folder(both); t = base2(); t.in_use["kid"] = {"workspaces": {"count": 1, "ids": ["w1"]}}
code, text = go(t, ["apply", "--plan", pp5] + ALLOW, ["yes", "yes", "yes"], d=d5b)
assert ("DELETE", "/openapi/v1/app_scopes/pay") in t.writes() and "Tenant:bob:Production:Payroll" not in t.names() and "removed 1" in text, text
# any other refusal on removal stops the run
t = base2(); t.scopes.append(sc("deep", "Deep", "kid", q("Application", "x")))
extra = plan3(); extra["scopes"].append({"order": 7, "ref": "x3", "parent_ref": "x2", "short_name": "Deep", "depth": 3, "short_query": q("Application", "x"), "action": "remove", "approved": True, "before": {"id": "deep", "short_name": "Deep", "short_query": q("Application", "x"), "parent_id": "kid"}})
d6b, pp6 = folder(extra)
code, text = go(t, ["apply", "--plan", pp6] + ALLOW, ["yes", "yes", "yes"], d=d6b)
assert [w for w in t.writes() if w[0] == "DELETE"] == [("DELETE", "/openapi/v1/app_scopes/" + i) for i in ("deep", "kid", "old")], "deepest first"

# 8.8: a top-level scope can never get a change action, and nothing outside the work area can
for ref, change, words in (("s2", {"action": "rename", "before": bef(base2(), "r"), "after": {"short_name": "X"}}, "top-level scope"),
                           ("s3", {"action": "requery", "before": bef(base2(), "r")}, "top-level scope"),
                           ("x2", {"action": "remove", "before": bef(base2(), "r")}, "top-level scope"),
                           ("s2", {"action": "rename", "before": bef(base2(), "o"), "after": {"short_name": "X"}}, 'is not under "Tenant:bob"'),
                           ("x2", {"action": "remove", "before": bef(base2(), "o")}, 'is not under "Tenant:bob"'),
                           ("s2", {"action": "rename", "before": bef(base2(), "me"), "after": {"short_name": "X"}}, 'is not under "Tenant:bob"')):
    dd, ppx = folder(plan3(**{ref: change})); t = base2()
    raises(lambda: go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"]), words)
    assert t.writes() == [], words
# an unknown action, or a change with no target, is refused
for ref, change, words in (("s2", {"action": "move"}, "does not understand"), ("s2", {"before": {}}, "does not say which existing scope"),
                           ("s2", {"after": {"short_name": " "}}, "no new name"), ("s3", {"after": {}}, "no new query")):
    dd, ppx = folder(plan3(**{ref: change})); t = base2()
    raises(lambda: go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"]), words)
    assert t.writes() == []

# 8.8: removing a parent while keeping its child is refused (child not approved, child left alone, or child not in the plan)
for change in ({"approved": False}, {"action": "leave"}, None):
    dd, ppx = folder(plan3(x2=change)); t = base2()
    raises(lambda: go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"]), 'cannot be removed because the scope "LegacyKid" under it is not also being removed')
    assert t.writes() == []
# and a plan cannot create something under a scope it removes
dd, ppx = folder(plan3(s4={"parent_ref": "x1"})); t = base2()
raises(lambda: go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"]), "under a scope it also removes")
assert t.writes() == []

# by hand items are listed with the reason and never done
dd, ppx = folder(plan3(x1={"action": "by_hand", "reason": "It has 2 workspaces attached."}, x2={"action": "leave"})); t = base2()
code, text = go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes"])
assert "BY HAND       Tenant:bob:Legacy: It has 2 workspaces attached." in text and "To do by hand in Secure Workload:" in text and "DELETE" not in kinds(t), text
assert "1 to do by hand, 1 kept, 1 left alone" in text

# safety rule 4: every change is read back, and the run stops at the first mismatch
for what, words, puts in (("name", "new name", 1), ("query", "new query", 2)):
    dd, ppx = folder(plan3()); t = base2(); t.corrupt_put = what
    raises(lambda: go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"], d=dd), "does not read back as planned")
    assert kinds(t).count("PUT") == puts and "DELETE" not in kinds(t) and load(records(dd)[0])["finished"] is False, (what, t.writes())
# safety rule 5: the record is saved after every single change, and an interrupted run is continued, not repeated
dd, ppx = folder(plan3()); t = base2(); t.fail_put_after = 1
raises(lambda: go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"], d=dd), "error 500")
rec = load(records(dd)[0])
assert rec["finished"] is False and len(rec["created"]) == 1 and [(c["kind"], c["status"]) for c in rec["changes"]] == [("rename", "done"), ("requery", "not done")] and rec["removed"] == []
assert rec["changes"][1]["how"] == "error 500; the tenant was read back", "a server error is treated as an unknown outcome and checked against the tenant"
t.fail_put_after = None; n = len(t.writes())
code, text = go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes"], d=dd)
assert code == 0 and "This continues the unfinished build" in text and len(records(dd)) == 1, text
assert t.writes()[n:] == [("PUT", "/openapi/v1/app_scopes/h"), ("DELETE", "/openapi/v1/app_scopes/kid"), ("DELETE", "/openapi/v1/app_scopes/old"),
                          ("POST", "/openapi/v1/app_scopes/commit_dirty?root_app_scope_id=r&sync=true")], t.writes()[n:]
rec = load(records(dd)[0])
assert rec["finished"] is True and len(rec["created"]) == 1 and len(rec["changes"]) == 2 and len(rec["removed"]) == 2 and len(rec["resumed_at"]) == 1
# and one undo reverses the whole build
code, text = go(t, ["undo", "--record", records(dd)[0], "--write"], ["yes"], d=dd)
assert code == 0 and t.shape() == start
# a finished run, run again, has nothing to do and writes nothing (the plan no longer matches the tenant, so it stops)
dd, ppx = folder(plan3()); t = base2(); go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"], d=dd)
n = len(t.writes()); raises(lambda: go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"], d=dd), "changed since the plan was made")
assert len(t.writes()) == n
# safety rule 6: query changes are not committed while someone else has uncommitted changes
dd, ppx = folder(plan3()); t = base2(); sget(t, "o")["dirty"] = True
code, text = go(t, ["apply", "--plan", ppx] + ALLOW, ["yes", "yes", "yes"], d=dd)
assert "NOT committed" in text and not any("commit_dirty" in p for _, p in t.writes()) and sget(t, "h")["dirty_short_query"] == NEWHOME and load(records(dd)[0])["committed"] is False
# then undo still recognizes the uncommitted query as its own and restores it
code, text = go(t, ["undo", "--record", records(dd)[0], "--write"], ["yes"], d=dd)
assert code == 0 and H.live_query(sget(t, "h")) == {"type": "subnet", "field": "ip", "value": "10.99.1.0/24"}

# 8.8: a version 1 or 2 plan builds exactly as before, and cannot be given the new permissions
dv, pv = folder()
t = Tenant(BASE); code, text = go(t, ["apply", "--plan", pv, "--write"], ["yes"], d=dv)
assert t.writes() == [("POST", "/openapi/v1/app_scopes")] * 4 + [("POST", "/openapi/v1/app_scopes/commit_dirty?root_app_scope_id=r&sync=true")]
assert "created and verified" in text and "4 to create, 0 already there, 0 left as they are." in text
kept = copy.deepcopy(PLAN); kept["schema_version"] = 2; kept["scopes"][0] = dict(kept["scopes"][0], short_name="Home")
dk, pk = folder(kept); t = Tenant(BASE); code, text = go(t, ["apply", "--plan", pk, "--write"], ["yes"], d=dk)
assert "exists with a different query, left as it is" in text and "PUT" not in kinds(t), text
for flag in ("--allow-changes", "--allow-removals"):
    t = Tenant(BASE); raises(lambda: go(t, ["apply", "--plan", pv, "--write", flag], ["yes"]), "need a plan file in format 3")
    assert t.writes() == []
raises(lambda: go(Tenant(BASE), ["export", "--allow-changes"]), "only for the apply command")
raises(lambda: go(Tenant(BASE), ["undo", "--record", "x", "--allow-removals"]), "only for the apply command")
bad = plan3(); bad["schema_version"] = 4; db_, pb = folder(bad)
raises(lambda: go(base2(), ["apply", "--plan", pb]), "understands formats 1 and 2 and 3")

# 8.5: the export records what depends on each scope: IDs and names only
de2 = tempfile.mkdtemp(); t = base2()
t.workspaces = [{"id": "w1", "name": "Shop policy", "app_scope_id": "p", "primary": True, "latest_adm_version": 4, "absolute_policies": [{"secret": "policy content"}]},
                {"id": "w2", "name": "Elsewhere", "app_scope_id": "o"}]
t.filters = [{"id": "f1", "name": "Web servers", "app_scope_id": "h", "query": {"type": "eq", "field": "ip", "value": "1.1.1.1"}}]
t.roles = [{"id": "ro1", "name": "Bob admins", "app_scope_id": "me", "description": "x"}]
code, text = go(t, ["export", "--under", "Tenant:bob"], d=de2)
ex = load([os.path.join(de2, f) for f in os.listdir(de2)][0]); by = {x["id"]: x for x in ex["scopes"]}
assert ex["schema_version"] == 2 and t.writes() == [] and "Not read" not in text
assert ex["dependents"] == {"workspaces": {"read": True}, "inventory_filters": {"read": True}, "roles": {"read": True}}
assert by["p"]["dependents"] == {"workspaces": [{"id": "w1", "name": "Shop policy"}], "inventory_filters": [], "roles": []}
assert by["h"]["dependents"]["inventory_filters"] == [{"id": "f1", "name": "Web servers"}] and by["me"]["dependents"]["roles"] == [{"id": "ro1", "name": "Bob admins"}]
raw = open([os.path.join(de2, f) for f in os.listdir(de2)][0]).read()
assert "policy content" not in raw and "Elsewhere" not in raw and "latest_adm_version" not in raw, "nothing else from those objects is stored"
assert "dirty_short_query" in by["h"]
# a key that cannot read one kind still gets an export, with that kind marked "not read" and the reason
de3 = tempfile.mkdtemp(); t.deny = {"workspaces", "roles"}
code, text = go(t, ["export", "--under", "Tenant:bob"], d=de3)
ex = load([os.path.join(de3, f) for f in os.listdir(de3)][0]); by = {x["id"]: x for x in ex["scopes"]}
assert code == 0 and ex["dependents"]["workspaces"] == {"read": False, "reason": "The API key is not allowed to read this.", "needs": "app_policy_management"}
assert ex["dependents"]["inventory_filters"] == {"read": True} and ex["dependents"]["roles"]["read"] is False
assert by["p"]["dependents"]["workspaces"] == "not read" and by["h"]["dependents"]["inventory_filters"] == [{"id": "f1", "name": "Web servers"}] and by["me"]["dependents"]["roles"] == "not read"
assert "Not read: workspaces." in text and "possibly in use by workspaces" in text and "app_policy_management" in text and "Not read: roles." in text
assert H.in_use_words("not json at all") == "not json at all" and H.in_use_words("") == "The tenant gave no detail."

# ================= Phase 2 review fixes: the record never trails the tenant =================
def one(rows, **want): return [r for r in rows if all(r.get(k) == v for k, v in want.items())]
def run3(t, d, pp, answers=("yes", "yes", "yes")): return go(t, ["apply", "--plan", pp] + ALLOW, list(answers), d=d)
END_STATE = None
def end_state():
    global END_STATE
    if END_STATE is None:
        dd, ppx = folder(plan3()); t = base2(); run3(t, dd, ppx); END_STATE = t.shape()
    return END_STATE

# fix 1: the entry is saved as "attempting", with the full before values, BEFORE the call is sent
class Spy(Tenant):
    """Reads the record file at the moment each change call arrives."""
    def __call__(self, req):
        m = req.get_method()
        if m in ("PUT", "DELETE") and getattr(self, "folder", None) and records(self.folder):
            self.seen.append((m, req.full_url.rsplit("/", 1)[1], load(records(self.folder)[0])))
        return Tenant.__call__(self, req)
dd, ppx = folder(plan3()); t = base2(); t.__class__ = Spy; t.folder = dd; t.seen = []
run3(t, dd, ppx)
assert [(m, i) for m, i, _ in t.seen] == [("PUT", "pay"), ("PUT", "h"), ("DELETE", "kid"), ("DELETE", "old")]
at_rename, at_query, at_kid, at_old = [r for _, _, r in t.seen]
assert at_rename["changes"] == [{"kind": "rename", "id": "pay", "ref": "s2", "status": "attempting", "before": {"id": "pay", "short_name": "Payroll", "short_query": q("Application", "payroll"), "parent_id": "p"}, "after": {"short_name": "Pay"}}]
assert [c["status"] for c in at_query["changes"]] == ["done", "attempting"] and at_query["changes"][1]["before"]["short_query"] == {"type": "subnet", "field": "ip", "value": "10.99.1.0/24"}
assert [(r["status"], r["before"]["id"], r["before"]["parent_id"], r["before"]["short_name"]) for r in at_kid["removed"]] == [("attempting", "kid", "old", "LegacyKid")]
assert [r["status"] for r in at_old["removed"]] == ["removed", "attempting"] and at_old["removed"][1]["before"]["description"] == "old stuff"
assert [c["status"] for c in load(records(dd)[0])["changes"]] == ["done", "done"] and [r["status"] for r in load(records(dd)[0])["removed"]] == ["removed", "removed"]

# fix 1 and fix 6, apply: the connection drops AFTER the tenant applied the call (the supervisor's reproduction), and BEFORE it arrived
for kind, key, landed_words, missed_words in (("rename", ("PUT", "pay"), "the change WAS made", "the change was NOT made"),
                                              ("requery", ("PUT", "h"), "the change WAS made", "the change was NOT made"),
                                              ("removal", ("DELETE", "kid"), "the scope IS gone", "the scope is still there")):
    for when in ("after", "before"):
        dd, ppx = folder(plan3()); t = base2(); t.drops[key] = when
        raises(lambda: run3(t, dd, ppx), landed_words if when == "after" else missed_words)
        rec = load(records(dd)[0]); n = len(t.writes())
        assert rec["finished"] is False, (kind, when)
        # the record says what the tenant really holds, and the run stopped right there
        if kind == "removal":
            entry = one(rec["removed"], name="Tenant:bob:Legacy:LegacyKid")[0]
            assert entry["status"] == ("removed" if when == "after" else "not removed") and "read back" in entry["how"], (when, entry)
            assert ("Tenant:bob:Legacy:LegacyKid" in t.names()) == (when == "before") and ("DELETE", "/openapi/v1/app_scopes/old") not in t.writes()
        else:
            entry = one(rec["changes"], kind=kind)[0]
            assert entry["status"] == ("done" if when == "after" else "not done") and "read back" in entry["how"], (when, entry)
            live = sget(t, key[1])
            changed = live["short_name"] == "Pay" if kind == "rename" else live["dirty_short_query"] == NEWHOME
            assert changed == (when == "after"), (kind, when)
            assert "DELETE" not in kinds(t) and (kind == "requery" or kinds(t).count("PUT") == 1), t.writes()
        # the same command again continues: nothing already done is sent a second time, and the result is the full build
        code, text = run3(t, dd, ppx, ["yes", "yes"])
        assert code == 0 and "This continues the unfinished build" in text and len(records(dd)) == 1, (kind, when, text)
        sent = [(m, p.rsplit("/", 1)[1]) for m, p in t.writes()]
        assert sent.count(key) == (1 if when == "after" else 2), (kind, when, sent)
        assert sent.count(("PUT", "pay")) == (2 if key == ("PUT", "pay") and when == "before" else 1), sent
        assert t.shape() == end_state(), (kind, when)
        rec = load(records(dd)[0])
        assert rec["finished"] is True and len([c for c in rec["changes"] if c["status"] == "done"]) == 2 and len([r for r in rec["removed"] if r["status"] == "removed"]) == 2
        assert not [c for c in rec["changes"] if c["status"] == "attempting"] and not [r for r in rec["removed"] if r["status"] == "attempting"]
        # and one undo reverses the whole thing
        code, text = go(t, ["undo", "--record", records(dd)[0], "--write"], ["yes"], d=dd)
        assert code == 0 and t.shape() == start, (kind, when, text)

# undo straight after a dropped call, with no rerun in between: undo reverses exactly what the tenant holds
for key, when in ((("PUT", "pay"), "after"), (("PUT", "pay"), "before"), (("PUT", "h"), "after"), (("DELETE", "kid"), "after"), (("DELETE", "kid"), "before"), (("DELETE", "old"), "after")):
    dd, ppx = folder(plan3()); t = base2(); t.drops[key] = when
    raises(lambda: run3(t, dd, ppx), "(the connection dropped). The tenant was read back")
    code, text = go(t, ["undo", "--record", records(dd)[0], "--write"], ["yes"], d=dd)
    assert code == 0 and t.shape() == start, (key, when, text, t.shape())

# the read-back also fails: the entry stays "attempting", and both resume and undo settle it by reading the tenant
for key, landed in ((("PUT", "pay"), True), (("PUT", "h"), True), (("DELETE", "kid"), True), (("PUT", "pay"), False), (("DELETE", "kid"), False)):
    for finish in ("resume", "undo"):
        dd, ppx = folder(plan3()); t = base2(); t.drops[key] = "after" if landed else "before"; t.blind = 99
        def cut_reads_after_change(req, t=t, key=key):
            # reads work until the change call has been sent, then every read fails
            if req.get_method() == "GET" and not any((m, p.rsplit("/", 1)[1]) == key for m, p in t.log): t.blind = 0
            elif req.get_method() == "GET": t.blind = 99
            return t(req)
        lines = []; it = iter(["yes", "yes", "yes"])
        raises(lambda: H.run(["apply", "--plan", ppx, "--out-dir", dd] + ALLOW, opener=cut_reads_after_change, ask=lambda p: next(it), ask_secret=lambda p: "S",
                             out=lines.append, env=ENV, sleep=lambda s: None), "could not be reached to see whether the change was made")
        rec = load(records(dd)[0])
        waiting = [c for c in rec["changes"] if c["status"] == "attempting"] + [r for r in rec["removed"] if r["status"] == "attempting"]
        assert len(waiting) == 1 and rec["finished"] is False and waiting[0]["before"]["id"] == key[1], (key, landed, rec)
        t.blind = 0
        if finish == "resume":
            code, text = run3(t, dd, ppx, ["yes", "yes"])
            assert code == 0 and t.shape() == end_state(), (key, landed, text)
            sent = [(m, p.rsplit("/", 1)[1]) for m, p in t.writes()]
            assert sent.count(key) == (1 if landed else 2), (key, landed, sent)
            rec = load(records(dd)[0])
            assert not [c for c in rec["changes"] if c["status"] == "attempting"] and not [r for r in rec["removed"] if r["status"] == "attempting"]
        code, text = go(t, ["undo", "--record", records(dd)[0], "--write"], ["yes"], d=dd)
        assert code == 0 and t.shape() == start, (key, landed, finish, text)

# a refusal other than "in use" on removal is recorded as not removed before the run stops
dd, ppx = folder(plan3()); t = base2()
def refuse_delete(req, t=t):
    if req.get_method() == "DELETE": raise urllib.error.HTTPError(req.full_url, 500, "x", {}, io.BytesIO(b'{"error":"boom"}'))
    return t(req)
lines = []; it = iter(["yes", "yes", "yes"])
raises(lambda: H.run(["apply", "--plan", ppx, "--out-dir", dd] + ALLOW, opener=refuse_delete, ask=lambda p: next(it), ask_secret=lambda p: "S", out=lines.append, env=ENV, sleep=lambda s: None), "(error 500). The tenant was read back: the scope is still there")
assert [(r["status"], r["how"]) for r in load(records(dd)[0])["removed"]] == [("not removed", "error 500; the tenant was read back")]
# a plain refusal (not a server error, not "in use") is recorded as not removed with the error number
dd, ppx = folder(plan3()); t = base2()
def forbid_delete(req, t=t):
    if req.get_method() == "DELETE": raise urllib.error.HTTPError(req.full_url, 403, "x", {}, io.BytesIO(b'{"error":"no"}'))
    return t(req)
it = iter(["yes", "yes", "yes"])
raises(lambda: H.run(["apply", "--plan", ppx, "--out-dir", dd] + ALLOW, opener=forbid_delete, ask=lambda p: next(it), ask_secret=lambda p: "S", out=lines.append, env=ENV, sleep=lambda s: None), "error 403")
assert [(r["status"], r["why"]) for r in load(records(dd)[0])["removed"]] == [("not removed", "the tenant refused with error 403")]

# fix 2 and fix 6, undo: its own calls get the same treatment
def built():
    dd, ppx = folder(plan3()); t = base2(); run3(t, dd, ppx)
    return t, dd, records(dd)[0]
def undo(t, dd, rec): return go(t, ["undo", "--record", rec, "--write"], ["yes"], d=dd)
t, dd, rec = built()
hr = [x["id"] for x in t.scopes if x["short_name"] == "HR"][0]
for key_of, kind, landed_words, missed_words in ((lambda: ("PUT", "pay"), "rename", "the old name IS back", "the old name is NOT back"),
                                                 (lambda: ("PUT", "h"), "requery", "the old query IS back", "the old query is NOT back"),
                                                 (lambda: ("DELETE", hr), "removal", "the scope IS gone", "the scope is still there")):
    for when in ("after", "before"):
        t, dd, rec = built(); hr = [x["id"] for x in t.scopes if x["short_name"] == "HR"][0]; key = key_of()
        n = len(t.writes()); t.drops[key] = when
        raises(lambda: undo(t, dd, rec), landed_words if when == "after" else missed_words)
        saved = load(rec)
        if kind == "removal":
            assert one(saved["created"], id=hr)[0]["undo"] == ("removed" if when == "after" else "not done"), (when, saved["created"])
            assert (hr in [x["id"] for x in t.scopes]) == (when == "before")
        else:
            entry = one(saved["changes"], kind=kind)[0]
            assert entry["restore"] == ("done" if when == "after" else "not done") and bool(entry.get("restored")) == (when == "after"), (kind, when, entry)
        # the same undo again finishes the job without repeating what is already back
        code, text = undo(t, dd, rec)
        assert code == 0 and t.shape() == start, (kind, when, text)
        sent = [(m, p.rsplit("/", 1)[1]) for m, p in t.writes()[n:]]
        assert sent.count(key) == (1 if when == "after" else 2), (kind, when, sent)
        assert t.writes()[n:].count(("POST", "/openapi/v1/app_scopes")) == 2, "each removed scope is recreated exactly once"
        code, text = undo(t, dd, rec)
        assert "Nothing to reverse." in text and t.shape() == start
# a recreate whose answer is lost looks before trying again, as create does
for knob, how, posts in (("drop_after_create", "found after the connection dropped", 2), ("drop_before_create", "recreated on the second try", 3)):
    for name in ("Legacy", "LegacyKid"):
        t, dd, rec = built(); n = len(t.writes())
        if knob == "drop_after_create": t.drop_after_create.add(name)
        else: t.drop_before_create[name] = 1
        code, text = undo(t, dd, rec)
        assert code == 0 and t.shape() == start and "(" + how + ")" in text, (knob, name, text)
        assert [x["short_name"] for x in t.scopes].count(name) == 1, "never recreated twice"
        assert t.writes()[n:].count(("POST", "/openapi/v1/app_scopes")) == posts, (knob, name, t.writes()[n:])
        assert one(load(rec)["removed"], name="Tenant:bob:Legacy" + (":LegacyKid" if name == "LegacyKid" else ""))[0]["recreate_how"] == how
# the answer is lost and the tenant cannot be read either: the entry stays "attempting", and the next undo adopts the scope it finds
t, dd, rec = built(); t.drop_after_create.add("Legacy")
def blind_after_post(req, t=t):
    if req.get_method() == "GET" and ("POST", "/openapi/v1/app_scopes") in t.log[t.mark:]: raise socket.timeout("timed out")
    return t(req)
t.mark = len(t.log); lines = []
raises(lambda: H.run(["undo", "--record", rec, "--write", "--out-dir", dd], opener=blind_after_post, ask=lambda p: "yes", ask_secret=lambda p: "S", out=lines.append, env=ENV, sleep=lambda s: None), "Could not reach the tenant")
entry = one(load(rec)["removed"], name="Tenant:bob:Legacy")[0]
assert entry["recreate"] == "attempting" and "recreated_id" not in entry and [x["short_name"] for x in t.scopes].count("Legacy") == 1
n = len(t.writes()); code, text = undo(t, dd, rec)
assert code == 0 and t.shape() == start and "was recreated by an earlier undo that lost its connection" in text, text
assert [x["short_name"] for x in t.scopes].count("Legacy") == 1 and t.writes()[n:].count(("POST", "/openapi/v1/app_scopes")) == 1, "only LegacyKid is left to recreate"
# but a same-named scope that undo did not make is still refused
t, dd, rec = built(); t.scopes.append(sc("zz", "Legacy", "me", q("Owner", "z")))
n = len(t.writes()); raises(lambda: undo(t, dd, rec), "already where the removed one was"); assert len(t.writes()) == n
# a dropped delete in the plain undo of a create-only build (plan formats 1 and 2) and in --find-created
for extra in ([], ["find"]):
    for when in ("after", "before"):
        dv2, pv2 = folder(); t = Tenant(BASE); go(t, ["apply", "--plan", pv2, "--write"], ["yes"], d=dv2)
        dns = [x["id"] for x in t.scopes if x["short_name"] == "DNS"][0]; t.drops[("DELETE", dns)] = when
        argv = ["undo", "--find-created", "--under", "Tenant:bob", "--write"] if extra else ["undo", "--record", records(dv2)[0], "--write"]
        raises(lambda: go(t, argv, ["yes"], d=dv2), "the scope IS gone" if when == "after" else "the scope is still there")
        if not extra: assert one(load(records(dv2)[0])["created"], id=dns)[0]["undo"] == ("removed" if when == "after" else "not done")
        code, text = go(t, argv, ["yes"], d=dv2)
        assert code == 0 and t.names() == Tenant(BASE).names() and "removed and gone from the tenant" in text, (extra, when, text)

# fix 3: in undo, a scope the run created that is now in use is reported in plain words, not as a raw error
for find in (False, True):
    dv3, pv3 = folder(); t = Tenant(BASE); go(t, ["apply", "--plan", pv3, "--write"], ["yes"], d=dv3)
    pay = [x["id"] for x in t.scopes if x["short_name"] == "payroll"][0]; prod = [x["id"] for x in t.scopes if x["short_name"] == "Production"][0]
    t.in_use[pay] = {"workspaces": {"count": 1, "ids": ["w9"]}}
    argv = ["undo", "--find-created", "--under", "Tenant:bob", "--write"] if find else ["undo", "--record", records(dv3)[0], "--write"]
    code, text = go(t, argv, ["yes"], d=dv3)
    assert code == 2 and "IN USE, not removed: Tenant:bob:Production:payroll. The tenant says: This scope has dependent objects; workspaces: 1 (IDs: w9)" in text, text
    assert "not removed: Tenant:bob:Production (a scope under it is in use)" in text and "Clear what depends on each in Secure Workload, then run the same undo command again" in text
    assert "error 422" not in text and "unprocessable" not in text.lower() and "Verified:" not in text
    assert t.writes().count(("DELETE", "/openapi/v1/app_scopes/" + pay)) == 1 and ("DELETE", "/openapi/v1/app_scopes/" + prod) not in t.writes(), "nothing retried, its parent left"
    assert sorted(x["short_name"] for x in t.scopes if x["id"].startswith("n")) == ["Production", "payroll"], "the rest was still removed"
    if not find:
        saved = load(records(dv3)[0])["created"]
        assert one(saved, id=pay)[0]["undo"] == "in use" and "workspaces: 1" in one(saved, id=pay)[0]["tenant_said"] and one(saved, id=prod)[0]["undo"] == "not removed"
    # once the customer clears it, the same undo finishes
    t.in_use.clear(); code, text = go(t, argv, ["yes"], d=dv3)
    assert code == 0 and t.names() == Tenant(BASE).names(), text
# the same in the undo of a change plan
t, dd, rec = built(); hr = [x["id"] for x in t.scopes if x["short_name"] == "HR"][0]; t.in_use[hr] = {"policies": {"count": 3, "ids": ["p1", "p2", "p3"]}}
code, text = undo(t, dd, rec)
assert code == 2 and "IN USE, not removed: Tenant:bob:Production:HR. The tenant says: This scope has dependent objects; policies: 3 (IDs: p1, p2, p3)" in text and "Reversed." not in text, text
assert sget(t, "pay")["short_name"] == "Payroll", "everything else was reversed"
t.in_use.clear(); code, text = undo(t, dd, rec); assert code == 0 and t.shape() == start

# fix 4: --no-commit makes the approved changes and leaves them uncommitted
dd, ppx = folder(plan3()); t = base2()
code, text = go(t, ["apply", "--plan", ppx, "--no-commit"] + ALLOW, ["yes", "yes", "yes"], d=dd)
assert code == 0 and not any("commit_dirty" in p for _, p in t.writes()) and kinds(t) == ["POST", "PUT", "PUT", "DELETE", "DELETE"], t.writes()
assert "Not committed, because --no-commit was given." in text and "select Commit Changes there when you are ready" in text and "Scope changes committed." not in text
home = sget(t, "h")
assert home["dirty_short_query"] == NEWHOME and home["short_query"] == {"type": "subnet", "field": "ip", "value": "10.99.1.0/24"}, "the new query is pending, the old one still in force"
rec = load(records(dd)[0]); assert rec["finished"] is True and rec["committed"] == "left uncommitted (--no-commit)"
# undo of an uncommitted run puts the query back
code, text = go(t, ["undo", "--record", records(dd)[0], "--write"], ["yes"], d=dd)
assert code == 0 and H.live_query(sget(t, "h")) == {"type": "subnet", "field": "ip", "value": "10.99.1.0/24"} and sorted(n for n, *_ in t.shape()) == sorted(n for n, *_ in start)
# it works for a create-only plan too, does nothing in a preview, and belongs to apply only
dv4, pv4 = folder(); t = Tenant(BASE); code, text = go(t, ["apply", "--plan", pv4, "--write", "--no-commit"], ["yes"], d=dv4)
assert kinds(t) == ["POST"] * 4 and "Not committed, because --no-commit was given." in text and load(records(dv4)[0])["committed"] == "left uncommitted (--no-commit)"
t = Tenant(BASE); code, text = go(t, ["apply", "--plan", pv4, "--no-commit"]); assert t.writes() == [] and "--no-commit does nothing without --write" in text
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--no-commit"]); assert t.writes() == [] and "do nothing without --write" in text
for cmd in (["export"], ["undo", "--record", "x"], ["check-labels", "--labels", "x"]):
    raises(lambda: go(Tenant(BASE), cmd + ["--no-commit"]), "--no-commit is only for the apply command")
# and it never weakens a prompt: changes and removals still need their typed yes
t = base2(); code, text = go(t, ["apply", "--plan", pp, "--no-commit", "--yes"] + ALLOW, ["no"]); assert code == 1 and t.writes() == []

# ---------------- Windows ----------------
# printed commands are copy-and-paste correct for the computer the helper runs on
real_name = os.name
try:
    os.name = "nt"
    line = H.command_line("undo", "--record", "2026-11-19 081200 bob - CSW Apply Record.json")
    assert line == 'py csw_scope_helper.py undo --record "2026-11-19 081200 bob - CSW Apply Record.json"', line
    assert H.command_line("undo", "--record", "plain.json") == "py csw_scope_helper.py undo --record plain.json"
    os.name = "posix"
    line = H.command_line("undo", "--record", "2026-11-19 081200 bob - CSW Apply Record.json")
    assert line == "python3 csw_scope_helper.py undo --record '2026-11-19 081200 bob - CSW Apply Record.json'", line
    assert H.command_line("undo", "--record", "it's $HOME.json") == "python3 csw_scope_helper.py undo --record 'it'\"'\"'s $HOME.json'"
finally:
    os.name = real_name
dw = tempfile.mkdtemp(); real_name = os.name
try:
    os.name = "nt"
    code, text = go(Tenant(BASE), ["apply", "--plan", plan_path, "--write", "--yes"], d=dw)
finally:
    os.name = real_name
assert 'To remove what this build created: py csw_scope_helper.py undo --record "' in text, text
# a scope name that Windows cannot use as a file name still gives a usable file name
tw = Tenant([dict(BASE[0])] + [dict(BASE[1], short_name="CON", name="Tenant:CON")] + BASE[2:])
dwn = tempfile.mkdtemp(); go(tw, ["export", "--under", "Tenant:CON"], d=dwn)
assert [f for f in os.listdir(dwn)] == ["%s CON scope - CSW Existing Scopes.json" % datetime.date.today().isoformat()]
# non-ASCII scope names: saved as UTF-8, and printing never crashes on a console that cannot show them
tu = Tenant([dict(BASE[0])] + [dict(BASE[1], short_name="Café 東京", name="Tenant:Café 東京")] + BASE[2:])
dun = tempfile.mkdtemp(); code, text = go(tu, ["export", "--under", "Tenant:Café 東京"], d=dun)
assert code == 0 and load(os.path.join(dun, os.listdir(dun)[0]))["scopes"][0]["short_name"] == "Café 東京"
narrow = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
real_out, real_argv = sys.stdout, sys.argv
try:
    sys.stdout = narrow; sys.argv = ["csw_scope_helper.py", "--version"]
    try:
        H.main()
    except SystemExit:
        pass
    assert narrow.errors == "backslashreplace", "main() makes the console tolerant"
    print("Tenant:Café 東京"); narrow.flush()
finally:
    sys.stdout, sys.argv = real_out, real_argv

# ---------------- on-premises: a private certificate with --ca-file ----------------
# No certificate or private key is kept in the repository. A throwaway certificate authority and a certificate for
# 127.0.0.1 are made with the openssl command when this test runs, in a temporary folder that is deleted afterward.
def make_test_certificates(folder):
    """Return (authority certificate, server certificate and key), or a reason they could not be made."""
    openssl = shutil.which("openssl")
    if not openssl:
        return None, "the openssl command is not installed"
    with open(os.path.join(folder, "ca.cnf"), "w") as fh:
        fh.write("[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n[dn]\nCN=CSW Scope Builder test authority\n"
                 "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
    with open(os.path.join(folder, "server.cnf"), "w") as fh:
        fh.write("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=127.0.0.1\n")
    with open(os.path.join(folder, "server.ext"), "w") as fh:
        fh.write("subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                 "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    steps = (["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2", "-config", "ca.cnf", "-keyout", "ca.key", "-out", "ca.pem"],
             ["req", "-newkey", "rsa:2048", "-nodes", "-sha256", "-config", "server.cnf", "-keyout", "server.key", "-out", "server.csr"],
             ["x509", "-req", "-sha256", "-days", "2", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
              "-extfile", "server.ext", "-out", "server.crt"])
    for step in steps:
        done = subprocess.run([openssl] + step, cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if done.returncode != 0:
            return None, "the openssl command failed at: openssl " + " ".join(step[:2])
    return (os.path.join(folder, "ca.pem"), os.path.join(folder, "server.crt"), os.path.join(folder, "server.key")), ""

# a missing or unreadable certificate file is reported plainly (this needs no certificate)
dca = tempfile.mkdtemp()
with open(os.path.join(dca, "not-a-cert.pem"), "w") as fh: fh.write("this is not a certificate")
raises(lambda: go(Tenant(BASE), ["export", "--ca-file", os.path.join(dca, "not-a-cert.pem")], d=dca), "certificate file could not be read")
raises(lambda: go(Tenant(BASE), ["export", "--ca-file", os.path.join(dca, "missing.pem")], d=dca), "certificate file could not be read")
assert not [f for f in os.listdir(HERE) if f.lower().endswith((".pem", ".key", ".crt", ".p12", ".pfx"))], "no certificate or key file is kept in tests/"

certs_dir = tempfile.mkdtemp()
made, why_not = make_test_certificates(certs_dir)
if made is None:
    print("SKIPPED: the --ca-file test over a real verified connection, because " + why_not + ". Install openssl and run again to include it.")
else:
    ca_file, server_cert, server_key = made
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(BASE if self.path == "/openapi/v1/app_scopes" else []).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def log_message(self, *a): pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(server_cert, server_key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = "https://127.0.0.1:%d" % server.server_address[1]
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
    def real(argv, d):
        lines = []
        code = H.run(argv + ["--out-dir", d], out=lines.append, env=dict(ENV, CSW_URL=url), sleep=lambda s: None)
        return code, "\n".join(lines)
    try:
        # without the certificate file the helper refuses the connection, and says what to do
        raises(lambda: real(["export"], dca), "--ca-file")
        assert [f for f in os.listdir(dca) if f.endswith(".json")] == []
        # with it, the same call works over a verified connection
        code, text = real(["export", "--ca-file", ca_file], dca)
        assert code == 0 and "Saved 4 scopes" in text and len([f for f in os.listdir(dca) if f.endswith(".json")]) == 1
        # a different authority's certificate does not help
        other_dir = tempfile.mkdtemp(); other, _ = make_test_certificates(other_dir)
        raises(lambda: real(["export", "--ca-file", other[0]], dca), "--ca-file")
        shutil.rmtree(other_dir, ignore_errors=True)
    finally:
        server.shutdown()
        shutil.rmtree(certs_dir, ignore_errors=True)

print("ALL PASS")
