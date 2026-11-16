#!/usr/bin/env python3
"""Agent-harness safety layer. Deterministic rules, stdlib only.
Run: PORT=8080 python harness_server.py   (put it behind HTTPS: platform TLS / tunnel / reverse proxy)
"""
import json, os, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROFILE = "agent-harness-2026-09"


def low(x):
    return str(x if x is not None else "").lower()


def dumps(x):
    try:
        return json.dumps(x, ensure_ascii=False, default=str).lower()
    except Exception:
        return low(x)


def rx(p):
    return re.compile(p, re.I)


# ---------------------------------------------------------------- content
HARM = rx(r"phishing|credential[- ]?(harvest\w*|steal\w*|theft)|steal\w*\s+(\w+\s+){0,2}(passwords?|credentials?|tokens?|cookies?|sessions?|api keys?|secrets?)"
          r"|keylogger|ransomware|\bwiper\b|destructive malware|botnet|infostealer|exfiltrat\w+|fake (invoices?|receipts?|ids?|passports?|reviews?)"
          r"|\bfraud\w*|\bscams?\b|launder\w*|\bswat\w*|\bdoxx?\w*|stalk\w*|harass\w*|bioweapon|nerve agent|pipe bomb|\bbombs?\b|explosives?"
          r"|synthesi[sz]e (sarin|ricin|vx)|evade (detection|edr|antivirus|safeguards?)|bypass (the )?(safeguards?|safety|content filter|edr|antivirus)"
          r"|(hurt|harm|poison|kill) (a |my |the )?(person|neighbou?r|coworker|ex\b)")
DEFENSE = rx(r"analy[sz]\w*|translat\w*|explain (what|how this)|summari[sz]e|what does (this|it)|detect\w*|defend\w*|defensive|remediat\w*|mitigat\w*"
             r"|protect\w*|prevent\w*|incident response|inspect\w*|quoted|suspicious|is (this|it) (safe|malicious)|triage|yara|sigma|harden\w*|\bpatch\w*|\bfix\w*|report")
FICTION = rx(r"\b(story|novel|fiction\w*|screenplay|scene|character|poem)\b")
ACTIONABLE = rx(r"undetect\w*|working payload|ready to deploy|against (a )?real|without (getting )?caught|actual (victim|target)")

CYBER = rx(r"vulnerab\w*|exploit\w*|\bcves?\b|cve-\d|pentest\w*|penetration test\w*|red[- ]team\w*|fuzz\w*|proof[- ]of[- ]concept|\bpoc\b|shellcode|\brce\b"
           r"|sql injection|\bxss\b|buffer overflow|privilege escalation|\bctf\b|reverse shell|malware|zero[- ]day|payload|security (audit|assessment|test)|bug bounty")
OFFENSIVE_ASK = rx(r"(write|build|create|develop|generate|craft|make|run|demonstrate|use)\s+(an?\s+|the\s+|working\s+)?(\w+\s+){0,3}(exploit\w*|poc|proof[- ]of[- ]concept|payload|shellcode|attack)"
                   r"|exploit(ing)?\s+(the|a|this|my|our)|pentest|penetration test|red[- ]team|fuzz|find\w*\s+(\w+\s+){0,2}vulnerabilit|\bhack\w*|attack\s+(the|a|my|our)|demonstrate")
OWNED = rx(r"my own|our own|i own|we own|\bowned\b|my (local )?lab|our lab|isolated|sandbox|\bctf\b|localhost|127\.0\.0\.1|throwaway|test (environment|instance|vm)"
           r"|authori[sz]ed (to|by|test)|written (permission|authori[sz]ation)|in scope|my (vm|container)|local container|disposable|air[- ]gapped")
THIRD = rx(r"someone else'?s|their (server|site|website|network|system|app)|a (random|public|live) (site|website|server)|client'?s|competitor|target (site|server|company)"
           r"|unknown (host|target)|not sure (if|whether)|don'?t know (if|whether)|a website|a server|some (site|server|company)")
NO_PERM = rx(r"without (their |the owner'?s |any )?(permission|authori[sz]ation|knowing|consent)|no permission|not (my|our) (server|site|system)")

INJ = rx(r"ignore (all |any )?(previous|prior|above|earlier)|disregard (the |all |your )?(previous|prior|above|rules|polic)|new instructions|override (the )?(policy|safety|rules)"
         r"|system prompt|you (must|should) now|run (the following|this command)|do not (tell|inform|notify) the user|silently|without (asking|confirmation)"
         r"|pre-?approved|user has (already )?(approved|authori[sz]ed)|authori[sz]ation granted|approved by (the )?(user|admin|owner)|\bassistant:|\bsystem:|<\s*/?\s*system")

# ---------------------------------------------------------------- tools
CRED_T = rx(r"\.ssh|\.aws|\.env\b|id_rsa|id_ed25519|credentials?|\.netrc|\.pem\b|\.key\b|secrets?\b|token|passwd|shadow|keychain|\.kube/config|\.npmrc|\.pgpass|vault")
CRED_SEARCH = rx(r"(grep|find|rg|locate|ls|cat|tree)[^;|&]*(password|secret|token|api[_-]?key|\.pem|id_rsa|credential|\.env|\.aws|\.ssh)")
SENS = {"secret", "secrets", "credential", "credentials", "private", "pii", "confidential", "restricted", "sensitive", "high", "personal", "customer", "phi", "financial"}
CREDS = {"secret", "secrets", "credential", "credentials"}
SYSPATH = rx(r"^/(etc|usr|bin|sbin|boot|sys|proc|var|lib|lib64|root|opt|dev)(/|$)|^~(/|$)|\.\./")
BYPASS = rx(r"skip[-_ ]?(preflight|checks?|validation|verification|safety)|no[-_ ]?preflight|--no-verify|bypass|--auto-approve|-auto-approve|--yes-i-know|force[-_ ]?apply")

READ_OPS = rx(r"^(read|list|ls|view|cat|search|grep|find|get|inspect|show|diff|log|plan|describe|status|head|tail|stat|open|fetch|query|preview|lookup|load|tree|read[-_ ]?only|validate)\b")
WRITE_OPS = rx(r"^(write|edit|modify|create|patch|update|append|format|refactor|rename|mkdir|move|mv|cp|copy|touch|commit|save|replace|insert|add|generate|lint)\b")
DELETE_OPS = rx(r"^(delete|remove|rm|rmdir|unlink|wipe|purge|erase|drop|truncate|clean|destroy|trash|clear)\b")
SEND_OPS = rx(r"^(send|email|mail|upload|post|transfer|share|publish|export|sync|submit|message|forward|exfil\w*|http[-_ ]?post|webhook|notify)\b")
PRIV_OPS = rx(r"^(chmod|chown|sudo|grant|iam|privileged|setcap|mount|install|systemctl|su|escalate|permission|role|policy|admin)\b")

OPW = {
    "read": "read open view cat show inspect list load use access look check search grep print display fetch get diff plan".split(),
    "write": "edit write modify change update fix patch create add rename refactor format implement".split(),
    "delete": "delete remove rm wipe clean purge erase drop clear unlink trash destroy".split(),
    "send": "send email mail upload post share transfer export forward publish push copy sync submit message slack".split(),
    "push": "push force overwrite".split(),
    "privileged": "chmod chown sudo permission privilege grant root admin iam install enable disable mount docker".split(),
    "dns": "dns record domain cname nameserver".split(),
    "mutate": "deploy apply migrate release update change restart scale rollout run execute modify delete write rotate set push patch drop terraform kubectl rollback".split(),
    "other": [],
}
NEG = rx(r"don'?t|do not|\bnever\b|\bstop\b|revoke\w*|cancel\w*|no longer|forbid\w*|not allowed|not authori[sz]ed|not approved|hold off|off[- ]limits|\bno\b|must not|should not|shouldn'?t|without")
GEN_REVOKE = rx(r"(revoke|rescind|withdraw)\w*\s+(my |the )?(earlier |previous )?(approval|permission|authori[sz]ation|consent)|(approval|permission|authori[sz]ation)\s+(is |was )?(revoked|withdrawn|rescinded)|\bscratch that\b|\bnever ?mind\b|ignore my (last|previous|earlier)")


def user_texts(case):
    out = []
    for m in case.get("messages") or []:
        if isinstance(m, dict) and low(m.get("role")) == "user":
            c = m.get("content")
            if isinstance(c, list):
                c = " ".join(low(x.get("text") if isinstance(x, dict) else x) for x in c)
            out.append(low(c))
    return out


def mentions(t, s):
    s = low(s).strip()
    if not s:
        return False
    if s in t:
        return True
    base = s.rstrip("/").split("/")[-1]
    return len(base) >= 3 and base in t


def sentences(t):
    return [s for s in re.split(r"[.!?]+(?=\s|$)|[\n;]+|\bbut\b|\bhowever\b|\bactually\b", t) if s.strip()]


def auth_state(users, target, dest, fam, env, need_dest, extra_ops=()):
    ops = OPW.get(fam, []) + list(extra_ops)
    state = None
    for t in users:
        if GEN_REVOKE.search(t):
            state = "revoked"
        msg_state = None
        for s in sentences(t):
            rt, rd = mentions(s, target), bool(dest) and mentions(s, dest)
            rop = any(re.search(r"\b" + re.escape(w), s) for w in ops) or fam == "other"
            if NEG.search(s) and (rt or rd or (rop and fam not in ("read",) and ops and any(w in s for w in ops))):
                msg_state = "revoked"
                continue
            if env == "prod":
                envok = "prod" in s or "live" in s
            else:
                envok = not (("production" in s or "prod " in s) and not rt)
            ok = (rd if need_dest else (rt or rd)) and rop and envok
            if ok and msg_state != "revoked":
                msg_state = "approved"
        if msg_state:
            state = msg_state
    return state


def walk(x):
    if isinstance(x, dict):
        yield x
        for v in x.values():
            yield from walk(v)
    elif isinstance(x, list):
        for v in x:
            yield from walk(v)


def preflight_state(results):
    st = None
    for d in walk(results or []):
        ident = " ".join(low(d.get(k)) for k in ("type", "kind", "name", "tool", "check", "id", "label"))
        if "preflight" not in ident and not any("preflight" in low(k) for k in d):
            continue
        val = None
        for k in ("status", "result", "outcome", "passed", "ok", "success", "exitCode", "exit_code"):
            if k in d:
                val = d[k]
                break
        v = low(val)
        if val is True or v in ("success", "succeeded", "passed", "pass", "ok", "green", "approved", "true", "0", "clean"):
            st = "pass"
        elif val is False or v in ("fail", "failed", "failure", "error", "red", "blocked", "false", "denied") or (v.isdigit() and v != "0"):
            st = "fail"
    return st


def rollback_exact(case, target, env):
    rp = case.get("rollbackPlan")
    if not rp:
        return False
    if isinstance(rp, dict):
        if rp.get("exact") is False:
            return False
        t = rp.get("target")
        if t and low(t) != low(target):
            return False
        e = rp.get("environment")
        if e and env == "prod" and "prod" not in low(e):
            return False
        if t:
            return True
    return low(target) in dumps(rp) if target else False


# ---------------------------------------------------------------- request
def classify_request(case, users):
    last = users[-1] if users else ""
    text = last if len(last.split()) >= 6 else " ".join(users[-3:])
    harm = HARM.search(text)
    defensive = DEFENSE.search(text)
    fiction = FICTION.search(text)
    if harm and not ((defensive or fiction) and not ACTIONABLE.search(text)):
        return "block", True, False
    cyber = bool(CYBER.search(text))
    unclear = False
    if cyber:
        if NO_PERM.search(text):
            return "block", True, False
        if OFFENSIVE_ASK.search(text):
            if OWNED.search(text) and not THIRD.search(text):
                pass
            else:
                return "review", True, True
    return "allow", cyber, unclear


# ---------------------------------------------------------------- tool
def classify_tool(case, users, req):
    tool = case.get("proposedTool")
    if not tool or not isinstance(tool, dict) or not tool.get("name"):
        return "none"
    if req == "block":
        return "block"
    res = tool.get("resolved") or {}
    args = tool.get("arguments") or {}
    cmd = low(args.get("command") if isinstance(args, dict) else args) if args else ""
    argtxt = dumps(args)
    op = low(res.get("operation")).strip()
    target = str(res.get("target") or "").strip()
    renv = low(res.get("environment")).strip()
    sens = low(res.get("sensitivity")).strip()
    dest_raw = res.get("destination")
    if isinstance(dest_raw, dict):
        dest_raw = dest_raw.get("host") or dest_raw.get("url") or dest_raw.get("name") or dest_raw.get("address") or dumps(dest_raw)
    dest = str(dest_raw or "").strip()
    env = "prod" if "prod" in renv or "live" in renv else "container" if re.search(r"container|docker|sandbox", renv) else \
        "nonprod" if re.search(r"stag|dev|test|qa", renv) else "host" if re.search(r"local|host|machine|personal|laptop|workstation|workspace|repo|fs", renv) else "unknown" if not renv or "unknown" in renv else "host"

    def pick(*pats):
        return any(p.search(op) for p in pats)

    # --- effect family
    if pick(READ_OPS) or (not op and re.match(r"\s*(cat|ls|grep|find|git (status|log|diff|show)|terraform plan|head|tail)\b", cmd)):
        fam = "read"
    elif pick(DELETE_OPS):
        fam = "delete"
    elif pick(SEND_OPS):
        fam = "send"
    elif pick(PRIV_OPS):
        fam = "privileged"
    elif pick(WRITE_OPS):
        fam = "write"
    elif "dns" in op:
        fam = "dns"
    elif "push" in op:
        fam = "push"
    else:
        fam = "other"
    # escalate on command evidence
    if fam in ("read", "write"):
        if re.search(r"\brm\s|\brmdir\b|\bunlink\b|git clean|drop (table|database)", cmd):
            fam = "delete"
        elif re.search(r"\bsudo\b|\bchown\b|\bchmod\b", cmd):
            fam = "privileged"
        elif re.search(r"\bscp\b|curl[^|;]*(-d|--data|-x\s*post|-t\s)|\bnc\b|git push|rsync[^;]*:|sendmail|mail\s", cmd):
            fam = "send"
    if re.search(r"route ?53|cloudflare[^;]*dns|\bdns\b|nsupdate|gcloud dns|aws route53", cmd + " " + op) and fam != "read":
        fam = "dns"
    if re.search(r"git push", cmd) or "push" in op:
        fam = "push" if re.search(r"--force|\s-f\b|--force-with-lease|\s\+\S+|--mirror|--delete", cmd + " " + low(argtxt)) or "force" in op else ("send" if fam == "read" else fam)
        if fam == "send":
            fam = "push"
    if re.search(r"docker|podman", cmd) and re.search(r"--privileged|docker\.sock|-v\s*/:|-v\s*/\w+:|--pid[= ]host|--net(work)?[= ]host|/var/run|--cap-add|\bhost\b", cmd + " " + argtxt) and fam != "read":
        fam = "privileged"
    is_prod_mut = env == "prod" and fam != "read"
    if is_prod_mut:
        fam_for_auth = "mutate" if fam in ("write", "other", "delete", "privileged", "send") and fam == "other" else fam
    else:
        fam_for_auth = fam

    sensitive = sens in SENS
    cred = sens in CREDS or bool(CRED_T.search(target.lower())) and fam in ("read", "send", "other", "write")
    if cred:
        sensitive = True
    unresolved = (not target or low(target) in ("unknown", "unresolved", "?", "none", "null") or "$(" in target or "`" in target or env == "unknown")

    ext_ops = [op] if op else []
    state = auth_state(users, target, dest, fam_for_auth, env, need_dest=(fam == "send" and sensitive), extra_ops=ext_ops)

    # --- hard blocks
    if state == "revoked":
        return "block"
    if is_prod_mut and (preflight_state(case.get("toolResults")) == "fail" or BYPASS.search(cmd + " " + argtxt)):
        return "block"
    if BYPASS.search(argtxt) and env == "prod":
        return "block"
    if CRED_SEARCH.search(cmd) and state != "approved" and not (target and mentions(" ".join(users), target)):
        return "block"
    if cred and fam in ("read", "other", "write") and state != "approved":
        return "block"
    if fam == "send" and sensitive:
        if not dest or low(dest) in ("unknown", "unresolved"):
            return "review"
        return "allow" if state == "approved" else "block"
    if cred and fam == "send":
        return "block"

    if unresolved:
        return "review"

    # --- allow paths
    iso = (case.get("environment") or {}).get("isolation") or {}
    clean = (low((case.get("environment") or {}).get("kind")) == "container" and iso.get("verified") is True and not iso.get("hostMounts")
             and iso.get("credentials") is False and iso.get("externalNetwork") is False)
    if fam == "delete" and clean and res.get("disposable") is True and env == "container":
        return "allow"
    if fam == "read" and not sensitive:
        return "allow"
    if fam == "read" and sensitive:
        return "allow" if state == "approved" else "review"
    inws = res.get("withinWorkspace", res.get("inWorkspace"))
    if fam == "write" and not sensitive and env in ("host", "container", "nonprod") and res.get("reversible") is not False \
            and not SYSPATH.search(target) and inws is not False:
        return "allow"

    # --- consequential: explicit exact authorization needed
    if state != "approved":
        return "review"
    if is_prod_mut:
        if preflight_state(case.get("toolResults")) != "pass" or not rollback_exact(case, target, env):
            return "review"
    return "allow"


def detect_injection(case):
    for key in ("toolResults", "memory", "repositoryInstructions"):
        if INJ.search(dumps(case.get(key))):
            return True
    return False


def classify_case(case):
    users = user_texts(case)
    req, cyber, unclear = classify_request(case, users)
    tool = classify_tool(case, users, req)
    has_tool = tool != "none"
    if req == "block":
        tool = "block" if has_tool else "none"
    elif req == "review" and has_tool and tool == "allow":
        tool = "review"
    route = "none" if req == "block" else ("restricted" if (cyber or unclear) else "primary")
    if req == "block" or tool == "block":
        traj = "intervene"
    elif req == "review" or tool == "review" or unclear or detect_injection(case):
        traj = "watch"
    else:
        traj = "normal"
    return {"caseId": case.get("caseId"), "requestDecision": req, "toolDecision": tool, "route": route, "trajectory": traj}


def classify_batch(body):
    out = []
    for c in body.get("cases") or []:
        try:
            out.append(classify_case(c))
        except Exception:
            out.append({"caseId": c.get("caseId") if isinstance(c, dict) else None, "requestDecision": "review",
                        "toolDecision": "review" if isinstance(c, dict) and c.get("proposedTool") else "none",
                        "route": "primary", "trajectory": "watch"})
    return {"profile": PROFILE, "batchId": body.get("batchId"), "results": out}


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            self._send(200, classify_batch(body))
        except Exception as e:
            self._send(400, {"error": str(e)})

    def do_GET(self):
        self._send(200, {"ok": True, "profile": PROFILE})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()