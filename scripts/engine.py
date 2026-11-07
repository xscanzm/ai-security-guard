# -*- coding: utf-8 -*-
"""ai-security-guard 扫描引擎：找文件、跑规则、打码、算分。

这一层不负责输出格式，也不负责退出码；guard.py 负责 CLI。
"""

import fnmatch
import json
import os
import re
import sys
import unicodedata
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import rules as R


SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".next", ".nuxt", "target", "vendor", "coverage",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".ai-guard", ".tox",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".exe", ".dll", ".so",
    ".dylib", ".pyc", ".class", ".jar", ".woff", ".woff2", ".ttf", ".otf",
    ".mp3", ".mp4", ".mov", ".avi", ".sqlite", ".db", ".bin", ".lock",
}
MAX_FILE_SIZE = 1_500_000
MAX_SCAN_FILES = 5000

SAMPLE_PHONES = {"13800138000", "13900139000", "18888888888", "13800000000", "13000000000"}
SAMPLE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "test.local",
    "your-domain.com", "domain.com", "email.com", "xxx.com", "foo.com", "bar.com",
}
SAMPLE_NAMES = {"张三", "李四", "王五", "赵六", "某某", "客户", "联系人", "姓名", "先生", "女士"}

PHONE_RE = re.compile(r"(?<!\d)(?:\+?86[-\s]?)?(1[3-9]\d{9})(?!\d)")
ID_RE = re.compile(r"(?<!\d)(\d{17}[\dXx])(?!\d)")
BANK_RE = re.compile(r"(?<![\d-])((?:\d[ -]?){15,18}\d)(?![\d-])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
NAME_RE = re.compile(r"(?:客户|联系人|签约人|姓名|对接人)\s*[：:]\s*([\u4e00-\u9fa5]{2,4})(?=[\s，,。;；]|$)")
MONEY_RE = re.compile(r"(合同(?:金额|总价|总金额)|成交价|报价|底价|返点|折扣|单价)\s*[：:为]?\s*[¥￥]?\s*(\d[\d,]*(?:\.\d+)?)\s*(万|万元|元|块)?")
SALARY_RE = re.compile(r"(工资|薪资|月薪|年薪|底薪|绩效|提成)\s*[：:为]?\s*[¥￥]?\s*(\d[\d,]*(?:\.\d+)?)\s*(k|K|万|元|块)?")
INTERNAL_RE = re.compile(r"(内部资料|内部文件|机密|绝密|仅限内部|请勿外传|confidential|internal use only)", re.I)
ADDRESS_RE = re.compile(r"(?:地址|住址|门店地址|公司地址|收货地址)\s*[：:]\s*([^\n，。;；]{6,60})")
WECHAT_RE = re.compile(r"(?:微信|wechat|vx|VX|QQ)\s*[：:号]?\s*([A-Za-z][A-Za-z0-9_-]{5,19}|\d{5,12})")
SECRETISH_RE = re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']")

_COMPILED = {}

SECRET_RULES = {"C001", "C002", "C003", "C113", "C114"}


def _compile(rule):
    key = (rule["pattern"], rule["flags"], rule["multiline"])
    if key not in _COMPILED:
        flags = rule["flags"] | (re.MULTILINE if rule["multiline"] else 0)
        try:
            _COMPILED[key] = re.compile(rule["pattern"], flags)
        except re.error:
            _COMPILED[key] = None
    return _COMPILED[key]


def safe_read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(MAX_FILE_SIZE + 1)[:MAX_FILE_SIZE]
    except OSError:
        return ""


def rel_path(root, path):
    return os.path.relpath(path, root).replace("\\", "/")


def glob_match(rel, globs):
    p = rel.replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    for g in globs:
        gg = g.replace("\\", "/")
        if gg.startswith("*."):
            if name.lower().endswith(gg[1:].lower()):
                return True
        elif "/" in gg:
            if fnmatch.fnmatch(p, gg) or p.endswith("/" + gg) or fnmatch.fnmatch(p, "*/" + gg):
                return True
        else:
            if fnmatch.fnmatch(name, gg):
                return True
    return False


def load_ignore(root):
    patterns = []
    path = os.path.join(root, ".ai-guardignore")
    if os.path.isfile(path):
        for line in safe_read(path).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line.replace("\\", "/").lstrip("./"))
    return patterns


def ignored(rel, patterns):
    rel = rel.replace("\\", "/")
    name = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        if pat.endswith("/"):
            if rel.startswith(pat) or ("/" + pat) in ("/" + rel):
                return True
        elif fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat):
            return True
    return False


def iter_files(root):
    root = os.path.abspath(root)
    ignore = load_ignore(root)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git"))
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = rel_path(root, path)
            if ignored(rel, ignore):
                continue
            if os.path.splitext(name)[1].lower() in BINARY_EXT:
                continue
            try:
                if os.path.getsize(path) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            head = safe_read(path)[:400]
            if "ai-guard:ignore-file" in head:
                continue
            count += 1
            if count > MAX_SCAN_FILES:
                return
            yield path, rel


def load_terms(root):
    path = os.path.join(root, ".ai-guard", "terms.txt")
    terms = []
    if os.path.isfile(path):
        for line in safe_read(path).splitlines():
            line = line.strip()
            if line and not line.startswith("#") and len(line) >= 2:
                terms.append(line)
    return terms


def line_at(text, pos):
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end]


def line_no(text, pos):
    return text.count("\n", 0, pos) + 1


def mask_secret(value, keep=4):
    s = value.strip()
    if len(s) <= keep + 2:
        return s[:2] + "***"
    return s[:keep] + "****" + s[-4:]


def mask_phone(value):
    digits = re.sub(r"\D", "", value)
    return digits[:3] + "****" + digits[-4:] if len(digits) >= 11 else "***"


def mask_id(value):
    digits = re.sub(r"\D", "", value)
    return digits[:6] + "********" + digits[-4:] if len(digits) >= 14 else "***"


def mask_bank(value):
    digits = re.sub(r"\D", "", value)
    return "**** **** **** " + digits[-4:] if len(digits) >= 8 else "***"


def mask_email(value):
    local, _, domain = value.partition("@")
    return (local[:1] + "***@" + domain) if domain else "***"


def mask_name(value):
    return value[0] + "**" if len(value) > 1 else "*"


def mask_money(value):
    digits = re.sub(r"\D", "", value)
    return digits[0] + "***" if digits else "***"


def mask_address(value):
    return value[:6] + "***" if len(value) > 6 else value[:1] + "***"


def mask_value(value, kind):
    if kind == "none":
        return value
    if kind == "phone":
        return mask_phone(value)
    if kind == "id":
        return mask_id(value)
    if kind == "bank":
        return mask_bank(value)
    if kind == "email":
        return mask_email(value)
    if kind == "name":
        return mask_name(value)
    if kind == "money":
        return mask_money(value)
    if kind == "address":
        return mask_address(value)
    if kind == "generic":
        return value[:1] + "***" if value else "***"
    return mask_secret(value)


def mask_line(line, match_text, kind):
    if kind == "none":
        s = " ".join(line.split())
        return s[:180] + "…" if len(s) > 180 else s
    s = " ".join(line.split())
    if match_text:
        masked = mask_value(match_text, kind)
        s = s.replace(match_text, masked, 1)
        if len(s) > 180:
            s = s[:180] + "…"
    return s


def allowed(rule, line):
    low = line.lower()
    for pat in rule.get("allow", []):
        try:
            if re.search(pat, low, re.I):
                return True
        except re.error:
            continue
    return False


def finding(rule_id, domain, severity, title, path, line, snippet, why, fix):
    return {
        "id": rule_id, "domain": domain, "severity": severity, "title": title,
        "path": path, "line": line, "snippet": snippet, "why": why, "fix": list(fix),
    }


def id_checksum_ok(s):
    if len(s) != 18 or not s[:17].isdigit():
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    codes = "10X98765432"
    total = sum(int(c) * w for c, w in zip(s[:17], weights))
    return codes[total % 11] == s[17].upper()


def luhn_ok(s):
    digits = [int(c) for c in s if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _doc_findings(rel, text, terms):
    out = []
    for m in PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(1))
        if digits in SAMPLE_PHONES or digits.endswith("0000"):
            continue
        out.append(finding("D001", "doc", "high", R.SPECIAL["D001"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), m.group(0), "phone"),
                           R.SPECIAL["D001"]["why"], R.SPECIAL["D001"]["fix"]))
    for m in ID_RE.finditer(text):
        if not id_checksum_ok(m.group(1)):
            continue
        out.append(finding("D002", "doc", "critical", R.SPECIAL["D002"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), m.group(0), "id"),
                           R.SPECIAL["D002"]["why"], R.SPECIAL["D002"]["fix"]))
    for m in BANK_RE.finditer(text):
        raw = m.group(1)
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 16 or len(set(digits)) <= 2:
            continue
        if ID_RE.fullmatch(digits) and id_checksum_ok(digits):
            continue
        if not luhn_ok(digits):
            continue
        out.append(finding("D003", "doc", "critical", R.SPECIAL["D003"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), raw, "bank"),
                           R.SPECIAL["D003"]["why"], R.SPECIAL["D003"]["fix"]))
    for m in EMAIL_RE.finditer(text):
        addr = m.group(0)
        domain = addr.rsplit("@", 1)[-1].lower()
        if domain in SAMPLE_EMAIL_DOMAINS or "example" in domain:
            continue
        out.append(finding("D004", "doc", "medium", R.SPECIAL["D004"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), addr, "email"),
                           R.SPECIAL["D004"]["why"], R.SPECIAL["D004"]["fix"]))
    for m in NAME_RE.finditer(text):
        name = m.group(1)
        if name in SAMPLE_NAMES:
            continue
        out.append(finding("D005", "doc", "medium", R.SPECIAL["D005"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), name, "name"),
                           R.SPECIAL["D005"]["why"], R.SPECIAL["D005"]["fix"]))
    for m in MONEY_RE.finditer(text):
        num = m.group(2)
        unit = m.group(3) or ""
        if len(re.sub(r"\D", "", num)) < 3 and unit not in ("万", "万元"):
            continue
        out.append(finding("D006", "doc", "high", R.SPECIAL["D006"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), num, "money"),
                           R.SPECIAL["D006"]["why"], R.SPECIAL["D006"]["fix"]))
    for m in SALARY_RE.finditer(text):
        num = m.group(2)
        unit = m.group(3) or ""
        if len(re.sub(r"\D", "", num)) < 3 and unit not in ("k", "K", "万"):
            continue
        out.append(finding("D007", "doc", "high", R.SPECIAL["D007"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), num, "money"),
                           R.SPECIAL["D007"]["why"], R.SPECIAL["D007"]["fix"]))
    for m in INTERNAL_RE.finditer(text):
        line = line_at(text, m.start())
        if re.search(r"示例|不要|禁止|检测|规则|会抓|反例", line):
            continue
        out.append(finding("D008", "doc", "low", R.SPECIAL["D008"]["title"], rel, line_no(text, m.start()),
                           mask_line(line, m.group(0), "generic"),
                           R.SPECIAL["D008"]["why"], R.SPECIAL["D008"]["fix"]))
    for term in terms:
        m = re.search(re.escape(term), text, re.I)
        if not m:
            continue
        out.append(finding("D009", "doc", "critical", R.SPECIAL["D009"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), m.group(0), "name"),
                           R.SPECIAL["D009"]["why"], R.SPECIAL["D009"]["fix"]))
    for m in ADDRESS_RE.finditer(text):
        addr = m.group(1).strip()
        if len(addr) < 6 or re.search(r"示例|xxx|某市|某区", addr, re.I):
            continue
        out.append(finding("D010", "doc", "medium", R.SPECIAL["D010"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), addr, "address"),
                           R.SPECIAL["D010"]["why"], R.SPECIAL["D010"]["fix"]))
    for m in WECHAT_RE.finditer(text):
        value = m.group(1)
        if re.search(r"example|xxxxx|your|test|demo|123456|示例", value, re.I):
            continue
        out.append(finding("D011", "doc", "medium", R.SPECIAL["D011"]["title"], rel, line_no(text, m.start()),
                           mask_line(line_at(text, m.start()), value, "generic"),
                           R.SPECIAL["D011"]["why"], R.SPECIAL["D011"]["fix"]))
    return out


def _frontmatter(text):
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.S)
    return m.group(1) if m else ""


def _frontmatter_value(fm, key):
    lines = fm.splitlines()
    out = []
    capture = False
    for line in lines:
        if re.match(r"^%s\s*:" % re.escape(key), line):
            capture = True
            out.append(line.split(":", 1)[1].strip())
            continue
        if capture:
            if re.match(r"^\S", line):
                break
            out.append(line.strip())
    return " ".join(x for x in out if x).strip()


def _skill_findings(rel, text):
    out = []
    if not rel.endswith("SKILL.md"):
        return out
    fm = _frontmatter(text)
    tools = _frontmatter_value(fm, "allowed-tools")
    if tools:
        low = tools.lower()
        if "bash" in low:
            bash_tokens = re.findall(r"bash(?:\([^)]*\))?", low)
            for token in bash_tokens:
                if token == "bash" or "*" in token:
                    out.append(finding("S001", "skill", "critical", R.SPECIAL["S001"]["title"], rel, 1,
                                       "allowed-tools: " + token,
                                       R.SPECIAL["S001"]["why"], R.SPECIAL["S001"]["fix"]))
                    break
        if "write" in low:
            write_tokens = re.findall(r"write(?:\([^)]*\))?", low)
            for token in write_tokens:
                if token == "write" or "*" in token:
                    out.append(finding("S009", "skill", "high", R.SPECIAL["S009"]["title"], rel, 1,
                                       "allowed-tools: " + token,
                                       R.SPECIAL["S009"]["why"], R.SPECIAL["S009"]["fix"]))
                    break
    return out


def _json_load(text):
    try:
        return json.loads(text)
    except Exception:
        cleaned = re.sub(r"^\s*//.*$", "", text, flags=re.M)
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        try:
            return json.loads(cleaned)
        except Exception:
            return None


def _is_broad_dir(value):
    s = str(value).strip().replace("\\", "/")
    if s in ("/", "~", "$HOME", "C:", "C:/", "D:", "D:/", "E:", "E:/"):
        return True
    return bool(re.fullmatch(r"[A-Za-z]:/?", s))


def _settings_findings(rel, text, root):
    out = []
    data = _json_load(text)
    if data is None:
        if re.search(r"\"defaultMode\"\s*:\s*\"bypassPermissions\"", text):
            out.append(finding("P001", "perm", "critical", R.SPECIAL["P001"]["title"], rel, 1,
                               "defaultMode: bypassPermissions", R.SPECIAL["P001"]["why"], R.SPECIAL["P001"]["fix"]))
        if re.search(r"\"Bash\s*\(\s*\*\s*\)\"", text):
            out.append(finding("P002", "perm", "critical", R.SPECIAL["P002"]["title"], rel, 1,
                               "allow: Bash(*)", R.SPECIAL["P002"]["why"], R.SPECIAL["P002"]["fix"]))
        return out
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode == "bypassPermissions":
        out.append(finding("P001", "perm", "critical", R.SPECIAL["P001"]["title"], rel, 1,
                           "defaultMode: bypassPermissions", R.SPECIAL["P001"]["why"], R.SPECIAL["P001"]["fix"]))
    if mode == "acceptEdits":
        out.append(finding("P012", "perm", "medium", R.SPECIAL["P012"]["title"], rel, 1,
                           "defaultMode: acceptEdits", R.SPECIAL["P012"]["why"], R.SPECIAL["P012"]["fix"]))
    allow = perms.get("allow") or []
    if isinstance(allow, list):
        for item in allow:
            s = str(item)
            if re.match(r"^Bash\s*(\(\s*\*\s*\))?$", s, re.I):
                out.append(finding("P002", "perm", "critical", R.SPECIAL["P002"]["title"], rel, 1,
                                   "allow: " + s, R.SPECIAL["P002"]["why"], R.SPECIAL["P002"]["fix"]))
                break
    dirs = perms.get("additionalDirectories") or []
    if isinstance(dirs, list):
        for d in dirs:
            if _is_broad_dir(d):
                out.append(finding("P003", "perm", "high", R.SPECIAL["P003"]["title"], rel, 1,
                                   "additionalDirectories: " + str(d),
                                   R.SPECIAL["P003"]["why"], R.SPECIAL["P003"]["fix"]))
                break
    if data.get("enableAllProjectMcpServers") is True:
        out.append(finding("P004", "perm", "medium", R.SPECIAL["P004"]["title"], rel, 1,
                           "enableAllProjectMcpServers: true", R.SPECIAL["P004"]["why"], R.SPECIAL["P004"]["fix"]))
    if rel.endswith("settings.local.json") and not gitignore_has(root, "settings.local.json"):
        out.append(finding("P011", "perm", "medium", R.SPECIAL["P011"]["title"], rel, 1,
                           "settings.local.json 未加入 .gitignore", R.SPECIAL["P011"]["why"], R.SPECIAL["P011"]["fix"]))
    return out


def _mcp_findings(rel, text):
    out = []
    data = _json_load(text)
    if not isinstance(data, dict):
        return out
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return out
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", [])])
        if re.search(r"(?:^|[\s\"'])(?:[A-Za-z]:[\\/]|/|~)(?:[\s\"']|$)", cmd):
            out.append(finding("P005", "perm", "high", R.SPECIAL["P005"]["title"], rel, 1,
                               "MCP " + str(name) + " 的根目录是整盘", R.SPECIAL["P005"]["why"], R.SPECIAL["P005"]["fix"]))
        if re.search(r"shell|terminal|bash|exec|command", str(name) + " " + cmd, re.I):
            out.append(finding("P006", "perm", "high", R.SPECIAL["P006"]["title"], rel, 1,
                               "MCP " + str(name) + " 能执行命令", R.SPECIAL["P006"]["why"], R.SPECIAL["P006"]["fix"]))
    return out


def gitignore_has(root, name):
    path = os.path.join(root, ".gitignore")
    if not os.path.isfile(path):
        return False
    for line in safe_read(path).splitlines():
        if line.strip().rstrip("/") == name:
            return True
    return False


def _perm_findings(root):
    out = []
    env_path = os.path.join(root, ".env")
    if os.path.isfile(env_path) and not gitignore_has(root, ".env"):
        out.append(finding("P007", "perm", "medium", R.SPECIAL["P007"]["title"], ".env", 1,
                           ".env 没有被 .gitignore 忽略", R.SPECIAL["P007"]["why"], R.SPECIAL["P007"]["fix"]))
    if os.name != "nt":
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                try:
                    mode = os.stat(path).st_mode
                except OSError:
                    continue
                rel = rel_path(root, path)
                if os.path.isdir(path) and (mode & 0o002):
                    out.append(finding("P008", "perm", "medium", R.SPECIAL["P008"]["title"], rel, 1,
                                       "目录权限包含 world-writable", R.SPECIAL["P008"]["why"], R.SPECIAL["P008"]["fix"]))
                if os.path.isfile(path) and (name in (".env", "id_rsa", "id_ed25519") or name.endswith(".pem")):
                    if mode & 0o077:
                        out.append(finding("P009", "perm", "medium", R.SPECIAL["P009"]["title"], rel, 1,
                                           "密钥文件权限过宽", R.SPECIAL["P009"]["why"], R.SPECIAL["P009"]["fix"]))
    low = root.replace("\\", "/").lower()
    if re.search(r"desktop|downloads|onedrive|dropbox|icloud|坚果云|百度网盘", low):
        out.append(finding("P010", "perm", "low", R.SPECIAL["P010"]["title"], ".", 1,
                           "项目位于同步盘 / 桌面 / 下载目录", R.SPECIAL["P010"]["why"], R.SPECIAL["P010"]["fix"]))
    return out


def _scan_text(rel, text, terms, domains, root):
    out = []
    for rule in R.RULES:
        if domains and rule["domain"] not in domains:
            continue
        if not glob_match(rel, rule["globs"]):
            continue
        rx = _compile(rule)
        if rx is None:
            continue
        for m in rx.finditer(text):
            group = rule.get("mask_group") or 0
            try:
                matched = m.group(group)
            except IndexError:
                matched = m.group(0)
            line = line_at(text, m.start())
            if allowed(rule, line):
                continue
            kind = rule["mask"] if rule["id"] in SECRET_RULES else "none"
            snippet = mask_line(line, matched, kind)
            out.append(finding(rule["id"], rule["domain"], rule["severity"], rule["title"], rel,
                               line_no(text, m.start()), snippet, rule["why"], rule["fix"]))
            if rule.get("aggregate"):
                break
    if not domains or "skill" in domains:
        out.extend(_skill_findings(rel, text))
    if not domains or "perm" in domains:
        if rel.endswith(".claude/settings.json") or rel.endswith(".claude/settings.local.json"):
            out.extend(_settings_findings(rel, text, root))
        if rel.endswith(".mcp.json") or rel.endswith(".cursor/mcp.json"):
            out.extend(_mcp_findings(rel, text))
    if (not domains or "doc" in domains) and glob_match(rel, R.G_DOC):
        out.extend(_doc_findings(rel, text, terms))
    return out


def scan_file(path, root):
    root = os.path.abspath(root)
    path = os.path.abspath(path)
    rel = rel_path(root, path)
    text = safe_read(path)
    if not text:
        return []
    return _scan_text(rel, text, load_terms(root), None, root)


def scan_project(root, domains=None):
    root = os.path.abspath(root)
    terms = load_terms(root)
    findings = []
    for path, rel in iter_files(root):
        text = safe_read(path)
        if not text:
            continue
        findings.extend(_scan_text(rel, text, terms, domains, root))
    if not domains or "perm" in domains:
        findings.extend(_perm_findings(root))
    seen = set()
    unique = []
    for f in findings:
        key = (f["id"], f["path"], f["line"], f["snippet"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (R.SEV_ORDER[f["severity"]], f["path"], f["line"], f["id"]))
    return unique


def score(findings):
    counts = {k: 0 for k in R.SEV_WEIGHT}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    penalty = sum(R.SEV_WEIGHT[s] * counts[s] for s in counts)
    value = max(0, 100 - penalty)
    if value >= 90:
        grade = "A"
    elif value >= 75:
        grade = "B"
    elif value >= 60:
        grade = "C"
    elif value >= 40:
        grade = "D"
    else:
        grade = "F"
    return value, grade, counts


def summary(root, findings):
    value, grade, counts = score(findings)
    return {
        "version": "1.0.0",
        "root": os.path.abspath(root),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score": value,
        "grade": grade,
        "counts": counts,
        "findings": findings,
    }
