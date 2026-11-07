#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ai-security-guard 命令行入口。

用法：
    python scripts/guard.py scan .
    python scripts/guard.py skill .claude/skills/my-skill
    python scripts/guard.py install-hook
    python scripts/guard.py status
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import engine as E
import rules as R

VERSION = "1.0.0"
GUARD_PATH = os.path.abspath(__file__)


def _utf8():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _write_text(path, text):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _cache_path(root):
    return os.path.join(root, ".ai-guard", "last-scan.json")


def _write_cache(root, data):
    try:
        _write_text(_cache_path(root), json.dumps(data, ensure_ascii=False, indent=2))
    except OSError:
        pass


def _read_cache(root):
    return _read_json(_cache_path(root))


def _append_log(root, record):
    try:
        path = os.path.join(root, ".ai-guard", "hook.log")
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _header(data):
    c = data.get("counts", {})
    return [
        "ai-security-guard v%s" % VERSION,
        "体检目录：%s" % data.get("root", ""),
        "体检时间：%s" % data.get("generated_at", ""),
        "",
        "安全分：%d / 100   等级：%s" % (data.get("score", 0), data.get("grade", "F")),
        "严重 %d · 高危 %d · 中危 %d · 提示 %d" % (
            c.get("critical", 0), c.get("high", 0), c.get("medium", 0), c.get("low", 0)),
        "",
    ]


def render_text(data):
    lines = _header(data)
    findings = data.get("findings", [])
    if not findings:
        lines.append("这次没发现明显问题。")
        lines.append("")
        lines.append("已检查：代码里的密钥和危险写法、Skill 的权限和数据外发、文档里的真实信息、AI 工具的文件夹权限。")
        lines.append("建议：把 `python scripts/guard.py scan .` 加进发版前检查，别只体检一次。")
        return "\n".join(lines) + "\n"
    current = None
    for f in findings:
        if f["domain"] != current:
            current = f["domain"]
            lines.append("== %s ==" % R.DOMAIN_LABEL.get(current, current))
            lines.append("")
        lines.append("[%s] %s  %s" % (R.SEV_LABEL.get(f["severity"], f["severity"]), f["id"], f["title"]))
        lines.append("  位置：%s:%s" % (f["path"], f["line"]))
        lines.append("  片段：%s" % f["snippet"])
        lines.append("  为什么危险：%s" % f["why"])
        lines.append("  怎么改：")
        for i, step in enumerate(f["fix"], 1):
            lines.append("    %d. %s" % (i, step))
        lines.append("")
    lines.append("共 %d 个问题。先修严重和高危，再处理中危；改完重新跑一次。" % len(findings))
    lines.append("提示：报告只显示打码后的片段，不会把完整密钥或个人信息写进文件。")
    return "\n".join(lines) + "\n"


def render_md(data):
    c = data.get("counts", {})
    lines = [
        "# AI 项目安全体检报告",
        "",
        "- 目录：`%s`" % data.get("root", ""),
        "- 时间：%s" % data.get("generated_at", ""),
        "- 安全分：**%d / 100**（%s）" % (data.get("score", 0), data.get("grade", "F")),
        "- 问题：严重 %d · 高危 %d · 中危 %d · 提示 %d" % (
            c.get("critical", 0), c.get("high", 0), c.get("medium", 0), c.get("low", 0)),
        "",
        "## 问题清单",
        "",
        "| 级别 | 编号 | 问题 | 位置 |",
        "| --- | --- | --- | --- |",
    ]
    for f in data.get("findings", []):
        lines.append("| %s | %s | %s | `%s:%s` |" % (
            R.SEV_LABEL.get(f["severity"], f["severity"]), f["id"], f["title"], f["path"], f["line"]))
    lines.append("")
    lines.append("## 详情")
    lines.append("")
    for f in data.get("findings", []):
        lines.append("### [%s] %s %s" % (R.SEV_LABEL.get(f["severity"], f["severity"]), f["id"], f["title"]))
        lines.append("")
        lines.append("- 位置：`%s:%s`" % (f["path"], f["line"]))
        lines.append("- 片段：`%s`" % f["snippet"])
        lines.append("- 为什么危险：%s" % f["why"])
        lines.append("- 怎么改：")
        for i, step in enumerate(f["fix"], 1):
            lines.append("  %d. %s" % (i, step))
        lines.append("")
    lines.append("> 报告只显示打码后的片段，不会输出完整密钥或个人信息。")
    return "\n".join(lines) + "\n"


def render_json(data):
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def _render(data, fmt):
    if fmt == "md":
        return render_md(data)
    if fmt == "json":
        return render_json(data)
    return render_text(data)


def _should_fail(findings, fail_on):
    if fail_on == "none":
        return False
    limit = R.SEV_ORDER.get(fail_on, 1)
    return any(R.SEV_ORDER.get(f["severity"], 3) <= limit for f in findings)


def cmd_scan(args):
    root = os.path.abspath(args.path or ".")
    if not os.path.isdir(root):
        print("找不到目录：%s" % root, file=sys.stderr)
        return 3
    domains = None
    if args.domain and args.domain != "all":
        domains = [d.strip() for d in args.domain.split(",") if d.strip()]
    findings = E.scan_project(root, domains)
    data = E.summary(root, findings)
    text = _render(data, args.format)
    if args.output:
        out = args.output
        if out.endswith(("/", "\\")):
            out = os.path.join(out, "security-report." + ("md" if args.format == "md" else "txt"))
        _write_text(out, text)
        if not args.quiet:
            print("报告已写入：%s" % os.path.abspath(out))
    elif not args.quiet:
        print(text, end="")
    if not args.no_cache:
        _write_cache(root, data)
    return 1 if _should_fail(findings, args.fail_on) else 0


def cmd_skill(args):
    path = os.path.abspath(args.path)
    if os.path.isdir(path):
        root = path
        skill_md = os.path.join(path, "SKILL.md")
    else:
        root = os.path.dirname(path)
        skill_md = path
    if not os.path.isfile(skill_md):
        print("找不到 SKILL.md：%s" % skill_md, file=sys.stderr)
        return 3
    findings = E.scan_file(skill_md, root)
    scripts_dir = os.path.join(root, "scripts")
    if os.path.isdir(scripts_dir):
        for dirpath, dirnames, filenames in os.walk(scripts_dir):
            dirnames[:] = [d for d in dirnames if d not in E.SKIP_DIRS]
            for name in sorted(filenames):
                p = os.path.join(dirpath, name)
                if os.path.splitext(name)[1].lower() in E.BINARY_EXT:
                    continue
                findings.extend(E.scan_file(p, root))
    seen = set()
    unique = []
    for f in findings:
        key = (f["id"], f["path"], f["line"], f["snippet"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (R.SEV_ORDER[f["severity"]], f["path"], f["line"], f["id"]))
    print("Skill 体检：%s" % root)
    print("")
    if not unique:
        print("结论：没发现明显越权，可以装。")
        print("但仍建议打开 scripts/ 看一眼它到底执行了什么。")
        return 0
    for f in unique:
        print("[%s] %s  %s" % (R.SEV_LABEL[f["severity"]], f["id"], f["title"]))
        print("  位置：%s:%s" % (f["path"], f["line"]))
        print("  片段：%s" % f["snippet"])
        print("  为什么危险：%s" % f["why"])
        print("  怎么改：")
        for i, step in enumerate(f["fix"], 1):
            print("    %d. %s" % (i, step))
        print("")
    if any(f["severity"] == "critical" for f in unique):
        print("结论：别装。这个 Skill 碰到了密钥、外发或隐藏行为，风险太高。")
        return 1
    if any(f["severity"] == "high" for f in unique):
        print("结论：先改再用。至少把高危项处理掉，再考虑安装。")
        return 1
    print("结论：可以装，但装完先在小项目里试，别直接放到核心项目。")
    return 0


def _hook_input():
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def cmd_hook(args):
    data = _hook_input()
    tool = str(data.get("tool_name") or data.get("tool") or "")
    tool_input = data.get("tool_input") or {}
    path = ""
    if isinstance(tool_input, dict):
        path = str(tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path") or "")
    if not path:
        return 0
    root = os.getcwd()
    abs_path = path if os.path.isabs(path) else os.path.join(root, path)
    if not os.path.isfile(abs_path):
        return 0
    findings = E.scan_file(abs_path, root)
    findings = [f for f in findings if f["severity"] in ("critical", "high")]
    if not findings:
        return 0
    rel = E.rel_path(root, abs_path)
    _append_log(root, {
        "time": _now(), "tool": tool, "file": rel,
        "ids": [f["id"] for f in findings],
        "severities": [f["severity"] for f in findings],
    })
    print("", file=sys.stderr)
    print("🛡️ ai-security-guard 把问题交给了 AI 修改", file=sys.stderr)
    print("文件：%s" % rel, file=sys.stderr)
    print("发现 %d 个问题：" % len(findings), file=sys.stderr)
    for f in findings[:3]:
        print("  [%s] %s  %s" % (R.SEV_LABEL[f["severity"]], f["id"], f["title"]), file=sys.stderr)
        print("    片段：%s" % f["snippet"], file=sys.stderr)
        print("    先做：%s" % (f["fix"][0] if f["fix"] else "删掉这段"), file=sys.stderr)
    if len(findings) > 3:
        print("  ……还有 %d 个，完整报告运行：python scripts/guard.py scan ." % (len(findings) - 3), file=sys.stderr)
    print("", file=sys.stderr)
    print("请先改掉上面的问题，再继续。", file=sys.stderr)
    return 2


def _settings_path(args):
    if args.user:
        return os.path.expanduser(os.path.join("~", ".claude", "settings.json"))
    base = os.path.abspath(args.project or ".")
    return os.path.join(base, ".claude", "settings.json")


def _hook_command(sub):
    return '"%s" "%s" %s' % (sys.executable, GUARD_PATH, sub)


def cmd_install_hook(args):
    path = _settings_path(args)
    data = _read_json(path) or {}
    if not isinstance(data, dict):
        data = {}
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
        data["hooks"] = hooks
    post = hooks.get("PostToolUse")
    if not isinstance(post, list):
        post = []
        hooks["PostToolUse"] = post
    if args.uninstall:
        def keep(entry):
            return "guard.py" not in json.dumps(entry, ensure_ascii=False)
        hooks["PostToolUse"] = [e for e in post if keep(e)]
        if isinstance(hooks.get("SessionStart"), list):
            hooks["SessionStart"] = [e for e in hooks["SessionStart"] if keep(e)]
        _write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        print("已卸载 ai-security-guard 的 hook：%s" % path)
        return 0
    marker = "guard.py"
    if any(marker in json.dumps(e, ensure_ascii=False) for e in post):
        print("hook 已经装过了，不用重复装：%s" % path)
        return 0
    if os.path.isfile(path):
        backup = path + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(path, backup)
        print("已备份原设置：%s" % backup)
    post.append({
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{"type": "command", "command": _hook_command("hook")}],
    })
    if not args.no_session_start:
        session = hooks.get("SessionStart")
        if not isinstance(session, list):
            session = []
            hooks["SessionStart"] = session
        if not any(marker in json.dumps(e, ensure_ascii=False) for e in session):
            session.append({
                "matcher": "startup|resume",
                "hooks": [{"type": "command", "command": _hook_command("status --brief")}],
            })
    _write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print("已安装 ai-security-guard hook：%s" % path)
    print("以后 AI 每次写完文件，都会自动体检；发现严重/高危会把问题和改法交给 AI。")
    return 0


def cmd_status(args):
    root = os.path.abspath(args.path or ".")
    data = _read_cache(root)
    if not data:
        msg = "🛡️ ai-security-guard 已就位。还没体检过，运行：python scripts/guard.py scan ."
        print(msg)
        return 0
    c = data.get("counts", {})
    if args.brief:
        print("🛡️ 上次体检 %s：%d 分（%s），%d 个问题（严重 %d / 高危 %d）。" % (
            data.get("generated_at", ""), data.get("score", 0), data.get("grade", "F"),
            len(data.get("findings", [])), c.get("critical", 0), c.get("high", 0)))
        return 0
    print("ai-security-guard 状态")
    print("目录：%s" % root)
    print("上次体检：%s" % data.get("generated_at", "从未"))
    print("安全分：%d / 100（%s）" % (data.get("score", 0), data.get("grade", "F")))
    print("问题：严重 %d · 高危 %d · 中危 %d · 提示 %d" % (
        c.get("critical", 0), c.get("high", 0), c.get("medium", 0), c.get("low", 0)))
    findings = data.get("findings", [])
    if findings:
        print("")
        print("最该先处理的：")
        for f in findings[:5]:
            print("  [%s] %s  %s（%s:%s）" % (
                R.SEV_LABEL.get(f["severity"], f["severity"]), f["id"], f["title"], f["path"], f["line"]))
    print("")
    print("复查：python scripts/guard.py scan .")
    return 0


def cmd_log(args):
    root = os.path.abspath(args.path or ".")
    path = os.path.join(root, ".ai-guard", "hook.log")
    if not os.path.isfile(path):
        print("还没有拦截记录。")
        return 0
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except OSError:
        print("读不到日志：%s" % path, file=sys.stderr)
        return 3
    rows = rows[-max(1, args.limit):]
    print("最近的拦截记录（%d 条）：" % len(rows))
    for r in rows:
        print("  %s  %s  %s  规则：%s" % (
            r.get("time", ""), r.get("tool", ""), r.get("file", ""), ", ".join(r.get("ids", []))))
    return 0


def cmd_rules(args):
    domain = args.domain
    print("ai-security-guard 规则库（v%s）" % VERSION)
    print("")
    for d in ("code", "skill", "doc", "perm"):
        if domain and domain != "all" and domain != d:
            continue
        print("== %s ==" % R.DOMAIN_LABEL[d])
        for rule in R.RULES:
            if rule["domain"] == d:
                print("  %s  %s  %s" % (rule["id"], R.SEV_LABEL[rule["severity"]], rule["title"]))
        for rid, meta in R.SPECIAL.items():
            if meta["domain"] == d:
                print("  %s  %s  %s" % (rid, R.SEV_LABEL[meta["severity"]], meta["title"]))
        print("")
    return 0


DETECT = {
    "D001": "匹配 11 位手机号，排除 13800138000 这类示例号。",
    "D002": "匹配 18 位身份证号，并校验最后一位校验码，避免把随机数字当成身份证。",
    "D003": "匹配 16-19 位银行卡号，并通过 Luhn 校验。",
    "D004": "匹配邮箱地址，排除 example.com 等示例域名。",
    "D005": "匹配“客户/联系人/姓名：”后面的 2-4 个汉字。",
    "D006": "匹配合同金额、报价、底价、返点、折扣、单价后面的数字。",
    "D007": "匹配工资、薪资、月薪、年薪、底薪、绩效、提成后面的数字。",
    "D008": "匹配“内部资料/机密/仅限内部/请勿外传”等标记。",
    "D009": "读取 .ai-guard/terms.txt 里的自定义客户名单，逐条匹配。",
    "D010": "匹配“地址/住址/门店地址：”后面的详细地址。",
    "D011": "匹配微信号、QQ 号。",
    "S001": "解析 SKILL.md 的 allowed-tools，发现 Bash 或 Bash(*) 就报警。",
    "S009": "解析 SKILL.md 的 allowed-tools，发现 Write 或 Write(*) 就报警。",
    "P001": "读取 .claude/settings.json，发现 defaultMode=bypassPermissions 就报警。",
    "P002": "读取 permissions.allow，发现 Bash 或 Bash(*) 就报警。",
    "P003": "读取 permissions.additionalDirectories，发现 /、C:\\、~ 这类整盘范围就报警。",
    "P004": "读取 enableAllProjectMcpServers=true。",
    "P005": "读取 .mcp.json，发现文件服务的根目录是整盘就报警。",
    "P006": "读取 .mcp.json，发现 shell/terminal/exec 类服务就报警。",
    "P007": "检查 .env 是否存在，以及 .gitignore 有没有忽略它。",
    "P008": "在 Linux/macOS 上检查目录是否 world-writable。",
    "P009": "在 Linux/macOS 上检查密钥文件权限是否宽于 600。",
    "P010": "检查项目路径是否在桌面、下载、OneDrive、坚果云等目录。",
    "P011": "检查 settings.local.json 是否在 .gitignore 里。",
    "P012": "读取 defaultMode=acceptEdits。",
}


def cmd_explain(args):
    rid = args.rule_id.upper()
    rule = None
    for r in R.RULES:
        if r["id"] == rid:
            rule = r
            break
    if rule:
        print("%s  [%s]  %s" % (rule["id"], R.SEV_LABEL[rule["severity"]], rule["title"]))
        print("领域：%s" % R.DOMAIN_LABEL[rule["domain"]])
        print("")
        print("为什么危险：%s" % rule["why"])
        print("")
        print("怎么改：")
        for i, step in enumerate(rule["fix"], 1):
            print("  %d. %s" % (i, step))
        print("")
        print("检测方式：正则匹配，只输出打码后的片段。")
        return 0
    meta = R.SPECIAL.get(rid)
    if meta:
        print("%s  [%s]  %s" % (rid, R.SEV_LABEL[meta["severity"]], meta["title"]))
        print("领域：%s" % R.DOMAIN_LABEL[meta["domain"]])
        print("")
        print("为什么危险：%s" % meta["why"])
        print("")
        print("怎么改：")
        for i, step in enumerate(meta["fix"], 1):
            print("  %d. %s" % (i, step))
        print("")
        print("检测方式：%s" % DETECT.get(rid, "按文件结构和上下文判断。"))
        return 0
    print("没有这条规则：%s" % rid, file=sys.stderr)
    print("运行 `python scripts/guard.py rules` 查看全部规则。", file=sys.stderr)
    return 3


def build_parser():
    p = argparse.ArgumentParser(
        prog="guard.py",
        description="AI 项目安全体检：代码后门、Skill 越权、文档隐私、文件夹权限。",
    )
    p.add_argument("--version", action="version", version="ai-security-guard " + VERSION)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="体检一个项目")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--format", choices=["text", "md", "json"], default="text")
    s.add_argument("--output", "-o", default="")
    s.add_argument("--domain", default="all", help="all 或 code,skill,doc,perm 的组合")
    s.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="high")
    s.add_argument("--no-cache", action="store_true")
    s.add_argument("--quiet", "-q", action="store_true")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("skill", help="只体检一个 Skill")
    s.add_argument("path")
    s.set_defaults(func=cmd_skill)

    s = sub.add_parser("hook", help="给 Claude Code 用的自动体检入口（从 stdin 读 JSON）")
    s.set_defaults(func=cmd_hook)

    s = sub.add_parser("install-hook", help="把自动体检装进 Claude Code")
    _hook_target = s.add_mutually_exclusive_group()
    # 注意：这里的 default 必须是 None。argparse 用 `is` 判断取值是否等于默认值，
    # 如果 default 也写成 "."（与 const 是同一个驻留字符串），--user/--project 的互斥检查会被静默跳过。
    _hook_target.add_argument("--project", nargs="?", const=".", default=None, metavar="PATH")
    _hook_target.add_argument("--user", action="store_true")
    s.add_argument("--uninstall", action="store_true")
    s.add_argument("--no-session-start", action="store_true")
    s.set_defaults(func=cmd_install_hook)

    s = sub.add_parser("status", help="看上次体检结果")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--brief", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("log", help="看自动体检记录")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(func=cmd_log)

    s = sub.add_parser("rules", help="列出全部规则")
    s.add_argument("--domain", default="all")
    s.set_defaults(func=cmd_rules)

    s = sub.add_parser("explain", help="解释一条规则")
    s.add_argument("rule_id")
    s.set_defaults(func=cmd_explain)
    return p


def main(argv=None):
    _utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        args = parser.parse_args(["scan", "."])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
