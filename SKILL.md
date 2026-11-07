---
name: ai-security-guard
description: 给 AI 项目做安全体检，专抓四种外行常犯的泄密：代码里写死的密钥和后门、Skill/插件越权、文档里拿真客户信息当例子、AI 工具文件夹权限开太大。用户说“体检一下”“这个项目安全吗”“能不能发给别人”“这个 Skill 能装吗”“帮我看看有没有泄密”“上线前检查”“会不会泄露客户信息”“代码里有没有后门”“这份文档能不能外发”时使用。安装后还能作为项目默认安检员，在 AI 写完文件后自动体检，发现严重问题就让 AI 当场改。
---

# AI 项目安全体检

## 这个 Skill 是干什么的

它不是杀毒软件，也不是专业代码审计。它只盯一件事：**外行用 AI 干活时，最容易把公司家底漏出去的那几个口子。**

一共四类：

1. **代码**：写死的密钥、eval、SQL 拼接、pickle、debug=True、CORS 全开、777 权限。
2. **Skill / 插件**：绑了 `Bash(*)`、偷读 `~/.ssh`、把文件往外发、要求“别告诉用户”、`curl | bash`。
3. **文档**：拿真客户姓名、手机号、身份证、合同金额、底价当例子。
4. **权限**：`bypassPermissions`、`Bash(*)`、把整个 C 盘加进 AI 的工作目录、装了 shell 类 MCP。

## 什么时候用它

- 用户说“帮我体检一下这个项目”“这个项目安全吗”“能不能开源/发给客户”。
- 用户准备把项目上传 GitHub、发给外包、交付给客户。
- 用户要安装别人写的 Skill，问“这个能装吗”。
- 用户让 AI 写案例、模板、投标文件，里面可能有真实客户信息。
- 用户说“AI 老弹权限确认，我全点了同意”。
- 上线前、发版前、交接前。

## 怎么跑

先找到这个 Skill 的目录（也就是本文件所在目录），记作 `SKILL_DIR`。在用户的项目根目录执行：

```bash
python "$SKILL_DIR/scripts/guard.py" scan .
```

只查某一类：

```bash
python "$SKILL_DIR/scripts/guard.py" scan . --domain code
python "$SKILL_DIR/scripts/guard.py" scan . --domain skill,doc,perm
```

只查一个 Skill：

```bash
python "$SKILL_DIR/scripts/guard.py" skill .claude/skills/xxx
```

生成 Markdown 报告：

```bash
python "$SKILL_DIR/scripts/guard.py" scan . --format md --output security-report.md
```

给 CI 用（有高危就返回非 0）：

```bash
python "$SKILL_DIR/scripts/guard.py" scan . --format json --fail-on high
```

## 报告怎么读

报告分四段，每段对应一类问题。每条问题都有：

- **位置**：哪个文件、第几行。
- **片段**：只显示打码后的内容，不会把完整密钥或个人信息写出来。
- **为什么危险**：用非技术语言解释别人能怎么利用。
- **怎么改**：按顺序的 1-2-3 步。

安全分是 100 分制：严重扣 25、高危扣 12、中危扣 5、提示扣 2。A≥90，B≥75，C≥60，D≥40，F<40。分数只是帮你排优先级，不是保险单。

## 给用户解释时怎么说

- 先说结论：能不能发、能不能装、先改哪三条。
- 一次只说 3 条，别把 30 条问题全倒给老板。
- 每条都说清楚“别人能怎么用”和“第一步做什么”。
- 不要说“可能”“也许”来吓人；说具体的利用路径。
- 不要承诺“100% 安全”。说“这次没发现明显问题，但安全是持续的事”。

## 自动体检（可选）

在用户项目里装一次：

```bash
python "$SKILL_DIR/scripts/guard.py" install-hook
```

它会在 `.claude/settings.json` 里加一个 PostToolUse hook。以后 AI 每次写完文件，都会自动体检；发现严重/高危就把问题回给 AI，让它当场改；同时写进 `.ai-guard/hook.log`。安装时还会加一个 SessionStart hook，每次新会话先报一下上次体检状态。卸载：

```bash
python "$SKILL_DIR/scripts/guard.py" install-hook --uninstall
```

## 自定义客户名单

在项目里建 `.ai-guard/terms.txt`，一行一个词：

```
某某科技有限公司
某某连锁餐饮
张总
```

再跑 scan，命中就会报 D009（严重）。这个文件不要提交进 git。

## 修复顺序

1. **先止血**：吊销已经泄露的 key、改密码、把文件从公开仓库删掉。
2. **再改代码**：按报告里的步骤改，一次改一类。
3. **再复查**：重新跑 scan，确认分数上去了。
4. **最后补流程**：把 scan 加进发版前检查，把 `.env` 加进 `.gitignore`。

## 不要做什么

- 不要自动帮用户改代码，除非用户明确同意；安全修改经常需要人判断。
- 不要在报告、聊天、commit message 里粘贴完整密钥或个人信息。
- 不要为了“好看”把严重问题说成“小问题”。
- 不要把 scan 当成渗透测试；它只覆盖常见的、外行容易犯的错。
- 不要建议用户关闭安全检查来“让 AI 跑得更顺”。

## 文件结构

```
SKILL.md                 本文件
scripts/guard.py         CLI 入口
scripts/engine.py        扫描引擎
scripts/rules.py         规则库
references/              四类问题的详细说明
templates/               报告模板、安全基线模板
examples/vulnerable-demo 故意写坏的演示项目
```
