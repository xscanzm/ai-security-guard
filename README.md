# ai-security-guard

**给 AI 项目念一句“安全咒语”。跑一次，它就在后台盯着四个最容易泄密的口子。**

代码里写死的密钥、Skill 绑了最高权限、文档里拿真客户信息当例子、AI 工具的文件夹权限开太大——这四件事，靠开会和叮嘱防不住。这个工具换了个路子：不指望每个人不犯错，直接给项目装一个默认的安检员。

纯本地、零依赖、中文报告、只输出打码后的片段。不会把你的代码上传到任何地方。

## 它抓什么

| 类别 | 典型问题 | 例子 |
| --- | --- | --- |
| 代码 | 密钥、后门、危险写法 | `sk-...` 写死在代码里、`eval(user_input)`、SQL 用 f-string 拼、`debug=True`、`chmod 777` |
| Skill / 插件 | 权限过大、偷读、外发 | `allowed-tools: Bash(*)`、读 `~/.ssh/id_rsa`、`curl -d @文件`、`curl ... \| bash`、要求“别告诉用户” |
| 文档 | 真实个人信息、报价 | 真客户姓名、手机号、身份证、合同金额、底价、微信 |
| 权限 | AI 被放得太开 | `bypassPermissions`、`Bash(*)`、`additionalDirectories: ["C:\\"]`、shell 类 MCP |

规则库目前 52 条，分四个域：`C` 代码、`S` Skill、`D` 文档、`P` 权限。完整清单：

```bash
python scripts/guard.py rules
```

## 30 秒上手

### 方式一：装成 Claude Code Skill（推荐）

```bash
npx skills add https://github.com/xscanzm/ai-security-guard --skill ai-security-guard
```

装好后，在 Claude Code 里直接说“帮我体检一下这个项目”，它会自己跑。

### 方式二：git clone 到 Skill 目录

```bash
git clone https://github.com/xscanzm/ai-security-guard.git ~/.claude/skills/ai-security-guard
```

Windows PowerShell：

```powershell
git clone https://github.com/xscanzm/ai-security-guard.git "$env:USERPROFILE\.claude\skills\ai-security-guard"
```

### 方式三：就在项目里跑

```bash
git clone https://github.com/xscanzm/ai-security-guard.git
cd ai-security-guard
python scripts/guard.py scan /path/to/your-project
```

需要 Python 3.8+，不需要装任何第三方包。

### 方式四：一键安装脚本

```bash
bash install.sh                    # macOS / Linux / Git Bash
```
```powershell
powershell -ExecutionPolicy Bypass -File install.ps1   # Windows PowerShell
```

脚本会把 Skill 复制到 `~/.claude/skills/ai-security-guard`。该目录已存在时会直接停下、不覆盖；升级请先删掉旧目录再运行。

## 常用命令

```bash
# 体检整个项目
python scripts/guard.py scan .

# 只查代码 / 只查文档
python scripts/guard.py scan . --domain code
python scripts/guard.py scan . --domain doc

# 只查一个 Skill 能不能装
python scripts/guard.py skill .claude/skills/some-skill

# 生成 Markdown 报告，发给老板
python scripts/guard.py scan . --format md --output security-report.md

# 给 CI 用：有高危就失败
python scripts/guard.py scan . --format json --fail-on high

# 看上次结果 / 看拦截记录
python scripts/guard.py status
python scripts/guard.py log

# 解释一条规则
python scripts/guard.py explain C001
```

## 报告长什么样

```text
ai-security-guard v1.0.0
体检目录：D:\work\my-project
体检时间：2026-11-07 21:50:00

安全分：42 / 100   等级：D
严重 2 · 高危 3 · 中危 1 · 提示 0

== 代码后门与漏洞 ==

[严重] C001  代码里写死了 API Key
  位置：app.py:12
  片段：DEEPSEEK_API_KEY = "sk-d****cdef"
  为什么危险：这串 key 就像你公司的门禁卡。谁拿到代码，谁就能用你的账号调用模型或云服务，账单还算你的。
  怎么改：
    1. 先去平台吊销这把 key——只删代码不够，旧 key 已经泄露了。
    2. 把新 key 放进 .env 文件，并确认 .env 在 .gitignore 里。
    3. 代码里改成读环境变量，例如 os.getenv("DEEPSEEK_API_KEY")。
```

完整示例可以直接跑：

```bash
python scripts/guard.py scan examples/vulnerable-demo
```

## 自动体检：让它变成项目默认安检员

在你的项目根目录执行一次：

```bash
python ~/.claude/skills/ai-security-guard/scripts/guard.py install-hook
```

它会在 `.claude/settings.json` 里加一个 PostToolUse hook。以后 AI 每次写完文件，都会自动体检；发现严重/高危就把问题回给 AI，让它当场改；同时写进 `.ai-guard/hook.log`。安装时还会加一个 SessionStart hook，每次新会话先报一下上次体检状态。原设置会自动备份。

```bash
# 卸载
python ~/.claude/skills/ai-security-guard/scripts/guard.py install-hook --uninstall

# 装到用户级设置（所有项目生效）
python ~/.claude/skills/ai-security-guard/scripts/guard.py install-hook --user
```

## 自定义客户名单

在项目里建 `.ai-guard/terms.txt`，一行一个词：

```
某某科技有限公司
某某连锁餐饮
张总
```

再跑 scan，命中就会报 `D009`（严重）。这个文件默认被 `.gitignore` 忽略，不会进仓库。

## 它不做什么

- **不上传、不联网**：所有扫描都在本机完成。
- **不替代专业审计**：它抓的是常见的、外行容易犯的错，不是渗透测试。
- **不保证 100%**：规则是启发式的，会有漏报和误报。
- **不自动改代码**：安全修改需要人确认，AI 乱改可能更糟。
- **不扫二进制**：图片、PDF、Word、Excel 目前不解析，只扫文本文件。

## 误报怎么办

三种办法，从轻到重：

1. 在文件前 5 行加 `# ai-guard:ignore-file`，整个文件跳过。
2. 在项目根目录 `.ai-guardignore` 里写路径或通配符，例如 `examples/`。
3. 如果是规则本身的问题，欢迎提 issue，带上最小复现。

## 常见问题

**会把我的密钥上传吗？**
不会。没有网络请求，没有遥测，报告只写本地文件。

**为什么只提示、不自动修？**
因为“删掉这行”可能把业务改坏。工具负责发现和教怎么改，最后一步由人确认。

**Windows 能用吗？**
能。Windows 10/11 + Python 3.8+ 即可。路径、权限相关的规则在 Windows 上会自动跳过不适用项。

**支持哪些 AI 工具？**
核心是一个独立 CLI，任何工具都能调。自动体检目前适配 Claude Code 的 `.claude/settings.json`；Cursor 等工具可以手动把 `guard.py scan .` 加进发版前检查。

**规则会过时吗？**
会。AI 工具和攻击手法都在变，欢迎 PR 补规则。新增规则只要在 `scripts/rules.py` 里加一条，并在 `tests/test_guard.py` 里加断言。

## 开发

```bash
python -m unittest discover -s tests -v
python scripts/guard.py scan examples/vulnerable-demo
python scripts/guard.py scan . --no-cache
```

仓库结构：

```
SKILL.md                 Claude Code Skill 定义
scripts/guard.py         CLI
scripts/engine.py        扫描引擎
scripts/rules.py         52 条规则
references/              四类问题的详细说明 + 泄露应急
templates/               报告模板、安全基线
examples/vulnerable-demo 故意写坏的演示项目
tests/                   回归测试
.github/workflows/       CI
```

## License

MIT。随便用，出了问题别找我们——但欢迎提 issue。
