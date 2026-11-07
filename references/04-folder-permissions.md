# 文件夹与 AI 权限：别把整栋楼的钥匙，挂在一把螺丝刀上

## 先说结论

AI 工具要读文件、写文件、跑命令，这些都得给权限。问题不在于“给不给”，而在于**给多大**。

很多人的配置是：为了省事，直接开 `bypassPermissions`，把整个 C 盘加进工作目录，再装一个能执行命令的 MCP。等于把整栋楼的钥匙，挂在一把螺丝刀上。

---

## 权限分几层

以 Claude Code 为例，配置可能在四个地方：

| 文件 | 作用范围 | 说明 |
| --- | --- | --- |
| `~/.claude/settings.json` | 当前用户所有项目 | 用户级默认值 |
| `.claude/settings.json` | 当前项目，会进 git | 团队共享 |
| `.claude/settings.local.json` | 当前项目，不进 git | 个人本地覆盖 |
| `.mcp.json` | 当前项目的 MCP 服务 | 外部工具接入 |

优先级大致是：本地 > 项目 > 用户。具体以工具文档为准。

---

## 四个最危险的配置

### 1. `bypassPermissions`

```json
{
  "permissions": {
    "defaultMode": "bypassPermissions"
  }
}
```

含义：AI 不再问你“要不要执行”，直接干。

风险：AI 判断错一次，就是删文件、改配置、发数据。你连“它刚才做了什么”都不知道。

**怎么改**

```json
{
  "permissions": {
    "defaultMode": "default"
  }
}
```

保留确认。确实要少弹窗，用 `acceptEdits` 只自动接受文件修改，不要连命令一起放开。

### 2. `Bash(*)`

```json
{
  "permissions": {
    "allow": ["Bash(*)"]
  }
}
```

含义：任何 shell 命令都能跑。

风险：`rm -rf`、`curl | bash`、读 `.env` 再发走，全都不需要再确认。

**怎么改**

只放真正需要的命令，并且限定子命令：

```json
{
  "permissions": {
    "allow": [
      "Bash(git status:*)",
      "Bash(git diff:*)",
      "Bash(python -m unittest:*)"
    ],
    "deny": [
      "Bash(rm:*)",
      "Bash(curl:*)",
      "Bash(wget:*)"
    ]
  }
}
```

### 3. 把整个磁盘加进工作目录

```json
{
  "permissions": {
    "additionalDirectories": ["C:\\", "~"]
  }
}
```

含义：AI 能读写整块盘，包括桌面、下载、文档、其他项目。

风险：一份客户合同、一个 `.env`、一张身份证照片，都在它的视野里。

**怎么改**

只给当前项目，最多加一个明确的数据目录：

```json
{
  "permissions": {
    "additionalDirectories": ["./data"]
  }
}
```

### 4. 装了能执行命令的 MCP

```json
{
  "mcpServers": {
    "shell": {
      "command": "npx",
      "args": ["-y", "@example/shell-mcp"]
    }
  }
}
```

含义：AI 通过 MCP 调一个外部程序，这个程序能执行命令。

风险：MCP 服务本身的权限、更新、供应链，你都不一定控制得了。`npx -y` 每次还可能拉到新版本。

**怎么改**

- 只装来源明确、固定版本的 MCP。
- 文件类 MCP 不要以 `C:\` 或 `/` 启动，指定到项目目录。
- 不用的 MCP 从 `.mcp.json` 删掉。

---

## 其他容易忽略的口子

### `.env` 没进 `.gitignore`

```gitignore
.env
.env.*
!.env.example
```

`.env.example` 只放字段名，不放真值。

### 目录 777

```bash
chmod 755 uploads/
chmod 644 config.json
```

上传目录不要给执行权限。

### `settings.local.json` 被提交

```gitignore
.claude/settings.local.json
```

本地配置里可能有你的个人 token、绝对路径。

### 项目放在同步盘/桌面/下载目录

`OneDrive`、`Desktop`、`Downloads` 经常被自动同步、被其他软件扫描。密钥项目不要放这里。

---

## 一份相对安全的 `settings.json`

```json
{
  "permissions": {
    "defaultMode": "default",
    "allow": [
      "Read(./**)",
      "Write(./output/**)",
      "Bash(git status:*)",
      "Bash(git diff:*)",
      "Bash(python -m unittest:*)"
    ],
    "deny": [
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(~/.ssh/**)",
      "Read(~/.aws/**)",
      "Bash(rm:*)",
      "Bash(curl:*)",
      "Bash(wget:*)"
    ],
    "additionalDirectories": []
  }
}
```

原则：**默认拒绝，按需放行，危险命令显式拒绝。**

---

## 5 分钟自查

1. 打开 `.claude/settings.json`，搜 `bypassPermissions`。
2. 搜 `Bash(*)`。
3. 搜 `additionalDirectories`，看有没有 `C:\`、`/`、`~`。
4. 打开 `.mcp.json`，看有没有 `shell`、`filesystem` 指向根目录。
5. 看 `.env` 在不在 `.gitignore` 里。

五条里中了一条，今天就改。
