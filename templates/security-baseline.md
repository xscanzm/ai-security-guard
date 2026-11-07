# 团队 AI 安全基线（一页纸）

适用：所有用 AI 写代码、写文档、装 Skill 的同事。

## 五条硬规矩

1. **密钥不进代码。** 只放 `.env`，`.env` 必须在 `.gitignore` 里。
2. **装 Skill 前先体检。** 看权限、看读什么、看往哪发。`Bash(*)` 一律不装。
3. **文档例子用合成数据。** 真客户名、电话、身份证、合同底价，一个都不许贴。
4. **AI 权限最小化。** 不开 `bypassPermissions`，不给整盘目录，不装来路不明的 MCP。
5. **外发前跑一遍。** `python scripts/guard.py scan . --fail-on high`。

## 每个人 5 分钟能做的三件事

- 打开 `.claude/settings.json`，搜 `bypassPermissions` 和 `Bash(*)`。
- 打开 `.gitignore`，确认 `.env` 在里面。
- 把最近要发的文档，用 `guard.py scan . --domain doc` 跑一遍。

## 项目上线前

- [ ] `guard.py scan . --fail-on high` 通过
- [ ] `.env` 没有进 git
- [ ] 没有 `debug=True`
- [ ] 没有 `Bash(*)` / `bypassPermissions`
- [ ] 演示数据全是合成的
- [ ] 知道出了事找谁

## 出了事找谁

- 安全负责人：
- 法务/合规：
- 客户对接人：
- 应急群：

## 一句话

别拿员工的记性去赌安全，给项目装个默认的护栏。
