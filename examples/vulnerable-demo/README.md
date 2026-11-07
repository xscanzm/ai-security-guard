# 故意写坏的项目

这个项目里的每一处问题都是故意的，用来演示 ai-security-guard 能抓到什么。
不要部署它，也不要把里面的“密钥”和“客户信息”当真。

在仓库根目录运行：

```bash
python scripts/guard.py scan examples/vulnerable-demo
```

你会看到代码、Skill、文档、权限四类问题，以及每一项该怎么改。
