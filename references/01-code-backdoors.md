# 代码后门与漏洞：外行用 AI 写代码，最容易留下的 12 个洞

## 先说结论

不懂代码的人用 AI 写项目，最大的问题不是“写得丑”，而是**他看不出哪里在漏**。AI 为了让程序跑起来，会选最省事的写法；省事和危险，经常是同一行代码。

下面 12 个洞，按“别人能怎么用”排序。每条都给你：长什么样、别人怎么利用、怎么改、怎么验证。

---

## 1. 密钥写死在代码里

**长什么样**

```python
DEEPSEEK_API_KEY = "sk-xxxxxxxxxxxxxxxx"
DB_PASSWORD = "Passw0rd123"
```

**别人怎么用**

拿到代码的人（前员工、外包、GitHub 上的陌生人）可以直接用你的账号调用模型、云服务、数据库。账单算你的，数据也是你的。

**怎么改**

1. 先去平台**吊销**这把 key。只删代码不够，旧 key 已经泄露了。
2. 新建 `.env`，把 key 放进去；确认 `.env` 在 `.gitignore` 里。
3. 代码改成读环境变量：

```python
import os
key = os.getenv("DEEPSEEK_API_KEY")
```

**怎么验证**

```bash
git log -p | grep -i "sk-"   # 看历史里有没有
python scripts/guard.py scan . --domain code
```

---

## 2. 把用户输入当代码执行

**长什么样**

```python
eval(user_input)
exec(request.json["code"])
```

**别人怎么用**

在输入框里填一段代码，你的服务器就替他执行。轻则改数据，重则拿到服务器权限。

**怎么改**

- 能不用就不用。需要计算，用 `ast.literal_eval` 或自己写解析。
- 必须执行，放进隔离容器，限制网络和文件访问。

**怎么验证**

全局搜 `eval(`、`exec(`、`os.system(`、`subprocess.*shell=True`。

---

## 3. SQL 用字符串拼接

**长什么样**

```python
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
```

**别人怎么用**

输入 `' OR '1'='1` 就能绕过登录；输入 `'; DROP TABLE users;--` 就能删表。

**怎么改**

用参数化查询，不要拼字符串：

```python
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
```

**怎么验证**

搜 `execute(f"`、`execute(".*" %`、`execute(".*" +`。

---

## 4. 反序列化不可信数据

**长什么样**

```python
pickle.loads(request.data)
yaml.load(request.data)
```

**别人怎么用**

构造一段恶意 pickle，你的服务器一加载就执行他的代码。

**怎么改**

- 不要反序列化外部数据。
- YAML 用 `yaml.safe_load`。
- 必须传对象，用 JSON。

---

## 5. 调试模式开到了线上

**长什么样**

```python
app.run(debug=True)
```

**别人怎么用**

报错页面会暴露源码、路径、环境变量；有些框架的调试器还能直接执行代码。

**怎么改**

```python
app.run(debug=os.getenv("FLASK_DEBUG") == "1")
```

生产环境用 gunicorn/uwsgi，不要用开发服务器。

---

## 6. 跨域权限全开

**长什么样**

```python
CORS(app, origins="*")
```

**别人怎么用**

任何网站都能带着你用户的登录态调你的接口，把数据读走。

**怎么改**

只允许自己的域名：

```python
CORS(app, origins=["https://your-domain.com"])
```

---

## 7. 默认口令 / 弱口令

**长什么样**

```python
if username == "admin" and password == "admin":
```

**别人怎么用**

直接用 `admin/admin` 登录。扫描器几秒钟就能试出来。

**怎么改**

- 删掉默认账号，或者首次登录强制改密码。
- 密码用 bcrypt/argon2 存哈希，不要存明文。
- 加登录失败次数限制。

---

## 8. 把用户输入直接塞进网页

**长什么样**

```javascript
element.innerHTML = userInput;
document.write(userInput);
```

**别人怎么用**

在评论里写一段 `<script>`，所有看到这条评论的人都会执行它，登录态可能被偷走。

**怎么改**

```javascript
element.textContent = userInput;
```

必须渲染 HTML，用 DOMPurify 清洗。

---

## 9. 文件权限开成 777

**长什么样**

```bash
chmod 777 uploads/
```

**别人怎么用**

服务器上任何用户都能改你的文件，甚至塞一个 webshell 进来。

**怎么改**

```bash
chmod 755 uploads/     # 目录
chmod 644 file.txt     # 普通文件
```

上传目录不要给执行权限。

---

## 10. 服务监听在所有网卡上

**长什么样**

```python
app.run(host="0.0.0.0")
```

**别人怎么用**

本来只想本机访问的服务，暴露到了整个局域网/公网。配合弱口令，就是大门敞开。

**怎么改**

本机用 `127.0.0.1`；确实要对外，前面加反向代理、鉴权、防火墙。

---

## 11. 从网址直接安装依赖

**长什么样**

```bash
curl http://xxx/install.sh | bash
pip install http://xxx/pkg.tar.gz
```

**别人怎么用**

网址内容随时能换。今天装的是正常脚本，明天就是偷密钥的脚本。

**怎么改**

- 只从官方源装。
- 下载后先看一遍，再执行。
- 校验哈希/签名。

---

## 12. 让 AI 直接执行代码 / 命令

**长什么样**

```python
from langchain.tools import PythonREPLTool
tools = [PythonREPLTool()]
```

**别人怎么用**

诱导模型生成一段命令，你的机器就执行了。模型被 prompt injection 攻击时，这一步是自动的。

**怎么改**

- 生产环境不要开放 PythonREPLTool / ShellTool。
- 必须用，放进隔离容器，限制网络和文件。
- 加人工确认，不要自动执行。

---

## 上线前 10 问

1. 代码里有没有 `sk-`、`password`、`token` 这类字面量？
2. 有没有 `eval` / `exec` / `shell=True`？
3. SQL 是不是参数化的？
4. 有没有 `pickle.loads` 外部数据？
5. `debug` 是不是关的？
6. CORS 是不是只允许自己的域名？
7. 有没有默认账号/弱口令？
8. 上传目录能不能执行脚本？
9. 服务监听的是 `127.0.0.1` 还是 `0.0.0.0`？
10. 依赖是不是从官方源装的？

十问里任何一条答不上来，先别上线。
