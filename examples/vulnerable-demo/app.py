# 这是一个故意写坏的项目，用来演示 ai-security-guard 能抓到什么。
# 不要在生产环境使用，也不要把这里的“密钥”当真。
import pickle
import subprocess

DEEPSEEK_API_KEY = "sk-demo000000000000000000000000000000"
password = "SuperSecret123"


def find_user(db, name):
    sql = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(sql)


def run(cmd):
    return subprocess.run(cmd, shell=True)


def load(data):
    return pickle.loads(data)


def calc(expr):
    return eval(expr)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
