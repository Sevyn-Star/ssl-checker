# SSL 证书在线检测

## 这是什么

免登录。输入一个域名，检测它在 443 端口上的证书有效期、域名是否匹配、信任链是否完整，并在剩余 30、15、7、3 天时给出提醒。

## 本地运行

需要 Python 3.12 或更新版本。

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --port 8000
```

另开一个终端：

```bash
cd frontend
npm install
npm run dev
```

打开 http://localhost:5173 。

## Docker

```bash
docker compose up --build
```

打开 http://127.0.0.1:8080 。

## 检测范围

这一版做三件事：证书是否在有效期内、域名是否匹配、信任链是否完整。HSTS、443 以外的端口和批量监控不在这一版。

## 信任结果

信任结果依赖运行环境里的 `ca-certificates`。它表示这台服务信任该证书，不表示所有浏览器的根证书库都相同。

## 测试

下面两条不需要外网。`python` 是上一节虚拟环境里的解释器。

```bash
cd backend
source .venv/bin/activate
python -m pytest
```

```bash
cd frontend
npm test
```
