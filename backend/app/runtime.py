import os
import subprocess

from app.config import settings


def openssl_version() -> str:
    """返回 PATH 上 openssl 的第一行版本。macOS 自带 LibreSSL，开发时把 Homebrew openssl@3 的 bin 放在 PATH 前面。"""
    completed = subprocess.run(
        ["openssl", "version"],
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "openssl 执行失败"
        raise RuntimeError(detail)
    lines = completed.stdout.strip().splitlines()
    if not lines:
        raise RuntimeError("openssl 没有输出版本")
    return lines[0]


def ensure_runtime() -> str:
    """OpenSSL 3 才继续。信任库路径为空时放行，便于 macOS 开发；路径有值但文件不存在则拒绝。"""
    version = openssl_version()
    if not version.startswith("OpenSSL 3"):
        raise RuntimeError(f"需要 OpenSSL 3，当前是 {version}")
    bundle = settings.ca_bundle
    if bundle and not os.path.isfile(bundle):
        raise RuntimeError(f"信任库不存在: {bundle}")
    return version
