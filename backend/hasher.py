"""
哈希算法模块 —— 可插拔的文件哈希计算。
如需添加新算法（MD5、BLAKE3 等），只需新增函数并在 HASHERS 中注册。
"""

import hashlib
import sys
from typing import Callable


DEFAULT_CHUNK_SIZE = 8192


def _long_path(path: str) -> str:
    if sys.platform == "win32" and not path.startswith("\\\\?\\"):
        if len(path) > 248:
            return "\\\\?\\" + path
    return path


def sha256(filepath: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """SHA256 哈希（当前默认算法）"""
    sha = hashlib.sha256()
    try:
        with open(_long_path(filepath), "rb") as f:
            while chunk := f.read(chunk_size):
                sha.update(chunk)
        return sha.hexdigest()
    except (PermissionError, OSError):
        return ""


def md5(filepath: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """MD5 哈希（速度快，但存在碰撞风险，仅用于非安全场景）"""
    h = hashlib.md5()
    try:
        with open(_long_path(filepath), "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return ""


# 算法注册表：{名称: 函数}
HASHERS: dict[str, Callable[[str, int], str]] = {
    "sha256": sha256,
    "md5": md5,
}

# 默认算法
DEFAULT_HASHER = "sha256"


def compute(filepath: str, algorithm: str = DEFAULT_HASHER, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """统一入口：根据算法名计算文件哈希"""
    if algorithm not in HASHERS:
        raise ValueError(f"不支持的算法: {algorithm}，可用: {list(HASHERS.keys())}")
    return HASHERS[algorithm](filepath, chunk_size)
