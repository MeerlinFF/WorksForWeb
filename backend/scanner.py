"""
重复文件扫描引擎
提供异步扫描功能，通过回调函数实时报告进度。
"""

import os
import sys
from collections import defaultdict
from typing import Callable, Optional, Iterable

from hasher import compute


DEFAULT_SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".conda"}


def _long_path(path: str) -> str:
    """Windows 长路径支持：超过 260 字符自动加 \\\\?\\ 前缀"""
    if sys.platform == "win32" and not path.startswith("\\\\?\\"):
        if len(path) > 248:
            return "\\\\?\\" + path
    return path


def format_size(size_bytes: int) -> str:
    n: float = size_bytes
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def scan_duplicates(
    scan_dirs: str | Iterable[str],
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    skip_dirs: Optional[set[str]] = None,
) -> dict:
    """扫描一个或多个目录，返回重复文件信息。"""
    if isinstance(scan_dirs, str):
        scan_dirs = [scan_dirs]
    if skip_dirs is None:
        skip_dirs = DEFAULT_SKIP_DIRS

    dirs_list = list(scan_dirs)
    scan_label = dirs_list[0] if len(dirs_list) == 1 else f"{dirs_list[0]} 等 {len(dirs_list)} 个目录"

    # ---- 阶段 1：收集文件 ----
    size_to_files: dict[int, list[str]] = defaultdict(list)
    file_count = 0

    for d in dirs_list:
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in skip_dirs]
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    size = os.path.getsize(_long_path(filepath))
                except OSError:
                    continue
                if size > 0:
                    size_to_files[size].append(filepath)
                    file_count += 1

    if progress_callback:
        progress_callback("collect", file_count, file_count)

    # ---- 阶段 2：计算哈希 ----
    hash_to_files: dict[str, list[str]] = defaultdict(list)
    candidates = {s: p for s, p in size_to_files.items() if len(p) >= 2}
    total_hash = sum(len(v) for v in candidates.values())
    hashed = 0

    for size, filepaths in candidates.items():
        for filepath in filepaths:
            h = compute(filepath)
            if h:
                hash_to_files[h].append(filepath)
            hashed += 1
            if progress_callback:
                progress_callback("hash", hashed, total_hash)

    if progress_callback:
        progress_callback("hash", total_hash, total_hash)

    # ---- 阶段 3：整理结果 ----
    duplicate_groups = []
    wasted_bytes = 0
    for h, paths in hash_to_files.items():
        if len(paths) >= 2:
            group_size = os.path.getsize(_long_path(paths[0])) if os.path.exists(_long_path(paths[0])) else 0
            wasted_bytes += (len(paths) - 1) * group_size
            duplicate_groups.append({
                "hash": h,
                "size_bytes": group_size,
                "size_display": format_size(group_size),
                "files": sorted(paths),
            })

    # 按浪费空间从大到小排序
    duplicate_groups.sort(key=lambda g: g["size_bytes"] * (len(g["files"]) - 1), reverse=True)

    return {
        "scan_dir": scan_label,
        "total_files": file_count,
        "duplicate_groups": duplicate_groups,
        "duplicate_file_count": sum(len(g["files"]) for g in duplicate_groups),
        "wasted_bytes": wasted_bytes,
        "wasted_display": format_size(wasted_bytes),
    }
