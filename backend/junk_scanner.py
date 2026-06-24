"""
垃圾文件扫描引擎
模拟火绒垃圾清理逻辑，扫描系统常见垃圾文件。
"""

import os
import sys
import fnmatch
from collections import defaultdict
from typing import Callable, Optional


def _long_path(path: str) -> str:
    """Windows 长路径支持"""
    if sys.platform == "win32" and not path.startswith("\\\\?\\"):
        if len(path) > 248:
            return "\\\\?\\" + path
    return path


def _sanitize_path(path: str) -> str:
    """清理路径中的非法 Unicode 字符（孤立代理对等），确保 JSON 可序列化"""
    try:
        return path.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return path.encode("ascii", errors="replace").decode("ascii")


def format_size(size_bytes: int) -> str:
    n: float = size_bytes
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---- 预定义扫描类别 ----
# 每个类别包含: name(显示名), description, paths(扫描路径列表), patterns(文件名匹配模式)
JUNK_CATEGORIES: list[dict] = [
    {
        "id": "system_temp",
        "name": "系统临时文件",
        "description": "Windows 系统和应用程序产生的临时文件，删除后不影响系统运行",
        "paths": [
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Temp"),
        ],
        "patterns": ["*.*"],
        "max_depth": 0,           # 0 表示不限深度
        "min_size": 0,
        "icon": "⚙️",
    },
    {
        "id": "recycle_bin",
        "name": "回收站",
        "description": "回收站中的文件，确认不再需要后可清理",
        "paths": [],
        "patterns": ["*.*"],
        "max_depth": 0,
        "min_size": 0,
        "icon": "🗑️",
        "special": "recycle",     # 特殊处理标记
    },
    {
        "id": "browser_cache",
        "name": "浏览器缓存",
        "description": "Chrome、Edge、Firefox 等浏览器的缓存文件",
        "paths": [],
        "patterns": ["*.*"],
        "max_depth": 0,
        "min_size": 0,
        "icon": "🌐",
        "special": "browser_cache",
    },
    {
        "id": "windows_update",
        "name": "Windows 更新缓存",
        "description": "Windows Update 下载的更新安装包，安装后可安全删除",
        "paths": [
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "SoftwareDistribution", "Download"),
        ],
        "patterns": ["*.*"],
        "max_depth": 0,
        "min_size": 0,
        "icon": "🔄",
    },
    {
        "id": "thumb_cache",
        "name": "缩略图缓存",
        "description": "Windows 资源管理器生成的缩略图缓存数据库文件",
        "paths": [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Explorer") if os.environ.get("LOCALAPPDATA") else "",
        ],
        "patterns": ["thumbcache_*.db", "Thumbs.db", "iconcache_*.db"],
        "max_depth": 1,
        "min_size": 0,
        "icon": "🖼️",
    },
    {
        "id": "log_files",
        "name": "日志文件",
        "description": "系统和应用程序产生的日志文件（.log）",
        "paths": [
            os.environ.get("TEMP", ""),
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Temp"),
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Logs"),
        ],
        "patterns": ["*.log", "*.log.*", "*.etl"],
        "max_depth": 2,
        "min_size": 0,
        "icon": "📋",
    },
    {
        "id": "prefetch",
        "name": "预读取文件",
        "description": "Windows 预读取缓存，用于加速程序启动，删除后下次启动会重建",
        "paths": [
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Prefetch"),
        ],
        "patterns": ["*.pf"],
        "max_depth": 0,
        "min_size": 0,
        "icon": "⚡",
    },
    {
        "id": "recent_docs",
        "name": "最近文档记录",
        "description": "「最近使用的文件」快捷方式列表，清除不会删除原文件",
        "paths": [
            os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent") if os.environ.get("APPDATA") else "",
        ],
        "patterns": ["*.lnk"],
        "max_depth": 0,
        "min_size": 0,
        "icon": "📄",
    },
    {
        "id": "crash_dumps",
        "name": "崩溃转储文件",
        "description": "程序崩溃时产生的 .dmp 内存转储文件，通常较大",
        "paths": [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "CrashDumps") if os.environ.get("LOCALAPPDATA") else "",
            os.environ.get("TEMP", ""),
        ],
        "patterns": ["*.dmp", "*.mdmp", "*.hdmp"],
        "max_depth": 1,
        "min_size": 0,
        "icon": "⚠️",
    },
]


def _get_recycle_bin_paths() -> list[str]:
    """获取所有驱动器的回收站路径"""
    paths = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            rb = os.path.join(drive, "$Recycle.Bin")
            if os.path.isdir(rb):
                paths.append(rb)
    return paths


def _get_browser_cache_paths() -> list[str]:
    """获取常见浏览器的缓存目录"""
    paths = []
    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        return paths

    browsers = [
        # Chrome
        (os.path.join(local, "Google", "Chrome", "User Data", "Default", "Cache"), "Cache"),
        (os.path.join(local, "Google", "Chrome", "User Data", "Default", "Code Cache"), "Code Cache"),
        # Edge
        (os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "Cache"), "Cache"),
        (os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "Code Cache"), "Code Cache"),
        # Firefox
        (os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles"), ""),
    ]

    for base, _sub in browsers:
        if not base or not os.path.exists(base):
            continue
        if "Firefox" in base:
            # Firefox 需要进入 profiles 子目录
            try:
                for profile in os.listdir(base):
                    cache_dir = os.path.join(base, profile, "cache2")
                    if os.path.isdir(cache_dir):
                        paths.append(cache_dir)
            except PermissionError:
                pass
        else:
            paths.append(base)
    return paths


def _collect_files(path: str, patterns: list[str], max_depth: int, collected: list) -> None:
    """递归收集匹配的文件"""
    if not path or not os.path.isdir(path):
        return

    try:
        entries = os.listdir(_long_path(path))
    except (PermissionError, OSError):
        return

    for name in entries:
        full = os.path.join(path, name)
        try:
            if os.path.isfile(full):
                for pat in patterns:
                    if fnmatch.fnmatch(name.lower(), pat.lower()):
                        try:
                            collected.append((full, os.path.getsize(full)))
                        except OSError:
                            collected.append((full, 0))
                        break
            elif os.path.isdir(full) and max_depth != 0:
                # 跳过系统隐藏目录
                if name.startswith(".") or name in ("System Volume Information",):
                    continue
                _collect_files(full, patterns, max_depth - 1 if max_depth > 0 else 0, collected)
        except (PermissionError, OSError):
            continue


def scan_junk(
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    selected_categories: Optional[list[str]] = None,
    custom_dir: str = "",
) -> dict:
    """
    扫描垃圾文件，返回分类结果。

    参数:
        progress_callback: 进度回调 (phase, current, total)
        selected_categories: 要扫描的类别 ID 列表，None 表示全部
        custom_dir:         用户自定义扫描目录，非空时额外扫描该目录下所有文件
    """
    categories = list(JUNK_CATEGORIES)
    if selected_categories:
        categories = [c for c in JUNK_CATEGORIES if c["id"] in selected_categories]

    # 自定义目录：构造一个虚拟类别
    if custom_dir and os.path.isdir(custom_dir):
        categories.append({
            "id": "custom_dir",
            "name": f"自定义目录: {custom_dir}",
            "description": f"扫描指定目录下的所有文件: {custom_dir}",
            "paths": [custom_dir],
            "patterns": ["*.*"],
            "max_depth": 0,
            "min_size": 0,
            "icon": "📁",
        })

    total_categories = len(categories)
    results: list[dict] = []

    for cat_idx, cat in enumerate(categories):
        try:
            _scan_single_category(cat, results)
        except Exception as e:
            results.append({
                "category_id": cat["id"],
                "category_name": cat["name"],
                "category_desc": cat.get("description", ""),
                "icon": cat.get("icon", ""),
                "file_count": 0,
                "size_bytes": 0,
                "size_display": "0 B",
                "files": [],
                "error": str(e),
            })

        if progress_callback:
            progress_callback("scan", cat_idx + 1, total_categories)

    total_files = sum(r["file_count"] for r in results)
    total_size = sum(r["size_bytes"] for r in results)

    return {
        "total_files": total_files,
        "total_size_bytes": total_size,
        "total_size_display": format_size(total_size),
        "categories": results,
    }


def _scan_single_category(cat: dict, results: list) -> None:
    """扫描单个类别，结果追加到 results 列表"""
    # 确定实际扫描路径
    if cat.get("special") == "recycle":
        scan_paths = _get_recycle_bin_paths()
    elif cat.get("special") == "browser_cache":
        scan_paths = _get_browser_cache_paths()
    else:
        scan_paths = [p for p in cat["paths"] if p and os.path.isdir(p)]

    collected: list[tuple[str, int]] = []
    for sp in scan_paths:
        _collect_files(sp, cat["patterns"], cat["max_depth"], collected)

    # 去重，计算大小
    seen = set()
    unique_files: list[dict] = []
    cat_size = 0
    for fpath, fsize in collected:
        norm = fpath.lower()
        if norm not in seen:
            seen.add(norm)
            try:
                sz = os.path.getsize(fpath)
            except OSError:
                sz = fsize
            unique_files.append({
                "path": _sanitize_path(fpath),
                "size_bytes": sz,
                "size_display": format_size(sz),
            })
            cat_size += sz

    results.append({
        "category_id": cat["id"],
        "category_name": cat["name"],
        "category_desc": cat.get("description", ""),
        "icon": cat.get("icon", ""),
        "file_count": len(unique_files),
        "size_bytes": cat_size,
        "size_display": format_size(cat_size),
        "files": unique_files,
    })


def delete_junk_files(file_paths: list[str]) -> dict:
    """删除指定的垃圾文件"""
    deleted = []
    errors = []
    for fp in file_paths:
        try:
            if os.path.isfile(fp):
                os.remove(fp)
                deleted.append(fp)
            elif os.path.isdir(fp):
                import shutil
                shutil.rmtree(fp, ignore_errors=True)
                deleted.append(fp)
            else:
                errors.append({"path": fp, "error": "文件不存在"})
        except PermissionError:
            errors.append({"path": fp, "error": "权限不足，文件可能正在被占用"})
        except Exception as e:
            errors.append({"path": fp, "error": str(e)})
    return {"deleted": deleted, "errors": errors}
