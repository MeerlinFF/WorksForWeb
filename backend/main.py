"""
FastAPI 后端服务 —— 系统清理工具箱
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os
from datetime import datetime

from scanner import scan_duplicates, format_size
from junk_scanner import scan_junk, delete_junk_files
from api_helpers import register_scan_api

app = FastAPI(title="系统清理工具箱")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
#  静态文件 & 页面路由
# ============================================================
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


def _serve_page(route: str, filename: str):
    @app.get(route)
    async def _handler():
        path = os.path.join(frontend_dir, filename)
        if os.path.exists(path):
            return FileResponse(path)
        return {"message": "页面不存在"}


_serve_page("/", "nav.html")
_serve_page("/index.html", "index.html")
_serve_page("/junk.html", "junk.html")


@app.get("/favicon.ico")
async def favicon():
    from fastapi.responses import Response
    return Response(status_code=204)


# ============================================================
#  通用 API
# ============================================================
@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/default_dir")
async def get_default_dir():
    return {"dir": os.path.join(os.path.expanduser("~"), "Documents")}


class BrowseRequest(BaseModel):
    path: str = ""


@app.post("/api/browse")
async def browse_directory(req: BrowseRequest):
    target = req.path.strip()
    if not target:
        import string
        drives = []
        for letter in string.ascii_uppercase:
            p = f"{letter}:\\"
            if os.path.exists(p):
                drives.append({"label": f"{letter}:", "path": p, "children": []})
        return {"nodes": drives}

    if not os.path.isdir(target):
        raise HTTPException(400, f"路径不存在: {target}")

    try:
        entries = os.listdir(target)
    except PermissionError:
        raise HTTPException(403, "无访问权限")

    nodes = []
    for name in sorted(entries, key=str.lower):
        full = os.path.join(target, name)
        if os.path.isdir(full) and not name.startswith("."):
            nodes.append({"label": name, "path": full, "children": []})
    return {"nodes": nodes}


# ============================================================
#  功能模块 1：重复文件扫描
# ============================================================
duplicate_tasks: dict[str, dict] = {}


class DuplicateScanRequest(BaseModel):
    directories: list[str]
    skip_dirs: list[str] = []


class DuplicateDeleteRequest(BaseModel):
    files: list[str]


register_scan_api(
    app,
    prefix="scan",
    task_store=duplicate_tasks,
    scan_func=scan_duplicates,
    request_model=DuplicateScanRequest,
    build_kwargs=lambda req: dict(
        scan_dirs=[d.strip() for d in req.directories if d.strip()],
        skip_dirs=set(req.skip_dirs) if req.skip_dirs else None,
    ),
)


@app.get("/api/scan/{task_id}/status")
async def get_scan_status(task_id: str):
    """轮询扫描状态（旧版兼容）"""
    task = duplicate_tasks.get(task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    return {
        "status": task["status"],
        "progress_current": task["progress_current"],
        "progress_total": task["progress_total"],
        "error": task.get("error"),
    }


@app.get("/api/scan/{task_id}/report")
async def get_scan_report(task_id: str):
    """生成文本报告"""
    task = duplicate_tasks.get(task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    if task["status"] != "done":
        raise HTTPException(400, "扫描尚未完成")
    result = task["result"]

    lines = [
        "=" * 70,
        "  重复文件检测报告",
        f"  扫描目录: {result['scan_dir']}",
        f"  生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70,
        "",
    ]

    if not result["duplicate_groups"]:
        lines.append("恭喜！未发现重复文件。")
    else:
        lines.append(f"发现 {len(result['duplicate_groups'])} 组重复文件")
        lines.append(f"涉及 {result['duplicate_file_count']} 个文件")
        lines.append(f"可释放空间约 {result['wasted_display']}")
        lines.append("-" * 70)
        lines.append("")
        for idx, group in enumerate(result["duplicate_groups"], 1):
            lines.append(
                f"【重复组 {idx}】 大小: {group['size_display']}  "
                f"SHA256: {group['hash']}"
            )
            for i, p in enumerate(group["files"], 1):
                lines.append(f"    {i}. {p}")
            lines.append("")

    return PlainTextResponse("\n".join(lines), media_type="text/plain; charset=utf-8")


@app.post("/api/delete")
async def delete_files(req: DuplicateDeleteRequest):
    """物理删除重复文件"""
    deleted, errors = [], []
    for f in req.files:
        if not os.path.isfile(f):
            continue
        try:
            os.remove(f)
            deleted.append(f)
        except Exception as e:
            errors.append({"file": f, "error": str(e)})
    return {"deleted": deleted, "errors": errors}


# ============================================================
#  功能模块 2：垃圾文件清理
# ============================================================
junk_tasks: dict[str, dict] = {}


class JunkScanRequest(BaseModel):
    categories: list[str] = []


class JunkCleanRequest(BaseModel):
    files: list[str]


register_scan_api(
    app,
    prefix="junk",
    task_store=junk_tasks,
    scan_func=scan_junk,
    request_model=JunkScanRequest,
    build_kwargs=lambda req: dict(
        selected_categories=req.categories if req.categories else None,
    ),
)


@app.post("/api/junk/clean")
async def clean_junk_files(req: JunkCleanRequest):
    if not req.files:
        raise HTTPException(400, "文件列表为空")
    return delete_junk_files(req.files)


# ============================================================
#  启动
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765)
