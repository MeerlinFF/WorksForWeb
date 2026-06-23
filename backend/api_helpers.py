"""
API 工厂函数
将重复的 scan / stream / result 端点模式抽取为通用工厂，
添加新功能模块时只需一行调用。
"""

import json
import threading
import uuid
import asyncio
from typing import Callable, Optional

from fastapi import HTTPException
from fastapi.responses import StreamingResponse, Response
from pydantic import BaseModel


def register_scan_api(
    app,
    *,
    prefix: str,
    task_store: dict[str, dict],
    scan_func: Callable,
    request_model: type[BaseModel],
    build_kwargs: Optional[Callable] = None,
) -> None:
    """
    为一个扫描功能注册 3 个标准 API 端点：scan / stream / result。

    参数:
        app:            FastAPI 实例
        prefix:         URL 前缀，如 "junk" → /api/junk/scan
        task_store:     任务状态字典，如 junk_tasks
        scan_func:      扫描函数，签名为 (..., progress_callback=None) -> dict
        request_model:  Pydantic 请求模型
        build_kwargs:   可选，签名 (req) -> dict，将请求转为 scan_func 的 kwargs。
                        默认行为：将 req 的所有字段按原样传入。
    """

    # ---- 启动扫描 ----
    @app.post(f"/api/{prefix}/scan")
    async def _start_scan(req: request_model):  # noqa: F811
        task_id = str(uuid.uuid4())[:8]
        task_store[task_id] = {
            "status": "pending",
            "progress_current": 0,
            "progress_total": 0,
            "result": None,
            "error": None,
        }

        def _run():
            try:
                def on_progress(phase: str, current: int, total: int):
                    task_store[task_id].update({
                        "status": "scanning",
                        "progress_current": current,
                        "progress_total": total,
                    })

                if build_kwargs:
                    kwargs = build_kwargs(req)
                else:
                    kwargs = req.model_dump()
                kwargs["progress_callback"] = on_progress

                result = scan_func(**kwargs)
                task_store[task_id].update({
                    "status": "done",
                    "progress_current": 0,
                    "progress_total": 0,
                    "result": result,
                })
            except Exception as e:
                task_store[task_id].update({"status": "error", "error": str(e)})

        threading.Thread(target=_run, daemon=True).start()
        return {"task_id": task_id}

    # ---- SSE 实时进度 ----
    @app.get(f"/api/{prefix}/scan/{{task_id}}/stream")
    async def _stream_progress(task_id: str):
        if task_id not in task_store:
            raise HTTPException(404, "任务不存在")

        async def event_generator():
            last_state = None
            while True:
                task = task_store.get(task_id)
                if task is None:
                    break
                current = {
                    "status": task["status"],
                    "progress_current": task["progress_current"],
                    "progress_total": task["progress_total"],
                    "error": task.get("error"),
                }
                if current != last_state:
                    yield f"data: {json.dumps(current)}\n\n"
                    last_state = current.copy()
                if task["status"] in ("done", "error"):
                    break
                await asyncio.sleep(0.3)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    # ---- 获取结果 ----
    @app.get(f"/api/{prefix}/scan/{{task_id}}/result")
    async def _get_result(task_id: str):
        task = task_store.get(task_id)
        if not task:
            raise HTTPException(404, "任务不存在")
        if task["status"] == "error":
            raise HTTPException(500, task.get("error"))
        if task["status"] != "done":
            raise HTTPException(400, "扫描尚未完成")

        try:
            body = json.dumps(task["result"], ensure_ascii=False, default=str)
        except (TypeError, ValueError) as e:
            raise HTTPException(500, f"结果序列化失败: {e}")

        return Response(content=body, media_type="application/json")
