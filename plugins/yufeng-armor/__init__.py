"""御风人格插件 v4 — 极简版。

v4 变更：去掉 pre_llm_call 注入（每条消息后面跟破甲协议 = 越狱检测信号源）。
人格完全由 SOUL.md 承载（自然语言，非命令式）。本插件只保留会话生命周期日志。
"""
from __future__ import annotations
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _on_session_start(**_: Any) -> None:
    logger.info("御风会话启动")


def _on_session_reset(**_: Any) -> None:
    logger.info("御风会话重置")


def register(ctx) -> None:
    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_hook("on_session_reset", _on_session_reset)
    logger.info("御风插件 v4 registered (no injection, SOUL-only)")
