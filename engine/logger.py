"""
engine/logger.py

统一日志配置入口。

引擎内所有模块均通过 get_logger() 获取自己的 Logger，
不直接使用 print()，保证外部平台（SDK 模式）可以完全接管日志行为。

日志持久化策略：
  - CLI 模式：同时写入 stdout（带颜色）和 output/logs/<timestamp>.log 文件
  - SDK 模式：调用方自行配置 Handler，引擎不做任何输出
"""

import datetime
import logging
import os
import sys

_ROOT_LOGGER = "hybris_sast"
_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output", "logs")


def get_logger(name: str) -> logging.Logger:
    """
    各模块通过此函数获取命名 Logger。

    用法：
        from .logger import get_logger
        logger = get_logger("scanner")
        logger.info("Phase 0 执行中...")
    """
    return logging.getLogger(f"{_ROOT_LOGGER}.{name}")


def configure_cli_logging(verbose: bool = False) -> str:
    """
    CLI 模式下调用一次，同时配置：
      1. 彩色 StreamHandler -> stdout
      2. FileHandler -> output/logs/hybris_<timestamp>.log
    SDK 嵌入模式下不调用此函数，由调用方自行配置 Handler。

    返回本次生成的日志文件路径。
    """
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger(_ROOT_LOGGER)

    # 幂等：已经配置过就直接返回
    if root.handlers:
        return ""

    root.setLevel(logging.DEBUG)  # Root 必须允许 DEBUG 穿透，否则 file_handler 即使设为 DEBUG 也接收不到

    # ── Handler 1: 终端输出（带颜色） ──
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)  # 仅在此处拦截控制终端的输出级别
    console_handler.setFormatter(_ColorFormatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    ))
    root.addHandler(console_handler)

    # ── Handler 2: 文件持久化（无颜色转义字符） ──
    os.makedirs(_LOG_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(_LOG_DIR, f"hybris_{ts}.log")

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)  # 文件始终保存全量 DEBUG 日志
    file_handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(file_handler)

    return log_file


# ─── 带颜色的 Formatter（仅在 TTY 下生效） ────────────────────────────────────

_LEVEL_COLORS = {
    "DEBUG":    "\033[37m",     # 灰白
    "INFO":     "\033[36m",     # 青色
    "WARNING":  "\033[33m",     # 黄色
    "ERROR":    "\033[31m",     # 红色
    "CRITICAL": "\033[1;31m",   # 加粗红色
}
_RESET = "\033[0m"


class _ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if sys.stdout.isatty():
            color = _LEVEL_COLORS.get(record.levelname, "")
            return f"{color}{msg}{_RESET}"
        return msg
