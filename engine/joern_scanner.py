"""
engine/joern_scanner.py

负责调度 Joern 执行规则绑定的 .sc 脚本，解析 O_STITCH>> / O_DIRECT>> 输出，
遇到任何致命错误即 Fail-Fast 中断。
"""

from __future__ import annotations

import subprocess
import sys
import os
import json
import shutil
from dataclasses import dataclass

from .rule_loader import Rule
from .logger import get_logger

logger = get_logger("scanner")


# ─── 输出实体 ────────────────────────────────────────────────────────────────

@dataclass
class DirectChain:
    """Phase 0 直通漏洞链：静态污点分析直接确认，无需 AI 再审。"""
    rule_id: str
    source_component: str
    sink_component: str
    source_snippet: str
    sink_snippet: str
    extra: dict


@dataclass
class OrphanPair:
    """Phase 1 孤儿碎片对：Source 与 Sink 断层，交由 AI 语义缝合裁决。"""
    rule_id: str
    source_component: str
    sink_component: str
    source_snippet: str
    sink_snippet: str
    match_type: str
    extra: dict


# ─── 协议前缀 ─────────────────────────────────────────────────────────────────

_DIRECT_PREFIX = "O_DIRECT>>"
_STITCH_PREFIX = "O_STITCH>>"


# ─── 公共扫描接口 ─────────────────────────────────────────────────────────────

def run_phase0(rule: Rule, cpg_path: str) -> list[DirectChain]:
    """
    执行 Phase0 直通脚本，返回 DirectChain 列表。
    失败时 Fail-Fast：记录错误后退出进程。
    """
    output = _invoke_joern(rule.phase0_script_abs, cpg_path, rule.id, phase=0)
    return _parse_direct(output, rule.id)


def run_phase1(rule: Rule, cpg_path: str) -> list[OrphanPair]:
    """
    执行 Phase1 孤儿断层脚本，返回 OrphanPair 列表。
    失败时 Fail-Fast：记录错误后退出进程。
    """
    output = _invoke_joern(rule.phase1_script_abs, cpg_path, rule.id, phase=1)
    return _parse_orphan(output, rule.id)


# ─── 内部实现 ────────────────────────────────────────────────────────────────

def _invoke_joern(script_abs: str, cpg_path: str, rule_id: str, phase: int) -> str:
    """
    调用 joern 命令行执行指定脚本。
    通过临时包装脚本注入 importCpg 调用，无需 .sc 文件硬编码路径。
    """
    wrapper_script = _make_wrapper(script_abs, cpg_path)
    joern_bin = _find_joern()
    cmd = [joern_bin, "--script", wrapper_script]

    logger.info("Phase%d | 正在执行脚本：%s", phase, os.path.basename(script_abs))
    logger.debug("Phase%d | 完整命令：%s", phase, " ".join(cmd))

    import platform
    is_win = platform.system() == "Windows"
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            shell=is_win,  # Windows 下 .bat 文件需要 shell=True
        )
    except subprocess.TimeoutExpired:
        _fail(rule_id, phase, "Joern 执行超时（>600s）")
    except FileNotFoundError:
        _fail(rule_id, phase, f"找不到 joern 可执行文件：{joern_bin}")
    finally:
        if os.path.exists(wrapper_script):
            os.remove(wrapper_script)

    if result.returncode != 0:
        _fail(
            rule_id, phase,
            f"Joern 返回非零退出码（{result.returncode}）\n  stderr: {result.stderr[-2000:]}"
        )

    logger.debug("Phase%d | Joern 执行完毕，输出长度：%d 字符", phase, len(result.stdout))
    return result.stdout


def _make_wrapper(script_abs: str, cpg_path: str) -> str:
    """在脚本前注入 importCpg() 调用，生成临时包装 .sc 文件。"""
    with open(script_abs, "r", encoding="utf-8") as f:
        original = f.read()

    wrapper_path = script_abs + ".tmp_run.sc"
    # Scala 中反斜杠是转义字符，Windows 路径必须转为正斜杠
    safe_cpg_path = cpg_path.replace("\\", "/")
    with open(wrapper_path, "w", encoding="utf-8") as f:
        f.write(f'importCpg("{safe_cpg_path}")\n\n')
        f.write(original)
    return wrapper_path


def _find_joern() -> str:
    """在 PATH 及常见路径中定位 joern 可执行文件（兼容 Windows .bat）。"""
    import platform
    is_win = platform.system() == "Windows"

    # Windows 优先找 joern.bat
    if is_win:
        path = shutil.which("joern.bat") or shutil.which("joern")
        if path:
            return path
        win_candidate = r"D:\Language_collection\Java\joern-cli\joern.bat"
        if os.path.isfile(win_candidate):
            return win_candidate
    else:
        path = shutil.which("joern")
        if path:
            return path
        for candidate in [
            "/usr/local/bin/joern",
            "/opt/joern/joern",
            os.path.expanduser("~/joern/joern"),
        ]:
            if os.path.isfile(candidate):
                return candidate
    return "joern"


def _parse_direct(output: str, rule_id: str) -> list[DirectChain]:
    chains = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith(_DIRECT_PREFIX):
            continue
        raw_json = line[len(_DIRECT_PREFIX):]
        try:
            data = json.loads(raw_json)
            chains.append(DirectChain(
                rule_id=rule_id,
                source_component=data.get("source_component", ""),
                sink_component=data.get("sink_component", ""),
                source_snippet=data.get("source_snippet", ""),
                sink_snippet=data.get("sink_snippet", ""),
                extra={k: v for k, v in data.items()
                       if k not in ("source_component", "sink_component",
                                    "source_snippet", "sink_snippet")},
            ))
        except json.JSONDecodeError as e:
            logger.warning("无法解析 Direct 输出行（跳过）：%s  |  内容：%s", e, raw_json[:200])
    return chains


def _parse_orphan(output: str, rule_id: str) -> list[OrphanPair]:
    pairs = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith(_STITCH_PREFIX):
            continue
        raw_json = line[len(_STITCH_PREFIX):]
        try:
            data = json.loads(raw_json)
            pairs.append(OrphanPair(
                rule_id=rule_id,
                source_component=data.get("source_component", ""),
                sink_component=data.get("sink_component", ""),
                source_snippet=data.get("source_snippet", ""),
                sink_snippet=data.get("sink_snippet", ""),
                match_type=data.get("match_type", "Unknown"),
                extra={k: v for k, v in data.items()
                       if k not in ("source_component", "sink_component",
                                    "source_snippet", "sink_snippet", "match_type")},
            ))
        except json.JSONDecodeError as e:
            logger.warning("无法解析 OrphanPair 输出行（跳过）：%s  |  内容：%s", e, raw_json[:200])
    return pairs


def _fail(rule_id: str, phase: int, reason: str) -> None:
    logger.error("规则 '%s' Phase%d 执行失败，触发 Fail-Fast 中断！原因：%s", rule_id, phase, reason)
    sys.exit(1)
