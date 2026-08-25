"""
engine/llm_stitcher.py

并发地将 OrphanPair 发送给大语言模型进行语义裁决。
引擎保持无状态：不做任何本地缓存，每次扫描均获得独立的新鲜裁决。
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore

from .rule_loader import Rule
from .joern_scanner import OrphanPair
from .logger import get_logger

logger = get_logger("stitcher")


# ─── 输出实体 ────────────────────────────────────────────────────────────────

@dataclass
class StitchedChain:
    rule_id: str
    source_component: str
    sink_component: str
    source_snippet: str
    sink_snippet: str
    match_type: str
    verdict: str      # "[EXPLOITABLE]" 或 "[SAFE]"
    reasoning: str    # AI 给出的推理全文
    extra: dict = field(default_factory=dict)


# ─── 缝合入口 ─────────────────────────────────────────────────────────────────

def stitch_chains(
    orphan_pairs: list[OrphanPair],
    rule: Rule,
    api_key: str,
    api_base: str,
    model: str,
    timeout: int = 120,
    max_workers: int = 6,
) -> list[StitchedChain]:
    """
    并发地将所有孤儿碎片对发送给 LLM 裁决，按原始顺序返回结果。

    - max_workers：并发线程数，控制 API 请求速率，默认 6。
    - 无状态：不依赖任何本地缓存，每次调用都获得新鲜裁决。
    - 单个任务失败时降级为 [SAFE] 并记录 WARNING，不影响其他任务。
    """
    if OpenAI is None:
        raise ImportError("请先安装 openai 包：pip install openai")

    client = OpenAI(api_key=api_key, base_url=api_base)
    total = len(orphan_pairs)
    logger.info("AI 裁决并发数：%d  |  待处理：%d 组", max_workers, total)

    results: list[Optional[StitchedChain]] = [None] * total
    completed_count = 0
    count_lock = threading.Lock()

    def _judge(idx: int, pair: OrphanPair) -> tuple[int, StitchedChain]:
        prompt = _build_prompt(pair, rule)
        verdict, reasoning = _call_llm(
            client, model, prompt,
            rule.llm.max_tokens, rule.llm.temperature, timeout,
        )
        return idx, StitchedChain(
            rule_id=pair.rule_id,
            source_component=pair.source_component,
            sink_component=pair.sink_component,
            source_snippet=pair.source_snippet,
            sink_snippet=pair.sink_snippet,
            match_type=pair.match_type,
            verdict=verdict,
            reasoning=reasoning,
            extra=pair.extra,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_judge, idx, pair): idx
            for idx, pair in enumerate(orphan_pairs)
        }

        for future in as_completed(futures):
            idx = futures[future]
            try:
                idx, chain = future.result()
                results[idx] = chain
                with count_lock:
                    completed_count += 1
                    cnt = completed_count
                logger.info(
                    "[AI %d/%d] %s → %s  =>  %s",
                    cnt, total,
                    ".".join(chain.source_component.split(":")[0].split(".")[-2:]),
                    ".".join(chain.sink_component.split(":")[0].split(".")[-2:]),
                    chain.verdict,
                )
            except Exception as e:
                logger.warning("AI 裁决任务 #%d 异常，降级为 [SAFE]：%s", idx, e)
                pair = orphan_pairs[idx]
                results[idx] = StitchedChain(
                    rule_id=pair.rule_id,
                    source_component=pair.source_component,
                    sink_component=pair.sink_component,
                    source_snippet=pair.source_snippet,
                    sink_snippet=pair.sink_snippet,
                    match_type=pair.match_type,
                    verdict="[SAFE]",
                    reasoning=f"并发执行异常，降级处理：{e}",
                    extra=pair.extra,
                )

    return [r for r in results if r is not None]


# ─── Prompt 构建 ──────────────────────────────────────────────────────────────

def _build_prompt(pair: OrphanPair, rule: Rule) -> str:
    import json
    chain_nodes_raw = pair.extra.get("chain_nodes", [])
    chain_nodes_json_str = json.dumps(chain_nodes_raw, ensure_ascii=False, indent=2)

    return rule.llm.prompt_template.format(
        source_snippet=pair.source_snippet,
        sink_snippet=pair.sink_snippet,
        vuln_type=rule.llm.vuln_type,
        call_chain=pair.extra.get("call_chain", ""),
        chain_nodes_json=chain_nodes_json_str,
        breakpoint_method=pair.extra.get("breakpoint_method", ""),
        breakpoint_code=pair.extra.get("breakpoint_code", "")
    )


# ─── LLM 调用 ────────────────────────────────────────────────────────────────

def _call_llm(
    client,
    model: str,
    prompt: str,
    max_tokens: int,
    temperature: float,
    timeout: int,
) -> tuple[str, str]:
    import time
    
    max_retries = 9
    base_wait = 5 
    
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=timeout,
                stream=True,
            )
            full_text = ""
            for chunk in resp:
                if chunk.choices and chunk.choices[0].delta.content:
                    full_text += chunk.choices[0].delta.content
            full_text = full_text.strip()
            break
        except Exception as e:
            if attempt < max_retries - 1:
                wait_time = base_wait * (2 ** attempt)
                logger.debug(f"⚠️ API 频控或网络异常，{wait_time}秒后将触发第 {attempt + 1} 次退避重试... | Error: {e}")
                time.sleep(wait_time)
            else:
                logger.debug("LLM 调用连续失败 %d 次，放弃并降级为 [SAFE]：%s", max_retries, e)
                return "[SAFE]", f"LLM 调用持续异常：{e}"

    lines = full_text.splitlines()
    first_line = lines[0].strip() if lines else ""

    if "[EXPLOITABLE]" in first_line:
        verdict = "[EXPLOITABLE]"
    elif "[SAFE]" in first_line:
        verdict = "[SAFE]"
    elif "[EXPLOITABLE]" in full_text:
        verdict = "[EXPLOITABLE]"
    else:
        verdict = "[SAFE]"

    reasoning = "\n".join(lines[1:]).strip() if len(lines) > 1 else full_text
    return verdict, reasoning
