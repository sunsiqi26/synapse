"""
engine/core.py

HybrisScanner：供外部平台以 SDK 方式调用的统一高层接口。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .rule_loader import load_rule, load_rules_from_dir, Rule, RuleLoadError
from .joern_scanner import run_phase0, run_phase1, DirectChain, OrphanPair
from .llm_stitcher import stitch_chains, StitchedChain
from .investigator_agent import run_concurrent_investigations
from .logger import get_logger
from .checkpoint import (
    compute_fingerprint, load_checkpoint, save_checkpoint, clear_checkpoint,
    load_completed_rules, save_completed_rule, remove_completed_rule,
    clear_all_completed_rules, clear_all_checkpoints
)

logger = get_logger("core")


# ─── 报告实体 ────────────────────────────────────────────────────────────────

@dataclass
class ScanReport:
    direct_chains: list[DirectChain] = field(default_factory=list)
    ai_chains: list[StitchedChain] = field(default_factory=list)

    @property
    def exploitable(self) -> list[StitchedChain]:
        return [c for c in self.ai_chains if c.verdict in ("[EXPLOITABLE]", "[UNCERTAIN]")]

    @property
    def safe(self) -> list[StitchedChain]:
        return [c for c in self.ai_chains if c.verdict == "[SAFE]"]

    def to_dict(self) -> dict:
        return {
            "direct_chains": [vars(c) for c in self.direct_chains],
            "ai_chains": [vars(c) for c in self.ai_chains],
            "summary": {
                "direct": len(self.direct_chains),
                "exploitable": len(self.exploitable),
                "safe": len(self.safe),
            },
        }


# ─── SDK 主类 ─────────────────────────────────────────────────────────────────

class HybrisScanner:
    """
    供外部平台嵌入使用的 Python SDK。

    用法：
        scanner = HybrisScanner(cpg_path="./demo.bin")
        scanner.load_rule("python/django/ssti")
        report = scanner.run()
        for vuln in report.exploitable:
            print(vuln.reasoning)
    """

    def __init__(self, cpg_path: str, source_dir: str | None = None, config_path: str | None = None):
        self.cpg_path = os.path.abspath(cpg_path)
        self.source_dir = os.path.abspath(source_dir) if source_dir else None
        self._rules: list[Rule] = []
        self._config = _load_config(config_path)

    def load_rule(self, rule_id: str) -> "HybrisScanner":
        """装载单条规则，返回自身以支持链式调用。"""
        self._rules.append(load_rule(rule_id))
        return self

    def load_rule_dir(self, rule_dir: str) -> "HybrisScanner":
        """装载整个规则目录，Fail-Fast 遇到错误。"""
        self._rules.extend(load_rules_from_dir(rule_dir))
        return self

    def _detect_resumable_rules(self, model: str) -> dict:
        """扫描所有已完成规则，校验指纹，返回可恢复的规则集"""
        raw = load_completed_rules()
        resumable = {}
        for rule in self._rules:
            if rule.id in raw:
                prompt_val = rule.llm.phase3_prompt if rule.llm.phase3_prompt else "追溯源码确认漏洞。"
                fp = compute_fingerprint(self.cpg_path, rule.id, model, prompt_val, rule.llm.temperature)
                if raw[rule.id]["fingerprint"] == fp:
                    resumable[rule.id] = raw[rule.id]
                else:
                    logger.warning("规则 %s 配置已变更，缓存失效", rule.id)
                    remove_completed_rule(rule.id)
        return resumable

    def _prompt_resume(self, resumable: dict) -> bool:
        """展示进度摘要，询问用户是否恢复"""
        print("\n⚠️  检测到上次未完成的扫描进度：")
        for rule in self._rules:
            if rule.id in resumable:
                cnt = len(resumable[rule.id].get("ai_chains", []))
                exp = sum(1 for c in resumable[rule.id].get("ai_chains", []) if c.get("verdict") == "[EXPLOITABLE]")
                print(f"  ✅ {rule.id:<30s} — 已完成 ({exp} 条确认漏洞 / {cnt} 条总计)")
            else:
                cp = load_checkpoint(rule.id)
                if cp and cp.get("completed_chains"):
                    cnt = len(cp["completed_chains"])
                    print(f"  ⏳ {rule.id:<30s} — Phase 3 进行中 ({cnt} 条已完成)")
                else:
                    print(f"  ⬚  {rule.id:<30s} — 未开始")
        
        resp = input("\n是否从断点恢复？[Y/n]: ")
        return resp.strip().lower() in ('y', 'yes', '')

    def _restore_rule(self, rule_id: str, cached: dict, report: "ScanReport"):
        """从缓存恢复一条规则的结果"""
        for chain_dict in cached.get("ai_chains", []):
            d = dict(chain_dict)
            d.pop("_chain_ref", None)
            if "extra" in d and "_chain_ref" in d.get("extra", {}):
                d["extra"] = {k: v for k, v in d["extra"].items() if k != "_chain_ref"}
            report.ai_chains.append(StitchedChain(**d))
        
        exp = sum(1 for c in cached.get("ai_chains", []) if c.get("verdict") == "[EXPLOITABLE]")
        logger.info("✅ 规则 %s 从缓存加载：%d 条结果 (%d 条确认漏洞)", rule_id, len(cached.get("ai_chains", [])), exp)

    def run(self, no_ai: bool = False, resume: bool = False, fresh: bool = False) -> ScanReport:
        """
        执行所有已装载规则，返回 ScanReport。
        no_ai=True 时跳过 LLM 阶段，仅输出直通链路和孤儿碎片列表（不审判）。
        """
        if not self._rules:
            raise ValueError("没有加载任何规则，请先调用 load_rule() 或 load_rule_dir()。")

        report = ScanReport()
        api_key = self._config.get("api_key", "")
        api_base = self._config.get("api_base", "https://api.siliconflow.cn/v1")
        model = self._config.get("model", "deepseek-ai/DeepSeek-V3")
        timeout = int(self._config.get("timeout_seconds", 120))
        max_workers = int(self._config.get("phase2_max_workers", 6))

        # ── 断点恢复检测 ──
        if fresh:
            clear_all_completed_rules()
            clear_all_checkpoints()

        completed_rules_cache = {}
        global_resume_approved = False

        if not fresh:
            completed_rules_cache = self._detect_resumable_rules(model)
            
            # 检测是否有任何可恢复的进度 (完成的规则，或者进行中的 Phase 3)
            has_any_progress = bool(completed_rules_cache)
            if not has_any_progress:
                for rule in self._rules:
                    if load_checkpoint(rule.id):
                        has_any_progress = True
                        break
            
            if has_any_progress:
                if resume:
                    global_resume_approved = True
                    logger.info("已通过 --resume 强制启用全局断点恢复。")
                else:
                    global_resume_approved = self._prompt_resume(completed_rules_cache)
                    if not global_resume_approved:
                        completed_rules_cache.clear()
                        clear_all_completed_rules()
                        clear_all_checkpoints()

        for rule in self._rules:
            if rule.id in completed_rules_cache and global_resume_approved:
                self._restore_rule(rule.id, completed_rules_cache[rule.id], report)
                continue
            logger.info("=" * 50)
            logger.info("规则：%s  [%s]", rule.id, rule.report.severity)
            logger.info("=" * 50)

            # Phase 0：直通链路
            logger.info("[Phase 0] 执行直通链路分析...")
            directs = run_phase0(rule, self.cpg_path)
            logger.info("[Phase 0] 发现直通漏洞链：%d 条", len(directs))
            report.direct_chains.extend(directs)
            
            # 将 Phase 0 提取出的直通链统统包装为 StitchedChain，抛给 Phase 3 审判！不再有免检案卷！
            for d in directs:
                report.ai_chains.append(StitchedChain(
                    rule_id=d.rule_id,
                    source_component=d.source_component,
                    sink_component=d.sink_component,
                    source_snippet=d.source_snippet,
                    sink_snippet=d.sink_snippet,
                    match_type="DIRECT",
                    verdict="[EXPLOITABLE]",
                    reasoning="【Hybris 引擎静态原生确认 (Phase 0)】该链路由底座引擎判定为单体内直通，现移交高级引擎验证是否构成真实威胁。",
                    extra=d.extra
                ))

            # Phase 1：孤儿断层提取
            logger.info("[Phase 1] 执行孤儿断层提取...")
            raw_orphans = run_phase1(rule, self.cpg_path)
            
            # 根据 sast_status 拆分：CONFIRMED 免检放行，BROKEN 移交 AI
            orphans = []
            for o in raw_orphans:
                if o.extra.get("sast_status") == "CONFIRMED":
                    # 直接算作已被证实漏洞
                    report.ai_chains.append(StitchedChain(
                        rule_id=o.rule_id,
                        source_component=o.source_component,
                        sink_component=o.sink_component,
                        source_snippet=o.source_snippet,
                        sink_snippet=o.sink_snippet,
                        match_type=o.match_type,
                        verdict="[EXPLOITABLE]",
                        reasoning="【Hybris 引擎静态原生确认】该链路由 Pair-Wise DFE 在 AST 参数级别被证实物理连通，无需 AI 裁决即可确认存在漏洞路径。",
                        extra=o.extra
                    ))
                else:
                    orphans.append(o)
                    
            logger.info("[Phase 1] 提取完成。共计匹配 %d 组链路，其中 %d 条链路静态验证已全通(免检)，仅剩余 %d 处断裂需移交 AI 分析。", len(raw_orphans), len(raw_orphans) - len(orphans), len(orphans))

            # Phase 2：AI 语义裁决
            if orphans and not no_ai:
                logger.info("[Phase 2] AI 语义裁决...")
                stitched = stitch_chains(
                    orphan_pairs=orphans,
                    rule=rule,
                    api_key=api_key,
                    api_base=api_base,
                    model=model,
                    timeout=timeout,
                    max_workers=max_workers,
                )
                exploitable_cnt = sum(1 for c in stitched if c.verdict == "[EXPLOITABLE]")
                safe_cnt = sum(1 for c in stitched if c.verdict == "[SAFE]")
                logger.info("[Phase 2] 完成：确认漏洞 %d 条 | 排除误报 %d 条", exploitable_cnt, safe_cnt)
                report.ai_chains.extend(stitched)

            elif orphans and no_ai:
                logger.info("[Phase 2] 已跳过 AI 阶段（--no-ai 模式）")
                
            # Phase 3：高级代码取证 (The Ultimate Phase)
            if not no_ai:
                raw_exploitable = [
                    c for c in report.ai_chains 
                    if c.rule_id == rule.id and c.verdict == "[EXPLOITABLE]"
                ]
                
                # 【精确语法级去重算法】
                current_exploitable = []
                seen_routes = set()
                for c in raw_exploitable:
                    # 剥离底层 AST 杂乱后缀（如 <metaClassAdapter>），提取纯净的物理组件
                    clean_src = c.source_component.split("<")[0]
                    clean_sink = c.sink_component.split("<")[0]
                    # 致命修复：必须带上具体的漏洞切片特征！否则会发生“李鬼吃掉李逵”的惨剧！
                    route_fingerprint = f"{clean_src}|{clean_sink}|{c.source_snippet}|{c.sink_snippet}"
                    
                    if route_fingerprint not in seen_routes:
                        seen_routes.add(route_fingerprint)
                        current_exploitable.append(c)
                    else:
                        c.verdict = "[DUPLICATE]"
                        c.reasoning += "\n【系统级去重折叠】该链路由于起点、终点及代码片断完全一致，判定为绝对重合的分析路径，已被引擎合并折叠。"
                        
                logger.info("[Phase 3 准备] 原始疑似危险链 %d 条，精准特征去重后剩余独立攻击面 %d 条。", len(raw_exploitable), len(current_exploitable))

                if current_exploitable and self._config.get("enable_phase3", True):
                    # --- Checkpoint Integration ---
                    phase3_prompt_val = rule.llm.phase3_prompt if rule.llm.phase3_prompt else "追溯源码确认漏洞。"
                    fingerprint = compute_fingerprint(self.cpg_path, rule.id, model, phase3_prompt_val, rule.llm.temperature)
                    config_info = {
                        "cpg_path": self.cpg_path,
                        "rule_id": rule.id,
                        "model": model,
                        "phase3_prompt": phase3_prompt_val,
                        "temperature": rule.llm.temperature
                    }
                    
                    completed_chains = {}
                    if not fresh:
                        old_cp = load_checkpoint(rule.id)
                        if old_cp:
                            if old_cp.get("fingerprint") == fingerprint:
                                if global_resume_approved:
                                    completed_chains = old_cp.get("completed_chains", {})
                                    logger.info("[Checkpoint] 已从检查点加载 %d 条缓存结果。", len(completed_chains))
                                else:
                                    clear_checkpoint(rule.id)
                            else:
                                logger.warning("⚠️ 检测到上次的检查点，但您的扫描配置(模型/Prompt等)已变更，检查点失效。")
                                clear_checkpoint(rule.id)
                    else:
                        clear_checkpoint(rule.id)
                    # ------------------------------

                    max_chains = self._config.get("phase3_max_chains", 0)
                    if max_chains > 0 and len(current_exploitable) > max_chains:
                        logger.warning("[TPM保护] 当前疑似漏洞数(%d)超出限制，截断至前 %d 条进行 Phase 3 深度研判。", len(current_exploitable), max_chains)
                        for c in current_exploitable[max_chains:]:
                            c.reasoning += " (由于设定了 phase3_max_chains，已被跳过 Phase 3 分析)"
                        current_exploitable = current_exploitable[:max_chains]
                        
                    phase3_tasks = []
                    for c in current_exploitable:
                        clean_src = c.source_component.split("<")[0]
                        clean_sink = c.sink_component.split("<")[0]
                        route_fingerprint = f"{clean_src}|{clean_sink}|{c.source_snippet}|{c.sink_snippet}"
                        
                        if route_fingerprint in completed_chains:
                            logger.info("[Checkpoint] 命中缓存跳过 Agent: %s...", route_fingerprint[:60])
                            cached_res = completed_chains[route_fingerprint]
                            c.verdict = cached_res.get("verdict", c.verdict)
                            c.extra["phase3_report"] = cached_res.get("phase3_report", {})
                            
                            p3 = c.extra["phase3_report"]
                            if p3:
                                if p3.get("assessment") == "FALSE_POSITIVE":
                                    c.verdict = "[SAFE]"
                                    c.reasoning = f"【Phase 3 特工翻案 - 确认为误报！】 {p3.get('analysis_chain', '')}"
                                elif p3.get("assessment") == "UNCERTAIN":
                                    c.verdict = "[UNCERTAIN]"
                                    c.reasoning += f"\n【Phase 3 取证中止 - 链路存疑】 {p3.get('analysis_chain', '')}"
                            continue

                        phase3_tasks.append({
                            "rule_id": rule.id,
                            "source_component": c.source_component,
                            "sink_component": c.sink_component,
                            "source_snippet": c.source_snippet,
                            "sink_snippet": c.sink_snippet,
                            "chain_nodes": c.extra.get("chain_nodes", []),
                            "phase3_prompt": phase3_prompt_val,
                            "_chain_ref": c,
                            "_route_fingerprint": route_fingerprint
                        })
                    
                    if phase3_tasks:
                        logger.info("[Phase 3] 启动高级智能体自动取证与定级 (阶段分配 %d 条怀疑链路)...", len(phase3_tasks))
                        checkpoint_ctx = {
                            "rule_id": rule.id,
                            "fingerprint": fingerprint,
                            "config_info": config_info,
                            "completed_chains": completed_chains
                        }
                        
                        phase3_config = dict(self._config)
                        phase3_config["temperature"] = rule.llm.temperature  # 将 YAML 规则中的温度注入 Phase 3
                        p3_results = run_concurrent_investigations(phase3_tasks, phase3_config, self.cpg_path, self.source_dir, checkpoint_ctx=checkpoint_ctx)
                        
                        for res in p3_results:
                            ref = res.pop("_chain_ref")
                            ref.extra["phase3_report"] = res.get("phase3_report", {})
                            
                            p3 = ref.extra["phase3_report"]
                            if p3:
                                if p3.get("assessment") == "FALSE_POSITIVE":
                                    ref.verdict = "[SAFE]"
                                    ref.reasoning = f"【Phase 3 特工翻案 - 确认为误报！】 {p3.get('analysis_chain', '')}"
                                elif p3.get("assessment") == "UNCERTAIN":
                                    ref.verdict = "[UNCERTAIN]"
                                    ref.reasoning += f"\n【Phase 3 取证中止 - 链路存疑】 {p3.get('analysis_chain', '')}"
                        
                        if len(p3_results) == len(phase3_tasks):
                            logger.info("[Checkpoint] 该条规则全部链路分析完毕，自动清除检查点文件。")
                            clear_checkpoint(rule.id)
                        else:
                            logger.warning(f"[Checkpoint] 任务未完全成功 (下发 {len(phase3_tasks)} / 完成 {len(p3_results)})，已保留断点，以便下次续传。")
                    exploitable_final = sum(1 for c in current_exploitable if c.verdict == "[EXPLOITABLE]")
                    logger.info("[Phase 3] 审判完成：保留高危漏洞 %d 条，剔除误报 %d 条", exploitable_final, len(current_exploitable) - exploitable_final)
            
            # ── 规则完成后落盘 ──
            if not no_ai:
                phase3_prompt_val = rule.llm.phase3_prompt if rule.llm.phase3_prompt else "追溯源码确认漏洞。"
                fingerprint = compute_fingerprint(self.cpg_path, rule.id, model, phase3_prompt_val, rule.llm.temperature)
                rule_chains = [c for c in report.ai_chains if c.rule_id == rule.id]
                save_completed_rule(rule.id, fingerprint, rule_chains)
                clear_checkpoint(rule.id) # 确保清理

        return report


# ─── 全局配置加载 ─────────────────────────────────────────────────────────────

def _load_config(config_path: str | None = None) -> dict:
    if config_path is None:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(project_root, "config.json")

    if not os.path.exists(config_path):
        logger.warning("未找到 config.json，将使用内置默认配置（无 API Key）")
        return {}

    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)
