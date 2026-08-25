"""
engine/rule_loader.py

负责从 rules/ 目录加载 YAML 规则，转换为 Rule 实体对象，并进行完整性校验。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional
import yaml


# ─── 实体定义 ────────────────────────────────────────────────────────────────

@dataclass
class PhaseConfig:
    script: str          # 相对于项目根目录的 .sc 脚本路径


@dataclass
class LLMConfig:
    vuln_type: str
    prompt_template: str
    phase3_prompt: str = ""
    max_tokens: int = 1500
    temperature: float = 0.1


@dataclass
class ReportConfig:
    severity: str = "HIGH"
    cwe: str = ""
    remediation: str = ""


@dataclass
class Rule:
    id: str
    name: str
    description: str
    author: str
    phase0: PhaseConfig
    phase1: PhaseConfig
    llm: LLMConfig
    report: ReportConfig

    # 运行时注入：规则文件绝对路径 & 项目根目录（用于拼接 .sc 路径）
    _rule_file: str = field(default="", repr=False)
    _project_root: str = field(default="", repr=False)

    def resolve_script(self, relative_script: str) -> str:
        """将规则中的相对路径转换为绝对路径。"""
        return os.path.join(self._project_root, relative_script)

    @property
    def phase0_script_abs(self) -> str:
        return self.resolve_script(self.phase0.script)

    @property
    def phase1_script_abs(self) -> str:
        return self.resolve_script(self.phase1.script)


# ─── 默认 Prompt（兜底，当规则 YAML 中没有提供时使用） ────────────────────────

_DEFAULT_PROMPT = """\
你是一位专注于代码安全审计的顶级专家。
我们通过混合静态分析引擎，从一个大型应用中发现了一段可疑的跨层代码执行路径。

以下是断层分析中两端对应的代码片段：

--- 【Source：外部受控入口上下文】 ---
{source_snippet}

--- 【Sink：高危执行节点的直接上下文】 ---
{sink_snippet}

请判断：外部输入是否有可能在没有适当过滤或安全检查的情况下，流向 Sink 中的危险调用，从而触发【{vuln_type}】漏洞。

### 裁决格式 ###
第一行必须为 [EXPLOITABLE] 或 [SAFE] 之一。
第二行开始，用中文给出逐步推理的完整链路。
"""


# ─── 加载逻辑 ─────────────────────────────────────────────────────────────────

class RuleLoadError(Exception):
    """规则文件加载或校验失败时抛出。"""
    pass


def _project_root() -> str:
    """返回项目根目录（即 hybris_sast/ 所在目录）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_rule(rule_id: str) -> Rule:
    """
    根据规则 ID（如 'python/django/ssti'）加载并返回 Rule 实体。

    规则文件默认路径：<project_root>/rules/<rule_id>.yaml
    """
    root = _project_root()
    rule_path = os.path.join(root, "rules", rule_id + ".yaml")

    if not os.path.exists(rule_path):
        raise RuleLoadError(
            f"规则文件不存在：{rule_path}\n"
            f"  提示：请确认规则 ID '{rule_id}' 对应的文件位于 rules/ 目录下。"
        )

    with open(rule_path, "r", encoding="utf-8") as f:
        try:
            raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise RuleLoadError(f"规则文件 YAML 解析失败：{rule_path}\n  原因：{e}")

    return _parse_rule(raw, rule_path, root)


def load_rules_from_dir(rule_dir: str) -> list[Rule]:
    """
    将某个目录下所有的 .yaml 文件加载为规则。
    遇到任何一个文件加载失败时直接抛出，Fail-Fast。

    例：load_rules_from_dir("rules/python/")
    """
    root = _project_root()
    abs_dir = os.path.join(root, rule_dir.rstrip("/"))

    if not os.path.isdir(abs_dir):
        raise RuleLoadError(f"规则目录不存在：{abs_dir}")

    rules = []
    for dirpath, _, filenames in os.walk(abs_dir):
        for fname in filenames:
            if not fname.endswith(".yaml"):
                continue
            full_path = os.path.join(dirpath, fname)
            # 将文件路径转换为规则 ID
            rel = os.path.relpath(full_path, os.path.join(root, "rules"))
            rule_id = rel.replace(os.sep, "/").removesuffix(".yaml")

            with open(full_path, "r", encoding="utf-8") as f:
                try:
                    raw = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    raise RuleLoadError(
                        f"规则文件 YAML 解析失败：{full_path}\n  原因：{e}"
                    )
            rules.append(_parse_rule(raw, full_path, root))

    if not rules:
        raise RuleLoadError(f"规则目录 '{abs_dir}' 中没有找到任何 .yaml 文件。")

    return rules


def list_rules() -> list[dict]:
    """列出所有可用规则的摘要信息。"""
    root = _project_root()
    rules_dir = os.path.join(root, "rules")
    results = []
    for dirpath, _, filenames in os.walk(rules_dir):
        for fname in filenames:
            if not fname.endswith(".yaml"):
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, rules_dir)
            rule_id = rel.replace(os.sep, "/").removesuffix(".yaml")
            try:
                with open(full, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                results.append({
                    "id": rule_id,
                    "name": raw.get("name", "(unnamed)"),
                    "severity": raw.get("report", {}).get("severity", "?"),
                })
            except Exception:
                results.append({"id": rule_id, "name": "(parse error)", "severity": "?"})
    return results


# ─── 内部解析 ─────────────────────────────────────────────────────────────────

def _parse_rule(raw: dict, rule_file: str, root: str) -> Rule:
    """将原始 YAML dict 转换为 Rule 实体，并进行完整性验证。"""

    def _require(d: dict, key: str, context: str) -> object:
        if key not in d:
            raise RuleLoadError(f"规则文件缺少必填字段 '{context}.{key}'：{rule_file}")
        return d[key]

    rule_id = str(_require(raw, "id", "root"))
    name = str(_require(raw, "name", "root"))
    description = str(raw.get("description", ""))
    author = str(raw.get("author", "unknown"))

    phases = _require(raw, "phases", "root")
    phase0_raw = _require(phases, "phase0", "phases")
    phase1_raw = _require(phases, "phase1", "phases")

    phase0_script = str(_require(phase0_raw, "script", "phases.phase0"))
    phase1_script = str(_require(phase1_raw, "script", "phases.phase1"))

    # 校验 SC 脚本实际存在
    for label, rel_script in [("phases.phase0.script", phase0_script),
                               ("phases.phase1.script", phase1_script)]:
        abs_path = os.path.join(root, rel_script)
        if not os.path.exists(abs_path):
            raise RuleLoadError(
                f"规则 '{rule_id}' 中引用的脚本文件不存在：\n"
                f"  字段：{label}\n"
                f"  路径：{abs_path}"
            )

    llm_raw = raw.get("llm", {})
    vuln_type = str(llm_raw.get("vuln_type", name))
    prompt_template = str(llm_raw.get("prompt_template", _DEFAULT_PROMPT))
    phase3_prompt = str(llm_raw.get("phase3_prompt", ""))
    max_tokens = int(llm_raw.get("max_tokens", 1500))
    temperature = float(llm_raw.get("temperature", 0.1))

    report_raw = raw.get("report", {})
    severity = str(report_raw.get("severity", "HIGH"))
    cwe = str(report_raw.get("cwe", ""))
    remediation = str(report_raw.get("remediation", ""))

    rule = Rule(
        id=rule_id,
        name=name,
        description=description,
        author=author,
        phase0=PhaseConfig(script=phase0_script),
        phase1=PhaseConfig(script=phase1_script),
        llm=LLMConfig(
            vuln_type=vuln_type,
            prompt_template=prompt_template,
            phase3_prompt=phase3_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
        ),
        report=ReportConfig(severity=severity, cwe=cwe, remediation=remediation),
    )
    rule._rule_file = rule_file
    rule._project_root = root
    return rule
