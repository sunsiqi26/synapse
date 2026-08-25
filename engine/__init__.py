"""
engine/__init__.py

对外暴露引擎的核心公共接口，方便 SDK 调用方直接 from hybris_sast.engine import ...
"""

from .core import HybrisScanner, ScanReport
from .rule_loader import load_rule, load_rules_from_dir, list_rules, Rule, RuleLoadError
from .joern_scanner import DirectChain, OrphanPair
from .llm_stitcher import StitchedChain
from .logger import configure_cli_logging, get_logger

__all__ = [
    "HybrisScanner",
    "ScanReport",
    "load_rule",
    "load_rules_from_dir",
    "list_rules",
    "Rule",
    "RuleLoadError",
    "DirectChain",
    "OrphanPair",
    "StitchedChain",
    "configure_cli_logging",
    "get_logger",
]
