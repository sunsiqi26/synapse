"""
engine/checkpoint.py

负责 Phase 3 阶段漏洞探查的断点续传（持久化缓存）与状态追踪。
"""

import hashlib
import json
import os
import fcntl
import datetime
from .logger import get_logger

logger = get_logger("checkpoint")

def get_checkpoint_dir() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cp_dir = os.path.join(root, "output", "checkpoints")
    os.makedirs(cp_dir, exist_ok=True)
    return cp_dir

def compute_fingerprint(cpg_path: str, rule_id: str, model: str, prompt: str, temp: float) -> str:
    """计算会话指纹，保证 CPG、规则和重要推理参数的变化能使缓存失效"""
    raw = f"{cpg_path}|{rule_id}|{model}|{prompt}|{temp}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def get_checkpoint_path(rule_id: str) -> str:
    """固定同一条规则的文件名，方便检测"""
    safe_rule_id = rule_id.replace("/", "_").replace("\\", "_")
    return os.path.join(get_checkpoint_dir(), f"checkpoint_{safe_rule_id}.json")

def load_checkpoint(rule_id: str) -> dict:
    file_path = get_checkpoint_path(rule_id)
    if not os.path.exists(file_path):
        return {}
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("读取检查点失败，可能已损坏，将忽略：%s", e)
        return {}

def save_checkpoint(rule_id: str, fingerprint: str, config_info: dict, completed_chains: dict):
    """
    带文件锁的原子写入，防止多线程并发更新或强杀进程导致崩溃。
    completed_chains 格式: { "route_fingerprint": {"verdict": "[SAFE]", "phase3_report": {...}} }
    """
    file_path = get_checkpoint_path(rule_id)
    data = {
        "fingerprint": fingerprint,
        "updated_at": datetime.datetime.now().isoformat(),
        "config": config_info,
        "completed_chains": completed_chains
    }
    
    tmp_path = file_path + ".tmp"
    try:
        # 先以独占模式写入临时文件
        with open(tmp_path, "w", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
        # 原子替换正式文件
        os.replace(tmp_path, file_path)
    except Exception as e:
        logger.error("写入检查点时发生异常：%s", e)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

def clear_checkpoint(rule_id: str):
    """任务完整跑完或配置失效时，清理老缓存"""
    file_path = get_checkpoint_path(rule_id)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception:
            pass

# ─── completed_rules 持久化 ────────────────────────────

COMPLETED_RULES_FILE = "completed_rules.json"

def _get_completed_rules_path() -> str:
    return os.path.join(get_checkpoint_dir(), COMPLETED_RULES_FILE)

def load_completed_rules() -> dict:
    """加载已完成规则的缓存结果"""
    path = _get_completed_rules_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("读取 completed_rules 失败：%s", e)
        return {}

def save_completed_rule(rule_id: str, fingerprint: str, ai_chains: list):
    """将一条规则的最终结果追加写入 completed_rules.json"""
    all_rules = load_completed_rules()
    
    # 序列化 StitchedChain，剔除不可序列化的运行时字段
    serialized_chains = []
    for chain in ai_chains:
        d = vars(chain).copy()
        d.pop("_chain_ref", None)
        # extra 中也可能有不可序列化的引用
        if "extra" in d and "_chain_ref" in d.get("extra", {}):
            d["extra"] = {k: v for k, v in d["extra"].items() if k != "_chain_ref"}
        serialized_chains.append(d)
    
    all_rules[rule_id] = {
        "fingerprint": fingerprint,
        "completed_at": datetime.datetime.now().isoformat(),
        "ai_chains": serialized_chains
    }
    
    # 原子写入
    path = _get_completed_rules_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(all_rules, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        os.replace(tmp, path)
    except Exception as e:
        logger.error("写入 completed_rules 失败：%s", e)
        if os.path.exists(tmp):
            os.remove(tmp)

def remove_completed_rule(rule_id: str):
    """移除单条规则的缓存（指纹失效时）"""
    all_rules = load_completed_rules()
    if rule_id in all_rules:
        del all_rules[rule_id]
        path = _get_completed_rules_path()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(all_rules, f, ensure_ascii=False, indent=2)

def clear_all_completed_rules():
    """清除全部已完成规则的缓存"""
    path = _get_completed_rules_path()
    if os.path.exists(path):
        os.remove(path)

def clear_all_checkpoints():
    """清除所有 checkpoint_{rule}.json 文件"""
    cp_dir = get_checkpoint_dir()
    for f in os.listdir(cp_dir):
        if f.startswith("checkpoint_") and f.endswith(".json"):
            os.remove(os.path.join(cp_dir, f))
