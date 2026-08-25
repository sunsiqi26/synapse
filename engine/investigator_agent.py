import json
import os
import subprocess
import time
import requests
import shutil
import concurrent.futures
import threading
from typing import Dict, List, Any, Optional
from .checkpoint import save_checkpoint

try:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.console import Console
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False

from openai import OpenAI

class FatalAPIError(Exception):
    """用于标记不可通过普通指数退避恢复的 API 致命故障（如后端 Tool Choice 未开启）"""
    pass

from .logger import get_logger

logger = get_logger("investigator")

class JoernServerManager:
    def __init__(self, cpg_bin_path: str, host: str = "127.0.0.1", port: int = 8081):
        self.cpg_bin_path = cpg_bin_path
        self.host = host
        self.port = port
        self.process = None
        self.username = "cpg"
        self.password = "cpg"
        self.api_url = f"http://{self.host}:{self.port}/query-sync"

    def start(self):
        import socket
        def is_port_in_use(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex((self.host, port)) == 0

        while is_port_in_use(self.port):
            logger.warning(f"⚠️ 发现端口 {self.port} 已被残留或其它进程占用，自动跳频至 {self.port + 1}...")
            self.port += 1
            self.api_url = f"http://{self.host}:{self.port}/query-sync"

        logger.info(f"♨️ [引擎点火] 正在启动底层 Joern 常驻图谱 API (Port: {self.port})...")
        import platform
        
        # 兼容多平台寻找 joern 可执行文件
        is_win = platform.system() == "Windows"
        if is_win:
            joern_bin = shutil.which("joern.bat") or shutil.which("joern") or r"D:\Language_collection\Java\joern-cli\joern.bat"
        else:
            joern_bin = shutil.which("joern")
            if not joern_bin:
                candidates = ["/usr/local/bin/joern", "/opt/joern/joern", os.path.expanduser("~/bin/joern"), os.path.expanduser("~/joern/joern"), os.path.expanduser("~/joern-cli/joern")]
                for c in candidates:
                    if os.path.isfile(c) and os.access(c, os.X_OK):
                        joern_bin = c
                        break
            if not joern_bin:
                joern_bin = "joern" # 兜底依赖环境变量

        cmd = [
            joern_bin, "--server", "--server-host", self.host, "--server-port", str(self.port),
            "--server-auth-username", self.username, "--server-auth-password", self.password, self.cpg_bin_path
        ]
        env = os.environ.copy()
        
        # Windows 开发调试用的 Hardcode java home，如果在对应的平台存在该路径则临时注入，否则依赖外部环境配置
        if is_win:
            java_home = r"D:\Language_collection\Java\OpenJDK21U-jdk_x64_windows_hotspot_21.0.6_7"
            if os.path.exists(java_home):
                 env["JAVA_HOME"] = java_home
                 env["PATH"] = f"{java_home}\\bin;" + env.get("PATH", "")

        if is_win:
            self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, shell=True)
        else:
            self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, preexec_fn=os.setsid)
        
        logger.info(f"⏳ 等待极速图谱装载至 {self.port} 端口 (需10-15秒)...")
        for _ in range(40):
            try:
                res = requests.post(self.api_url, json={"query": "1+1"}, auth=(self.username, self.password), timeout=2)
                if res.status_code == 200:
                    logger.info("[✔] 常驻 API 服务已成功点亮！")
                    return True
            except Exception:
                time.sleep(1)
        
        logger.error("❌ Joern 服务启动超时！")
        self.stop()
        return False

    def stop(self):
        if self.process:
            logger.info("🧯 关闭 Joern Server...")
            import signal
            try:
                # 杀掉整个进程组（shell + java 子进程），防止 Java 变成孤儿进程
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.process.wait(timeout=5)
            except Exception:
                # 如果 SIGTERM 没杀掉，强制 SIGKILL
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            self.process = None
            
    def execute_query(self, scala_query: str) -> requests.Response:
        return requests.post(self.api_url, json={"query": scala_query.strip()}, auth=(self.username, self.password), timeout=10)

def safe_read_file(root_dir: str, file_path: str, start: int, end: int) -> str:
    if not file_path or file_path == "<empty>":
        return f"❌ 文件路径为空 (可能是缺少源码的框架外部方法)"
        
    abs_file = os.path.join(root_dir, file_path) if not os.path.isabs(file_path) else file_path
    if not os.path.isfile(abs_file):
        return f"❌ 文件没找到或不是文件: {file_path} (试图搜索的根目录: {root_dir})"
    try:
        with open(abs_file, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
        s, e = max(1, start), min(len(all_lines), end)
        if s > e: return "❌ 行号不合法"
        snippet = all_lines[s - 1 : e]
        out = f"\n👉 [深度阅读] {file_path} (Lines {s}~{e})\n" + "-"*60 + "\n"
        for i, text in enumerate(snippet): out += f"{s + i:4d} | {text.rstrip()}\n"
        out += "-"*60 + "\n"
        return out
    except Exception as ex:
        return f"❌ 读取异常: {ex}"

class Phase3Agent:
    TOOLS_SCHEMA = [
        {
            "type": "function",
            "function": {
                "name": "joern_read_method",
                "description": "极速抽取类的源码，并自动附带该方法内部的子调用清单（Callees）。支持正则！如果不确定精确方法名，可以传入类似 '.*fetch.*' 的正则，它最多会返回3个满足特征的方法原文。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "class_name": {"type": "string"},
                        "method_name": {"type": "string", "description": "方法名，支持例如 '.*sql.*' 这样的正则表达式。"}
                    },
                    "required": ["class_name", "method_name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "joern_get_callers",
                "description": "反向溯源图谱工具（胖工具：已包含上下文源码提取）：当你不知道是谁调用了目前这段代码时，或者需要往上看参数是怎么传进来的，用这个查出调用方的类名和方法名。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "class_name": {"type": "string", "description": "由于调用链断层，经常无法建立严格的实例类型，你可以在此直接填 '.*' 以使用模糊查阅匹配"},
                        "method_name": {"type": "string"}
                    },
                    "required": ["class_name", "method_name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "joern_find_definitions",
                "description": "查方法声明位置：输入一个函数名，返回它在哪个文件和类里被声明。只能搜方法/函数，搜不到变量、字段或属性。例如看到 obj.run() 就传 'run'。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "keyword": {"type": "string", "description": "纯方法名，如 'run'、'execute'、'get_config'"}
                    },
                    "required": ["keyword"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "joern_get_callees",
                "description": "正向溯源工具（向下钻取）：当你需要知道某个目前的方法在内部又调用了哪些其他方法时，使用这个工具获取完整的子调用树。返回调用代码特征和行号。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "class_name": {"type": "string"},
                        "method_name": {"type": "string"}
                    },
                    "required": ["class_name", "method_name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "joern_find_usages",
                "description": "查标识符引用位置：输入一个变量名、字段名或方法名，返回全站所有引用了它的代码位置。适合追踪字段、变量、方法的使用情况。keyword 只传一个纯单词，例如看到 self.config.options 就传 'options'。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "keyword": {"type": "string", "description": "纯单词，如 'options'、'execute'、'deploy_host'"}
                    },
                    "required": ["keyword"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "read_file_snippet",
                "description": "文件深度阅读工具：当你通过 grep 搜索等途径知道了某个文件的【相对文件路径】时，用来抽取指定行号的代码片段来阅读细节。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "需要读取的文件相对路径"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"}
                    },
                    "required": ["file_path", "start_line", "end_line"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "submit_finding",
                "description": "只有当你查清整个漏洞链路后，下达最终包含多维度评分的结案报告。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "assessment": {
                            "type": "string",
                            "enum": ["CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN"],
                            "description": "裁决结果。如果是 FALSE_POSITIVE，请务必用中文在 defense_penetration_review 字段中详述安全拦截机制、变量覆盖或为何无法造成危害的具体技术理由，绝不能填 N/A。"
                        },
                        "data_flow_trace": {
                            "type": "string",
                            "description": "完整数据追踪：客观记录代码自输入口（或持久化存储）至最终执行锚点（Sink）的完整跳转与变量传递路径。"
                        },
                        "defense_penetration_review": {
                            "type": "string",
                            "description": "控制层防御击穿评估：若有任何防御，尽可能思考防御无效的方案，逐层独立判定"
                        },
                        "execution_consequence": {
                            "type": "string",
                            "description": "环境逃逸破坏判定：抛开预期的业务包装，假设攻击者在输入中注入恶意载荷，该载荷从存储到最终被执行引擎消费的过程中，是否造成了漏洞"
                        },
                        "attacker_condition": {
                            "type": "string",
                            "description": "攻击者必须处于什么网络位置（内部/外部），需要什么权限（未授权/管理员/访客），以及必须注入哪些特定输入才能使攻击成功。"
                        },
                        "server_condition": {
                            "type": "string",
                            "description": "服务器先决条件，例如是否必须启用特定插件、默认配置是什么，或者该错误是否仅在特定操作系统/环境下触发。"
                        },
                        "security_impact": {
                            "type": "string",
                            "description": "安全影响分析。不仅要说明它是“危险的”，还要根据 CIA 三要素来描述它是否允许数据泄露、导致拒绝服务 (DoS) 或涉及敏感信息泄露。"
                        },
                        "proof_of_concept": {
                            "type": "string",
                            "description": "PoC 演示，你需要完整的描述从“用户可控点”出发，如何发送请求影响这条链路。若为误报，用中文填写 'N/A'"
                        },
                        "hazard_scores": {
                            "type": "object",
                            "properties": {
                                "attacker_condition_score": {"type": "integer"},
                                "server_condition_score": {"type": "integer"},
                                "security_impact_score": {"type": "integer"}
                            },
                            "required": ["attacker_condition_score", "server_condition_score", "security_impact_score"]
                        }
                    },
                    "required": ["assessment", "data_flow_trace", "defense_penetration_review", "execution_consequence", "attacker_condition", "server_condition", "security_impact", "proof_of_concept", "hazard_scores"]
                }
            }
        }
    ]

    def __init__(self, api_key: str, api_base: str, model: str, server_mgr: JoernServerManager, root_source_dir: str, max_turns: int = 30, temperature: float = 0.1, timeout: int = 300):
        self.api_key = api_key
        self.api_base = api_base
        self.timeout = timeout
        self.client = OpenAI(api_key=api_key, base_url=api_base, timeout=timeout, max_retries=0)
        self.model = model
        self.server_mgr = server_mgr
        self.root_source_dir = root_source_dir
        self.max_turns = max_turns
        self.temperature = temperature
    def _execute_tool(self, name: str, args: dict) -> str:
        try:
            import re, json
            
            def safe_post(q: str):
                return self.server_mgr.execute_query(q)
                
            def _parse_joern_json(stdout: str) -> list:
                stdout = re.sub(r'\x1b\[[0-9;]*m', '', stdout)
                # Strategy 1: Direct JSON array (works with println or clean output)
                json_match = re.search(r'(\[\{.*\}\]|\[\])', stdout, re.DOTALL)
                if json_match:
                    try:
                        return json.loads(json_match.group(1))
                    except:
                        try:
                            return json.loads(json_match.group(1).replace('\\"', '"').replace('\\\\', '\\'))
                        except:
                            pass
                # Strategy 2: query-sync REPL format - JSON inside String = "..."
                str_match = re.search(r'String\s*=\s*"(.+)"\s*$', stdout, re.MULTILINE)
                if str_match:
                    escaped = str_match.group(1)
                    unescaped = escaped.replace('\\"', '"').replace('\\\\', '\\')
                    try:
                        return json.loads(unescaped)
                    except:
                        pass
                return []

            if name == "joern_read_method":
                c, m = args.get("class_name", ".*"), args.get("method_name")
                q = f'''{{ import ujson._; val r = cpg.method.name("{m}").filter(_.fullName.contains("{c}")).l.take(3).map(m => ujson.Obj("file" -> m.filename, "start" -> m.lineNumber.getOrElse(-1), "end" -> m.lineNumberEnd.getOrElse(-1), "name" -> m.name)); ujson.write(r) }}'''
                res = safe_post(q)
                if res.status_code == 200:
                    stdout = res.json().get("stdout", "")
                    methods = _parse_joern_json(stdout)
                    if not methods: return f"❌ 图谱未解析到匹配目标。\n引擎原始返回:\n{stdout}"
                    out = ""
                    for m_dict in methods:
                        rel_file = str(m_dict.get("file", "")).strip()
                        if not rel_file or rel_file == "<empty>": continue
                        start = int(m_dict.get("start", -1))
                        end = int(m_dict.get("end", -1))
                        if start != -1 and end != -1:
                            out += f"\n👉 [深度阅读] {c}::{m_dict.get('name', m)} (Line {start}~{end})\n"
                            out += safe_read_file(self.root_source_dir, rel_file, max(1, start - 30), end)
                    return out if out else "❌ 返回为空"
                return f"❌ HTTP {res.status_code}"

            elif name == "joern_find_definitions":
                kw = args.get("keyword")
                q = f'''{{ import ujson._; val r = cpg.method.fullName("(?i).*{kw}.*").map(m => ujson.Obj("file" -> m.filename, "start" -> m.lineNumber.getOrElse(-1), "end" -> m.lineNumberEnd.getOrElse(-1), "class" -> m.typeDecl.name.headOption.getOrElse("Unknown"), "name" -> m.name)).l.distinct.take(30); ujson.write(r) }}'''
                res = safe_post(q)
                if res.status_code == 200:
                    stdout = res.json().get("stdout", "")
                    nodes = _parse_joern_json(stdout)
                    if not nodes: return f"❌ 语法图谱内未找到声明或定义。\n引擎原始返回:\n{stdout}"
                    out = f"[全局定义大普查] 找到匹配 '{kw}' 的相关方法声明目录:\n" + "-"*60 + "\n"
                    cnt = 0
                    for m_dict in nodes:
                        rel_file = str(m_dict.get("file", "")).strip()
                        if not rel_file or rel_file == "<empty>": continue
                        out += f"定义位置: {rel_file} | 行号: {m_dict.get('start', -1)}~{m_dict.get('end', -1)} | 类/模块: {m_dict.get('class', '')} | 方法名: {m_dict.get('name', '')}\n"
                        cnt += 1
                    return out + "-"*60 + "\n" if cnt > 0 else "❌ 返回列表为空"
                return f"❌ HTTP {res.status_code}"

            elif name == "joern_get_callers":
                c, m = args.get("class_name", ".*"), args.get("method_name")
                q = f'''{{ import ujson._; val r = cpg.call.code(".*\\\\b{m}\\\\b.*").method.l.distinct.take(5).map(m => ujson.Obj("file" -> m.filename, "start" -> m.lineNumber.getOrElse(-1), "end" -> m.lineNumberEnd.getOrElse(-1), "class" -> m.typeDecl.name.headOption.getOrElse("Unknown"), "name" -> m.name)); ujson.write(r) }}'''
                res = safe_post(q)
                if res.status_code == 200:
                    stdout = res.json().get("stdout", "")
                    callers = _parse_joern_json(stdout)
                    if not callers: return f"❌ 图谱引擎未解析到调用代码。\n引擎原始返回:\n{stdout}"
                    out = ""
                    for m_dict in callers:
                        rel_file, start, end = str(m_dict.get("file", "")).strip(), int(m_dict.get("start", -1)), int(m_dict.get("end", -1))
                        c_name, m_name = str(m_dict.get("class", "")), str(m_dict.get("name", ""))
                        if not rel_file or rel_file == "<empty>" or start == -1: continue
                        if "<meta" in m_name or "<fake" in m_name or "<meta" in c_name: continue
                        out += f"\n👉 [命中 Caller 胖工具] {c_name}::{m_name} (位于文件: {rel_file}, 行号: {start}~{end})\n"
                        out += safe_read_file(self.root_source_dir, rel_file, max(1, start - 4), end + 5)
                    return out if out else "❌ 返回为空，缺乏物理坐标"
                return f"❌ HTTP {res.status_code}"

            elif name == "joern_get_callees":
                c, m = args.get("class_name", ".*"), args.get("method_name")
                q = f'''{{ import ujson._; val r = cpg.method.name("{m}").filter(_.fullName.contains("{c}")).call.map(cc => ujson.Obj("callee" -> cc.name, "code" -> cc.code, "line" -> cc.lineNumber.getOrElse(-1))).l.distinct.take(30); ujson.write(r) }}'''
                res = safe_post(q)
                if res.status_code == 200:
                    stdout = res.json().get("stdout", "")
                    calls = _parse_joern_json(stdout)
                    if not calls: return f"❌ 未找到底层调用记录。\n引擎原始返回:\n{stdout}"
                    out = f"👉 [{c}::{m}] 函数体内部调用的外部模块清单:\n" + "-"*60 + "\n"
                    cnt = 0
                    for m_dict in calls:
                        out += f"行号 {int(m_dict.get('line', -1)):4d} | 调用的方法: {str(m_dict.get('callee', ''))[:20]:20s} | 代码特征: {str(m_dict.get('code', '')).strip()}\n"
                        cnt += 1
                    return out + "-"*60 + "\n" if cnt > 0 else "❌ 未解析到具体子调用"
                return f"❌ HTTP {res.status_code}"

            elif name == "joern_find_usages":
                kw = args.get("keyword")
                q = f'''{{ import ujson._; val r = (cpg.call.code("(?i).*{kw}.*") ++ cpg.identifier.name("(?i).*{kw}.*")).map(n => ujson.Obj("file" -> n.method.filename, "line" -> n.lineNumber.getOrElse(-1), "caller" -> n.method.name)).l.distinct.take(20); ujson.write(r) }}'''
                res = safe_post(q)
                if res.status_code == 200:
                    stdout = res.json().get("stdout", "")
                    nodes = _parse_joern_json(stdout)
                    if not nodes: return f"❌ 未能寻觅到代码结构。\n引擎原始返回:\n{stdout}"
                    out = f"[全局语法树寻根] 捕捉到引用了 '{kw}' 的上下文:\n" + "="*70 + "\n"
                    cnt = 0
                    for m_dict in nodes:
                        rel_file = str(m_dict.get("file", "")).strip()
                        if not rel_file or rel_file == "<empty>": continue
                        line = int(m_dict.get("line", -1))
                        caller = str(m_dict.get("caller", ""))
                        out += f"\n📍 [引用] 位置: {rel_file} | 行: {line:4d} | 宿主上下文方法: {caller}\n"
                        if line != -1:
                            out += "`" * 50 + "\n"
                            out += safe_read_file(self.root_source_dir, rel_file, max(1, line - 4), line + 5)
                            out += "`" * 50 + "\n"
                        cnt += 1
                    return out + "="*70 + "\n" if cnt > 0 else "❌ 返回为空（引用的可能属于内置结构，无物理文件坐标）"
                return f"❌ HTTP {res.status_code}"

            elif name == "read_file_snippet":
                return safe_read_file(self.root_source_dir, args.get("file_path"), args.get("start_line"), args.get("end_line"))
            
            else:
                return f"❌ 未知工具: {name}"
        except Exception as e:
            return f"❌ 内部执行异常: {e}"

    def investigate(self, task: dict) -> dict:
        rule_id = task.get("rule_id", "Unknown")
        source_component = task.get("source_component", "Unknown")
        sink_component = task.get("sink_component", "Unknown")
        source_snippet = task.get("source_snippet", "")
        sink_snippet = task.get("sink_snippet", "")
        chain_nodes = task.get("chain_nodes", [])
        phase3_prompt = task.get("phase3_prompt", "追溯源码确认漏洞。")

        system_prompt = """你是一个装备了全套源码查证工具的高级渗透测试专家（Penetration Tester）。擅长排版、总结证据。
你的核心目标是：沿着线索路径，亲自查阅源码，尝试构造一条完整的、可行的攻击链路（从用户可控输入到危险 Sink 的 RCE/注入）。
【渗透测试纪律】：
1. 你的默认立场是"这个漏洞大概率能打通"。静态引擎已经发现了可疑路径，你需要亲自用工具去验证它是否真的能走通。
2. 在每一次调用工具之前，必须在回复中给出你的推理依据和下一步攻击思路。
3. 【强制物理禁令】：你必须至少调用 2 轮 joern_read_method / read_file_snippet 等工具查阅实际代码后，才能使用 submit_finding 提交结论。
4. 如果你沿路追踪后发现攻击链路完全畅通（用户输入可以无过滤地到达危险 Sink），最终裁决必须是 CONFIRMED，并在 proof_of_concept 中描述完整的攻击步骤。
5. 判定 FALSE_POSITIVE 的合法条件包含两类：
   (a) 不可达 (Unreachable/Dead Code)：追溯调用栈发现没有任何外部可控的地方能够触发该线索，或该方法从未被使用。
   (b) 物理屏障 (Code-level Barrier)：沿路追踪撞上了确凿的代码级过滤（如强类型转换、正则白名单、参数化查询等）。
6. 严禁使用"可能在实际环境中被限制"、"默认配置可能安全"、"需要高权限所以不算漏洞"等非代码级理由来判定 FALSE_POSITIVE！哪怕需要管理员权限，只要输入能到达危险 Sink 且没有代码级过滤，就是 CONFIRMED！
"""

        user_input = f"""
【渗透测试任务 - 攻击链路验证】：
静态分析引擎在代码中发现了一条可疑的危险执行路径。请你立刻出发，亲自用工具追踪这条路径，验证攻击者是否真的能把恶意输入打进 Sink。

**攻击起点 (Source)**:
- 节点标记: {source_component}

**攻击终点 (Sink)**:
- 节点标记: {sink_component}



【专家预设查证指南 (Expert Prompt)】:
{phase3_prompt}

【渗透测试指导】：
1. 从 Source 出发，逐跳追踪数据流向，直到 Sink。
2. 在每一跳检查：用户输入在这里有没有被过滤、转义、类型转换？
3. 如果一路畅通无阻，构造一个完整的 PoC 攻击步骤。
4. 哪怕该入口需要管理员权限，只要恶意输入能到达 Sink 且无代码级过滤，就是 CONFIRMED。

最后通过 submit_finding 提交终审裁决。
"""
        # ========== 链路级重试机制 ==========
        # 400 "tool choice" 等基础设施错误与链路内容无关，
        # 应当重置对话历史从头重跑整条链路，而非直接放弃。
        max_chain_retries = 3
        
        for chain_attempt in range(max_chain_retries):
            if chain_attempt > 0:
                #backoff = 10 * chain_attempt  # 10s, 20s
                backoff = 5  # 1s, 2s
                logger.info(f"[{rule_id}] 🔄 链路级重试 ({chain_attempt + 1}/{max_chain_retries})，等待 {backoff}s 后从头重跑...")
                time.sleep(backoff)
                self.client = OpenAI(api_key=self.api_key, base_url=self.api_base, max_retries=3)
            
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_input}
            ]

            logger.debug(f"[{rule_id}] ====================")
            logger.debug(f"[{rule_id}] 开始深入排查 (Phase 3)" + (f" [重试 {chain_attempt + 1}]" if chain_attempt > 0 else ""))
            logger.debug(f"[{rule_id}] ====================")
            logger.debug(f"════════════════════════════════════════════════════════════")
            logger.debug(f"  🔍 [{rule_id} | Phase 3 链路调查启动]")
            logger.debug(f"  Source: {source_component}")
            logger.debug(f"  Sink:   {sink_component}")
            logger.debug(f"════════════════════════════════════════════════════════════")
            
            seen_tools = set()
            total = self.max_turns
            chain_fatal = False

            for turn in range(self.max_turns): # 防死循环强杀机制
                if turn == int(total * 0.8):
                    messages.append({"role": "user", "content": f"[System Status] Turn Executed: {turn} / {total}. Remaining: {total - turn}."})
                elif turn == total - 2:
                    messages.append({"role": "user", "content": f"[System Status] Mandatory Final Action: Turn limit reached. Execution of `submit_finding` is strictly required."})

                try:
                    # 应对 429 频控及短暂网络波动的指数退避重试机制
                    max_retries = 20
                    retry_count = 0
                    fatal_error_count = 0
                    msg_dict = None
                    
                    while retry_count < max_retries:
                        stream_ref = [None]
                        
                        def _do_stream():
                            res = self.client.chat.completions.create(model=self.model, messages=messages, tools=self.TOOLS_SCHEMA, temperature=self.temperature, stream=True)
                            stream_ref[0] = res
                            c_buf = ""
                            t_buf = {}
                            for chunk in res:
                                if not chunk.choices: continue
                                delta = chunk.choices[0].delta
                                if delta.content: c_buf += delta.content
                                if delta.tool_calls:
                                    for tc_chunk in delta.tool_calls:
                                        idx = tc_chunk.index
                                        if idx not in t_buf:
                                            t_buf[idx] = {"id": tc_chunk.id, "type": "function", "function": {"name": "", "arguments": ""}}
                                        if tc_chunk.function.name: t_buf[idx]["function"]["name"] += tc_chunk.function.name
                                        if tc_chunk.function.arguments: t_buf[idx]["function"]["arguments"] += tc_chunk.function.arguments
                            md = {"role": "assistant"}
                            if c_buf:
                                md["content"] = c_buf
                            else:
                                md["content"] = None
                            if t_buf:
                                md["tool_calls"] = [t_buf[i] for i in sorted(t_buf.keys())]
                            return md, c_buf

                        try:
                            import concurrent.futures
                            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                                future = executor.submit(_do_stream)
                                try:
                                    msg_dict, c_buf_out = future.result(timeout=self.timeout)
                                    if c_buf_out:
                                        logger.debug(f"[{rule_id} | Turn {turn+1}] 🧠 心智推演:\n{c_buf_out}")
                                    break # Success, break out of while retry_count loop
                                except concurrent.futures.TimeoutError:
                                    if stream_ref[0] is not None:
                                        try: stream_ref[0].close()
                                        except Exception: pass
                                    raise TimeoutError(f"代理商幽灵死锁超过 {self.timeout} 秒，绝对时间墙已拔线强杀！")
                                    
                        except Exception as inner_e:
                            error_msg = str(inner_e).lower()
                            is_fatal = "tool choice" in error_msg or "401" in error_msg
                        
                            if is_fatal:
                                fatal_error_count += 1
                                logger.warning(f"[{rule_id} | Turn {turn+1}] 探测到 API 后端致命错误 ({fatal_error_count}/3): {inner_e}")
                            
                                if fatal_error_count >= 3:
                                    raise FatalAPIError(f"后端大面积不支持 Tool Calling，Fast-Fail 熔断: {inner_e}")
                            
                                # 重建 Client，试图换节点，且仅短暂等待
                                self.client = OpenAI(api_key=self.api_key, base_url=self.api_base, timeout=self.timeout, max_retries=0)
                                time.sleep(2)
                                continue
                        
                            retry_count += 1
                            if retry_count >= max_retries:
                                raise inner_e # 若超限则抛出给外层的断路器
                            logger.debug(f"[{rule_id} | Turn {turn+1}] ⚠️ API 频控或网络异常，正触发第 {retry_count} 次退避重试... | Error: {inner_e}")
                            if retry_count >= 3:
                                self.client = OpenAI(api_key=self.api_key, base_url=self.api_base, timeout=self.timeout, max_retries=0)
                            time.sleep(5) # 失败了固定等 5 秒，防止出现几分钟的傻等

                    messages.append(msg_dict)
                
                    if "tool_calls" not in msg_dict or not msg_dict["tool_calls"]:
                        logger.debug(f"[{rule_id} | Turn {turn+1}] ⚠️ 模型未调用任何工具，拉回正轨。")
                        messages.append({"role": "user", "content": "必须调用工具搜集证据，或者以 submit_finding 结束。"})
                        continue
                
                    for tc in msg_dict["tool_calls"]:
                        name = tc["function"]["name"].split(":")[-1]
                        try:
                            args = json.loads(tc["function"]["arguments"])
                        except Exception:
                            args = {}
                        
                        logger.debug(f"[{rule_id} | Turn {turn+1}] 🛠️ 调用工具: {name} | 参数: {json.dumps(args, ensure_ascii=False)}")
                    
                        if name == "submit_finding":
                            logger.debug(f"[{rule_id} | Turn {turn+1}] 📜 终审报告提交: {args.get('assessment')}")
                            if args.get('defense_penetration_review'):
                                logger.debug(f"[{rule_id} | Turn {turn+1}] 🛡️ 防御击穿评估: {args.get('defense_penetration_review')}")
                            return args # 一锤定音

                        # ====== 防物理死循环拦截 ======
                        tool_signature = f"{name}::{json.dumps(args, sort_keys=True)}"
                        if tool_signature in seen_tools:
                            res_str = "[物理外挂拦截] 你此前已完全用同样的词条调用过该工具并遭遇报错。底层坚决拦截你的原地死循环，请立即更换关键字、正则表达式"
                            #logger.warning(f"[{rule_id} | Turn {turn+1}] 🛑 触发防死循环物理拦截: {name}")
                        else:
                            seen_tools.add(tool_signature)
                            # 普通工具执行
                            result = self._execute_tool(name, args)
                            res_str = str(result)
                        
                        if len(res_str) > 4000:
                            res_str = res_str[:4000] + "\n... [安全保护机制触发：内容过长，已被强制截断。系统强制要求：请缩小搜索范围或使用 read_file_snippet 精确读行] ..."
                        logger.debug(f"[{rule_id} | Turn {turn+1}] 📥 工具返回:\n{res_str[:500]} ...")
                        messages.append({"role": "tool", "tool_call_id": tc["id"], "name": tc["function"]["name"], "content": res_str}) # 限长防止上下文崩盘
                except FatalAPIError as fe:
                    logger.error(f"🚨 触发 API 致命故障快读失败 (Fast-Fail): {fe}")
                    chain_fatal = True  # 标记为基础设施故障，触发链路级重试
                    break
                except Exception as e:
                    logger.error(f"Agent 调用异常: {e}")
                    time.sleep(2)
                    break
            
            # 如果是基础设施故障，且还有重试次数，从头重跑整条链
            if chain_fatal and chain_attempt < max_chain_retries - 1:
                continue
            
            # 其他原因中断（正常结束、死循环、普通异常），不再重试
            break

        # 兜底降级处理 (Graceful Degradation)
        logger.warning(f"⚠️ 链路 {rule_id} 调查触发断路器，强制安全降级返回 UNCERTAIN。")
        return {
            "assessment": "UNCERTAIN",
            "analysis_chain": "网络连接失败 / 特工陷入死循环退出，请人工复核源码数据流。",
            "attacker_condition": "N/A",
            "server_condition": "N/A",
            "security_impact": "N/A",
            "proof_of_concept": "N/A",
            "hazard_scores": {"attacker_condition_score": 0, "server_condition_score": 0, "security_impact_score": 0}
        }

def run_concurrent_investigations(tasks: List[dict], config: dict, cpg_path: str, source_dir: str | None = None, checkpoint_ctx: Optional[dict] = None) -> List[dict]:
    """主干入口：并发启动多个特工，返回收集了 hazard_scores 的新 JSON 列表"""
    root_src = source_dir if source_dir else config.get("root_source_dir", os.getcwd())
    api_key = config.get("api_key", "")
    api_base = config.get("api_base", "https://api.siliconflow.cn/v1")
    model = config.get("model", "deepseek-ai/DeepSeek-V3")
    max_workers = config.get("phase3_max_workers", 3)
    max_turns = config.get("phase3_max_turns", 30)

    if not tasks: return []

    mgr = JoernServerManager(cpg_path)
    progress = None
    
    try:
        if not mgr.start():
            logger.error("图谱常驻服务拉起失败，取消 Phase 3。")
            return tasks # 原样返回降级
        
        temperature = config.get("temperature", 0.1)
        timeout = config.get("timeout_seconds", 300)
        agent = Phase3Agent(api_key, api_base, model, mgr, root_src, max_turns=max_turns, temperature=temperature, timeout=timeout)
        logger.info(f"[Phase 3 配置] 模型: {model} | 温度: {temperature} | 最大轮次: {max_turns} | 并发数: {max_workers}")
    
        results = []
    
        cp_lock = threading.Lock()

        # UI setup
        if HAS_RICH:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console
            )
            task_id = progress.add_task("[cyan]🔍 Phase 3 图谱黑客特工极速取证中...", total=len(tasks))
            progress.start()
        else:
            logger.info(f"🔍 开始并发探查 {len(tasks)} 条链路...")
            task_id = None
        def w(task):
            res = agent.investigate(task)
            task["phase3_report"] = res
            return task

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(w, t): t for t in tasks}
            for future in concurrent.futures.as_completed(futures):
                try:
                    res_task = future.result()
                    results.append(res_task)
                    
                    if checkpoint_ctx:
                        route_fp = res_task.get("_route_fingerprint")
                        if route_fp:
                            with cp_lock:
                                # Update locally
                                checkpoint_ctx["completed_chains"][route_fp] = {
                                    "verdict": res_task.get("_chain_ref").verdict if res_task.get("_chain_ref") else "[EXPLOITABLE]",
                                    "phase3_report": res_task.get("phase3_report", {})
                                }
                                # Save to disk
                                save_checkpoint(
                                    checkpoint_ctx["rule_id"],
                                    checkpoint_ctx["fingerprint"],
                                    checkpoint_ctx["config_info"],
                                    checkpoint_ctx["completed_chains"]
                                )
                except Exception as e:
                    logger.error(f"并发特工子线程出错: {e}")
                    failed_task = futures[future]
                    failed_task["phase3_report"] = {
                        "assessment": "UNCERTAIN",
                        "analysis_chain": f"执行线程严重崩溃: {str(e)}。强制标记为存疑。"
                    }
                    results.append(failed_task)
                    if checkpoint_ctx:
                        route_fp = failed_task.get("_route_fingerprint")
                        if route_fp:
                            with cp_lock:
                                checkpoint_ctx["completed_chains"][route_fp] = {
                                    "verdict": "[UNCERTAIN]",
                                    "phase3_report": failed_task["phase3_report"]
                                }
                                save_checkpoint(
                                    checkpoint_ctx["rule_id"],
                                    checkpoint_ctx["fingerprint"],
                                    checkpoint_ctx["config_info"],
                                    checkpoint_ctx["completed_chains"]
                                )
                if progress:
                    progress.advance(task_id)
    except KeyboardInterrupt:
        logger.warning("⚠️ 用户中断 (Ctrl+C)，正在安全关闭 Joern Server...")
        raise
    finally:
        if progress: progress.stop()
        mgr.stop()

    return results
