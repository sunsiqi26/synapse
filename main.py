#!/usr/bin/env python3
"""
main.py —— Hybris-SAST CLI 入口

用法示例：
  # 执行单条规则
  python main.py --cpg ./jumpserver.bin --src ./jumpserver --rule python/django/ssti

  # 组合扫描
  python main.py --cpg ./demo.bin --src ./demo --rule java/spring/sqli --rule java/spring/ssti

  # 批量扫描某个规则目录
  python main.py --cpg ./demo.bin --src ./demo --rule-dir rules/java/spring/

  # 列出所有可用规则
  python main.py --list-rules

  # 纯静态模式（不调用 AI）
  python main.py --cpg ./demo.bin --src ./demo --rule python/celery/rce --no-ai

注意：API Key、模型等鉴权参数统一在 config.json 中配置，不通过 CLI 传入。
"""

import argparse
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from engine.logger import configure_cli_logging, get_logger
from engine.rule_loader import load_rule, load_rules_from_dir, list_rules, RuleLoadError
from engine.core import HybrisScanner
from reporter import generate_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hybris-sast",
        description="Hybris-SAST：基于 Joern CPG + AI 语义审判的混合漏洞扫描引擎",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--cpg",
        metavar="PATH",
        help="Joern CPG 文件路径（.bin）",
    )
    parser.add_argument(
        "--src",
        metavar="PATH",
        help="目标对象源码根目录（辅助 Phase 3 Agent 取证）",
    )
    parser.add_argument(
        "--rule",
        metavar="RULE_ID",
        action="append",
        dest="rules",
        default=[],
        help="指定规则 ID（可多次使用），如：python/django/ssti",
    )
    parser.add_argument(
        "--rule-dir",
        metavar="DIR",
        help="批量加载某个规则子目录，如：rules/java/spring/",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help="HTML 报告输出路径（默认：output/reports/report_<timestamp>.html）",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="跳过 AI 语义裁决阶段，仅执行静态图分析",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="从上一次的断点处恢复扫描 (跳过已完成的 Checkpoint)",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="无视历史缓存，强制开启全新扫描",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="列出所有可用规则后退出",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="启用 DEBUG 级别日志输出",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    log_file = configure_cli_logging(verbose=args.verbose)
    logger = get_logger("cli")

    # ── 列出规则 ──────────────────────────────────────────────────────────────
    if args.list_rules:
        available = list_rules()
        if not available:
            print("rules/ 目录下暂无可用规则。")
            return
        print(f"\n{'ID':<35} {'名称':<40} {'严重度'}")
        print("-" * 85)
        for r in available:
            print(f"{r['id']:<35} {r['name']:<40} {r['severity']}")
        print()
        return

    # ── 参数校验 ──────────────────────────────────────────────────────────────
    if not args.cpg:
        print("错误：--cpg 为必要参数。运行 --help 查看帮助。", file=sys.stderr)
        sys.exit(1)

    if not args.rules and not args.rule_dir:
        print("错误：必须指定至少一条 --rule 或 --rule-dir。运行 --help 查看帮助。", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.cpg):
        print(f"错误：CPG 文件不存在：{args.cpg}", file=sys.stderr)
        sys.exit(1)

    # ── 加载规则 ──────────────────────────────────────────────────────────────
    scanner = HybrisScanner(cpg_path=args.cpg, source_dir=args.src)

    try:
        for rule_id in args.rules:
            scanner.load_rule(rule_id)
            logger.info("规则已装载：%s", rule_id)

        if args.rule_dir:
            scanner.load_rule_dir(args.rule_dir)
            logger.info("目录规则已装载：%s", args.rule_dir)

    except RuleLoadError as e:
        logger.error("规则加载失败：%s", e)
        sys.exit(1)

    # ── 执行扫描 ──────────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("  Hybris-SAST 扫描引擎启动")
    logger.info("=" * 60)

    report = scanner.run(no_ai=args.no_ai, resume=args.resume, fresh=args.fresh)

    # ── 生成报告 ──────────────────────────────────────────────────────────────
    if args.output:
        output_path = os.path.abspath(args.output)
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        project_root = os.path.dirname(__file__)
        output_path = os.path.join(project_root, "output", "reports", f"report_{ts}.html")

    rule_ids = args.rules + ([args.rule_dir] if args.rule_dir else [])
    generate_report(
        report=report,
        cpg_path=args.cpg,
        output_path=output_path,
        rule_ids=rule_ids,
    )

    # ── 最终摘要 ──────────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("扫描完成")

    logger.info("  [数据源] 直通漏洞链 (Phase 0)     : %d 条", len(report.direct_chains))
    logger.info("  [数据源] 断层拼接链 (Phase 1/2)   : %d 条", len(report.ai_chains))
    logger.info("  [最终裁决] 保留真实高危漏洞 (Phase 3) : %d 条", len(report.exploitable))
    logger.info("  [最终裁决] 成功剔除虚假误报 (Phase 3) : %d 条", len(report.safe))
    
    logger.info("  HTML 报告     : %s", output_path)
    logger.info("  JSON Dump     : %s", output_path.replace(".html", ".json"))
    if log_file:
        logger.info("  日志文件     : %s", log_file)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
# python3 main.py --cpg /home/aka/joern/test_cpg/dataease-21021.bin   --src /home/aka/joern/test_sources/dataease-2.10.21   --rule java/spring/pt
# python3 main.py --cpg /home/aka/joern/test_cpg/jumpserver41016.bin   --src /home/aka/joern/test_sources/jumpserver-v4.10.16/   --rule  python/web/rce
#python3 main.py --cpg /home/aka/joern/test_cpg/dataease-21021.bin   --src /home/aka/joern/test_sources/dataease-2.10.21   --rule-dir rules/java/spring