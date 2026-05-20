# Bounty Hunter - GitHub 漏洞赏金自动化管道
#
# 使用方法：
#   python main.py              # 本地测试（测试模式）
#   python main.py --real      # 真实模式（需要配置 GitHub Token）
#
# GitHub Actions 自动触发，参考 .github/workflows/bounty-hunt.yml

import os
import sys
import json
import logging
import logging.handlers
import argparse
from datetime import datetime

# 确保 modules 目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.github_search import GitHubSearch
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.pr_generator import PRGenerator
from modules.notifier import BarkNotifier

# ==================== 日志配置 ====================
def setup_logging(config):
    log_cfg = config.get("logging", {})
    log_file = log_cfg.get("file", "outputs/bounty_hunter.log")
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger("bounty_hunter")
    logger.setLevel(getattr(logging, log_cfg.get("level", "INFO")))

    # 文件 Handler（轮转）
    fh = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=log_cfg.get("max_bytes", 10 * 1024 * 1024),
        backupCount=log_cfg.get("backup_count", 5),
        encoding="utf-8"
    )
    fh.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    # 控制台 Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s | %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(ch)

    return logger


def load_config():
    import yaml
    with open("config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_state():
    """加载已扫描记录，避免重复扫描"""
    state_file = "outputs/scanned_repos.json"
    if os.path.exists(state_file):
        with open(state_file, encoding="utf-8") as f:
            return json.load(f)
    return {"scanned": [], "prs_created": []}


def save_state(state):
    os.makedirs("outputs", exist_ok=True)
    with open("outputs/scanned_repos.json", "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def is_test_mode(config):
    return not config.get("github", {}).get("token") or config.get("github", {}).get("token").strip() == ""


def main():
    parser = argparse.ArgumentParser(description="Bounty Hunter - GitHub 漏洞赏金自动化")
    parser.add_argument("--real", action="store_true", help="真实模式（需要 GitHub Token）")
    args = parser.parse_args()

    config = load_config()
    logger = setup_logging(config)

    test_mode = not args.real and is_test_mode(config)

    if test_mode:
        logger.info("=" * 50)
        logger.info("  Bounty Hunter - 测试模式")
        logger.info("  不调用真实 GitHub API，使用模拟数据")
        logger.info("  填入 config.yaml 中的 token 后用 --real 运行")
        logger.info("=" * 50)
    else:
        logger.info("=" * 50)
        logger.info("  Bounty Hunter - 真实模式")
        logger.info("=" * 50)

    # 加载状态
    state = load_state()

    # 初始化模块
    notifier = BarkNotifier(config, logger)
    searcher = GitHubSearch(config, logger, test_mode)
    scanner = VulnerabilityScanner(config, logger)
    pr_gen = PRGenerator(config, logger, test_mode)

    # ===== Step 1: 搜索目标项目 =====
    logger.info("[Step 1] 搜索有安全策略的开源项目...")
    repos = searcher.find_bounty_projects()

    if not repos:
        logger.warning("未找到任何目标项目，请检查 GitHub Token 或网络连接")
        notifier.notify_scan_complete(0, test_mode)
        return

    logger.info(f"找到 {len(repos)} 个候选项目")
    notifier.notify_scan_start(len(repos))

    # ===== Step 2: 扫描漏洞 =====
    logger.info("[Step 2] 开始扫描漏洞...")
    max_repos = config.get("scanner", {}).get("max_repos_per_run", 10)
    pr_count_today = sum(1 for pr in state.get("prs_created", []) if datetime.now().strftime("%Y-%m-%d") in pr.get("created", ""))

    all_findings = []

    for i, repo in enumerate(repos[:max_repos], 1):
        repo_id = f"{repo['owner']}/{repo['name']}"
        logger.info(f"  [{i}/{min(len(repos), max_repos)}] 扫描 {repo_id}...")

        if repo_id in state.get("scanned", []) and config.get("scanner", {}).get("skip_scanned", True):
            logger.info(f"    已扫描过，跳过")
            continue

        findings = scanner.scan_repo(repo)

        if findings:
            logger.info(f"    发现 {len(findings)} 个潜在漏洞:")
            for f in findings:
                logger.info(f"      [{f['severity']}] {f['type']} @ {f['file']}:{f['line']}")
            all_findings.append({"repo": repo, "findings": findings})
            notifier.notify_findings(repo, findings)
        else:
            logger.info(f"    无漏洞或无相关代码文件")

        # 标记已扫描
        state.setdefault("scanned", []).append(repo_id)

    logger.info(f"扫描完成，共发现 {len(all_findings)} 个有漏洞的项目")

    # ===== Step 3: 生成 PR（仅真实模式）=====
    if test_mode:
        logger.info("[Step 3] 测试模式：跳过 PR 创建")
        logger.info("  发现的漏洞已保存到 outputs/pending_findings.json")
        os.makedirs("outputs", exist_ok=True)
        with open("outputs/pending_findings.json", "w", encoding="utf-8") as f:
            json.dump(all_findings, f, ensure_ascii=False, indent=2)
    else:
        logger.info("[Step 3] 生成修复 PR...")
        max_prs = config.get("github", {}).get("max_prs_per_day", 3)
        remaining = max_prs - pr_count_today

        if remaining <= 0:
            logger.warning("今日 PR 数量已达上限，请明天再试")
        else:
            for item in all_findings[:remaining]:
                repo = item["repo"]
                findings = item["findings"]
                pr_url = pr_gen.create_pr(repo, findings)
                if pr_url:
                    state.setdefault("prs_created", []).append({
                        "repo": f"{repo['owner']}/{repo['name']}",
                        "url": pr_url,
                        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    notifier.notify_pr_created(pr_url, repo)

    # 保存状态
    save_state(state)

    # ===== 完成通知 =====
    notifier.notify_scan_complete(len(all_findings), test_mode)
    logger.info("=" * 50)
    logger.info(f"本次扫描完成！发现 {len(all_findings)} 个有漏洞的项目")
    if test_mode:
        logger.info("输出文件：outputs/pending_findings.json")
    logger.info("=" * 50)


if __name__ == "__main__":
    main()
