"""
Bark 通知模块
复用 smart-money-monitor 的通知模式
支持：漏洞发现通知、PR 创建通知、扫描完成通知
"""

import requests
import urllib.parse


class BarkNotifier:
    """Bark 推送通知器"""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.bark_cfg = config.get("bark", {})
        self.bark_key = self.bark_cfg.get("key", "")

    def _send(self, title, body, url=""):
        """发送 Bark 通知"""
        if not self.bark_key or self.bark_key.strip() == "":
            self.logger.info(f"[BARK] {title} — {body}")
            return

        try:
            bark_url = f"https://api.day.app/{self.bark_key.strip()}/{urllib.parse.quote(title)}"
            params = {}
            if body:
                params["body"] = body
            if url:
                params["url"] = url

            resp = requests.get(bark_url, params=params, timeout=10)
            if resp.status_code == 200:
                self.logger.info(f"[BARK] 推送成功: {title}")
            else:
                self.logger.warning(f"[BARK] 推送失败: {resp.status_code} {resp.text}")
        except Exception as e:
            self.logger.warning(f"[BARK] 推送异常: {e}")

    def notify_scan_start(self, repo_count):
        """扫描开始通知"""
        self._send(
            "Bounty Hunter 开始扫描",
            f"发现 {repo_count} 个候选项目，正在逐一分析...",
        )

    def notify_findings(self, repo, findings):
        """发现漏洞通知"""
        vuln_types = list(set(f["type"] for f in findings))
        severities = list(set(f["severity"] for f in findings))
        title = f"发现漏洞: {repo['owner']}/{repo['name']}"
        body = f"{len(findings)} 个漏洞 | 类型: {', '.join(vuln_types)} | 等级: {', '.join(severities)}"
        repo_url = f"https://github.com/{repo['owner']}/{repo['name']}"
        self._send(title, body, url=repo_url)

    def notify_pr_created(self, pr_url, repo):
        """PR 创建成功通知"""
        if pr_url.startswith("MOCK:"):
            self.logger.info(f"[PR 创建] {pr_url} (测试模式)")
            return

        title = f"PR 已创建: {repo['owner']}/{repo['name']}"
        body = "Draft PR 已创建，请在 GitHub 上 review 后 publish"
        self._send(title, body, url=pr_url)

    def notify_scan_complete(self, findings_count, test_mode):
        """扫描完成通知"""
        if test_mode:
            self._send(
                "Bounty Hunter 测试扫描完成",
                f"发现 {findings_count} 个有漏洞的项目（测试模式，无真实操作）",
            )
        else:
            self._send(
                "Bounty Hunter 扫描完成",
                f"发现 {findings_count} 个有漏洞的项目，请前往 GitHub review 草稿 PR",
            )
