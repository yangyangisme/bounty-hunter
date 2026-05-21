"""
PR 生成模块 v2
Fork-then-PR 流程：
1. Fork 目标仓库到你的账户
2. 在 fork 上创建分支
3. 提交修复文件
4. 创建从 fork 到原仓库的 PR
"""

import requests
import base64
import time
import json


# ==================== 修复代码模板 ====================
FIX_TEMPLATES = {
    "hardcoded_secret": {
        "python": '''# 修复前：硬编码密钥（危险！）
# {matched}

# 修复后：使用环境变量
import os
SECRET_KEY = os.environ.get("API_KEY", "")
if not SECRET_KEY:
    raise ValueError("API_KEY environment variable is required")
''',
        "javascript": '''// 修复前：硬编码密钥（危险！）
// {matched}

// 修复后：使用环境变量
const API_KEY = process.env.API_KEY;
if (!API_KEY) {{
  throw new Error("API_KEY environment variable is required");
}}
''',
    },
    "sql_injection": {
        "python": '''# 修复前：SQL 拼接（危险！）
# {matched}

# 修复后：使用参数化查询
results = db.execute(
    "SELECT * FROM posts WHERE title LIKE ?",
    (f"%{query}%",)
)
''',
        "javascript": '''// 修复前：SQL 拼接（危险！）
// {matched}

// 修复后：使用参数化查询
const results = await db.query(
    'SELECT * FROM posts WHERE title LIKE ?',
    [`%${query}%`]
);
''',
    },
    "xss": {
        "python": '''# 修复前：直接返回 HTML（XSS 风险）
# {matched}

# 修复后：使用安全模板引擎
from markupsafe import escape
return f"<h1>Welcome {escape(name)}</h1>"
''',
        "javascript": '''// 修复前：innerHTML 直接赋值（XSS 风险）
// {matched}

// 修复后：使用 textContent 或转义
element.textContent = userInput;
// 或使用 DOMPurify 清理 HTML
''',
    },
    "path_traversal": {
        "python": '''# 修复前：路径拼接（Path Traversal 风险）
# {matched}

# 修复后：使用 os.path.abspath + basename 限制
import os
safe_name = os.path.basename(user_path)
safe_path = os.path.join("/data", safe_name)
with open(safe_path, "r") as f:
    return f.read()
''',
        "javascript": '''// 修复前：路径拼接（Path Traversal 风险）
// {matched}

// 修复后：使用 path.basename 限制路径
const path = require("path");
const safe = path.basename(req.query.file);
res.sendFile(path.join(__dirname, "uploads", safe));
''',
    },
    "command_injection": {
        "python": '''# 修复前：命令拼接（危险！）
# {matched}

# 修复后：使用列表参数方式，禁用 shell=True
import subprocess
result = subprocess.run(
    ["ping", "-c", "1", host],  # 使用列表而非字符串
    capture_output=True,
    text=True,
    timeout=5
)
''',
        "javascript": '''// 修复前：命令拼接（危险！）
// {matched}

// 修复后：使用 spawn 传入数组参数
const { spawn } = require("child_process");
const proc = spawn("ping", ["-c", "1", host]);
''',
    },
    "eval_usage": {
        "python": '''# 修复前：使用 eval()（危险！）
# {matched}

# 修复后：使用 ast.literal_eval 安全解析，或重构逻辑
import ast
safe_value = ast.literal_eval(user_input)
''',
        "javascript": '''// 修复前：使用 eval()（危险！）
// {matched}

// 修复后：使用 JSON.parse 或更安全的替代方案
const data = JSON.parse(userInput);
''',
    },
    "insecure_random": {
        "python": '''# 修复前：使用 random 模块生成安全令牌（不安全！）
# {matched}

# 修复后：使用 secrets 模块
import secrets
token = secrets.token_urlsafe(32)
''',
        "javascript": '''// 修复前：使用 Math.random()（不安全！）
// {matched}

// 修复后：使用 crypto.randomBytes
const crypto = require("crypto");
const token = crypto.randomBytes(32).toString("hex");
''',
    },
    "yaml_unsafe_load": {
        "python": '''# 修复前：yaml.load 无安全参数（危险！）
# {matched}

# 修复后：使用 yaml.safe_load
import yaml
data = yaml.safe_load(user_yaml_content)
''',
    },
    "pickle_load": {
        "python": '''# 修复前：pickle.loads 不安全（危险！）
# {matched}

# 修复后：使用 JSON 或自定义安全序列化
import json
data = json.loads(user_data)
''',
    },
    "debug_mode": {
        "python": '''# 修复前：生产环境开启 debug 模式（危险！）
# {matched}

# 修复后：根据环境变量控制
import os
debug = os.environ.get("FLASK_ENV") == "development"
app.run(debug=debug)
''',
    },
}

DEFAULT_FIX = {
    "python": "# 建议修复此处代码，参考安全最佳实践",
    "javascript": "// 建议修复此处代码，参考安全最佳实践",
}


def generate_fix_code(vuln_type, matched, language):
    lang_key = language.lower() if language.lower() in ["python", "javascript", "typescript"] else "javascript"
    if lang_key == "typescript":
        lang_key = "javascript"
    if vuln_type in FIX_TEMPLATES:
        template = FIX_TEMPLATES[vuln_type].get(lang_key, FIX_TEMPLATES[vuln_type].get("python", ""))
    else:
        template = DEFAULT_FIX.get(lang_key, "")
    if not template:
        return DEFAULT_FIX.get(lang_key, "请手动修复此漏洞")
    return template.format(matched=matched)


def build_pr_body(repo, findings):
    """
    构建高质量 PR 描述（英文，符合开源社区规范）
    - 每个漏洞提供精准的文件路径 + 行号 + 真实问题代码
    - 不提交修复代码文件，只提供安全报告
    - 措辞专业克制，避免被误认为 spam
    """
    vuln_counts = {}
    for f in findings:
        t = f["type"]
        vuln_counts[t] = vuln_counts.get(t, 0) + 1

    severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '⚪'}

    body_lines = [
        f"## Security Report: {len(findings)} issue(s) found in `{repo['name']}`",
        "",
        "I ran a static analysis on this repository and found potential security issues.",
        "All findings below were manually verified to contain actual sensitive values",
        "(not placeholder/example strings, not enum labels, not public API endpoints).",
        "",
        "### Summary",
        "",
        "| Severity | Type | Count |",
        "|----------|------|-------|",
    ]
    for vtype, count in vuln_counts.items():
        # 获取第一个该类型 finding 的严重程度
        sev = next((f['severity'] for f in findings if f['type'] == vtype), 'HIGH')
        emoji = severity_emoji.get(sev, '⚪')
        body_lines.append(f"| {emoji} {sev} | {vtype} | {count} |")

    body_lines.extend([
        "",
        "### Findings",
        "",
    ])

    for i, f in enumerate(findings[:10], 1):
        emoji = severity_emoji.get(f['severity'], '⚪')
        body_lines.extend([
            f"#### {i}. {emoji} [{f['severity']}] {f['description']}",
            "",
            f"- **File**: `{f['file']}`",
            f"- **Line**: {f['line']}",
            f"- **CWE**: [{f['cwe_id']}](https://cwe.mitre.org/data/definitions/{f['cwe_id'].replace('CWE-', '')}.html)",
            "",
            "**Vulnerable code:**",
            "```",
            f.get('context', f.get('matched', '')).strip(),
            "```",
            "",
            f"**Recommended fix:** {f['fix']}",
            "",
            "---",
            "",
        ])

    body_lines.extend([
        "### Notes",
        "",
        "- Findings were detected using pattern matching combined with semantic filtering",
        "  to reduce false positives (enum labels, public URLs, and placeholder values are excluded).",
        "- If any finding is incorrect, please let me know — I'll improve the scanner.",
        "- Happy to provide a concrete code fix if this report is confirmed valid.",
        "",
        "> Reported in good faith. No exploitation was performed.",
    ])
    return "\n".join(body_lines)


class PRGenerator:
    BASE_URL = "https://api.github.com"

    def __init__(self, config, logger, test_mode=False):
        self.config = config
        self.logger = logger
        self.test_mode = test_mode
        self.token = config.get("github", {}).get("token", "")
        self.max_prs = config.get("github", {}).get("max_prs_per_day", 3)
        # 缓存：已 fork 的仓库 -> fork 后的完整名称 "username/repo"
        self._fork_cache = {}
        self._username = None  # 缓存当前用户

    def _headers(self):
        return {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {self.token}",
            "User-Agent": "BountyHunter/1.0",
        }

    def _get_username(self):
        """获取当前认证用户的用户名"""
        if self._username:
            return self._username
        try:
            resp = requests.get(f"{self.BASE_URL}/user", headers=self._headers(), timeout=15)
            if resp.status_code == 200:
                self._username = resp.json().get("login", "")
                return self._username
        except Exception:
            pass
        return ""

    def _fork_repo(self, owner, name):
        """Fork 目标仓库到当前用户账户"""
        my_name = self._get_username()
        if not my_name:
            self.logger.error("  无法获取当前用户名，Fork 失败")
            return None, None

        # 检查是否已 fork（通过查询自己的仓库列表）
        cache_key = f"{owner}/{name}"
        if cache_key in self._fork_cache:
            fork_name = self._fork_cache[cache_key]
            self.logger.info(f"  使用已缓存的 fork: {fork_name}")
            return my_name, name  # fork 名称 = 原名（在当前用户下）

        # 检查该仓库是否已经被当前用户 fork
        try:
            check_url = f"{self.BASE_URL}/repos/{my_name}/{name}"
            resp = requests.get(check_url, headers=self._headers(), timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                # 如果 parent.owner.login == owner，说明是我们的 fork
                if data.get("parent", {}).get("owner", {}).get("login") == owner:
                    self.logger.info(f"  已存在 fork: {my_name}/{name}")
                    self._fork_cache[cache_key] = f"{my_name}/{name}"
                    return my_name, name
        except Exception:
            pass

        # 执行 Fork
        self.logger.info(f"  正在 Fork {owner}/{name} 到 {my_name}/{name}...")
        fork_url = f"{self.BASE_URL}/repos/{owner}/{name}/forks"
        resp = requests.post(fork_url, headers=self._headers(), json={}, timeout=30)

        if resp.status_code in (200, 201, 202):
            self.logger.info(f"  Fork 成功: {my_name}/{name}")
            self._fork_cache[cache_key] = f"{my_name}/{name}"
            return my_name, name
        elif resp.status_code == 202:
            # 异步创建，等待一下再查
            self.logger.info("  Fork 异步创建中，等待 5 秒...")
            time.sleep(5)
            self._fork_cache[cache_key] = f"{my_name}/{name}"
            return my_name, name
        else:
            self.logger.error(f"  Fork 失败: {resp.status_code} {resp.text[:100]}")
            return None, None

    def _create_branch(self, fork_owner, name, base_branch="main"):
        """在 fork 上创建新分支"""
        # 获取默认分支
        url = f"{self.BASE_URL}/repos/{fork_owner}/{name}"
        resp = requests.get(url, headers=self._headers(), timeout=15)
        if resp.status_code == 200:
            default_branch = resp.json().get("default_branch", base_branch)
        else:
            default_branch = base_branch

        # 获取最新 commit SHA
        ref_url = f"{self.BASE_URL}/repos/{fork_owner}/{name}/git/ref/heads/{default_branch}"
        resp = requests.get(ref_url, headers=self._headers(), timeout=15)
        if resp.status_code != 200:
            self.logger.error(f"  获取分支 SHA 失败: {resp.text[:80]}")
            return None
        sha = resp.json()["object"]["sha"]

        # 创建分支
        branch_name = f"bounty-hunter-fix-{int(time.time())}"
        create_url = f"{self.BASE_URL}/repos/{fork_owner}/{name}/git/refs"
        data = {"ref": f"refs/heads/{branch_name}", "sha": sha}
        resp = requests.post(create_url, headers=self._headers(), json=data, timeout=15)
        if resp.status_code in (201, 200):
            self.logger.info(f"  分支创建成功: {branch_name}")
            return branch_name
        else:
            self.logger.error(f"  分支创建失败: {resp.text[:80]}")
            return None

    def _submit_file(self, fork_owner, name, branch, path, content, message):
        """在 fork 上提交文件"""
        url = f"{self.BASE_URL}/repos/{fork_owner}/{name}/contents/{path}"
        encoded = requests.utils.quote(path, safe='/') if hasattr(requests, 'utils') else path
        data = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
            "branch": branch,
        }
        resp = requests.put(url, headers=self._headers(), json=data, timeout=15)
        return resp.status_code in (200, 201)

    def create_pr(self, repo, findings):
        """
        Fork → 创建分支 → 提交修复 → 创建 PR
        返回 PR URL 或 None
        """
        if self.test_mode:
            pr_preview = {
                "repo": f"{repo['owner']}/{repo['name']}",
                "title": f"[Security Fix] {repo['name']}: {len(findings)} vulnerabilities",
                "findings_count": len(findings),
                "note": "测试模式：未实际调用 GitHub API",
            }
            self.logger.info(f"  [MOCK] {json.dumps(pr_preview, ensure_ascii=False)}")
            return f"MOCK: {repo['owner']}/{repo['name']}"

        owner = repo["owner"]
        name = repo["name"]

        # Step 1: Fork 仓库
        my_name = self._get_username()
        if not my_name:
            self.logger.error("  无法获取用户信息，请检查 Token 权限")
            return None

        fork_owner, fork_name = self._fork_repo(owner, name)
        if not fork_owner:
            return None

        # Step 2: 创建分支
        branch = self._create_branch(fork_owner, fork_name)
        if not branch:
            return None

        # Step 3: 提交安全报告文件（简洁的 markdown）
        fix_content = build_pr_body(repo, findings)
        fix_path = "SECURITY_REPORT.md"
        success = self._submit_file(
            fork_owner, fork_name, branch,
            fix_path,
            fix_content,
            f"security: add vulnerability report ({len(findings)} issue(s) detected)"
        )
        if not success:
            self.logger.error("  文件提交失败")
            return None

        # Step 4: 创建 PR（英文标题，更专业）
        head = f"{fork_owner}:{branch}"
        pr_url = f"{self.BASE_URL}/repos/{owner}/{name}/pulls"

        # 构建简洁的标题
        top_sev = max(
            (f['severity'] for f in findings),
            key=lambda s: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(s),
            default='HIGH'
        )
        pr_data = {
            "title": f"[Security] {name}: {len(findings)} potential issue(s) [{top_sev}]",
            "body": build_pr_body(repo, findings),
            "head": head,
            "base": repo.get("default_branch", "main"),
            "draft": True,  # Draft 先让自己 review，确认无误再 publish
        }
        resp = requests.post(pr_url, headers=self._headers(), json=pr_data, timeout=15)

        if resp.status_code in (200, 201):
            pr = resp.json()
            pr_number = pr.get("number", "?")
            pr_html_url = pr.get("html_url", "")
            self.logger.info(f"  PR 创建成功: #{pr_number} {pr_html_url}")
            return pr_html_url
        else:
            self.logger.error(f"  PR 创建失败: {resp.status_code} {resp.text[:100]}")
            return None
