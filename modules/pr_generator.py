"""
PR 生成模块
通过 GitHub API 创建修复分支、提交修复代码、创建 Draft PR
测试模式：输出 PR 预览而不实际调用 API
"""

import requests
import base64
import time
import json
import os


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

# 默认修复模板
DEFAULT_FIX = {
    "python": "# 建议修复此处代码，参考安全最佳实践",
    "javascript": "// 建议修复此处代码，参考安全最佳实践",
}


def generate_fix_code(vuln_type, matched, language):
    """根据漏洞类型和语言生成修复代码"""
    lang_key = language.lower() if language.lower() in ["python", "javascript", "typescript"] else "javascript"

    # 统一语言映射
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
    """构建 PR 描述"""
    vuln_counts = {}
    for f in findings:
        t = f["type"]
        vuln_counts[t] = vuln_counts.get(t, 0) + 1

    body_lines = [
        f"# 安全漏洞修复：{repo['name']}",
        "",
        "## 发现摘要",
        "",
        f"| 漏洞类型 | 数量 |",
        f"|----------|------|",
    ]
    for vtype, count in vuln_counts.items():
        cwe = findings[0]["cwe_id"] if any(f["type"] == vtype for f in findings) else "N/A"
        body_lines.append(f"| {vtype} ({cwe}) | {count} |")

    body_lines.extend([
        "",
        "## 漏洞详情",
        "",
    ])

    for f in findings[:5]:  # 最多显示5个
        body_lines.extend([
            f"### [{f['severity']}] {f['description']} — {f['file']}:{f['line']}",
            "",
            f"**CWE**: {f['cwe_id']}",
            "",
            f"**问题代码**:",
            "```",
            f"{f['context']}",
            "```",
            "",
            f"**建议修复**:",
            "```",
            generate_fix_code(f["type"], f["matched"], repo.get("language", "")),
            "```",
            "",
            "---",
            "",
        ])

    body_lines.extend([
        "## 注意事项",
        "",
        "- 此 PR 包含安全修复，建议优先 review",
        "- 所有修复均遵循安全编码最佳实践",
        "- 如有疑问，请参考 OWASP 安全指南",
        "",
        "## CLA",
        "",
        "贡献此修复即表示您同意将代码按项目原有许可证发布。",
    ])

    return "\n".join(body_lines)


class PRGenerator:
    """PR 生成器"""

    BASE_URL = "https://api.github.com"

    def __init__(self, config, logger, test_mode=False):
        self.config = config
        self.logger = logger
        self.test_mode = test_mode
        self.token = config.get("github", {}).get("token", "")
        self.max_prs = config.get("github", {}).get("max_prs_per_day", 3)

    def _headers(self):
        return {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {self.token}",
            "User-Agent": "BountyHunter/1.0",
        }

    def _create_branch(self, owner, name, base_branch="main"):
        """创建新分支"""
        # 先获取默认分支
        url = f"{self.BASE_URL}/repos/{owner}/{name}"
        resp = requests.get(url, headers=self._headers(), timeout=15)
        if resp.status_code == 200:
            default_branch = resp.json().get("default_branch", base_branch)
        else:
            default_branch = base_branch

        # 获取最新 commit SHA
        ref_url = f"{self.BASE_URL}/repos/{owner}/{name}/git/ref/heads/{default_branch}"
        resp = requests.get(ref_url, headers=self._headers(), timeout=15)
        if resp.status_code != 200:
            self.logger.error(f"获取分支信息失败: {resp.text}")
            return None
        sha = resp.json()["object"]["sha"]

        # 创建新分支
        branch_name = f"bounty-hunter/fix-{int(time.time())}"
        create_url = f"{self.BASE_URL}/repos/{owner}/{name}/git/refs"
        data = {
            "ref": f"refs/heads/{branch_name}",
            "sha": sha,
        }
        resp = requests.post(create_url, headers=self._headers(), json=data, timeout=15)
        if resp.status_code in (201, 200):
            self.logger.info(f"  分支创建成功: {branch_name}")
            return branch_name
        else:
            self.logger.error(f"  分支创建失败: {resp.text}")
            return None

    def _submit_file(self, owner, name, branch, path, content, message):
        """提交单个文件"""
        url = f"{self.BASE_URL}/repos/{owner}/{name}/contents/{path}"
        data = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
            "branch": branch,
        }
        resp = requests.put(url, headers=self._headers(), json=data, timeout=15)
        return resp.status_code in (200, 201)

    def create_pr(self, repo, findings):
        """
        创建修复 PR
        返回 PR URL 或 None
        """
        if self.test_mode:
            pr_preview = {
                "repo": f"{repo['owner']}/{repo['name']}",
                "title": f"[Security Fix] {repo['name']}: {len(findings)} vulnerabilities",
                "findings_count": len(findings),
                "severities": list(set(f["severity"] for f in findings)),
                "note": "测试模式：未实际调用 GitHub API",
            }
            self.logger.info(f"  [MOCK PR] {json.dumps(pr_preview, ensure_ascii=False)}")
            return f"MOCK: {repo['owner']}/{repo['name']}"

        owner = repo["owner"]
        name = repo["name"]

        # 创建分支
        branch = self._create_branch(owner, name)
        if not branch:
            return None

        # 提交修复文件
        fix_content = build_pr_body(repo, findings)
        fix_path = f"security-fix-{int(time.time())}.md"

        success = self._submit_file(
            owner, name, branch,
            fix_path,
            fix_content,
            f"docs: add security vulnerability fix report ({len(findings)} issues)"
        )
        if not success:
            self.logger.error("  文件提交失败")
            return None

        # 创建 PR
        pr_url = f"{self.BASE_URL}/repos/{owner}/{name}/pulls"
        pr_data = {
            "title": f"[Security Fix] {name}: {len(findings)} vulnerabilities detected",
            "body": build_pr_body(repo, findings),
            "head": branch,
            "base": "main",
            "draft": True,  # 草稿 PR，需要你手动 publish
        }
        resp = requests.post(pr_url, headers=self._headers(), json=pr_data, timeout=15)

        if resp.status_code in (200, 201):
            pr = resp.json()
            pr_number = pr.get("number", "?")
            pr_html_url = pr.get("html_url", "")
            self.logger.info(f"  PR 创建成功: #{pr_number} {pr_html_url}")
            return pr_html_url
        else:
            self.logger.error(f"  PR 创建失败: {resp.status_code} {resp.text}")
            return None
