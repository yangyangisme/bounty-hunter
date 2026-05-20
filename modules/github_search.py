"""
GitHub 搜索模块
通过 GitHub API 搜索有安全策略（SECURITY.md / VULNERABILITY.md）的开源项目
测试模式：返回模拟数据
"""

import requests
import time
import random


# ==================== 模拟数据（测试模式）====================
MOCK_REPOS = [
    {
        "owner": "example",
        "name": "flask-api",
        "language": "Python",
        "stars": 1200,
        "description": "A lightweight Flask REST API boilerplate",
        "has_security_md": True,
        "file_patterns": ["app.py", "utils/auth.py", "models/user.py"],
    },
    {
        "owner": "community",
        "name": "express-blog",
        "language": "JavaScript",
        "stars": 580,
        "description": "A simple blog engine built with Express.js",
        "has_security_md": True,
        "file_patterns": ["server.js", "routes/auth.js", "db/query.js"],
    },
    {
        "owner": "devteam",
        "name": "py-crawler",
        "language": "Python",
        "stars": 320,
        "description": "Web crawler with async support",
        "has_security_md": False,
        "file_patterns": ["crawler.py", "fetcher.py"],
    },
    {
        "owner": "startup",
        "name": "react-dashboard",
        "language": "JavaScript",
        "stars": 890,
        "description": "React admin dashboard template",
        "has_security_md": True,
        "file_patterns": ["src/api/client.js", "src/utils/format.js"],
    },
    {
        "owner": "oss",
        "name": "node-upload",
        "language": "JavaScript",
        "stars": 210,
        "description": "File upload microservice",
        "has_security_md": True,
        "file_patterns": ["server.js", "middleware/upload.js"],
    },
]

# 模拟漏洞代码片段
MOCK_CODE_SNIPPETS = {
    "flask-api": {
        "app.py": '''from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    # SQL Injection vulnerability
    results = db.execute(f"SELECT * FROM posts WHERE title LIKE \'%{query}%\'")
    return jsonify(results)
''',
        "utils/auth.py": '''import secrets
API_KEY = "sk-1234567890abcdef"  # Hardcoded secret

def verify_token(token):
    # Insecure random - should use secrets module
    return token == str(random.randint(100000, 999999))
''',
        "models/user.py": '''def get_user_html(name):
    return f"<h1>Welcome {name}</h1>"  # XSS vulnerability
''',
    },
    "express-blog": {
        "server.js": '''const express = require("express");
const { exec } = require("child_process");

app.get("/ping", (req, res) => {
    // Command injection
    exec("ping " + req.query.host, (err, stdout) => {
        res.send(stdout);
    });
});
''',
        "routes/auth.js": '''router.post("/login", (req, res) => {
    const sql = `SELECT * FROM users WHERE name='${req.body.name}' AND pass='${req.body.pass}'`;
    db.query(sql);  // SQL injection
});
''',
    },
    "py-crawler": {
        "crawler.py": '''import os
def read_file(path):
    # Path traversal
    with open("data/" + path, "r") as f:
        return f.read()
''',
    },
    "react-dashboard": {
        "src/api/client.js": '''const API_KEY = "pk_test_51abc123xyz";  // hardcoded secret
const API_URL = "http://api.internal.corp/";  // hardcoded internal URL

fetch(API_URL + "/user/" + userId)
  .then(r => r.json())
  .then(d => document.getElementById("app").innerHTML = d.name);  // XSS
''',
    },
    "node-upload": {
        "server.js": '''app.get("/download", (req, res) => {
    // Path traversal vulnerability
    res.sendFile(__dirname + "/uploads/" + req.query.file);
});
''',
        "middleware/upload.js": '''app.post("/upload", (req, res) => {
    const filename = req.files[0].name;
    // No sanitization - possible path traversal
    fs.writeFileSync("/uploads/" + filename, data);
});
''',
    },
}


class GitHubSearch:
    """GitHub 项目搜索器"""

    BASE_URL = "https://api.github.com"

    def __init__(self, config, logger, test_mode=False):
        self.config = config
        self.logger = logger
        self.test_mode = test_mode
        self.token = config.get("github", {}).get("token", "")
        self.languages = config.get("github", {}).get("languages", ["Python", "JavaScript"])
        self.keywords = config.get("github", {}).get("search_keywords", ["SECURITY.md"])

    def _headers(self):
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "BountyHunter/1.0",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    def _rate_limit_check(self):
        """检查 GitHub API 速率限制"""
        if not self.token:
            return {"remaining": 10}  # 未认证每小时60次
        try:
            resp = requests.get(f"{self.BASE_URL}/rate_limit", headers=self._headers(), timeout=10)
            data = resp.json()
            return data.get("resources", {}).get("search", {}).get("remaining", 0)
        except Exception as e:
            self.logger.warning(f"无法检查速率限制: {e}")
            return 0

    def _search_repos(self, keyword, language, per_page=30):
        """搜索包含特定文件的仓库"""
        # GitHub Search API query 格式：
        # keyword language:Python stars:>100
        # 注意：stars:>100 不能用 + 连接，会被 URL 编码破坏
        query = f'{keyword} language:{language}'
        url = f"{self.BASE_URL}/search/repositories"
        params = {"q": query, "sort": "stars", "order": "desc", "per_page": per_page}
        try:
            resp = requests.get(url, headers=self._headers(), params=params, timeout=15)
            if resp.status_code == 403:
                self.logger.warning("GitHub API 速率限制已达，请稍后再试")
                return []
            if resp.status_code != 200:
                self.logger.warning(f"GitHub API 错误: {resp.status_code} {resp.text}")
                return []
            data = resp.json()
            return data.get("items", [])
        except Exception as e:
            self.logger.error(f"搜索 API 请求失败: {e}")
            return []

    def _get_repo_contents(self, owner, name, path=""):
        """获取仓库中的文件列表"""
        url = f"{self.BASE_URL}/repos/{owner}/{name}/contents/{path}"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=15)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception:
            return []

    def _get_file_content(self, owner, name, path):
        """获取单个文件内容"""
        url = f"{self.BASE_URL}/repos/{owner}/{name}/contents/{path}"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=15)
            if resp.status_code == 200:
                import base64
                data = resp.json()
                content = data.get("content", "")
                if data.get("encoding") == "base64":
                    return base64.b64decode(content).decode("utf-8", errors="ignore")
                return content
            return ""
        except Exception:
            return ""

    def _get_code_files(self, owner, name, extension):
        """获取仓库中特定扩展名的代码文件（使用 Git Trees API，性能更好）"""
        # 先获取仓库默认分支
        try:
            repo_url = f"{self.BASE_URL}/repos/{owner}/{name}"
            resp = requests.get(repo_url, headers=self._headers(), timeout=15)
            if resp.status_code != 200:
                return []
            default_branch = resp.json().get("default_branch", "main")
        except Exception:
            default_branch = "main"

        # 用 Git Trees API 获取所有文件（recursive=1）
        try:
            tree_url = f"{self.BASE_URL}/repos/{owner}/{name}/git/trees/{default_branch}"
            resp = requests.get(tree_url, headers=self._headers(), params={"recursive": "1"}, timeout=30)
            if resp.status_code != 200:
                # 降级：尝试 contents API
                return self._get_code_files_via_contents(owner, name, extension)
            data = resp.json()
            tree = data.get("tree", [])

            # 按语言过滤扩展名
            ext_map = {"Python": [".py"], "JavaScript": [".js", ".jsx"], "TypeScript": [".ts", ".tsx"]}
            allowed_exts = ext_map.get(extension, [f".{extension.lower()}"])

            code_files = []
            for item in tree:
                if item.get("type") == "blob":
                    path = item.get("path", "")
                    # 跳过 test/、docs/、node_modules/ 等
                    if any(skip in path for skip in ["test/", "docs/", "node_modules/", "__pycache__/", ".git/"]):
                        continue
                    if any(path.endswith(ext) for ext in allowed_exts):
                        code_files.append(path)

            return code_files[:20]  # 最多20个文件
        except requests.exceptions.Timeout:
            self.logger.warning(f"  Trees API 超时，跳过 {owner}/{name}")
            return self._get_code_files_via_contents(owner, name, extension)
        except Exception as e:
            self.logger.warning(f"  Trees API 失败: {e}，降级到 Contents API")
            return self._get_code_files_via_contents(owner, name, extension)

    def _get_code_files_via_contents(self, owner, name, extension):
        """降级方案：递归获取仓库文件"""
        ext_map = {"Python": [".py"], "JavaScript": [".js", ".jsx"], "TypeScript": [".ts", ".tsx"]}
        allowed_exts = ext_map.get(extension, [f".{extension.lower()}"])
        result = []

        def scan_dir(path=""):
            try:
                url = f"{self.BASE_URL}/repos/{owner}/{name}/contents/{path}"
                resp = requests.get(url, headers=self._headers(), timeout=15)
                if resp.status_code != 200:
                    return
                items = resp.json()
                if not isinstance(items, list):
                    return
                for item in items:
                    if item.get("type") == "dir":
                        p = item.get("path", "")
                        if not any(s in p for s in ["test/", "docs/", "node_modules/", "__pycache__/"]):
                            scan_dir(p)
                    elif item.get("type") == "file":
                        path = item.get("path", "")
                        if any(path.endswith(ext) for ext in allowed_exts):
                            result.append(path)
            except Exception:
                pass

        scan_dir()
        return result[:20]

    def find_bounty_projects(self):
        """查找有安全策略的目标项目"""
        if self.test_mode:
            self.logger.info("  [MOCK] 返回 5 个模拟项目")
            return MOCK_REPOS

        all_repos = []
        seen = set()

        for keyword in self.keywords:
            for lang in self.languages:
                self.logger.info(f"  搜索: {keyword} + {lang}")
                repos = self._search_repos(keyword, lang, per_page=10)
                for repo in repos:
                    repo_id = f"{repo['owner']['login']}/{repo['name']}"
                    if repo_id not in seen:
                        seen.add(repo_id)
                        all_repos.append({
                            "owner": repo["owner"]["login"],
                            "name": repo["name"],
                            "language": repo.get("language", ""),
                            "stars": repo.get("stargazers_count", 0),
                            "description": repo.get("description", ""),
                            "has_security_md": True,
                            "file_patterns": [],
                        })
                time.sleep(2)  # 避免超速

        self.logger.info(f"  共找到 {len(all_repos)} 个候选仓库")
        return all_repos

    def get_repo_code_files(self, owner, name, language):
        """获取仓库的代码文件列表"""
        if self.test_mode:
            for mock in MOCK_REPOS:
                if mock["owner"] == owner and mock["name"] == name:
                    return mock.get("file_patterns", [])
            return []

        ext_map = {
            "Python": "Python",
            "JavaScript": "JavaScript",
            "TypeScript": "TypeScript",
        }
        ext = ext_map.get(language, language)
        files = self._get_code_files(owner, name, ext)

        # 过滤出有意义的代码文件
        code_files = [f for f in files if not f.startswith("test") and not f.startswith("docs")]
        return code_files[:20]  # 最多20个文件

    def get_file_content(self, owner, name, path):
        """获取文件内容（使用 Git Blobs API）"""
        if self.test_mode:
            key = name
            if key in MOCK_CODE_SNIPPETS and path in MOCK_CODE_SNIPPETS[key]:
                return MOCK_CODE_SNIPPETS[key][path]
            return ""

        try:
            url = f"{self.BASE_URL}/repos/{owner}/{name}/contents/{path}"
            resp = requests.get(url, headers=self._headers(), timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("content", "")
                if data.get("encoding") == "base64":
                    import base64
                    return base64.b64decode(content).decode("utf-8", errors="ignore")
                return content
            return ""
        except Exception:
            return ""
