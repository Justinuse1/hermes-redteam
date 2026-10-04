"""红线闸（pre_tool_call）：把"口头规则"变成"真的拦得住"。

设计原则（踩过的坑都在这三条里）：
1. **默认闭嘴**：normal 模式只观察不拦（否则插件会挡住主业，比没有更糟）。
   redteam 模式才动手。毁灭性命令例外 —— 那是任何模式都拦的安全网。
2. **拦要给出路**：拦截信息里必须写清"为什么拦 + 怎么放行"，否则就是卡死自己。
   越界目标用 approve 升级给人拍板（"方向存疑先停后问"的机器版），不是硬拒。
3. **只卡确定的**：宁可漏放不可误杀。白名单（工具源/公共源）先过，
   只在命中"明确红线"时才拦：靶名/域名/凭证入库、越界目标、毁灭性命令。
"""

from __future__ import annotations

import re

# ---- 任何模式都拦：毁灭性命令（安全网，不是红队规则）----
FATAL_PATTERNS = [
    (r"rm\s+(-[a-zA-Z]*\s+)*-?[rf]{1,2}[a-zA-Z]*\s+/(\s|$|\*)", "删根目录"),
    (r"\bmkfs(\.\w+)?\b", "格式化文件系统"),
    (r"\bdd\b[^|;]*\bof=/dev/(sd|nvme|hd|vd)", "dd 覆盖裸设备"),
    (r":\(\)\s*\{\s*:\|:&\s*\}\s*;:", "fork 炸弹"),
    (r">\s*/dev/(sd|nvme|hd|vd)\w", "重定向覆盖裸设备"),
    (r"\bchmod\s+-R\s+777\s+/\s*$", "根目录全开权限"),
    (r"\bshutdown\b|\breboot\b|\bhalt\b", "关机/重启（需人工执行）"),
]

# ---- 凭证样式（用于"不入库"红线）----
SECRET_PATTERNS = [
    (r"\bsk-[A-Za-z0-9_-]{20,}", "OpenAI/兼容 key"),
    (r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b", "Telegram bot token"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS AK"),
    (r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}", "GitHub token"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "私钥"),
    (r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}", "JWT"),
]

# ---- 公共源/工具源白名单：这些域名不算"越界目标" ----
INFRA_ALLOW = [
    "github.com", "githubusercontent.com", "gitlab.com", "pypi.org", "files.pythonhosted.org",
    "npmjs.com", "registry.npmjs.org", "nodejs.org", "debian.org", "ubuntu.com", "archlinux.org",
    "api.telegram.org", "telegram.org", "openai.com", "anthropic.com", "deepseek.com",
    "bigmodel.cn", "zhipuai.cn", "aliyuncs.com", "cloudflare.com", "google.com",
    "golang.org", "go.dev", "rust-lang.org", "crates.io", "docker.com", "docker.io",
    "cloudflare-dns.com", "1.1.1.1", "8.8.8.8", "githubassets.com", "objects.githubusercontent.com",
    "shodan.io", "censys.io", "fofa.info", "quake.360.net", "hunter.how", "zoomeye.org",
    "exploit-db.com", "nvd.nist.gov", "cve.org", "mitre.org", "vulners.com",
]

HOST_RE = re.compile(
    r"""(?ix)
    \b(?:https?://)?                                  # scheme 可选
    (?P<host>
        (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+   # 域名
        (?:com|net|org|cn|io|ai|dev|app|xyz|top|site|info|biz|me|cc|tv|co|uk|de|jp|kr|hk|tw|ru|fr|nl|se|ch|it|es|br|in|id|th|vn|my|sg|ph|au|ca|us|edu|gov|mil|pro|online|shop|store|club|live|fun|space|website|tech|ltd|group|link|click|work|life|world|today|news|media|agency|solutions|services|network|systems|digital|zone|one|run|red|blue|gg|sh|st|ws)
        |\d{1,3}(?:\.\d{1,3}){3}                      # 或裸 IP
    )
    (?::\d{1,5})?                                     # 端口
    """)

# 哪些工具的参数算"会落库/会外发"
WRITEY_TOOLS = {"write_file", "patch", "terminal", "execute_code", "browser_exec", "browser_navigate"}
GIT_MUTATING = re.compile(r"\bgit\s+(push|commit|add|remote\s+add|tag)\b")


def hosts_in(text: str) -> list[str]:
    if not text:
        return []
    out = []
    for m in HOST_RE.finditer(text):
        h = m.group("host").lower().strip(".")
        if h and h not in out:
            out.append(h)
    return out


def secrets_in(text: str) -> list[str]:
    found = []
    for pat, label in SECRET_PATTERNS:
        if re.search(pat, text or ""):
            found.append(label)
    return found


def _norm(t: str) -> str:
    return (t or "").lower().strip().strip(".").split(":")[0]


def in_scope(host: str, scope_list: list[str]) -> bool:
    """目标命中判定：相等或子域命中。scope 里写 example.com 则 a.example.com 也算。"""
    h = _norm(host)
    if not h:
        return False
    for s in scope_list:
        s = _norm(s)
        if not s:
            continue
        if h == s or h.endswith("." + s) or (s.startswith("*.") and h.endswith(s[1:])):
            return True
        if h in s:  # scope 写了 URL/路径的情况
            return True
    return False


def is_infra(host: str) -> bool:
    h = _norm(host)
    return any(h == a or h.endswith("." + a) for a in INFRA_ALLOW)


def _short(text: str, n: int = 160) -> str:
    text = " ".join((text or "").split())
    return text[:n] + ("…" if len(text) > n else "")


def classify(tool_name: str, args: dict, st: dict, scope_list: list[str], cfg: dict) -> dict | None:
    """返回 None=放行；{action: block|approve, message: ...} = 拦或升级给人。"""
    try:
        blob = " ".join(str(v) for v in (args or {}).values())
    except Exception:
        blob = ""
    cfg = cfg or {}
    guard_on = bool(cfg.get("guard_enabled", True))
    redteam = st.get("mode") == "redteam"
    target = (st.get("target") or "").strip()

    # ---- 1) 安全网：毁灭性命令 ----
    # 2026-10-04：改为受 guard_enabled 控制（原先硬编码始终拦，与"执行层拦截可关"冲突）
    if guard_on and tool_name in ("terminal", "execute_code"):
        for pat, label in FATAL_PATTERNS:
            if re.search(pat, blob, re.I | re.M):
                return {"action": "block",
                        "message": (f"purge 安全网拦下：疑似「{label}」—— {_short(blob)}\n"
                                    "这类命令必须人工在服务器上确认后执行，agent 不许自己跑。"
                                    "确认无误要放行，就由管理员临时把 plugins.entries.purge.settings.guard_enabled 设为 false。")}

    # ---- 2) 凭证/靶名入库（任何模式，因为是"一次性造成永久损失"的那类）----
    if cfg.get("block_target_in_repo", True) and tool_name in WRITEY_TOOLS:
        hit_secrets = secrets_in(blob)
        touches_git = bool(GIT_MUTATING.search(blob)) or tool_name in ("write_file", "patch")
        names_hit = [t for t in ([target] + [s for s in scope_list if s]) if t and len(t) > 3
                     and re.search(re.escape(t), blob, re.I)]
        if hit_secrets and touches_git:
            return {"action": "block",
                    "message": (f"purge 红线拦下：参数里出现凭证（{', '.join(hit_secrets)}）且动作会落盘/推仓库。\n"
                                "红线：靶名/域名/凭证不入库。要写就先落到 $HERMES_HOME/.env（凭证）"
                                "或本地不留痕的临时文件，或在提交前跑 purge 的入库前扫描。")}
        if touch_git_push := bool(re.search(r"\bgit\s+push\b", blob)):
            if names_hit:
                return {"action": "block",
                        "message": (f"purge 红线拦下：这条 git push 的命令行里带着目标标识（{', '.join(names_hit[:3])}）。\n"
                                    "把目标名写进 push 命令本身就等于写进日志/历史。改成不带目标的命令，"
                                    "或者先 purge scan 扫一遍再决定。")}

    # ---- 3) 越界目标（只在 redteam 模式 + 有 scope 时）----
    if redteam and guard_on and scope_list:
        hosts = [h for h in hosts_in(blob) if not is_infra(h)]
        out_of_scope = [h for h in hosts if not in_scope(h, scope_list)]
        if out_of_scope:
            return {"action": "approve",
                    "message": (f"purge 越界提醒：动作里有 {len(out_of_scope)} 个不在目标清单里的主机 "
                                f"（{', '.join(out_of_scope[:5])}）。\n"
                                f"当前目标={target or '-'}；清单={', '.join(scope_list[:8])}\n"
                                "要放行就把目标加进清单（purge target <目标> / purge_objective），不打就换掉。"
                                "方向存疑先停后问；拿不准就问人，不要自己扩大范围。")}
    return None
