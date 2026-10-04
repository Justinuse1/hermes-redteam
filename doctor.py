"""purge 自检（doctor）：一眼看清"能力层到底有没有生效"。

这个模块的存在理由：本机踩过的真实坑 —— 文件落位 ≠ 运行时生效。
- 加强层写进 SOUL.md 了，但旧会话的系统提示是会话建立时冻结的 → 那条会话里没有层；
- 技能目录有 58 个 SKILL.md，但没被加载/没进提示 → 模型看不见；
- 工具箱有软链，但二进制不响应 → 跑起来才发现。

所以 doctor 一律先查"运行时证据"（state.db 里的真实系统提示、真实二进制），
再查文件是否存在。只看文件必瞎。
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

from .state import hermes_home, load, scope

# 红队工具箱：移植时约定的必备件
TOOLKIT = [
    "fscan", "gogo", "chisel", "frp", "ligolo",
    "httpx", "subfinder", "dnsx", "naabu", "ksubdomain", "oneforall",
    "suo5", "gowitness", "nuclei", "feroxbuster", "ffuf", "gobuster",
    "nmap", "masscan", "sqlmap", "nikto", "searchsploit", "amass",
]

RECENT_SESSIONS = 8


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    try:
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return "-"


def _marker_key(marker: str) -> str:
    """用 marker 的版本串前缀做宽匹配：'REDTEAM-ENHANCE-LAYER v1' → 'REDTEAM-ENHANCE'。

    宽匹配的理由：注入路径可能改写空白/换行，卡整串会误报成"没注入"。
    """
    return (marker or "REDTEAM-ENHANCE").split(" v")[0].split()[0][:24]


def check_layer(marker: str) -> dict:
    out = {"marker": marker, "skipped": not marker, "exists": False, "bytes": 0,
           "sha256": "-", "marker_present": False, "sections": 0}
    if not marker:
        return out
    soul = hermes_home() / "SOUL.md"
    out["path"] = str(soul)
    out["exists"] = soul.is_file()
    if not out["exists"]:
        return out
    try:
        text = soul.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        out["error"] = str(e)
        return out
    out["bytes"] = len(text.encode("utf-8"))
    out["sha256"] = _sha256(soul)
    out["marker_present"] = _marker_key(marker) in text
    out["sections"] = sum(1 for ln in text.splitlines() if ln.startswith("## "))
    return out


def check_skills() -> dict:
    d = hermes_home() / "skills"
    out = {"dir": str(d), "count": 0, "no_frontmatter": [], "sample": []}
    if not d.is_dir():
        return out
    for skill_md in d.rglob("SKILL.md"):
        out["count"] += 1
        try:
            head = skill_md.read_text(encoding="utf-8", errors="replace")[:400]
        except Exception:
            out["no_frontmatter"].append(skill_md.parent.name)
            continue
        if not head.lstrip().startswith("---"):
            out["no_frontmatter"].append(skill_md.parent.name)
        if len(out["sample"]) < 5:
            out["sample"].append(skill_md.parent.name)
    return out


# 技能正文里"必须有"的环境变量：技能能列出来 ≠ 能跑（缺 key 要等动手才发现）
_ENV_PATTERNS = (
    r"os\.environ\[\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']\s*\]",
    r"process\.env\.([A-Z][A-Z0-9_]{2,})",
    r"process\.env\[\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']\s*\]",
    r"\$\{([A-Z][A-Z0-9_]{2,})\}",
)
# 平台自带/无关痛痒的变量，缺了不算技能不可用
_ENV_IGNORE = {
    "PATH", "HOME", "USER", "SHELL", "PWD", "TERM", "LANG", "TZ", "TMPDIR", "TEMP", "TMP",
    "HERMES_HOME", "HOSTNAME", "OS", "COMSPEC", "APPDATA", "LOCALAPPDATA",
    "PYTHONPATH", "VIRTUAL_ENV", "NODE_ENV", "CI", "DEBUG", "HTTP_PROXY", "HTTPS_PROXY",
    # shell 内建/临时变量：技能正文里出现 ${IFS} 这类不算"要凭证"
    "IFS", "RANDOM", "LINENO", "SECONDS", "OPTARG", "OPTIND", "PIPESTATUS",
    "BASH_SOURCE", "FUNCNAME", "PS1", "PS2", "PS3", "PS4",
}


def _env_file_keys() -> set:
    keys = set()
    for p in (hermes_home() / ".env", hermes_home() / ".credentials.yaml"):
        try:
            if not p.is_file():
                continue
            for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]", ln)
                if m:
                    keys.add(m.group(1))
        except Exception:
            pass
    return keys


def check_skill_env() -> dict:
    """技能可用性：正文里点名的必需环境变量，本机有没有。

    判定口径：
      · `os.environ["X"]` / `process.env.X` / `process.env["X"]` / `${X}` = 必需；
      · `os.environ.get("X", 默认值)` = 不算必需（有默认值）；
      · 变量在环境里、或在 $HERMES_HOME/.env / .credentials.yaml 里写过 = 就位。
    """
    d = hermes_home() / "skills"
    out = {"checked": 0, "unavailable": [], "env_keys_seen": 0}
    if not d.is_dir():
        return out
    have = set(os.environ.keys()) | _env_file_keys()
    out["env_keys_seen"] = len(have)
    for skill_md in sorted(d.rglob("SKILL.md")):
        try:
            text = skill_md.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        out["checked"] += 1
        needs = set()
        for pat in _ENV_PATTERNS:
            for m in re.finditer(pat, text):
                name = m.group(1)
                if name not in _ENV_IGNORE:
                    needs.add(name)
        missing = sorted(n for n in needs if n not in have)
        if missing:
            out["unavailable"].append({"skill": skill_md.parent.name, "missing_env": missing})
    return out


# 工具名 → 可执行文件名（同一个工具常拆成多支）；找不到 PATH 再扫这些目录
TOOLKIT_ALIASES = {
    "frp": ("frpc", "frps"),
    "ligolo": ("ligolo-proxy", "ligolo-agent"),
    "oneforall": ("oneforall", "OneForAll"),
}
_TOOL_DIRS = ("/usr/local/bin", "/usr/bin", "/opt/OneForAll",
              "/opt/redteam-toolkit", os.path.expanduser("~/.purge/toolkit"))


def _find_tool(name: str) -> str:
    for cand in TOOLKIT_ALIASES.get(name, (name,)):
        p = shutil.which(cand)
        if p:
            return p
        for d in _TOOL_DIRS:
            f = os.path.join(d, cand)
            if os.path.isfile(f):
                return f
            # 上游工具集是 <toolkit>/<工具名>/<二进制> 一层子目录结构，
            # 只扫平铺目录会漏掉全部工具（曾误报 0/23）
            for hit in sorted(glob.glob(os.path.join(d, "*", cand))):
                if os.path.isfile(hit):
                    return hit
    return ""


def check_toolkit() -> dict:
    found, missing = {}, []
    for t in TOOLKIT:
        p = _find_tool(t)
        if p:
            found[t] = p
        else:
            missing.append(t)
    return {"found": found, "missing": missing, "ok": len(found), "total": len(TOOLKIT)}


def check_roles() -> dict:
    """角色体系完整性：六角色稿在不在、每份多长。"""
    out = {"count": 0, "expected": 0, "missing": [], "bytes": {}, "custom": 0, "ok": False}
    try:
        from . import roles as R
    except Exception as e:
        out["error"] = str(e)
        return out
    order = list(getattr(R, "ROLE_ORDER", []) or [])
    tbl = getattr(R, "ROLES", {}) or {}
    out["expected"] = len(order) or 6
    for k in order:
        txt = ""
        try:
            if hasattr(R, "role_prompt"):
                txt = R.role_prompt(k) or ""
        except Exception:
            txt = ""
        if not txt and isinstance(tbl.get(k), str):
            txt = tbl[k]
        if not txt and isinstance(tbl.get(k), dict):
            txt = tbl[k].get("body") or tbl[k].get("prompt") or ""
        if txt:
            out["count"] += 1
            out["bytes"][k] = len(txt)
            try:
                if hasattr(R, "role_is_custom") and R.role_is_custom(k):
                    out["custom"] += 1
            except Exception:
                pass
        else:
            out["missing"].append(k)
    out["ok"] = (not out["missing"]) and out["count"] >= 6
    return out


def check_redteam_skills() -> dict:
    """可选技能库（插件自带 skills/redteam）。目录不存在 = 未启用，不算问题。"""
    d = Path(__file__).resolve().parent / "skills" / "redteam"
    out = {"dir": str(d), "count": 0, "empty": [], "enabled": d.is_dir(), "ok": True}
    if not d.is_dir():
        return out
    for f in sorted(d.glob("*.md")):
        out["count"] += 1
        try:
            if f.stat().st_size < 50:
                out["empty"].append(f.name)
        except Exception:
            pass
    out["ok"] = out["count"] > 0 and not out["empty"]
    return out


def check_score_table() -> dict:
    """计分表版本：条数 / 分组分布 / 指纹 / 满分。"""
    out = {"count": 0, "groups": {}, "fingerprint": "-", "total_possible": 0.0, "ok": False}
    try:
        from . import state as S
    except Exception as e:
        out["error"] = str(e)
        return out
    pts = list(getattr(S, "SCORE_POINTS", []) or [])
    out["count"] = len(pts)
    g = {}
    for p in pts:
        k = (p or {}).get("group") or "?"
        g[k] = g.get(k, 0) + 1
    out["groups"] = g
    codes = sorted(str((p or {}).get("code") or "") for p in pts)
    out["fingerprint"] = hashlib.sha256("|".join(codes).encode("utf-8")).hexdigest()[:12]
    try:
        out["total_possible"] = round(sum(float((p or {}).get("default") or 0) for p in pts), 2)
    except Exception:
        pass
    out["ok"] = out["count"] >= 25
    return out


def check_gateway() -> dict:
    out = {"service_active": None, "log": str(hermes_home() / "logs" / "gateway.log"),
           "log_bytes": 0, "log_age_s": None, "telegram_lines": 0}
    try:
        r = subprocess.run(["systemctl", "is-active", "hermes-gateway"],
                           capture_output=True, text=True, timeout=6)
        out["service_active"] = (r.stdout or "").strip() or "unknown"
    except Exception:
        pass  # Windows/无 systemd：跳过不算失败
    log = hermes_home() / "logs" / "gateway.log"
    if log.is_file():
        st = log.stat()
        out["log_bytes"] = st.st_size
        out["log_age_s"] = int(time.time() - st.st_mtime)
        try:
            tail = log.read_text(encoding="utf-8", errors="replace")[-200_000:]
            out["telegram_lines"] = sum(1 for ln in tail.splitlines() if "Telegram" in ln)
        except Exception:
            pass
    return out


def check_sessions(marker: str, limit: int = RECENT_SESSIONS) -> dict:
    """运行时证据：最近几条会话的真实系统提示里，到底有没有加强层。"""
    db = hermes_home() / "state.db"
    out = {"db": str(db), "exists": db.is_file(), "sessions": [],
           "stale": [], "marker_key": _marker_key(marker)}
    if not out["exists"]:
        return out
    key = out["marker_key"]
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        rows = list(con.execute(
            """select s.id, s.source, s.started_at, s.message_count, s.system_prompt_hash,
                      s.ended_at, p.prompt
               from sessions s
               left join system_prompts p on p.hash = s.system_prompt_hash
               order by s.started_at desc limit ?""", (limit,)))
        con.close()
    except Exception as e:
        out["error"] = str(e)
        return out
    for sid, src, started, mc, _h, ended, prompt in rows:
        prompt = prompt or ""
        has = key in prompt
        row = {
            "id": sid, "source": src, "message_count": mc or 0,
            "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)) if started else "-",
            "ended": bool(ended), "prompt_chars": len(prompt), "has_layer": has,
        }
        if not has and not ended:
            row["verdict"] = "这条活会话没有加强层 → 让它 /new（会话提示建立时冻结，永不中途更新）"
            out["stale"].append(sid)
        elif not has:
            row["verdict"] = "历史会话，无层（正常，已结束）"
        out["sessions"].append(row)
    return out


def run(ctx, cfg: dict | None = None) -> dict:
    cfg = cfg or {}
    marker = cfg.get("layer_marker") or ""
    st = load(ctx)
    from .state import ledger_summary
    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hermes_home": str(hermes_home()),
        "mode": st.get("mode"),
        "target": st.get("target") or "-",
        "engagement": st.get("engagement") or "-",
        "scope": scope(ctx, cfg.get("scope_file") or ""),
        "layer": check_layer(marker),
        "skills": check_skills(),
        "skill_env": check_skill_env(),
        "toolkit": check_toolkit(),
        "gateway": check_gateway(),
        "sessions": check_sessions(marker),
        "roles": check_roles(),
        "redteam_skills": check_redteam_skills(),
        "score_table": check_score_table(),
        "ledger": ledger_summary(),
        "history_tail": (st.get("history") or [])[-5:],
    }
    problems = []
    if marker and not result["layer"]["marker_present"]:
        problems.append("SOUL.md 里没有加强层版本串 —— 层没落地或被人改了")
    if result["skills"]["count"] == 0:
        # 注：$HERMES_HOME/skills 是宿主自己的技能库，空着不是插件的问题。
        pass
    if result["skills"]["no_frontmatter"]:
        problems.append(f"{len(result['skills']['no_frontmatter'])} 个技能缺 frontmatter，Hermes 不会加载")
    una = result["skill_env"]["unavailable"]
    if una:
        detail = "; ".join(f"{u['skill']}(缺 {','.join(u['missing_env'])})" for u in una[:3])
        problems.append(f"{len(una)} 条技能缺必需环境变量，跑起来会失败: {detail}")
    # 工具箱缺件只在 render 里列清单，不判故障 —— 纯台账用途不需要这些工具
    _ = result["toolkit"]["missing"]
    if result["sessions"]["stale"]:
        problems.append(f"{len(result['sessions']['stale'])} 条活会话的系统提示里没有层 → 让对方 /new")
    R, RS, SC = result["roles"], result["redteam_skills"], result["score_table"]
    if not R.get("ok"):
        problems.append("角色体系不完整：%d/%d 就位%s" % (
            R.get("count", 0), R.get("expected", 6),
            ("，缺 " + ",".join(R.get("missing") or [])) if R.get("missing") else ""))
    if not RS.get("ok"):
        problems.append("红队技能库异常：%d 个（空 %d）" % (RS.get("count", 0), len(RS.get("empty") or [])))
    if not SC.get("ok"):
        problems.append("计分表异常：%d 条（应 >=25）" % SC.get("count", 0))
    if st.get("mode") == "redteam" and not st.get("target"):
        problems.append("redteam 模式开着但没有目标 —— 先 purge target")
    result["problems"] = problems
    result["ok"] = not problems
    return result


def render(res: dict) -> str:
    L, S, T, G, SE = res["layer"], res["skills"], res["toolkit"], res["gateway"], res["sessions"]
    lines = []
    lines.append(f"purge 自检 @ {res['ts']}   模式={res['mode']}  目标={res['target']}")
    lines.append(f"HOME {res['hermes_home']}")
    lines.append("")
    if L.get("skipped"):
        lines.append("[加强层]   未配 marker（不检查 SOUL）")
    else:
        lines.append(f"[加强层] SOUL.md {L['bytes']}B sha={L['sha256']} 版本串={'在' if L['marker_present'] else '不在'} 章节={L['sections']}")
    lines.append(f"[技能]   {S['count']} 条  frontmatter 缺失={len(S['no_frontmatter'])}")
    SEV = res.get("skill_env") or {"checked": 0, "unavailable": []}
    una = SEV.get("unavailable") or []
    una_txt = ""
    if una:
        una_txt = "  缺 key: " + ", ".join(f"{u['skill']}→{','.join(u['missing_env'])}" for u in una[:4])
    lines.append(f"[技能可用] 查 {SEV.get('checked', 0)} 条 · 不可用 {len(una)} 条{una_txt}")
    LG = res.get("ledger") or {"count": 0, "score": 0}
    lines.append(f"[战果账本] {LG.get('count', 0)} 条 · 计分 {LG.get('score', 0)} · 本次 engagement={res.get('engagement', '-')}")
    lines.append(f"[工具箱] {T['ok']}/{T['total']} 就位" + (f"  缺: {', '.join(T['missing'])}" if T["missing"] else ""))
    RL = res.get("roles") or {}
    lines.append("[角色体系] %d/%d 骨架就位 · 已自填 %d" % (
        RL.get("count", 0), RL.get("expected", 6), RL.get("custom", 0)))

    if RL.get("custom", 0) == 0:
        lines.append("           角色提示词还没填 —— 去 roles.d/ 写 <role>.md（见 roles.d/README.md）")
    RSD = res.get("redteam_skills") or {}
    if RSD.get("enabled"):
        lines.append("[技能库]   %d 个%s" % (RSD.get("count", 0),
                                         ("  空: " + ",".join(RSD.get("empty") or [])) if RSD.get("empty") else ""))
    else:
        lines.append("[技能库]   未启用（skills/redteam 不存在，属正常）")
    SCT = res.get("score_table") or {}
    gtxt = " ".join("%s=%s" % (k, v) for k, v in sorted((SCT.get("groups") or {}).items()))
    lines.append("[计分表]   %d 条 fp=%s 满分=%s  %s" % (SCT.get("count", 0), SCT.get("fingerprint", "-"),
                                                     SCT.get("total_possible", 0), gtxt))
    ga = G.get("service_active")
    lines.append(f"[网关]   systemd={ga if ga else '-'}  日志={G['log_bytes']}B  最后写入={G['log_age_s']}s 前  Telegram 行={G['telegram_lines']}")
    lines.append("")
    lines.append(f"[会话提示完整性] 最近 {len(SE['sessions'])} 条（运行时证据：这条会话的模型到底看没看到层）")
    for s in SE["sessions"]:
        flag = "有层" if s["has_layer"] else "无层"
        lines.append(f"  {s['started']}  {s['source']:<9} {s['id']}  消息{s['message_count']:<4} 提示{s['prompt_chars']:<6} {flag}")
        if s.get("verdict"):
            lines.append(f"      → {s['verdict']}")
    lines.append("")
    if res["problems"]:
        lines.append("问题：")
        lines += [f"  ✗ {p}" for p in res["problems"]]
    else:
        lines.append("无阻断性问题。工具箱清单见上，按需安装。")
    return "\n".join(lines)


def to_json(res: dict) -> str:
    return json.dumps(res, ensure_ascii=False, indent=2)
