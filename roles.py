# -*- coding: utf-8 -*-
"""角色体系（框架版）。

六个角色 = 主会话（指挥）+ 五个执行角色。角色 code 同时是提示词文件名与账本里的角色取值。

**提示词正文请自行填写**：把每个角色的提示词写到 ``roles.d/<code>.md``，
插件每次取稿时读取该文件。本仓库**不带任何角色提示词正文** —— 那是你的战术资产。

    roles.d/plan.md        主会话（指挥）
    roles.d/recon.md       信息收集
    roles.d/assess.md      资产梳理
    roles.d/vuln-scan.md   漏洞发现
    roles.d/exploit.md     漏洞利用
    roles.d/internal.md    内网渗透

写好后调 ``purge_role_prompt("recon")`` 即取到全文；文件缺失时返回占位模板。
"""
from pathlib import Path

PLANNER_ROLE = "plan"

ROLE_ORDER = ["plan", "recon", "assess", "vuln-scan", "exploit", "internal"]

ROLE_TITLES = {
    "plan": "主会话（指挥）",
    "recon": "信息收集",
    "assess": "资产梳理",
    "vuln-scan": "漏洞发现",
    "exploit": "漏洞利用",
    "internal": "内网渗透",
}

# 角色↔工具映射：上游工具名 → 本插件工具名。改这里的名字即可对接你自己的工具集。
TOOL_MAP = {
    "preflight": "purge_preflight",
    "record": "purge_record",
    "status": "purge_status",
    "roles": "purge_roles",
    "role_prompt": "purge_role_prompt",
    "objective": "purge_objective",
    "asset_add/query/get/test/assess/stats": "purge_asset_*",
    "vuln_add/query/update": "purge_vuln_*",
    "credential_add/list": "purge_credential_*",
    "webshell_add/list/update": "purge_webshell_*",
    "tunnel_add/list/update": "purge_tunnel_*",
    "chain_add/attack_chain/attack_path": "purge_chain / purge_attack_chain / purge_attack_path",
    "score_hit/score_list": "purge_score_hit / purge_score_list",
    "poc_add/search/get/use": "purge_poc_*",
    "http_evidence_add": "purge_http_evidence_add",
    "attack_file_add/list": "purge_attack_file_*",
    "report/report_targets": "purge_report / purge_report_targets",
    "attack_chain/attack_path": "purge_attack_chain / purge_attack_path",
}

# 角色提示词目录
ROLES_DIR = Path(__file__).resolve().parent / "roles.d"

_PLACEHOLDER = """# {title}

> **这个角色的提示词还没写。**
> 把你的 `{role}` 角色提示词写到 `roles.d/{role}.md`（UTF-8），
> 存盘后调 `purge_role_prompt("{role}")` 即可取到全文。

## 建议包含

- **你是谁 / 边界** —— 负责什么、不碰什么、什么时候停手问人。
- **开工动作** —— 先查哪个台账、先跑哪条命令、上一个角色该交接什么给你。
- **产出要求** —— 结果落到哪个台账（asset / vuln / credential / …）、报告要写哪些字段。
- **交接** —— 什么条件下交给下一个角色，交什么。
"""


def _load_role(role: str) -> str:
    """从 roles.d/<role>.md 读；缺失或空则返回占位模板。"""
    p = ROLES_DIR / ("%s.md" % role)
    if p.is_file():
        try:
            txt = p.read_text(encoding="utf-8").strip()
            if txt:
                return txt
        except Exception:
            pass
    return _PLACEHOLDER.format(role=role, title=ROLE_TITLES.get(role, role))


# 启动时加载一次；改 roles.d/*.md 后重启网关（或调 purge_role_prompt_reset）刷新。
ROLES = {r: _load_role(r) for r in ROLE_ORDER}


def role_is_custom(role: str) -> bool:
    """该角色是否已填入自己的提示词（false = 还在用占位模板）。"""
    return (ROLES_DIR / ("%s.md" % role)).is_file() and bool(ROLES.get(role, "").strip()) \
        and not ROLES.get(role, "").startswith("# " + ROLE_TITLES.get(role, role) + "\n\n> **这个角色")


def role_reload():
    """重新从 roles.d/ 加载全部角色稿。"""
    global ROLES
    ROLES = {r: _load_role(r) for r in ROLE_ORDER}
    return {r: len(ROLES[r]) for r in ROLE_ORDER}


def role_list():
    """六角色清单：[{role, title, planner, dispatcher, chars, custom}]。"""
    out = []
    for r in ROLE_ORDER:
        out.append({
            "role": r,
            "title": ROLE_TITLES[r],
            "planner": r == PLANNER_ROLE,
            "dispatcher": r != PLANNER_ROLE,
            "chars": len(ROLES[r]),
            "custom": role_is_custom(r),
        })
    return out


def role_prompt(role):
    """取角色稿全文；role 支持 code 与中文名。"""
    if role in ROLES:
        return ROLES[role]
    for r, t in ROLE_TITLES.items():
        if role == t or role in t:
            return ROLES[r]
    return None


def role_of(text):
    """把 code 或中文名（或含中文名的串）归一化成 code；认不出返回 None。"""
    if not text:
        return None
    s = str(text).strip()
    if s in ROLES:
        return s
    for r, t in ROLE_TITLES.items():
        if s == t or t in s or r in s:
            return r
    return None


def commander_brief():
    """指挥官开工简报：红队模式下 purge_objective / purge_mode 直接贴给用户与模型。"""
    lines = []
    lines.append("## 角色体系（%d 个角色）" % len(ROLE_ORDER))
    lines.append("你是 **%s（%s）**：做计划、派活、核对落库、向用户汇报。" % (PLANNER_ROLE, ROLE_TITLES[PLANNER_ROLE]))
    lines.append("")
    lines.append("| 角色 | 职责 | 取稿 |")
    lines.append("|---|---|---|")
    for r in ROLE_ORDER:
        tag = "（你）" if r == PLANNER_ROLE else ""
        mark = "" if role_is_custom(r) else " ⚠未填"
        lines.append("| `%s`%s | %s%s | `purge_role_prompt(%r)` |" % (r, tag, ROLE_TITLES[r], mark, r))
    lines.append("")
    if not any(role_is_custom(r) for r in ROLE_ORDER):
        lines.append("> ⚠ **一个角色提示词都还没填。** 去 `roles.d/` 下给每个角色写一个 `.md`，")
        lines.append("> 否则取到的是占位模板。见 `roles.d/README.md`。")
        lines.append("")
    lines.append("## 开工动作（按顺序）")
    lines.append("1. `purge_preflight(target)` —— 动手前体检：目标是否在清单、有无授权线索、工具就位情况。")
    lines.append("2. 决定首个执行角色，用 `purge_role_prompt(<role>)` 取该角色稿。")
    lines.append("3. 把角色稿交给执行体（子代理 / 新会话 / 你自己）—— 任务描述要自包含：目标、已知资产与入口、已测过什么、期望产出。")
    lines.append("4. 回报后**核对账本**（`purge_status`）：没落库的成果不算成果，让它补。")
    lines.append("5. 一次推进一步；同一目标的并发数自己控。")
    return "\n".join(lines)
