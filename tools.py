"""purge 工具处理器：模型能直接调的四个动作。

规矩（照 Hermes 插件契约）：签名 (args: dict, **kwargs) -> str，永远返回 JSON 字符串，
永远不抛异常。工具出错的正确姿势是把错误讲清楚，不是把 agent 崩掉。
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from . import doctor, guard, ledger, roles, state

# 目标类型 → 检查重点
SENSITIVE_TLDS = (".gov", ".mil", ".edu", ".go.jp", ".gov.cn", ".ac.uk", ".gov.uk", ".gob.", ".gouv.")
AUTH_HINTS = ("授权", "已授权", "授权书", "src", "众测", "自测", "自有资产", "自己", "红队", "演练", "ctf", "靶场", "authoriz", "bugbounty", "bug bounty", "scope")


def _j(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


# ---------------------------------------------------------------- 工具
def purge_status(args: dict, **kwargs) -> str:
    """一条命令看清：层在不在、技能在不在、工具在不在、活会话带不带层。"""
    cfg = kwargs.get("_purge_cfg") or {}
    ctx = kwargs.get("_purge_ctx")
    want_json = bool(args.get("json"))
    res = doctor.run(ctx, cfg)
    try:
        res["tables"] = ledger.summary(ctx, args.get("engagement"))
    except Exception:
        res["tables"] = {}
    if want_json:
        return _j(res)
    txt = doctor.render(res)
    tb = res.get("tables") or {}
    if tb:
        txt += "\n台账: " + " / ".join("%s=%s" % (k, v) for k, v in tb.items()
                                       if k not in ("engagement", "dir"))
    return txt


def purge_preflight(args: dict, **kwargs) -> str:
    """动手前的体检：这个目标该不该打、按什么规矩打。"""
    ctx = kwargs.get("_purge_ctx")
    cfg = kwargs.get("_purge_cfg") or {}
    target = (args.get("target") or "").strip()
    note = (args.get("note") or "").strip()
    if not target:
        return _j({"error": "没给 target。用法：purge_preflight(target='example.com', note='有授权书/SRC 范围')"})

    st = state.load(ctx)
    scope_list = state.scope(ctx, cfg.get("scope_file") or "")
    host = guard._norm(target)
    checks, verdicts = [], []

    # 1) 清单命中
    in_list = guard.in_scope(host, scope_list)
    checks.append({"check": "在目标清单里", "pass": bool(in_list),
                   "detail": "已列在 scope" if in_list else f"不在清单（当前 {len(scope_list)} 条）"})

    # 2) 公共源/工具源
    is_infra = guard.is_infra(host)
    checks.append({"check": "不是工具/公共源", "pass": not is_infra,
                   "detail": "这是工具源或公共基础设施，别当靶" if is_infra else "不是白名单域名"})

    # 3) 私网/保留地址
    private = False
    try:
        ip = ipaddress.ip_address(host)
        private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        private = bool(re.match(r"^(localhost|.*\.local|.*\.lan|.*\.internal)$", host))
    checks.append({"check": "不是私网/保留地址", "pass": not private,
                   "detail": "内网/保留地址 —— 确认是自家或授权内网" if private else "公网地址"})

    # 4) 敏感 TLD
    sensitive = host.endswith(SENSITIVE_TLDS)
    checks.append({"check": "不是政府/教育等敏感域", "pass": not sensitive,
                   "detail": "敏感域，必须有明确书面授权" if sensitive else "普通域"})

    # 5) 授权信息
    blob = f"{note} {st.get('objective') or ''}".lower()
    # "无授权"/"未授权" 里含有"授权"两个字 —— 朴素的子串匹配会把"我没有授权"读成有授权，必须显式反查
    _neg = re.search(r"(无|没有|未|没)\s*[^。；，,]{0,4}授权|not\s+authori[sz]ed|no\s+authoriz", blob, re.I)
    has_auth = any(h.lower() in blob for h in AUTH_HINTS) and not _neg
    checks.append({"check": "有授权/范围说明", "pass": bool(has_auth),
                   "detail": ("note/目标说明里有授权线索" if has_auth else
                              ("明确写了没授权" if _neg else "没看到授权线索 —— 补一句授权来源再打"))})

    # verdict
    if is_infra:
        verdict = "no-go"
        verdicts.append("工具源/公共基础设施不是靶。")
    elif sensitive and not has_auth:
        verdict = "need-auth"
        verdicts.append("敏感域且无授权说明：先拿到书面授权再动。")
    elif not in_list and not has_auth:
        verdict = "need-auth"
        verdicts.append("不在清单里也没授权线索：「方向存疑先停后问」——先问。")
    elif not in_list:
        verdict = "go-with-scope-update"
        verdicts.append(f"有授权线索但不在清单：先把目标写进清单（purge_objective 或 purge target {target}）。")
    else:
        verdict = "go"
        verdicts.append("在清单里、有授权线索，可以按既定规矩开打。")

    return _j({
        "target": target,
        "verdict": verdict,
        "verdict_reason": verdicts,
        "checks": checks,
        "scope": scope_list,
        "current_target": st.get("target") or "",
        "red_lines": [
            "靶名/域名/凭证不入库（提交前先 purge_scan）",
            "不自设不合理场景；方向存疑先停后问",
            "只在清单内动手；越界会被红线闸拦下",
        ],
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
    })


def purge_objective(args: dict, **kwargs) -> str:
    """立目标：写目标卡、开红队模式、把目标记进清单。"""
    ctx = kwargs.get("_purge_ctx")
    target = (args.get("target") or "").strip()
    objective = (args.get("objective") or "").strip()
    scope_extra = args.get("scope") or []
    if isinstance(scope_extra, str):
        scope_extra = [s.strip() for s in scope_extra.split(",") if s.strip()]
    if not target:
        return _j({"error": "没给 target。用法：purge_objective(target='x.example.com', objective='拿下后台只读验证')"})

    st = state.set_target(ctx, target, objective)
    if scope_extra:
        st = state.load(ctx)
        st["scope"] = list(dict.fromkeys((st.get("scope") or []) + [s.strip() for s in scope_extra if s.strip()]))
        state.save(ctx, st)
    st = state.set_mode(ctx, "redteam")

    card = [
        "# 目标卡",
        f"- 目标：{target}",
        f"- 目的：{objective or '（未写，补一句，免得不自设场景）'}",
        f"- 清单：{', '.join(state.scope(ctx, '')) or target}",
        f"- 模式：redteam（红线闸生效）",
        f"- 立卡时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## 规矩",
        "- 靶名/域名/凭证不入库；提交前 purge_scan",
        "- 不自设不合理场景；方向存疑先停后问",
        "- 每次动手前 purge_preflight 过一遍",
        "",
        "## 进度",
        "- [ ] 信息收集",
        "- [ ] 验证",
        "- [ ] 报告（purge_report 落盘）",
    ]
    eng = (st.get("engagement") or ledger._slug(target))
    scope_list = list(state.scope(ctx, "") or [])
    if target not in scope_list:
        scope_list = [target] + scope_list
    ypath = _objective_write(eng, target, scope_list, objective)
    card_txt = _objective_card_text(eng)
    path = state.write_report(ctx, f"objective-{target}", "\n".join(card))
    return _j({"ok": True, "mode": st.get("mode"), "target": target, "engagement": eng,
               "scope": scope_list,
               "card_path": str(path), "card": "\n".join(card),
               "objective_card": card_txt, "objective_card_path": str(ypath),
               "roles": roles.role_list(),
               "next": roles.commander_brief()})


def purge_mode(args: dict, **kwargs) -> str:
    """看/切作战模式。聊天里说一句就能切，不用满 TG 找按钮。

    normal  = 只观察：不动手，红队工具不出手
    redteam = 红线闸生效：清单外的动作会被拦下来
    开红队必须同时有靶子 —— 没靶子的红队只是空闸，容易误判"已授权"。
    """
    ctx = kwargs.get("_purge_ctx")
    want = (args.get("mode") or "").strip().lower()
    if want in ("", "?", "status", "show", "看", "状态"):
        st = state.load(ctx)
        return _j({"mode": st.get("mode") or "normal", "target": st.get("target") or "",
                   "scope": state.scope(ctx, ""),
                   "hint": "切模式：purge_mode(mode='redteam') / purge_mode(mode='normal')；"
                           "斜杠版：/purge-mode redteam"})
    if want in ("red", "redteam", "red-team", "红队", "开红队", "on"):
        want = "redteam"
    elif want in ("normal", "off", "关红队", "正常", "观察"):
        want = "normal"
    if want not in ("normal", "redteam"):
        return _j({"error": f"不认的模式 {want!r}；只支持 normal / redteam。"})

    st = state.load(ctx)
    if args.get("target"):
        st = state.set_target(ctx, args["target"], st.get("objective") or "")
    if want == "redteam" and not (st.get("target") or "").strip():
        return _j({"ok": False, "mode": state.load(ctx).get("mode") or "normal",
                   "error": "红队模式要配靶子才有意义 —— 没目标时闸门无从判定放不放行。"
                            "先给目标：purge_mode(mode='redteam', target='x.example.com')，"
                            "或聊天里发 /purge-target x.example.com。"})
    st = state.set_mode(ctx, want)
    out = {"ok": True, "mode": st.get("mode"), "target": st.get("target") or "",
           "scope": state.scope(ctx, ""),
           "note": "redteam=红线闸生效（清单外动作会被拦，每次动手前 purge_preflight）；"
                   "normal=只观察不动手。"}
    if want == "redteam":
        out["roles"] = roles.role_list()
        out["next"] = roles.commander_brief()
    return _j(out)


# ---------------------------------------------------------------- 角色体系（块1：六角色）
def purge_roles(args: dict, **kwargs) -> str:
    """红队角色体系：六角色清单 + 外部工具名到本插件的映射表 + 指挥官开工简报。"""
    return _j({
        "ok": True,
        "planner": roles.PLANNER_ROLE,
        "roles": roles.role_list(),
        "tool_map": roles.TOOL_MAP,
        "brief": roles.commander_brief(),
    })


def purge_role_prompt(args: dict, **kwargs) -> str:
    """取某个红队角色的提示词全文 —— 派子代理时把这整段贴进任务描述。"""
    key = (args.get("role") or "").strip()
    if not key:
        return _j({"ok": False, "error": "要给 role：%s（或对应中文名）" % " / ".join(roles.ROLE_ORDER)})
    code = roles.role_of(key)
    if code is None:
        return _j({"ok": False, "error": "认不出角色 %r；只支持 %s"
                   % (key, " / ".join(roles.ROLE_ORDER))})
    p = roles.role_prompt(code) or ""
    return _j({"ok": True, "role": code, "title": roles.ROLE_TITLES[code],
               "planner": code == roles.PLANNER_ROLE, "chars": len(p),
               "usage": "把 prompt 全文贴进 delegate_task 的 context，子代理才知道职责边界与不许越界。",
               "prompt": p})


def purge_report(args: dict, **kwargs) -> str:
    """报告回放：把这次的结果落盘存档。"""
    ctx = kwargs.get("_purge_ctx")
    name = (args.get("name") or "").strip() or "report"
    body = args.get("body") or ""
    if not body:
        return _j({"error": "没给 body。把要存档的内容放进 body（markdown）。"})
    st = state.load(ctx)
    header = (f"# {name}\n\n- 时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
              f"- 目标：{st.get('target') or '-'}\n- 目的：{st.get('objective') or '-'}\n\n---\n\n")
    path = state.write_report(ctx, name, header + body)
    return _j({"ok": True, "path": str(path), "bytes": len(body)})


def purge_record(args: dict, **kwargs) -> str:
    """战果入账：打下来的东西落一条（可统计、可回看、可交付）。"""
    ctx = kwargs.get("_purge_ctx")
    st = state.load(ctx)
    kind = (args.get("kind") or "").strip()
    if not kind:
        lst = state.score_kind_list()
        return _j({"error": "没给 kind。合法类目（code 或中文名，共 %d 项）：%s%s"
                          % (len(lst), " / ".join(lst[:10]), " …" if len(lst) > 10 else "")})
    rec = state.ledger_add({
        "engagement": args.get("engagement") or st.get("engagement") or "general",
        "target": args.get("target") or st.get("target") or "",
        "kind": kind,
        "score": args.get("score"),
        "evidence": args.get("evidence") or "",
        "note": args.get("note") or "",
        "verified": bool(args.get("verified", False)),
    })
    summ = state.ledger_summary()
    return _j({"ok": True, "entry": rec, "total": summ["count"], "score": summ["score"],
               "ledger": summ["path"]})


def purge_scan(args: dict, **kwargs) -> str:
    """入库前扫描：这个目录里有没有靶名、域名、凭证会被提交出去。"""
    ctx = kwargs.get("_purge_ctx")
    cfg = kwargs.get("_purge_cfg") or {}
    path = Path(args.get("path") or ".").expanduser()
    max_files = int(args.get("max_files") or 4000)
    if not path.exists():
        return _j({"error": f"路径不存在: {path}"})

    st = state.load(ctx)
    needles = [t for t in ([st.get("target")] + list(state.scope(ctx, cfg.get("scope_file") or ""))) if t and len(t) > 3]
    needles = list(dict.fromkeys(needles))

    # 优先只看会被提交的文件（git 仓库）
    files, mode = [], "walk"
    try:
        r = subprocess.run(["git", "-C", str(path), "ls-files"], capture_output=True, text=True, timeout=20)
        if r.returncode == 0 and r.stdout.strip():
            files = [path / f for f in r.stdout.splitlines() if f.strip()]
            mode = "git-tracked"
    except Exception:
        pass
    if not files:
        for p in path.rglob("*"):
            if p.is_file() and ".git/" not in str(p).replace("\\", "/"):
                files.append(p)
                if len(files) >= max_files:
                    break

    hits, scanned, skipped = [], 0, 0
    for f in files[:max_files]:
        try:
            if f.stat().st_size > 2_000_000:
                skipped += 1
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            skipped += 1
            continue
        scanned += 1
        sec = guard.secrets_in(text)
        name_hits = [n for n in needles if re.search(re.escape(n), text, re.I)]
        if sec or name_hits:
            hits.append({"file": str(f), "secrets": sec, "target_mentions": name_hits,
                         "line": _first_line(text, sec, name_hits)})
    return _j({
        "path": str(path), "mode": mode, "scanned": scanned, "skipped": skipped,
        "needles": needles, "hit_count": len(hits), "hits": hits[:50],
        "verdict": "clean" if not hits else "must-clean-before-push",
        "note": "命中不代表一定错，但 push 之前必须逐条确认或清掉。",
    })


def _first_line(text: str, secrets: list, names: list) -> str:
    for i, ln in enumerate(text.splitlines(), 1):
        for pat, _ in guard.SECRET_PATTERNS:
            if re.search(pat, ln):
                return f"L{i}: " + " ".join(ln.split())[:120]
        for n in names:
            if re.search(re.escape(n), ln, re.I):
                return f"L{i}: " + " ".join(ln.split())[:120]
    return ""


# ---------------------------------------------------------------- schema
SCHEMAS = {
    "purge_status": {
        "name": "purge_status",
        "description": ("自检：一次看清 purge 能力层有没有真的生效 —— 加强层是否在 SOUL.md、"
                        "技能条数、红队工具箱哪些缺件、网关状态，以及最近几条会话的真实系统提示里到底带不带加强层"
                        "（会话提示在建立时冻结，旧会话永远是旧提示，这是本机踩过的坑）。"
                        "用户问「你怎么没生效 / 技能有没有加载 / 环境对不对」时先跑这个。"),
        "parameters": {"type": "object", "properties": {
            "json": {"type": "boolean", "description": "true=返回原始 JSON（给脚本/程序用）"}}, "required": []},
    },
    "purge_preflight": {
        "name": "purge_preflight",
        "description": ("动手前体检：给一个目标，判断该不该打 —— 是否在目标清单、是否工具/公共源、"
                        "是否私网或敏感域、有没有授权线索，并给出 go / go-with-scope-update / need-auth / no-go 的结论。"
                        "任何针对具体目标的动作之前都先跑它。"),
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string", "description": "目标域名或 IP"},
            "note": {"type": "string", "description": "授权/范围说明，例如『客户授权书已签，范围仅此域名』"}},
            "required": ["target"]},
    },
    "purge_objective": {
        "name": "purge_objective",
        "description": ("立目标：把目标、目的、范围记下来，开红队模式（红线闸生效），并落一张目标卡。"
                        "开始一个受控任务时先调它，任务结束再关（purge mode normal）。"),
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string", "description": "主目标"},
            "objective": {"type": "string", "description": "这次要达成什么、边界在哪"},
            "scope": {"type": "array", "items": {"type": "string"}, "description": "本次允许涉及的其它目标"}},
            "required": ["target"]},
    },
    "purge_mode": {
        "name": "purge_mode",
        "description": ("看/切作战模式，聊天里说一句就能切（不必让用户去找斜杠按钮）："
                        "normal=只观察不动手；redteam=红线闸生效，清单外的动作会被拦。"
                        "用户在聊天里说『开红队 / 关红队 / 现在什么模式 / 进入作战状态』时调它。"
                        "不给 mode = 只看当前模式。开红队会自动要求有靶子：没目标先要目标，"
                        "或一并把 target 给上。"),
        "parameters": {"type": "object", "properties": {
            "mode": {"type": "string", "description": "normal | redteam；不给=只报当前模式"},
            "target": {"type": "string", "description": "开红队时顺带给的目标（可省，省了用已设的）"}},
            "required": []},
    },
    "purge_report": {
        "name": "purge_report",
        "description": "报告回放：把阶段性结果/复盘落盘存档（$HERMES_HOME/purge/reports/），供以后回看。",
        "parameters": {"type": "object", "properties": {
            "name": {"type": "string", "description": "报告名（用于文件名）"},
            "body": {"type": "string", "description": "markdown 正文"}},
            "required": ["name", "body"]},
    },
    "purge_record": {
        "name": "purge_record",
        "description": ("战果入账：把这次拿到的东西记进战果账本（可统计、可回看、可交付）。"
                        "kind 用得分点（内置 25 项口径），"
                        "可传 code 或中文名，例如：domain-control（域名控制权限）/ server-host（服务器主机权限）"
                        "/ terminal-access（终端权限）/ db-credential（数据库账号）/ web-app（Web应用系统）"
                        "/ central-system（集权系统）/ bigdata-system（大数据系统）/ netdev（网络设备）"
                        "/ cloud-platform（云平台）/ iot-platform（物联网平台）/ secdev（安全设备）"
                        "/ file-storage（文件存储）/ ai-agent（AI Agent）/ model-compute（模型算力）"
                        "/ model-data（模型数据）/ computepower-admin / computepower-cards"
                        "/ boundary-logical|boundary-strong|boundary-physical|boundary-supply（边界穿透）"
                        "/ netdev-redirect|netdev-implant|iot-corenet（网络/物联网纵深）。"
                        "不给 score 就按该项默认分计（默认分与上限见 state.SCORE_POINTS）。"
                        "只有真验证过的才算，没验证的把 verified 留 false。"),
        "parameters": {"type": "object", "properties": {
            "kind": {"type": "string", "description": "得分点 code 或中文名（共 25 项，见描述）"},
            "score": {"type": "number", "description": "自定义计分，不给就按类目默认权重"},
            "evidence": {"type": "string", "description": "证据位置（报告/截图/shell 记录路径）"},
            "note": {"type": "string", "description": "一句话说明"},
            "verified": {"type": "boolean", "description": "是否已真验证（默认 false）"}},
            "required": ["kind"]},
    },
    "purge_scan": {
        "name": "purge_scan",
        "description": ("入库前扫描：扫一个目录（优先只看 git 追踪的文件），找凭证（各类 key/token/私钥）"
                        "和目标名/域名。push 前必扫。返回 must-clean-before-push 时不许推。"),
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "要扫的目录，默认当前目录"},
            "max_files": {"type": "integer", "description": "最多扫多少个文件，默认 4000"}},
            "required": []},
    },
    "purge_roles": {
        "name": "purge_roles",
        "description": ("红队角色体系：列六个角色（`plan` 指挥 + `recon` 信息收集 / `assess` 资产梳理 / "
                        "`vuln-scan` 漏洞发现 / `exploit` 漏洞利用 / `internal` 内网渗透）、各角色职责，"
                        "以及外部工具名到本插件的映射表，并给出指挥官开工简报（先派谁、怎么派）。"
                        "开红队模式后先跑它，再决定派哪个角色。"),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    "purge_role_prompt": {
        "name": "purge_role_prompt",
        "description": ("取某个红队角色的提示词全文（职责边界 + 记分纪律 + 打之前先查账本 + 落库溯源 + 交付口径）。"
                        "派子代理前调它，把返回的 prompt 全文贴进 delegate_task 的任务描述 —— 子代理看不到本会话上下文，"
                        "不贴它就会越界（让信息收集去测漏洞、让漏洞发现去打内网）。"
                        "role 传 code（plan / recon / assess / vuln-scan / exploit / internal）或中文名"
                        "（指挥 / 信息收集 / 资产梳理 / 漏洞发现 / 漏洞利用 / 内网渗透）。"),
        "parameters": {"type": "object", "properties": {
            "role": {"type": "string", "description": "角色 code 或中文名"}},
            "required": ["role"]},
    },
}


# ================================================================ 块2：台账工具族
# 外部台账工具名 → 本插件 purge_*
# 存储走 ledger.py（$HERMES_HOME/purge/engagements/<靶标>/<族>.json）
# 命名规则：上游 redteam_asset_add → 这里 purge_asset_add（前缀整体替换）

# ---------------------------------------------------------------- asset 族
def purge_asset_add(args: dict, **kwargs) -> str:
    """把资产及其端口/服务/指纹写入资产库（按 ip 幂等 upsert）。"""
    try:
        ip = str(args.get("ip") or "").strip()
        if not ip:
            return _j({"ok": False, "error": "要 ip（IPv4）。"})
        prov = str(args.get("provenance") or "").strip()
        if prov not in ("passive", "active"):
            return _j({"ok": False, "error": "provenance 必填，只能填 passive（被动收集）或 active（主动探测）。"})
        rec = {
            "ip": ip,
            "state": str(args.get("state") or "unknown"),
            "primary_name": args.get("primary_name") or "",
            "provenance": prov,
            "tool": args.get("tool") or "",
            "discovered_at": args.get("discovered_at") or "",
            "first_seen": args.get("first_seen") or "",
            "names": args.get("names") or [],
            "ports": args.get("ports") or [],
        }
        got, created = ledger.asset_upsert(kwargs.get("ctx"), rec, args.get("engagement"))
        return _j({"ok": True, "created": created, "asset": got,
                   "hint": "新建" if created else "已合并进同一 ip 的既有记录"})
    except Exception as e:
        return _j({"ok": False, "error": "资产写入失败：%s" % e})


def purge_asset_query(args: dict, **kwargs) -> str:
    """查资产库：按网段/端口/服务/指纹/状态/关键词过滤。"""
    try:
        rows = ledger.asset_query(
            kwargs.get("ctx"), args.get("engagement"),
            cidr=args.get("cidr"), port=args.get("port"), service=args.get("service"),
            fingerprint=args.get("fingerprint"), provenance=args.get("provenance"),
            q=args.get("q"), state=args.get("state"), scope=args.get("scope"),
            sort=args.get("sort"), limit=args.get("limit"))
        return _j({"ok": True, "count": len(rows), "assets": rows})
    except Exception as e:
        return _j({"ok": False, "error": "资产查询失败：%s" % e})


def purge_asset_get(args: dict, **kwargs) -> str:
    """按 id 取一条资产的完整记录（含端口、指纹、测试记录）。"""
    try:
        rid = str(args.get("id") or "").strip()
        if not rid:
            return _j({"ok": False, "error": "要 id（例如 a0001）。"})
        rec = ledger.find_by_id(kwargs.get("ctx"), "assets", rid, args.get("engagement"))
        if rec is None:
            return _j({"ok": False, "error": "没有这条资产：%s" % rid})
        return _j({"ok": True, "asset": rec})
    except Exception as e:
        return _j({"ok": False, "error": "取资产失败：%s" % e})


def purge_asset_stats(args: dict, **kwargs) -> str:
    """资产库概览：条数、存活数、端口数、TOP 端口/服务/产品。"""
    try:
        return _j({"ok": True, "engagement": ledger.current_engagement(kwargs.get("ctx")),
                   "stats": ledger.asset_stats(kwargs.get("ctx"), args.get("engagement")),
                   "all_tables": ledger.summary(kwargs.get("ctx"), args.get("engagement"))})
    except Exception as e:
        return _j({"ok": False, "error": "统计失败：%s" % e})


def purge_asset_test(args: dict, **kwargs) -> str:
    """给资产登记一次测试记录（测了什么、结果、暴露面、是否被拦）。"""
    try:
        ctx = kwargs.get("ctx")
        rec = None
        if args.get("asset_id"):
            rec = ledger.find_by_id(ctx, "assets", args["asset_id"], args.get("engagement"))
        if rec is None and args.get("ip"):
            for r in ledger.table_read(ctx, "assets", args.get("engagement")):
                if str(r.get("ip")) == str(args["ip"]):
                    rec = r
                    break
        if rec is None:
            return _j({"ok": False, "error": "找不到资产：给 asset_id 或已入库的 ip。"})
        entry = {
            "status": args.get("status") or "tested",
            "test": args.get("test") or "",
            "notes": args.get("notes") or "",
            "surface": args.get("surface") or "",
            "blocked": bool(args.get("blocked")),
            "updated_by": args.get("updated_by") or "",
            "at": ledger._now(),
        }
        rec.setdefault("tests", []).append(entry)
        rec["updated_at"] = ledger._now()
        ledger.table_update(ctx, "assets", rec["id"], {"tests": rec["tests"]}, args.get("engagement"))
        return _j({"ok": True, "asset_id": rec["id"], "ip": rec.get("ip"), "entry": entry,
                   "history": len(rec["tests"])})
    except Exception as e:
        return _j({"ok": False, "error": "登记测试记录失败：%s" % e})


def purge_asset_assess(args: dict, **kwargs) -> str:
    """给资产打价值评估：优先级、潜在利用点、理由。"""
    try:
        ctx = kwargs.get("ctx")
        rec = None
        if args.get("asset_id"):
            rec = ledger.find_by_id(ctx, "assets", args["asset_id"], args.get("engagement"))
        if rec is None and args.get("ip"):
            for r in ledger.table_read(ctx, "assets", args.get("engagement")):
                if str(r.get("ip")) == str(args["ip"]):
                    rec = r
                    break
        if rec is None:
            return _j({"ok": False, "error": "找不到资产：给 asset_id 或已入库的 ip。"})
        rec["assessment"] = {
            "priority": args.get("priority") or "",
            "potential": args.get("potential") or "",
            "reason": args.get("reason") or "",
            "assessed_by": args.get("assessed_by") or "",
            "at": ledger._now(),
        }
        rec["updated_at"] = ledger._now()
        ledger.table_update(ctx, "assets", rec["id"], {"assessment": rec["assessment"]},
                            args.get("engagement"))
        return _j({"ok": True, "asset_id": rec["id"], "assessment": rec["assessment"]})
    except Exception as e:
        return _j({"ok": False, "error": "评估失败：%s" % e})


def purge_asset_link(args: dict, **kwargs) -> str:
    """登记两个对象之间的关系（资产↔域名↔漏洞↔凭据↔WebShell…）。"""
    try:
        need = ("src_kind", "src_id", "dst_kind", "dst_id")
        miss = [k for k in need if not str(args.get(k) or "").strip()]
        if miss:
            return _j({"ok": False, "error": "缺参数：%s" % ", ".join(miss)})
        rec = ledger.table_append(kwargs.get("ctx"), "links", {
            "src_kind": args["src_kind"], "src_id": args["src_id"],
            "dst_kind": args["dst_kind"], "dst_id": args["dst_id"],
            "relation": args.get("relation") or "related",
            "confidence": args.get("confidence") if args.get("confidence") is not None else 1.0,
        }, args.get("engagement"))
        return _j({"ok": True, "link": rec})
    except Exception as e:
        return _j({"ok": False, "error": "登记关系失败：%s" % e})


def purge_asset_graph(args: dict, **kwargs) -> str:
    """导出资产关系图：节点（资产）+ 边（names/links）。"""
    try:
        ctx = kwargs.get("ctx")
        rows = ledger.asset_query(ctx, args.get("engagement"), cidr=args.get("cidr"), limit=None)
        nodes = [{"id": r.get("id"), "ip": r.get("ip"), "state": r.get("state"),
                  "name": r.get("primary_name")} for r in rows]
        edges = []
        for r in rows:
            for n in (r.get("names") or []):
                edges.append({"from": r.get("id"), "to": n.get("name"),
                              "kind": "name", "role": n.get("kind") or "domain"})
        for lk in ledger.table_read(ctx, "links", args.get("engagement")):
            edges.append({"from": lk.get("src_id"), "to": lk.get("dst_id"),
                          "kind": lk.get("relation") or "related",
                          "note": "%s→%s" % (lk.get("src_kind"), lk.get("dst_kind"))})
        return _j({"ok": True, "nodes": nodes, "edges": edges,
                   "counts": {"nodes": len(nodes), "edges": len(edges)}})
    except Exception as e:
        return _j({"ok": False, "error": "导出关系图失败：%s" % e})


def purge_asset_timeline(args: dict, **kwargs) -> str:
    """资产事件时间线：入库、测试、评估、发现时间按序排出。"""
    try:
        ctx = kwargs.get("ctx")
        rows = ledger.asset_query(ctx, args.get("engagement"))
        ev = []
        for r in rows:
            if r.get("discovered_at") or r.get("first_seen"):
                ev.append({"at": r.get("discovered_at") or r.get("first_seen"),
                           "kind": "discover", "asset_id": r.get("id"),
                           "ip": r.get("ip"), "detail": r.get("primary_name") or ""})
            ev.append({"at": r.get("created_at"), "kind": "ingest",
                       "asset_id": r.get("id"), "ip": r.get("ip"), "detail": "入库"})
            for t in (r.get("tests") or []):
                ev.append({"at": t.get("at"), "kind": "test", "asset_id": r.get("id"),
                           "ip": r.get("ip"), "detail": "%s %s" % (t.get("status") or "", t.get("test") or "")})
            if r.get("assessment"):
                ev.append({"at": (r["assessment"] or {}).get("at"), "kind": "assess",
                           "asset_id": r.get("id"), "ip": r.get("ip"),
                           "detail": (r["assessment"] or {}).get("priority") or ""})
        ev = [x for x in ev if x.get("at")]
        ev.sort(key=lambda x: str(x.get("at")))
        lim = args.get("limit")
        if lim:
            try:
                ev = ev[-int(lim):]
            except Exception:
                pass
        return _j({"ok": True, "events": ev, "count": len(ev)})
    except Exception as e:
        return _j({"ok": False, "error": "生成时间线失败：%s" % e})


_ASSET_SCHEMAS = {
    "purge_asset_add": {
        "name": "purge_asset_add",
        "description": ("把一个资产及其端口/服务/指纹写入资产库（按 ip 幂等 upsert，重复采集自动合并）。"
                        "每条发现必须标 provenance：被动收集填 passive，主动探测填 active，并填 tool（数据源或工具名）。"),
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string", "description": "靶标 id；省略则用当前会话绑定的靶标"},
            "ip": {"type": "string", "description": "资产 IP（IPv4）"},
            "state": {"type": "string", "description": "live | dead | unknown，默认 unknown"},
            "primary_name": {"type": "string", "description": "主域名/主机名"},
            "provenance": {"type": "string", "description": "passive（被动收集）| active（主动探测），必填"},
            "tool": {"type": "string", "description": "数据源或工具名，例如 crt.sh / nmap / nuclei / curl"},
            "discovered_at": {"type": "string", "description": "发现时间（ISO）。不填按第一次入库时刻记；重复采集不覆盖"},
            "first_seen": {"type": "string", "description": "数据源报告的首次出现时间"},
            "names": {"type": "array", "description": "关联的域名/证书名",
                      "items": {"type": "object", "properties": {
                          "name": {"type": "string"}, "kind": {"type": "string", "description": "domain | hostname | cert_cn"},
                          "provenance": {"type": "string", "description": "passive | active"}}}},
            "ports": {"type": "array", "description": "开放端口及其服务/指纹",
                      "items": {"type": "object", "properties": {
                          "port": {"type": "integer"}, "proto": {"type": "string", "description": "tcp（默认）| udp"},
                          "service": {"type": "string"}, "product": {"type": "string"},
                          "version": {"type": "string"}, "banner": {"type": "string"},
                          "url": {"type": "string", "description": "Web 服务完整 URL"},
                          "title": {"type": "string", "description": "页面标题"},
                          "provenance": {"type": "string"}, "tool": {"type": "string"},
                          "fingerprints": {"type": "array", "items": {"type": "object", "properties": {
                              "category": {"type": "string"}, "vendor": {"type": "string"},
                              "product": {"type": "string"}, "version": {"type": "string"},
                              "evidence": {"type": "string"}, "confidence": {"type": "number"}}}}}}}},
            "required": ["ip", "provenance"]}},
    "purge_asset_query": {
        "name": "purge_asset_query",
        "description": "查资产库。支持网段、端口、服务、指纹关键词、状态、来源、任意关键词过滤，可排序与限数。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"},
            "cidr": {"type": "string", "description": "网段过滤，例如 10.0.0.0/24"},
            "port": {"type": "integer", "description": "只留开放了该端口的资产"},
            "service": {"type": "string", "description": "按服务名过滤，例如 http / mysql"},
            "fingerprint": {"type": "string", "description": "指纹关键词，例如 nginx / 致远OA"},
            "provenance": {"type": "string", "description": "passive | active"},
            "q": {"type": "string", "description": "任意关键词（全字段模糊匹配）"},
            "state": {"type": "string", "description": "live | dead | unknown"},
            "scope": {"type": "string", "description": "一次给多个网段（JSON 数组字符串）"},
            "sort": {"type": "string", "description": "排序字段，前缀 - 表示倒序，例如 -updated_at"},
            "limit": {"type": "integer", "description": "最多返回几条"}},
            "required": []}},
    "purge_asset_get": {
        "name": "purge_asset_get",
        "description": "按 id 取一条资产的完整记录（端口、指纹、测试记录、评估结果）。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"}, "id": {"type": "string", "description": "资产 id，例如 a0001"}},
            "required": ["id"]}},
    "purge_asset_stats": {
        "name": "purge_asset_stats",
        "description": "资产库概览：总条数/存活数/端口数 + TOP 端口、服务、产品，附带九族台账条数。",
        "parameters": {"type": "object", "properties": {"engagement": {"type": "string"}}, "required": []}},
    "purge_asset_test": {
        "name": "purge_asset_test",
        "description": ("给资产登记一次测试记录：测了什么、结果如何、暴露面在哪、有没有被拦。"
                        "每测一轮都要登记，避免下游角色重复测同一个入口。"),
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"},
            "asset_id": {"type": "string", "description": "资产 id（与 ip 二选一）"},
            "ip": {"type": "string", "description": "资产 IP（与 asset_id 二选一）"},
            "status": {"type": "string", "description": "tested | blocked | skipped | failed"},
            "test": {"type": "string", "description": "做了什么测试，例如 目录爆破 / 弱口令 / POC 验证"},
            "notes": {"type": "string", "description": "结果说明"},
            "surface": {"type": "string", "description": "暴露面，例如 8443/portal 登录口"},
            "blocked": {"type": "boolean", "description": "是否被 WAF/风控拦住"},
            "updated_by": {"type": "string", "description": "哪个角色登记的"}},
            "required": []}},
    "purge_asset_assess": {
        "name": "purge_asset_assess",
        "description": "给资产打价值评估：优先级、潜在利用点、判定理由。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"},
            "asset_id": {"type": "string", "description": "资产 id（与 ip 二选一）"},
            "ip": {"type": "string"},
            "priority": {"type": "string", "description": "high | medium | low"},
            "potential": {"type": "string", "description": "潜在利用点，例如 未授权访问 / 弱口令 / 已知 CVE"},
            "reason": {"type": "string", "description": "判定理由（要能自圆其说）"},
            "assessed_by": {"type": "string", "description": "评估角色"}},
            "required": []}},
    "purge_asset_link": {
        "name": "purge_asset_link",
        "description": "登记两个对象之间的关系（资产↔域名↔漏洞↔凭据↔WebShell），供关系图与攻击链使用。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"},
            "src_kind": {"type": "string", "description": "源类型：asset | vuln | credential | webshell | tunnel"},
            "src_id": {"type": "string"},
            "dst_kind": {"type": "string"},
            "dst_id": {"type": "string"},
            "relation": {"type": "string", "description": "关系名，例如 hosts / exploits / leads_to"},
            "confidence": {"type": "number", "description": "0–1"}},
            "required": ["src_kind", "src_id", "dst_kind", "dst_id"]}},
    "purge_asset_graph": {
        "name": "purge_asset_graph",
        "description": "导出资产关系图：节点（资产）与边（域名关联 + 登记的关系）。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"}, "cidr": {"type": "string"}}, "required": []}},
    "purge_asset_timeline": {
        "name": "purge_asset_timeline",
        "description": "资产事件时间线：发现、入库、测试、评估按时间排出，用来判断哪些入口已被覆盖。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"}, "limit": {"type": "integer", "description": "只留最后 N 条"}},
            "required": []}},
}

SCHEMAS.update(_ASSET_SCHEMAS)

def _now_iso() -> str:
    """本地时间 ISO 串（台账时间戳统一走这里）。"""
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# ---------------------------------------------------------------- 块2 批2：vuln 族
def purge_vuln_add(args: dict, **kwargs) -> str:
    """登记一条漏洞（发现即记，不要只在报告里写）。"""
    eng = args.get("engagement")
    title = (args.get("title") or "").strip()
    if not title:
        return _j({"ok": False, "error": "title 必填（一句话说清是什么漏洞）"})
    sev = (args.get("severity") or "").strip().lower()
    if sev and sev not in ("critical", "high", "medium", "low", "info"):
        return _j({"ok": False, "error": "severity 只能填 critical/high/medium/low/info"})
    rec = {
        "title": title, "severity": sev or "medium",
        "vuln_type": args.get("vuln_type") or args.get("type") or "",
        "asset_id": args.get("asset_id") or "", "ip": args.get("ip") or "",
        "port": args.get("port"), "url": args.get("url") or "",
        "cve": args.get("cve") or "", "cvss": args.get("cvss"),
        "description": args.get("description") or "",
        "evidence": args.get("evidence") or "",
        "poc": args.get("poc") or "",
        "references": args.get("references") or [],
        "status": (args.get("status") or "open").strip().lower(),
        "discovered_by": args.get("discovered_by") or "",
        "created_at": _now_iso(),
    }
    rec = ledger.table_append(None, "vulns", rec, eng)
    return _j({"ok": True, "vuln": {"id": rec["id"], "title": rec["title"], "severity": rec["severity"],
                                    "status": rec["status"], "asset_id": rec["asset_id"]}})


def purge_vuln_query(args: dict, **kwargs) -> str:
    """按条件查漏洞台账（动手前先查，别重复测同一条）。"""
    rows = ledger.table_read(None, "vulns", args.get("engagement"))
    sev = (args.get("severity") or "").strip().lower()
    st = (args.get("status") or "").strip().lower()
    aid = (args.get("asset_id") or "").strip()
    ip = (args.get("ip") or "").strip()
    vt = (args.get("vuln_type") or args.get("type") or "").strip().lower()
    q = (args.get("q") or "").strip().lower()
    out = []
    for r in rows:
        if sev and str(r.get("severity", "")).lower() != sev:
            continue
        if st and str(r.get("status", "")).lower() != st:
            continue
        if aid and r.get("asset_id") != aid:
            continue
        if ip and r.get("ip") != ip:
            continue
        if vt and vt not in str(r.get("vuln_type", "")).lower():
            continue
        if q and q not in json.dumps(r, ensure_ascii=False).lower():
            continue
        out.append(r)
    lim = int(args.get("limit") or 200)
    return _j({"ok": True, "count": len(out), "vulns": out[:lim]})


def purge_vuln_update(args: dict, **kwargs) -> str:
    """改漏洞的状态/严重度/补充证据（例如从 open 改成 confirmed / false-positive）。"""
    rid = (args.get("id") or "").strip()
    if not rid:
        return _j({"ok": False, "error": "id 必填（先 purge_vuln_query 拿 id）"})
    patch = {}
    for k in ("status", "severity", "evidence", "poc", "description", "notes", "cve", "cvss"):
        if k in args and args[k] not in (None, ""):
            patch[k] = args[k]
    if not patch:
        return _j({"ok": False, "error": "没有要改的字段"})
    patch["updated_by"] = args.get("updated_by") or ""
    patch["updated_at"] = _now_iso()
    rec = ledger.table_update(None, "vulns", rid, patch, args.get("engagement"))
    if rec is None:
        return _j({"ok": False, "error": "找不到漏洞 %s" % rid})
    return _j({"ok": True, "vuln": rec})


# ---------------------------------------------------------------- 块2 批2：credential 族
def purge_credential_add(args: dict, **kwargs) -> str:
    """登记一条凭据（账号/口令/hash/密钥/token）。凭据落库才有价值，别只写在报告里。"""
    eng = args.get("engagement")
    user = (args.get("username") or "").strip()
    if not user:
        return _j({"ok": False, "error": "username 必填"})
    kind = (args.get("kind") or "password").strip().lower()
    if kind not in ("password", "hash", "key", "token", "cookie", "cert"):
        return _j({"ok": False, "error": "kind 只能填 password/hash/key/token/cookie/cert"})
    rec = {
        "username": user, "secret": args.get("secret") or "",
        "kind": kind, "service": args.get("service") or "",
        "ip": args.get("ip") or "", "port": args.get("port"),
        "asset_id": args.get("asset_id") or "",
        "valid": bool(args.get("valid", False)),
        "source": args.get("source") or "",
        "notes": args.get("notes") or "",
        "discovered_by": args.get("discovered_by") or "",
        "created_at": _now_iso(),
    }
    rec = ledger.table_append(None, "credentials", rec, eng)
    return _j({"ok": True, "credential": {"id": rec["id"], "username": rec["username"], "kind": rec["kind"],
                                          "service": rec["service"], "ip": rec["ip"], "valid": rec["valid"]}})


def purge_credential_list(args: dict, **kwargs) -> str:
    """列凭据台账（可按 ip/service/kind/valid 过滤）。"""
    rows = ledger.table_read(None, "credentials", args.get("engagement"))
    ip = (args.get("ip") or "").strip()
    svc = (args.get("service") or "").strip().lower()
    kind = (args.get("kind") or "").strip().lower()
    want_valid = args.get("valid", None)
    out = []
    for r in rows:
        if ip and r.get("ip") != ip:
            continue
        if svc and svc not in str(r.get("service", "")).lower():
            continue
        if kind and str(r.get("kind", "")).lower() != kind:
            continue
        if want_valid is not None and bool(r.get("valid")) != bool(want_valid):
            continue
        out.append(r)
    lim = int(args.get("limit") or 200)
    return _j({"ok": True, "count": len(out), "credentials": out[:lim]})


# ---------------------------------------------------------------- 块2 批2：access 族
def purge_access_add(args: dict, **kwargs) -> str:
    """登记一次「拿到了什么权限」（shell / rdp / ssh / webshell / 后台 / 数据库）。"""
    eng = args.get("engagement")
    kind = (args.get("kind") or "").strip().lower()
    if kind not in ("shell", "rdp", "ssh", "webshell", "console", "database", "domain-admin", "other"):
        return _j({"ok": False, "error": "kind 只能填 shell/rdp/ssh/webshell/console/database/domain-admin/other"})
    if not (args.get("asset_id") or args.get("ip")):
        return _j({"ok": False, "error": "asset_id 或 ip 至少给一个"})
    rec = {
        "kind": kind, "asset_id": args.get("asset_id") or "", "ip": args.get("ip") or "",
        "level": args.get("level") or "", "method": args.get("method") or "",
        "credential_id": args.get("credential_id") or "",
        "username": args.get("username") or "",
        "notes": args.get("notes") or "",
        "obtained_by": args.get("obtained_by") or "",
        "created_at": _now_iso(),
    }
    rec = ledger.table_append(None, "access", rec, eng)
    return _j({"ok": True, "access": {"id": rec["id"], "kind": rec["kind"], "ip": rec["ip"],
                                      "level": rec["level"], "method": rec["method"]}})


def purge_access_list(args: dict, **kwargs) -> str:
    """列已拿到的权限（评估 commander 判断能不能进内网用这个）。"""
    rows = ledger.table_read(None, "access", args.get("engagement"))
    ip = (args.get("ip") or "").strip()
    kind = (args.get("kind") or "").strip().lower()
    out = []
    for r in rows:
        if ip and r.get("ip") != ip:
            continue
        if kind and str(r.get("kind", "")).lower() != kind:
            continue
        out.append(r)
    lim = int(args.get("limit") or 200)
    return _j({"ok": True, "count": len(out), "access": out[:lim]})


# ---------------------------------------------------------------- 块2 批2：webshell 族
def purge_webshell_add(args: dict, **kwargs) -> str:
    """登记一个 WebShell（URL + 类型 + 连接口令）。传上去就要记，别靠脑子记。"""
    eng = args.get("engagement")
    url = (args.get("url") or "").strip()
    if not url:
        return _j({"ok": False, "error": "url 必填"})
    rec = {
        "url": url, "type": (args.get("type") or "").strip().lower(),
        "password": args.get("password") or args.get("pass") or "",
        "ip": args.get("ip") or "", "path": args.get("path") or "",
        "note": args.get("note") or "", "status": (args.get("status") or "live").strip().lower(),
        "obtained_by": args.get("obtained_by") or "",
        "created_at": _now_iso(),
    }
    rec = ledger.table_append(None, "webshells", rec, eng)
    return _j({"ok": True, "webshell": {"id": rec["id"], "url": rec["url"], "type": rec["type"],
                                        "ip": rec["ip"], "status": rec["status"]}})


def purge_webshell_list(args: dict, **kwargs) -> str:
    """列 WebShell（可按 ip/type/status 过滤）。"""
    rows = ledger.table_read(None, "webshells", args.get("engagement"))
    ip = (args.get("ip") or "").strip()
    ty = (args.get("type") or "").strip().lower()
    st = (args.get("status") or "").strip().lower()
    out = []
    for r in rows:
        if ip and r.get("ip") != ip:
            continue
        if ty and str(r.get("type", "")).lower() != ty:
            continue
        if st and str(r.get("status", "")).lower() != st:
            continue
        out.append(r)
    lim = int(args.get("limit") or 200)
    return _j({"ok": True, "count": len(out), "webshells": out[:lim]})


def purge_webshell_update(args: dict, **kwargs) -> str:
    """改 WebShell 状态（活着/被杀/已弃用）。"""
    rid = (args.get("id") or "").strip()
    if not rid:
        return _j({"ok": False, "error": "id 必填"})
    patch = {}
    for k in ("status", "password", "pass", "note", "url", "type"):
        if k in args and args[k] not in (None, ""):
            patch[k] = args[k]
    if "pass" in patch:
        patch["password"] = patch.pop("pass")
    if not patch:
        return _j({"ok": False, "error": "没有要改的字段"})
    patch["updated_at"] = _now_iso()
    rec = ledger.table_update(None, "webshells", rid, patch, args.get("engagement"))
    if rec is None:
        return _j({"ok": False, "error": "找不到 webshell %s" % rid})
    return _j({"ok": True, "webshell": rec})


# ---------------------------------------------------------------- 块2 批2：tunnel 族
def purge_tunnel_add(args: dict, **kwargs) -> str:
    """登记一条隧道/代理（socks / http / 端口转发）。进内网的第一件事就是记它。"""
    eng = args.get("engagement")
    kind = (args.get("kind") or "").strip().lower()
    if kind not in ("socks", "socks5", "http", "portfwd", "reverse", "vpn", "other"):
        return _j({"ok": False, "error": "kind 只能填 socks/socks5/http/portfwd/reverse/vpn/other"})
    rec = {
        "kind": kind, "listen": args.get("listen") or "",
        "target": args.get("target") or "", "via_host": args.get("via_host") or "",
        "ip": args.get("ip") or "", "port": args.get("port"),
        "tool": args.get("tool") or "", "note": args.get("note") or "",
        "status": (args.get("status") or "live").strip().lower(),
        "created_by": args.get("created_by") or "",
        "created_at": _now_iso(),
    }
    rec = ledger.table_append(None, "tunnels", rec, eng)
    return _j({"ok": True, "tunnel": {"id": rec["id"], "kind": rec["kind"], "listen": rec["listen"],
                                      "target": rec["target"], "status": rec["status"]}})


def purge_tunnel_list(args: dict, **kwargs) -> str:
    """列隧道（可按 kind/status/via_host 过滤）。"""
    rows = ledger.table_read(None, "tunnels", args.get("engagement"))
    kind = (args.get("kind") or "").strip().lower()
    st = (args.get("status") or "").strip().lower()
    via = (args.get("via_host") or "").strip()
    out = []
    for r in rows:
        if kind and str(r.get("kind", "")).lower() != kind:
            continue
        if st and str(r.get("status", "")).lower() != st:
            continue
        if via and r.get("via_host") != via:
            continue
        out.append(r)
    lim = int(args.get("limit") or 200)
    return _j({"ok": True, "count": len(out), "tunnels": out[:lim]})


def purge_tunnel_update(args: dict, **kwargs) -> str:
    """改隧道状态（活着/断了/已关闭）。"""
    rid = (args.get("id") or "").strip()
    if not rid:
        return _j({"ok": False, "error": "id 必填"})
    patch = {}
    for k in ("status", "note", "listen", "target", "via_host"):
        if k in args and args[k] not in (None, ""):
            patch[k] = args[k]
    if not patch:
        return _j({"ok": False, "error": "没有要改的字段"})
    patch["updated_at"] = _now_iso()
    rec = ledger.table_update(None, "tunnels", rid, patch, args.get("engagement"))
    if rec is None:
        return _j({"ok": False, "error": "找不到隧道 %s" % rid})
    return _j({"ok": True, "tunnel": rec})


# ---------------------------------------------------------------- 块2 批2：schema 注册
_P2B_SCHEMAS = {
    "purge_vuln_add": {
        "name": "purge_vuln_add",
        "description": ("登记一条漏洞。发现即记，不要只在最后报告里写 —— 指挥官要靠台账判断"
                        "「测过什么、还缺什么」。severity 用 critical/high/medium/low/info；evidence 写原始回显。"),
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string", "description": "一句话说清是什么漏洞（必填）"},
            "severity": {"type": "string", "description": "critical / high / medium / low / info"},
            "vuln_type": {"type": "string", "description": "类别，如 未授权访问 / SQL注入 / 弱口令 / 反序列化"},
            "asset_id": {"type": "string", "description": "关联的资产 id（purge_asset_query 拿）"},
            "ip": {"type": "string"}, "port": {"type": "integer"},
            "url": {"type": "string"}, "cve": {"type": "string"}, "cvss": {"type": "number"},
            "description": {"type": "string", "description": "原理、影响、复现条件"},
            "evidence": {"type": "string", "description": "原始回显/截图路径，溯源用"},
            "poc": {"type": "string", "description": "验证用的命令或请求"},
            "references": {"type": "array", "items": {"type": "string"}, "description": "参考链接"},
            "status": {"type": "string", "description": "open / confirmed / false-positive / fixed，默认 open"},
            "discovered_by": {"type": "string", "description": "哪个角色报的（recon/assess/vuln-scan/exploit/internal）"},
            "engagement": {"type": "string", "description": "靶标（默认用当前目标）"}},
            "required": ["title"]},
    },
    "purge_vuln_query": {
        "name": "purge_vuln_query",
        "description": "按条件查漏洞台账。动手前先查，避免重复测同一条。",
        "parameters": {"type": "object", "properties": {
            "severity": {"type": "string"}, "status": {"type": "string"},
            "asset_id": {"type": "string"}, "ip": {"type": "string"},
            "vuln_type": {"type": "string"}, "q": {"type": "string", "description": "全文关键词"},
            "limit": {"type": "integer"}, "engagement": {"type": "string"}},
            "required": []},
    },
    "purge_vuln_update": {
        "name": "purge_vuln_update",
        "description": "更新漏洞状态/严重度/证据（open → confirmed → false-positive）。",
        "parameters": {"type": "object", "properties": {
            "id": {"type": "string", "description": "漏洞 id（必填）"},
            "status": {"type": "string"}, "severity": {"type": "string"},
            "evidence": {"type": "string"}, "poc": {"type": "string"},
            "description": {"type": "string"}, "notes": {"type": "string"},
            "cve": {"type": "string"}, "cvss": {"type": "number"},
            "updated_by": {"type": "string"}, "engagement": {"type": "string"}},
            "required": ["id"]},
    },
    "purge_credential_add": {
        "name": "purge_credential_add",
        "description": ("登记凭据（账号/口令/hash/密钥/token/cookie）。拿到就记，凭据落库才算战果；"
                        "valid 标记是否验证过能登录。"),
        "parameters": {"type": "object", "properties": {
            "username": {"type": "string", "description": "账号（必填）"},
            "secret": {"type": "string", "description": "口令/hash/密钥内容"},
            "kind": {"type": "string", "description": "password / hash / key / token / cookie / cert"},
            "service": {"type": "string", "description": "属于什么服务，如 ssh / mysql / 致远OA"},
            "ip": {"type": "string"}, "port": {"type": "integer"},
            "asset_id": {"type": "string"}, "valid": {"type": "boolean", "description": "验证过能登录吗"},
            "source": {"type": "string", "description": "从哪来的（弱口令爆破/配置泄露/内存抓取）"},
            "notes": {"type": "string"}, "discovered_by": {"type": "string"},
            "engagement": {"type": "string"}},
            "required": ["username"]},
    },
    "purge_credential_list": {
        "name": "purge_credential_list",
        "description": "列凭据台账（可按 ip/service/kind/valid 过滤）。",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "service": {"type": "string"}, "kind": {"type": "string"},
            "valid": {"type": "boolean"}, "limit": {"type": "integer"}, "engagement": {"type": "string"}},
            "required": []},
    },
    "purge_access_add": {
        "name": "purge_access_add",
        "description": ("登记一次「拿到了什么权限」（shell/rdp/ssh/webshell/console/database/domain-admin）。"
                        "指挥官靠它判断能不能往内网走。"),
        "parameters": {"type": "object", "properties": {
            "kind": {"type": "string", "description": "shell/rdp/ssh/webshell/console/database/domain-admin/other（必填）"},
            "asset_id": {"type": "string"}, "ip": {"type": "string", "description": "asset_id 或 ip 至少给一个"},
            "level": {"type": "string", "description": "权限级别，如 普通用户 / 管理员 / SYSTEM / 域管"},
            "method": {"type": "string", "description": "怎么拿到的（漏洞利用/弱口令/配置泄露）"},
            "credential_id": {"type": "string", "description": "用哪条凭据拿的"},
            "username": {"type": "string"}, "notes": {"type": "string"},
            "obtained_by": {"type": "string"}, "engagement": {"type": "string"}},
            "required": ["kind"]},
    },
    "purge_access_list": {
        "name": "purge_access_list",
        "description": "列已拿到的权限（评估能不能进内网、能不能收工用这个）。",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "kind": {"type": "string"},
            "limit": {"type": "integer"}, "engagement": {"type": "string"}},
            "required": []},
    },
    "purge_webshell_add": {
        "name": "purge_webshell_add",
        "description": "登记一个 WebShell（URL + 类型 + 连接口令）。传上去就记，别靠脑子记。",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "WebShell 完整 URL（必填）"},
            "type": {"type": "string", "description": "php / jsp / aspx / phpstudy 等"},
            "password": {"type": "string", "description": "连接口令"},
            "ip": {"type": "string"}, "path": {"type": "string"},
            "note": {"type": "string"}, "status": {"type": "string", "description": "live / dead / dropped"},
            "obtained_by": {"type": "string"}, "engagement": {"type": "string"}},
            "required": ["url"]},
    },
    "purge_webshell_list": {
        "name": "purge_webshell_list",
        "description": "列 WebShell（可按 ip/type/status 过滤）。",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "type": {"type": "string"}, "status": {"type": "string"},
            "limit": {"type": "integer"}, "engagement": {"type": "string"}},
            "required": []},
    },
    "purge_webshell_update": {
        "name": "purge_webshell_update",
        "description": "改 WebShell 状态（活着 / 被杀 / 已弃用）。",
        "parameters": {"type": "object", "properties": {
            "id": {"type": "string", "description": "webshell id（必填）"},
            "status": {"type": "string"}, "password": {"type": "string"},
            "note": {"type": "string"}, "url": {"type": "string"}, "type": {"type": "string"},
            "engagement": {"type": "string"}},
            "required": ["id"]},
    },
    "purge_tunnel_add": {
        "name": "purge_tunnel_add",
        "description": ("登记一条隧道/代理（socks/http/端口转发）。进内网第一件事就是记它 —— "
                        "断了要能照着 listen/target 重建。"),
        "parameters": {"type": "object", "properties": {
            "kind": {"type": "string", "description": "socks/socks5/http/portfwd/reverse/vpn/other（必填）"},
            "listen": {"type": "string", "description": "本地监听，如 127.0.0.1:1080"},
            "target": {"type": "string", "description": "转发到哪，如 10.0.0.0/24"},
            "via_host": {"type": "string", "description": "通过哪台机器（跳板）"},
            "ip": {"type": "string"}, "port": {"type": "integer"},
            "tool": {"type": "string", "description": "用什么建的（chisel / frp / ssh -D / nps）"},
            "note": {"type": "string"}, "status": {"type": "string"},
            "created_by": {"type": "string"}, "engagement": {"type": "string"}},
            "required": ["kind"]},
    },
    "purge_tunnel_list": {
        "name": "purge_tunnel_list",
        "description": "列隧道（可按 kind/status/via_host 过滤）。",
        "parameters": {"type": "object", "properties": {
            "kind": {"type": "string"}, "status": {"type": "string"}, "via_host": {"type": "string"},
            "limit": {"type": "integer"}, "engagement": {"type": "string"}},
            "required": []},
    },
    "purge_tunnel_update": {
        "name": "purge_tunnel_update",
        "description": "改隧道状态（活着 / 断了 / 已关闭）。",
        "parameters": {"type": "object", "properties": {
            "id": {"type": "string", "description": "隧道 id（必填）"},
            "status": {"type": "string"}, "note": {"type": "string"},
            "listen": {"type": "string"}, "target": {"type": "string"}, "via_host": {"type": "string"},
            "engagement": {"type": "string"}},
            "required": ["id"]},
    },
}

SCHEMAS.update(_P2B_SCHEMAS)


# ================================================================ 块2 批3a：会话族 + HTTP 证据
_ENG_FILTERS = ("engagement",)


def _lim(args, default=50) -> int:
    try:
        return max(1, min(int(args.get("limit") or default), 500))
    except Exception:
        return default


def purge_engagement_open(args: dict, **kwargs) -> str:
    """打开/创建一次靶标（按单位名），并把当前会话绑上去。"""
    tgt = (args.get("target") or "").strip()
    if not tgt:
        return _j({"ok": False, "error": "没给 target。用法：target='某某单位', scope='192.0.2.0/24,*.example.com'"})
    st = state.set_target(None, tgt, args.get("objective") or "")
    eng = (st.get("engagement") or "").strip() or ledger._slug(tgt)
    p = ledger.purge_root() / "session_bind.json"
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"target": tgt, "engagement": eng,
                                 "scope": args.get("scope") or "", "at": _now_iso()},
                                ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass
    ledger.engage_dir(None, eng)
    return _j({"ok": True, "target": tgt, "engagement": eng, "scope": args.get("scope") or "",
               "dir": str(ledger.engage_dir(None, eng)),
               "note": "后续资产工具默认作用于该靶标"})


def purge_session_bind(args: dict, **kwargs) -> str:
    """把一个已存在的靶标绑给当前会话（省略参数则列出可绑的）。"""
    eng = (args.get("engagement") or "").strip()
    avail = []
    root = ledger.purge_root() / "engagements"
    if root.is_dir():
        avail = sorted([d.name for d in root.iterdir() if d.is_dir()])
    if not eng:
        return _j({"ok": True, "available": avail, "count": len(avail),
                   "note": "没给 engagement 就只列已有靶标"})
    st = state.set_target(None, eng, "")
    real = (st.get("engagement") or "").strip() or ledger._slug(eng)
    ledger.engage_dir(None, real)
    return _j({"ok": True, "engagement": real, "requested": eng, "available": avail})


def purge_session_info(args: dict, **kwargs) -> str:
    """当前绑的是哪个靶标 + 台账条数 + 最近流水。"""
    st = state.load(None)
    eng = ledger.current_engagement(None)
    tb = ledger.summary(None, eng)
    return _j({"ok": True, "target": st.get("target") or "", "mode": st.get("mode") or "normal",
               "engagement": eng, "dir": tb.get("dir"),
               "counts": {k: v for k, v in tb.items() if k not in ("engagement", "dir")},
               "history_tail": (st.get("history") or [])[-5:]})


def purge_sessions(args: dict, **kwargs) -> str:
    """一屏总览所有可复用入口：webshell / 隧道 / 凭据 / 访问。"""
    eng = args.get("engagement")
    n = _lim(args, 10)

    def _alive(rows):
        return sum(1 for r in rows
                   if str(r.get("status") or r.get("state") or "").lower() in ("alive", "online", "ok", "up"))

    ws = ledger.table_read(None, "webshells", eng)
    tun = ledger.table_read(None, "tunnels", eng)
    cre = ledger.table_read(None, "credentials", eng)
    acc = ledger.table_read(None, "access", eng)
    return _j({"ok": True,
               "engagement": ledger._slug(eng) if eng else ledger.current_engagement(None),
               "webshells": {"count": len(ws), "alive": _alive(ws),
                             "items": [{"id": r.get("id"), "url": r.get("url"), "type": r.get("type"),
                                        "status": r.get("status")} for r in ws[:n]]},
               "tunnels": {"count": len(tun), "alive": _alive(tun),
                           "items": [{"id": r.get("id"), "kind": r.get("kind"), "listen": r.get("listen"),
                                      "target": r.get("target"), "status": r.get("status")} for r in tun[:n]]},
               "credentials": {"count": len(cre), "valid": sum(1 for r in cre if r.get("valid")),
                               "items": [{"id": r.get("id"), "username": r.get("username"),
                                          "service": r.get("service"), "ip": r.get("ip"),
                                          "valid": r.get("valid")} for r in cre[:n]]},
               "access": {"count": len(acc),
                          "items": [{"id": r.get("id"), "kind": r.get("kind"), "ip": r.get("ip"),
                                     "level": r.get("level")} for r in acc[:n]]},
               "note": "打内网前先看这里，别重复造轮子"})


def purge_session_check(args: dict, **kwargs) -> str:
    """实测 webshell / 隧道的连通性并回写在线状态。"""
    eng = args.get("engagement")
    try:
        timeout = max(1.0, min(float(args.get("timeout") or 4.0), 30.0))
    except Exception:
        timeout = 4.0
    res = {"ok": True, "webshells": [], "tunnels": []}
    for r in ledger.table_read(None, "webshells", eng):
        url = r.get("url") or ""
        status, detail = "offline", ""
        if url:
            try:
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = "alive" if resp.status < 500 else "offline"
                    detail = "HTTP %s" % resp.status
            except Exception as ex:
                detail = type(ex).__name__ + ": " + str(ex)[:80]
        else:
            detail = "没 url"
        ledger.table_update(None, "webshells", r.get("id"), {"status": status, "checked_at": _now_iso()}, eng)
        res["webshells"].append({"id": r.get("id"), "url": url, "status": status, "detail": detail})
    for r in ledger.table_read(None, "tunnels", eng):
        listen = r.get("listen") or ""
        status, detail = "offline", ""
        host, _, port = listen.rpartition(":")
        if host and port.isdigit():
            try:
                s = socket.create_connection((host, int(port)), timeout=timeout)
                s.close()
                status, detail = "alive", "TCP 通"
            except Exception as ex:
                detail = type(ex).__name__
        else:
            detail = "listen 不是 host:port"
        ledger.table_update(None, "tunnels", r.get("id"), {"status": status, "checked_at": _now_iso()}, eng)
        res["tunnels"].append({"id": r.get("id"), "listen": listen, "status": status, "detail": detail})
    res["alive"] = sum(1 for x in (res["webshells"] + res["tunnels"]) if x["status"] == "alive")
    res["total"] = len(res["webshells"]) + len(res["tunnels"])
    return _j(res)


def purge_agent_slot(args: dict, **kwargs) -> str:
    """子代理并发闸门：同一靶标最多 3 个在跑（args.max 或 REDTEAM_MAX_AGENTS 可覆盖）。"""
    action = (args.get("action") or "status").strip().lower()
    label = (args.get("label") or "").strip()
    key = (args.get("key") or "").strip()
    try:
        maxn = max(1, int(args.get("max") or os.environ.get("REDTEAM_MAX_AGENTS") or 3))
    except Exception:
        maxn = 3
    p = ledger.purge_root() / "slots.json"
    try:
        slots = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
    except Exception:
        slots = {}
    if not isinstance(slots, dict):
        slots = {}
    eng = ledger.current_engagement(None)
    running = slots.get(eng) or {}
    if not isinstance(running, dict):
        running = {}
    if action == "status":
        return _j({"ok": True, "action": "status", "engagement": eng, "max": maxn,
                   "running": len(running), "free": max(0, maxn - len(running)), "slots": running})
    if action == "release":
        rid = key or label
        running.pop(rid, None)
        slots[eng] = running
        p.write_text(json.dumps(slots, ensure_ascii=False, indent=2), encoding="utf-8")
        return _j({"ok": True, "action": "release", "engagement": eng,
                   "running": len(running), "released": rid})
    if action == "acquire":
        if len(running) >= maxn:
            return _j({"ok": False, "action": "acquire", "engagement": eng, "max": maxn,
                       "running": len(running), "slots": running,
                       "error": "名额满了，等一个跑完再占；不要重试硬塞"})
        rid = key or label or ("slot%d" % (len(running) + 1))
        running[rid] = {"label": label or rid, "at": _now_iso()}
        slots[eng] = running
        p.write_text(json.dumps(slots, ensure_ascii=False, indent=2), encoding="utf-8")
        return _j({"ok": True, "action": "acquire", "engagement": eng, "slot": rid,
                   "running": len(running), "free": max(0, maxn - len(running))})
    return _j({"ok": False, "error": "action 只能填 status/acquire/release"})


def purge_role_prompt_reset(args: dict, **kwargs) -> str:
    """清掉靶标级角色稿覆盖，回到 roles.d/ 里的默认稿。"""
    eng = ledger._slug(args.get("engagement") or ledger.current_engagement(None))
    role = (args.get("role") or "").strip()
    d = ledger.purge_root() / "engagements" / eng / "prompts"
    removed = []
    if d.is_dir():
        for f in sorted(d.glob("*.md")):
            if not role or f.stem == role:
                try:
                    f.unlink()
                    removed.append(f.stem)
                except Exception:
                    pass
    return _j({"ok": True, "engagement": eng, "removed": removed,
               "note": "默认稿在 roles.d/<role>.md，删覆盖文件即回到它"})


def purge_http_evidence_add(args: dict, **kwargs) -> str:
    """保存一条 HTTP 证据（原始请求 + 响应）。"""
    req = args.get("request") or ""
    url = (args.get("url") or "").strip()
    if not req and not url:
        return _j({"ok": False, "error": "至少给 request 或 url 之一"})
    rec = {"vuln_id": (args.get("vuln_id") or "").strip(), "asset_id": (args.get("asset_id") or "").strip(),
           "label": (args.get("label") or "").strip(), "method": (args.get("method") or "GET").upper(),
           "url": url, "status": args.get("status"), "request": req,
           "response": args.get("response") or "", "note": (args.get("note") or "").strip(),
           "captured_by": (args.get("captured_by") or "").strip(), "at": _now_iso()}
    saved = ledger.table_append(None, "http_evidence", rec, args.get("engagement"))
    return _j({"ok": True, "evidence": saved,
               "note": "request 要完整可重放（请求行 + Host 等头部 + 必要时 body）"})


_P3A_SCHEMAS = {
    "purge_engagement_open": {
        "name": "purge_engagement_open",
        "description": "打开/创建一次靶标（按单位名）并把当前会话绑上去；已存在则复用其资产库。",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string", "description": "靶标名（单位/项目名，必填）"},
            "scope": {"type": "string", "description": "授权范围，如 192.0.2.0/24,*.example.com"},
            "objective": {"type": "string", "description": "这次要达成什么"}},
            "required": ["target"]}},
    "purge_session_bind": {
        "name": "purge_session_bind",
        "description": "把已存在的靶标绑给当前会话（省略 engagement 则列出可绑的）。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string", "description": "靶标 id 或单位名"}},
            "required": []}},
    "purge_session_info": {
        "name": "purge_session_info",
        "description": "看当前绑的是哪个靶标、台账各族条数、最近流水。开工前先跑。",
        "parameters": {"type": "object", "properties": {}, "required": []}},
    "purge_sessions": {
        "name": "purge_sessions",
        "description": "一屏总览可复用入口：webshell / 隧道 / 凭据 / 访问，含在线统计。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"}, "limit": {"type": "integer"}},
            "required": []}},
    "purge_session_check": {
        "name": "purge_session_check",
        "description": "实测所有 webshell 与隧道的连通性并回写在线状态。开工前和长任务后各跑一次。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"}, "timeout": {"type": "number"}},
            "required": []}},
    "purge_agent_slot": {
        "name": "purge_agent_slot",
        "description": "子代理并发闸门：同靶标最多 3 个在跑。派活前 acquire、结束后 release、看剩余用 status。",
        "parameters": {"type": "object", "properties": {
            "action": {"type": "string", "description": "status / acquire / release"},
            "label": {"type": "string", "description": "这批活是什么"}, "key": {"type": "string"},
            "max": {"type": "integer", "description": "覆盖上限（默认 3）"}},
            "required": []}},
    "purge_role_prompt_reset": {
        "name": "purge_role_prompt_reset",
        "description": "把角色提示词恢复为内置默认（清掉靶标级覆盖）。省略 role 则全部重置。",
        "parameters": {"type": "object", "properties": {
            "engagement": {"type": "string"}, "role": {"type": "string"}},
            "required": []}},
    "purge_http_evidence_add": {
        "name": "purge_http_evidence_add",
        "description": "保存一条 HTTP 证据（原始请求 + 响应），报告里可粘回 Burp/Yakit。request 必须完整可重放。",
        "parameters": {"type": "object", "properties": {
            "vuln_id": {"type": "string"}, "asset_id": {"type": "string"},
            "label": {"type": "string", "description": "这条证据说明什么"},
            "method": {"type": "string"}, "url": {"type": "string"}, "status": {"type": "integer"},
            "request": {"type": "string", "description": "完整原始请求（请求行+头部+body）"},
            "response": {"type": "string", "description": "原始响应（含状态行与头部）"},
            "note": {"type": "string"}, "captured_by": {"type": "string"}, "engagement": {"type": "string"}},
            "required": []}},
}

SCHEMAS.update(_P3A_SCHEMAS)


# ================================================================ 块2 批3b：攻击链 / 攻击文件 / Web / 域名 / 报告
CHAIN_STAGES = [
    ("recon", "① 信息收集（互联网侧）"),
    ("internet-access", "② 互联网资产权限"),
    ("pivot", "③ 边界突破（搭隧道）"),
    ("intranet-access", "④ 内网资产权限"),
    ("target-access", "⑤ 靶标权限"),
]
STAGE_ALIAS = {
    "recon": "recon", "信息收集": "recon", "侦察": "recon",
    "internet-access": "internet-access", "互联网资产权限": "internet-access", "互联网权限": "internet-access",
    "pivot": "pivot", "边界突破": "pivot", "隧道": "pivot",
    "intranet-access": "intranet-access", "内网资产权限": "intranet-access", "内网权限": "intranet-access",
    "target-access": "target-access", "靶标权限": "target-access", "拿下靶标": "target-access",
}


def _stage_of(v) -> str:
    s = str(v or "").strip()
    if not s:
        return "recon"
    return STAGE_ALIAS.get(s, STAGE_ALIAS.get(s.lower(), s))


def _point_of(code) -> float:
    try:
        return float(state.score_default_of(code))
    except Exception:
        return 0.0


def purge_chain_add(args: dict, **kwargs) -> str:
    """记一个攻击链步骤（报告里"这一步怎么来的"全靠它）。"""
    title = (args.get("title") or "").strip()
    if not title:
        return _j({"ok": False, "error": "没给 title。用法：stage='边界突破', title='打点拿 webshell', tool='冰蝎马...', detail='为什么', result='回显 uid=0'"})
    rec = {"stage": _stage_of(args.get("stage")), "stage_name": "",
           "seq": args.get("seq"), "title": title,
           "detail": (args.get("detail") or "").strip(), "tool": (args.get("tool") or "").strip(),
           "result": (args.get("result") or "").strip(), "evidence": (args.get("evidence") or "").strip(),
           "evidence_ref": (args.get("evidence_ref") or "").strip(),
           "asset_id": (args.get("asset_id") or "").strip(), "vuln_id": (args.get("vuln_id") or "").strip(),
           "access_id": (args.get("access_id") or "").strip(),
           "target": (args.get("target") or "").strip(),
           "point_code": (args.get("point_code") or "").strip(),
           "stage_code": (args.get("stage_code") or "").strip(),
           "self_created": bool(args.get("self_created")),
           "recorded_by": (args.get("recorded_by") or "").strip(), "at": _now_iso()}
    for code, label in CHAIN_STAGES:
        if code == rec["stage"]:
            rec["stage_name"] = label
            break
    if not rec["stage_name"]:
        rec["stage_name"] = rec["stage"]
    saved = ledger.table_append(None, "chains", rec, args.get("engagement"))
    return _j({"ok": True, "step": saved, "note": "tool 写实际命令原文，detail 写思路与线索来路，result 写实际回显"})


def purge_chain(args: dict, **kwargs) -> str:
    """读完整攻击链（按 seq 排序），看链路是否闭合。"""
    rows = ledger.table_read(None, "chains", args.get("engagement"))
    def _k(r):
        try:
            return (0, int(r.get("seq")))
        except Exception:
            return (1, 0)
    steps = sorted(rows, key=_k)
    by_stage = {}
    for r in steps:
        s = r.get("stage") or "recon"
        by_stage.setdefault(s, {"stage_name": r.get("stage_name") or s, "count": 0, "steps": []})
        by_stage[s]["count"] += 1
        by_stage[s]["steps"].append({"id": r.get("id"), "seq": r.get("seq"), "title": r.get("title"),
                                     "tool": r.get("tool"), "result": r.get("result")})
    present = [c for c, _ in CHAIN_STAGES if c in by_stage]
    missing = [c for c, _ in CHAIN_STAGES if c not in by_stage]
    return _j({"ok": True, "count": len(steps), "steps": steps,
               "by_stage": by_stage, "stages_present": present, "stages_missing": missing,
               "closed": not missing})


def purge_attack_chain(args: dict, **kwargs) -> str:
    """五阶段视图：每阶段拿了几分、涉及哪些资产、边界隧道是什么。"""
    eng = args.get("engagement")
    chains = ledger.table_read(None, "chains", eng)
    assets = ledger.table_read(None, "assets", eng)
    tunnels = ledger.table_read(None, "tunnels", eng)
    stages = []
    total = 0.0
    for code, label in CHAIN_STAGES:
        mine = [r for r in chains if (r.get("stage") or "") == code]
        pts = sum(_point_of(r.get("point_code") or r.get("stage_code")) for r in mine)
        ids = sorted({r.get("asset_id") for r in mine if r.get("asset_id")})
        total += pts
        item = {"stage": code, "name": label, "steps": len(mine), "points": round(pts, 2),
                "assets": ids}
        if code == "pivot":
            item["tunnels"] = [{"id": t.get("id"), "kind": t.get("kind"), "listen": t.get("listen"),
                                "target": t.get("target")} for t in tunnels]
        stages.append(item)
    reached = [s["stage"] for s in stages if s["steps"] > 0]
    nxt = next((s for s in stages if s["steps"] == 0), None)
    return _j({"ok": True, "engagement": ledger._slug(eng) if eng else ledger.current_engagement(None),
               "stages": stages, "points_total": round(total, 2),
               "reached": reached, "next_stage": (nxt["stage"] if nxt else None),
               "assets_total": len(assets),
               "note": "开工时看它在第几阶段、下一步打哪；汇报时按阶段给结论"})


def purge_attack_path(args: dict, **kwargs) -> str:
    """导出攻击图谱（资产 + 漏洞 + 已控制标记），可选 cidr 缩小范围。"""
    eng = args.get("engagement")
    cidr = (args.get("cidr") or "").strip()
    net = None
    if cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return _j({"ok": False, "error": "cidr 不合法：%s" % cidr})
    owned = {r.get("ip") for r in ledger.table_read(None, "access", eng) if r.get("ip")}
    nodes, edges = [], []
    for a in ledger.table_read(None, "assets", eng):
        ip = a.get("ip") or ""
        if net is not None:
            try:
                if not ipaddress.ip_address(ip) in net:
                    continue
            except Exception:
                continue
        nodes.append({"id": a.get("id"), "ip": ip, "state": a.get("state"),
                      "owned": bool(a.get("id") in owned or ip in owned),
                      "ports": [p.get("port") for p in (a.get("ports") or [])],
                      "meta": {"owned": bool(ip in owned)}})
    for v in ledger.table_read(None, "vulns", eng):
        nodes.append({"id": v.get("id"), "kind": "vuln", "title": v.get("title"),
                      "severity": v.get("severity"), "ip": v.get("ip")})
        if v.get("asset_id"):
            edges.append({"from": v.get("asset_id"), "to": v.get("id"), "rel": "has-vuln"})
    for l in ledger.table_read(None, "links", eng):
        edges.append({"from": l.get("src_id"), "to": l.get("dst_id"),
                      "rel": l.get("rel") or "related"})
    return _j({"ok": True, "cidr": cidr or "*", "nodes": nodes, "edges": edges,
               "counts": {"nodes": len(nodes), "edges": len(edges), "owned": sum(1 for n in nodes if n.get("owned"))}})


def purge_web_list(args: dict, **kwargs) -> str:
    """列 Web 资产（含可访问 URL）。"""
    eng = args.get("engagement")
    cidr = (args.get("cidr") or "").strip()
    net = None
    if cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return _j({"ok": False, "error": "cidr 不合法：%s" % cidr})
    out = []
    for a in ledger.table_read(None, "assets", eng):
        ip = a.get("ip") or ""
        if net is not None:
            try:
                if not ipaddress.ip_address(ip) in net:
                    continue
            except Exception:
                continue
        for p in (a.get("ports") or []):
            svc = str(p.get("service") or "").lower()
            prod = str(p.get("product") or "")
            if svc in ("http", "https") or "http" in prod.lower() or p.get("port") in (80, 443, 8080, 8443):
                scheme = "https" if (svc == "https" or p.get("tls") or p.get("port") in (443, 8443)) else "http"
                host = (a.get("names") or [{}])[0].get("name") if a.get("names") else ip
                port = p.get("port")
                url = "%s://%s%s" % (scheme, host or ip, "" if (scheme == "https" and port == 443)
                                     or (scheme == "http" and port == 80) else ":%s" % port)
                out.append({"asset_id": a.get("id"), "ip": ip, "url": url, "port": port,
                            "product": prod, "title": p.get("title") or "",
                            "server": p.get("server") or ""})
    return _j({"ok": True, "count": len(out[: _lim(args, 100)]), "total": len(out),
               "web": out[: _lim(args, 100)], "note": "做 Web 前先看这里，优先从接口入手"})


def purge_domain_index(args: dict, **kwargs) -> str:
    """按域名聚合资产（主域 / 子域 / C 段关系）。"""
    eng = args.get("engagement")
    idx = {}
    for a in ledger.table_read(None, "assets", eng):
        for nm in (a.get("names") or []):
            name = (nm.get("name") or "").strip() if isinstance(nm, dict) else str(nm).strip()
            if not name:
                continue
            parts = name.split(".")
            root = ".".join(parts[-2:]) if len(parts) >= 2 else name
            idx.setdefault(root, {"root": root, "names": [], "ips": []})
            if name not in idx[root]["names"]:
                idx[root]["names"].append(name)
            if a.get("ip") and a["ip"] not in idx[root]["ips"]:
                idx[root]["ips"].append(a["ip"])
    out = sorted(idx.values(), key=lambda x: (-len(x["names"]), x["root"]))
    return _j({"ok": True, "count": len(out), "domains": out})


def purge_attack_file_add(args: dict, **kwargs) -> str:
    """保存一个**实际生效**的攻击文件（脚本/POC/EXP/字典）到目标文件夹。"""
    name = (args.get("name") or "").strip()
    ev = (args.get("evidence") or "").strip()
    if not name:
        return _j({"ok": False, "error": "没给 name（文件名）"})
    if not ev:
        return _j({"ok": False, "error": "evidence 必填：写清验证效果（如「回显 uid=0」）。没打通的别放进来。"})
    target = (args.get("target") or args.get("ip") or "").strip() or "unknown"
    body = args.get("content") or ""
    saved_path = ""
    if body:
        d = ledger.purge_root() / "engagements" / (ledger._slug(args.get("engagement"))
                                                   if args.get("engagement") else ledger.current_engagement(None)) / "attack-files" / ledger._slug(target)
        try:
            d.mkdir(parents=True, exist_ok=True)
            f = d / Path(name).name
            f.write_text(body, encoding="utf-8")
            saved_path = str(f)
        except Exception as ex:
            return _j({"ok": False, "error": "写文件失败：%s" % ex})
    rec = {"target": target, "name": name, "kind": (args.get("kind") or "").strip(),
           "description": (args.get("description") or "").strip(), "evidence": ev,
           "path": saved_path or (args.get("path") or "").strip(),
           "asset_id": (args.get("asset_id") or "").strip(), "vuln_id": (args.get("vuln_id") or "").strip(),
           "created_by": (args.get("created_by") or "").strip(), "at": _now_iso()}
    saved = ledger.table_append(None, "attack_files", rec, args.get("engagement"))
    return _j({"ok": True, "file": saved, "saved_path": saved_path})


def purge_attack_file_list(args: dict, **kwargs) -> str:
    """列已保存的攻击文件（按目标分组）。"""
    eng = args.get("engagement")
    tgt = (args.get("target") or "").strip()
    rows = ledger.table_read(None, "attack_files", eng)
    if tgt:
        rows = [r for r in rows if (r.get("target") or "") == tgt]
    groups = {}
    for r in rows:
        groups.setdefault(r.get("target") or "unknown", []).append(
            {"id": r.get("id"), "name": r.get("name"), "kind": r.get("kind"),
             "evidence": r.get("evidence"), "path": r.get("path")})
    return _j({"ok": True, "count": len(rows), "by_target": groups,
               "note": "打某个目标前先看这里，别重复造轮子"})


def purge_report_targets(args: dict, **kwargs) -> str:
    """按目标（IP / URL / C 段）看成果：漏洞 / 权限 / 凭据 / 攻击文件 / 攻击链。"""
    eng = args.get("engagement")

    def _rows(t):
        return ledger.table_read(None, t, eng)

    tgt = (args.get("target") or "").strip()
    buckets = {}
    def _b(k):
        return buckets.setdefault(k, {"target": k, "vulns": [], "access": [], "credentials": [],
                                      "attack_files": [], "chains": [], "points": 0.0})
    for v in _rows("vulns"):
        k = v.get("ip") or v.get("asset_id") or "unknown"
        b = _b(k)
        b["vulns"].append({"id": v.get("id"), "title": v.get("title"), "severity": v.get("severity")})
        b["points"] += _point_of(v.get("point_code"))
    for a in _rows("access"):
        _b(a.get("ip") or a.get("asset_id") or "unknown")["access"].append(
            {"id": a.get("id"), "kind": a.get("kind"), "level": a.get("level")})
    for c in _rows("credentials"):
        _b(c.get("ip") or "unknown")["credentials"].append(
            {"id": c.get("id"), "username": c.get("username"), "service": c.get("service"), "valid": c.get("valid")})
    for f in _rows("attack_files"):
        _b(f.get("target") or "unknown")["attack_files"].append({"id": f.get("id"), "name": f.get("name")})
    for s in _rows("chains"):
        _b(s.get("target") or "unknown")["chains"].append(
            {"id": s.get("id"), "stage": s.get("stage"), "title": s.get("title")})
        b = _b(s.get("target") or "unknown")
        b["points"] += _point_of(s.get("point_code") or s.get("stage_code"))
    out = sorted(buckets.values(), key=lambda x: -x["points"])
    if tgt:
        out = [b for b in out if b["target"] == tgt]
        if not out:
            return _j({"ok": True, "target": tgt, "found": False,
                       "note": "该目标暂无台账记录"})
    for b in out:
        b["points"] = round(b["points"], 2)
        b["missing"] = [x for x in ("vulns", "access", "credentials") if not b[x]]
    return _j({"ok": True, "count": len(out), "targets": out,
               "note": "（上游已弃用本工具、改用计分报告；Hermes 侧保留做按目标查台账）"})


_P3B_SCHEMAS = {
    "purge_chain_add": {
        "name": "purge_chain_add",
        "description": "记一个攻击链步骤。报告里「这一步怎么来的」全靠它：tool 写实际命令原文，detail 写思路与线索来路，result 写实际回显。",
        "parameters": {"type": "object", "properties": {
            "stage": {"type": "string", "description": "五个阶段之一：信息收集/互联网资产权限/边界突破/内网资产权限/靶标权限"},
            "seq": {"type": "integer", "description": "序号（排序用）"},
            "title": {"type": "string", "description": "这一步干了什么（必填）"},
            "detail": {"type": "string", "description": "为什么这么做、线索从哪来"},
            "tool": {"type": "string", "description": "实际用的命令原文"},
            "result": {"type": "string", "description": "实际回显/结果"},
            "evidence": {"type": "string"}, "evidence_ref": {"type": "string"},
            "asset_id": {"type": "string"}, "vuln_id": {"type": "string"}, "access_id": {"type": "string"},
            "target": {"type": "string"}, "point_code": {"type": "string"}, "stage_code": {"type": "string"},
            "self_created": {"type": "boolean", "description": "是不是自己写的工具/脚本"},
            "recorded_by": {"type": "string"}, "engagement": {"type": "string"}},
            "required": ["title"]}},
    "purge_chain": {
        "name": "purge_chain",
        "description": "读完整攻击链（按 seq 排序），检查链路是否闭合：入口 → 权限 → 内网突破。",
        "parameters": {"type": "object", "properties": {"engagement": {"type": "string"}}, "required": []}},
    "purge_attack_chain": {
        "name": "purge_attack_chain",
        "description": "五阶段视图（信息收集→互联网权限→边界突破→内网权限→靶标权限），含各阶段得分与边界隧道。",
        "parameters": {"type": "object", "properties": {"engagement": {"type": "string"}}, "required": []}},
    "purge_attack_path": {
        "name": "purge_attack_path",
        "description": "导出攻击图谱（资产 + 漏洞 + 已控制标记）,用于横向路径规划与战果汇报。",
        "parameters": {"type": "object", "properties": {
            "cidr": {"type": "string", "description": "可选，缩小范围如 10.0.0.0/24"},
            "engagement": {"type": "string"}}, "required": []}},
    "purge_web_list": {
        "name": "purge_web_list",
        "description": "列 Web 资产（含可直接访问的 URL）。做 Web 渗透前先看这里。",
        "parameters": {"type": "object", "properties": {
            "cidr": {"type": "string"}, "limit": {"type": "integer"}, "engagement": {"type": "string"}},
            "required": []}},
    "purge_domain_index": {
        "name": "purge_domain_index",
        "description": "按域名维度聚合资产：每个域名关联了哪些 IP/资产。梳理主域、子域与 C 段关系。",
        "parameters": {"type": "object", "properties": {"engagement": {"type": "string"}}, "required": []}},
    "purge_attack_file_add": {
        "name": "purge_attack_file_add",
        "description": "保存一个实际生效的攻击文件（脚本/POC/EXP/字典）。evidence 必填且要写清验证效果；没打通的别放进来。",
        "parameters": {"type": "object", "properties": {
            "name": {"type": "string", "description": "文件名（必填）"},
            "target": {"type": "string", "description": "目标文件夹（IP / URL 主机 / C 段）"},
            "kind": {"type": "string", "description": "脚本 / POC / EXP / 字典"},
            "description": {"type": "string"}, "evidence": {"type": "string", "description": "验证效果，如「回显 uid=0」（必填）"},
            "content": {"type": "string", "description": "文件正文（给了就落盘）"},
            "path": {"type": "string"}, "asset_id": {"type": "string"}, "vuln_id": {"type": "string"},
            "created_by": {"type": "string"}, "engagement": {"type": "string"}},
            "required": ["name", "evidence"]}},
    "purge_attack_file_list": {
        "name": "purge_attack_file_list",
        "description": "列已保存的攻击文件（按目标文件夹分组）。打某目标前先看这里。",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string"}, "engagement": {"type": "string"}}, "required": []}},
    "purge_report_targets": {
        "name": "purge_report_targets",
        "description": "按目标（IP/URL/C 段）看成果：漏洞 / 权限 / 凭据 / 攻击文件 / 攻击链，并标出还缺什么。",
        "parameters": {"type": "object", "properties": {
            "target": {"type": "string"}, "engagement": {"type": "string"}}, "required": []}},
}

SCHEMAS.update(_P3B_SCHEMAS)


# ================================================================ 块2 批3c：POC 知识库 + 得分面板
def poc_kb_path() -> Path:
    return ledger.purge_root() / "poc_kb.json"


def poc_kb_read() -> list:
    p = poc_kb_path()
    if not p.is_file():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else []
    except Exception:
        return []


def poc_kb_write(rows: list) -> None:
    p = poc_kb_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def _score_points_all() -> list:
    """内置 25 项 + 用户改过的覆盖。"""
    base = list(state.SCORE_POINTS or [])
    custom = {}
    p = ledger.purge_root() / "score_points_custom.json"
    if p.is_file():
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(d, list):
                custom = {x.get("code") or x.get("name"): x for x in d if isinstance(x, dict)}
            elif isinstance(d, dict):
                custom = d
        except Exception:
            custom = {}
    out = []
    for p0 in base:
        c = dict(p0)
        c.update(custom.get(c.get("code")) or {})
        out.append(c)
    for k, v in custom.items():
        if not any(x.get("code") == k or x.get("name") == k for x in out):
            out.append(v)
    return out


def purge_score_list(args: dict, **kwargs) -> str:
    """得分面板：所有得分点（分值/分类/是否拿下/证据）+ 总分进度。"""
    eng = args.get("engagement")
    ledger.PURGE_LOCK = None
    hits = []
    p = state.ledger_path()
    if p.is_file():
        try:
            for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    r = json.loads(ln)
                except Exception:
                    continue
                if eng and (r.get("engagement") or "") != ledger._slug(eng):
                    continue
                hits.append(r)
        except Exception:
            hits = []
    got = {}
    for h in hits:
        k = h.get("code") or h.get("kind")
        got.setdefault(k, {"count": 0, "score": 0.0, "evidence": []})
        got[k]["count"] += 1
        got[k]["score"] += float(h.get("score") or 0)
        if h.get("evidence"):
            got[k]["evidence"].append(str(h.get("evidence"))[:120])
    pts = []
    total_got = 0.0
    total_all = 0.0
    for x in _score_points_all():
        k = x.get("code")
        g = got.get(k) or got.get(x.get("name"))
        v = float(g["score"] if g else 0.0)
        d = float(x.get("default") or 0)
        total_got += v
        total_all += d
        pts.append({"code": k, "name": x.get("name"), "group": x.get("group"),
                    "default": d, "hit": bool(g), "count": (g["count"] if g else 0),
                    "score": round(v, 2), "evidence": (g["evidence"] if g else [])[:3]})
    unlisted = [{"key": k, "count": v["count"], "score": round(v["score"], 2)}
                for k, v in got.items() if not any(p2.get("code") == k or p2.get("name") == k for p2 in pts)]
    return _j({"ok": True, "engagement": ledger._slug(eng) if eng else "全部",
               "points": pts, "unlisted": unlisted,
               "total_score": round(total_got, 2), "total_possible": round(total_all, 2),
               "hit_count": sum(1 for x in pts if x["hit"]), "point_count": len(pts),
               "note": "规划下一步前先看这里，按分值高低决定先打什么"})


def purge_score_hit(args: dict, **kwargs) -> str:
    """记一次得分（走计分账本，同一条 kind 可多次）。"""
    code = (args.get("code") or args.get("point_id") or args.get("point_name") or "").strip()
    if not code:
        return _j({"ok": False, "error": "没给 code/point_id/point_name。用法：code='central-system' 或 point_name='控制集权系统'"})
    p = state.score_point_of(code) or state.score_point_of(args.get("point_name") or "")
    kind = code
    if p:
        kind = p.get("code")
    entry = {"engagement": ledger._slug(args.get("engagement") or ledger.current_engagement(None)),
             "target": (args.get("target") or "").strip(), "kind": kind,
             "evidence": (args.get("evidence") or "").strip(),
             "note": (args.get("note") or "").strip(),
             "score": args.get("points"), "verified": bool(args.get("evidence"))}
    rec = state.ledger_add(entry)
    extra = {"asset_id": args.get("asset_id"), "port": args.get("port"), "vuln_id": args.get("vuln_id"),
             "step_id": args.get("step_id"), "self_created": args.get("self_created"),
             "recorded_by": args.get("recorded_by")}
    rec["extra"] = {k: v for k, v in extra.items() if v not in (None, "")}
    return _j({"ok": True, "recorded": rec,
               "matched_point": ({"code": p.get("code"), "name": p.get("name"),
                                  "group": p.get("group"), "default": p.get("default")} if p else None),
               "note": "查不到得分点就按 5 分兜底；要加新得分点用 purge_score_point_save"})


def purge_score_point_save(args: dict, **kwargs) -> str:
    """新增/修改得分点（带 id 或 code 为改，不带为增）。"""
    name = (args.get("name") or "").strip()
    code = (args.get("code") or "").strip()
    pid = (args.get("id") or "").strip()
    if not name and not code:
        return _j({"ok": False, "error": "至少要给 name 或 code"})
    p = ledger.purge_root() / "score_points_custom.json"
    rows = []
    if p.is_file():
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            rows = d if isinstance(d, list) else []
        except Exception:
            rows = []
    key = pid or code or name
    rec = {"id": pid or key, "code": code or ledger._slug(name), "name": name or code,
           "category": (args.get("category") or "").strip(), "group": (args.get("category") or "").strip(),
           "points": args.get("points"), "default": args.get("points"),
           "description": (args.get("description") or "").strip(),
           "enabled": bool(args.get("enabled", True)), "updated_at": _now_iso()}
    hit = False
    for i, r in enumerate(rows):
        if (r.get("id") == key) or (r.get("code") and r.get("code") == key):
            rows[i] = dict(r, **{k: v for k, v in rec.items() if v is not None})
            hit = True
            break
    if not hit:
        rows.append({k: v for k, v in rec.items() if v is not None})
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return _j({"ok": True, "action": ("updated" if hit else "created"), "point": rec,
               "total_custom": len(rows)})


def purge_score_report(args: dict, **kwargs) -> str:
    """攻击得分链路复现报告：只收录拿到分的成果，附可复现原始请求。"""
    eng = args.get("engagement")
    limit = _lim(args, 50)
    hits = []
    p = state.ledger_path()
    if p.is_file():
        try:
            for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    r = json.loads(ln)
                except Exception:
                    continue
                if eng and (r.get("engagement") or "") != ledger._slug(eng):
                    continue
                if float(r.get("score") or 0) <= 0:
                    continue
                hits.append(r)
        except Exception:
            hits = []
    ev = ledger.table_read(None, "http_evidence", eng)
    chains = ledger.table_read(None, "chains", eng)
    total = sum(float(h.get("score") or 0) for h in hits)
    groups = {}
    for h in hits:
        g = h.get("group") or "未分类"
        groups.setdefault(g, {"group": g, "score": 0.0, "items": []})
        groups[g]["score"] += float(h.get("score") or 0)
        groups[g]["items"].append(h)
    out = []
    for g in sorted(groups.values(), key=lambda x: -x["score"]):
        g["score"] = round(g["score"], 2)
        g["items"] = g["items"][:limit]
        out.append(g)
    md = []
    md.append("# 攻击得分链路复现报告")
    md.append("")
    md.append("- 靶标：%s" % (eng or ledger.current_engagement(None)))
    md.append("- 得分项：%d 条 / 总分 **%s**" % (len(hits), round(total, 2)))
    md.append("- 生成时间：%s" % _now_iso())
    md.append("")
    for g in out:
        md.append("## %s（%s 分，%d 项）" % (g["group"], g["score"], len(g["items"])))
        for h in g["items"]:
            md.append("")
            md.append("- **[%s] %s** — %s 分" % (h.get("code") or h.get("kind"), h.get("kind"), h.get("score")))
            if h.get("target"):
                md.append("  - 目标：%s" % h.get("target"))
            if h.get("evidence"):
                md.append("  - 证据：%s" % h.get("evidence"))
            if h.get("note"):
                md.append("  - 说明：%s" % h.get("note"))
        md.append("")
    if ev:
        md.append("## 可复现原始请求（%d 条）" % len(ev))
        for e in ev[:limit]:
            md.append("")
            md.append("### %s — %s" % (e.get("label") or e.get("url"), e.get("id")))
            md.append("```http")
            md.append((e.get("request") or "").rstrip())
            md.append("")
            md.append((e.get("response") or "").rstrip())
            md.append("```")
    if chains:
        md.append("")
        md.append("## 攻击链")
        for c in chains:
            md.append("- (%s) %s — %s" % (c.get("stage_name") or c.get("stage"), c.get("title"),
                                          (c.get("result") or "")[:80]))
    body = "\n".join(md)
    res = {"ok": True, "groups": out, "total_score": round(total, 2), "count": len(hits),
           "evidence_count": len(ev), "chain_count": len(chains)}
    if args.get("markdown"):
        res["markdown"] = body
    else:
        res["markdown"] = body
    return _j(res)


def _nuclei_dirs() -> list:
    out = []
    for c in (Path.home() / "nuclei-templates", Path.home() / ".local" / "nuclei-templates",
              Path.home() / "nuclei_templates"):
        if c.is_dir():
            out.append(c)
    env = os.environ.get("NUCLEI_TEMPLATES")
    if env and Path(env).is_dir():
        out.append(Path(env))
    return out


def purge_poc_search(args: dict, **kwargs) -> str:
    """打 Nday 前先查现成的：本机知识库 + nuclei 模板库。"""
    q = (args.get("q") or "").strip().lower()
    cve = (args.get("cve") or "").strip().lower()
    comp = (args.get("component") or "").strip().lower()
    kind = (args.get("kind") or "").strip()
    lang = (args.get("language") or "").strip()
    src = (args.get("source") or "").strip()
    ver = args.get("verified")
    n = _lim(args, 20)

    def _hit(r):
        if cve and cve not in str(r.get("cve") or "").lower():
            return False
        if comp and comp not in " ".join([str(r.get("component") or ""), str(r.get("title") or ""),
                                          str(r.get("description") or "")]).lower():
            return False
        if kind and (r.get("kind") or "") != kind:
            return False
        if lang and (r.get("language") or "") != lang:
            return False
        if src and (r.get("source") or "") != src:
            return False
        if ver is not None and bool(r.get("verified")) != bool(ver):
            return False
        if q:
            blob = " ".join([str(r.get("title") or ""), str(r.get("description") or ""),
                             str(r.get("component") or ""), str(r.get("cve") or ""),
                             str(r.get("usage") or ""), " ".join(r.get("tags") or [])]).lower()
            if q not in blob:
                return False
        return True

    rows = [r for r in poc_kb_read() if _hit(r)]
    rows.sort(key=lambda r: (not bool(r.get("verified")), -int(r.get("use_count") or 0)))
    kb = [{"id": r.get("id"), "code": r.get("code"), "title": r.get("title"), "kind": r.get("kind"),
           "component": r.get("component"), "cve": r.get("cve"), "verified": bool(r.get("verified")),
           "use_count": int(r.get("use_count") or 0), "path": r.get("path"), "source": r.get("source")}
          for r in rows[:n]]
    tpls = []
    for d in _nuclei_dirs():
        try:
            for f in d.rglob("*.yaml"):
                nm = f.name.lower()
                if q and q not in nm and (not comp or comp not in nm) and (not cve or cve not in nm):
                    continue
                tpls.append({"template": f.name, "path": str(f)})
                if len(tpls) >= n:
                    break
        except Exception:
            pass
        if len(tpls) >= n:
            break
    return _j({"ok": True, "knowledge_base": {"count": len(rows), "items": kb},
               "nuclei": {"count": len(tpls), "dirs": [str(x) for x in _nuclei_dirs()], "items": tpls},
               "note": "知识库用 purge_poc_get 拿全文；模板直接 nuclei -t <path> -u <target>"})


def _poc_find(rows, pid, code):
    for r in rows:
        if pid and r.get("id") == pid:
            return r
        if code and r.get("code") == code:
            return r
    return None


def purge_poc_get(args: dict, **kwargs) -> str:
    """取一条知识库 POC/EXP 的完整内容。"""
    pid = (args.get("id") or "").strip()
    code = (args.get("code") or "").strip()
    if not pid and not code:
        return _j({"ok": False, "error": "给 id 或 code 之一"})
    r = _poc_find(poc_kb_read(), pid, code)
    if not r:
        return _j({"ok": False, "error": "知识库里没这条：%s" % (pid or code)})
    body = r.get("content") or ""
    if not body and r.get("path"):
        try:
            p = Path(r["path"])
            if p.is_file():
                body = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    return _j({"ok": True, "poc": r, "content": body})


def purge_poc_add(args: dict, **kwargs) -> str:
    """把通用可复用的 POC/EXP 落进知识库（跨靶标共享）。"""
    title = (args.get("title") or "").strip()
    if not title:
        return _j({"ok": False, "error": "没给 title"})
    rows = poc_kb_read()
    code = (args.get("code") or "").strip() or ("poc-" + ledger._slug(title).lower()[:40])
    exist = _poc_find(rows, "", code)
    saved_path = (args.get("path") or "").strip()
    body = args.get("content") or ""
    if body and not saved_path:
        d = ledger.purge_root() / "poc_kb"
        try:
            d.mkdir(parents=True, exist_ok=True)
            fn = (args.get("filename") or (code + ".txt"))
            f = d / Path(fn).name
            f.write_text(body, encoding="utf-8")
            saved_path = str(f)
        except Exception as ex:
            return _j({"ok": False, "error": "落盘失败：%s" % ex})
    rec = {"code": code, "title": title, "kind": (args.get("kind") or "POC"),
           "category": (args.get("category") or "").strip(), "cve": (args.get("cve") or "").strip(),
           "component": (args.get("component") or "").strip(), "versions": (args.get("versions") or "").strip(),
           "severity": (args.get("severity") or "").strip(), "language": (args.get("language") or "").strip(),
           "source": (args.get("source") or "").strip(), "source_url": (args.get("source_url") or "").strip(),
           "description": (args.get("description") or "").strip(), "usage": (args.get("usage") or "").strip(),
           "content": body, "path": saved_path, "filename": (args.get("filename") or ""),
           "verified": bool(args.get("verified")), "verified_note": (args.get("verified_note") or "").strip(),
           "tags": list(args.get("tags") or []), "use_count": 0, "used_on": [],
           "created_by": (args.get("created_by") or "").strip(),
           "found_by_agent": (args.get("found_by_agent") or "").strip(),
           "asset_target": (args.get("asset_target") or "").strip(),
           "created_at": _now_iso(), "updated_at": _now_iso()}
    if exist:
        for i, r in enumerate(rows):
            if r is exist:
                rows[i] = dict(r, **rec)
                rows[i]["id"] = r.get("id")
                rows[i]["created_at"] = r.get("created_at") or _now_iso()
                break
        act = "updated"
    else:
        rec["id"] = "kb%04d" % (len(rows) + 1)
        rows.append(rec)
        act = "created"
    poc_kb_write(rows)
    return _j({"ok": True, "action": act, "code": code, "saved_path": saved_path,
               "poc": _poc_find(rows, "", code),
               "note": "只对本次靶标有效的脚本走 purge_attack_file_add，别混进知识库"})


def purge_poc_list(args: dict, **kwargs) -> str:
    """列知识库里的 POC/EXP。"""
    rows = poc_kb_read()
    kind = (args.get("kind") or "").strip()
    comp = (args.get("component") or "").strip()
    src = (args.get("source") or "").strip()
    ver = args.get("verified")
    out = []
    for r in rows:
        if kind and (r.get("kind") or "") != kind:
            continue
        if comp and comp not in str(r.get("component") or ""):
            continue
        if src and (r.get("source") or "") != src:
            continue
        if ver is not None and bool(r.get("verified")) != bool(ver):
            continue
        out.append({"id": r.get("id"), "code": r.get("code"), "title": r.get("title"),
                    "kind": r.get("kind"), "component": r.get("component"), "cve": r.get("cve"),
                    "verified": bool(r.get("verified")), "use_count": int(r.get("use_count") or 0),
                    "path": r.get("path")})
    out.sort(key=lambda r: (not r["verified"], -r["use_count"]))
    return _j({"ok": True, "count": len(out), "total": len(rows), "items": out[:_lim(args, 100)]})


def purge_poc_update(args: dict, **kwargs) -> str:
    """更新知识库条目（补验证结论 / 改版本 / 补正文）。"""
    pid = (args.get("id") or "").strip()
    code = (args.get("code") or "").strip()
    if not pid and not code:
        return _j({"ok": False, "error": "给 id 或 code 之一"})
    rows = poc_kb_read()
    r = _poc_find(rows, pid, code)
    if not r:
        return _j({"ok": False, "error": "知识库里没这条：%s" % (pid or code)})
    patch_d = args.get("patch") if isinstance(args.get("patch"), dict) else {}
    allowed = ("title", "kind", "category", "cve", "component", "versions", "severity", "language",
               "source", "source_url", "description", "usage", "content", "path", "filename",
               "verified", "verified_note", "tags")
    for k in allowed:
        if args.get(k) is not None:
            patch_d[k] = args.get(k)
    if args.get("verified") is not None:
        patch_d["verified"] = bool(args.get("verified"))
    if args.get("verified_note") is not None:
        patch_d["verified_note"] = args.get("verified_note")
    r.update(patch_d)
    r["updated_at"] = _now_iso()
    poc_kb_write(rows)
    return _j({"ok": True, "poc": r, "changed": sorted(patch_d.keys())})


def purge_poc_use(args: dict, **kwargs) -> str:
    """记一次复用（用在哪个靶标）。"""
    pid = (args.get("id") or "").strip()
    code = (args.get("code") or "").strip()
    if not pid and not code:
        return _j({"ok": False, "error": "给 id 或 code 之一"})
    rows = poc_kb_read()
    r = _poc_find(rows, pid, code)
    if not r:
        return _j({"ok": False, "error": "知识库里没这条：%s" % (pid or code)})
    r["use_count"] = int(r.get("use_count") or 0) + 1
    used = list(r.get("used_on") or [])
    u = (args.get("used_on") or ledger.current_engagement(None)).strip()
    if u:
        used.append({"on": u, "at": _now_iso()})
    r["used_on"] = used[-20:]
    r["updated_at"] = _now_iso()
    poc_kb_write(rows)
    return _j({"ok": True, "code": r.get("code"), "use_count": r["use_count"], "used_on": r["used_on"][-1]})


_P3C_SCHEMAS = {
    "purge_poc_search": {
        "name": "purge_poc_search",
        "description": "打 Nday/1day 前先查现成的：① 本机知识库（跨靶标共享，按已验证→复用次数排序）② 本机 nuclei 模板库。命中就取用。",
        "parameters": {"type": "object", "properties": {
            "q": {"type": "string", "description": "关键词"}, "cve": {"type": "string"},
            "component": {"type": "string", "description": "组件名，如 致远OA / 用友NC"},
            "kind": {"type": "string"}, "category": {"type": "string"},
            "asset_target": {"type": "string"}, "language": {"type": "string"},
            "source": {"type": "string"}, "verified": {"type": "boolean"},
            "limit": {"type": "integer"}, "engagement": {"type": "string"}},
            "required": []}},
    "purge_poc_get": {
        "name": "purge_poc_get",
        "description": "取一条知识库 POC/EXP 的完整内容（正文 + 用法 + 验证记录 + 落盘路径）。",
        "parameters": {"type": "object", "properties": {
            "id": {"type": "string"}, "code": {"type": "string"}}, "required": []}},
    "purge_poc_add": {
        "name": "purge_poc_add",
        "description": "把通用可复用的 POC/EXP 落进知识库（跨靶标共享）。只收录真正有效的；只对本次靶标有效的走 purge_attack_file_add。",
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string", "description": "标题（必填）"},
            "kind": {"type": "string", "description": "POC / EXP / 字典 / 工具"},
            "category": {"type": "string"}, "cve": {"type": "string"},
            "component": {"type": "string"}, "versions": {"type": "string"},
            "severity": {"type": "string"}, "language": {"type": "string"},
            "source": {"type": "string"}, "source_url": {"type": "string"},
            "description": {"type": "string"}, "usage": {"type": "string", "description": "怎么用"},
            "content": {"type": "string", "description": "正文"}, "path": {"type": "string"},
            "filename": {"type": "string"}, "verified": {"type": "boolean"},
            "verified_note": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}},
            "created_by": {"type": "string"}, "found_by_agent": {"type": "string"},
            "asset_target": {"type": "string"}, "engagement": {"type": "string"}},
            "required": ["title"]}},
    "purge_poc_list": {
        "name": "purge_poc_list",
        "description": "列知识库里的 POC/EXP（可按 kind/verified/component 过滤）。盘点手上已有哪些武器。",
        "parameters": {"type": "object", "properties": {
            "kind": {"type": "string"}, "verified": {"type": "boolean"},
            "component": {"type": "string"}, "source": {"type": "string"},
            "limit": {"type": "integer"}}, "required": []}},
    "purge_poc_update": {
        "name": "purge_poc_update",
        "description": "更新知识库条目：补验证结论、修正影响版本、补用法或正文、改标签。实战验证通过后一定回来置 verified=true。",
        "parameters": {"type": "object", "properties": {
            "id": {"type": "string"}, "code": {"type": "string"},
            "patch": {"type": "object", "description": "要改的字段（可选）"},
            "verified": {"type": "boolean"}, "verified_note": {"type": "string"},
            "usage": {"type": "string"}, "content": {"type": "string"},
            "versions": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}},
            "required": []}},
    "purge_poc_use": {
        "name": "purge_poc_use",
        "description": "记一次知识库 POC/EXP 的复用（用在哪个靶标/目标）。复用次数高的排前面。",
        "parameters": {"type": "object", "properties": {
            "id": {"type": "string"}, "code": {"type": "string"},
            "used_on": {"type": "string"}}, "required": []}},
    "purge_score_list": {
        "name": "purge_score_list",
        "description": "得分目标面板：所有得分点（分值/分类/是否拿下/证据）与总分进度。每次规划下一步前先看这里。",
        "parameters": {"type": "object", "properties": {"engagement": {"type": "string"}}, "required": []}},
    "purge_score_hit": {
        "name": "purge_score_hit",
        "description": "记录一次得分（25 项得分点，按 code 或中文名匹配）。拿到成果就记，附证据。",
        "parameters": {"type": "object", "properties": {
            "code": {"type": "string", "description": "得分点 code，如 central-system"},
            "point_id": {"type": "string"}, "point_name": {"type": "string", "description": "中文名，如 控制集权系统"},
            "points": {"type": "number", "description": "覆盖分值（一般不用填，按规则自动）"},
            "target": {"type": "string"}, "asset_id": {"type": "string"}, "port": {"type": "integer"},
            "vuln_id": {"type": "string"}, "step_id": {"type": "string"},
            "evidence": {"type": "string", "description": "命中证据（写了才算已验证）"},
            "self_created": {"type": "boolean"}, "note": {"type": "string"},
            "recorded_by": {"type": "string"}, "engagement": {"type": "string"}},
            "required": []}},
    "purge_score_point_save": {
        "name": "purge_score_point_save",
        "description": "新增或修改得分点（分值/名称/分类/说明/启用）。带 id 或 code 为修改，不带为新增。",
        "parameters": {"type": "object", "properties": {
            "id": {"type": "string"}, "name": {"type": "string"}, "code": {"type": "string"},
            "category": {"type": "string"}, "points": {"type": "number"},
            "description": {"type": "string"}, "enabled": {"type": "boolean"},
            "engagement": {"type": "string"}}, "required": []}},
    "purge_score_report": {
        "name": "purge_score_report",
        "description": "攻击得分链路复现报告：只收录拿到分的成果，附可粘进 Yakit Repeater 复现的原始请求。交付报告用这个。",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "integer"}, "markdown": {"type": "boolean"},
            "engagement": {"type": "string"}}, "required": []}},
}

SCHEMAS.update(_P3C_SCHEMAS)


# ================================================================ 块5：目标卡（对齐上游 engagement.yaml）
def _objective_path(eng: str) -> Path:
    return ledger.engage_dir(None, eng) / "engagement.yaml"


def _objective_write(eng: str, target_name: str, scope_cidrs: list, objective: str = "",
                     extra: dict = None) -> Path:
    p = _objective_path(eng)
    p.parent.mkdir(parents=True, exist_ok=True)
    scope = [str(x).strip() for x in (scope_cidrs or []) if str(x).strip()]
    lines = [
        "# 目标卡（engagement.yaml）",
        "target_name: %s" % target_name,
        "scope_cidrs: [%s]" % ", ".join(scope),
        "objective: %s" % (objective or ""),
        "created_at: %s" % _now_iso(),
        "updated_at: %s" % _now_iso(),
    ]
    for k, v in (extra or {}).items():
        if v in (None, ""):
            continue
        lines.append("%s: %s" % (k, v))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _objective_read(eng: str) -> dict:
    p = _objective_path(eng)
    if not p.is_file():
        return {}
    out = {}
    try:
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", ln)
            if not m:
                continue
            k, v = m.group(1), m.group(2).strip()
            if v.startswith("[") and v.endswith("]"):
                out[k] = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
            else:
                out[k] = v.strip("'\"")
    except Exception:
        return {}
    return out


def _objective_card_text(eng: str) -> str:
    """上游 readObjectiveCard 的等价物：没有目标就返回空串，不编。"""
    meta = _objective_read(eng)
    name = str(meta.get("target_name") or "").strip()
    if not name:
        return ""
    scope = [str(x).strip() for x in (meta.get("scope_cidrs") or []) if str(x).strip()]
    scope_line = "、".join(scope) if scope else "只打这个单位名下的资产"
    return "\n".join([
        "## 本次目标",
        "只打：%s" % name,
        "范围：%s" % scope_line,
        "不打：回报里带出来的其它单位。只有用户明确说出新的单位名称，才改打新目标。",
    ])


def purge_objective_card(args: dict, **kwargs) -> str:
    """取当前靶标的目标卡（拼进系统提示词/角色稿的那段）。也可用来核对范围。"""
    eng = (args.get("engagement") or "").strip() or ledger.current_engagement(None)
    meta = _objective_read(eng)
    name = str(meta.get("target_name") or "").strip()
    if not name:
        return _j({"ok": False, "engagement": eng,
                   "error": "这个靶标还没有目标卡。先 purge_objective(target=..., scope=[...]) 立卡"})
    scope = [str(x).strip() for x in (meta.get("scope_cidrs") or []) if str(x).strip()]
    return _j({"ok": True, "engagement": eng, "target_name": name, "scope_cidrs": scope,
               "objective": meta.get("objective") or "",
               "card": _objective_card_text(eng), "path": str(_objective_path(eng))})


def purge_objective_card_save(args: dict, **kwargs) -> str:
    """直接改目标卡：补/改范围 CIDR、改单位名、补充目的。不重开模式。"""
    eng = (args.get("engagement") or "").strip() or ledger.current_engagement(None)
    meta = _objective_read(eng)
    name = (args.get("target_name") or args.get("target") or "").strip() or str(meta.get("target_name") or "").strip()
    if not name:
        return _j({"ok": False, "error": "没给单位名，也没有现存目标卡"})
    scope = args.get("scope") or args.get("scope_cidrs")
    if scope is None:
        scope = meta.get("scope_cidrs") or []
    if isinstance(scope, str):
        scope = [s.strip() for s in scope.split(",") if s.strip()]
    obj = (args.get("objective") or "").strip() or str(meta.get("objective") or "")
    bad = []
    for c in scope:
        try:
            ipaddress.ip_network(str(c), strict=False)
        except Exception:
            bad.append(str(c))
    p = _objective_write(eng, name, scope, obj)
    return _j({"ok": True, "engagement": eng, "target_name": name, "scope_cidrs": list(scope),
               "invalid_cidrs": bad, "card": _objective_card_text(eng), "path": str(p),
               "note": "非法 CIDR 只是提示，没挡；确认后可用 purge_objective 重立"})


_P5_SCHEMAS = {
    "purge_objective_card": {
        "name": "purge_objective_card",
        "description": "取当前靶标的目标卡（只打谁/范围/不打谁）。拼角色提示词时用它，没有卡会明说没有、不编目标。",
        "parameters": {"type": "object", "properties": {"engagement": {"type": "string"}}, "required": []}},
    "purge_objective_card_save": {
        "name": "purge_objective_card_save",
        "description": "改目标卡：单位名 / 范围 CIDR / 目的。落成 engagement.yaml，不改模式、不清战果。",
        "parameters": {"type": "object", "properties": {
            "target_name": {"type": "string"}, "target": {"type": "string"},
            "scope": {"description": "范围 CIDR，数组或逗号分隔"},
            "scope_cidrs": {"type": "array", "items": {"type": "string"}},
            "objective": {"type": "string"}, "engagement": {"type": "string"}}, "required": []}},
}

SCHEMAS.update(_P5_SCHEMAS)
