"""红队能力层 —— Hermes 原生插件：台账 / 目标卡 / 报告 / 自检。

它把红队作业台账用 Hermes 插件契约实现：
  加强层自检（doctor） / 红线闸（pre_tool_call） / 红队模式上下文注入（pre_llm_call）
  / 目标 preflight / 目标卡 / 报告回放 / 入库前扫描

三条设计底线（都是踩坑换来的）：
  1. 文件落位 ≠ 运行时生效 —— 所以一切结论都从运行时证据取（真实系统提示、真实二进制）。
  2. 默认不干扰 —— normal 模式只观察；红线闸只在 redteam 模式生效（毁灭性命令除外）。
  3. 插件永远不崩主流程 —— 所有钩子 fail-open，所有工具返回 JSON 而不是抛异常。
"""

from __future__ import annotations

import functools
import json
import logging
import time
from pathlib import Path

from . import cli as cli_mod
from . import doctor, guard, state, tools

logger = logging.getLogger(__name__)

# session_id → {"soul_mtime": ..., "session_started": ...}（用于判断会话提示是否早于加强层）
_SESSION_INFO: dict = {}


def _cfg(ctx) -> dict:
    """读插件配置；读不出来就用默认值（fail-open）。"""
    keys = {
        "mode": "redteam_hold",       # 占位，不用它覆盖状态
        "guard_enabled": True,
        "block_target_in_repo": True,
        "layer_marker": "",   # 留空 = 不检查 SOUL（你没注入提示词层时别误报）
        "scope_file": "",
    }
    out = {}
    for k, default in keys.items():
        try:
            out[k] = ctx.get_config(k, default=default)
        except Exception:
            out[k] = default
    return out


def _bind(handler, ctx, cfg):
    """把 ctx/cfg 绑进工具处理器（工具契约只允许 (args, **kwargs)）。"""
    def _call(args, **kwargs):
        kwargs.setdefault("_purge_ctx", ctx)
        kwargs.setdefault("_purge_cfg", cfg)
        return handler(args, **kwargs)
    return _call


# ------------------------------------------------------------------ 钩子
def _make_pre_tool_call(ctx, cfg):
    def _hook(tool_name=None, args=None, task_id=None, **kwargs):
        try:
            st = state.load(ctx)
            scope_list = state.scope(ctx, cfg.get("scope_file") or "")
            verdict = guard.classify(tool_name or "", args or {}, st, scope_list, cfg)
            if verdict:
                logger.warning("purge 闸: %s %s -> %s", tool_name, verdict.get("action"),
                               (verdict.get("message") or "")[:120])
            return verdict
        except Exception as e:  # fail-open：插件坏了不能挡住主业
            logger.warning("purge guard 异常，放行: %s", e)
            return None
    return _hook


def _make_pre_llm_call(ctx, cfg):
    def _hook(session_id=None, user_message=None, is_first_turn=False, platform=None, **kwargs):
        notes = []
        try:
            # 1) 会话提示早于加强层落盘 → 这条会话的模型可能看不到层
            info = _SESSION_INFO.get(session_id or "")
            if info and info.get("stale_prompt"):
                notes.append(
                    "【环境提醒】这条会话的系统提示建立于加强层落盘之前，Hermes 的会话提示终身不变，"
                    "所以本会话很可能没有加强层。需要完整能力就开新会话（Telegram/CLI 里发 /new）。")
            # 2) redteam 模式：注入作战约束（只在需要时注入，别每回合灌水）
            st = state.load(ctx)
            if st.get("mode") == "redteam":
                scope_list = state.scope(ctx, cfg.get("scope_file") or "")
                notes.append("\n".join([
                    "【purge 作战约束｜redteam 模式生效中】",
                    f"- 目标：{st.get('target') or '（未设，先 purge_objective）'}",
                    f"- 目的：{st.get('objective') or '（未写）'}",
                    f"- 清单：{', '.join(scope_list) or '（空）'}",
                    "- 靶名/域名/凭证不入库；push 前必须 purge_scan",
                    "- 不自设不合理场景；方向存疑先停后问（stop and ask）",
                    "- 动手前 purge_preflight 过一遍；越界动作会被红线闸拦下",
                ]))
        except Exception as e:
            logger.debug("purge pre_llm_call 注水失败（忽略）: %s", e)
            return None
        if not notes:
            return None
        return {"context": "\n".join(notes)}
    return _hook


def _make_on_session_start(ctx, cfg):
    def _hook(session_id=None, model=None, platform=None, **kwargs):
        try:
            soul = state.hermes_home() / "SOUL.md"
            soul_mtime = soul.stat().st_mtime if soul.is_file() else 0
            started = time.time()
            stale = bool(soul_mtime and started < soul_mtime - 2)
            _SESSION_INFO[session_id or "-"] = {"soul_mtime": soul_mtime,
                                                "session_started": started,
                                                "stale_prompt": stale}
            if stale:
                logger.warning("purge: 新会话 %s 建立时间早于 SOUL.md 落盘时间，本会话可能不带加强层",
                               session_id)
            marker = cfg.get("layer_marker") or ""
            if marker:
                key = doctor._marker_key(marker)
                layer_ok = soul.is_file() and key in soul.read_text(encoding="utf-8", errors="replace")
            else:
                layer_ok = True   # 没配 marker：不检查，也不算缺
            logger.info("purge: 会话 %s 建立（platform=%s model=%s）加强层=%s 层标记=%s",
                        session_id or "-", platform or "-", model or "-",
                        "有" if layer_ok else "缺", "在" if layer_ok else "不在")
            if not layer_ok:
                logger.warning("purge: SOUL.md 里没有加强层版本串（%s）—— 层没落地或被改", marker)
        except Exception as e:
            logger.debug("purge on_session_start 异常（忽略）: %s", e)
    return _hook


# ------------------------------------------------------------------ 斜杠命令
_SLASH_USAGE = (
    "purge 用法（方括号里的参数可省，省了只报当前状态）：\n"
    "  /purge            总览（模式 / 目标 / 体检 / 账本 / 会话层证据）\n"
    "  /purge-mode [normal|redteam]    看/切模式（redteam 才开红线闸 + 作战约束注入）\n"
    "  /purge-target [目标|clear]      看/立/清作战目标\n"
    "  /purge-ledger     战果账本（条数 / 计分 / 类目）\n"
    "  /purge-scan <路径>  入库前扫描靶名与凭证（要显式给路径）\n"
    "  /purge-doctor     只跑体检（跟 /purge 同源，输出更长）\n"
    "  /purge-help       这张表"
)

# 注册名必须用连字符：Telegram 菜单把 "-" 净化成 "_"（只能 [a-z0-9_]），
# 网关收到 /purge_mode 后会 replace("_","-") 再查注册表 —— 注册成下划线就永远查不到，
# 用户点菜单只会收到 "unknown command"。CLI 侧按原名查，写连字符两边都对。
SLASH_NAMES = ("purge", "purge-mode", "purge-target", "purge-ledger",
               "purge-scan", "purge-doctor", "purge-help")


def _make_slash(ctx, cfg, fixed: str | None = None):
    """fixed=None → /purge 走子命令；fixed='mode' → /purge-mode 只认参数。"""
    def _handle(raw: str = "") -> str:
        text = (raw or "").strip()
        if fixed:
            sub, arg = fixed, text
        else:
            parts = text.split()
            sub = parts[0].lower() if parts else "status"
            arg = parts[1] if len(parts) > 1 else ""
        try:
            st = state.load(ctx)
            if sub in ("", "status"):
                return doctor.render(doctor.run(ctx, cfg))
            if sub == "help":
                return _SLASH_USAGE
            if sub == "doctor":
                res = doctor.run(ctx, cfg)
                txt = doctor.render(res)
                extra = []
                for u in ((res.get("skill_env") or {}).get("unavailable") or []):
                    extra.append("  技能缺 key: %s → %s" % (u.get("skill"), ",".join(u.get("missing_env") or [])))
                tk = res.get("toolkit") or {}
                for m in (tk.get("missing") or []):
                    extra.append(f"  工具箱缺: {m}")
                for h in (res.get("history_tail") or []):
                    extra.append("  历史: " + json.dumps(h, ensure_ascii=False)[:160])
                return txt + ("\n[明细]\n" + "\n".join(extra) if extra else "\n[明细] 无（技能 key 齐、工具箱齐、无历史）")
            if sub == "mode":
                if arg.lower() in ("redteam", "on", "开", "红队"):
                    state.set_mode(ctx, "redteam")
                    return ("purge: 已切 redteam —— 红线闸生效、每回合注入作战约束。\n"
                            "越界动作会被拦下；拦截消息里会说明怎么放行。")
                if arg.lower() in ("normal", "off", "关", "常规"):
                    state.set_mode(ctx, "normal")
                    return "purge: 已切 normal —— 只观察不拦（毁灭性命令除外）"
                cur = st.get("mode") or "normal"
                return ("🎛 purge 模式：%s\n"
                        "  redteam —— 红线闸开：越界/毁灭性动作拦下，每回合给模型注入作战约束\n"
                        "  normal  —— 只观察不拦（毁灭性命令仍拦）\n"
                        "切模式：发 /purge-mode redteam  或  /purge-mode normal\n"
                        "当前目标：%s｜engagement：%s"
                        % (cur, st.get("target") or "-", st.get("engagement") or "-"))
            if sub in ("on", "off"):
                state.set_mode(ctx, "redteam" if sub == "on" else "normal")
                return f"purge: 模式={state.load(ctx).get('mode')}"
            if sub == "target":
                if not arg:
                    return ("🎯 purge 目标：%s｜目的：%s｜engagement：%s\n"
                            "立目标：/purge-target example.com\n"
                            "清目标：/purge-target clear\n"
                            "（redteam 模式下，动作不落在目标清单里会被红线闸拦下）"
                            % (st.get("target") or "-", st.get("objective") or "-",
                               st.get("engagement") or "-"))
                if arg.lower() in ("clear", "清", "-"):
                    state.set_target(ctx, "")
                    return "purge: 目标已清空"
                state.set_target(ctx, arg)
                st2 = state.load(ctx)
                if (st2.get("mode") or "normal") != "redteam":
                    # 跟工具路 purge_objective 同一套语义：立目标 = 建令牌 + 激活（开 redteam）
                    st2 = state.set_mode(ctx, "redteam")
                return (f"purge: 目标={st2.get('target')}  令牌(engagement)={st2.get('engagement')}\n"
                        f"✅ 已自动激活：模式=redteam（红线闸生效，报告按 {st2.get('engagement')} 归档）\n"
                        "要收工就 /purge-mode normal；要放行清单外的动作先 /purge-target 加目标。")
            if sub == "ledger":
                s = state.ledger_summary()
                lines = [f"📊 战果账本：{s.get('count', 0)} 条 · 计分 {s.get('score', 0)}",
                         f"  文件 {s.get('path')}"]
                for k, v in sorted((s.get("by_kind") or {}).items(),
                                   key=lambda kv: -kv[1].get("count", 0)):
                    lines.append(f"  {k}: {v.get('count', 0)} 条 / {round(float(v.get('score') or 0), 2)}")
                last = s.get("last")
                lines.append("  最近一条: " + (json.dumps(last, ensure_ascii=False)[:200] if last
                                              else "无（账本空的 —— 有战果时让模型调 purge_record）"))
                return "\n".join(lines)
            if sub == "scan":
                if not arg:
                    return ("🔍 /purge-scan 要指定路径，例如 /purge-scan .\n"
                            "扫的是靶名 / 域名 / 凭证；命中不等于错，但 push 前必须逐条确认。")
                return tools.purge_scan({"path": arg}, _purge_ctx=ctx, _purge_cfg=cfg)
            if sub == "preflight":
                return tools.purge_preflight({"target": arg}, _purge_ctx=ctx, _purge_cfg=cfg)
            return _SLASH_USAGE + f"\n当前：模式={st.get('mode')} 目标={st.get('target') or '-'}"
        except Exception as e:
            return f"purge 出错：{e}"
    return _handle


# ------------------------------------------------------------------ 注册
def register(ctx):
    cfg = _cfg(ctx)

    # 工具（模型可直接调）
    for tool_name, schema in tools.SCHEMAS.items():
        handler = getattr(tools, tool_name, None)
        if handler is None:
            logger.warning("purge: schema 有 %s 但没有对应处理器，跳过", tool_name)
            continue
        ctx.register_tool(name=tool_name, toolset="purge", schema=schema,
                          handler=_bind(handler, ctx, cfg))

    # 钩子
    ctx.register_hook("pre_tool_call", _make_pre_tool_call(ctx, cfg))
    ctx.register_hook("pre_llm_call", _make_pre_llm_call(ctx, cfg))
    ctx.register_hook("on_session_start", _make_on_session_start(ctx, cfg))

    # 会话内斜杠命令（同时进 Telegram 机器人菜单）
    ctx.register_command("purge", _make_slash(ctx, cfg),
                         description="🧪 purge 总览：模式/目标/体检/账本/会话层证据")
    ctx.register_command("purge-mode", _make_slash(ctx, cfg, fixed="mode"),
                         description="🎛 看/切模式：redteam 开红线闸+作战约束 / normal 只观察",
                         argument_mode="options")
    ctx.register_command("purge-target", _make_slash(ctx, cfg, fixed="target"),
                         description="🎯 看/立/清作战目标（/purge-target clear 清空）")
    ctx.register_command("purge-ledger", _make_slash(ctx, cfg, fixed="ledger"),
                         description="📊 战果账本：条数/计分/类目/最近一条")
    ctx.register_command("purge-scan", _make_slash(ctx, cfg, fixed="scan"),
                         description="🔍 入库前扫描靶名与凭证（默认扫当前目录）")
    ctx.register_command("purge-doctor", _make_slash(ctx, cfg, fixed="doctor"),
                         description="🩺 只跑体检（加强层/技能/工具箱/网关）")
    ctx.register_command("purge-help", _make_slash(ctx, cfg, fixed="help"),
                         description="purge 命令表")
    ctx.register_cli_command("purge", "purge 能力层：自检 / 目标 / 报告 / 扫描",
                             functools.partial(cli_mod.setup, ctx=ctx, cfg=cfg),
                             functools.partial(cli_mod.handle, ctx=ctx, cfg=cfg))

    logger.info("purge 插件已注册：%d 工具 / 3 钩子 / 7 斜杠命令 / 1 CLI 命令", len(tools.SCHEMAS))
