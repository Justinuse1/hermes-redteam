"""hermes purge — 命令行入口（诊断/目标/报告/账本/扫描都能在 shell 里跑，不依赖模型）。

注意：Hermes 插件的 CLI handler **不会**打印返回值（只拿 int 当退出码），
所以这里必须自己 print。踩过一次坑，写死在文件头的注释里。
"""

from __future__ import annotations

import json
import time

from . import doctor, state, tools


def setup(parser, ctx=None, cfg=None):
    sub = parser.add_subparsers(dest="purge_cmd")

    p = sub.add_parser("doctor", help="能力层自检（层/技能/工具箱/网关/会话提示完整性）")
    p.add_argument("--json", action="store_true", help="输出 JSON")

    sub.add_parser("status", help="一行看当前状态（模式/目标/scope/账本）")

    p = sub.add_parser("mode", help="切模式：normal | redteam")
    p.add_argument("value", nargs="?", help="normal 或 redteam")

    p = sub.add_parser("target", help="设目标（自动进 scope、开 redteam、生成目标卡）")
    p.add_argument("value", nargs="?", help="靶名/域名")
    p.add_argument("--objective", "-o", default="", help="本次目标一句话")
    p.add_argument("--clear", action="store_true", help="清空目标")

    p = sub.add_parser("scope", help="看/加 scope 清单")
    p.add_argument("value", nargs="*", help="要加进 scope 的条目")

    p = sub.add_parser("preflight", help="动手前校验目标该不该打")
    p.add_argument("value", help="目标")
    p.add_argument("--in-scope", action="store_true", help="声明已在授权范围内")

    p = sub.add_parser("scan", help="入库前扫描（靶名/域名/凭证）")
    p.add_argument("path", nargs="?", default=".", help="目录，默认当前目录")

    p = sub.add_parser("reports", help="看报告目录最近的文件")
    p.add_argument("--n", type=int, default=10)

    p = sub.add_parser("ledger", help="战果账本：list / stat / add")
    p.add_argument("action", nargs="?", default="stat", choices=["list", "stat", "add"])
    p.add_argument("--kind", default="", help="add 时的类目")
    p.add_argument("--score", type=float, default=None)
    p.add_argument("--target", default="")
    p.add_argument("--note", default="")
    p.add_argument("--evidence", default="")
    p.add_argument("--n", type=int, default=20)

    if ctx is not None:
        try:
            ctx.register_command  # 只是确认 ctx 可用；斜杠命令在 __init__ 里注册
        except Exception:
            pass
    return None


def handle(args, ctx=None, cfg=None) -> int:
    cmd = getattr(args, "purge_cmd", None) or "status"
    try:
        out = _dispatch(cmd, args, ctx, cfg)
    except Exception as exc:  # CLI 不该崩，崩了也要说人话
        out = f"purge {cmd} 出错: {type(exc).__name__}: {exc}"
    print(out)
    return 0


def _dispatch(cmd, args, ctx, cfg) -> str:
    cfg = cfg or {}

    if cmd == "doctor":
        res = doctor.run(ctx, cfg)
        if getattr(args, "json", False):
            return json.dumps(res, ensure_ascii=False, indent=2)
        return doctor.render(res)

    if cmd == "status":
        st = state.load(ctx)
        lg = state.ledger_summary()
        sc = state.scope(ctx, cfg.get("scope_file") or "")
        return "\n".join([
            f"[模式] {st.get('mode')}",
            f"[目标] {st.get('target') or '-'}  engagement={st.get('engagement') or '-'}",
            f"[任务] {st.get('objective') or '-'}",
            f"[scope] {len(sc)} 条: {', '.join(sc[:8]) if sc else '(空)'}",
            f"[账本] {lg['count']} 条 · 计分 {lg['score']} · {lg['path']}",
            f"[报告] {state.reports_dir(str(st.get('engagement') or ''))}",
        ])

    if cmd == "mode":
        v = getattr(args, "value", None)
        if not v:
            return f"当前模式: {state.load(ctx).get('mode')}（可用: normal | redteam）"
        st = state.set_mode(ctx, v)
        return f"模式已切到 {st.get('mode')}"

    if cmd == "target":
        if getattr(args, "clear", False):
            st = state.load(ctx)
            st["target"] = ""
            st["objective"] = ""
            st["engagement"] = ""
            st["mode"] = "normal"
            state.save(ctx, st)
            state.log_event(ctx, "target_clear", "")
            return "目标已清空，模式回 normal"
        v = getattr(args, "value", None)
        if not v:
            st = state.load(ctx)
            return f"当前目标: {st.get('target') or '-'} / {st.get('objective') or '-'}"
        res = json.loads(tools.purge_objective(
            {"target": v, "objective": getattr(args, "objective", "") or ""},
            _purge_ctx=ctx, _purge_cfg=cfg))
        if res.get("error"):
            return res["error"]
        return (res.get("card") or "") + f"\n\n目标卡已落盘: {res.get('card_path')}"

    if cmd == "scope":
        vals = getattr(args, "value", []) or []
        if not vals:
            sc = state.scope(ctx, cfg.get("scope_file") or "")
            return ("scope:\n" + "\n".join(f"  - {s}" for s in sc)) if sc else "scope 为空"
        added = []
        for v in vals:
            added += state.add_scope(ctx, v)
        return "已加入 scope: " + ", ".join(added)

    if cmd == "preflight":
        return json.dumps(json.loads(tools.purge_preflight(
            {"target": args.value, "in_scope_claimed": getattr(args, "in_scope", False)},
            _purge_ctx=ctx, _purge_cfg=cfg)), ensure_ascii=False, indent=2)

    if cmd == "scan":
        return json.dumps(json.loads(tools.purge_scan({"path": args.path},
                                                      _purge_ctx=ctx, _purge_cfg=cfg)),
                          ensure_ascii=False, indent=2)

    if cmd == "reports":
        d = state.reports_dir(str(state.load(ctx).get("engagement") or ""))
        files = sorted(d.rglob("*"), key=lambda x: x.stat().st_mtime if x.is_file() else 0,
                       reverse=True)[: args.n]
        if not files:
            return f"没有报告（目录: {d}）"
        return "\n".join(f"{time.strftime('%m-%d %H:%M', time.localtime(f.stat().st_mtime))}  {f.stat().st_size:>7}B  {f}"
                         for f in files if f.is_file())

    if cmd == "ledger":
        act = getattr(args, "action", "stat")
        if act == "add":
            kinds = ", ".join(state.SCORE_WEIGHTS.keys())
            if not args.kind:
                return f"add 需要 --kind。合法类目: {kinds}"
            rec = state.ledger_add({"kind": args.kind, "score": args.score, "target": args.target,
                                    "note": args.note, "evidence": args.evidence})
            return f"已入账: {rec}"
        if act == "list":
            rows = state.ledger_list(limit=args.n)
            if not rows:
                return "账本还是空的"
            return "\n".join(f"{r.get('ts')}  [{r.get('kind')}] +{r.get('score')}  "
                             f"{r.get('target') or '-'}  {r.get('note') or ''}" for r in rows)
        lg = state.ledger_summary()
        kinds = " · ".join(f"{k}×{v['count']}(+{round(v['score'], 1)})"
                           for k, v in sorted(lg["by_kind"].items(), key=lambda x: -x[1]["count"]))
        last = lg.get("last") or {}
        return "\n".join([f"战果 {lg['count']} 条 · 计分 {lg['score']}",
                          f"按类目: {kinds or '-'}",
                          f"最近一条: {last.get('ts', '-')} [{last.get('kind', '-')}] {last.get('note', '')}",
                          f"账本: {lg['path']}"])

    return f"未知子命令: {cmd}"
