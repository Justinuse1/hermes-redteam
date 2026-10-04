#!/usr/bin/env python3
"""purge 插件验收测试：钩子到底有没有真的挂上、真的拦得住。

为什么单独写这个：插件"装上了"和"拦得住"是两件事。这个脚本用真调用而不是真攻击，
逐条验证 pre_tool_call / pre_llm_call / 工具 handler 的行为，输出可贴进验收数据。

用法：
    HERMES_HOME=~/.hermes python3 purge_selftest.py
退出码 0 = 全过。
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path

HOME = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
sys.path.insert(0, os.path.join(HOME, "plugins"))

# 测试必须跑在沙箱 HOME 里 —— 否则 purge_record 会把假战果写进真账本、
# set_target 会把假靶子写进真 scope（血泪教训：假靶子会污染真账本）。
REAL_HOME = HOME
SANDBOX = tempfile.mkdtemp(prefix="purge-selftest-home-")

import purge.guard as G          # noqa: E402
import purge.ledger as L         # noqa: E402
import purge.state as S          # noqa: E402
import purge.tools as T          # noqa: E402
import purge.doctor as D         # noqa: E402
import purge as P                # noqa: E402

# 用插件自己的工厂函数建钩子 —— 跟 register() 里挂上去的是同一套闭包
PT = P._make_pre_tool_call(None, {})
PL = P._make_pre_llm_call(None, {})
OS = P._make_on_session_start(None, {})

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))


def main():
    os.environ["HERMES_HOME"] = SANDBOX
    (Path(SANDBOX) / "SOUL.md").write_text("REDTEAM-ENHANCE-LAYER v1\n", encoding="utf-8")
    print(f"HERMES_HOME={REAL_HOME}  （读写走沙箱 {SANDBOX}）")
    print(f"真实状态文件（不被本次测试改动）={Path(REAL_HOME) / 'purge' / 'state.json'}")

    # ---------------- 1. pre_tool_call 钩子
    print("\n[1] pre_tool_call 红线闸")
    S.save(None, dict(S.DEFAULT_STATE))
    r = PT(tool_name="terminal", args={"command": "curl http://evil.example.net/x"}, task_id="t1")
    check("normal 模式不碰主业（返回 None）", r is None, repr(r))

    # 毁灭性命令：任何模式都拦
    r = PT(tool_name="terminal", args={"command": "rm -rf / --no-preserve-root"}, task_id="t2")
    check("毁灭性命令在 normal 模式也拦", isinstance(r, dict) and r.get("action") == "block",
          json.dumps(r, ensure_ascii=False)[:120])

    # 进红队模式 + 设清单
    S.set_target(None, "acme.example.com", "只读验证")
    S.add_scope(None, "api.acme.example.com")
    S.set_mode(None, "redteam")

    r = PT(tool_name="terminal", args={"command": "nmap -sV acme.example.com"}, task_id="t3")
    check("清单内目标放行", r is None, repr(r))

    r = PT(tool_name="terminal", args={"command": "curl http://random-unlisted.example.net/"}, task_id="t4")
    blocked = isinstance(r, dict) and r.get("action") in ("block", "approve")
    check("清单外目标被拦/转人工", blocked, json.dumps(r, ensure_ascii=False)[:160])
    if isinstance(r, dict):
        check("拦截信息里写了为什么+怎么放行",
              ("清单" in json.dumps(r, ensure_ascii=False)) and ("放行" in json.dumps(r, ensure_ascii=False)))

    r = PT(tool_name="terminal",
           args={"command": "git push origin main && echo sk-abcdef1234567890abcdef"}, task_id="t5")
    check("推送里带凭证被拦", isinstance(r, dict) and r.get("action") == "block",
          json.dumps(r, ensure_ascii=False)[:160])

    r = PT(tool_name="terminal", args={"command": "pip install requests"}, task_id="t6")
    check("公共源/工具源不被误伤", r is None or (isinstance(r, dict) and r.get("action") != "block"), repr(r))

    # ---------------- 2. pre_llm_call 注入
    print("\n[2] pre_llm_call 目标卡注入")
    r = PL(task_id="t7", session_id="s1")
    blob = json.dumps(r, ensure_ascii=False) if r else ""
    check("redteam 模式注入目标卡", "acme.example.com" in blob and "红线" in blob, blob[:160])
    check("注入里带 scope", "api.acme.example.com" in blob)

    S.set_mode(None, "normal")
    r = PL(task_id="t8", session_id="s1")
    check("normal 模式不注入（省 token）", r is None or "acme.example.com" not in json.dumps(r, ensure_ascii=False),
          repr(r)[:120])

    # 会话早于加强层 → 提醒（这是今天踩的坑，必须有回归）
    OS(session_id="stale-sess", model="m", platform="telegram")
    P._SESSION_INFO["stale-sess"]["soul_mtime"] = time.time() + 60
    P._SESSION_INFO["stale-sess"]["stale_prompt"] = True
    r = PL(task_id="t9", session_id="stale-sess")
    check("旧会话会被提醒开新会话", r is not None and "/new" in json.dumps(r, ensure_ascii=False),
          json.dumps(r, ensure_ascii=False)[:150])


    # ---------------- 3. 工具 handler
    print("\n[3] 工具 handler")
    out = json.loads(T.purge_preflight({"target": "github.com"}))
    check("公共源判 no-go", out["verdict"] == "no-go", out["verdict"])
    out = json.loads(T.purge_preflight({"target": "new-unlisted.example.net", "note": "无授权"}))
    check("不在清单无授权判 need-auth", out["verdict"] == "need-auth", out["verdict"])
    out = json.loads(T.purge_objective({"target": "acme.example.com", "objective": "只读验证"}))
    check("立目标落目标卡 + 开红队", out.get("ok") and out.get("mode") == "redteam", str(out.get("mode")))
    out = json.loads(T.purge_record({"kind": "central-system"}))
    check("战果入账按上游得分点计分",
          float(out["entry"]["score"]) == 500.0 and out["entry"].get("code") == "central-system",
          f"score={out['entry']['score']} code={out['entry'].get('code')}")
    out = json.loads(T.purge_record({"kind": "控制集权系统"}))
    check("旧类目别名仍可记账（→central-system）",
          float(out["entry"]["score"]) == 500.0 and out["entry"].get("code") == "central-system",
          f"score={out['entry']['score']} code={out['entry'].get('code')}")

    d = tempfile.mkdtemp(prefix="purgescan_")
    with open(os.path.join(d, "leak.txt"), "w", encoding="utf-8") as f:
        f.write("target=acme.example.com\napi_key=sk-abcdef1234567890abcdef\n")
    out = json.loads(T.purge_scan({"path": d}))
    check("入库扫描揪出靶名+凭证", out["verdict"] == "must-clean-before-push" and out["hit_count"] >= 1,
          f"hits={out['hit_count']}")

    check("purge_mode 进了工具表", "purge_mode" in T.SCHEMAS)
    out = json.loads(T.purge_mode({}))
    check("purge_mode 空参只报模式", out.get("mode") in ("normal", "redteam"), str(out.get("mode")))
    out = json.loads(T.purge_mode({"mode": "normal"}))
    check("purge_mode 能切 normal", out.get("ok") and out.get("mode") == "normal", str(out.get("mode")))
    out = json.loads(T.purge_mode({"mode": "redteam"}))
    check("有靶子才给开红队", out.get("ok") is True and out.get("mode") == "redteam", str(out.get("mode")))

    # ---------------- 3b. 块1：六角色体系
    out = json.loads(T.purge_roles({}))
    roles_seq = [r["role"] for r in (out.get("roles") or [])]
    check("purge_roles 列全六角色", out.get("ok") and roles_seq == ["plan", "recon", "assess", "vuln-scan", "exploit", "internal"],
          str(roles_seq))
    check("purge_roles 带工具映射表", len(out.get("tool_map") or {}) >= 15, str(len(out.get("tool_map") or {})))
    check("purge_roles 带指挥官开工简报", "开工动作" in (out.get("brief") or ""), "")
    bad = []
    for r in ("plan", "recon", "assess", "vuln-scan", "exploit", "internal"):
        o = json.loads(T.purge_role_prompt({"role": r}))
        if not (o.get("ok") and (o.get("prompt") or "").strip()):
            bad.append(r)
    check("六个角色稿都能取到（未填时给占位模板）", not bad, ("失败:" + ",".join(bad)) if bad else "6/6")
    o = json.loads(T.purge_role_prompt({"role": "信息收集"}))
    check("role_prompt 支持中文名", o.get("ok") and o.get("role") == "recon", str(o.get("role")))
    o = json.loads(T.purge_role_prompt({"role": "没这个角色"}))
    check("role_prompt 认不出时明确拒绝", o.get("ok") is False, str(o.get("error"))[:40])
    o = json.loads(T.purge_roles({}))
    filled = [r["role"] for r in (o.get("roles") or []) if r.get("custom")]
    check("角色自填状态可查", isinstance(filled, list),
          ("已填 %d/6: " % len(filled)) + ",".join(filled) if filled else "0/6（未填，属正常）")
    o = json.loads(T.purge_role_prompt({"role": "plan"}))
    check("指挥稿能取到（未填时给占位模板）",
          o.get("ok") and (o.get("prompt") or "").strip(),
          "%d 字符" % len(o.get("prompt") or ""))
    check("plan 被标为指挥角色", o.get("planner") is True, str(o.get("planner")))
    out = json.loads(T.purge_mode({"mode": "redteam"}))
    check("开红队后给出角色体系与下一步",
          out.get("ok") and len(out.get("roles") or []) == 6 and "开工动作" in (out.get("next") or ""), "")
    out = json.loads(T.purge_objective({"target": "acme.example.com", "objective": "回归：目标卡带角色体系"}))
    check("目标卡带角色体系", out.get("ok") and len(out.get("roles") or []) == 6 and "开工动作" in (out.get("next") or ""), "")

    # ---------------- 3c. 块2：台账引擎 + asset 族
    L.table_write(None, "assets", [], "p2test")
    L.table_write(None, "links", [], "p2test")
    o = json.loads(T.purge_asset_add({"engagement": "p2test", "ip": "10.0.0.5", "provenance": "passive",
                                      "tool": "crt.sh", "names": [{"name": "oa.demo.local", "kind": "domain"}],
                                      "ports": [{"port": 443, "service": "https", "product": "nginx",
                                                 "version": "1.24.0",
                                                 "fingerprints": [{"category": "框架", "product": "Seeyon OA",
                                                                   "confidence": 0.9}]}]}))
    check("asset_add 新建并给 id", o.get("ok") and o.get("created") and o["asset"]["id"] == "a0001",
          str((o.get("asset") or {}).get("id")))
    o = json.loads(T.purge_asset_add({"engagement": "p2test", "ip": "10.0.0.5", "provenance": "active",
                                      "state": "live", "ports": [{"port": 22, "service": "ssh"}]}))
    check("asset_add 按 ip 幂等合并（不新建、端口并入）",
          o.get("ok") and o.get("created") is False and len(o["asset"]["ports"]) == 2, "")
    check("合并时 active 覆盖 passive", o["asset"].get("provenance") == "active", str(o["asset"].get("provenance")))
    check("asset_query 网段过滤", json.loads(T.purge_asset_query({"engagement": "p2test", "cidr": "10.0.0.0/24"}))["count"] == 1, "")
    check("asset_query 服务过滤", json.loads(T.purge_asset_query({"engagement": "p2test", "service": "ssh"}))["count"] == 1, "")
    check("asset_query 指纹过滤", json.loads(T.purge_asset_query({"engagement": "p2test", "fingerprint": "seeyon"}))["count"] == 1, "")
    check("asset_query 网段不命中返回 0", json.loads(T.purge_asset_query({"engagement": "p2test", "cidr": "192.168.0.0/24"}))["count"] == 0, "")
    o = json.loads(T.purge_asset_get({"engagement": "p2test", "id": "a0001"}))
    check("asset_get 按 id 取到", o.get("ok") and o["asset"]["ip"] == "10.0.0.5", "")
    check("asset_get 不存在时明确报错", json.loads(T.purge_asset_get({"engagement": "p2test", "id": "a9999"})).get("ok") is False, "")
    o = json.loads(T.purge_asset_test({"engagement": "p2test", "asset_id": "a0001", "status": "tested",
                                       "test": "弱口令", "blocked": False, "updated_by": "vuln-scan"}))
    check("asset_test 登记测试记录", o.get("ok") and o.get("history") == 1, "")
    check("asset_test 找不到资产时报错", json.loads(T.purge_asset_test({"engagement": "p2test", "asset_id": "a9999"})).get("ok") is False, "")
    o = json.loads(T.purge_asset_assess({"engagement": "p2test", "ip": "10.0.0.5", "priority": "high",
                                         "potential": "未授权访问", "reason": "OA 端口暴露"}))
    check("asset_assess 打评估", o.get("ok") and o["assessment"]["priority"] == "high", "")
    o = json.loads(T.purge_asset_link({"engagement": "p2test", "src_kind": "asset", "src_id": "a0001",
                                       "dst_kind": "vuln", "dst_id": "v0001", "relation": "exploits"}))
    check("asset_link 登记关系（id 走 lk 前缀）", o.get("ok") and str(o["link"]["id"]).startswith("lk"),
          str((o.get("link") or {}).get("id")))
    check("asset_link 缺参数时拒绝", json.loads(T.purge_asset_link({"engagement": "p2test", "src_kind": "asset"})).get("ok") is False, "")
    o = json.loads(T.purge_asset_graph({"engagement": "p2test"}))
    check("asset_graph 出节点与边", o.get("ok") and o["counts"]["nodes"] == 1 and o["counts"]["edges"] >= 2, str(o.get("counts")))
    o = json.loads(T.purge_asset_timeline({"engagement": "p2test"}))
    check("asset_timeline 出事件流", o.get("ok") and o.get("count") >= 3, str(o.get("count")))
    o = json.loads(T.purge_asset_stats({"engagement": "p2test"}))
    check("asset_stats 统计口径", o.get("ok") and o["stats"]["assets"] == 1 and o["stats"]["live"] == 1,
          str((o.get("stats") or {}).get("assets")))
    check("asset_add 缺 provenance 时拒绝", json.loads(T.purge_asset_add({"engagement": "p2test", "ip": "1.1.1.1"})).get("ok") is False, "")
    check("asset_add 缺 ip 时拒绝", json.loads(T.purge_asset_add({"engagement": "p2test", "provenance": "active"})).get("ok") is False, "")
    check("台账落在 engagements/<靶标>/ 下",
          os.path.isdir(os.path.join(SANDBOX, "purge", "engagements", "p2test")), "")
    check("台账工具都注册了 handler",
          all(callable(getattr(T, k, None)) for k in T.SCHEMAS if k.startswith("purge_asset_")), "")

    # ---------------- 3d. 块2 批2：vuln / credential / access / webshell / tunnel
    for _t in ("vulns", "credentials", "access", "webshells", "tunnels"):
        L.table_write(None, _t, [], "p2test")
    o = json.loads(T.purge_vuln_add({"engagement": "p2test", "title": "致远OA 未授权访问", "severity": "critical",
                                     "ip": "10.0.0.5", "vuln_type": "未授权访问", "evidence": "GET ... -> 200"}))
    check("vuln_add 登记并给 id", o.get("ok") and o["vuln"]["id"] == "v0001" and o["vuln"]["severity"] == "critical", "")
    check("vuln_add 非法 severity 拒绝", json.loads(T.purge_vuln_add({"engagement": "p2test", "title": "x", "severity": "urgent"})).get("ok") is False, "")
    check("vuln_add 缺 title 拒绝", json.loads(T.purge_vuln_add({"engagement": "p2test", "severity": "high"})).get("ok") is False, "")
    check("vuln_query 按严重度过滤", json.loads(T.purge_vuln_query({"engagement": "p2test", "severity": "critical"}))["count"] == 1, "")
    check("vuln_query 按状态不命中", json.loads(T.purge_vuln_query({"engagement": "p2test", "status": "confirmed"}))["count"] == 0, "")
    o = json.loads(T.purge_vuln_update({"engagement": "p2test", "id": "v0001", "status": "confirmed"}))
    check("vuln_update 改状态", o.get("ok") and o["vuln"]["status"] == "confirmed", "")
    check("vuln_update 不存在时报错", json.loads(T.purge_vuln_update({"engagement": "p2test", "id": "v9999", "status": "fixed"})).get("ok") is False, "")
    o = json.loads(T.purge_credential_add({"engagement": "p2test", "username": "admin", "secret": "admin123",
                                           "service": "ssh", "ip": "10.0.0.5", "valid": True}))
    check("credential_add 登记", o.get("ok") and o["credential"]["id"] == "c0001", "")
    check("credential_add 缺 username 拒绝", json.loads(T.purge_credential_add({"engagement": "p2test", "secret": "x"})).get("ok") is False, "")
    check("credential_add 非法 kind 拒绝", json.loads(T.purge_credential_add({"engagement": "p2test", "username": "a", "kind": "sms"})).get("ok") is False, "")
    check("credential_list 按 valid 过滤", json.loads(T.purge_credential_list({"engagement": "p2test", "valid": True}))["count"] == 1, "")
    o = json.loads(T.purge_access_add({"engagement": "p2test", "kind": "shell", "ip": "10.0.0.5", "level": "管理员"}))
    check("access_add 登记权限", o.get("ok") and o["access"]["id"] == "ac0001", "")
    check("access_add 缺 ip/asset_id 拒绝", json.loads(T.purge_access_add({"engagement": "p2test", "kind": "shell"})).get("ok") is False, "")
    check("access_add 非法 kind 拒绝", json.loads(T.purge_access_add({"engagement": "p2test", "kind": "god", "ip": "1.1.1.1"})).get("ok") is False, "")
    check("access_list 按 kind 过滤", json.loads(T.purge_access_list({"engagement": "p2test", "kind": "shell"}))["count"] == 1, "")
    o = json.loads(T.purge_webshell_add({"engagement": "p2test", "url": "http://10.0.0.5/shell.jsp", "type": "jsp",
                                         "password": "c", "ip": "10.0.0.5"}))
    check("webshell_add 登记", o.get("ok") and o["webshell"]["id"] == "w0001", "")
    check("webshell_add 缺 url 拒绝", json.loads(T.purge_webshell_add({"engagement": "p2test", "type": "jsp"})).get("ok") is False, "")
    o = json.loads(T.purge_webshell_update({"engagement": "p2test", "id": "w0001", "status": "dead"}))
    check("webshell_update 改状态", o.get("ok") and o["webshell"]["status"] == "dead", "")
    o = json.loads(T.purge_tunnel_add({"engagement": "p2test", "kind": "socks5", "listen": "127.0.0.1:1080",
                                       "target": "10.0.0.0/24", "via_host": "10.0.0.5", "tool": "chisel"}))
    check("tunnel_add 登记", o.get("ok") and o["tunnel"]["id"] == "t0001", "")
    check("tunnel_add 非法 kind 拒绝", json.loads(T.purge_tunnel_add({"engagement": "p2test", "kind": "magic"})).get("ok") is False, "")
    check("tunnel_list 按 kind 过滤", json.loads(T.purge_tunnel_list({"engagement": "p2test", "kind": "socks5"}))["count"] == 1, "")
    o = json.loads(T.purge_tunnel_update({"engagement": "p2test", "id": "t0001", "status": "closed"}))
    check("tunnel_update 改状态", o.get("ok") and o["tunnel"]["status"] == "closed", "")
    o = json.loads(T.purge_status({"json": True, "engagement": "p2test"}))
    _tb = o.get("tables") or {}
    check("purge_status 带台账计数", _tb.get("vulns") == 1 and _tb.get("credentials") == 1 and _tb.get("tunnels") == 1, str(_tb))
    check("批2 十三个工具都注册了 handler",
          all(callable(getattr(T, k, None)) for k in ("purge_vuln_add", "purge_vuln_query", "purge_vuln_update",
              "purge_credential_add", "purge_credential_list", "purge_access_add", "purge_access_list",
              "purge_webshell_add", "purge_webshell_list", "purge_webshell_update",
              "purge_tunnel_add", "purge_tunnel_list", "purge_tunnel_update")), "")

    # ---------------- 3e. 块5：目标卡（engagement.yaml）
    T.purge_objective_card_save({"engagement": "某某单位-20261004", "target_name": "某某单位",
                                 "scope": ["10.0.0.0/24", "192.168.1.0/24"], "objective": "拿下后台只读验证"})
    o = json.loads(T.purge_objective_card({"engagement": "某某单位-20261004"}))
    check("目标卡 目标名", o.get("target_name") == "某某单位", str(o.get("target_name")))
    check("目标卡 范围两个", o.get("scope_cidrs") == ["10.0.0.0/24", "192.168.1.0/24"], str(o.get("scope_cidrs")))
    check("目标卡 正文含 只打", "只打：某某单位" in (o.get("card") or ""), "")
    check("目标卡 正文含 不打", "不打：" in (o.get("card") or ""), "")
    check("目标卡 落盘 engagement.yaml", (o.get("path") or "").endswith("engagement.yaml"), o.get("path"))
    o = json.loads(T.purge_objective_card_save({"engagement": "某某单位-20261004", "scope": "bad-cidr,10.0.0.0/24"}))
    check("目标卡 非法 CIDR 只提示不挡", o.get("ok") and "bad-cidr" in (o.get("invalid_cidrs") or []), str(o.get("invalid_cidrs")))
    o = json.loads(T.purge_objective_card({"engagement": "没有这个靶标"}))
    check("目标卡 没立卡时明说没有", o.get("ok") is False, "")

    # ---------------- 3f. 块6：doctor 三项自检
    import importlib
    D = importlib.import_module("purge.doctor")
    r = D.check_roles()
    check("doctor 角色体系 6/6", r["ok"] and r["count"] == 6, str(r.get("missing")))
    r = D.check_redteam_skills()
    check("doctor 技能库（未启用则跳过）", r["ok"],
          "未启用" if not r.get("enabled") else "%d 个" % r.get("count", 0))
    r = D.check_score_table()
    check("doctor 计分表 >=25 条", r["ok"] and r["count"] >= 25, str(r.get("fingerprint")))

    S.set_target(None, "")
    out = json.loads(T.purge_mode({"mode": "redteam"}))
    check("空靶子拒绝开红队", out.get("ok") is False, str(out.get("error"))[:40])

    # ---------------- 4. doctor（切回真 HOME：核加强层 / 技能 / 工具箱）
    os.environ["HERMES_HOME"] = REAL_HOME
    print("\n[4] doctor 自检")
    res = D.run(None, {})
    for k in ("layer", "skills", "skill_env", "toolkit", "gateway", "sessions", "ledger"):
        check(f"doctor 覆盖 {k}", k in res)
    txt = D.render(res)
    check("doctor 有人话输出",
          "[会话提示完整性]" in txt and "[技能可用]" in txt and "[战果账本]" in txt,
          txt.splitlines()[1][:80] if len(txt.splitlines()) > 1 else "")

    # ---------------- 5. 斜杠命令注册名（Telegram 菜单往返）
    print("\n[5] 斜杠命令注册名")
    names = tuple(getattr(P, "SLASH_NAMES", ()))
    check("注册了 7 条斜杠命令", len(names) == 7, str(len(names)))
    check("注册名一律用连字符（下划线在 TG 侧查不到）",
          all("_" not in n for n in names),
          ", ".join(n for n in names if "_" in n) or "ok")
    check("TG 菜单净化(_)/网关归一(-) 往返无损",
          all(n.replace("-", "_").replace("_", "-") == n for n in names))

    # ---------------- 收尾（沙箱随进程丢弃；真 HOME 的状态/账本全程未动）
    print(f"\n结果: {len(PASS)} 过 / {len(FAIL)} 挂")
    if FAIL:
        print("失败的项: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
