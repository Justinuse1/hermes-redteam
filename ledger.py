"""purge 台账层（块2）：把九族结构化台账（资产/漏洞/凭据/会话/隧道/…）落到插件侧。

上游存在 engagements/<靶标>/{assets,vulns,credentials,...}.json，这里等价：
  $HERMES_HOME/purge/engagements/<靶标id>/<族名>.json   （JSON 数组，原子写）

设计取舍：
- 只认文件、不认 ctx.state —— 网关钩子、CLI、工具调用是三拨进程，只有文件共享。
- 一族一个 JSON 数组（不是 jsonl）：量小（几百条），upsert 要改单条，数组最好处理。
- 所有函数 fail-open：读坏了就当空表，绝不因为台账坏了把工具弄崩。
- 字段名尽量对齐上游（ip/provenance/ports[].port …），子代理照上游稿子填就能落。
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from pathlib import Path

# 九族台账 + 作用域
TABLES = ("assets", "vulns", "credentials", "access", "webshells",
          "tunnels", "chains", "attack_files", "http_evidence", "targets", "pocs", "links")

# 各族 id 前缀
ID_PREFIX = {
    "assets": "a", "vulns": "v", "credentials": "c", "access": "ac",
    "webshells": "w", "tunnels": "t", "chains": "ch", "attack_files": "f",
    "http_evidence": "he", "targets": "tg", "pocs": "poc", "links": "lk",
}


def hermes_home() -> Path:
    env = os.environ.get("HERMES_HOME")
    return Path(env) if env else Path.home() / ".hermes"


def purge_root() -> Path:
    d = hermes_home() / "purge"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _slug(s: str) -> str:
    """文件名安全化：保留中文（靶标名要能读懂），挡掉路径分隔符和 ..。"""
    s = (s or "").strip().replace("/", "_").replace("\\", "_")
    s = re.sub(r"[^\w.\-]+", "_", s, flags=re.UNICODE)
    s = s.strip("._-")
    if not s or set(s) <= {"."}:
        return "unnamed"
    return s[:80]


def current_engagement(ctx=None) -> str:
    """当前交战 id：state.engagement 优先，否则由 target 推。"""
    try:
        from . import state
        st = state.load(ctx)
        eid = (st.get("engagement") or "").strip()
        if eid:
            return _slug(eid)
        tgt = (st.get("target") or "").strip()
        if tgt:
            return _slug(tgt)
    except Exception:
        pass
    return "default"


def engage_dir(ctx=None, engagement: str | None = None) -> Path:
    eid = _slug(engagement) if engagement else current_engagement(ctx)
    d = purge_root() / "engagements" / eid
    d.mkdir(parents=True, exist_ok=True)
    return d


def table_path(ctx, name: str, engagement: str | None = None) -> Path:
    return engage_dir(ctx, engagement) / (name + ".json")


def table_read(ctx, name: str, engagement: str | None = None) -> list:
    try:
        p = table_path(ctx, name, engagement)
        if p.is_file():
            rows = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(rows, list):
                return rows
    except Exception:
        pass
    return []


def table_write(ctx, name: str, rows: list, engagement: str | None = None) -> None:
    try:
        p = table_path(ctx, name, engagement)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:
        pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z") or time.strftime("%Y-%m-%dT%H:%M:%S")


def new_id(ctx, name: str, engagement: str | None = None) -> str:
    pre = ID_PREFIX.get(name, "x")
    rows = table_read(ctx, name, engagement)
    n = 0
    for r in rows:
        m = re.match(r"^%s(\d+)$" % re.escape(pre), str(r.get("id") or ""))
        if m:
            n = max(n, int(m.group(1)))
    return "%s%04d" % (pre, n + 1)


def table_append(ctx, name: str, rec: dict, engagement: str | None = None) -> dict:
    rows = table_read(ctx, name, engagement)
    rec = dict(rec)
    rec.setdefault("id", new_id(ctx, name, engagement))
    rec.setdefault("created_at", _now())
    rec["updated_at"] = rec.get("updated_at") or rec["created_at"]
    rows.append(rec)
    table_write(ctx, name, rows, engagement)
    return rec


def table_update(ctx, name: str, rid: str, patch: dict, engagement: str | None = None):
    rows = table_read(ctx, name, engagement)
    hit = None
    for r in rows:
        if str(r.get("id")) == str(rid):
            r.update({k: v for k, v in patch.items() if v is not None})
            r["updated_at"] = _now()
            hit = r
            break
    if hit is not None:
        table_write(ctx, name, rows, engagement)
    return hit


def find_by_id(ctx, name: str, rid: str, engagement: str | None = None):
    for r in table_read(ctx, name, engagement):
        if str(r.get("id")) == str(rid):
            return r
    return None


# ---------------------------------------------------------------- 过滤/合并工具
def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(ip) in net
    except Exception:
        return False


def _dedup_ports(ports: list) -> list:
    """按 (port, proto) 去重，后来的指纹字段合并进先来的。"""
    seen = {}
    order = []
    for p in ports or []:
        if not isinstance(p, dict) or p.get("port") in (None, ""):
            continue
        key = (str(p.get("port")), str(p.get("proto") or "tcp"))
        if key not in seen:
            seen[key] = dict(p)
            order.append(key)
        else:
            cur = seen[key]
            for k, v in p.items():
                if v in (None, "", [], {}):
                    continue
                if k == "fingerprints" and isinstance(v, list):
                    old = cur.get("fingerprints") or []
                    cur["fingerprints"] = old + [x for x in v if x not in old]
                elif not cur.get(k):
                    cur[k] = v
    return [seen[k] for k in order]


def _dedup_names(names: list) -> list:
    seen, out = set(), []
    for n in names or []:
        if not isinstance(n, dict):
            continue
        k = (str(n.get("name") or ""), str(n.get("kind") or "domain"))
        if k[0] and k not in seen:
            seen.add(k)
            out.append(n)
    return out


def asset_upsert(ctx, rec: dict, engagement: str | None = None):
    """按 ip 幂等 upsert（对齐上游 redteam_asset_add）。返回 (记录, 是否新建)。"""
    rows = table_read(ctx, "assets", engagement)
    ip = str(rec.get("ip") or "").strip()
    hit = None
    for r in rows:
        if str(r.get("ip")) == ip and ip:
            hit = r
            break
    if hit is None:
        rec = dict(rec)
        rec.setdefault("id", new_id(ctx, "assets", engagement))
        rec["created_at"] = _now()
        rec["updated_at"] = rec["created_at"]
        rec.setdefault("state", "unknown")
        rec["names"] = _dedup_names(rec.get("names"))
        rec["ports"] = _dedup_ports(rec.get("ports"))
        rows.append(rec)
        table_write(ctx, "assets", rows, engagement)
        return rec, True
    # merge
    for k in ("primary_name", "state"):
        if rec.get(k):
            hit[k] = rec[k]
    for k in ("names", "ports"):
        hit[k] = _dedup_names((hit.get(k) or []) + (rec.get(k) or [])) if k == "names" \
            else _dedup_ports((hit.get(k) or []) + (rec.get(k) or []))
    for k in ("discovered_at", "first_seen"):
        if rec.get(k) and not hit.get(k):
            hit[k] = rec[k]
    if rec.get("provenance") == "active":
        hit["provenance"] = "active"
    hit["updated_at"] = _now()
    table_write(ctx, "assets", rows, engagement)
    return hit, False


def asset_query(ctx, engagement=None, cidr=None, port=None, service=None,
                fingerprint=None, provenance=None, q=None, state=None,
                scope=None, sort=None, limit=None) -> list:
    rows = table_read(ctx, "assets", engagement)
    out = []
    for r in rows:
        if cidr and not ip_in_cidr(str(r.get("ip") or ""), cidr):
            continue
        if scope:
            try:
                nets = json.loads(scope) if str(scope).strip().startswith("[") else [scope]
            except Exception:
                nets = [scope]
            if nets and not any(ip_in_cidr(str(r.get("ip") or ""), n) for n in nets):
                continue
        if state and str(r.get("state") or "unknown") != str(state):
            continue
        if provenance and str(r.get("provenance") or "") != str(provenance):
            continue
        if port is not None and not any(str(p.get("port")) == str(port) for p in (r.get("ports") or [])):
            continue
        if service and not any(str(p.get("service") or "").lower() == str(service).lower()
                               for p in (r.get("ports") or [])):
            continue
        if fingerprint:
            fpat = str(fingerprint).lower()
            hay = json.dumps(r.get("ports") or [], ensure_ascii=False).lower()
            if fpat not in hay:
                continue
        if q:
            qs = str(q).lower()
            if qs not in json.dumps(r, ensure_ascii=False).lower():
                continue
        out.append(r)
    if sort:
        key = str(sort).lstrip("-")
        out.sort(key=lambda x: str(x.get(key) or ""), reverse=str(sort).startswith("-"))
    if limit:
        try:
            out = out[: int(limit)]
        except Exception:
            pass
    return out


def asset_stats(ctx, engagement=None) -> dict:
    rows = table_read(ctx, "assets", engagement)
    svc, prod, portc = {}, {}, {}
    live = 0
    for r in rows:
        if str(r.get("state") or "") == "live":
            live += 1
        for p in (r.get("ports") or []):
            pt = str(p.get("port"))
            portc[pt] = portc.get(pt, 0) + 1
            s = (p.get("service") or "").strip()
            if s:
                svc[s] = svc.get(s, 0) + 1
            pr = (p.get("product") or "").strip()
            if pr:
                prod[pr] = prod.get(pr, 0) + 1
    top = lambda d: sorted(d.items(), key=lambda kv: -kv[1])[:15]
    return {"assets": len(rows), "live": live,
            "ports": len(portc), "top_ports": top(portc),
            "top_services": top(svc), "top_products": top(prod)}


def summary(ctx=None, engagement=None) -> dict:
    """一条命令看全九族条数（给 purge_status / doctor 用）。"""
    eng = engagement or current_engagement(ctx)
    out = {"engagement": eng, "dir": str(engage_dir(ctx, eng))}
    for t in TABLES:
        out[t] = len(table_read(ctx, t, eng))
    return out
