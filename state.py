"""purge 插件的状态层：红队模式、目标、scope 清单。

状态走 ctx.state（profile 级、原子写、并发安全），文件只用于人看/脚本读。
所有函数都 fail-open：状态读不出来就按 normal 走，绝不因为插件坏了挡住主业。
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

DEFAULT_STATE = {
    "mode": "normal",          # normal | redteam
    "target": "",              # 当前目标（靶名/域名）
    "objective": "",           # 本次目标一句话
    "scope": [],               # 允许的目标清单
    "engagement": "",          # 本次交战 id（目标+日期），报告按它分目录
    "started_at": None,
    "history": [],             # [{ts, event, detail}]
    "reports": [],             # [{ts, name, path}]
}

MAX_HISTORY = 200


def hermes_home() -> Path:
    """profile 感知的 HERMES_HOME。"""
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env)
    return Path.home() / ".hermes"


def state_path() -> Path:
    d = hermes_home() / "purge"
    d.mkdir(parents=True, exist_ok=True)
    return d / "state.json"


def load(ctx=None) -> dict:
    """状态只认文件（$HERMES_HOME/purge/state.json）。

    为什么不用 ctx.state：网关进程里跑的钩子、和 shell 里跑的 `hermes purge`、
    还有工具调用，是三拨不同的进程 —— 只有文件能让它们看到同一份状态。
    """
    raw = {}
    try:
        p = state_path()
        if p.is_file():
            raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    out = dict(DEFAULT_STATE)
    out.update({k: v for k, v in raw.items() if k in DEFAULT_STATE})
    return out


def save(ctx, st: dict) -> None:
    """原子写：先写临时文件再 rename，免得网关读到一个写了一半的 JSON。"""
    try:
        p = state_path()
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:
        pass


def log_event(ctx, event: str, detail: str = "") -> dict:
    """把一次状态变更记进 history（人看的流水）。"""
    st = load(ctx)
    hist = list(st.get("history") or [])
    hist.append({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, "detail": detail[:400]})
    st["history"] = hist[-MAX_HISTORY:]
    save(ctx, st)
    return st


def set_mode(ctx, mode: str) -> dict:
    st = load(ctx)
    mode = (mode or "").strip().lower()
    if mode not in ("normal", "redteam"):
        raise ValueError("mode 只能是 normal 或 redteam")
    st["mode"] = mode
    st["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S") if mode == "redteam" else None
    save(ctx, st)
    log_event(ctx, f"mode={mode}")
    return st


def set_target(ctx, target: str, objective: str = "") -> dict:
    st = load(ctx)
    st["target"] = (target or "").strip()
    if objective:
        st["objective"] = objective.strip()
    if st["target"] and st["target"] not in (st.get("scope") or []):
        st["scope"] = list(st.get("scope") or []) + [st["target"]]
    if st["target"]:
        # 一次任务一个目录：目标 + 日期（换目标就换目录，报告不会串）
        st["engagement"] = f"{_slug(st['target'])}-{time.strftime('%Y%m%d')}"
    save(ctx, st)
    log_event(ctx, "target", f"{st['target']} | {st['objective']} | {st.get('engagement')}")
    return st


def add_scope(ctx, value: str) -> list[str]:
    """加一条进清单（去重、留痕）。清单是"允许动手"的唯一依据。"""
    v = (value or "").strip()
    if not v:
        return []
    st = load(ctx)
    st["scope"] = list(dict.fromkeys(list(st.get("scope") or []) + [v]))
    save(ctx, st)
    log_event(ctx, "scope_add", v)
    return [v]


def scope(ctx, cfg_scope_file: str = "") -> list[str]:
    """scope = 状态里的清单 + 可选的外部清单文件。"""
    st = load(ctx)
    items = [s for s in (st.get("scope") or []) if s]
    if cfg_scope_file:
        p = Path(cfg_scope_file).expanduser()
        try:
            if p.is_file():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        items.append(line)
        except Exception:
            pass
    seen, out = set(), []
    for it in items:
        k = it.lower()
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out


def is_redteam(ctx) -> bool:
    try:
        return load(ctx).get("mode") == "redteam"
    except Exception:
        return False


def reports_dir(engagement: str = "") -> Path:
    d = hermes_home() / "purge" / "reports"
    if engagement:
        d = d / _slug(engagement)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _slug(s: str) -> str:
    """文件名安全化：保留中文（人看的报告名要能读懂），挡掉路径分隔符和 ..。"""
    s = (s or "").strip().replace("/", "_").replace("\\", "_")
    s = re.sub(r"[^\w.\-]+", "_", s, flags=re.UNICODE)
    s = s.strip("._-") or "report"
    return s[:80]


def write_report(ctx, name: str, body: str) -> Path:
    """报告回放：落盘 + 记进状态，返回路径。

    目录按 engagement 分（一次任务一个目录），文件名带时间戳前缀，
    所有外部输入都过 _slug —— 记录名可能来自模型，不能让它拼出路径。
    """
    ts = time.strftime("%Y%m%d-%H%M%S")
    eng = _slug(load(ctx).get("engagement") or "general")
    path = reports_dir(eng) / f"{ts}_{_slug(name)}.md"
    path.write_text(body, encoding="utf-8")
    st = load(ctx)
    reps = list(st.get("reports") or [])
    reps.append({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "name": name, "path": str(path)})
    st["reports"] = reps[-100:]
    save(ctx, st)
    return path


# ------------------------------------------------------------------ 战果账本
# 战果即弹药：每次打下来的东西都落一条，能统计、能回看。
# 计分口径与内置 score-rules 的
# DEFAULT_SCORE_POINTS 对齐（25 个得分点：no/code/name/group/default/cap/
# dedup_scope/rule）。applyScoreCaps / evaluateScoreBoard 是上游唯一实现，
# 面板、报告、攻击链三处总分共用同一套口径 —— 这里同样只留一份。

SCORE_POINTS = [
    {
        "no": 1, "code": 'domain-control', "name": '域名控制权限',
        "group": 'GENERAL', "default": 50, "cap": 400,
        "dedup_scope": 'system', "score_desc": '一级 50 / 二级 20 分/个',
        "rule": '**一级域名 50 分/个，二级域名 20 分/个**，按域名类型给分；本项上限 400 分（G3）。 记分时在 evidence 里写明域名与其类型；拿到二级域名时把单次分值调整为 20。',
    },
    {
        "no": 2, "code": 'terminal-access', "name": '终端权限（手机、Pad、PC、打印机、摄像头、wifi 路由器等）',
        "group": 'GENERAL', "default": 10, "cap": 600,
        "dedup_scope": 'system', "score_desc": '5 / 10 分/台',
        "rule": '**打印机、wifi 路由器 5 分/台；PC、Pad、手机、摄像头、电子大屏 10 分/台**（G4），按台累加；本项上限 600 分（G3）。 控制的终端设备需能证明与目标单位的关系（G7）；拿到 5 分档设备时把单次分值调整为 5。 钓鱼获取的终端同样按本项计分，在 evidence 里写明目标人员角色（普通办公 / IT 运维 / 业务运营）。',
    },
    {
        "no": 3, "code": 'server-host', "name": '服务器主机权限（含 webshell 权限）',
        "group": 'GENERAL', "default": 50, "cap": 600,
        "dedup_scope": 'system', "score_desc": '普通 10 / 管理员 50 分/个',
        "rule": '**普通权限 10 分/个，管理员权限 50 分/个**；本项上限 600 分（G3）。 同一主机只按最高权限计一次（G1）——拿到 root/SYSTEM 后同主机不再累加普通权限。 获取 1 台服务器主机不扣分；拿到普通权限时把单次分值调整为 10。',
    },
    {
        "no": 4, "code": 'db-credential', "name": '数据库连接账号密码（含 SQL 注入）',
        "group": 'GENERAL', "default": 50, "cap": 400,
        "dedup_scope": 'system', "score_desc": '普通 10 / 管理员 50 / 未授权 10 分/个',
        "rule": '**普通用户权限 10 分/个，管理员权限 50 分/个；redis 和其他空密码、未授权访问成果统一 10 分/个**；本项上限 400 分（G3）。 同一数据库的同等权限（含管理员）只得一次分；同一主机上的系统权限、应用权限、数据库权限按最高权限只得一次分（G1）。 数据成果单独计分（G2）；拿到普通权限/未授权时把单次分值调整为 10。',
    },
    {
        "no": 5, "code": 'web-app', "name": '邮箱系统 / 办公自动化与业务生产系统 / 其他 Web 应用系统权限',
        "group": 'WEB', "default": 100, "cap": 2000,
        "dedup_scope": 'system', "score_desc": '管理员 100 / 普通 50 分/个',
        "rule": '**管理员权限 100 分/个，普通用户权限 50 分/个；同一个系统只计算一次最高权限分**（G1）；本项上限 2000 分（G3）。 本项合并原表第 5、6 项（规则与上限完全相同），**即"控制 Web 应用系统"这一类**；记分时在 evidence 里写明是哪类系统： · **邮箱系统**； · **办公自动化与业务生产系统**（办公 OA、ERP、直报即时通讯、财务系统、业务生产系统、数据仓库等被控或瘫痪后影响行业或单位业务生产、运行管理、日常办公的系统）； · **其他 Web 应用系统（兜底归类）**：用凭据清单里的账号**实测能登录**的 HTTP/HTTPS 站点，凡不归入其他更具体的得分点类别（集权系统走第 7 项、大数据系统走第 8 项、云管理平台走第 11 项、物联网管控平台走第 12 项、安全设备走第 13 项等），统一按本项计分（管理员 100 / 普通 50）。**凭据里只登记了 `host:port`、没写系统名或业务归属的 Web 登录（后台、管理端、运营平台、自研业务系统等）也走这一条**——先判是否有更贴切的类别，没有就归入"控制 Web 应用系统"，不因"看不出是不是邮箱/OA"而漏记。记分时 `target` 写实际登录 URL（带端口），evidence 写清"什么站点 + 什么账号 + 管理员/普通档"，并按红线一先实测登录。 邮件数据按重要程度再单独计分（G2）；拿到普通用户权限时把单次分值调整为 50。',
    },
    {
        "no": 7, "code": 'central-system', "name": '集权系统权限（运维 / 身份 / 组网 / 终端管理后台）',
        "group": 'CENTRAL', "default": 500, "cap": 4000,
        "dedup_scope": 'system', "score_desc": '管理员 500 / 普通 50 分/个',
        "rule": '**系统管理员权限 500 分/个，普通权限 50 分/个**；同一权限只给一次分，即获取管理员和普通权限只给管理员权限分（G1）；本项上限 4000 分（G3）。 集权系统包括四类： · **运维集权类**：堡垒机、集中监控、统一资源发布等； · **身份权限管理类**：SSO、4A、IAM 等； · **组网集权类**：域控、证书认证、SDWAN 统一控制器等； · **终端主机管理后台类**：终端管理软件后台、零信任控制中心等。 ⚠️ 集权系统**托管的主机、终端等设备跨类引用"控制一般系统"的分值**（如 PC、移动终端 10 分/台，G4）——**不要按集权系统最高档 500 分算**，那会严重偏高；批量控制需提供证明：至少登录托管节点数量的 20%，最多登录 20 台即可。',
    },
    {
        "no": 8, "code": 'bigdata-system', "name": '大数据系统权限',
        "group": 'BIGDATA', "default": 1000, "cap": 4000,
        "dedup_scope": 'system', "score_desc": '管理员 1000 / 普通 100 分/个',
        "rule": '**管理员权限 1000 分，普通权限 100 分/个**；同一权限只给一次分，既获取管理员和普通权限只给管理员权限分（G1）；本项上限 4000 分（G3）。 数据单独计分（G2）；**有效数据量小于 5 亿条或 1TB 的按普通数据库计算**（即改用第 4 项分值）。',
    },
    {
        "no": 9, "code": 'netdev', "name": '网络设备权限（防火墙、路由器、交换机、网闸、光闸、摆渡机、VPN 等）',
        "group": 'NETINFRA', "default": 200, "cap": 2000,
        "dedup_scope": 'service', "score_desc": '普通 100 / 管理员 200 / 加成 200·1000 分',
        "rule": '**普通用户权限 100 分，管理员权限 200 分**；本项上限 2000 分（G3）。需提供路由表等证据或连接量截图（G7）。 在同一台设备上做到下列动作**再加分**（按做到的那一档记分）： · 借助该设备进行**网络重定向或业务劫持**：+200 分； · 在该设备上**植入远控程序并成功进行后续攻击**：1000 分。 拿到普通权限或加成分时，把单次分值按实际档位调整。',
    },
    {
        "no": 10, "code": 'iiot', "name": '工业互联网系统权限',
        "group": 'NETINFRA', "default": 200, "cap": 2000,
        "dedup_scope": 'system', "score_desc": '管理员 200 / 设备 10 分/个',
        "rule": '**管理后台管理员权限 200 分；托管的互联设备 10 分/个**（G4）；本项上限 2000 分（G3）。 含车联网、智能制造、远程诊断、智能交通等。设备按个累加时用另起的命中记录（分值调为 10）。',
    },
    {
        "no": 11, "code": 'cloud-platform', "name": '云管理平台控制权（含 PaaS 云平台，如 K8S、红帽 OpenShift 等）',
        "group": 'NETINFRA', "default": 500, "cap": 2000,
        "dedup_scope": 'system', "score_desc": '管理员 500 / 节点 10 分/台',
        "rule": '**管理员权限 500 分；云上主机、容器 10 分/台**（G4）；本项上限 2000 分（G3）。云上业务系统按重要系统规则单独计分。 通过 ak/sk 批量控制默认**只计算被控节点分数、不计算管理员分数**，除非提供证明具有管理员权限（如新增云上节点、用户权限管理等）。 ⚠️ **节点数量小于 100 的按普通 Web 应用给分，节点不给分**（即走第 5、6 项口径）。',
    },
    {
        "no": 12, "code": 'iot-platform', "name": '物联网设备管控平台权限',
        "group": 'NETINFRA', "default": 200, "cap": 2000,
        "dedup_scope": 'system', "score_desc": '平台 200 / 连接点 10 / 核心网 +5000 分',
        "rule": '**带控制功能的物联网平台 200 分；按平台上连接点数计算 10 分/台**（G4）；本项上限 2000 分（G3）。 **通过物联网端点设备打入核心网并控制业务生产等重要系统的，单独加 5000 分**（不受本项 2000 分上限约束，单独记一条命中）。',
    },
    {
        "no": 13, "code": 'secdev', "name": '安全设备权限（IPS、IDS、审计设备、WAF 等非集权类安全设备）',
        "group": 'NETINFRA', "default": 200, "cap": 1000,
        "dedup_scope": 'service', "score_desc": '管理员 200 分',
        "rule": '**管理员权限 200 分**；本项上限 1000 分（G3）。仅限非集权类安全设备（集权类走第 7 项）。',
    },
    {
        "no": 14, "code": 'file-storage', "name": '文件存储类系统权限（FTP、对象存储、企业 NAS、企业网盘等）',
        "group": 'STORAGE', "default": 50, "cap": 500,
        "dedup_scope": 'system', "score_desc": '管理员 50 / 普通 10 分/个',
        "rule": '**管理员权限 50 分/个；普通用户权限、空系统或只含有测试数据的系统 10 分/个**；本项上限 500 分（G3）。 含 FTP、对象存储（按系统计分）、企业 NAS、企业网盘等；数据单独计分（G2）。拿到普通权限时把单次分值调整为 10。',
    },
    {
        "no": 15, "code": 'ai-agent', "name": '模型智能体、skill 等 agent 工具（并能操作 agent 进行攻击）',
        "group": 'MODEL', "default": 100, "cap": 4000,
        "dedup_scope": 'service', "score_desc": '100–500 分/个',
        "rule": '**100–500 分/个**，区间分，按控制与操作深度研判；本项上限 4000 分（G3）。 含模型智能体、skill 等 agent 工具；记分时在 evidence 里写明控制/操作深度，并按研判档位调整单次分值。',
    },
    {
        "no": 16, "code": 'model-compute', "name": '算力管理平台权限 / 训练数据与知识库系统权限',
        "group": 'MODEL', "default": 500, "cap": 4000,
        "dedup_scope": 'system', "score_desc": '系统管理权限 500 分/个',
        "rule": '**获取系统管理权限 500 分/个**；本项上限 4000 分（G3）。 本项合并原表第 16、17 项（规则逐字相同），记分时在 evidence 里写明是哪类系统： · **算力管理平台**（可管控调度算力资源等）； · **训练数据、知识库等相关系统**（可窃取篡改训练数据或知识库、实施数据投毒等）。 含大量数据系统（超 1 亿条或 10TB）**得分翻倍**、控制知识库相关系统**得分翻倍**（G5）。',
    },
    {
        "no": 18, "code": 'model-data', "name": '模型相关数据系统权限',
        "group": 'MODEL', "default": 500, "cap": 4000,
        "dedup_scope": 'system', "score_desc": '系统管理员权限 500 分/个',
        "rule": '**获取系统管理员权限 500 分/个**；本项上限 4000 分（G3）。 可干扰模型训练、推理、运营服务，窃取篡改模型权重文件等。 ⚠️ 与第 16、17 项的差异**不可抹平**：本项**没有"控制知识库相关系统得分翻倍"**，但有"数据资产成果参照数据评分"（G2）；超大数据规模系统（超 1 亿条或超 10TB）得分翻倍（G5）。',
    },
    {
        "no": 19, "code": 'computepower-admin', "name": '算力基础设施 · 管理员权限',
        "group": 'MODEL', "default": 500, "cap": 2000,
        "dedup_scope": 'system', "score_desc": '管理员 500 分/个',
        "rule": '**管理员权限 500 分/个**；本项上限 2000 分（含路径分，G3）。 本项与「算力基础设施 · 算力卡资源」同属第 19 项、共用 2000 分上限，三项（管理员权限 / 大量算力卡资源 / 算力卡池化平台）可分别得分但受本条总上限约束。',
    },
    {
        "no": 19, "code": 'computepower-cards', "name": '算力基础设施 · 算力卡资源 / 算力卡池化平台',
        "group": 'MODEL', "default": 10, "cap": 2000,
        "dedup_scope": 'none', "score_desc": '10 分/卡',
        "rule": '**10 分/卡**，按卡累加（G4）；获取大量算力卡资源得分、获取算力卡池化平台直接得分，各上限 2000 分，且与「管理员权限」共用第 19 项总上限 2000 分。 记分时在 evidence 里写明卡数或平台名称。',
    },
    {
        "no": 22, "code": 'boundary-logical', "name": '进入逻辑隔离业务内网',
        "group": 'BOUNDARY', "default": 1000, "cap": 0,
        "dedup_scope": 'target', "score_desc": '1000 分',
        "rule": '**1000 分**。适用范围：整个目标单位突破同一类网络边界只给一次分。 证明材料（G7）：防火墙隔离设备的控制截图、能访问内网的截图证明等。',
    },
    {
        "no": 23, "code": 'boundary-strong', "name": '进入逻辑强隔离业务内网',
        "group": 'BOUNDARY', "default": 10000, "cap": 0,
        "dedup_scope": 'target', "score_desc": '10000 分',
        "rule": '**10000 分**。适用范围：整个目标单位突破同一类网络边界只给一次分。 证明材料（G7）：网闸类隔离设备的控制截图、能访问内网的截图证明等。',
    },
    {
        "no": 24, "code": 'boundary-physical', "name": '进入物理隔离内网、核心生产网',
        "group": 'BOUNDARY', "default": 30000, "cap": 0,
        "dedup_scope": 'target', "score_desc": '30000 分',
        "rule": '**30000 分**。适用范围：整个目标单位突破同一类网络边界只给一次分。 证明材料（G7）：防火墙、VPN、多网卡主机、网络设备、网闸类隔离设备的控制截图，能访问内网的截图证明等。 如铁路调度专网、银行核心账务网、电力生产控制大区、运营商信令网、能源生产物联网等。',
    },
    {
        "no": 25, "code": 'boundary-supply', "name": '借助供应链运维通道或云服务进入内网',
        "group": 'BOUNDARY', "default": 1000, "cap": 3000,
        "dedup_scope": 'service', "score_desc": '1000 分（最多 3000）',
        "rule": '按三种情形计分： · 进入**同一主防单位内网**：1000 分； · 借助**一家**供应链单位或云服务进入**多家**主防单位内网：1000 分/每家主防单位； · 借助**多家**供应链单位或云服务进入**一家**主防单位内网不同网络区域：1000 分/个，最多 3000 分。 记分时在 evidence 里写明属于哪种情形、涉及哪家主防单位/哪个网络区域。',
    },
    {
        "no": 9, "code": 'netdev-redirect', "name": '网络设备 · 借助该设备进行网络重定向或业务劫持',
        "group": 'NETINFRA', "default": 200, "cap": 2000,
        "dedup_scope": 'none', "score_desc": '重定向 / 业务劫持 +200 分',
        "rule": '**在原「网络设备权限」分之上另加 200 分**（文档第 9 项）。 适用：改路由/策略把流量引向我方可控节点、DNS 劫持、业务流量劫持等实际生效的重定向。 需要提供证据（G7）：路由表、策略配置或连接量截图；evidence 里写清重定向方向与验证方式。',
    },
    {
        "no": 9, "code": 'netdev-implant', "name": '网络设备 · 植入远控程序并成功进行后续攻击',
        "group": 'NETINFRA', "default": 1000, "cap": 2000,
        "dedup_scope": 'none', "score_desc": '植入远控 + 后续攻击 1000 分',
        "rule": '**在原「网络设备权限」分之上另加 1000 分**（文档第 9 项）。 需要证明「植入成功 **且** 借它完成了后续攻击」两件事：远控进程/持久化证据 + 经该设备发起的后续成果。',
    },
    {
        "no": 12, "code": 'iot-corenet', "name": '物联网 · 经端点设备打入核心网并控制重要系统',
        "group": 'NETINFRA', "default": 5000, "cap": 5000,
        "dedup_scope": 'none', "score_desc": '核心网 +5000 分',
        "rule": '**文档第 12 项明确「单独加 5000 分」**，不占该条 2000 分的上限。 适用：从物联网端点设备横向进入核心网，并控制业务生产等重要系统； evidence 里写清：从哪个端点进、核心网里控了什么系统、拿到了什么权限。',
    },
]

SCORE_BY_CODE = {p["code"]: p for p in SCORE_POINTS}
SCORE_BY_NAME = {p["name"]: p for p in SCORE_POINTS}
SCORE_GROUPS = ["GENERAL", "WEB", "CENTRAL", "BIGDATA", "NETINFRA",
                "STORAGE", "MODEL", "BOUNDARY"]

# 历史账本里用过的旧类目 → 新得分点 code（保证老记录仍可解析、可汇总）
LEGACY_KIND_ALIAS = {
    '突破网络边界': 'boundary-logical',
    '控制一般系统': 'server-host',
    '控制Web应用系统': 'web-app',
    '控制大数据系统': 'bigdata-system',
    '控制模型相关系统': 'model-compute',
    '控制网络基础设施': 'netdev',
    '控制集权系统': 'central-system',
    '设备终端': 'terminal-access',
    '文件存储类系统': 'file-storage',
    '数据成果': '',
    '其他': '',
}

# 兼容旧接口：kind（中文名 / code / 旧类目）→ 默认分值
SCORE_WEIGHTS = {p["name"]: p["default"] for p in SCORE_POINTS}
SCORE_WEIGHTS.update({p["code"]: p["default"] for p in SCORE_POINTS})
for _k, _c in LEGACY_KIND_ALIAS.items():
    if _c and _c in SCORE_BY_CODE:
        SCORE_WEIGHTS.setdefault(_k, SCORE_BY_CODE[_c]["default"])
SCORE_WEIGHTS.setdefault('数据成果', 30)
SCORE_WEIGHTS.setdefault('其他', 5)


def score_point_of(kind: str) -> dict | None:
    """kind 归一化到上游得分点：支持 code、中文名、旧类目别名。"""
    k = (kind or "").strip()
    if not k:
        return None
    if k in SCORE_BY_CODE:
        return SCORE_BY_CODE[k]
    if k in SCORE_BY_NAME:
        return SCORE_BY_NAME[k]
    alias = LEGACY_KIND_ALIAS.get(k)
    if alias and alias in SCORE_BY_CODE:
        return SCORE_BY_CODE[alias]
    return None


def score_default_of(kind: str) -> float:
    """该 kind 的默认分（查不到走旧类目表，再兜底 5 分）。"""
    p = score_point_of(kind)
    if p:
        return float(p["default"])
    return float(SCORE_WEIGHTS.get((kind or "").strip(), 5))


def score_kind_list() -> list[str]:
    """给工具描述 / 报错提示用的类目清单（上游 code + 中文名）。"""
    return [f"{p['code']}（{p['name']}）" for p in SCORE_POINTS]



def ledger_path() -> Path:
    d = hermes_home() / "purge"
    d.mkdir(parents=True, exist_ok=True)
    return d / "ledger.jsonl"


def ledger_add(entry: dict) -> dict:
    _kind = entry.get("kind") or ""
    _pt = score_point_of(_kind)
    rec = {
        "ts": entry.get("ts") or time.strftime("%Y-%m-%d %H:%M:%S"),
        "engagement": entry.get("engagement") or "general",
        "target": entry.get("target") or "",
        "kind": _kind or "其他",
        "code": _pt["code"] if _pt else "",
        "group": _pt["group"] if _pt else "",
        "score": float(entry.get("score") if entry.get("score") is not None
                       else score_default_of(_kind)),
        "evidence": entry.get("evidence") or "",
        "note": entry.get("note") or "",
        "verified": bool(entry.get("verified", False)),
    }
    with ledger_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def ledger_list(limit: int = 20) -> list[dict]:
    p = ledger_path()
    if not p.is_file():
        return []
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    out = []
    for ln in lines[-max(1, limit):]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out


def ledger_summary() -> dict:
    rows = ledger_list(limit=100000)
    by_kind: dict[str, dict] = {}
    for r in rows:
        k = r.get("kind") or "其他"
        slot = by_kind.setdefault(k, {"count": 0, "score": 0.0})
        slot["count"] += 1
        slot["score"] += float(r.get("score") or 0)
    return {
        "count": len(rows),
        "score": round(sum(float(r.get("score") or 0) for r in rows), 2),
        "by_kind": by_kind,
        "last": rows[-1] if rows else None,
        "path": str(ledger_path()),
    }

