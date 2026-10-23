"""Task contract: the structured form of "what this run is allowed to do, and what counts as done".

Why this exists
---------------
A prompt that says "targets come from 风哥" is advice; it does not stop a scanner. This module
turns that advice into a file the executors read, and a completion check that fails when the
evidence does not back the claim.

Design
------
* One JSON document per task, plain stdlib, atomic writes, no daemons.
* State machine: draft -> ready -> running -> verify -> delivered, plus blocked/failed/stopped.
* Evidence entries carry path + sha256 + timestamp, so a later reader can prove the bytes are
  the ones that were produced (a pointer alone rots).
* Findings are tri-state: observed (saw it) / candidate (needs review) / confirmed (reproduced).
* close() refuses to deliver when evidence is missing, a hash no longer matches, or a promised
  deliverable was never produced — "the workflow ran" is not "the task is done".

CLI
---
    python3 -m yf_tools.task_contract new    --target T --operation active -o c.json
    python3 -m yf_tools.task_contract set    c.json --scope a.example --egress 127.0.0.1:7890
    python3 -m yf_tools.task_contract state  c.json ready
    python3 -m yf_tools.task_contract evidence c.json --path /root/apks/x.yml --kind sub
    python3 -m yf_tools.task_contract finding  c.json --id F1 --status candidate --note "..."
    python3 -m yf_tools.task_contract coverage c.json --planned 100 --done 74
    python3 -m yf_tools.task_contract verify c.json
    python3 -m yf_tools.task_contract close  c.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

OPERATIONS = ("read_only", "low_impact", "active", "validation")
STATES = ("draft", "ready", "running", "verify", "delivered", "blocked", "failed", "stopped")
FINDING_STATES = ("observed", "candidate", "confirmed")

# Allowed transitions. blocked/failed/stopped are reachable from any live state.
_TRANSITIONS = {
    "draft": {"ready", "blocked", "failed", "stopped"},
    "ready": {"running", "blocked", "failed", "stopped"},
    "running": {"verify", "blocked", "failed", "stopped"},
    "verify": {"delivered", "running", "blocked", "failed", "stopped"},
    "delivered": set(),
    "blocked": {"ready", "stopped"},
    "failed": {"ready", "stopped"},
    "stopped": set(),
}


class ContractError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ContractError(f"contract not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ContractError(f"contract is not valid JSON: {exc}") from exc
    if data.get("kind") != "yf_task_contract":
        raise ContractError("not a yf_task_contract document")
    return data


def save(path: str | Path, data: dict) -> None:
    data["updated_at"] = _now()
    _atomic_write(Path(path), data)


def new(target: str, operation: str = "active", task: str = "") -> dict:
    if not isinstance(target, str) or not target.strip():
        raise ContractError("target is required")
    if operation not in OPERATIONS:
        raise ContractError(f"operation must be one of {OPERATIONS}")
    return {
        "kind": "yf_task_contract",
        "version": 1,
        "task": task or target,
        "target": target.strip(),
        "operation": operation,
        "state": "draft",
        "scope": [],
        "forbidden": [],
        "egress": "",
        "deliverables": [],
        "evidence": [],
        "findings": [],
        "coverage": {"planned": 0, "done": 0, "skipped": []},
        "unmet": [],
        "history": [{"at": _now(), "event": "created", "target": target, "operation": operation}],
        "created_at": _now(),
        "updated_at": _now(),
    }


def set_state(data: dict, new_state: str) -> dict:
    if new_state not in STATES:
        raise ContractError(f"state must be one of {STATES}")
    cur = data.get("state", "draft")
    if new_state == cur:
        return data
    if new_state not in _TRANSITIONS.get(cur, set()):
        raise ContractError(f"illegal transition {cur} -> {new_state}")
    if new_state == "ready":
        if not data.get("target"):
            raise ContractError("cannot ready a contract without a target")
        if not data.get("scope"):
            raise ContractError("cannot ready a contract without an explicit scope list")
    data["state"] = new_state
    data.setdefault("history", []).append({"at": _now(), "event": "state", "from": cur, "to": new_state})
    return data


def add_evidence(data: dict, path: str, kind: str = "artifact", note: str = "") -> dict:
    p = Path(path)
    if not p.is_file():
        raise ContractError(f"evidence file does not exist: {p}")
    entry = {
        "path": str(p.resolve()),
        "sha256": _sha256(p),
        "bytes": p.stat().st_size,
        "kind": kind,
        "note": note,
        "at": _now(),
    }
    ev = data.setdefault("evidence", [])
    for existing in ev:
        if existing.get("path") == entry["path"] and existing.get("sha256") == entry["sha256"]:
            return data  # same bytes already registered
    ev.append(entry)
    return data


def add_finding(data: dict, fid: str, status: str, note: str = "", target: str = "") -> dict:
    if status not in FINDING_STATES:
        raise ContractError(f"finding status must be one of {FINDING_STATES}")
    if status == "confirmed" and not data.get("evidence"):
        raise ContractError("a confirmed finding needs at least one registered evidence file")
    findings = data.setdefault("findings", [])
    for item in findings:
        if item.get("id") == fid:
            item.update({"status": status, "note": note, "at": _now()})
            if target:
                item["target"] = target
            return data
    findings.append({"id": fid, "status": status, "note": note, "target": target or data.get("target", ""), "at": _now()})
    return data


def set_coverage(data: dict, planned: int | None = None, done: int | None = None,
                 skipped: list[str] | None = None) -> dict:
    cov = data.setdefault("coverage", {"planned": 0, "done": 0, "skipped": []})
    if planned is not None:
        cov["planned"] = int(planned)
    if done is not None:
        cov["done"] = int(done)
    if skipped:
        cov["skipped"] = list(skipped)
    return data


def verify(data: dict) -> list[str]:
    """Return the list of unmet conditions. Empty list = the contract can be delivered."""
    problems: list[str] = []

    if data.get("state") not in ("verify", "delivered"):
        problems.append(f"state is {data.get('state')}, expected verify before delivery")

    if not data.get("scope"):
        problems.append("no scope recorded")

    for idx, ev in enumerate(data.get("evidence", [])):
        path = Path(ev.get("path", ""))
        if not path.is_file():
            problems.append(f"evidence[{idx}] missing on disk: {ev.get('path')}")
            continue
        current = _sha256(path)
        if current != ev.get("sha256"):
            problems.append(
                f"evidence[{idx}] hash changed ({ev.get('path')}): "
                f"recorded {str(ev.get('sha256'))[:12]} now {current[:12]}"
            )

    for item in data.get("findings", []):
        if item.get("status") == "confirmed" and not any(
            ev.get("kind") in ("poc", "repro", "artifact", "raw") for ev in data.get("evidence", [])
        ):
            problems.append(f"finding {item.get('id')} is confirmed but no repro/PoC evidence is registered")

    cov = data.get("coverage") or {}
    planned, done = int(cov.get("planned") or 0), int(cov.get("done") or 0)
    if planned and done < planned:
        skipped = cov.get("skipped") or []
        unexplained = planned - done - len(skipped)
        if unexplained > 0:
            problems.append(
                f"coverage incomplete: planned {planned}, done {done}, "
                f"skipped listed {len(skipped)}, unexplained {unexplained}"
            )

    for name in data.get("deliverables", []):
        if not any(Path(ev.get("path", "")).name == Path(name).name for ev in data.get("evidence", [])):
            problems.append(f"deliverable not produced: {name}")

    return problems


def close(data: dict) -> dict:
    problems = verify(data)
    data["unmet"] = problems
    if problems:
        if data.get("state") in ("ready", "running", "blocked", "failed"):
            data["state"] = "verify"
        data.setdefault("history", []).append(
            {"at": _now(), "event": "close_refused", "unmet": len(problems)})
        return data
    data["state"] = "delivered"
    data["delivered_at"] = _now()
    data.setdefault("history", []).append({"at": _now(), "event": "delivered"})
    return data


# ---------------------------------------------------------------- CLI


def _parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="task_contract", description=(__doc__ or "").splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_new = sub.add_parser("new", help="create a draft contract")
    p_new.add_argument("--target", required=True)
    p_new.add_argument("--operation", default="active", choices=OPERATIONS)
    p_new.add_argument("--task", default="")
    p_new.add_argument("-o", "--out", required=True)

    p_set = sub.add_parser("set", help="update scope / forbidden / egress / deliverables")
    p_set.add_argument("file")
    p_set.add_argument("--scope", action="append", default=None)
    p_set.add_argument("--forbidden", action="append", default=None)
    p_set.add_argument("--egress", default=None)
    p_set.add_argument("--deliverable", action="append", default=None)

    p_state = sub.add_parser("state", help="move the state machine")
    p_state.add_argument("file")
    p_state.add_argument("state", choices=STATES)

    p_ev = sub.add_parser("evidence", help="register an artifact with its hash")
    p_ev.add_argument("file")
    p_ev.add_argument("--path", required=True)
    p_ev.add_argument("--kind", default="artifact")
    p_ev.add_argument("--note", default="")

    p_f = sub.add_parser("finding", help="record a finding (observed/candidate/confirmed)")
    p_f.add_argument("file")
    p_f.add_argument("--id", required=True)
    p_f.add_argument("--status", required=True, choices=FINDING_STATES)
    p_f.add_argument("--note", default="")
    p_f.add_argument("--target", default="")

    p_c = sub.add_parser("coverage", help="record planned/done/skipped")
    p_c.add_argument("file")
    p_c.add_argument("--planned", type=int, default=None)
    p_c.add_argument("--done", type=int, default=None)
    p_c.add_argument("--skipped", action="append", default=None)

    p_v = sub.add_parser("verify", help="check without closing")
    p_v.add_argument("file")

    p_close = sub.add_parser("close", help="close; refuses delivery while conditions are unmet")
    p_close.add_argument("file")

    p_show = sub.add_parser("show", help="print a summary")
    p_show.add_argument("file")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    if args.cmd == "new":
        data = new(args.target, args.operation, args.task)
        save(args.out, data)
        print(json.dumps({"created": args.out, "state": data["state"]}, ensure_ascii=False))
        return 0

    data = load(args.file)

    if args.cmd == "set":
        if args.scope:
            data["scope"] = list(args.scope)
        if args.forbidden:
            data["forbidden"] = list(args.forbidden)
        if args.egress is not None:
            data["egress"] = args.egress
        if args.deliverable:
            data["deliverables"] = list(args.deliverable)
        save(args.file, data)
        print("updated")
        return 0

    if args.cmd == "state":
        set_state(data, args.state)
        save(args.file, data)
        print(f"state={data['state']}")
        return 0

    if args.cmd == "evidence":
        add_evidence(data, args.path, args.kind, args.note)
        save(args.file, data)
        print(f"evidence={len(data['evidence'])}")
        return 0

    if args.cmd == "finding":
        add_finding(data, args.id, args.status, args.note, args.target)
        save(args.file, data)
        print(f"findings={len(data['findings'])}")
        return 0

    if args.cmd == "coverage":
        set_coverage(data, args.planned, args.done, args.skipped)
        save(args.file, data)
        print(json.dumps(data["coverage"], ensure_ascii=False))
        return 0

    if args.cmd == "verify":
        problems = verify(data)
        if not problems:
            print("OK: all delivery conditions met")
            return 0
        print("UNMET:")
        for p in problems:
            print("  -", p)
        return 1

    if args.cmd == "close":
        data = close(data)
        save(args.file, data)
        if data["unmet"]:
            print(f"NOT DELIVERED ({len(data['unmet'])} unmet):")
            for p in data["unmet"]:
                print("  -", p)
            return 1
        print("delivered")
        return 0

    if args.cmd == "show":
        summary = {
            "task": data.get("task"), "target": data.get("target"),
            "operation": data.get("operation"), "state": data.get("state"),
            "scope": data.get("scope"), "egress": data.get("egress"),
            "evidence": len(data.get("evidence", [])),
            "findings": [(f.get("id"), f.get("status")) for f in data.get("findings", [])],
            "coverage": data.get("coverage"), "unmet": data.get("unmet", []),
        }
        print(json.dumps(summary, ensure_ascii=False, indent=1))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
