#!/usr/bin/env python3
"""Securer's bridge to a local System One model (Julia 1 or Laya).

Securer runs this once per command its parser could not decide. It reads one
JSON request on stdin and prints one JSON answer:

    in:  {"state": "...", "question": "...", "options": ["no...", "yes..."], "type": "noul"}
    out: {"probabilities": [p_no, p_yes]}

Loading the model takes a few seconds, so the first call also starts a warm
copy in the background that listens on a Unix socket inside .securer/model/
and exits after 30 idle minutes. Later calls answer in milliseconds.
Everything (weights, caches, the Python environment) stays in .securer/model.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
IDLE_SECONDS = 30 * 60
os.environ.setdefault("HF_HOME", os.path.join(HERE, "hf"))
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("USE_TF", "0")


def sock_path(engine):
    return os.path.join(HERE, f"{engine}.sock")


def load(engine):
    """Returns decide(request) -> probability that the answer is 'yes'."""
    if engine == "julia":
        from julia import load_model  # pip install -e .securer/model/Julia-1

        model = load_model(os.path.join(HERE, "Julia-1"), device="cpu", strict_encoding=False, max_length=2048, head_length=256)

        def decide(req):
            no, yes = req["options"]
            try:
                res = model.predict(
                    state=req["state"],
                    questions={"outside": {"type": "noul", "instructions": req["question"], "criteria": {"false": no, "true": yes}}},
                )
                return float(res["answers"]["outside"]["noul"])
            except TypeError:
                # Older list-style API: false option first, true second.
                row = model.predict([{"state": req["state"], "question": req["question"], "options": [no, yes], "type": "noul"}])[0]
                probs = row["probabilities"]
                return float(probs[1] if isinstance(probs, (list, tuple)) else list(probs.values())[1])

        return decide

    if engine == "laya":
        import laya  # pip install laya

        agent = laya.load("convaiinnovations/laya-multilingual")

        def decide(req):
            res = agent.predict(req["state"], {"outside": {"type": "noul", "instructions": req["question"]}})
            return float(res["answers"]["outside"]["noul"])

        return decide

    raise SystemExit(f"unknown engine {engine!r}")


def answer(decide, req):
    try:
        p = decide(req)
        return {"probabilities": [1.0 - p, p]}
    except Exception as e:  # reported to Securer, which then uses its safe default
        return {"error": f"{type(e).__name__}: {e}"}


def ask_server(engine, req):
    path = sock_path(engine)
    if not hasattr(socket, "AF_UNIX") or not os.path.exists(path):
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(30)
            s.connect(path)
            s.sendall(json.dumps(req).encode() + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            return json.loads(buf)
    except (OSError, ValueError):
        return None


def serve(engine):
    decide = load(engine)
    path = sock_path(engine)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(8)
    srv.settimeout(IDLE_SECONDS)
    try:
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                break
            with conn:
                conn.settimeout(30)
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                try:
                    out = answer(decide, json.loads(buf))
                except ValueError as e:
                    out = {"error": f"bad request: {e}"}
                conn.sendall(json.dumps(out).encode() + b"\n")
    finally:
        srv.close()
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["julia", "laya"], default="julia")
    ap.add_argument("--serve", action="store_true", help="run the warm background copy")
    ap.add_argument("--no-server", action="store_true", help="always load the model in this process")
    args = ap.parse_args()

    if args.serve:
        serve(args.engine)
        return

    req = json.load(sys.stdin)
    if not args.no_server:
        out = ask_server(args.engine, req)
        if out is not None:
            print(json.dumps(out))
            return
        if hasattr(socket, "AF_UNIX"):
            # Start the warm copy for next time, then answer this one ourselves.
            subprocess.Popen(
                [sys.executable, os.path.abspath(__file__), "--engine", args.engine, "--serve"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True, cwd=HERE,
            )
    print(json.dumps(answer(load(args.engine), req)))


if __name__ == "__main__":
    main()
