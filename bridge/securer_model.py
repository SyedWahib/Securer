#!/usr/bin/env python3
"""Securer's bridge to a local System One model (Julia 1 or Laya).

Securer runs this once per command its parser could not decide. It reads one
JSON request on stdin and prints one JSON answer:

    in:  {"state": "...", "question": "...", "options": ["no...", "yes..."], "type": "noul"}
    out: {"probabilities": [p_no, p_yes]}

Loading the model takes a few seconds, so the first call also starts a warm
copy in the background that listens on a Unix socket inside .securer/model/
and exits after 30 idle minutes. Later calls answer in milliseconds.
Everything (weights, the Python environment) stays in .securer/model.

Julia runs on ONNX Runtime from Supersonic Labs' official ONNX export, so
PyTorch is not needed. `--install julia` downloads that export at a pinned
revision, checks every file's hash, quantizes the weights to INT8 and keeps
the smaller model only if it still agrees with the reference logits that
Supersonic published alongside the export.
"""
import argparse
import hashlib
import json
import logging
import math
import os
import shutil
import socket
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
IDLE_SECONDS = 30 * 60
os.environ.setdefault("HF_HOME", os.path.join(HERE, "hf"))
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("USE_TF", "0")

JULIA_DIR = os.path.join(HERE, "Julia-1")
JULIA_REVISION = "82a2fadf8fccfccdc5fd4e1009ba8f1a265eb7a8"
# HF_ENDPOINT is the usual way to point Hugging Face downloads at a mirror.
JULIA_URL = os.environ.get("HF_ENDPOINT", "https://huggingface.co").rstrip("/") + (
    f"/SupersonicLabs/Julia-1-ONNX/resolve/{JULIA_REVISION}/"
)
# name -> (size in bytes, hash). LFS files carry a SHA-256 of their content;
# small files carry their git blob id.
JULIA_FILES = {
    "model.onnx": (2988923, "sha256:97141d0cfb1da6204e9f8f24d581af72eaeb82cda21149d83eaa6df7160fbcd9"),
    "model.onnx.data": (576782336, "sha256:fd915be810d7ebfb80fb05a48dd33c9484d17ae1b6bcb9e1f544cbaaa913ded1"),
    "tokenizer.json": (34363188, "sha256:609d8f4c067cd3950f88594c5a802616cea245823836ef5848ee4fc40aab5b6f"),
    "parity-cases.json": (53278, "git:8c40728b6ad635e81dc1df4965ed5651ca404e26"),
}
# The export was checked against the original model at these lengths.
PARITY_LENGTHS = (1024, 256)
DECIDE_LENGTHS = (2048, 256)
# Out of Supersonic's 100 reference cases. The FP32 export matches all 100.
MIN_MATCHES_FP32 = 99
MIN_MATCHES_INT8 = 97


def sock_path(engine):
    # Relative to HERE, which main() makes the working directory: socket
    # paths are limited to about 100 bytes, and project paths can be longer.
    return f"{engine}.sock"


class Julia:
    """Julia 1's request encoding and decision graph, as in julia/data.py upstream."""

    TYPES = {"choice": 0, "score": 1, "noul": 2}
    MARKER = "<mask>"

    def __init__(self, model_path, folder=JULIA_DIR):
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.tok = Tokenizer.from_file(os.path.join(folder, "tokenizer.json"))
        ids = [self.tok.token_to_id(t) for t in ("<bos>", "<eos>", self.MARKER, "<pad>")]
        if None in ids:
            raise ValueError("tokenizer is missing <bos>, <eos>, <mask> or <pad>")
        self.cls, self.sep, self.mask, self.pad = ids
        opts = ort.SessionOptions()
        opts.log_severity_level = 3
        self.session = ort.InferenceSession(model_path, opts, providers=["CPUExecutionProvider"])

    def encode(self, text):
        return self.tok.encode(text, add_special_tokens=False).ids

    def sequence(self, row, max_length, head_length, strict=False):
        kind = row.get("type", "choice")
        state, question, labels = row["state"], row["question"], row["options"]
        if strict and any(self.MARKER in t for t in [state, question, *labels]):
            raise ValueError("reserved model marker in request")

        def clean(t):
            return t.replace(self.MARKER, " ")

        head = self.encode(f"{kind} question: {clean(question)}")
        option_ids = [self.encode(" " + clean(x)) for x in labels]
        if strict and any(len(x) > 48 for x in option_ids):
            raise ValueError("option exceeds 48 tokens")
        options = [[self.mask] + x[:48] for x in option_ids]
        budget = head_length - sum(map(len, options))
        if budget < 16:
            per_option = max(4, (head_length - 16) // len(options))
            options = [x[:per_option] for x in options]
            budget = head_length - sum(map(len, options))
        if strict and (len(head) > budget or any(len(x) != len(y) + 1 for x, y in zip(options, option_ids))):
            raise ValueError("question and options exceed the head budget")
        ids = [self.cls] + head[: max(8, budget)] + [self.sep]
        markers = []
        for option in options:
            markers.append(len(ids))
            ids.extend(option)
        ids.append(self.sep)
        state_ids = self.encode(clean(state))
        room = max_length - len(ids) - 1
        if room < 1:
            raise ValueError("question and options leave no room for the state")
        if strict and len(state_ids) > room:
            raise ValueError("state exceeds the context budget")
        return ids + state_ids[:room] + [self.sep], markers, self.TYPES[kind]

    def logits(self, rows, lengths=DECIDE_LENGTHS, strict=False):
        import numpy as np

        enc = [self.sequence(r, *lengths, strict=strict) for r in rows]
        width = ((max(len(ids) for ids, _, _ in enc) + 7) // 8) * 8
        count = max(len(m) for _, m, _ in enc)
        input_ids = np.full((len(enc), width), self.pad, dtype=np.int64)
        attention = np.zeros((len(enc), width), dtype=np.int64)
        positions = np.zeros((len(enc), count), dtype=np.int64)
        mask = np.zeros((len(enc), count), dtype=bool)
        for i, (ids, markers, _) in enumerate(enc):
            input_ids[i, : len(ids)] = ids
            attention[i, : len(ids)] = 1
            positions[i, : len(markers)] = markers
            mask[i, : len(markers)] = True
        qtype = np.array([q for _, _, q in enc], dtype=np.int64)
        (out,) = self.session.run(
            ["logits"],
            {"input_ids": input_ids, "attention_mask": attention, "marker_pos": positions,
             "marker_mask": mask, "qtype": qtype},
        )
        return [out[i, : len(m)].tolist() for i, (_, m, _) in enumerate(enc)]


def softmax(z):
    top = max(z)
    e = [math.exp(x - top) for x in z]
    return [x / sum(e) for x in e]


def julia_model_path():
    try:
        with open(os.path.join(JULIA_DIR, "installed.json")) as f:
            return os.path.join(JULIA_DIR, json.load(f)["model"])
    except (OSError, ValueError, KeyError):
        raise SystemExit("Julia is not installed yet: run sh .securer/model/setup.sh")


def load(engine):
    """Returns decide(request) -> probability that the answer is 'yes'."""
    if engine == "julia":
        model = Julia(julia_model_path())

        def decide(req):
            row = {"state": req["state"], "question": req["question"], "options": req["options"], "type": "noul"}
            return softmax(model.logits([row])[0])[1]

        return decide

    if engine == "laya":
        import laya  # pip install laya

        agent = laya.load("convaiinnovations/laya-multilingual")

        def decide(req):
            res = agent.predict(req["state"], {"outside": {"type": "noul", "instructions": req["question"]}})
            return float(res["answers"]["outside"]["noul"])

        return decide

    raise SystemExit(f"unknown engine {engine!r}")


def verified(path, digest):
    kind, want = digest.split(":")
    h = hashlib.sha256() if kind == "sha256" else hashlib.sha1(b"blob %d\0" % os.path.getsize(path))
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest() == want


def fetch(name, folder, base_url):
    size, digest = JULIA_FILES[name]
    path = os.path.join(folder, name)
    if os.path.exists(path) and os.path.getsize(path) == size and verified(path, digest):
        return path
    part = path + ".part"
    print(f"Downloading {name} ({size / 1e6:.0f} MB)", flush=True)
    try:
        with urllib.request.urlopen(base_url + name, timeout=60) as r, open(part, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
    except OSError as e:
        raise SystemExit(f"Could not download {base_url + name}: {e}")
    if os.path.getsize(part) != size or not verified(part, digest):
        os.remove(part)
        raise SystemExit(f"{name} does not match its published hash, so it was deleted and setup stopped")
    os.replace(part, path)
    return path


def parity(model, cases):
    """Counts the reference cases where the model picks the same option."""
    matches, worst = 0, 0.0
    for start in range(0, len(cases), 4):
        group = cases[start : start + 4]
        got = model.logits([c["request"] for c in group], PARITY_LENGTHS, strict=True)
        for case, z in zip(group, got):
            ref = case["pytorch_logits"]
            matches += max(range(len(z)), key=z.__getitem__) == max(range(len(ref)), key=ref.__getitem__)
            worst = max(worst, max(abs(a - b) for a, b in zip(z, ref)))
    return matches, worst


def install_julia(folder=JULIA_DIR, base_url=JULIA_URL):
    stamp = os.path.join(folder, "installed.json")
    if os.path.exists(stamp):
        with open(stamp) as f:
            if json.load(f).get("revision") == JULIA_REVISION:
                print("Julia 1 is already installed.")
                return
    os.makedirs(folder, exist_ok=True)
    for name in JULIA_FILES:
        fetch(name, folder, base_url)
    with open(os.path.join(folder, "parity-cases.json")) as f:
        cases = json.load(f)

    fp32 = os.path.join(folder, "model.onnx")
    matches, worst = parity(Julia(fp32, folder), cases)
    print(f"FP32 export: {matches}/{len(cases)} reference cases match (largest logit gap {worst:.5f})")
    if matches < MIN_MATCHES_FP32:
        raise SystemExit("The model does not reproduce Supersonic's reference results; not enabling it.")

    from onnxruntime.quantization import QuantType, quantize_dynamic

    logging.disable(logging.WARNING)  # its advice about static pre-processing does not apply here

    int8 = os.path.join(folder, "model.int8.onnx")
    print("Quantizing the weights to INT8", flush=True)
    # MatMul and Gather (the 256k-token embedding table, two thirds of the weights).
    quantize_dynamic(fp32, int8, weight_type=QuantType.QInt8, op_types_to_quantize=["MatMul", "Gather"],
                     extra_options={"MatMulConstBOnly": True})
    q_matches, q_worst = parity(Julia(int8, folder), cases)
    print(f"INT8 weights: {q_matches}/{len(cases)} reference cases match (largest logit gap {q_worst:.5f})")
    if q_matches >= MIN_MATCHES_INT8:
        keep, result = "model.int8.onnx", {"matches": q_matches, "largest_logit_gap": q_worst}
        for name in ("model.onnx", "model.onnx.data"):
            os.remove(os.path.join(folder, name))
    else:
        print("INT8 drifted too far from the reference; keeping the FP32 weights instead.")
        keep, result = "model.onnx", {"matches": matches, "largest_logit_gap": worst}
        os.remove(int8)
    with open(stamp, "w") as f:
        json.dump({"revision": JULIA_REVISION, "model": keep, "parity": result, "cases": len(cases)}, f, indent=2)
    total = sum(os.path.getsize(os.path.join(folder, n)) for n in os.listdir(folder))
    print(f"Julia 1 installed in {folder} ({total / 1e6:.0f} MB)")


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
    ap.add_argument("--install", action="store_true", help="download and check the Julia model")
    ap.add_argument("--serve", action="store_true", help="run the warm background copy")
    ap.add_argument("--no-server", action="store_true", help="always load the model in this process")
    args = ap.parse_args()
    os.chdir(HERE)

    if args.install:
        if args.engine != "julia":
            raise SystemExit("--install is only needed for julia")
        install_julia()
        return
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
