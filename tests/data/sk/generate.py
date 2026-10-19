"""Regenerate software-signed OpenSSH SK verification fixtures (requires OpenSSL 3).

These emulate authenticator signatures; no hardware or private keys are retained.
Run from any directory with: python3 tests/data/sk/generate.py /path/to/openssl
"""

import base64
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

OUTPUT = Path(__file__).parent
OPENSSL = sys.argv[1] if len(sys.argv) > 1 else "openssl"
MESSAGE = b"challenge"
TRAILER = b"\x01\x01\x02\x03\x04"  # user present, counter 0x01020304


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


def run(*args):
    return subprocess.check_output([OPENSSL, *args])


def read_der(data, offset):
    tag, size = data[offset : offset + 2]
    assert size < 128
    return tag, data[offset + 2 : offset + 2 + size], offset + 2 + size


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    key, data, sig = (root / name for name in ("key.pem", "data", "sig"))
    for kind in ("ecdsa", "ed25519"):
        algorithm = (
            b"sk-ecdsa-sha2-nistp256@openssh.com"
            if kind == "ecdsa"
            else b"sk-ssh-ed25519@openssh.com"
        )
        options = ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
        if kind == "ed25519":
            options = ["-algorithm", "ED25519"]
        run("genpkey", *options, "-out", str(key))
        public = run("pkey", "-in", str(key), "-pubout", "-outform", "DER")
        for name, application in (("default", b"ssh:"), ("custom", b"ssh:pam-test")):
            data.write_bytes(
                hashlib.sha256(application).digest()
                + TRAILER
                + hashlib.sha256(MESSAGE).digest()
            )
            if kind == "ecdsa":
                run("dgst", "-sha256", "-sign", str(key), "-out", str(sig), str(data))
                _, sequence, _ = read_der(sig.read_bytes(), 0)
                _, r, offset = read_der(sequence, 0)
                _, s, _ = read_der(sequence, offset)
                signature = ssh_string(r) + ssh_string(s)
                public_blob = ssh_string(b"nistp256") + ssh_string(public[-65:])
            else:
                run("pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(data), "-out", str(sig))
                signature = sig.read_bytes()
                public_blob = ssh_string(public[-32:])
            public_blob = ssh_string(algorithm) + public_blob + ssh_string(application)
            prefix = OUTPUT / f"{kind}_{name}"
            prefix.with_suffix(".pub").write_text(
                algorithm.decode() + " " + base64.b64encode(public_blob).decode() + "\n"
            )
            wire = ssh_string(algorithm) + ssh_string(signature) + TRAILER
            prefix.with_suffix(".sig").write_text(base64.b64encode(wire).decode() + "\n")
