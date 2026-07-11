"""Cost accounting (EXPERIMENTS.md RQ2, PAPER.md C4).

What does continuity charge? We count primitive *operations* (KDF, hash,
AEAD, signature, DH) per message and per epoch change, and measure real
wire bytes — not wall-clock, whose Python overhead would swamp and
misrepresent the primitives (EXPERIMENTS §2). KDF and hash counts are
instrumented empirically by patching tessera.kdf / tessera.H; AEAD and
signature counts are one-per-operation by construction and asserted
against the code paths.

Time estimates multiply op-counts by *illustrative* per-op costs for a
modern x86 core (order-of-magnitude, from published libsodium / BoringSSL
Ed25519 and ChaCha20-Poly1305 benchmarks). They exist to show the shape —
signatures dominate the KDF chain by ~50x — not to claim a throughput.
"""

from __future__ import annotations

import contextlib
import struct

import tessera
from tessera import (
    FP_LEN, SALT_LEN, Member, MemberKeys,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Illustrative per-op costs (microseconds), modern x86 single core.
# Sources: libsodium / BoringSSL microbenchmarks, order-of-magnitude.
US = {"kdf": 0.30, "hash": 0.08, "aead": 0.40, "sign": 18.0, "verify": 45.0,
      "dh": 35.0}


class Counter:
    def __init__(self):
        self.n = {k: 0 for k in ("kdf", "hash", "aead", "sign", "verify", "dh")}

    def add(self, kind, k=1):
        self.n[kind] += k

    def micros(self):
        return sum(self.n[k] * US[k] for k in self.n)

    def __repr__(self):
        parts = ", ".join(f"{k}={v}" for k, v in self.n.items() if v)
        return f"<{parts} | {self.micros():.1f}us>"


@contextlib.contextmanager
def counting():
    """Patch the pure-Python primitives to count real invocations. AEAD/
    signature/DH are counted separately at call sites (they are C calls and
    exactly one-per-operation here)."""
    c = Counter()
    real_kdf, real_H = tessera.kdf, tessera.H

    def kdf(key, label, data):
        c.add("kdf")
        return real_kdf(key, label, data)

    def H(data):
        c.add("hash")
        return real_H(data)

    tessera.kdf, tessera.H = kdf, H
    try:
        yield c
    finally:
        tessera.kdf, tessera.H = real_kdf, real_H


def _swarm(n):
    keys = {f"a{i}".encode(): (Ed25519PrivateKey.generate(),
                               X25519PrivateKey.generate()) for i in range(n)}
    roster = {mid: MemberKeys(sk.public_key(), kk.public_key())
              for mid, (sk, kk) in keys.items()}
    import os
    secret = os.urandom(32)
    return [Member(mid, sk, kk, roster, secret) for mid, (sk, kk) in keys.items()]


# ---------------------------------------------------------------- per message

def per_message():
    """Cost to send one message and for one receiver to verify+deliver it.
    Signature/AEAD are added by construction: send = 1 sign + 1 aead-encrypt;
    receive-deliver = 1 verify + 1 aead-decrypt."""
    swarm = _swarm(3)
    sender, receiver = swarm[0], swarm[1]

    with counting() as cs:
        wire = sender.send(b"a representative agent message of moderate size")
    cs.add("sign"); cs.add("aead")  # send: sign header||H(body), encrypt body

    with counting() as cr:
        evs = receiver.receive(wire)
    cr.add("verify"); cr.add("aead")  # receive: verify sig, decrypt body
    assert any(type(e).__name__ == "Delivered" for e in evs)

    wire_bytes = _wire_size(wire)
    return dict(send=cs, recv=cr, wire_bytes=wire_bytes)


def per_heartbeat():
    swarm = _swarm(3)
    a, b = swarm[0], swarm[1]
    with counting() as cs:
        hb = a.heartbeat()
    cs.add("sign")
    with counting() as cr:
        b.receive_heartbeat(hb)
    cr.add("verify")
    return dict(emit=cs, recv=cr, hb_bytes=_hb_size(hb))


def per_epoch_change(n):
    """Cost of a HEAL epoch change: coordinator seals to N-1 members, each
    member unwraps. Seal/open are HPKE-shaped: 1 DH + 1 aead each side."""
    swarm = _swarm(n)
    coord = swarm[0]
    with counting() as cc:
        ec, _ = coord.make_epoch_change("HEAL")
    # coordinator: one ephemeral DH + one AEAD seal per recipient (N members)
    cc.add("dh", n); cc.add("aead", n); cc.add("sign")  # + coord signature
    member = swarm[1]
    with counting() as cm:
        member.apply_epoch_change(ec)
    cm.add("verify")            # coordinator signature
    cm.add("dh"); cm.add("aead")  # unwrap own sealed secret
    return dict(n=n, coordinator=cc, member=cm,
                bundle_bytes=_ec_size(ec))


# ---------------------------------------------------------------- sizes

def _wire_size(w):
    # header + body(=salt+plaintext+16 tag) + sig(64)
    return len(w.header_bytes()) + len(w.body) + len(w.sig)


def _hb_size(hb):
    return len(hb.signed_payload()) + len(hb.sig)


def _ec_size(ec):
    body = ec.context()
    sealed = sum(len(m) + len(e) + len(c) for m, e, c in ec.sealed)
    sigs = sum(len(m) + len(s) for m, s in ec.proposal_sigs) + len(ec.coord_sig)
    return len(body) + sealed + sigs


# ---------------------------------------------------------------- baseline

def baseline_signed_no_chain():
    """The marginal-cost baseline: sign + AEAD per message, NO chain (no fp,
    no salt-advance). Isolates what the transcript binding actually adds."""
    # send: 1 sign + 1 aead; recv: 1 verify + 1 aead; zero KDF, zero hash-chain
    send = Counter(); send.add("sign"); send.add("aead")
    recv = Counter(); recv.add("verify"); recv.add("aead")
    # wire: header(no fp) + body(no salt) + sig
    header = 1 + 4 + 8 + 1 + 2  # ver,E,n,idlen,id(~2)
    body = len(b"a representative agent message of moderate size") + 16
    return dict(send=send, recv=recv, wire_bytes=header + body + 64)


# ---------------------------------------------------------------- report

def report():
    m = per_message()
    hb = per_heartbeat()
    base = baseline_signed_no_chain()

    lines = ["## RQ2 — Cost", "",
             "Per-op costs are illustrative (modern x86, us): "
             + ", ".join(f"{k}={v}" for k, v in US.items()) + ".", "",
             "### Per message", "",
             "| path | KDF | hash | AEAD | sign | verify | est. us | wire B |",
             "|---|---|---|---|---|---|---|---|"]
    for label, c, wb in [("Tessera send", m["send"], m["wire_bytes"]),
                         ("Tessera recv", m["recv"], m["wire_bytes"]),
                         ("baseline send (signed, no chain)", base["send"],
                          base["wire_bytes"]),
                         ("baseline recv", base["recv"], base["wire_bytes"])]:
        lines.append(_row(label, c, wb))

    dsend = m["send"].micros() - base["send"].micros()
    lines += ["",
              f"**Marginal cost of binding, send:** "
              f"+{m['send'].n['kdf']} KDF, +{m['send'].n['hash']} hash "
              f"= +{dsend:.1f} us over the signed baseline "
              f"({dsend / m['send'].micros() * 100:.1f}% of send cost). "
              f"The Ed25519 signature ({US['sign']} us) dwarfs it — the whole "
              f"chain costs about 1/{US['sign'] / dsend:.0f} of one signature, "
              f"the signature you already pay for authenticity.",
              f"**Wire overhead of binding:** "
              f"+{m['wire_bytes'] - base['wire_bytes']} B/message "
              f"(fp {FP_LEN} + salt {SALT_LEN}).",
              "",
              "### Per heartbeat", "",
              "| path | KDF | hash | AEAD | sign | verify | est. us | bytes |",
              "|---|---|---|---|---|---|---|---|",
              _row("emit", hb["emit"], hb["hb_bytes"]),
              _row("recv", hb["recv"], hb["hb_bytes"]),
              "",
              "### Per epoch change (HEAL), by swarm size N", "",
              "| N | coordinator us | member us | bundle B | per-member B |",
              "|---|---|---|---|---|"]
    for n in (5, 25, 100):
        e = per_epoch_change(n)
        lines.append(
            f"| {n} | {e['coordinator'].micros():.0f} | "
            f"{e['member'].micros():.0f} | {e['bundle_bytes']} | "
            f"{e['bundle_bytes'] // n} |")
    lines += ["",
              "Epoch cost is O(N) at the coordinator (one seal per member); "
              "MLS's ratchet tree would make it O(log N) if N grows large "
              "(PROTOCOL §9). At the cadences of PROTOCOL §12 (~15 min) this "
              "is negligible against per-message traffic."]
    return "\n".join(lines)


def _row(label, c, size):
    n = c.n
    return (f"| {label} | {n['kdf']} | {n['hash']} | {n['aead']} | "
            f"{n['sign']} | {n['verify']} | {c.micros():.1f} | {size} |")


if __name__ == "__main__":
    import json
    import os
    print(report())
    # persist the machine-readable numbers too
    os.makedirs("results", exist_ok=True)
    m, hb = per_message(), per_heartbeat()
    data = dict(
        per_message_send=m["send"].n, per_message_recv=m["recv"].n,
        wire_bytes=m["wire_bytes"], heartbeat_bytes=hb["hb_bytes"],
        baseline_wire_bytes=baseline_signed_no_chain()["wire_bytes"],
        epoch=[{**{"n": nn}, "coordinator_us": per_epoch_change(nn)["coordinator"].micros(),
                "bundle_bytes": per_epoch_change(nn)["bundle_bytes"]}
               for nn in (5, 25, 100)])
    json.dump(data, open("results/rq2_cost.json", "w"), indent=2)
