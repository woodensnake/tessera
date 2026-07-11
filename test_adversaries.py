"""M2 adversary harness: one test per RQ1 claim (EXPERIMENTS §1), including
the honest negatives. Detection latency is measured from injection."""

from adversaries import run_adversary_trial
from sim import run_trial


# --- the zero that must stay zero ---

def test_honest_run_has_no_false_positives():
    """EXPERIMENTS §5: any detection in an adversary-free run is a dispatch
    bug. This is the canary the whole harness leans on."""
    for seed in range(8):
        m = run_trial(n=5, duration=400, seed=seed, rate=0.3, loss=0.03)
        assert m["detection_count"] == 0
        assert m["false_positive"] is False
        assert m["forged_accepted"] == 0


def test_impostor_never_accepted():
    """A6: no keys means it cannot speak. forged_accepted must stay 0."""
    m = run_adversary_trial("A6", n=5, duration=400, seed=1, rate=0.3)
    assert m["forged_accepted"] == 0
    assert m["adversary"] == "A6"


# --- clone (A3): the RQ1 centerpiece ---

def test_speaking_clone_produces_evidence_fast():
    """H1b: a live clone's second message at a slot is a signed contradiction,
    detected within about one message, and correctly attributed."""
    m = run_adversary_trial("A3", n=5, duration=400, seed=2, rate=0.5)
    assert m["detected"] is True
    assert m["detection_kind"] in ("CloneEvidence", "Fork")
    assert m["attribution_correct"] is True
    assert m["detection_positions"] <= 2
    assert m["forged_accepted"] == 0  # a contradiction is evidence, not delivery


def test_stale_restore_clone_caught_when_it_speaks():
    """A snapshot-restored clone that SPEAKS new content at its frozen (still
    in-window) slot is caught as a contradiction — PROTOCOL §8's "detected on
    its next message", now qualified: it is the message, not a passive
    heartbeat, that betrays it."""
    m = run_adversary_trial("A3-stale", n=6, duration=400, seed=3, rate=0.5)
    assert m["detected"] is True
    assert m["detection_kind"] == "CloneEvidence"
    assert m["attribution_correct"] is True


def test_silent_clone_is_not_detected():
    """H1c, and a finding broader than PROTOCOL §8 first claimed: a SILENT
    clone is undetectable by fingerprint whether synced or stale. A clone
    frozen at a past position holds the correct fingerprint for it, so its
    heartbeat is indistinguishable from an honest laggard's. 'Behind' is not
    'forked'; only a spoken contradiction reveals a clone."""
    synced = run_adversary_trial("A3-silent", n=5, duration=400, seed=4, rate=0.5)
    assert synced["detected"] is False
    assert synced["detection_count"] == 0


# --- equivocation (A4) ---

def test_equivocation_forks_and_attributes():
    """A4: divergent messages to two halves fork the swarm; the next crossing
    wire raises Fork, attributed to the equivocator."""
    m = run_adversary_trial("A4", n=6, duration=400, seed=5, rate=0.5)
    assert m["detected"] is True
    assert m["detection_kind"] in ("Fork", "ChainDivergence")
    assert m["attribution_correct"] is True


# --- eavesdropper / key thief (A1/A2): confidentiality, not detection ---

def test_eavesdropper_reads_nothing():
    """A1 floor: ciphertext alone yields no plaintext and no alarm."""
    m = run_adversary_trial("A1", n=5, duration=300, seed=6, rate=0.3)
    assert m["adversary_reads"] == 0
    assert m["detected"] is False


def test_key_thief_reads_until_first_gap_then_blinds():
    """A2 with perfect capture reads while synced; with a capture gap it goes
    permanently blind — the gap-lockout property from the attacker's side."""
    full = run_adversary_trial("A2", n=5, duration=400, seed=7, rate=0.5,
                               capture=1.0, loss=0.0)
    assert full["adversary_reads"] > 0
    assert full["adversary_blind_from"] is None  # never missed, never blind

    gappy = run_adversary_trial("A2", n=5, duration=400, seed=7, rate=0.5,
                                capture=0.9)
    assert gappy["adversary_blind_from"] is not None  # a gap froze its chain
    assert gappy["detected"] is False                 # passive: nothing to detect
