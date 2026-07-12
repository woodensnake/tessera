"""Lane sim: sequencer-free liveness. The point is convergence under loss
WITHOUT any global order — matching the single chain's robustness."""

from lane_sim import run_lane_trial


def test_lossless_converges_to_one_braid():
    m = run_lane_trial(n=5, duration=300, seed=1, rate=0.3, loss=0.0)
    assert m["converged"] and m["distinct_braids_at_end"] == 1
    assert m["lane_forks"] == 0 and m["braid_divergences"] == 0
    assert m["delivered"] == m["sent"] * 4        # every member sees every lane


def test_converges_under_loss_without_a_sequencer():
    """The headline: no global sequencer, yet the swarm converges under loss
    up to 20% — braid claims drive lost-tail recovery per lane."""
    for loss in (0.05, 0.10, 0.20):
        for seed in range(3):
            m = run_lane_trial(n=5, duration=300, seed=seed, rate=0.3, loss=loss)
            assert m["converged"], f"diverged at loss={loss} seed={seed}"
            assert m["lane_forks"] == 0
            assert m["braid_divergences"] == 0    # honest run: never a fork


def test_burst_loss_still_converges():
    m = run_lane_trial(n=6, duration=300, seed=2, rate=0.3, loss=0.08,
                       burst_len=10)
    assert m["converged"]
    assert m["lane_forks"] == 0 and m["braid_divergences"] == 0


def _wave(n, frac, start, dur):
    k = max(1, int(n * frac))
    return {f"agent-{i:03d}".encode(): (start, start + dur)
            for i in range(1, k + 1)}


def test_correlated_churn_recovers_without_a_rekey():
    """The parity result: a correlated outage that stormed the single chain
    (40% of the swarm offline, deep enough to exceed the resync threshold) is
    handled on lanes by per-member resync — with ZERO global re-keys, so the
    cascade cannot form — and the swarm fully reconverges."""
    for seed in range(4):
        m = run_lane_trial(n=20, duration=350, seed=seed, rate=0.5,
                           offline_windows=_wave(20, 0.4, 80.0, 120.0))
        assert m["converged"], f"did not reconverge, seed={seed}"
        assert m["resyncs"] > 0            # the deep outage exercised resync
        assert m["rekeys"] == 0            # and never a global re-key: no storm
        assert m["lane_forks"] == 0 and m["braid_divergences"] == 0


def test_shallow_churn_recovers_via_nack():
    """A shallow outage stays under the resync threshold and recovers by
    per-lane NACK — still no re-key, still converges."""
    m = run_lane_trial(n=15, duration=300, seed=1, rate=0.2,
                       offline_windows=_wave(15, 0.4, 100.0, 40.0))
    assert m["converged"] and m["rekeys"] == 0
    assert m["lane_forks"] == 0 and m["braid_divergences"] == 0


def test_seed_determinism():
    a = run_lane_trial(n=5, duration=200, seed=42, rate=0.3, loss=0.05)
    b = run_lane_trial(n=5, duration=200, seed=42, rate=0.3, loss=0.05)
    assert a == b
