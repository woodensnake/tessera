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


def test_seed_determinism():
    a = run_lane_trial(n=5, duration=200, seed=42, rate=0.3, loss=0.05)
    b = run_lane_trial(n=5, duration=200, seed=42, rate=0.3, loss=0.05)
    assert a == b
