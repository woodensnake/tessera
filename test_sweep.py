"""Fast smoke tests for the sweep harness — structure and determinism, not
the full 200-seed runs (those live in `python sweep.py`)."""

from sweep import rq1, rq3, rq3_churn, bootstrap_ci


def test_bootstrap_ci_is_deterministic_and_ordered():
    xs = [0.1, 0.2, 0.15, 0.3, 0.25, 0.05]
    a = bootstrap_ci(xs, seed=1)
    b = bootstrap_ci(xs, seed=1)
    assert a == b                    # same seed, same interval
    assert a[0] <= a[1]


def test_rq1_smoke_positives_and_negatives():
    rows = {r["adversary"]: r for r in rq1(seeds=6)}
    # positives fire, negatives stay silent, forgeries never accepted
    assert rows["A3"]["detection_rate"] > 0.5
    assert rows["A4"]["detection_rate"] == 1.0
    assert rows["A3-silent"]["detection_rate"] == 0.0
    assert rows["A6"]["detection_rate"] == 0.0
    for r in rows.values():
        assert r["forged_accepted_total"] == 0
        assert r["false_positive_rate"] == 0.0


def test_rq3_loss_is_absorbed_at_rung1():
    # the headline RQ3a finding, in miniature: loss alone -> no rejoins
    rows = rq3(seeds=6)
    for r in rows:
        assert r["mean_rejoins"] == 0.0
        assert r["swarm_dead_rate"] == 0.0
        assert r["total_forks"] == 0


def test_rq3_churn_cliff_has_the_right_shape():
    # below the window's time span: no rejoins; well above it: rejoins appear
    rows = {(r["window"], r["offline_D"]): r for r in rq3_churn(seeds=6)}
    assert rows[(128, 5)]["mean_rejoins"] == 0.0     # D << W-secs
    assert rows[(32, 100)]["mean_rejoins"] > 0.0     # D >> W-secs
    # and nobody dies on either side of the cliff
    assert all(r["swarm_dead_rate"] == 0.0 for r in rows.values())
