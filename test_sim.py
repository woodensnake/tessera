"""Simulator smoke tests: each checks one property the M3 runs will rely on."""

from sim import Partition, run_trial


def test_lossless_swarm_stays_in_lockstep():
    m = run_trial(n=5, duration=300, seed=1, rate=0.2, loss=0.0)
    assert m["sent"] > 0
    assert m["delivered"] == m["sent"] * 5  # every member sees every message
    assert m["gaps"] == 0 and m["nacks"] == 0 and m["rejoins"] == 0
    assert m["forks"] == 0 and m["continuity_breaks"] == 0
    assert m["behind_at_end"] == 0 and not m["swarm_dead"]


def test_iid_loss_resolves_at_rung1():
    m = run_trial(n=5, duration=600, seed=2, rate=0.2, loss=0.02)
    assert m["gaps"] > 0                    # loss actually occurred
    assert m["rung1_recoveries"] > 0        # and the ladder's first rung worked
    assert m["rejoins"] == 0                # 2% iid never needed Rung 2
    assert m["forks"] == 0 and m["continuity_breaks"] == 0
    assert m["behind_at_end"] == 0 and not m["swarm_dead"]


def test_burst_loss_still_recovers():
    m = run_trial(n=5, duration=600, seed=3, rate=0.2, loss=0.05, burst_len=10)
    assert m["gaps"] > 0
    assert m["forks"] == 0 and m["continuity_breaks"] == 0
    assert not m["swarm_dead"]
    # burst loss may or may not force a rejoin at these settings; what
    # matters is the swarm ends whole either way
    assert m["behind_at_end"] == 0


def test_long_offline_agent_recovers_via_resync():
    # agent offline long enough that the missed range ages out of every
    # peer's 64-message window at 5 agents x 0.5 msg/s. The default Rung-1.5
    # resync brings it back with NO epoch change (the storm-safe path).
    m = run_trial(n=5, duration=400, seed=4, rate=0.5,
                  offline_windows={b"agent-002": (60.0, 180.0)})
    assert m["resyncs"] >= 1
    assert m["epoch_changes"] == 0            # resync mints no epoch
    assert m["rejoins"] == 0
    assert m["messages_lost_to_laggards"] > 0  # missed history is still gone
    assert m["forks"] == 0 and m["continuity_breaks"] == 0
    assert m["behind_at_end"] == 0 and not m["swarm_dead"]


def test_legacy_rejoin_path_still_works():
    # with resync disabled, the same outage recovers via the JOIN epoch change
    m = run_trial(n=5, duration=400, seed=4, rate=0.5, use_resync=False,
                  offline_windows={b"agent-002": (60.0, 180.0)})
    assert m["rejoins"] >= 1 and m["epoch_changes"] >= 1
    assert m["resyncs"] == 0
    assert m["behind_at_end"] == 0 and not m["swarm_dead"]


def test_partition_heals():
    part = Partition(start=100.0, end=160.0,
                     group_a=frozenset({b"agent-000", b"agent-001"}))
    m = run_trial(n=5, duration=500, seed=5, rate=0.3, partitions=[part])
    assert m["gaps"] > 0                    # the minority side missed traffic
    assert m["forks"] == 0                  # perfect sequencer: no split-brain
    assert m["behind_at_end"] == 0 and not m["swarm_dead"]


def test_same_seed_same_result():
    a = run_trial(n=5, duration=200, seed=42, rate=0.2, loss=0.05)
    b = run_trial(n=5, duration=200, seed=42, rate=0.2, loss=0.05)
    assert a == b
