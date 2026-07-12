"""Parameter sweeps (EXPERIMENTS.md M3).

Turns the single-trial simulators into distributions: many seeded trials
per config, aggregated with medians and bootstrap CIs. RQ3 (the liveness
cliff) is the go/no-go gate and runs first.

Every result is a pure function of (config, seed), so trials parallelize
across cores with no shared state and the output is independent of
scheduling. Results are written to results/*.json (config-as-data,
regenerable) and summarized as markdown.

    python sweep.py rq3     # liveness cliff (the gate)
    python sweep.py rq1     # detection latency distributions
    python sweep.py all
"""

from __future__ import annotations

import json
import os
import statistics
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass

from sim import run_trial
from adversaries import run_adversary_trial
from lane_sim import run_lane_trial

RESULTS = os.path.join(os.path.dirname(__file__), "results")
SEEDS = int(os.environ.get("TESSERA_SEEDS", "200"))


# ---------------------------------------------------------------- stats

def bootstrap_ci(xs, stat=statistics.mean, n=2000, alpha=0.05, seed=0):
    """Percentile bootstrap CI. Deterministic given seed."""
    import random
    if not xs:
        return (None, None)
    rng = random.Random(seed)
    k = len(xs)
    reps = sorted(stat([xs[rng.randrange(k)] for _ in range(k)])
                  for _ in range(n))
    lo = reps[int(alpha / 2 * n)]
    hi = reps[int((1 - alpha / 2) * n)]
    return (lo, hi)


def rate_ci(flags, seed=0):
    """Fraction True, with bootstrap CI."""
    xs = [1.0 if f else 0.0 for f in flags]
    m = statistics.mean(xs) if xs else 0.0
    return m, bootstrap_ci(xs, seed=seed)


# ---------------------------------------------------------------- parallel

@dataclass(frozen=True)
class Cell:
    """One point in a sweep grid: a label, the trial fn name, and kwargs.
    Seeds are added per trial."""
    label: str
    kind: str            # "honest" | "adversary"
    kwargs: tuple        # tuple of (key, value) pairs, hashable for caching


def _one(args):
    kind, kwargs, seed = args
    kw = dict(kwargs)
    kw["seed"] = seed
    if kind == "honest":
        return run_trial(**kw)
    if kind == "lane":
        return run_lane_trial(**kw)
    return run_adversary_trial(**kw)


def run_cells(cells, seeds=SEEDS):
    """Run every (cell, seed) across the process pool. Returns
    {label: [trial_dict, ...]}."""
    jobs, index = [], []
    for c in cells:
        for s in range(seeds):
            jobs.append((c.kind, c.kwargs, s))
            index.append(c.label)
    out = {c.label: [] for c in cells}
    with ProcessPoolExecutor() as ex:
        for label, result in zip(index, ex.map(_one, jobs, chunksize=4)):
            out[label].append(result)
    return out


# ---------------------------------------------------------------- RQ3

def rq3(seeds=SEEDS):
    """Liveness cliff. For each loss level (i.i.d. and burst), what fraction
    of trials are absorbed entirely by Rung 1 (no rejoin), how many rejoins
    occur, and does the swarm ever die or end desynchronized? The cliff p* is
    where Rung-1-only resolution collapses and rejoins/death climb."""
    loss_levels = [0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.15, 0.20]
    base = dict(n=10, duration=300, rate=0.2)
    cells = []
    for p in loss_levels:
        cells.append(Cell(f"iid/{p}", "honest",
                          tuple({**base, "loss": p}.items())))
        cells.append(Cell(f"burst/{p}", "honest",
                          tuple({**base, "loss": p, "burst_len": 10}.items())))
    raw = run_cells(cells, seeds)

    rows = []
    for model in ("iid", "burst"):
        for p in loss_levels:
            trials = raw[f"{model}/{p}"]
            rung1_only, ci_r1 = rate_ci([t["rejoins"] == 0 for t in trials])
            dead, _ = rate_ci([t["swarm_dead"] for t in trials])
            behind, _ = rate_ci([t["behind_at_end"] > 0 for t in trials])
            rejoins = [t["rejoins"] for t in trials]
            forks = sum(t["forks"] for t in trials)
            cbreaks = sum(t["continuity_breaks"] for t in trials)
            rows.append(dict(
                model=model, loss=p,
                rung1_only=rung1_only, rung1_only_ci=ci_r1,
                mean_rejoins=statistics.mean(rejoins),
                max_rejoins=max(rejoins),
                mean_epoch_changes=statistics.mean(t["epoch_changes"]
                                                   for t in trials),
                swarm_dead_rate=dead, ended_behind_rate=behind,
                total_forks=forks, total_continuity_breaks=cbreaks))
    return rows


def rq3_churn(seeds=SEEDS, n=15, dur=400):
    """The cliff RQ3-loss did NOT find: it is driven by outage-vs-window, not
    packet loss. A wave of agents goes offline simultaneously for duration D;
    if D exceeds the window's time span they cannot Rung-1 recover and must
    rejoin — and if the wave is large, one rejoin's epoch change can strand
    the others mid-recovery, cascading into a rejoin storm. We sweep D against
    window W to locate that edge."""
    rate = 0.2
    wave_frac = 0.4
    win_secs = {32: 32 / (n * rate), 64: 64 / (n * rate), 128: 128 / (n * rate)}
    Ds = [5, 15, 25, 40, 60, 100]
    cells = []
    for W in (32, 64, 128):
        for D in Ds:
            offline = _wave(n, wave_frac, start=100.0, duration=float(D))
            # use_resync=False: this sweep characterizes the *legacy* rejoin
            # storm (the problem). RQ3c (rq3_fix) shows resync curing it.
            cells.append(Cell(
                f"W{W}/D{D}", "honest",
                tuple({"n": n, "duration": dur, "rate": rate, "window": W,
                       "offline_windows": offline, "use_resync": False}.items())))
    raw = run_cells(cells, seeds)

    rows = []
    for W in (32, 64, 128):
        for D in Ds:
            trials = raw[f"W{W}/D{D}"]
            rejoins = [t["rejoins"] for t in trials]
            dead, _ = rate_ci([t["swarm_dead"] for t in trials])
            behind, _ = rate_ci([t["behind_at_end"] > 0 for t in trials])
            any_rejoin, _ = rate_ci([t["rejoins"] > 0 for t in trials])
            rows.append(dict(
                window=W, window_secs=round(win_secs[W], 1), offline_D=D,
                crosses_window=D > win_secs[W],
                any_rejoin_rate=any_rejoin,
                mean_rejoins=statistics.mean(rejoins), max_rejoins=max(rejoins),
                mean_epoch_changes=statistics.mean(t["epoch_changes"]
                                                   for t in trials),
                swarm_dead_rate=dead, ended_behind_rate=behind))
    return rows


def _wave(n, frac, start, duration):
    """Correlated outage: the first `frac` of members go offline together."""
    k = max(1, int(n * frac))
    return {f"agent-{i:03d}".encode(): (start, start + duration)
            for i in range(1, k + 1)}  # skip agent-000 (kept as a stable peer)


def rq3_window(seeds=40, n=100):
    """Window-in-time (§11.8a): does a fixed real-time retention floor move the
    cliff outward? At N=100 (20 msg/s), a 64-message window is only ~3 s of
    buffer, so a 25 s outage crosses it badly. A 30 s time-floor should hold
    regardless of N. Legacy rejoin (use_resync=False) so the cliff is visible
    as rejoins rather than being absorbed by resync."""
    dur = 250
    offline = _wave(n, 0.4, start=100.0, duration=25.0)
    base = {"n": n, "duration": dur, "rate": 0.2, "window": 64,
            "offline_windows": offline, "use_resync": False}
    cells = [
        Cell("count-only", "honest", tuple({**base}.items())),
        Cell("count+30s-floor", "honest",
             tuple({**base, "window_secs": 30.0}.items())),
    ]
    raw = run_cells(cells, seeds)
    rows = []
    for label in ("count-only", "count+30s-floor"):
        t = raw[label]
        rows.append(dict(
            variant=label,
            mean_rejoins=statistics.mean(x["rejoins"] for x in t),
            any_rejoin_rate=statistics.mean(1.0 if x["rejoins"] > 0 else 0.0
                                            for x in t),
            ended_behind_rate=statistics.mean(1.0 if x["behind_at_end"] > 0
                                              else 0.0 for x in t)))
    return rows


def report_rq3_window(rows):
    lines = ["## RQ3d — Window-in-time: does a real-time floor move the cliff?",
             "", "| variant | mean rejoins | any-rejoin | ended behind |",
             "|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['variant']} | {r['mean_rejoins']:.1f} | "
                     f"{r['any_rejoin_rate']:.2f} | {r['ended_behind_rate']:.2f} |")
    return "\n".join(lines)


def rq3_fix(seeds=40, n=100):
    """A/B the storm fix: at a cliff-crossing config (correlated outage well
    past the window), compare the legacy JOIN-based rejoin against Rung-1.5
    resync. The claim is that resync — which mints no epoch and re-keys no one
    — eliminates the swarm-wide rejoin cascade."""
    dur = 300
    offline = _wave(n, 0.4, start=100.0, duration=40.0)  # deep past the cliff
    base = {"n": n, "duration": dur, "rate": 0.2, "window": 64,
            "offline_windows": offline}
    cells = [
        Cell("legacy", "honest", tuple({**base, "use_resync": False}.items())),
        Cell("resync", "honest", tuple({**base, "use_resync": True}.items())),
    ]
    raw = run_cells(cells, seeds)
    rows = []
    for label in ("legacy", "resync"):
        t = raw[label]
        rows.append(dict(
            variant=label,
            mean_rejoins=statistics.mean(x["rejoins"] for x in t),
            mean_resyncs=statistics.mean(x["resyncs"] for x in t),
            mean_epoch_changes=statistics.mean(x["epoch_changes"] for x in t),
            ended_behind_rate=statistics.mean(1.0 if x["behind_at_end"] > 0
                                              else 0.0 for x in t),
            swarm_dead_rate=statistics.mean(1.0 if x["swarm_dead"] else 0.0
                                            for x in t),
            forks=sum(x["forks"] for x in t),
            continuity_breaks=sum(x["continuity_breaks"] for x in t)))
    return rows


def report_rq3_fix(rows):
    lines = ["## RQ3c — Storm fix: resync vs legacy rejoin (N=100, past cliff)", "",
             "| variant | mean rejoins | mean resyncs | epoch chg | "
             "ended behind | dead | forks | cbreaks |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r['variant']} | {r['mean_rejoins']:.1f} | "
            f"{r['mean_resyncs']:.1f} | {r['mean_epoch_changes']:.1f} | "
            f"{r['ended_behind_rate']:.2f} | {r['swarm_dead_rate']:.2f} | "
            f"{r['forks']} | {r['continuity_breaks']} |")
    return "\n".join(lines)


def rq5_lanes(seeds=SEEDS):
    """Sequencer-free liveness (§11.1). The single-chain RQ3a absorbed loss to
    20% — but only with a perfect sequencer, so its numbers are upper bounds.
    This sweeps the lane sim, which has NO sequencer, and asks: does the swarm
    still converge (all honest members reach one braid)? If it matches RQ3a,
    the sequencer idealization was not load-bearing for liveness."""
    losses = [0.0, 0.01, 0.02, 0.05, 0.10, 0.20]
    base = dict(n=8, duration=300, rate=0.2)
    cells = [Cell(f"iid/{p}", "lane", tuple({**base, "loss": p}.items()))
             for p in losses]
    cells += [Cell(f"burst/{p}", "lane",
                   tuple({**base, "loss": p, "burst_len": 10}.items()))
              for p in losses if p > 0]
    raw = run_cells(cells, seeds)
    rows = []
    for label, trials in raw.items():
        model, p = label.split("/")
        conv, _ = rate_ci([t["converged"] for t in trials])
        rows.append(dict(
            model=model, loss=float(p), converged_rate=conv,
            total_lane_forks=sum(t["lane_forks"] for t in trials),
            total_braid_divergences=sum(t["braid_divergences"] for t in trials),
            mean_nacks=statistics.mean(t["nacks"] for t in trials)))
    return sorted(rows, key=lambda r: (r["model"], r["loss"]))


def report_rq5(rows):
    lines = ["## RQ5 — Sequencer-free liveness (per-sender lanes)", "",
             "| model | loss | converged | lane forks | braid div | mean NACKs |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r['model']} | {r['loss']:.2f} | {r['converged_rate']:.3f} "
            f"| {r['total_lane_forks']} | {r['total_braid_divergences']} "
            f"| {r['mean_nacks']:.1f} |")
    return "\n".join(lines)


# ---------------------------------------------------------------- RQ1

def rq1(seeds=SEEDS, n=5):
    """Detection latency distributions per adversary. Confirms the positives
    (clone/equivocation caught fast, attributed) and the negatives (silent
    clone, eavesdropper) hold across seeds, not just one lucky trial."""
    base = dict(n=n, duration=300, rate=0.5)
    advs = ["A3", "A3-stale", "A3-silent", "A4", "A6", "A1"]
    cells = [Cell(a, "adversary", tuple({**base, "adversary": a}.items()))
             for a in advs]
    raw = run_cells(cells, seeds)

    rows = []
    for a in advs:
        trials = raw[a]
        det = [t for t in trials if t["detected"]]
        lat = [t["detection_latency"] for t in det]
        pos = [t["detection_positions"] for t in det]
        attr_ok = [t["attribution_correct"] for t in det
                   if t["attribution_correct"] is not None]
        rows.append(dict(
            adversary=a, n=len(trials),
            detection_rate=len(det) / len(trials),
            median_latency=statistics.median(lat) if lat else None,
            latency_ci=bootstrap_ci(lat, statistics.median) if lat else None,
            median_positions=statistics.median(pos) if pos else None,
            max_positions=max(pos) if pos else None,
            attribution_correct_rate=(statistics.mean(attr_ok)
                                      if attr_ok else None),
            false_positive_rate=statistics.mean(t["false_positive"]
                                                for t in trials),
            forged_accepted_total=sum(t["forged_accepted"] for t in trials)))
    return rows


# ---------------------------------------------------------------- report

def _fmt_ci(ci):
    if not ci or ci[0] is None:
        return "—"
    return f"[{ci[0]:.3f}, {ci[1]:.3f}]"


def report_rq3(rows):
    lines = ["## RQ3a — Liveness under steady loss (i.i.d. / burst)", "",
             "| model | loss | Rung-1-only | mean rejoins | epoch chg | "
             "dead | ended behind | forks | cbreaks |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r['model']} | {r['loss']:.3f} | {r['rung1_only']:.3f} "
            f"{_fmt_ci(r['rung1_only_ci'])} | {r['mean_rejoins']:.2f} "
            f"| {r['mean_epoch_changes']:.2f} | {r['swarm_dead_rate']:.3f} "
            f"| {r['ended_behind_rate']:.3f} | {r['total_forks']} "
            f"| {r['total_continuity_breaks']} |")
    return "\n".join(lines)


def report_rq3_churn(rows):
    lines = ["## RQ3b — Liveness under correlated churn (outage vs window)", "",
             "| W | W secs | outage D | crosses W? | any-rejoin | "
             "mean rejoins | max | epoch chg | dead | ended behind |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r['window']} | {r['window_secs']} | {r['offline_D']} "
            f"| {'yes' if r['crosses_window'] else 'no'} "
            f"| {r['any_rejoin_rate']:.3f} | {r['mean_rejoins']:.2f} "
            f"| {r['max_rejoins']} | {r['mean_epoch_changes']:.2f} "
            f"| {r['swarm_dead_rate']:.3f} | {r['ended_behind_rate']:.3f} |")
    return "\n".join(lines)


def report_rq1(rows):
    lines = ["## RQ1 — Detection", "",
             "| adversary | det. rate | median latency (s) | median pos | "
             "max pos | attrib ok | false pos | forged acc |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        ml = f"{r['median_latency']:.3f}" if r['median_latency'] is not None else "—"
        mp = r['median_positions'] if r['median_positions'] is not None else "—"
        xp = r['max_positions'] if r['max_positions'] is not None else "—"
        ar = (f"{r['attribution_correct_rate']:.2f}"
              if r['attribution_correct_rate'] is not None else "—")
        lines.append(
            f"| {r['adversary']} | {r['detection_rate']:.3f} | {ml} | {mp} "
            f"| {xp} | {ar} | {r['false_positive_rate']:.3f} "
            f"| {r['forged_accepted_total']} |")
    return "\n".join(lines)


def scaled():
    """Breadth: do the M3 findings hold as the swarm grows? Detection at
    N∈{25,100} and the churn cliff at N∈{25,100}. Fewer seeds at N=100 (each
    trial is ~O(N²) work); the question there is the cliff's *shape*, not a
    tight CI. Writes results/scaled_*.json."""
    plan = [
        ("rq1_n25",   lambda: rq1(seeds=100, n=25)),
        ("rq3_n25",   lambda: rq3_churn(seeds=100, n=25, dur=400)),
        ("rq3_n100",  lambda: rq3_churn(seeds=40, n=100, dur=300)),
    ]
    for name, fn in plan:
        rows = fn()
        json.dump(rows, open(os.path.join(RESULTS, f"scaled_{name}.json"), "w"),
                  indent=2)
        rep = report_rq1(rows) if name.startswith("rq1") else report_rq3_churn(rows)
        print(f"### scaled/{name}\n{rep}\n", flush=True)


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    os.makedirs(RESULTS, exist_ok=True)
    if which == "scaled":
        scaled()
        return
    if which in ("rq3", "all"):
        rows = rq3()
        json.dump(rows, open(os.path.join(RESULTS, "rq3.json"), "w"), indent=2)
        print(report_rq3(rows), "\n")
        churn = rq3_churn()
        json.dump(churn, open(os.path.join(RESULTS, "rq3_churn.json"), "w"),
                  indent=2)
        print(report_rq3_churn(churn), "\n")
        fix = rq3_fix()
        json.dump(fix, open(os.path.join(RESULTS, "rq3_fix.json"), "w"), indent=2)
        print(report_rq3_fix(fix), "\n")
        win = rq3_window()
        json.dump(win, open(os.path.join(RESULTS, "rq3_window.json"), "w"),
                  indent=2)
        print(report_rq3_window(win), "\n")
    if which in ("rq1", "all"):
        rows = rq1()
        json.dump(rows, open(os.path.join(RESULTS, "rq1.json"), "w"), indent=2)
        print(report_rq1(rows), "\n")
    if which in ("rq5", "lanes", "all"):
        rows = rq5_lanes()
        json.dump(rows, open(os.path.join(RESULTS, "rq5_lanes.json"), "w"),
                  indent=2)
        print(report_rq5(rows), "\n")


if __name__ == "__main__":
    main()
