#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed

BINARY_PATH = "./build/scratch/ns3.43-secure-adaptive-routing-default"

DEFAULT_SCENARIOS = [
    "pulsing_grayhole",
    "ldos_bufferbloat",
    "metric_poisoning",
    "selective_drop",
    "latency_jitter"
]

def generate_weight_combinations(step=0.1):
    """
    Generate all (w1, w2, w3, w4) tuples such that w1 + w2 + w3 + w4 == 1.0,
    with step size 'step'.
    """
    n_steps = int(round(1.0 / step))
    combinations = []
    for i1 in range(n_steps + 1):
        for i2 in range(n_steps + 1 - i1):
            for i3 in range(n_steps + 1 - i1 - i2):
                i4 = n_steps - i1 - i2 - i3
                w1 = round(i1 * step, 2)
                w2 = round(i2 * step, 2)
                w3 = round(i3 * step, 2)
                w4 = round(i4 * step, 2)
                combinations.append((w1, w2, w3, w4))
    return combinations

def run_single_simulation(w1, w2, w3, w4, scenario, seed, topology="nsfnet"):
    """
    Execute a single ns-3 run and extract summary metrics.
    """
    cmd = [
        BINARY_PATH,
        f"--topology={topology}",
        f"--w1={w1}",
        f"--w2={w2}",
        f"--w3={w3}",
        f"--w4={w4}",
        f"--scenario={scenario}",
        f"--seed={seed}",
        "--csvFile=none"
    ]
    
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        min_pdr = 100.0
        conv_time = 0.0
        switches = 0
        false_pos = 0
        
        output_text = res.stdout + "\n" + res.stderr
        for line in output_text.splitlines():
            if "[RUN COMPLETE]" in line:
                parts = line.split()
                for p in parts:
                    if p.startswith("minPdr="):
                        min_pdr = float(p.split("=")[1])
                    elif p.startswith("convTime="):
                        conv_time = float(p.split("=")[1])
                    elif p.startswith("switches="):
                        switches = int(p.split("=")[1])
                    elif p.startswith("falsePos="):
                        false_pos = int(p.split("=")[1])
                        
        return {
            "topology": topology,
            "w1": w1,
            "w2": w2,
            "w3": w3,
            "w4": w4,
            "scenario": scenario,
            "seed": seed,
            "min_pdr": min_pdr,
            "convergence_time": conv_time,
            "path_switches": switches,
            "false_positive": false_pos
        }
    except Exception as e:
        print(f"Error executing simulation for topology={topology}, w=({w1},{w2},{w3},{w4}), scenario={scenario}, seed={seed}: {e}", file=sys.stderr)
        return None

def run_grid_search(step=0.1, topology="nsfnet", scenarios=None, seeds=None, output_csv="grid_search_results.csv", max_workers=16):
    if scenarios is None:
        scenarios = DEFAULT_SCENARIOS
    if seeds is None:
        seeds = [1, 2, 3]
        
    weights_list = generate_weight_combinations(step)
    total_runs = len(weights_list) * len(scenarios) * len(seeds)
    print("=" * 70)
    print(f"Grid Search: Topology={topology.upper()} | {len(weights_list)} weight vectors x {len(scenarios)} scenarios x {len(seeds)} seeds = {total_runs} runs")
    print(f"Scenarios: {scenarios}")
    print(f"Step: {step} | Seeds: {seeds} | Workers: {max_workers} | Output: {output_csv}")
    print("=" * 70)
    
    tasks = []
    for w in weights_list:
        for s in scenarios:
            for sd in seeds:
                tasks.append((w[0], w[1], w[2], w[3], s, sd, topology))
            
    results = []
    completed = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {
            executor.submit(run_single_simulation, *task): task for task in tasks
        }
        
        for future in as_completed(future_to_task):
            res = future.result()
            completed += 1
            if res is not None:
                results.append(res)
            if completed % 200 == 0 or completed == total_runs:
                print(f"Progress: [{completed}/{total_runs}] runs finished ({completed/total_runs*100:.1f}%)")
                
    df = pd.DataFrame(results)
    df.to_csv(output_csv, index=False)
    print(f"\nAll {completed} simulation runs completed. Raw data saved to {output_csv}")
    return df

def analyze_and_rank_weights(df, output_ranked_csv="weight_candidates_ranked.csv"):
    """
    Score and rank weight combinations based on performance across:
    - Pulsing Grayhole, LDoS Bufferbloat, Metric Poisoning, Selective Drop, Latency Jitter
    - Fast convergence and minimal path flapping
    """
    seeds = sorted(df["seed"].unique())
    num_seeds = len(seeds)
    print(f"\nAnalyzing data aggregated across {num_seeds} random seed(s): {seeds}")

    records = []
    grouped_weights = df.groupby(["w1", "w2", "w3", "w4"])
    
    for (w1, w2, w3, w4), w_group in grouped_weights:
        seed_stats = []
        for s, s_group in w_group.groupby("seed"):
            # Compute attack delivery performance
            atk_pdr = s_group["min_pdr"].mean()
            switches = s_group["path_switches"].sum()
            fps = s_group["false_positive"].sum()
            
            seed_stats.append({
                "seed": s,
                "atk_pdr": atk_pdr,
                "fps": fps,
                "switches": switches
            })
            
        seed_df = pd.DataFrame(seed_stats)
        mean_atk_pdr = seed_df["atk_pdr"].mean()
        std_atk_pdr = seed_df["atk_pdr"].std() if len(seed_df) > 1 else 0.0
        mean_fps = seed_df["fps"].mean()
        mean_switches = seed_df["switches"].mean()
        std_switches = seed_df["switches"].std() if len(seed_df) > 1 else 0.0
        
        # Penalties: False positive penalty + Flapping penalty + Variance penalty
        fp_penalty = mean_fps * 30.0
        flapping_penalty = max(0.0, mean_switches - 4.0) * 1.5
        variance_penalty = std_atk_pdr * 0.5
        
        score = mean_atk_pdr - fp_penalty - flapping_penalty - variance_penalty
        
        # Overall Detection & Adaptive Routing Accuracy (%)
        # Combines Attack Mitigation Delivery (50%), Non-Attack Specificity (50%),
        # minus multi-seed variance and excess route flapping penalties.
        specificity = max(0.0, 100.0 - mean_fps * 50.0)
        accuracy = max(
            0.0,
            min(
                100.0,
                (0.50 * mean_atk_pdr)
                + (0.50 * specificity)
                - (std_atk_pdr * 0.5)
                - (max(0.0, mean_switches - 3.0) * 0.25),
            ),
        )
        
        records.append({
            "w1": w1,
            "w2": w2,
            "w3": w3,
            "w4": w4,
            "mean_attack_pdr": round(mean_atk_pdr, 2),
            "std_attack_pdr": round(std_atk_pdr, 2),
            "mean_fps": round(mean_fps, 2),
            "mean_switches": round(mean_switches, 2),
            "std_switches": round(std_switches, 2),
            "composite_score": round(score, 2),
            "accuracy": round(accuracy, 2)
        })
        
    rank_df = pd.DataFrame(records)
    rank_df.sort_values(by=["accuracy", "composite_score"], ascending=[False, False], inplace=True)
    rank_df.reset_index(drop=True, inplace=True)
    rank_df["rank"] = rank_df.index + 1
    rank_df.to_csv(output_ranked_csv, index=False)
    
    print("\n" + "=" * 98)
    print("               TOP 10 WEIGHT COMBINATIONS (RANKED BY ACCURACY & STABILITY)              ")
    print("=" * 98)
    top10 = rank_df.head(10)
    display_cols = ["rank", "w1", "w2", "w3", "w4", "mean_attack_pdr", "std_attack_pdr", "mean_fps", "mean_switches", "composite_score", "accuracy"]
    print(top10[display_cols].to_string(index=False))
    
    # Evaluate Baseline (0.50, 0.20, 0.20, 0.10)
    baseline_match = rank_df[
        (np.isclose(rank_df["w1"], 0.50)) & 
        (np.isclose(rank_df["w2"], 0.20)) & 
        (np.isclose(rank_df["w3"], 0.20)) & 
        (np.isclose(rank_df["w4"], 0.10))
    ]
    
    print("\n" + "=" * 98)
    print("            DATA-DRIVEN EVALUATION OF BASELINE: (0.50, 0.20, 0.20, 0.10)            ")
    print("=" * 98)
    if not baseline_match.empty:
        base_row = baseline_match.iloc[0]
        rank_val = int(base_row['rank'])
        pdr_val = base_row['mean_attack_pdr']
        pdr_std = base_row['std_attack_pdr']
        fps_val = base_row['mean_fps']
        sw_val = base_row['mean_switches']
        score_val = base_row['composite_score']
        acc_val = base_row['accuracy']
        
        print(f"Rank:                  #{rank_val} out of {len(rank_df)} evaluated combinations")
        print(f"Attack PDR:            {pdr_val:.2f}% +/- {pdr_std:.2f}%")
        print(f"False Positives:       {fps_val:.2f} across disturbance scenarios")
        print(f"Path Switches:         {sw_val:.2f} +/- {base_row['std_switches']:.2f} total across scenarios")
        print(f"Composite Score:       {score_val:.2f} / 100")
        print(f"Routing Accuracy:      {acc_val:.2f}%")
    print("=" * 98)
    
    return rank_df

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Seed Grid Search for Adaptive Routing Weights")
    parser.add_argument("--topology", type=str, default="nsfnet", help="Topology: nsfnet or geant (default: nsfnet)")
    parser.add_argument("--step", type=float, default=0.1, help="Weight increment step (default: 0.1)")
    parser.add_argument("--seeds", type=str, default="1,2,3", help="Comma-separated random seeds (default: 1,2,3)")
    parser.add_argument("--output", type=str, default="grid_search_results.csv", help="Output CSV path")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 16, help="Parallel worker threads")
    parser.add_argument("--skip-run", action="store_true", help="Skip running and analyze existing CSV")
    args = parser.parse_args()
    
    seeds = [int(s.strip()) for s in args.seeds.split(",")]
    
    if args.skip_run and os.path.exists(args.output):
        df = pd.read_csv(args.output)
    else:
        df = run_grid_search(step=args.step, topology=args.topology, seeds=seeds, output_csv=args.output, max_workers=args.workers)
        
    analyze_and_rank_weights(df)
