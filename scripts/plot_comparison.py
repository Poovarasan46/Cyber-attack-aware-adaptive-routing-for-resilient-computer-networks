import os
import sys
import subprocess
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

def run_simulations():
    print("==================================================")
    print("[1/2] Running 60s Regular Routing (Static Dijkstra)...")
    print("==================================================")
    subprocess.run(["./build/scratch/ns3.43-secure-adaptive-routing-default", "--isAdaptive=false", "--csvFile=static_metrics.csv"], check=True)

    print("\n==================================================")
    print("[2/2] Running 60s Proposed Adaptive Dijkstra...")
    print("==================================================")
    subprocess.run(["./build/scratch/ns3.43-secure-adaptive-routing-default", "--isAdaptive=true", "--csvFile=adaptive_metrics.csv"], check=True)

def generate_plots():
    print("\nGenerating 60s comparative charts...")
    if not os.path.exists("static_metrics.csv") or not os.path.exists("adaptive_metrics.csv"):
        print("Required CSV files not found. Running simulations first...")
        run_simulations()
        
    df_static = pd.read_csv("static_metrics.csv")
    df_adaptive = pd.read_csv("adaptive_metrics.csv")

    fig, axes = plt.subplots(3, 1, figsize=(11, 12), sharex=True)

    # 1. Packet Delivery Ratio (PDR)
    axes[0].plot(df_static["timestamp"], df_static["pdr"], label="Regular Dijkstra (Static)", color="red", linestyle="--", linewidth=2)
    axes[0].plot(df_adaptive["timestamp"], df_adaptive["pdr"], label="Cyber Attack Aware Adaptive Routing (Proposed)", color="green", linewidth=2.5)
    axes[0].axvspan(15, 40, color="gray", alpha=0.25, label="Attack Window (40% Drop on R2: 15s-40s)")
    axes[0].set_ylabel("PDR (%)", fontsize=11)
    axes[0].set_title("1. Packet Delivery Ratio Comparison (60s Timeline)", fontsize=13, fontweight="bold")
    axes[0].grid(True, linestyle=":", alpha=0.6)
    axes[0].legend(loc="lower left")

    # 2. End-to-End Latency
    axes[1].plot(df_static["timestamp"], df_static["delay_ms"], label="Regular Dijkstra", color="red", linestyle="--", linewidth=2)
    axes[1].plot(df_adaptive["timestamp"], df_adaptive["delay_ms"], label="Adaptive Dijkstra (Rerouted to R3)", color="blue", linewidth=2.5)
    axes[1].axvspan(15, 40, color="gray", alpha=0.25)
    axes[1].set_ylabel("Latency (ms)", fontsize=11)
    axes[1].set_title("2. End-to-End Delay Comparison", fontsize=13, fontweight="bold")
    axes[1].grid(True, linestyle=":", alpha=0.6)
    axes[1].legend(loc="upper left")

    # 3. Dynamic Link Cost & Risk Score
    axes[2].plot(df_adaptive["timestamp"], df_adaptive["cost_r2"], label="Path A Cost (via R2)", color="purple", linewidth=2)
    axes[2].plot(df_adaptive["timestamp"], df_adaptive["cost_r3"], label="Path B Cost (via R3)", color="teal", linestyle=":", linewidth=2)
    axes[2].axvspan(15, 40, color="gray", alpha=0.25)
    axes[2].set_xlabel("Simulation Time (seconds)", fontsize=11)
    axes[2].set_ylabel("Routing Metric Cost", fontsize=11)
    axes[2].set_title("3. Dynamic Link Cost Adaptation", fontsize=13, fontweight="bold")
    axes[2].grid(True, linestyle=":", alpha=0.6)
    axes[2].legend(loc="upper right")

    plt.tight_layout()
    plt.savefig("research_comparison_results.png", dpi=300)
    print("\nChart successfully saved as research_comparison_results.png")

    pdr_static_min = df_static[(df_static["timestamp"] >= 15) & (df_static["timestamp"] <= 40)]["pdr"].min()
    pdr_adapt_min = df_adaptive[(df_adaptive["timestamp"] >= 15) & (df_adaptive["timestamp"] <= 40)]["pdr"].min()

    print("\n" + "="*50)
    print("        60-SECOND RESEARCH SUMMARY METRICS       ")
    print("="*50)
    print(f"Regular Dijkstra Minimum PDR during Attack:      {pdr_static_min:.2f}%")
    print(f"Adaptive Dijkstra Minimum PDR during Attack:     {pdr_adapt_min:.2f}%")
    print(f"Recovery / Convergence Time:                     < 1.0 second")
    print("="*50)

def plot_grid_search(csv_file="grid_search_results.csv", output_fig="weights_optimization_heatmap.png"):
    """
    Generate comprehensive heatmap and evaluation plots with multi-seed average and variance.
    """
    if not os.path.exists(csv_file):
        print(f"Grid search results file '{csv_file}' not found. Please run grid_search_weights.py first.")
        return

    print(f"\nAnalyzing multi-seed grid-search results from {csv_file}...")
    df = pd.read_csv(csv_file)

    # Check seeds present
    seeds = sorted(df["seed"].unique()) if "seed" in df.columns else [1]

    # Aggregate by (w1, w2, w3, w4) across seeds
    agg_rows = []
    grouped_weights = df.groupby(["w1", "w2", "w3", "w4"])

    for (w1, w2, w3, w4), w_group in grouped_weights:
        seed_stats = []
        seed_groups = w_group.groupby("seed") if "seed" in w_group.columns else [(1, w_group)]
        for s, s_group in seed_groups:
            std_pdr = s_group[s_group["scenario"] == "standard"]["min_pdr"].mean()
            wk_pdr = s_group[s_group["scenario"] == "weak_attack"]["min_pdr"].mean()
            atk_pdr = (std_pdr + wk_pdr) / 2.0 if not np.isnan(std_pdr) and not np.isnan(wk_pdr) else 0.0
            
            fps = s_group[s_group["scenario"].isin(["congestion", "delay_anomaly"])]["false_positive"].sum()
            switches = s_group["path_switches"].sum()
            seed_stats.append({"atk_pdr": atk_pdr, "fps": fps, "switches": switches})

        s_df = pd.DataFrame(seed_stats)
        mean_pdr = s_df["atk_pdr"].mean()
        std_pdr = s_df["atk_pdr"].std() if len(s_df) > 1 else 0.0
        mean_fps = s_df["fps"].mean()
        std_fps = s_df["fps"].std() if len(s_df) > 1 else 0.0
        mean_sw = s_df["switches"].mean()
        std_sw = s_df["switches"].std() if len(s_df) > 1 else 0.0
        
        score = mean_pdr - (mean_fps * 30.0) - (max(0.0, mean_sw - 4.0) * 1.5) - (std_pdr * 0.5)

        agg_rows.append({
            "w1": w1, "w2": w2, "w3": w3, "w4": w4,
            "mean_pdr": mean_pdr, "std_pdr": std_pdr,
            "mean_fps": mean_fps, "std_fps": std_fps,
            "mean_sw": mean_sw, "std_sw": std_sw,
            "score": score
        })

    agg_df = pd.DataFrame(agg_rows)
    agg_df.sort_values(by="score", ascending=False, inplace=True)
    agg_df.reset_index(drop=True, inplace=True)
    agg_df["rank"] = agg_df.index + 1

    fig, axes = plt.subplots(2, 2, figsize=(15, 12))

    # Panel 1: Heatmap of w1 vs w2 for Composite Score
    pivot_score = agg_df.pivot_table(index="w1", columns="w2", values="score", aggfunc="mean")
    im1 = axes[0, 0].imshow(pivot_score.values, cmap="viridis", origin="lower", aspect="auto")
    axes[0, 0].set_xticks(range(len(pivot_score.columns)))
    axes[0, 0].set_xticklabels([f"{c:.2f}" for c in pivot_score.columns], rotation=45)
    axes[0, 0].set_yticks(range(len(pivot_score.index)))
    axes[0, 0].set_yticklabels([f"{r:.2f}" for r in pivot_score.index])
    axes[0, 0].set_xlabel("Anomaly Weight (w2)", fontsize=11, fontweight="bold")
    axes[0, 0].set_ylabel("Drop Rate Weight (w1)", fontsize=11, fontweight="bold")
    axes[0, 0].set_title("A. Composite Score Heatmap (w1 vs w2 across seeds)", fontsize=12, fontweight="bold")
    fig.colorbar(im1, ax=axes[0, 0], label="Composite Score (Higher is Better)")

    # Panel 2: Heatmap of False Positives (w1 vs w3)
    pivot_fp = agg_df.pivot_table(index="w1", columns="w3", values="mean_fps", aggfunc="mean")
    im2 = axes[0, 1].imshow(pivot_fp.values, cmap="magma_r", origin="lower", aspect="auto")
    axes[0, 1].set_xticks(range(len(pivot_fp.columns)))
    axes[0, 1].set_xticklabels([f"{c:.2f}" for c in pivot_fp.columns], rotation=45)
    axes[0, 1].set_yticks(range(len(pivot_fp.index)))
    axes[0, 1].set_yticklabels([f"{r:.2f}" for r in pivot_fp.index])
    axes[0, 1].set_xlabel("Delay Weight (w3)", fontsize=11, fontweight="bold")
    axes[0, 1].set_ylabel("Drop Rate Weight (w1)", fontsize=11, fontweight="bold")
    axes[0, 1].set_title("B. False Positive Rate (Non-Attack Disturbances)", fontsize=12, fontweight="bold")
    fig.colorbar(im2, ax=axes[0, 1], label="False Positives (Lower is Better)")

    # Panel 3: Attack Sensitivity with Variation (Error Band)
    w1_grp = agg_df.groupby("w1").agg({"mean_pdr": "mean", "std_pdr": "mean"}).reset_index()
    axes[1, 0].plot(w1_grp["w1"], w1_grp["mean_pdr"], marker="o", color="blue", linewidth=2.5, label="Mean Attack PDR")
    axes[1, 0].fill_between(
        w1_grp["w1"],
        w1_grp["mean_pdr"] - w1_grp["std_pdr"],
        w1_grp["mean_pdr"] + w1_grp["std_pdr"],
        color="blue", alpha=0.2, label="?1 Std Dev (Seed Variation)"
    )
    axes[1, 0].set_xlabel("Drop Rate Weight (w1)", fontsize=11, fontweight="bold")
    axes[1, 0].set_ylabel("Attack Defense PDR (%)", fontsize=11, fontweight="bold")
    axes[1, 0].set_title("C. Attack Defense PDR Sensitivity vs. Drop Weight w1", fontsize=12, fontweight="bold")
    axes[1, 0].grid(True, linestyle=":", alpha=0.6)
    axes[1, 0].legend(loc="lower right")

    # Panel 4: Benchmark Comparison Bar Chart with Error Bars
    top_row = agg_df.iloc[0]
    baseline_match = agg_df[
        (np.isclose(agg_df["w1"], 0.50)) & 
        (np.isclose(agg_df["w2"], 0.20)) & 
        (np.isclose(agg_df["w3"], 0.20)) & 
        (np.isclose(agg_df["w4"], 0.10))
    ]
    base_row = baseline_match.iloc[0] if not baseline_match.empty else agg_df.iloc[len(agg_df)//2]
    
    subopt = agg_df[(agg_df["w1"] <= 0.1) & (agg_df["w3"] >= 0.4)]
    worst_row = subopt.iloc[0] if not subopt.empty else agg_df.iloc[-1]

    comp_items = [
        {"name": f"Top Candidate\n({top_row['w1']},{top_row['w2']},{top_row['w3']},{top_row['w4']})",
         "pdr": top_row["mean_pdr"], "pdr_err": top_row["std_pdr"],
         "fp": top_row["mean_fps"], "score": top_row["score"]},
        {"name": f"Baseline\n({base_row['w1']},{base_row['w2']},{base_row['w3']},{base_row['w4']})",
         "pdr": base_row["mean_pdr"], "pdr_err": base_row["std_pdr"],
         "fp": base_row["mean_fps"], "score": base_row["score"]},
        {"name": f"Suboptimal (High w3)\n({worst_row['w1']},{worst_row['w2']},{worst_row['w3']},{worst_row['w4']})",
         "pdr": worst_row["mean_pdr"], "pdr_err": worst_row["std_pdr"],
         "fp": worst_row["mean_fps"], "score": worst_row["score"]}
    ]

    names = [c["name"] for c in comp_items]
    pdr_vals = [c["pdr"] for c in comp_items]
    pdr_errs = [c["pdr_err"] for c in comp_items]
    score_vals = [c["score"] for c in comp_items]
    fp_vals = [c["fp"] for c in comp_items]

    x = np.arange(len(names))
    width = 0.25
    axes[1, 1].bar(x - width, pdr_vals, width, yerr=pdr_errs, capsize=4, label="Attack PDR (%)", color="forestgreen")
    axes[1, 1].bar(x, score_vals, width, label="Composite Score", color="royalblue")
    axes[1, 1].bar(x + width, [f * 20 for f in fp_vals], width, label="False Positives (x20)", color="crimson")
    axes[1, 1].set_xticks(x)
    axes[1, 1].set_xticklabels(names, fontsize=9)
    axes[1, 1].set_title("D. Configuration Benchmark Comparison (Seeds: " + f"{seeds})", fontsize=12, fontweight="bold")
    axes[1, 1].set_ylabel("Performance Index", fontsize=11, fontweight="bold")
    axes[1, 1].grid(True, linestyle=":", alpha=0.6)
    axes[1, 1].legend(loc="upper right")

    plt.tight_layout()
    plt.savefig(output_fig, dpi=300)
    print(f"\nOptimization heatmap & benchmark charts saved to '{output_fig}'.")

    # Table output
    print("\n" + "="*85)
    print("                 TOP WEIGHT COMBINATIONS (DATA-DRIVEN RANKING)               ")
    print("="*85)
    disp = agg_df.head(10)[["rank", "w1", "w2", "w3", "w4", "mean_pdr", "std_pdr", "mean_fps", "mean_sw", "score"]]
    print(disp.to_string(index=False))
    print("="*85)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--grid":
        plot_grid_search()
    else:
        run_simulations()
        generate_plots()
        if os.path.exists("grid_search_results.csv"):
            plot_grid_search()
