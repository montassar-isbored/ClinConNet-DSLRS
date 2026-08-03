import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def analyze_and_plot(csv_file="dslrs_performance_benchmark.csv"):
    # 1. Load Data
    df = pd.read_csv(csv_file)

    # Order phases explicitly for logical lifecycle display
    phase_order = ["Publish", "Update", "Revoke", "Deanonymize"]
    df["Phase"] = pd.Categorical(df["Phase"], categories=phase_order, ordered=True)

    # 2. Compute Mean and Median
    stats = df.groupby(["Ring_Size", "Phase"], observed=False)[
        ["Client_Gen_Time_ms", "E2E_Consensus_Time_ms"]
    ].agg(["mean", "median"])

    print("=== PERFORMANCE SUMMARY STATISTICS ===")
    print(stats.round(2))

    # Export statistical summary to CSV
    stats.to_csv("dslrs_statistical_summary.csv")

    # 3. Plotting Configuration
    sns.set_theme(style="whitegrid")

    # Plot 1: Client Generation Time Box Plot
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.boxplot(
        data=df,
        x="Phase",
        y="Client_Gen_Time_ms",
        hue="Ring_Size",
        palette="Blues",
        ax=ax
    )
    ax.set_title("Client Generation Time Distribution by Phase and Ring Size", fontsize=14)
    ax.set_xlabel("Lifecycle Phase", fontsize=12)
    ax.set_ylabel("Time (ms)", fontsize=12)
    ax.legend(title="Ring Size (n)")
    plt.tight_layout()
    plt.savefig("client_generation_time_boxplot.png", dpi=300)
    plt.close()

    # Plot 2: E2E Consensus Time Box Plot
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.boxplot(
        data=df,
        x="Phase",
        y="E2E_Consensus_Time_ms",
        hue="Ring_Size",
        palette="Oranges",
        ax=ax
    )
    ax.set_title("End-to-End Consensus Time Distribution by Phase and Ring Size", fontsize=14)
    ax.set_xlabel("Lifecycle Phase", fontsize=12)
    ax.set_ylabel("Time (ms)", fontsize=12)
    ax.legend(title="Ring Size (n)")
    plt.tight_layout()
    plt.savefig("e2e_consensus_time_boxplot.png", dpi=300)
    plt.close()

    print("\n[INFO] Plots generated successfully:")
    print(" - client_generation_time_boxplot.png")
    print(" - e2e_consensus_time_boxplot.png")
    print(" - dslrs_statistical_summary.csv")

if __name__ == "__main__":
    analyze_and_plot()