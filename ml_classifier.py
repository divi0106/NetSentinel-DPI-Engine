import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

print("╔══════════════════════════════════════════════╗")
print("║      DPI ML TRAFFIC CLASSIFIER               ║")
print("╚══════════════════════════════════════════════╝")

# ── Step 1: Generate training data ───────────────────────────
# First run engine on test pcap to get flows.csv
print("\n[Step 1] Generating training data...")
os.system("./dpi_engine test_dpi.pcap /dev/null --lbs 2 --fps 2")

# ── Step 2: Load flow features ────────────────────────────────
print("\n[Step 2] Loading flow features from flows.csv...")
df = pd.read_csv("flows.csv")
print(f"  Loaded {len(df)} flows")
print(f"  Columns: {list(df.columns)}")
print(f"\n  App distribution:")
print(df["app_type"].value_counts().to_string())

# Remove unknowns
df = df[df["app_type"] != "Unknown"]
df = df[df["app_type"] != "HTTPS"]  # too generic
print(f"\n  After filtering: {len(df)} flows")

if len(df) < 5:
    print("\n[!] Not enough data to train!")
    print("    Run engine on more PCAP files first.")
    print("    Try: ./dpi_engine capture.pcap /dev/null")
    exit(1)

# ── Step 3: Prepare features ──────────────────────────────────
print("\n[Step 3] Preparing features...")
X = df[["dst_port", "protocol",
        "packet_count", "byte_count", "avg_pkt_size"]]
y = df["app_type"]

print(f"  Features: {list(X.columns)}")
print(f"  Classes:  {list(y.unique())}")

# ── Step 4: Train model ───────────────────────────────────────
print("\n[Step 4] Training Random Forest...")

if len(df) >= 10:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)
    has_test = True
else:
    X_train, y_train = X, y
    has_test = False
    print("  (Small dataset — using all data for training)")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)
model.fit(X_train, y_train)
print("  Training complete!")

# ── Step 5: Evaluate ──────────────────────────────────────────
if has_test:
    print("\n[Step 5] Evaluating model...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n  Accuracy: {acc*100:.1f}%")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred))

# ── Step 6: Feature importance ────────────────────────────────
print("\n[Step 6] Feature Importance:")
features = ["dst_port", "protocol",
            "packet_count", "byte_count", "avg_pkt_size"]
importances = model.feature_importances_
for feat, imp in sorted(zip(features, importances),
                        key=lambda x: -x[1]):
    bar = "#" * int(imp * 50)
    print(f"  {feat:<15} {imp:.3f}  {bar}")

# ── Step 7: Save model ────────────────────────────────────────
print("\n[Step 7] Saving model...")
pickle.dump(model, open("dpi_model.pkl", "wb"))
print("  Model saved → dpi_model.pkl")

# ── Step 8: Predict on new flows ──────────────────────────────
print("\n[Step 8] Predicting on all flows...")
df_all = pd.read_csv("flows.csv")
X_all  = df_all[["dst_port", "protocol",
                  "packet_count", "byte_count",
                  "avg_pkt_size"]]

df_all["predicted_app"] = model.predict(X_all)

print("\n  Sample predictions:")
print("  {:<15} {:<15} {:<15}".format(
    "dst_port", "actual", "predicted"))
print("  " + "-"*45)
for _, row in df_all.head(15).iterrows():
    match = "✓" if row["app_type"] == row["predicted_app"] \
            else "✗"
    print("  {:<15} {:<15} {:<15} {}".format(
        str(int(row["dst_port"])),
        row["app_type"],
        row["predicted_app"],
        match))

df_all.to_csv("flows_predicted.csv", index=False)
print("\n  Full predictions saved → flows_predicted.csv")

print("\n╔══════════════════════════════════════════════╗")
print("║  ML CLASSIFIER COMPLETE                      ║")
print("║  Model: Random Forest (100 trees)            ║")
print("║  Input: 5 network behavioral features        ║")
print("║  No SNI or domain names used!                ║")
print("╚══════════════════════════════════════════════╝")
print()
print("Resume line:")
print("'Trained Random Forest classifier on network")
print(" flow features — identifies apps without SNI'")