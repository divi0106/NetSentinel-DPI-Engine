import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import pickle
import glob
import os

print("╔══════════════════════════════════════════════╗")
print("║     NetSentinel ML — CICIDS2017 Training     ║")
print("╚══════════════════════════════════════════════╝")

# ── Step 1: Load all CSV files ────────────────────────────────
print("\n[Step 1] Loading CICIDS2017 dataset...")
all_files = glob.glob("cicids_data/*.csv")
print(f"  Found {len(all_files)} files")

dfs = []
for f in all_files:
    print(f"  Loading: {os.path.basename(f)}")
    try:
        df = pd.read_csv(f, encoding='utf-8', low_memory=False)
        dfs.append(df)
    except Exception as e:
        print(f"  Error: {e}")

df = pd.concat(dfs, ignore_index=True)
print(f"\n  Total rows loaded: {len(df):,}")

# ── Step 2: Clean data ────────────────────────────────────────
print("\n[Step 2] Cleaning data...")

# Strip whitespace from column names
df.columns = df.columns.str.strip()

# Find the label column
label_col = None
for col in df.columns:
    if 'label' in col.lower():
        label_col = col
        break

print(f"  Label column: {label_col}")
print(f"\n  Traffic distribution:")
print(df[label_col].value_counts().to_string())

# Drop infinite and NaN values
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
print(f"\n  Rows after cleaning: {len(df):,}")

# ── Step 3: Select features ───────────────────────────────────
print("\n[Step 3] Selecting features...")

# Best features for network traffic classification
feature_cols = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Packet Length Mean',
    'Packet Length Std',
]

# Only use columns that exist
available = [c for c in feature_cols if c in df.columns]
print(f"  Using {len(available)} features")

X = df[available]
y = df[label_col].str.strip()

# Simplify labels
def simplify_label(label):
    label = label.upper()
    if 'BENIGN' in label or 'NORMAL' in label:
        return 'NORMAL'
    elif 'DDOS' in label or 'DOS' in label:
        return 'DDoS'
    elif 'PORTSCAN' in label or 'PORT' in label:
        return 'PortScan'
    elif 'WEB' in label or 'SQL' in label or 'XSS' in label:
        return 'WebAttack'
    elif 'BRUTE' in label or 'FORCE' in label:
        return 'BruteForce'
    elif 'INFILTR' in label:
        return 'Infiltration'
    else:
        return 'Other'

y = y.apply(simplify_label)
print(f"\n  Simplified labels:")
print(y.value_counts().to_string())

# ── Step 4: Balance dataset ───────────────────────────────────
print("\n[Step 4] Balancing dataset...")

# Sample max 50000 per class to keep training fast
balanced_dfs = []
for label in y.unique():
    mask = y == label
    count = mask.sum()
    sample = min(count, 50000)
    idx = y[mask].sample(sample, random_state=42).index
    balanced_dfs.append(df.loc[idx])

df_balanced = pd.concat(balanced_dfs)
X_bal = df_balanced[available]
y_bal = df_balanced[label_col].str.strip().apply(simplify_label)

print(f"  Balanced dataset size: {len(df_balanced):,}")
print(f"  Label distribution:")
print(y_bal.value_counts().to_string())

# ── Step 5: Train model ───────────────────────────────────────
print("\n[Step 5] Training Random Forest...")
print("  (This may take 1-2 minutes...)")

X_train, X_test, y_train, y_test = train_test_split(
    X_bal, y_bal, test_size=0.2, random_state=42, stratify=y_bal)

print(f"  Training samples: {len(X_train):,}")
print(f"  Testing samples:  {len(X_test):,}")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    n_jobs=-1,           # use all CPU cores
    random_state=42,
    verbose=1
)
model.fit(X_train, y_train)
print("  Training complete!")

# ── Step 6: Evaluate ──────────────────────────────────────────
print("\n[Step 6] Evaluating model...")
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"\n  ┌─────────────────────────────────┐")
print(f"  │  ACCURACY: {acc*100:.2f}%              │")
print(f"  └─────────────────────────────────┘")

print("\n  Classification Report:")
print(classification_report(y_test, y_pred))

# ── Step 7: Feature importance ────────────────────────────────
print("\n[Step 7] Feature Importance:")
importances = model.feature_importances_
for feat, imp in sorted(zip(available, importances),
                        key=lambda x: -x[1])[:10]:
    bar = "#" * int(imp * 50)
    print(f"  {feat:<35} {imp:.3f}  {bar}")

# ── Step 8: Save model ────────────────────────────────────────
print("\n[Step 8] Saving model...")
model_data = {
    'model':    model,
    'features': available,
    'accuracy': acc,
    'classes':  list(model.classes_)
}
pickle.dump(model_data, open("cicids_model.pkl", "wb"))
print("  Model saved → cicids_model.pkl")

# ── Step 9: Sample predictions ────────────────────────────────
print("\n[Step 9] Sample predictions:")
sample = X_test.head(10)
preds  = model.predict(sample)
actual = y_test.head(10).values

print(f"\n  {'Actual':<15} {'Predicted':<15} {'Match'}")
print(f"  {'-'*40}")
for a, p in zip(actual, preds):
    match = "✓" if a == p else "✗"
    print(f"  {a:<15} {p:<15} {match}")

print(f"\n╔══════════════════════════════════════════════╗")
print(f"║  CICIDS2017 TRAINING COMPLETE                ║")
print(f"║  Accuracy: {acc*100:.2f}%                          ║")
print(f"║  Training samples: {len(X_train):,}               ║")
print(f"║  Model saved: cicids_model.pkl               ║")
print(f"╚══════════════════════════════════════════════╝")
print()
print("Resume line:")
print(f"'Trained Random Forest on CICIDS2017 dataset")
print(f" ({len(X_train):,} samples) — {acc*100:.1f}% accuracy'")