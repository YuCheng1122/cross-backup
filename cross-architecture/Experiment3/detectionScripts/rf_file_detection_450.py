import pandas as pd
import numpy as np
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import KFold
import matplotlib.pyplot as plt
import seaborn as sns

# Create directory for results
results_dir = 'cross_architecture_results'
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

# Load datasets from all architectures
architectures = {
    'ARM': '/home/tommy/cross-architecture/Experiment3/scripts_20250328/ARM_file_features_samples.csv',
    'Intel 80386': '/home/tommy/cross-architecture/Experiment3/scripts_20250328/Intel_80386_file_features_samples.csv',
    'AMD X86-64': '/home/tommy/cross-architecture/Experiment3/scripts_20250328/Advanced Micro Devices X86-64_file_features_samples.csv',
    'MIPS': '/home/tommy/cross-architecture/Experiment3/scripts_20250328/MIPS R3000_file_features_samples.csv'
}

# Load all datasets
datasets = {}
for arch, path in architectures.items():
    datasets[arch] = pd.read_csv(path)
    print(f"Loaded {arch} dataset with {len(datasets[arch])} samples")

# Balance the datasets to have exactly 450 benign and 450 malware samples
for arch in architectures.keys():
    df = datasets[arch]
    
    # Step 1: Separate benign and malware samples
    benign_samples = df[df['label'] == 'benign']
    malware_samples = df[df['label'] != 'benign']
    
    # Get the unique malware labels
    malware_labels = malware_samples['label'].unique()
    print(f"{arch} has {len(malware_labels)} malware classes: {malware_labels}")
    
    # Step 2: Balance benign samples to exactly 450
    if len(benign_samples) > 450:
        benign_samples = benign_samples.sample(n=450, random_state=42)
    elif len(benign_samples) < 450:
        benign_samples = benign_samples.sample(n=450, replace=True, random_state=42)
    
    # Step 3: Balance malware samples by taking an equal number from each malware class
    samples_per_malware_class = 450 // len(malware_labels)
    balanced_malware = []
    
    for label in malware_labels:
        class_samples = malware_samples[malware_samples['label'] == label]
        if len(class_samples) > samples_per_malware_class:
            class_samples = class_samples.sample(n=samples_per_malware_class, random_state=42)
        elif len(class_samples) < samples_per_malware_class:
            class_samples = class_samples.sample(n=samples_per_malware_class, replace=True, random_state=42)
        balanced_malware.append(class_samples)
    
    # Combine all balanced malware samples
    balanced_malware_df = pd.concat(balanced_malware, ignore_index=True)
    
    # Ensure we have exactly 450 malware samples in total
    if len(balanced_malware_df) > 450:
        balanced_malware_df = balanced_malware_df.sample(n=450, random_state=42)
    elif len(balanced_malware_df) < 450:
        balanced_malware_df = balanced_malware_df.sample(n=450, replace=True, random_state=42)
    
    # Combine balanced benign and malware samples
    datasets[arch] = pd.concat([benign_samples, balanced_malware_df], ignore_index=True)
    
    # Create binary label
    datasets[arch]['binary_label'] = datasets[arch]['label'].apply(lambda x: 'benign' if x == 'benign' else 'malware')
    
    # Verify balanced dataset
    benign_count = len(datasets[arch][datasets[arch]['binary_label'] == 'benign'])
    malware_count = len(datasets[arch][datasets[arch]['binary_label'] == 'malware'])
    print(f"{arch} balanced binary labels: benign={benign_count}, malware={malware_count}")
    
    # Save the balanced dataset
    datasets[arch].to_csv(f"{results_dir}/{arch}_balanced_dataset.csv", index=False)
    print(f"Saved balanced dataset for {arch}")

# Exclude non-feature columns
excluded_columns = ['file_name', 'CPU', 'label', 'binary_label']

# Find common features across all datasets
all_features = set()
for df in datasets.values():
    all_features.update(set(df.columns))
common_features = list(all_features - set(excluded_columns))

# Make sure all datasets have the same features, filling missing ones with zeros
for arch in architectures.keys():
    for feature in common_features:
        if feature not in datasets[arch].columns:
            datasets[arch][feature] = 0

# Setup for K-Fold cross-validation (only for self-detection)
k_folds = 5
kf = KFold(n_splits=k_folds, shuffle=True, random_state=42)

# Initialize results storage
arch_names = list(architectures.keys())
n_archs = len(arch_names)

# For self-detection with 5-fold CV
self_detection_f1_scores = {}  # Dictionary to store F1 scores for each fold of self-detection
self_detection_avg_f1 = {}     # Dictionary to store average F1 scores for self-detection

# For cross-architecture detection
cross_arch_f1_matrix = np.zeros((n_archs, n_archs))  # Matrix to store F1 scores

# Create a results dataframe to store all F1 scores
results_df = pd.DataFrame(columns=['Source', 'Target', 'Type', 'Fold', 'F1_Score'])
row_count = 0

# PART 1: Self-detection using 5-fold cross-validation
print("\n=== PART 1: Self-Detection using 5-Fold Cross-Validation ===")
for i, arch in enumerate(arch_names):
    print(f"\n--- Self-Detection for {arch} ---")
    
    # Get data for this architecture
    df = datasets[arch]
    X = df[common_features].values
    y = df['binary_label'].values
    
    # Save the full dataset
    df.to_csv(f"{results_dir}/{arch}_full_dataset.csv", index=False)
    
    # Initialize list to store F1 scores for each fold
    self_detection_f1_scores[arch] = []
    
    # Perform 5-fold cross-validation
    for fold, (train_idx, test_idx) in enumerate(kf.split(X)):
        print(f"Processing Fold {fold+1}/{k_folds}")
        
        # Split data for this fold
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        
        # Save fold-specific data
        fold_train_df = df.iloc[train_idx].copy()
        fold_test_df = df.iloc[test_idx].copy()
        fold_train_df.to_csv(f"{results_dir}/{arch}_fold{fold+1}_train.csv", index=False)
        fold_test_df.to_csv(f"{results_dir}/{arch}_fold{fold+1}_test.csv", index=False)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Make predictions and calculate F1 score
        y_pred = model.predict(X_test)
        f1 = f1_score(y_test, y_pred, average='weighted')
        self_detection_f1_scores[arch].append(f1)
        
        # Add to results dataframe
        results_df.loc[row_count] = [arch, arch, 'Self-Detection', fold+1, f1]
        row_count += 1
        
        print(f"Fold {fold+1} F1 Score: {f1:.4f}")
    
    # Calculate average F1 score for this architecture
    avg_f1 = np.mean(self_detection_f1_scores[arch])
    std_f1 = np.std(self_detection_f1_scores[arch])
    self_detection_avg_f1[arch] = avg_f1
    
    print(f"Average F1 Score for {arch} (self-detection): {avg_f1:.4f} ± {std_f1:.4f}")
    
    # Store the self-detection result in the matrix diagonal
    cross_arch_f1_matrix[i, i] = avg_f1

# PART 2: Cross-Architecture Detection (train on whole source architecture, test on whole target architecture)
print("\n=== PART 2: Cross-Architecture Detection ===")
for i, source_arch in enumerate(arch_names):
    print(f"\n--- Training on {source_arch} ---")
    
    # Get source data (full dataset)
    source_df = datasets[source_arch]
    X_source = source_df[common_features].values
    y_source = source_df['binary_label'].values
    
    # Train model on the entire source dataset
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_source, y_source)
    
    # Test on all target architectures (except self, which was handled with 5-fold CV)
    for j, target_arch in enumerate(arch_names):
        if target_arch == source_arch:
            # Skip self-detection as it was already done with 5-fold CV
            continue
        
        print(f"Testing on {target_arch}")
        
        # Get target data (full dataset)
        target_df = datasets[target_arch]
        X_target = target_df[common_features].values
        y_target = target_df['binary_label'].values
        
        # Make predictions on the target architecture
        y_pred = model.predict(X_target)
        
        # Calculate F1 score
        f1 = f1_score(y_target, y_pred, average='weighted')
        cross_arch_f1_matrix[i, j] = f1
        
        # Add to results dataframe
        results_df.loc[row_count] = [source_arch, target_arch, 'Cross-Architecture', 'Full', f1]
        row_count += 1
        
        print(f"F1 Score ({source_arch} -> {target_arch}): {f1:.4f}")

# Save detailed results to CSV
results_df.to_csv(f"{results_dir}/all_detection_results.csv", index=False)
print(f"Saved all detection results to {results_dir}/all_detection_results.csv")

# Create individual bar charts for each source architecture
for i, source_arch in enumerate(arch_names):
    # Get F1 scores for this source architecture
    f1_scores = cross_arch_f1_matrix[i, :]
    
    # Create bar chart
    plt.figure(figsize=(10, 6))
    bars = plt.bar(arch_names, f1_scores, capsize=5)
    
    # Highlight self-detection bar
    bars[i].set_color('orange')
    
    plt.xlabel('Target Architecture')
    plt.ylabel('F1 Score')
    plt.title(f'F1 Scores: Model Trained on {source_arch}')
    plt.ylim(0, 1.0)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f'{results_dir}/f1_scores_{source_arch}_bar_chart.png', dpi=600)
    plt.close()

# Create a heatmap for F1 scores
plt.figure(figsize=(12, 10))
sns.heatmap(cross_arch_f1_matrix, annot=True, fmt='.4f', cmap='Blues',
            xticklabels=arch_names, yticklabels=arch_names)

plt.xlabel('Target Architecture')
plt.ylabel('Source Architecture')
plt.title('F1 Scores: Training on Row Architecture, Testing on Column Architecture')
plt.tight_layout()
plt.savefig(f'{results_dir}/f1_score_heatmap.png', dpi=600)
plt.close()

# Summary of self-detection results
self_detection_df = pd.DataFrame(columns=['Architecture', 'Avg_F1_Score', 'Std_F1_Score'])
for i, arch in enumerate(arch_names):
    avg_f1 = np.mean(self_detection_f1_scores[arch])
    std_f1 = np.std(self_detection_f1_scores[arch])
    self_detection_df.loc[i] = [arch, avg_f1, std_f1]

self_detection_df.to_csv(f"{results_dir}/self_detection_summary.csv", index=False)
print(f"Saved self-detection summary to {results_dir}/self_detection_summary.csv")

print(f"\nAll results saved to the '{results_dir}' directory")
print("For self-detection, 5-fold cross-validation was used.")
print("For cross-architecture detection, models were trained on the entire source dataset and tested on the entire target dataset.")
print("The heatmap shows how well classifiers trained on one architecture perform on other architectures.")
print("Each architecture has 450 benign and 450 malware samples, with malware samples evenly distributed across classes.")