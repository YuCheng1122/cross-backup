import pandas as pd
import numpy as np
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
import matplotlib.pyplot as plt
import seaborn as sns

# Load the AMD X86-64 features file
amd_df = pd.read_csv('/home/tommy/cross-architecture/Experiment3/scripts_20250328/Advanced Micro Devices X86-64_file_features_samples.csv')
print(f"AMD X86-64 dataset has {len(amd_df)} samples")

# Load the ARM features file
arm_df = pd.read_csv('/home/tommy/cross-architecture/Experiment3/scripts_20250328/ARM_file_features_samples.csv')
print(f"ARM dataset has {len(arm_df)} samples")

# Load the MIPS features file (for testing)
mips_df = pd.read_csv('/home/tommy/cross-architecture/Experiment3/scripts_20250328/MIPS R3000_file_features_samples.csv')
print(f"MIPS dataset has {len(mips_df)} samples")

# Check label distributions for all architectures
for df, name in [(amd_df, "AMD X86-64"), (arm_df, "ARM"), (mips_df, "MIPS")]:
    label_counts = df['label'].value_counts()
    print(f"\n{name} Label distribution:")
    for label, count in label_counts.items():
        print(f"  {label}: {count} samples")

# Use only ARM dataset for training
train_df = arm_df.copy()
print(f"\nTraining dataset size (ARM only): {len(train_df)} samples")

# Extract features and labels
# Exclude non-feature columns
excluded_columns = ['file_name', 'CPU', 'label']
feature_columns = [col for col in train_df.columns if col not in excluded_columns]

# Ensure both datasets have the same feature columns
common_features = [col for col in feature_columns if col in mips_df.columns]
if len(common_features) != len(feature_columns):
    print(f"\nWarning: Some features are missing in MIPS dataset. Using only {len(common_features)} common features.")
    feature_columns = common_features

print(f"\nNumber of features used: {len(feature_columns)}")

# Create directory for results
results_dir = 'cross_arch_arm_only_results'
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

# Prepare training data
X_train = train_df[feature_columns].values
y_train = train_df['label'].values

# Prepare test data (MIPS)
X_test = mips_df[feature_columns].values
y_test = mips_df['label'].values

# Train the Random Forest classifier
print("\nTraining Random Forest classifier on ARM data only...")
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)

# Make predictions on MIPS test data
print("Making predictions on MIPS test data...")
y_pred = rf.predict(X_test)

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
conf_matrix = confusion_matrix(y_test, y_pred)

# Print results
print("\nPerformance Metrics on MIPS Test Data:")
print(f"  Accuracy: {accuracy:.4f}")
print(f"  Precision: {precision:.4f}")
print(f"  Recall: {recall:.4f}")
print(f"  F1 Score: {f1:.4f}")

# Generate and save classification report
class_report = classification_report(y_test, y_pred)
print("\nClassification Report:")
print(class_report)

with open(f'{results_dir}/classification_report.txt', 'w') as f:
    f.write(class_report)

# Save test results with predictions
test_results_df = mips_df.copy()
test_results_df['predicted_label'] = y_pred
test_results_df.to_csv(f'{results_dir}/mips_test_predictions.csv', index=False)

# Plot confusion matrix
unique_labels = sorted(mips_df['label'].unique())
plt.figure(figsize=(10, 8))
sns.heatmap(conf_matrix, annot=True, fmt='d', 
            xticklabels=unique_labels, 
            yticklabels=unique_labels, 
            cmap='Blues')
plt.xlabel('Predicted')
plt.ylabel('True')
plt.title('Confusion Matrix on MIPS Test Data')
plt.tight_layout()
plt.savefig(f'{results_dir}/confusion_matrix.png')
plt.close()

# Feature importance
feature_importance = rf.feature_importances_
sorted_idx = np.argsort(feature_importance)[::-1]

print("\nTop 10 most important features:")
for i in range(min(10, len(feature_columns))):
    feature_idx = sorted_idx[i]
    print(f"{feature_columns[feature_idx]}: {feature_importance[feature_idx]:.4f}")

# Plot feature importance
plt.figure(figsize=(12, 8))
top_features = 20  # Show top 20 features
plt.barh(range(top_features), feature_importance[sorted_idx[:top_features]])
plt.yticks(range(top_features), [feature_columns[i] for i in sorted_idx[:top_features]])
plt.xlabel('Feature Importance')
plt.title('Top 20 Most Important Features')
plt.tight_layout()
plt.savefig(f'{results_dir}/feature_importance.png')
plt.close()

# Save all metrics to a summary file
with open(f'{results_dir}/performance_metrics_summary.txt', 'w') as f:
    f.write("Cross-Architecture ML Evaluation Results\n")
    f.write("=====================================\n\n")
    f.write(f"Training Data: ARM ({len(arm_df)} samples) only\n")
    f.write(f"Test Data: MIPS ({len(mips_df)} samples)\n\n")
    f.write(f"Number of features used: {len(feature_columns)}\n\n")
    
    f.write("Performance Metrics:\n")
    f.write(f"  Accuracy: {accuracy:.4f}\n")
    f.write(f"  Precision: {precision:.4f}\n")
    f.write(f"  Recall: {recall:.4f}\n")
    f.write(f"  F1 Score: {f1:.4f}\n\n")
    
    f.write("Classification Report:\n")
    f.write(class_report)
    
    f.write("\nConfusion Matrix:\n")
    f.write(str(conf_matrix))
    
    f.write("\n\nTop 10 Most Important Features:\n")
    for i in range(min(10, len(feature_columns))):
        feature_idx = sorted_idx[i]
        f.write(f"{feature_columns[feature_idx]}: {feature_importance[feature_idx]:.4f}\n")

print(f"\nAll results saved to the '{results_dir}' directory")
print("\nSummary: This cross-architecture evaluation tested how well a model trained on")
print("ARM samples only performs on the MIPS architecture.")