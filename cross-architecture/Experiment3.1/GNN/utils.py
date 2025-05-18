from cProfile import label
import scipy.sparse as sp
import torch
import numpy as np
import scipy.sparse as sp
import torch
import networkx as nx
import random
from pathlib import Path
from tqdm import tqdm
import pickle
from typing import Dict, List, Tuple, Generator, Sequence
import pandas as pd


def iterate_Gpickle(
    csv_file_path: str | Path,
    root_dir: str | Path
) -> Generator[Tuple[Path, nx.DiGraph, Dict[str, Sequence[str]]], None, None]:
    """
    Iterate through gpickle files listed in a CSV.
    
    Args:
        csv_file_path: Path to CSV file with file names
        root_dir: Root directory for gpickle files
        
    Returns:
        Generator yielding tuples of (path, graph, pcode_map)
    """
    root_path = Path(root_dir)
    
    # Read file names from CSV
    csv_result = read_csv(csv_file_path)
    file_names = csv_result[0]  # Get file names only
    
    for file_name in tqdm(file_names, desc="Processing Gpickle files"):
        # Try different directory structures
        paths_to_try = [
            # Try with benign/malware subdirectories with 2-char prefix
            *[root_path / sub / file_name[:2] / f"{file_name}.gpickle" for sub in ("benign", "malware")],
            # Try with benign/malware subdirectories without prefix
            *[root_path / sub / f"{file_name}.gpickle" for sub in ("benign", "malware")],
            # Try direct in root directory
            root_path / f"{file_name}.gpickle",
        ]
        
        # Try each path
        for path in paths_to_try:
            if path.exists():
                try:
                    with open(path, "rb") as fp:
                        G = pickle.load(fp)
                    pcode_map = nx.get_node_attributes(G, "pcode")
                    yield path, G, pcode_map
                    break  # Found and loaded successfully, move to next file
                except Exception as e:
                    tqdm.write(f"[Error] Load Gpickle Failed {path}: {e}")
        else:
            # None of the paths worked
            tqdm.write(f"[Warning] File Not Found: {file_name}.gpickle")


def read_csv(csv_file_path: str | Path) -> List[str]:
    """
    Read a CSV file and return file names and labels as a dictionary.
    
    Args:
        csv_file_path (str or Path): The path to the CSV file.
    
    Returns:
        Tuple[List[str], Dict[str, int]]: File names and a dictionary mapping file names to labels.
    """
    df = pd.read_csv(csv_file_path)
    file_names = df['file_name'].tolist()
    
    # Create a dictionary mapping file names to labels
    labels_dict = {}
    if 'label' in df.columns:
        for idx, row in df.iterrows():
            labels_dict[row['file_name']] = row['label']
    
    return file_names, labels_dict


def encode_labels_for_gcn(labels):
    """
    Encode labels for GCN model handling both binary and multi-class classification.
    
    Args:
        labels: numpy array of labels
    
    Returns:
        torch.LongTensor: encoded labels ready for GCN
    """
    unique_labels = np.unique(labels)
    
    if len(unique_labels) == 2 and set(unique_labels) == {0, 1}:
        # Binary classification - just return LongTensor directly
        return torch.LongTensor(labels)
    else:
        # Multi-class classification - use one-hot encoding first
        classes = sorted(set(labels))
        classes_dict = {c: i for i, c in enumerate(classes)}
        # Convert labels to indices
        label_indices = np.array([classes_dict[label] for label in labels])
        return torch.LongTensor(label_indices)


def visualize_results(train_losses, train_accs, val_losses, val_accs, report, cm, class_names, save_dir):
    """
    視覺化訓練結果
    
    Args:
        train_losses: 訓練損失
        train_accs: 訓練準確率
        val_losses: 驗證損失
        val_accs: 驗證準確率
        report: 分類報告
        cm: 混淆矩陣
        class_names: 類別名稱
        save_dir: 保存目錄
    """
    os.makedirs(save_dir, exist_ok=True)
    
    # 繪製損失曲線
    plt.figure(figsize=(10, 5))
    plt.plot(train_losses, label='Train Loss')
    plt.plot(val_losses, label='Validation Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.title('Training and Validation Loss')
    plt.legend()
    plt.grid(True)
    plt.savefig(os.path.join(save_dir, 'loss_curve.png'))
    plt.close()
    
    # 繪製準確率曲線
    plt.figure(figsize=(10, 5))
    plt.plot(train_accs, label='Train Accuracy')
    plt.plot(val_accs, label='Validation Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.title('Training and Validation Accuracy')
    plt.legend()
    plt.grid(True)
    plt.savefig(os.path.join(save_dir, 'accuracy_curve.png'))
    plt.close()
    
    # 繪製混淆矩陣
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=class_names, yticklabels=class_names)
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.title('Confusion Matrix')
    plt.savefig(os.path.join(save_dir, 'confusion_matrix.png'))
    plt.close()
    
    # 保存分類報告
    with open(os.path.join(save_dir, 'classification_report.txt'), 'w') as f:
        f.write(report)

