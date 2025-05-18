import torch
import numpy as np
from torch_geometric.data import DataLoader
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import os
import time
from tqdm import tqdm

# 載入模型
from model import GCN

def train(model, train_loader, optimizer, criterion, device, epoch):
    """
    Trains the model for one epoch.
    
    Args:
        model: GCN Model
        train_loader: DataLoader for training data
        optimizer: Optimizer for model parameters
        criterion: Loss function
        device: Device to run the model on (CPU or GPU)
        epoch: Current epoch number
        
    Returns:
        avg_loss: Average loss for the epoch
        accuracy: Accuracy of the model on the training data
    """
    model.train()
    total_loss = 0
    correct = 0
    total = 0
    
    progress_bar = tqdm(train_loader, desc=f"Epoch {epoch}")
    
    for batch in progress_bar:
        batch = batch.to(device)
        optimizer.zero_grad()
        out = model(batch.x, batch.edge_index, batch.batch)
        loss = criterion(out, batch.y)
        
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item() * batch.num_graphs
        # Need to add softmax
        pred = out.argmax(dim=1)
        correct += int((pred == batch.y).sum())
        total += batch.y.size(0)
        
        progress_bar.set_postfix({
            'loss': f"{loss.item():.4f}",
            'acc': f"{correct/total:.4f}"
        })
    
    avg_loss = total_loss / len(train_loader.dataset)
    accuracy = correct / total
    
    return avg_loss, accuracy