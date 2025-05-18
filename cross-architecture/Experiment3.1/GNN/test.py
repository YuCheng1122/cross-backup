import torch
from tqdm import tqdm

def test(model, test_loader, criterion, device):
    """
    Evaluates the model on the test dataset.
    
    Args:
        model: GCN Model
        test_loader: DataLoader for test data
        criterion: Loss function
        device: Device to run the model on (CPU or GPU)
        
    Returns:
        avg_loss: Average loss on the test data
        accuracy: Accuracy of the model on the test data
        y_true: True labels for the test data
        y_pred: Predicted labels for the test data
    """
    model.eval()
    total_loss = 0
    correct = 0
    total = 0
    
    y_true = []
    y_pred = []
    
    with torch.no_grad():
        for batch in tqdm(test_loader, desc="Testing"):
            batch = batch.to(device)
            
            out = model(batch.x, batch.edge_index, batch.batch)
            
            loss = criterion(out, batch.y)
            
            total_loss += loss.item() * batch.num_graphs
            pred = out.argmax(dim=1)
            correct += int((pred == batch.y).sum())
            total += batch.y.size(0)
            
            y_true.extend(batch.y.cpu().numpy())
            y_pred.extend(pred.cpu().numpy())
    
    avg_loss = total_loss / len(test_loader.dataset)
    accuracy = correct / total
    
    return avg_loss, accuracy, y_true, y_pred
