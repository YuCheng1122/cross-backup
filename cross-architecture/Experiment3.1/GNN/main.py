import torch
from torch_geometric.data import DataLoader
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
from tqdm import tqdm

# 導入自定義模組
from train_utils import load_data
from model import GCN


def main():
    # 檔案路徑
    train_csv_path = "/home/tommy/Projects/cross-architecture/Experiment3.1/dataset/cleaned_20250509_train.csv"
    test_csv_path = "/home/tommy/Projects/cross-architecture/Experiment3.1/dataset/cleaned_20250509_test.csv"
    train_dir = "/home/tommy/Projects/cross-architecture/Vector/20250509_train"
    test_dir = "/home/tommy/Projects/cross-architecture/Vector/20250509_test"
    
    # 超參數
    batch_size = 32
    hidden_channels = 64
    lr = 0.001
    epochs = 30
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    print(f"使用設備: {device}")
    
    # 載入資料
    print("載入訓練資料...")
    train_graphs, train_labels = load_data(train_csv_path, train_dir)
    print(f"載入了 {len(train_graphs)} 個訓練圖")
    
    print("載入測試資料...")
    test_graphs, test_labels = load_data(test_csv_path, test_dir)
    print(f"載入了 {len(test_graphs)} 個測試圖")
    
    # 標籤編碼
    label_encoder = LabelEncoder()
    encoded_train_labels = label_encoder.fit_transform(train_labels)
    encoded_test_labels = label_encoder.transform(test_labels)
    num_classes = len(label_encoder.classes_)
    print(f"類別數: {num_classes}")
    print(f"類別: {label_encoder.classes_}")
    
    # 更新圖的標籤
    for i, data in enumerate(train_graphs):
        data.y = torch.tensor([encoded_train_labels[i]], dtype=torch.float)
    
    for i, data in enumerate(test_graphs):
        data.y = torch.tensor([encoded_test_labels[i]], dtype=torch.float)
    
    # 創建 DataLoader
    train_loader = DataLoader(train_graphs, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_graphs, batch_size=batch_size, shuffle=False)

    model = GCN(num_node_features=256, hidden_channels=hidden_channels, num_classes=num_classes).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = torch.nn.CrossEntropyLoss()
    
    train_losses = []
    test_accuracies = []
    
    for epoch in range(1, epochs + 1):
        # 訓練
        model.train()
        total_loss = 0
        
        for batch in tqdm(train_loader, desc=f"Epoch {epoch}/{epochs}"):
            batch = batch.to(device)
            optimizer.zero_grad()
            out = model(batch.x, batch.edge_index, batch.batch)
            loss = criterion(out, batch.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * batch.num_graphs
        
        avg_loss = total_loss / len(train_loader.dataset)
        train_losses.append(avg_loss)
        
        # 測試
        model.eval()
        correct = 0
        
        with torch.no_grad():
            for batch in test_loader:
                batch = batch.to(device)
                out = model(batch.x, batch.edge_index, batch.batch)
                pred = out.argmax(dim=1)
                correct += int((pred == batch.y).sum())
        
        test_accuracy = correct / len(test_loader.dataset)
        test_accuracies.append(test_accuracy)
        
        print(f"Epoch {epoch}, Loss: {avg_loss:.4f}, Test Accuracy: {test_accuracy:.4f}")
    
    # 保存模型
    torch.save(model.state_dict(), "gcn_model.pth")
    print("模型已保存到 gcn_model.pth")
    
    # 繪製訓練曲線
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    plt.plot(train_losses)
    plt.title('Training Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    
    plt.subplot(1, 2, 2)
    plt.plot(test_accuracies)
    plt.title('Test Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    
    plt.tight_layout()
    plt.savefig('training_curves.png')
    plt.show()
    
    # 最終評估
    model.eval()
    y_true = []
    y_pred = []
    
    with torch.no_grad():
        for batch in test_loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index, batch.batch)
            pred = out.argmax(dim=1)
            y_true.extend(batch.y.cpu().numpy())
            y_pred.extend(pred.cpu().numpy())
    
    # 印出類別名稱和對應的數值
    for i, class_name in enumerate(label_encoder.classes_):
        print(f"類別 {i}: {class_name}")
    
    # 計算每個類別的準確率
    from sklearn.metrics import classification_report
    report = classification_report(y_true, y_pred, target_names=label_encoder.classes_)
    print("\n分類報告:")
    print(report)

if __name__ == "__main__":
    main()