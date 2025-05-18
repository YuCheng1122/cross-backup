import networkx as nx
import torch
from torch_geometric.data import Data
import sklearn.preprocessing as labelEncoder
from torch_geometric.utils import from_networkx
import numpy as np
from torch_geometric.data import DataLoader

from utils import read_csv, iterate_Gpickle

def load_data(csv_file_path, root_dir, vector_dim=256):
    """
    Load graph data from gpickle files and prepare for dataloader.
    
    Args:
        csv_file_path: Path to CSV file with file names and labels
        root_dir: Root directory for gpickle files
        transform: Optional transform to apply to graphs
        
    Returns:
        Tuple[List[Data], List[int]]: List of PyG Data objects and corresponding labels
    """

    graph_list = []
    labels = []
    
    # Get file names and labels from CSV
    file_names, labels_dict = read_csv(csv_file_path)
    
    # Iterate through gpickle files
    for path, G, pcode_map in iterate_Gpickle(csv_file_path, root_dir):
        try:
            file_name = path.stem
            label = labels_dict.get(file_name, 0)
    
            for node in G.nodes():
                vec = G.nodes[node].get("vector")
                if not isinstance(vec, np.ndarray) or vec.size != vector_dim:
                    vec = np.zeros(vector_dim, dtype=np.float32)
                # G.nodes[node]["x"] = torch.tensor(vec, dtype=torch.float32)
            data = from_networkx(G,group_node_attrs=["vector"])
            del data.vector
            graph_list.append(data)
            labels.append(label)
    
        except Exception as e:
            print(f"[ERROR] {path}: {e}")

    le = labelEncoder.LabelEncoder()
    le.fit(labels)
    labels_trans = le.transform(labels)

    return graph_list, labels_trans

