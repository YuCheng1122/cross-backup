from typing import List, Dict, Sequence, Generator, Tuple
from pathlib import Path

import pandas as pd
from tqdm import tqdm
import networkx as nx
import numpy as np
from gensim.models import Word2Vec
import pickle

from preprocessing import read_csv, _tokenize_line


def iterate_Gpickle(
    csv_file_path: str | Path,
    root_dir:      str | Path
) -> Generator[Tuple[Path, Dict[str, Sequence[str]]], None, None]:
    """
    Iterate through all Gpickle files in a folder and its subfolders.
    Args:
        csv_file_path (str | Path): Path to the CSV file containing file names.
        root_dir (str | Path): Root directory for Gpickle files.
    Returns:
        Generator[Tuple[Path, Dict[str, Sequence[str]]], None, None]: A generator yielding tuples of file paths and their content.
    """
    root_path = Path(root_dir)
    for file_name in tqdm(read_csv(csv_file_path), desc="Processing Gpickle files"):
        prefix = file_name[:2]
        for sub in ("benign", "malware"):
            path = root_path / sub / prefix / f"{file_name}.gpickle"
            if path.exists():
                try:
                    with open(path, "rb") as fp:
                        G = pickle.load(fp)
                    pcode_map = nx.get_node_attributes(G, "pcode")
                    yield path, G, pcode_map
                except Exception as e:
                    tqdm.write(f"[Error] Load Gpickle Failed {path}: {e}")
                break
        else:
            tqdm.write(f"[Warning] File Not Found: {file_name}.gpickle")
            
def load_word2vec(model_path: str | Path) -> Word2Vec:
    """Docstring for load_word2vec
    Parm:
        model_path (str | Path): Path to the Word2Vec model.
    Returns:
        Word2Vec: Loaded Word2Vec model.
    """
    return Word2Vec.load(str(model_path))

def pcode_to_vectors(
    model:       Word2Vec,
    pcode_map:  Dict[str, Sequence[str]]
) -> np.ndarray:
    """
    Convert pcode dictionary to vectors using Word2Vec model.
    Args:
        model (Word2Vec): Word2Vec model.
        pcode_dict (Dict[str, Sequence[str]]): Dictionary containing pcode data.
    Returns:
        np.ndarray: Array of vectors."""

    node_vecs: Dict[str, np.ndarray] = {}
    
    for addr, lines in pcode_map.items():
        tokens: List[str] = []
        for line in lines:
            tokens.extend(_tokenize_line(line))
        ws = [model.wv[t] for t in tokens if t in model.wv]
        if ws:
            node_vecs[addr] = np.mean(ws, axis=0)
        else:
            node_vecs[addr] = np.zeros(model.vector_size, dtype=float)
    return node_vecs

def save_graph_with_vectors(
    csv_file_path: str | Path,
    gpickle_root:   str | Path,
    out_root:    str | Path,
    w2v_model_path: str | Path
):
    """
    Convert Gpickle files to vectors using Word2Vec model.
    Args:
        csv_file_path (str | Path): Path to the CSV file containing file names.
        gpickle_root (str | Path): Root directory for Gpickle files.
        vector_root (str | Path): Root directory for saving vector files.
        w2v_model_path (str | Path): Path to the Word2Vec model.
    Returns:
        None
    """
    gpickle_root = Path(gpickle_root)
    out_root      = Path(out_root)
    model = load_word2vec(w2v_model_path)

    for gpath, G, pcode_map in iterate_Gpickle(csv_file_path, gpickle_root):
        node_vecs = pcode_to_vectors(model, pcode_map)
        for addr, vec in node_vecs.items():
            G.nodes[addr]["vector"] = vec
            G.nodes[addr].pop("pcode", None)


        zero = np.zeros(model.vector_size, dtype=float)
        for addr in G.nodes:
            if "vector" not in G.nodes[addr]:
                G.nodes[addr]["vector"] = zero
            G.nodes[addr].pop("pcode", None)

        for k in ("log_info", "fcg_hash"):
            G.graph.pop(k, None) 

        rel_path = gpath.relative_to(gpickle_root)
        out_path = out_root / rel_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as fp:
            pickle.dump(G, fp)

        # tqdm.write(f"[Saved] {out_path} (added {len(node_vecs)} node vectors)")
        
if __name__ == "__main__":
    CSV_FILE_PATH = "/home/tommy/Projects/cross-architecture/Experiment3.1/dataset/20250509_test.csv"
    GPICKLE_DIR = "/home/tommy/Projects/cross-architecture/Gpickle/20250509_test"
    VECTOR_DIR = "/home/tommy/Projects/cross-architecture/Vector/20250509_test"
    WORD2VEC_MODEL_PATH = "/home/tommy/Projects/cross-architecture/Experiment3.1/wordEmbedding/word2vec_20250509_train.model"
    
    save_graph_with_vectors(
        CSV_FILE_PATH,
        GPICKLE_DIR,
        VECTOR_DIR,
        WORD2VEC_MODEL_PATH
    )