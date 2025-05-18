import json
import networkx as nx
from pathlib import Path
from typing import Dict, List, Tuple, Generator
import pandas as pd
from tqdm import tqdm
import multiprocessing as mp
from functools import partial
import pickle
from networkx.utils import open_file

def read_csv(csv_file_path: str | Path) -> List[List[str]]:
    """
    Read a CSV file and return its content as a list of lists.

    Args:
        file_path (str): The path to the CSV file.

    Returns:
        List[List[str]]: The content of the CSV file.
    """
    df = pd.read_csv(csv_file_path)
    file_names = df['file_name'].tolist()
    return file_names

def load_pcode(file_path: str | Path) -> Dict:
    """
    Load JSON data from a file.

    Args:
        file_path (str | Path): The path to the JSON file.

    Returns:
        Dict: The JSON content.
    """
    with open(file_path, "r") as f:
        return json.load(f)

def iterate_json_files(csv_file_path: str | Path, root_dir: str | Path) -> Generator[Tuple[Path, Dict], None, None]:
    """
    Iterate through all JSON files in a folder and its subfolders.

    Args:
        csv_file_path (str): The path to the CSV file containing file names.
        root_dir (str): The root directory containing benign and malware folders.

    Yields:
        Tuple[Path, Dict]: A tuple containing the file path and its content.
    """
    root_path = Path(root_dir)
    file_names = read_csv(csv_file_path)
    for file_name in tqdm(file_names, desc="Processing JSON files"):
        prefix = file_name[:2]
        possible_paths = [
            root_path / "benign" / prefix / f"{file_name}.json",
            root_path / "malware" / prefix / f"{file_name}.json"
        ]

        found = False
        for path in possible_paths:
            if path.exists():
                found = True
                try:
                    yield path, load_pcode(path)
                except json.JSONDecodeError:
                    print(f"Error decoding JSON: {path}")
                break
        
        if not found:
            print(f"File not found: {file_name}.json")

def clean_data(json_data: Dict) -> nx.DiGraph:
    """
    Clean JSON data and create a networkx graph from function calls.
    
    Args:
        json_data (Dict): The JSON data loaded from a file.
        
    Returns:
        nx.DiGraph: A directed graph representing function calls.
    """
    # Create a directed graph
    G = nx.DiGraph()
    
    # Extract function calls from the JSON data
    function_calls = json_data.get("function_calls", {})
    
    # Add nodes and edges to the graph
    for caller, callees in function_calls.items():
        # Add caller node if it doesn't exist
        if not G.has_node(caller):
            G.add_node(caller)
        
        # Add callee nodes and edges
        for callee in callees:
            if not G.has_node(callee):
                G.add_node(callee)
            G.add_edge(caller, callee)
    
    # Optionally add pcode information as node attributes
    pcode = json_data.get("pcode", {})
    for func_addr, code_lines in pcode.items():
        if G.has_node(func_addr):
            G.nodes[func_addr]["pcode"] = code_lines
    
    # Add additional metadata
    if "log_info" in json_data:
        G.graph["log_info"] = json_data["log_info"]
    if "fcg_hash" in json_data:
        G.graph["fcg_hash"] = json_data["fcg_hash"]
        
    return G

def save_graph(G, output_file):
    """
    Save a graph to a gpickle file using the correct function based on networkx version.
    
    Args:
        G (nx.DiGraph): The graph to save.
        output_file (Path): The output file path.
    """
    try:
        try:
            @open_file(1, mode='wb')
            def write_gpickle_custom(G, path):
                """Write graph in Python pickle format."""
                pickle.dump(G, path, protocol=pickle.HIGHEST_PROTOCOL)
                
            write_gpickle_custom(G, output_file)
            print(f"Saved graph to {output_file} using custom pickle")
            return
        except ImportError:
            pass
            
        # Try pickle module directly (most reliable fallback)
        with open(output_file, 'wb') as f:
            pickle.dump(G, f, protocol=pickle.HIGHEST_PROTOCOL)
        print(f"Saved graph to {output_file} using direct pickle")
    except Exception as e:
        print(f"Error saving graph to {output_file}: {str(e)}")
        raise

def process_single_file(file_data, output_base_path):
    """
    Process a single JSON file and save the resulting graph as a gpickle file.
    Used by the multiprocessing pool.
    
    Args:
        file_data (tuple): A tuple containing (file_path, json_data)
        output_base_path (Path): The base output directory
    
    Returns:
        str: A message indicating the result
    """
    file_path, json_data = file_data
    
    try:
        # Clean data and create graph
        G = clean_data(json_data)
        
        # Determine if it's malware or benign based on the file path
        category = "malware" if "malware" in str(file_path) else "benign"
        file_name = file_path.stem
        prefix = file_name[:2]
        
        # Create output directory structure
        output_dir = output_base_path / category / prefix
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create output filename
        output_file = output_dir / f"{file_name}.gpickle"
        
        # Save graph
        save_graph(G, output_file)
        
        return f"Successfully processed {file_path}"
    except Exception as e:
        return f"Error processing {file_path}: {str(e)}"

def process_files(csv_file_path: str | Path, root_dir: str | Path, output_base_dir: str | Path, num_processes=None):
    """
    Process all JSON files and save the resulting graphs as gpickle files.
    Uses multiprocessing to process files in parallel.
    
    Args:
        csv_file_path (str | Path): The path to the CSV file containing file names.
        root_dir (str | Path): The root directory containing benign and malware folders.
        output_base_dir (str | Path): The base directory to save the gpickle files.
        num_processes (int, optional): Number of processes to use. Defaults to None (uses CPU count).
    """
    output_base_path = Path(output_base_dir)
    
    # Collect all file data first
    file_data_list = []
    for file_path, json_data in iterate_json_files(csv_file_path, root_dir):
        file_data_list.append((file_path, json_data))
    
    # Use multiprocessing to process files in parallel
    if num_processes is None:
        num_processes = mp.cpu_count()
    
    print(f"Processing {len(file_data_list)} files using {num_processes} processes...")
    
    # Create a partial function with fixed output_base_path
    process_func = partial(process_single_file, output_base_path=output_base_path)
    
    # Use multiprocessing pool to process files
    with mp.Pool(processes=num_processes) as pool:
        results = list(tqdm(
            pool.imap(process_func, file_data_list),
            total=len(file_data_list),
            desc="Processing files"
        ))
    
    # Count successes and failures
    successes = sum(1 for result in results if not result.startswith("Error"))
    failures = len(results) - successes
    
    print(f"Processing complete: {successes} files processed successfully, {failures} failures")

def main():
    csv_file_path = "/home/tommy/Projects/cross-architecture/Experiment3.1/dataset/20250509_test.csv" 
    root_dir = "/home/tommy/datasets/cross-architecture/results_merged" 
    output_base_dir = "/home/tommy/Projects/cross-architecture/Gpickle/20250509_test"
    process_files(csv_file_path, root_dir, output_base_dir)
    
    print("Processing complete. All gpickle files have been saved.")

if __name__ == "__main__":
    main()