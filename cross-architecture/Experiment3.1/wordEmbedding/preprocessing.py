import json
from os import name
import re
from pathlib import Path
from typing import List, Dict, Sequence, Tuple, Generator, Optional
from unicodedata import category
import pandas as pd
from tqdm import tqdm



__all__ = ['load_json', 'Pcode_to_sentence']

#Regex pattern preprocessing
#1)  opcode_pattern: Extract P-Code
#2)  opcode_pattern: Extract Calculation

_opcode_pat = re.compile(r"(?:\)\s+|---\s+)([A-Z_]+)")
_operand_pattern = re.compile(r"\(([^ ,]+)\s*,\s*[^,]*,\s*([0-9]+)\)")

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
    Load a JSON file and return its content.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict: The content of the JSON file.
    """
    path = Path(file_path)
    with path.open(encoding="utf-8") as fp:
        return json.load(fp)

def iterate_json_files(csv_file_path: str | Path, root_dir: str | Path) -> Generator[Tuple[Path, Dict], None, None]:
    """
    Iterate through all JSON files in a folder and its subfolders.

    Args:
        foder_path (str): The path to the folder.
        suffix (str): The file extension to look for.

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

def _map_operand(op_type:str, size:str | None) -> str:
    op_type_l = op_type.lower()
    if op_type_l == 'register':
        return f"REG{size}" if size else "REG"
    if op_type_l == 'ram':
        return f"MEM{size}" if size else "MEM"
    if op_type_l in {'const', 'unique'}:
        return f"CONST{size}" if size else "CONST"
    return op_type.upper()

def _tokenize_line(line:str) -> List[str]:
    """
    Tokenize a line of text into words.

    Args:
        line (str): The line of text to tokenize.

    Returns:
        List[str]: A list of words.
    """
    
    # Preprocess P-Code
    command = _opcode_pat.search(line)
    if not command:
        return []
    command = command.group(1)
    
    # Preprocess Operands
    arguments : List[str] = []
    for operand, size in _operand_pattern.findall(line):
        arguments.append(_map_operand(operand, size))
        
    # Combine P-Code and Operands
    combined = "-".join([command] + arguments)
    return [combined]

def Pcode_to_sentence(pcode_dict: Dict[str, Sequence[str]]) -> List[List[str]]:
    """
    Convert P-Code to a sentence.
    
    Args:
        pcode_dict (Dict[str, Sequence[str]]): A dictionary containing P-Code.
        
    Returns:
        List[List[str]]: A list of sentences, where each sentence is a list of words.
    """
    sentences: List[List[str]] = []
    for addr, lines in pcode_dict["pcode"].items():
        sent: List[str] = []
        for line in lines:
            sent.extend(_tokenize_line(line))
        if sent:
            sentences.append(sent)
    return sentences


    
if __name__== "__main__":
    # Example usage
    folder_path = Path("/home/tommy/datasets/cross-architecture/results_0428")
    for file_path, pcode_dict in iterate_json_files(folder_path):
        sentences = Pcode_to_sentence(pcode_dict)
        #print one folder 
        print(f"File: {file_path}")