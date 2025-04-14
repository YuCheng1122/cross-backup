import json
import os
import csv
import re
import statistics
import datetime
import glob
import pandas as pd
from collections import defaultdict, Counter
from tqdm import tqdm
import multiprocessing
from functools import partial

def process_pcode_operations(pcode_list):
    """
    Process P-code operations and count them by category
    """
    operation_counts = {
        "DATA_MOVING": 0,
        "ARITHMETIC": 0,
        "LOGICAL": 0,
        "INTEGER_COMPARISON": 0,
        "BOOLEAN": 0,
        "FLOATING_POINT": 0,
        "FLOATING_POINT_COMPARE": 0,
        "FLOATING_POINT_CONVERSION": 0,
        "BRANCHING": 0,
        "EXTENSION": 0,
        "BITFIELD": 0,
        "MANAGED": 0,
        "MISC": 0
    }
    
    # Define regex patterns for different operation categories
    patterns = {
        # 資料搬移
        "DATA_MOVING": r"(COPY|LOAD|STORE|INDIRECT)",
        
        # 整數運算
        "ARITHMETIC": (
            r"(INT_ADD|INT_SUB|INT_CARRY|INT_SCARRY|INT_SBORROW|INT_2COMP|"
            r"INT_MULT|INT_DIV|INT_SDIV|INT_REM|INT_SREM|PTRADD|PTRSUB)"
        ),
        # 位元/邏輯運算
        "LOGICAL": (
            r"(INT_NEGATE|INT_XOR|INT_AND|INT_OR|INT_LEFT|INT_RIGHT|"
            r"INT_SRIGHT|POPCOUNT|LZCOUNT)"
        ),
        # 整數比較
        "INTEGER_COMPARISON": r"(INT_EQUAL|INT_NOTEQUAL|INT_SLESS|INT_SLESSEQUAL|INT_LESS|INT_LESSEQUAL)",
        # 布林運算
        "BOOLEAN": r"(BOOL_NEGATE|BOOL_XOR|BOOL_AND|BOOL_OR)",
        # 浮點運算
        "FLOATING_POINT": r"(FLOAT_ADD|FLOAT_SUB|FLOAT_MULT|FLOAT_DIV|FLOAT_NEG|FLOAT_ABS|FLOAT_SQRT|FLOAT_NAN)",
        # 浮點比較
        "FLOATING_POINT_COMPARE": r"(FLOAT_EQUAL|FLOAT_NOTEQUAL|FLOAT_LESS|FLOAT_LESSEQUAL)",
        # 浮點轉換
        "FLOATING_POINT_CONVERSION": (
            r"(INT2FLOAT|FLOAT2FLOAT|TRUNC|CEIL|FLOOR|ROUND|"
            r"FLOAT_INT2FLOAT|FLOAT_FLOAT2FLOAT)"
        ),
        # 分支/呼叫
        "BRANCHING": r"(CBRANCH|BRANCHIND|BRANCH|CALL|CALLIND|CALLOTHER|RETURN)",
        # 擴展運算
        "EXTENSION": r"(INT_ZEXT|INT_SEXT|PIECE|SUBPIECE|CAST|MULTIEQUAL)",
        # 位元欄位操作
        "BITFIELD": r"(EXTRACT|INSERT)",
        # 記憶體管理 / 新增物件
        "MANAGED": r"(CPOOLREF|NEW)",
        # 其他雜項
        "MISC": r"(SEGMENTOP|UNIMPLEMENTED)"
    }
    
    # Count operations in each pcode instruction
    total_ops = 0
    unrecognized_ops = set()
    
    for instruction in pcode_list:
        matched = False
        
        # 改進: 先處理分支指令的特殊情況
        if instruction.startswith(" --- "):
            for branching_op in ["CBRANCH", "BRANCHIND", "BRANCH", "CALL", "CALLIND", "CALLOTHER", "RETURN"]:
                if branching_op in instruction:
                    operation_counts["BRANCHING"] += 1
                    total_ops += 1
                    matched = True
                    break
            continue
        
        # 改進: 簡化並優化操作碼提取的正則表達式
        op_match = None
        
        op_match = re.search(r'(?:\)|\s)\s*([A-Z][A-Z0-9_]+)\s*\(', instruction)
        
        if not op_match:
            op_match = re.search(r'^([A-Z][A-Z0-9_]+)\s*\(', instruction)
        
        if op_match:
            operation = op_match.group(1)
            
            for category, pattern in patterns.items():
                if re.search(pattern, operation):
                    operation_counts[category] += 1
                    matched = True
                    total_ops += 1
                    break
            
            if not matched:
                unrecognized_ops.add(operation)
        
    operation_counts["TOTAL_OPS"] = total_ops
    operation_counts["UNRECOGNIZED_OPS"] = len(unrecognized_ops)
    
    return operation_counts, patterns, list(unrecognized_ops)

def analyze_cfg(pcode_list):
    """
    Analyze the Control Flow Graph (CFG) by identifying basic blocks and edges
    from P-code instructions
    """
    if not pcode_list:
        return {"CFG_NODES": 0, "CFG_EDGES": 0}
    
    # Identify basic blocks by finding branch instructions and their targets
    branch_targets = set()
    for instruction in pcode_list:
        if " --- " in instruction:
            # Extract target address from branch instructions
            match = re.search(r'ram, (0x[0-9a-f]+)', instruction)
            if match:
                branch_targets.add(match.group(1))
    
    # Create basic blocks
    basic_blocks = []
    current_block = []
    
    for instruction in pcode_list:
        # Check if this instruction is the start of a new basic block
        # (either it's the first instruction or it's a branch target)
        if not current_block:
            current_block.append(instruction)
        else:
            current_block.append(instruction)
            
            # Check if this instruction ends a basic block
            if " --- " in instruction:
                basic_blocks.append(current_block)
                current_block = []
    
    # Add the last block if there's any instruction left
    if current_block:
        basic_blocks.append(current_block)
    
    # Count edges - each basic block can have 0, 1, or 2 outgoing edges depending on branch type
    edges = 0
    for block in basic_blocks:
        last_instruction = block[-1] if block else ""
        
        if not " --- " in last_instruction:
            # Not a control flow instruction - shouldn't happen but let's be safe
            continue
        
        if "CBRANCH" in last_instruction:
            # Conditional branch has two outgoing edges
            edges += 2
        elif "BRANCH" in last_instruction or "BRANCHIND" in last_instruction:
            # Unconditional branch has one outgoing edge
            edges += 1
        elif "CALL" in last_instruction or "CALLIND" in last_instruction:
            # Call has one outgoing edge to the callee and one to the next instruction
            edges += 2
        elif "RETURN" in last_instruction:
            # Return has no outgoing edges within this function
            pass
        elif "CALLOTHER" in last_instruction:
            # CALLOTHER has one outgoing edge (similar to CALL)
            edges += 1
        else:
            # Handle other control flow operations conservatively
            edges += 1
    
    return {
        "CFG_NODES": len(basic_blocks),
        "CFG_EDGES": edges,
        "CFG_EDGE_TO_NODE_RATIO": edges / len(basic_blocks) if len(basic_blocks) > 0 else 0
    }

def analyze_function_calls(function_addr, function_calls):
    """
    Analyze function calls to compute in-degree and out-degree
    """
    # Calculate out-degree (number of functions this function calls)
    out_degree = len(function_calls.get(function_addr, []))
    
    # Calculate in-degree (number of functions that call this function)
    in_degree = sum(1 for addr, callees in function_calls.items() 
                    if function_addr in callees)
    
    # Get the list of functions this function calls
    called_functions = function_calls.get(function_addr, [])
    
    # Get the list of functions that call this function
    caller_functions = [addr for addr, callees in function_calls.items() 
                      if function_addr in callees]
    
    return {
        "FUNCTION_OUT_DEGREE": int(out_degree),
        "FUNCTION_IN_DEGREE": int(in_degree),
        "CALLS_TO": called_functions,
        "CALLED_BY": caller_functions  
    }

def process_binary_file(file_path, log_file):
    """
    Process a binary file and extract features
    """
    try:
        # Read the JSON data
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Extract basic file information
        full_file_name = os.path.basename(file_path)
        if '_' in full_file_name:
            file_name = full_file_name.split('_')[0]
        else:
            file_name = os.path.splitext(full_file_name)[0]
        
        # Extract architecture information if available
        architecture = data.get("log_info", {}).get("architecture", "unknown")
        
        # Process functions
        functions_data = []
        file_level_features = defaultdict(list)
        
        # Extract function call graph
        function_calls = data.get("function_calls", {})
        pcode_data = data.get("pcode", {})
        
        if not pcode_data:
            log_message = f"WARNING: No pcode data found in {full_file_name} (Architecture: {architecture})"
            with open(log_file, 'a') as log:
                log.write(log_message + "\n")
            
            # Return None instead of empty data structure to filter out this file
            return None
        
        # Process each function
        for func_addr, pcode_list in pcode_data.items():
            if not pcode_list:  # Skip empty functions
                continue
                
            # Process P-code operations for this function
            op_counts, patterns, unrecognized_ops = process_pcode_operations(pcode_list)
            
            # Log unrecognized operations
            if unrecognized_ops:
                log_message = f"WARNING: {len(unrecognized_ops)} unrecognized operation types found in function {func_addr} in {full_file_name}: {', '.join(unrecognized_ops)}"
                with open(log_file, 'a') as log:
                    log.write(log_message + "\n")
            
            # Analyze CFG for this function
            cfg_metrics = analyze_cfg(pcode_list)
            
            # Analyze function calls
            call_metrics = analyze_function_calls(func_addr, function_calls)
            
            # Combine all function-level features
            function_features = {**op_counts, **cfg_metrics, **call_metrics}
            
            # Add to functions list
            functions_data.append({
                "function_name": func_addr,
                "function_level_features": function_features
            })
            
            # Collect metrics for file-level aggregation
            for metric, value in function_features.items():
                # Only aggregate numeric values, skip the lists of function addresses
                if isinstance(value, (int, float)) and metric not in ["CALLS_TO", "CALLED_BY"]:
                    file_level_features[metric].append(value)
        
        # Calculate file-level aggregated features
        aggregated_features = {
            "Total_functions": len(functions_data)
        }
        
        for metric, values in file_level_features.items():
            if values:  # Check if we have values to calculate statistics
                aggregated_features[f"Total_{metric}"] = sum(values)
                
                # Only calculate mean for values that make sense
                if metric not in ["ARCHITECTURE"]:
                    if metric in ["FUNCTION_IN_DEGREE", "FUNCTION_OUT_DEGREE"]:
                        aggregated_features[f"Avg_{metric}"] = round(statistics.mean(values), 2)
                    else:
                        aggregated_features[f"Avg_{metric}"] = statistics.mean(values)
        
        # Construct the final result
        result = {
            "file_name": file_name,
            "architecture": architecture,
            "file_level_features": aggregated_features,
            "functions": functions_data
        }
        
        return result
    
    except Exception as e:
        log_message = f"ERROR processing {file_path}: {str(e)}"
        with open(log_file, 'a') as log:
            log.write(log_message + "\n")
        return None

def process_file_wrapper(file_path, log_file):
    """
    Wrapper function for process_binary_file to use with multiprocessing
    """
    return process_binary_file(file_path, log_file)

def get_metadata_map():
    """
    Read metadata from the specified CSV file and create a mapping
    from file name to CPU and label information
    """
    metadata_file = "/home/tommy/cross-architecture/Experiment3/csv/Sorted_Dataset_20250312114058.csv"
    try:
        df = pd.read_csv(metadata_file)
        metadata_map = {}
        for _, row in df.iterrows():
            # Extract just the file name without extension and _CPU suffix
            file_name = row.get('file_name', '')
            # If filename contains underscore, just take the first part (MD5 hash)
            if '_' in file_name:
                clean_name = file_name.split('_')[0]
            else:
                # Otherwise remove the extension
                clean_name = os.path.splitext(file_name)[0]
                
            metadata_map[clean_name] = {
                'CPU': row.get('CPU', ''),
                'label': row.get('label', '')  # Unified label field for both benign and malware
            }
        return metadata_map
    except Exception as e:
        print(f"Warning: Could not read metadata file: {e}")
        return {}

def save_to_csv(data_list, output_file_prefix, metadata_map):
    """
    Save the extracted data to CSV files, including metadata columns
    
    Args:
        data_list: List of processed binary data
        output_file_prefix: Output file prefix for CSV
        metadata_map: Map of file names to metadata
    """
    # Filter out None values (failed processing)
    data_list = [data for data in data_list if data]
    
    if not data_list:
        print("No valid data to save.")
        return
    
    # Use unified label field for all data
    label_field = "label"
    
    # ========== 文件級特徵處理 ==========
    
    # Create file-level CSV
    with open(f"{output_file_prefix}_file_features.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Get all possible feature keys
        feature_keys = set()
        for data in data_list:
            feature_keys.update(data["file_level_features"].keys())
        
        # 需要排除的文件級特徵
        unnecessary_file_features = [
            "Avg_BITFIELD", "Avg_UNRECOGNIZED_OPS", "Avg_MISC", "Avg_MANAGED",
            "Total_BITFIELD", "Total_MANAGED", "Total_MISC", "Total_UNRECOGNIZED_OPS"
        ]
        feature_keys = [k for k in feature_keys if k not in unnecessary_file_features]
        
        # Write header with metadata columns first
        header = ["file_name", "CPU", label_field] + list(sorted(feature_keys))
        writer.writerow(header)
        
        # Write data for each file
        for data in data_list:
            file_name = data["file_name"]
            metadata = metadata_map.get(file_name, {'CPU': '', label_field: ''})
            
            row = [file_name, metadata['CPU'], metadata[label_field]]
            row.extend([data["file_level_features"].get(key, "") for key in header[3:]])
            writer.writerow(row)
    
    # ========== 函數級特徵處理 ==========
    
    # Create function-level CSV
    with open(f"{output_file_prefix}_function_features.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Get all possible feature keys
        feature_keys = set()
        for data in data_list:
            for func in data["functions"]:
                feature_keys.update(func["function_level_features"].keys())
        
        # 需要排除的函數級特徵 - 新增:
        # 1. 與文件級特徵相同的不需要特徵
        # 2. 函數級特定的不需要特徵 (MISC, BITFIELD, MANAGED 等)
        unnecessary_function_features = [
            "UNRECOGNIZED_OPS", "MISC", "MANAGED", "BITFIELD"
        ]
        
        # 移除列表類型的特徵和不需要的特徵
        list_features = ["CALLS_TO", "CALLED_BY"]
        csv_feature_keys = [k for k in feature_keys 
                           if k not in list_features and k not in unnecessary_function_features]
        
        # Write header with metadata columns first
        header = ["file_name", "CPU", label_field, "function_name"] + list(sorted(csv_feature_keys))
        writer.writerow(header)
        
        # Write data for each function
        for data in data_list:
            file_name = data["file_name"]
            metadata = metadata_map.get(file_name, {'CPU': '', label_field: ''})
            
            for func in data["functions"]:
                # 過濾掉不需要的特徵
                filtered_features = {k: v for k, v in func["function_level_features"].items() 
                                   if k in csv_feature_keys}
                
                row = [file_name, metadata['CPU'], metadata[label_field], func["function_name"]]
                row.extend([filtered_features.get(key, "") for key in header[4:]])
                writer.writerow(row)
    
    # ========== 函數調用關係處理 ==========
    
    # Create a separate CSV for function call relationships
    with open(f"{output_file_prefix}_function_calls.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        header = ["file_name", "CPU", label_field, "function_name", "calls_function", "relationship_type"]
        writer.writerow(header)
        
        # Write data for each function's call relationships
        for data in data_list:
            file_name = data["file_name"]
            metadata = metadata_map.get(file_name, {'CPU': '', label_field: ''})
            
            for func in data["functions"]:
                func_name = func["function_name"]
                features = func["function_level_features"]
                
                # Write outgoing calls (this function calls other functions)
                for called_func in features.get("CALLS_TO", []):
                    row = [file_name, metadata['CPU'], metadata[label_field], func_name, called_func, "calls"]
                    writer.writerow(row)
                
                # Write incoming calls (other functions call this function)
                for caller_func in features.get("CALLED_BY", []):
                    row = [file_name, metadata['CPU'], metadata[label_field], func_name, caller_func, "called_by"]
                    writer.writerow(row)

def process_files_batch(files, log_file, desc):
    """
    Process a batch of files using multiprocessing
    """
    num_processes = max(1, multiprocessing.cpu_count() - 1)  # Leave one CPU free
    
    # Create a partial function with the log_file parameter
    process_func = partial(process_file_wrapper, log_file=log_file)
    
    # Process files in parallel
    with multiprocessing.Pool(processes=num_processes) as pool:
        results = list(tqdm(
            pool.imap(process_func, files),
            total=len(files),
            desc=desc
        ))
    
    return [r for r in results if r]  # Filter out None results

def process_all_data():
    """
    Process all files in the results directory
    """
    base_dir = "/home/tommy/datasets/cross-architecture/results"
    output_dir = "/home/tommy/Projects/cross-architecture/datasets/csv"
    logs_dir = "/home/tommy/Projects/logs"
    
    # Create output and logs directories if they don't exist
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    
    # Get current date for file naming
    current_date = datetime.datetime.now().strftime("%Y%m%d")
    
    # Define log file path
    log_file = os.path.join(logs_dir, f"{current_date}_all_data_cleaning.log")
    
    # Load metadata map
    metadata_map = get_metadata_map()
    
    # Initialize log file
    with open(log_file, 'w') as log:
        log.write(f"Processing all data on {datetime.datetime.now()}\n")
        log.write("-" * 80 + "\n")
    
    # Find all benign files
    benign_dir = os.path.join(base_dir, "benign")
    benign_files = glob.glob(os.path.join(benign_dir, "**", "*.json"), recursive=True)
    
    print(f"Found {len(benign_files)} total benign files to process")
    
    benign_data = process_files_batch(
        benign_files, 
        log_file, 
        "Processing all benign files"
    )
    
    # Find all malware files
    malware_dir = os.path.join(base_dir, "malware")
    malware_files = glob.glob(os.path.join(malware_dir, "**", "*.json"), recursive=True)
    
    print(f"Found {len(malware_files)} total malware files to process")
    
    malware_data = process_files_batch(
        malware_files, 
        log_file, 
        "Processing all malware files"
    )
    
    # Save benign data with unified label field
    benign_output_prefix = os.path.join(output_dir, f"{current_date}-5_cleaned_all_benign")
    save_to_csv(benign_data, benign_output_prefix, metadata_map)
    print(f"Saved {len(benign_data)} benign samples to {benign_output_prefix}_*.csv")
    
    # Save malware data with unified label field
    malware_output_prefix = os.path.join(output_dir, f"{current_date}-5_cleaned_all_malware")
    save_to_csv(malware_data, malware_output_prefix, metadata_map)
    print(f"Saved {len(malware_data)} malware samples to {malware_output_prefix}_*.csv")
    
    # Save combined data (benign + malware)
    combined_data = benign_data + malware_data
    combined_output_prefix = os.path.join(output_dir, f"{current_date}-5_cleaned_all_combined")
    save_to_csv(combined_data, combined_output_prefix, metadata_map)
    print(f"Saved {len(combined_data)} combined samples to {combined_output_prefix}_*.csv")
    
    # Deduplicated version removed as requested
    
    # Log completion
    with open(log_file, 'a') as log:
        log.write(f"Completed processing all data. Processed {len(benign_data)} benign and {len(malware_data)} malware samples.\n")
        log.write(f"Total combined samples: {len(combined_data)}\n")

def main():
    # Process all data at once
    print("Processing all dataset...")
    process_all_data()
    
    print("\nAll processing complete!")

if __name__ == "__main__":
    main()