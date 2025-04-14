#!/usr/bin/env python3
import os
import glob
import json
import pandas as pd
from datetime import datetime

def jaccard_score(A, B):
    intersection = len(A.intersection(B))
    union = len(A.union(B))
    if union == 0:
        return 0, 0, 0
    return intersection / union, intersection, union

def calculate_cls_similarity(seq1, seq2):
    """
    計算兩個序列的 CLS (Common Longest Subsequence) 相似度
    """
    m, n = len(seq1), len(seq2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq1[i-1] == seq2[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    
    cls_length = dp[m][n]
    score = (2.0 * cls_length) / (len(seq1) + len(seq2)) if (len(seq1) + len(seq2)) > 0 else 0
    
    return score, cls_length

def build_func_info(pcode_dict, func_names, func_features):
    """
    建立 mapping: function name -> (address, opcode set, opcode sequence, features)
    """
    info = {}
    for addr, lines in pcode_dict.items():
        name = func_names.get(addr, addr)
        opcode_set = set()
        opcode_seq = []
        
        # 解析 opcode
        for line in lines:
            tokens = line.split()
            if tokens:
                if tokens[0].startswith('(') and len(tokens) > 3:
                    opcode = tokens[3]
                    opcode_set.add(opcode)
                    opcode_seq.append(opcode)
                elif len(tokens) > 1:
                    opcode = tokens[1]
                    opcode_set.add(opcode)
                    opcode_seq.append(opcode)
                    
        # 獲取函式特徵
        features = func_features.get(addr, [0, 0, 0, 0])  # 預設值為 [0,0,0,0]
        
        info[name] = (addr, opcode_set, opcode_seq, features)
    return info

def load_user_defined_funcs(filepath):
    user_defined_funcs = set()
    try:
        with open(filepath, 'r') as f:
            for line in f:
                func = line.strip()
                if func:
                    user_defined_funcs.add(func)
    except FileNotFoundError:
        print(f"Warning: User defined functions file {filepath} not found")
    return user_defined_funcs

def get_config_name(filename):
    """從檔案名稱中提取配置名稱"""
    # 例如從 'mirai.arm.baseline.txt' 提取 'baseline'
    parts = filename.split('.')
    if len(parts) >= 3:
        return parts[2]  # 配置名稱是第三個部分
    return None

def load_data_from_directory(dir_path):
    """從目錄載入所有配置的數據"""
    results = {}
    files = glob.glob(os.path.join(dir_path, "*.txt"))
    
    for file_path in files:
        try:
            config_name = get_config_name(os.path.basename(file_path))
            if not config_name:
                continue
                
            with open(file_path, "r") as f:
                data = json.load(f)
                results[config_name] = data
                print(f"成功載入配置 {config_name} 的數據")
        except Exception as e:
            print(f"載入檔案 {file_path} 時發生錯誤: {str(e)}")
            continue
    
    return results

def compare_same_configs(arm_data, mips_data, user_defined_funcs, compare_dir, timestamp):
    """比較相同配置名稱的 ARM 和 MIPS 架構數據"""
    
    # 找出兩個架構共有的配置
    common_configs = set(arm_data.keys()) & set(mips_data.keys())
    
    for config in common_configs:
        print(f"比較配置: {config}")
        
        arm_config_data = arm_data[config]
        mips_config_data = mips_data[config]
        
        pcode_arm = arm_config_data.get("pcode", {})
        func_names_arm = arm_config_data.get("func_names", {})
        func_features_arm = arm_config_data.get("func_features", {})
        pcode_mips = mips_config_data.get("pcode", {})
        func_names_mips = mips_config_data.get("func_names", {})
        func_features_mips = mips_config_data.get("func_features", {})
        
        if not (pcode_arm and pcode_mips):
            print(f"配置 {config} 缺少必要的數據")
            continue

        arm_info = build_func_info(pcode_arm, func_names_arm, func_features_arm)
        mips_info = build_func_info(pcode_mips, func_names_mips, func_features_mips)
        common_funcs = set(arm_info.keys()) & set(mips_info.keys())
        
        if not common_funcs:
            print(f"配置 {config} 沒有共同的函數")
            continue

        results = []
        for func in sorted(common_funcs):
            arm_addr, arm_op_set, arm_op_seq, arm_features = arm_info[func]
            mips_addr, mips_op_set, mips_op_seq, mips_features = mips_info[func]
            
            sim, intersection, union = jaccard_score(arm_op_set, mips_op_set)
            cls_sim, cls_length = calculate_cls_similarity(arm_op_seq, mips_op_seq)
            is_user_defined = 1 if (func in user_defined_funcs) else 0
            
            results.append({
                "Config": config,
                "ARM Address": arm_addr,
                "ARM Function Name": func,
                "ARM Called Count": arm_features[0],  # 被呼叫次數
                "ARM Calling Count": arm_features[1],  # 呼叫其他函式數
                "ARM Param Count": arm_features[2],  # 參數個數
                "ARM CBranch Count": arm_features[3],  # cbranch 次數
                "ARM Set Size": len(arm_op_set),
                "ARM Sequence Length": len(arm_op_seq),
                "MIPS Address": mips_addr,
                "MIPS Function Name": func,
                "MIPS Called Count": mips_features[0],  # 被呼叫次數
                "MIPS Calling Count": mips_features[1],  # 呼叫其他函式數
                "MIPS Param Count": mips_features[2],  # 參數個數
                "MIPS CBranch Count": mips_features[3],  # cbranch 次數
                "MIPS Set Size": len(mips_op_set),
                "MIPS Sequence Length": len(mips_op_seq),
                "Similarity Score": sim,
                "Intersection Size": intersection,
                "Union Size": union,
                "CLS Length": cls_length,
                "CLS Similarity Score": cls_sim,
                "UserDefined": is_user_defined
            })
        
        if results:
            df = pd.DataFrame(results)
            current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_csv = os.path.join(compare_dir, 
                                    f"comparison_{timestamp}_{config}_{current_time}.csv")
            df.to_csv(output_csv, index=False)
            print(f"已儲存配置 {config} 的比較結果至 {output_csv}")
    
    return True

def main():
    # 結果存放目錄
    RESULTS_DIR = "."  # 修改為當前目錄
    COMPARE_DIR = os.path.join(RESULTS_DIR, "compare")
    os.makedirs(COMPARE_DIR, exist_ok=True)

    # 載入使用者定義的函式
    user_defined_funcs = load_user_defined_funcs('/home/tommy/user_defined_funcs.txt')

    # 找出 RESULTS 目錄下的 timestamp 子目錄
    timestamp_dirs = [d for d in os.listdir(RESULTS_DIR)
                     if os.path.isdir(os.path.join(RESULTS_DIR, d)) and d.lower() != "compare"]

    if not timestamp_dirs:
        print("找不到 timestamp 目錄")
        return 1

    timestamp_dirs.sort()
    for ts in timestamp_dirs:
        print(f"處理時間戳記目錄: {ts}")
        ts_path = os.path.join(RESULTS_DIR, ts)
        
        # 檢查並載入 ARM 和 MIPS 目錄
        arm_path = os.path.join(ts_path, "arm")
        mips_path = os.path.join(ts_path, "mips")
        
        if not (os.path.exists(arm_path) and os.path.exists(mips_path)):
            print(f"在 {ts} 中找不到 arm 或 mips 目錄")
            continue
            
        # 載入所有配置的數據
        arm_data = load_data_from_directory(arm_path)
        mips_data = load_data_from_directory(mips_path)
        
        if not (arm_data and mips_data):
            print(f"無法載入 {ts} 的數據")
            continue
            
        # 比較相同配置名稱的組合
        if compare_same_configs(arm_data, mips_data, user_defined_funcs, COMPARE_DIR, ts):
            print(f"完成 {ts} 的所有配置比較")
        else:
            print(f"比較過程中發生錯誤")

    return 0

if __name__ == "__main__":
    exit(main())