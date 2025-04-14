#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pandas as pd
import shutil
from tqdm import tqdm

# 參數設定
csv_path = "/home/tommy/Projects/cross-architecture/datasets/csv/Cross-arch_Dataset_20250407154948.csv"
benign_binary_path = "/home/tommy/datasets/benignware"
malware_binary_path = "/home/tommy/datasets/Malware202403"
dest_base = "/home/tommy/datasets/cross-architecture/data/20250407"

# 目的資料夾分成 benign 與 malware
dest_benign = os.path.join(dest_base, "benign")
dest_malware = os.path.join(dest_base, "malware")

# 讀取 CSV 檔案
df = pd.read_csv(csv_path)

total = len(df)
print(f"總共有 {total} 筆資料，開始複製檔案...")

# 逐筆處理 CSV 中的每一筆資料
for idx, row in tqdm(df.iterrows(), total=total, desc="複製檔案"):
    file_name = row['file_name']
    label = row['label']
    
    # 判斷來源與目的地：若 label 為 "benignware" 則使用 benign 路徑，
    # 其他則視為 malware（惡意軟體家族），使用 malware 路徑
    if label == "benign":
        source_base = benign_binary_path
        dest_folder_base = dest_benign
    else:
        source_base = malware_binary_path
        dest_folder_base = dest_malware
    
    # 假設檔案皆存放於子目錄中，該子目錄名稱為檔名的前兩個字元
    subdir = file_name[:2]
    source_file = os.path.join(source_base, subdir, file_name)
    dest_dir = os.path.join(dest_folder_base, subdir)
    dest_file = os.path.join(dest_dir, file_name)
    
    # 若目的資料夾不存在，則建立之
    os.makedirs(dest_dir, exist_ok=True)
    
    try:
        shutil.copy2(source_file, dest_file)
    except Exception as e:
        print(f"複製檔案失敗: {source_file} -> {dest_file}，錯誤: {e}")

print("所有檔案複製完成！")
