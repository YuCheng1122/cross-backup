#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pandas as pd
import numpy as np
import datetime
from tqdm import tqdm
import random

# === 設定檔案路徑 ===
benign_csv_path = '/home/tommy/datasets/benignware_info.csv'
malware_csv_path = '/home/tommy/datasets/202403_Malware(New).csv'
# 額外的惡意軟體資料集路徑
additional_malware_csv_path = '/home/tommy/datasets/202503_Malware.csv'

# 二進位檔案根目錄
benign_binary = '/home/tommy/datasets/benignware'
malware_binary = '/home/tommy/datasets/Malware202403'
# 額外的惡意軟體二進位檔案根目錄
additional_malware_binary = '/home/tommy/datasets/Malware202503/Malware'

# 讀取 CSV 檔案
df_benign = pd.read_csv(benign_csv_path)
df_malware = pd.read_csv(malware_csv_path)
# 如果額外惡意軟體檔案存在，也讀取它
try:
    df_additional_malware = pd.read_csv(additional_malware_csv_path)
    additional_malware_available = True
    print(f"已載入額外惡意軟體資料: {additional_malware_csv_path}")
except Exception as e:
    additional_malware_available = False
    print(f"警告: 無法載入額外惡意軟體資料 ({e})")

# 設定要處理的 CPU 架構（移除 AArch64）
cpu_list = ["Intel 80386", "ARM", "MIPS R3000", "Advanced Micro Devices X86-64", "PowerPC"]

# CPU 標籤映射字典 - 將 malware 的 CPU 標籤映射為與 benign 相同格式
cpu_mapping = {
    "Intel i386-32": "Intel 80386",
    "ARM-32": "ARM",
    "MIPS R3000-32": "MIPS R3000",
    "Advanced Micro Devices x86-64": "Advanced Micro Devices X86-64",  # 注意大小寫差異：x86-64 -> X86-64
    "PowerPC-32": "PowerPC"
}

# 映射 malware 資料集中的 CPU 欄位
df_malware['CPU'] = df_malware['CPU'].map(cpu_mapping).fillna(df_malware['CPU'])
# 如果額外惡意軟體資料集可用，也映射其 CPU 欄位
if additional_malware_available:
    df_additional_malware['CPU'] = df_additional_malware['CPU'].map(cpu_mapping).fillna(df_additional_malware['CPU'])

# 設定目標抽樣筆數
target_count = 3000

# 惡意軟體家族
malware_families = ["mirai", "gafgyt", "tsunami", "mobidash", "hajime", "dofloo", "kaiji", "wroba", "meterpreter"]

# ==============================
# 依據檔案實際大小進行 stratified 隨機抽樣
# 若總數不足 target_count 則全部取出；若足夠則分成 bins 個區間，各區間先取定額，最後補足不足的部分
# ==============================
def sample_by_filesize(df, binary_base, target_count=2000, bins=10, random_state=42):
    # 設定隨機種子
    random.seed(random_state)
    np.random.seed(random_state)
    
    # 定義一個函式取得檔案大小
    def get_size(file_name):
        # 根據檔名前兩個字元作為子目錄
        subdir = file_name[:2]
        path = os.path.join(binary_base, subdir, file_name)
        try:
            return os.path.getsize(path)
        except Exception as e:
            # 若檔案不存在或發生錯誤，回傳 -1 以便後續排除
            return -1

    # 加入檔案大小欄位
    df['file_size'] = df['file_name'].apply(get_size)
    # 排除無法取得檔案大小的資料（檔案不存在或錯誤）
    df = df[df['file_size'] >= 0].copy()
    
    # 根據檔案大小排序
    df = df.sort_values(by='file_size').reset_index(drop=True)
    total = len(df)
    
    if total <= target_count:
        return df

    # 將資料分成 bins 個區間
    splitted = np.array_split(df, bins)
    samples = []
    base_quota = target_count // bins  # 每區間目標數
    # 先各區取定額
    for part in splitted:
        if len(part) >= base_quota:
            samples.append(part.sample(n=base_quota, random_state=random_state))
        else:
            samples.append(part.copy())  # 若不足則全部取出
    sampled_df = pd.concat(samples, ignore_index=True)
    
    # 計算目前已取樣數量
    current_count = len(sampled_df)
    remaining = target_count - current_count
    if remaining > 0:
        # 從未被選取的資料中補足
        selected_indices = sampled_df.index.tolist()
        # 取得全部索引
        all_indices = set(df.index.tolist())
        remain_indices = list(all_indices - set(selected_indices))
        if len(remain_indices) > 0:
            extra = df.loc[remain_indices].sample(n=min(remaining, len(remain_indices)), random_state=random_state)
            sampled_df = pd.concat([sampled_df, extra], ignore_index=True)
    # 最後隨機打散
    sampled_df = sampled_df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    # 刪除輔助欄位 file_size
    sampled_df = sampled_df.drop(columns=['file_size'])
    return sampled_df

# 用來儲存最終抽樣結果與除錯資訊
selected_rows = []
selected_rows_with_additional = []  # 用於儲存包含額外惡意軟體的結果
debug_info = []
debug_info_with_additional = []  # 用於儲存包含額外惡意軟體的除錯資訊

# ---------------------------
# 處理良性軟體
# ---------------------------
for cpu in tqdm(cpu_list, desc="處理良性軟體"):
    debug_entry = {}
    debug_entry_additional = {}  # 用於儲存包含額外惡意軟體的除錯資訊
    debug_entry['CPU'] = cpu
    debug_entry_additional['CPU'] = cpu

    # 過濾該 CPU 且非 packed 的良性資料
    df_b_cpu = df_benign[(df_benign['CPU'] == cpu) & (df_benign['is_packed'] == 0)]
    orig_count = len(df_b_cpu)
    debug_entry['良性 原始數量'] = orig_count
    debug_entry_additional['良性 原始數量'] = orig_count

    if orig_count == 0:
        print(f"警告: {cpu} 下良性資料數量為 0")
        debug_entry['良性 取樣數量'] = 0
        debug_entry_additional['良性 取樣數量'] = 0
    else:
        # 根據檔案大小 stratified 抽樣
        sample_b = sample_by_filesize(df_b_cpu.copy(), benign_binary, target_count=target_count, bins=10, random_state=42)
        sample_b = sample_b[['file_name', 'CPU']].copy()
        sample_b['label'] = 'benign'
        selected_rows.append(sample_b)
        selected_rows_with_additional.append(sample_b.copy())  # 複製到額外資料集結果
        debug_entry['良性 取樣數量'] = len(sample_b)
        debug_entry_additional['良性 取樣數量'] = len(sample_b)
    
    debug_info.append(debug_entry)
    debug_info_with_additional.append(debug_entry_additional)

# ---------------------------
# 處理惡意軟體
# ---------------------------
for cpu in tqdm(cpu_list, desc="處理惡意軟體"):
    debug_entry = {}
    debug_entry_additional = {}
    debug_entry['CPU'] = cpu
    debug_entry_additional['CPU'] = cpu
    cpu_debug = {}
    cpu_debug_additional = {}

    for family in malware_families:
        # 過濾該 CPU 且屬於該家族，並排除 is_packed 為 true 的資料
        df_m_filtered = df_malware[
            (df_malware['CPU'] == cpu) &
            (df_malware['family'].str.lower() == family.lower()) &
            (df_malware['is_packed'].astype(str).str.lower() == "false")
        ]
        orig_count = len(df_m_filtered)
        cpu_debug[family] = {'原始數量': orig_count}
        cpu_debug_additional[family] = {'原始數量': orig_count}

        if orig_count == 0:
            print(f"警告: {cpu} 下 {family} 資料數量為 0")
            cpu_debug[family]['取樣數量'] = 0
            cpu_debug_additional[family]['取樣數量'] = 0
            continue

        # 根據檔案大小 stratified 抽樣
        sample_m = sample_by_filesize(df_m_filtered.copy(), malware_binary, target_count=target_count, bins=10, random_state=42)
        sample_m = sample_m[['file_name', 'CPU']].copy()
        sample_m['label'] = family
        selected_rows.append(sample_m)
        selected_rows_with_additional.append(sample_m.copy())  # 先加入基本資料集結果
        
        sampled_count = len(sample_m)
        cpu_debug[family]['取樣數量'] = sampled_count
        cpu_debug_additional[family]['取樣數量'] = sampled_count

        # 如果資料不足且有額外惡意軟體資料集可用，則從中補充
        if additional_malware_available and sampled_count < target_count:
            remaining_count = target_count - sampled_count
            print(f"嘗試從額外資料集補充 {cpu} - {family} 資料 (需要 {remaining_count} 筆)")
            
            # 過濾額外資料集中符合條件的資料
            df_additional_filtered = df_additional_malware[
                (df_additional_malware['CPU'] == cpu) &
                (df_additional_malware['family'].str.lower() == family.lower()) &
                (df_additional_malware['is_packed'].astype(str).str.lower() == "false")
            ]
            
            additional_orig_count = len(df_additional_filtered)
            cpu_debug_additional[family]['額外原始數量'] = additional_orig_count
            
            if additional_orig_count == 0:
                print(f"警告: 額外資料集中 {cpu} 下 {family} 資料數量為 0")
                cpu_debug_additional[family]['額外取樣數量'] = 0
            else:
                # 從額外資料集中抽樣所需數量
                additional_sample = sample_by_filesize(
                    df_additional_filtered.copy(), 
                    additional_malware_binary, 
                    target_count=remaining_count, 
                    bins=min(10, additional_orig_count // (remaining_count // 10 + 1) + 1), 
                    random_state=42
                )
                additional_sample = additional_sample[['file_name', 'CPU']].copy()
                additional_sample['label'] = family
                additional_sample['source'] = 'additional'  # 標記來源為額外資料集
                
                # 將額外抽樣結果加入到僅有額外資料的結果中
                selected_rows_with_additional.append(additional_sample)
                additional_sampled_count = len(additional_sample)
                cpu_debug_additional[family]['額外取樣數量'] = additional_sampled_count
                print(f"已從額外資料集補充 {additional_sampled_count} 筆 {cpu} - {family} 資料")
    
    debug_entry['惡意家族分布'] = cpu_debug
    debug_entry_additional['惡意家族分布'] = cpu_debug_additional
    debug_info.append(debug_entry)
    debug_info_with_additional.append(debug_entry_additional)

# ---------------------------
# 合併所有抽樣結果
# ---------------------------
final_df = pd.concat(selected_rows, ignore_index=True)
final_df = final_df[['file_name', 'CPU', 'label']]

# 合併包含額外惡意軟體的抽樣結果
final_df_with_additional = pd.concat(selected_rows_with_additional, ignore_index=True)
# 檢查是否有 'source' 欄位，若沒有則不包含在輸出
if 'source' in final_df_with_additional.columns:
    final_df_with_additional = final_df_with_additional[['file_name', 'CPU', 'label', 'source']]
else:
    final_df_with_additional = final_df_with_additional[['file_name', 'CPU', 'label']]

# 輸出檔案
timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
output_filename = f"Cross-arch_Dataset_{timestamp}.csv"
output_with_additional_filename = f"Cross-arch_Dataset_with_Additional_{timestamp}.csv"

final_df.to_csv(output_filename, index=False)
final_df_with_additional.to_csv(output_with_additional_filename, index=False)

# 輸出除錯資訊
print("====== 原始資料集除錯資訊 ======")
for entry in debug_info:
    print(f"CPU: {entry['CPU']}")
    if '良性 原始數量' in entry:
        print(f"  良性: 原始={entry['良性 原始數量']}，取樣={entry.get('良性 取樣數量', 0)}")
    if '惡意家族分布' in entry:
        print("  惡意家族:")
        for fam, stats in entry['惡意家族分布'].items():
            print(f"    - {fam}: 原始={stats.get('原始數量', 0)}，取樣={stats.get('取樣數量', 0)}")
    print("")

print("\n====== 包含額外資料集除錯資訊 ======")
for entry in debug_info_with_additional:
    print(f"CPU: {entry['CPU']}")
    if '良性 原始數量' in entry:
        print(f"  良性: 原始={entry['良性 原始數量']}，取樣={entry.get('良性 取樣數量', 0)}")
    if '惡意家族分布' in entry:
        print("  惡意家族:")
        for fam, stats in entry['惡意家族分布'].items():
            basic_info = f"    - {fam}: 原始={stats.get('原始數量', 0)}，取樣={stats.get('取樣數量', 0)}"
            if '額外原始數量' in stats:
                basic_info += f"，額外原始={stats.get('額外原始數量', 0)}，額外取樣={stats.get('額外取樣數量', 0)}"
            print(basic_info)
    print("")

print(f"原始資料已輸出至: {output_filename}")
print(f"包含額外資料的結果已輸出至: {output_with_additional_filename}")