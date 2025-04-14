#!/usr/bin/env python3
import pandas as pd

# 讀取惡意樣本 CSV 檔案
malware_csv = '/home/tommy/cross-architecture/202503_Malware.csv'
df_malware = pd.read_csv(malware_csv)

# 處理惡意樣本的 label 欄位：填補缺失值、轉換為字串
df_malware['label'] = df_malware['label'].fillna('').astype(str)

# 處理 CPU 欄位：填補缺失值、去除前後空白
df_malware['CPU'] = df_malware['cpu'].fillna('').astype(str).apply(lambda x: x.strip())

# 過濾條件：
# 1. 過濾掉 label 為 "<unknown>" 或以 "SINGLETON:" 開頭的資料
# 2. 過濾掉 CPU 為含有 "64" 的項目(如 AArch64, X86-64)、空值、"未知"或以 "<unknown" 開頭的資料
df = df_malware[
    # (~df_malware['label'].str.startswith("SINGLETON:")) & 
    # (df_malware['label'] != "<unknown>") &
    # (~df_malware['CPU'].str.contains("64")) & 
    # (~df_malware['CPU'].str.startswith("<unknown")) & 
    (~df_malware['CPU'].isin(['', '未知']))
]

# 依 CPU 和 label 進行分組計數
label_counts = df.groupby(['CPU', 'label']).size().reset_index(name='出現次數')

# 將 'label' 欄位重命名為 'family'
label_counts = label_counts.rename(columns={'label': 'family'})

# 依 CPU 與出現次數排序（先依 CPU 字母順序排序，相同 CPU 內再依出現次數降序排序）
label_counts = label_counts.sort_values(by=['CPU', '出現次數'], ascending=[True, False])

# 將統計結果存成 CSV 檔案（編碼 utf-8-sig 可確保 Excel 正確顯示中文）
label_counts.to_csv('cpu_family_counts.csv', index=False, encoding='utf-8-sig')

print("統計結果已存成 'cpu_family_counts.csv'")