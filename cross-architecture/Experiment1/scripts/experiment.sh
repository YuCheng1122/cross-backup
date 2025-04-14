#!/bin/bash
# experiment.sh
# 用法:
#   ./experiment.sh --compile   # 執行編譯階段 (build: 針對 arm 與 mips)
#   ./experiment.sh --extract   # 執行 GHIDRA 分析階段 (ExtractPcode Java 腳本)
#   ./experiment.sh --compare   # 執行 Python 結果比較階段
#   ./experiment.sh --all       # 依序執行所有階段
#
# 範例:
#   ./experiment.sh --all

#############################
# 進度更新函數
#############################
progress_update() {
    echo "==> $1 完成！"
}

#############################
# 階段1：編譯階段（消融實驗：不同編譯設定）
#############################
compile_phase() {
    echo "開始執行編譯階段（消融實驗：不同編譯設定）..."
    
    # 添加工具鏈到 PATH (請確認路徑正確)
    export PATH="$HOME/x-tools/arm-unknown-linux-gnueabi/bin:$HOME/x-tools/mips-unknown-linux-gnu/bin:$PATH"
    
    BOT_DIR="/home/tommy/cross-architecture/Experiment1/MIRAI/Mirai-Source-Code/mirai/bot"
    
    # 定義輸出基本目錄 (改為 ../data)
    BASE_DATA_DIR="$(pwd)/../data"
    mkdir -p "$BASE_DATA_DIR"
    
    # 定義各組編譯設定，編譯參數即為 key 值
    declare -A compile_configs
    compile_configs[baseline]="-O0 -g -fno-common"
    compile_configs[opt_size]="-O1 -Os -g"
    compile_configs[opt_O1]="-O1 -g"
    compile_configs[opt_O2]="-O2 -g"
    compile_configs[opt_O3]="-O3 -g"
    compile_configs[opt_inline]="-O1 -finline-functions -g"
    compile_configs[opt_sibling_calls]="-O1 -foptimize-sibling-calls -g"
    compile_configs[opt_stack_protector]="-O1 -fstack-protector -g"
    compile_configs[opt_exceptions]="-O1 -fexceptions -g"
    compile_configs[opt_no_common]="-O1 -fno-common -g"
    
    # 函數：針對指定架構與編譯設定進行編譯
    compile_arch() {
        local arch="$1"
        local compiler="$2"
        local config_name="$3"
        local flags="$4"
        local objdump_cmd=""
        case "$arch" in
            arm)
                objdump_cmd="arm-unknown-linux-gnueabi-objdump"
                ;;
            mips)
                objdump_cmd="mips-unknown-linux-gnu-objdump"
                ;;
            *)
                echo "未知的架構: $arch"
                exit 1
                ;;
        esac
        
        # 建立暫存編譯目錄，避免中間檔案混淆
        local build_dir
        build_dir="$(pwd)/build_${arch}_${config_name}"
        mkdir -p "$build_dir"
        
        echo "[$arch][$config_name] 使用旗標: ${flags}"
        # 編譯所有 C 檔案，產生中間目標檔 (.o)
        for src in "${BOT_DIR}"/*.c; do
            local obj_file
            obj_file="$(basename "${src}" .c).o"
            ${compiler} ${flags} -c "${src}" -o "${build_dir}/${obj_file}"
        done
        
        # 鏈接產生二進位檔，檔名格式：mirai.<arch>.<compile_parameter>
        local binary_file="${BASE_DATA_DIR}/mirai.${arch}.${config_name}"
        ${compiler} ${flags} -static "${build_dir}"/*.o -o "${binary_file}" -lpthread
        
        # 導出符號表，檔名格式：symbols.<arch>.<compile_parameter>.txt
        if command -v "$objdump_cmd" &> /dev/null; then
            "$objdump_cmd" -t "${binary_file}" > "${BASE_DATA_DIR}/symbols.${arch}.${config_name}.txt"
        else
            echo "Warning: ${objdump_cmd} not found, skip symbol dump"
        fi
        
        # 清除暫存編譯目錄
        rm -rf "$build_dir"
    }
    
    # 函數：檢查指定二進位檔的 debug 資訊
    check_debug_info() {
        local arch="$1"
        local config_name="$2"
        local binary_file="${BASE_DATA_DIR}/mirai.${arch}.${config_name}"
        echo "檢查 ${arch}（配置：${config_name}）的 debug 資訊..."
        if [ -f "${binary_file}" ]; then
            readelf -S "${binary_file}" | grep debug
        else
            echo "找不到二進位檔：${binary_file}"
        fi
    }
    
    # 針對每個編譯設定進行編譯（分別針對 arm 與 mips 架構）
    for config in "${!compile_configs[@]}"; do
        local flags="${compile_configs[$config]}"
        echo "-------------------------------"
        echo "開始編譯設定： ${config}"
        compile_arch "arm" "arm-unknown-linux-gnueabi-gcc" "$config" "$flags"
        compile_arch "mips" "mips-unknown-linux-gnu-gcc" "$config" "$flags"
        
        # 檢查 debug 資訊
        check_debug_info "arm" "$config"
        check_debug_info "mips" "$config"
    done
    
    progress_update "編譯階段"
}

#############################
# 階段2：執行 GHIDRA 分析 (ExtractPcode Java)
#############################
extract_phase() {
    echo "開始執行 GHIDRA 分析階段..."
    local target_binary="$1"  # 新增參數接收目標二進位檔名稱
    
    BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
    cd "$BASE_DIR" || exit 1
    
    GHIDRA_HOME="/home/tommy/ghidra_11.2.1_PUBLIC"
    PROJECT_DIR="${BASE_DIR}/ghidra_projects"
    SCRIPT="${BASE_DIR}/ExtractPcodeAndFeatures.java"
    SCRIPT_PATH="${BASE_DIR}"
    OLD_OUT_DIR="${BASE_DIR}/tempJavaOutput"
    RESULTS_DIR="${BASE_DIR}/results"
    DATA_DIR="${BASE_DIR}/../data"
    
    BATCH_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    
    if [ ! -d "$PROJECT_DIR" ]; then
        mkdir -p "$PROJECT_DIR"
    fi
    
    echo "Base Directory: $BASE_DIR"
    echo "GHIDRA_HOME: $GHIDRA_HOME"
    echo "PROJECT_DIR: $PROJECT_DIR"
    echo "OLD_OUT_DIR: $OLD_OUT_DIR"
    echo "DATA_DIR: $DATA_DIR"
    echo "RESULTS_DIR: $RESULTS_DIR"
    echo "Batch Timestamp: $BATCH_TIMESTAMP"
    
    process_binary() {
        local file="$1"
        if [ ! -f "$file" ]; then
            echo "錯誤：找不到檔案 $file"
            return 1
        fi
        
        local base
        base=$(basename "$file")
        if [[ $base != mirai.* ]]; then
            echo "略過非二進位檔: $base"
            return 1
        fi

        local binary="$file"
        local arch
        arch=$(echo "$base" | cut -d'.' -f2)
        local PROJECT_NAME="Project_${arch}_${base}"
        echo "正在分析檔案: $binary (專案名稱: $PROJECT_NAME)"
        
        "$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" "$PROJECT_NAME" \
            -import "$binary" \
            -postScript "$SCRIPT" \
            -scriptPath "$SCRIPT_PATH" \
            -deleteProject
        
        local GENERATED_FILE="${base}.txt"
        echo "預期輸出檔案: ${OLD_OUT_DIR}/${GENERATED_FILE}"
        
        local DEST_DIR="${RESULTS_DIR}/${BATCH_TIMESTAMP}/${arch}"
        mkdir -p "$DEST_DIR"
        
        if [ -f "${OLD_OUT_DIR}/${GENERATED_FILE}" ]; then
            mv "${OLD_OUT_DIR}/${GENERATED_FILE}" "${DEST_DIR}/${base}.txt"
            echo "移動 ${GENERATED_FILE} 至 ${DEST_DIR}/${base}.txt"
        else
            echo "找不到輸出檔案: ${OLD_OUT_DIR}/${GENERATED_FILE}"
        fi
    }
    
    if [ -n "$target_binary" ]; then
        echo "指定分析特定二進位檔: $target_binary"
        local target_file="${DATA_DIR}/${target_binary}"
        process_binary "$target_file"
    else
        echo "分析所有二進位檔..."
        for file in "${DATA_DIR}"/*; do
            if [ -f "$file" ]; then
                process_binary "$file"
            fi
        done
    fi

    progress_update "GHIDRA 分析階段"
}

#############################
# 階段3：執行 Python 結果比較分析
#############################
compare_phase() {
    echo "開始執行 Python 結果比較分析階段..."
    
    # 定義 BASE_DIR 及其他目錄變數
    BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
    CURRENT_DIR="$(pwd)"
    
    PYTHON_SCRIPT="${BASE_DIR}/compare_pcode.py"
    RESULTS_DIR="${BASE_DIR}/results"
    
    # 檢查必要的目錄和檔案
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo "錯誤：找不到 Python 腳本 $PYTHON_SCRIPT"
        return 1
    fi
    
    if [ ! -d "$RESULTS_DIR" ]; then
        echo "錯誤：找不到結果目錄 $RESULTS_DIR"
        return 1
    fi
    
    # 確保所需的 Python 套件已安裝
    python3 -c "import pandas" 2>/dev/null || {
        echo "正在安裝所需的 Python 套件..."
        pip3 install pandas
    }
    
    # 切換到結果目錄
    cd "$RESULTS_DIR" || {
        echo "錯誤：無法切換到結果目錄 $RESULTS_DIR"
        return 1
    }
    
    # 執行 Python 腳本
    echo "執行 Python 分析腳本..."
    python3 "$PYTHON_SCRIPT"
    PYTHON_EXIT_CODE=$?
    
    # 切換回原始目錄
    cd "$CURRENT_DIR"
    
    # 檢查 Python 腳本執行結果
    if [ $PYTHON_EXIT_CODE -eq 0 ]; then
        progress_update "Python 結果比較分析階段"
        return 0
    else
        echo "錯誤：Python 腳本執行失敗 (退出碼: $PYTHON_EXIT_CODE)"
        return 1
    fi
}

#############################
# 用法說明
#############################
usage() {
    echo "用法: $0 [--compile | --extract [binary_name] | --compare | --all]"
    echo "  --compile : 執行編譯階段 (build: 針對 arm 與 mips)"
    echo "  --extract [binary_name] : 執行 GHIDRA 分析階段 (ExtractPcode Java)"
    echo "                           可選參數 binary_name 指定要分析的特定二進位檔"
    echo "  --compare : 執行 Python 結果比較階段"
    echo "  --all     : 依序執行所有階段"
    exit 1
}

#############################
# 主流程：根據命令列參數選擇要執行的階段
#############################
if [ $# -eq 0 ]; then
    usage
fi

case "$1" in
    --compile)
        compile_phase
        ;;
    --extract)
        if [ -n "$2" ]; then
            extract_phase "$2"
        else
            extract_phase
        fi
        ;;
    --compare)
        compare_phase
        ;;
    --all)
        compile_phase
        extract_phase
        compare_phase
        ;;
    *)
        usage
        ;;
esac
