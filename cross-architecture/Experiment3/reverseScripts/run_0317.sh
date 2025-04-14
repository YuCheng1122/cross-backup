#!/bin/bash
# Define paths
GHIDRA_HOME="/home/tommy/ghidra_11.2.1_PUBLIC"
SCRIPT="ExtractPcodeAndFunctionCalls.java"
SCRIPT_PATH="/home/tommy/Projects/cross-architecture/Experiment3/reverseScripts"
BASE_DIR="/home/tommy/Projects/cross-architecture/Experiment3"
DATA_DIR="/home/tommy/datasets/cross-architecture/data_20250407"
DATASET_CSV="/home/tommy/Projects/cross-architecture/datasets/csv/Cross-arch_Dataset_20250407154948.csv"

# Storage paths updated to new location
STORAGE_BASE_DIR="/home/tommy/datasets/cross-architecture"
RESULTS_DIR="$STORAGE_BASE_DIR/results"
LOGS_DIR="$STORAGE_BASE_DIR/logs"
TEMP_DIR="$STORAGE_BASE_DIR/temp_hash"
GHIDRA_TEMP="$STORAGE_BASE_DIR/ghidra_temp"

# Create temporary project directory in RAM
mkdir -p "$GHIDRA_TEMP"

# Time formatting function
format_time() {
    local seconds=$1
    printf "%02d:%02d:%02d" $((seconds/3600)) $(((seconds%3600)/60)) $((seconds%60))
}

# Default parameters
CORES=$(($(nproc) * 4))
TARGET_COUNT=0
declare -a CPU_LIST=()
declare -a FAMILY_LIST=()
BATCH_SIZE=10
ALL_FILES=false
MULTI_TARGET=true
TARGET_CPU=""
TARGET_FAMILY=""

# Function to display usage
show_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  all                 Process all files"
    echo "  cores=N             Use N cores for processing (default: all system cores)"
    echo "  cpu=ARCHITECTURE    Target specific CPU architecture (e.g., ARM, MIPS)"
    echo "  family=NAME         Target specific malware family"
    echo "  count=N             Number of unique results to collect"
    echo "  multi               Enable multi-target mode for processing multiple CPUs/families"
    echo "  cpus=ARCH1,ARCH2    Comma-separated list of CPU architectures to target"
    echo "  families=FAM1,FAM2  Comma-separated list of malware families to target"
    echo "  data=PATH           Custom data directory path (default: $DATA_DIR)"
    echo "  batch=N             Number of files to process in each batch (default: 10)"
    echo ""
    echo "Examples:"
    echo "  $0 cpu=ARM family=mirai count=10 cores=4"
    echo "  $0 multi cpus=ARM,MIPS families=mirai,hajime count=5 cores=4 batch=20"
}

# Parse command line parameters
for arg in "$@"; do
    case "$arg" in
        all)
            ALL_FILES=true ;;
        multi)
            MULTI_TARGET=true ;;
        cores=*)
            CORES=${arg#cores=} ;;
        cpu=*)
            TARGET_CPU=${arg#cpu=} ;;
        cpus=*)
            IFS=',' read -r -a CPU_LIST <<< "${arg#cpus=}" ;;
        family=*)
            TARGET_FAMILY=${arg#family=} ;;
        families=*)
            IFS=',' read -r -a FAMILY_LIST <<< "${arg#families=}" ;;
        count=*)
            TARGET_COUNT=${arg#count=} ;;
        data=*)
            DATA_DIR=${arg#data=}
            # Do not change RESULTS_DIR, now it stays in new storage location regardless of data dir 
            ;;
        batch=*)
            BATCH_SIZE=${arg#batch=} ;;
        help|--help)
            show_usage
            exit 0 ;;
        *)
            echo "Unknown option: $arg"
            show_usage
            exit 1 ;;
    esac
done

# If a specific CPU/family is provided but not in multi-target mode, add to lists
if [[ -n "$TARGET_CPU" && "$MULTI_TARGET" == true && ${#CPU_LIST[@]} -eq 0 ]]; then
    CPU_LIST=("$TARGET_CPU")
fi

if [[ -n "$TARGET_FAMILY" && "$MULTI_TARGET" == true && ${#FAMILY_LIST[@]} -eq 0 ]]; then
    FAMILY_LIST=("$TARGET_FAMILY")
fi

# Check and create necessary directories
mkdir -p "$RESULTS_DIR" "$LOGS_DIR" "$GHIDRA_TEMP" "$TEMP_DIR"

# Set up log file
LOG_FILE="$LOGS_DIR/batch_execution_$(date +%Y%m%d_%H%M%S).log"
echo "===== Batch Analysis Started $(date '+%Y-%m-%d %H:%M:%S') =====" > "$LOG_FILE"

# Hash cache
declare -A hash_cache

# Get FCG hash from JSON file
get_fcg_hash() {
    local file="$1"
    jq -r '.fcg_hash' "$file"
}

# Check result uniqueness function
is_unique_result() {
    local result_file="$1"
    local hash_dir="$2"
    local target_count="$3"
    
    mkdir -p "$hash_dir"
    
    # Get FCG hash from the result file
    local hash=$(get_fcg_hash "$result_file")
    
    # If hash is empty or null, fallback to old method
    if [[ -z "$hash" || "$hash" == "null" ]]; then
        echo "Warning: FCG hash not found in $result_file, falling back to old hash method"
        hash=$(jq '{pcode, function_calls}' "$result_file" | md5sum | awk '{print $1}')
    fi
    
    # Check memory cache
    if [[ -n "${hash_cache[$hash]}" ]]; then
        return 1
    fi
    
    # Check file system
    local hash_file="$hash_dir/$hash"
    if [[ -f "$hash_file" ]]; then
        hash_cache[$hash]="$result_file"
        return 1
    else
        echo "$result_file" > "$hash_file"
        hash_cache[$hash]="$result_file"
        return 0
    fi
}

# Process single file function
process_single_file() {
    local file_path="$1"
    local hash_dir="$2"
    local target_count="$3"
    
    # Check if target has been reached
    if [[ -f "$hash_dir/COMPLETE" ]]; then
        return 0
    fi
    
    # Extract file information
    local binary_name=$(basename "$file_path")
    local relative_path=${file_path#"$DATA_DIR/"}
    local relative_dir=$(dirname "$relative_path")
    
    # Set up result path
    local result_dir="$RESULTS_DIR/$relative_dir"
    mkdir -p "$result_dir"
    local result_file="$result_dir/${binary_name}.json"
    
    # Create project name and log file
    local project_name="Project_${binary_name}_$(date +%s)_$$"
    local process_log="$LOGS_DIR/${binary_name}_$(date +%s)_$$.log"
    
    # Run Ghidra analysis
    "$GHIDRA_HOME/support/analyzeHeadless" "$GHIDRA_TEMP" "$project_name" \
        -import "$file_path" \
        -postScript "$SCRIPT" "$result_file" \
        -scriptPath "$SCRIPT_PATH" > "$process_log" 2>&1
    
    # Clean up project
    if [[ -d "$GHIDRA_TEMP/$project_name" ]]; then
        rm -rf "$GHIDRA_TEMP/$project_name"
    fi
    
    # Check result and process uniqueness
    if [[ -f "$result_file" ]]; then
        if is_unique_result "$result_file" "$hash_dir" "$target_count"; then
            local unique_count=$(find "$hash_dir" -type f -not -name "COMPLETE" | wc -l)
            echo "Found unique result: $unique_count/$target_count File: $binary_name"
            
            if [[ $unique_count -ge $target_count ]]; then
                touch "$hash_dir/COMPLETE"
                echo "Target reached: $unique_count/$target_count"
            fi
        fi
    fi
}

# Batch process files function
process_file_batch() {
    local hash_dir="${@: -2:1}"
    local target_count="${@: -1:1}"
    local file_paths=("${@:1:$#-2}")
    
    echo "Starting batch processing of ${#file_paths[@]} files"
    
    # Export functions and variables
    export -f process_single_file is_unique_result get_fcg_hash
    export GHIDRA_HOME GHIDRA_TEMP SCRIPT_PATH SCRIPT DATA_DIR RESULTS_DIR LOGS_DIR
    
    # Use GNU Parallel for processing
    if command -v parallel &> /dev/null; then
        parallel --jobs $CORES --halt soon,fail=1 \
            "process_single_file {} \"$hash_dir\" \"$target_count\"" ::: "${file_paths[@]}"
    else
        # Basic parallel processing
        local running=0
        for file_path in "${file_paths[@]}"; do
            # Check if target has been reached
            if [[ -f "$hash_dir/COMPLETE" ]]; then
                break
            fi
            
            # Control number of parallel jobs
            while [[ $running -ge $CORES ]]; do
                sleep 0.5
                running=$(jobs -p | wc -l)
            done
            
            # Process file
            process_single_file "$file_path" "$hash_dir" "$target_count" &
            ((running++))
        done
        
        # Wait for all tasks to complete
        wait
    fi
    
    echo "Batch processing completed"
}

# Display summary of FCG hash distribution
display_hash_distribution() {
    local hash_dir="$1"
    
    echo "FCG Hash Distribution:"
    for hash_file in "$hash_dir"/*; do
        if [[ -f "$hash_file" && "$hash_file" != "$hash_dir/COMPLETE" ]]; then
            local hash=$(basename "$hash_file")
            local file=$(cat "$hash_file")
            local binary_name=$(basename "$file")
            echo "- $hash: $binary_name"
        fi
    done
}

# Get file list from CSV
get_files_from_csv() {
    local target_cpu="$1"
    local target_family="$2"
    
    awk -F, -v cpu="$target_cpu" -v family="$target_family" '
    NR > 1 {
        if ((cpu == "" || $2 == cpu) && (family == "" || $3 == family)) {
            print $1
        }
    }' "$DATASET_CSV"
}

# Multi-target processing main function
process_multi_targeted() {
    echo "Starting multi-target processing..."
    
    # Check CSV file exists
    if [[ ! -f "$DATASET_CSV" ]]; then
        echo "Error: Dataset CSV file does not exist: $DATASET_CSV"
        exit 1
    fi
    
    # Automatically detect CPU architectures and families
    if [[ ${#CPU_LIST[@]} -eq 0 ]]; then
        mapfile -t CPU_LIST < <(awk -F, 'NR > 1 {print $2}' "$DATASET_CSV" | sort -u)
        echo "Auto-detected CPU architectures: ${CPU_LIST[*]}"
    fi
    
    if [[ ${#FAMILY_LIST[@]} -eq 0 ]]; then
        mapfile -t FAMILY_LIST < <(awk -F, 'NR > 1 {print $3}' "$DATASET_CSV" | sort -u)
        echo "Auto-detected malware families: ${FAMILY_LIST[*]}"
    fi
    
    # Display configuration information
    echo "Configuration:"
    echo "- Data directory: $DATA_DIR"
    echo "- Storage base directory: $STORAGE_BASE_DIR"
    echo "- Results directory: $RESULTS_DIR"
    echo "- Logs directory: $LOGS_DIR"
    echo "- Temp directory: $TEMP_DIR"
    echo "- Ghidra temp directory: $GHIDRA_TEMP"
    echo "- Using $CORES cores for parallel processing"
    echo "- Batch size: $BATCH_SIZE files per batch"
    echo "- Target CPUs: ${CPU_LIST[*]}"
    echo "- Target families: ${FAMILY_LIST[*]}"
    echo "- Collecting $TARGET_COUNT unique results per combination"
    
    # Process each CPU-family combination
    local completed=0
    local combinations=$((${#CPU_LIST[@]} * ${#FAMILY_LIST[@]}))
    local overall_start_time=$(date +%s)
    
    for cpu in "${CPU_LIST[@]}"; do
        for family in "${FAMILY_LIST[@]}"; do
            ((completed++))
            local combo_start_time=$(date +%s)
            
            echo ""
            echo "===== Processing combination $completed/$combinations: CPU=$cpu, Family=$family ====="
            
            # Create combination-specific hash directory
            local combo_hash_dir="$TEMP_DIR/${cpu}_${family}"
            mkdir -p "$combo_hash_dir"
            rm -rf "$combo_hash_dir"/*
            
            # Calculate total number of files
            local filenames=($(get_files_from_csv "$cpu" "$family"))
            local total_files=${#filenames[@]}
            
            if [[ $total_files -eq 0 ]]; then
                echo "No files match combination: CPU=$cpu, Family=$family"
                continue
            fi
            
            echo "Found $total_files files for CPU=$cpu, Family=$family"
            
            # Check if target count exceeds available files
            local actual_target_count=$TARGET_COUNT
            if [[ $total_files -lt $TARGET_COUNT ]]; then
                echo "Warning: Only $total_files files available (less than target $TARGET_COUNT)"
                actual_target_count=$total_files
            fi
            
            # Batch process files
            local batch_files=()
            local batch_count=0
            
            for filename in "${filenames[@]}"; do
                # Check if target has been reached
                if [[ -f "$combo_hash_dir/COMPLETE" ]]; then
                    echo "Target count reached, stopping processing"
                    break
                fi
                
                # Find actual file path
                local file_path=$(find "$DATA_DIR" -name "$filename" -type f)
                
                if [[ -n "$file_path" ]]; then
                    batch_files+=("$file_path")
                    
                    # Process batch when enough files have been collected
                    if [[ ${#batch_files[@]} -ge $BATCH_SIZE ]]; then
                        ((batch_count++))
                        echo "Processing batch $batch_count with ${#batch_files[@]} files"
                        process_file_batch "${batch_files[@]}" "$combo_hash_dir" "$actual_target_count"
                        batch_files=()
                    fi
                else
                    echo "Warning: File not found in data directory: $filename"
                fi
            done
            
            # Process remaining files
            if [[ ${#batch_files[@]} -gt 0 ]]; then
                ((batch_count++))
                echo "Processing final batch $batch_count with ${#batch_files[@]} files"
                process_file_batch "${batch_files[@]}" "$combo_hash_dir" "$actual_target_count"
            fi
            
            # Collect statistics
            local unique_count=$(find "$combo_hash_dir" -type f -not -name "COMPLETE" | wc -l)
            local combo_end_time=$(date +%s)
            local combo_duration=$((combo_end_time - combo_start_time))
            
            echo "Completed processing combination CPU=$cpu, Family=$family in $(format_time $combo_duration). Collected $unique_count unique results"
            
            # Estimate overall progress
            local overall_elapsed=$((combo_end_time - overall_start_time))
            local avg_time_per_combo=$((overall_elapsed / completed))
            local remaining_combos=$((combinations - completed))
            local eta=$((avg_time_per_combo * remaining_combos))
            
            echo "Overall progress: $completed/$combinations combinations processed ($(printf "%.1f" $((completed * 100 / combinations)))%)"
            echo "Estimated time remaining: $(format_time $eta)"
            echo "-----------------------------------------------------------"
        done
    done
    
    # Display summary
    local overall_end_time=$(date +%s)
    local total_duration=$((overall_end_time - overall_start_time))
    echo "All combinations processed, total time $(format_time $total_duration)"
    
    echo ""
    echo "===== Multi-target Mode Summary ====="
    for combo_dir in "$TEMP_DIR"/*_*; do
        if [[ -d "$combo_dir" ]]; then
            dir_name=$(basename "$combo_dir")
            IFS='_' read -r cpu family <<< "$dir_name"
            unique_count=$(find "$combo_dir" -type f -not -name "COMPLETE" | wc -l)
            echo "CPU=$cpu, Family=$family: $unique_count unique results"
            
            # Display hash distribution if requested
            if [[ "$TARGET_COUNT" -le 10 ]]; then
                display_hash_distribution "$combo_dir"
            fi
        fi
    done
    
    # Generate summary of all FCG hashes
    echo ""
    echo "===== FCG Hash Analysis ====="
    echo "Creating FCG hash frequency report..."
    
    # Create a temporary file for hash frequency
    local hash_freq_file="$LOGS_DIR/fcg_hash_frequency_$(date +%Y%m%d_%H%M%S).txt"
    
    # Find all hashes and count frequencies
    find "$TEMP_DIR" -type f -not -name "COMPLETE" | while read hash_file; do
        basename "$hash_file"
    done | sort | uniq -c | sort -nr > "$hash_freq_file"
    
    # Display top 20 most common hashes
    echo "Top 20 most common FCG hashes:"
    head -n 20 "$hash_freq_file" | awk '{printf "%-32s: %d occurrences\n", $2, $1}'
    
    echo "Complete FCG hash frequency report saved to: $hash_freq_file"
}

# Execute main function
process_multi_targeted

echo "===== Batch Analysis Completed $(date '+%Y-%m-%d %H:%M:%S') ====="
echo "Analysis logs saved in: $LOG_FILE"
echo "Analysis results saved in: $RESULTS_DIR directory"