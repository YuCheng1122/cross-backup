#!/usr/bin/env python3
import pandas as pd
import os
import sys

def analyze_malware_distribution(csv_path, output_file=None):
    """
    Analyze malware dataset to show distribution of labels across CPU architectures,
    with special focus on packed vs unpacked status.
    
    Parameters:
    csv_path (str): Path to the CSV file containing malware data
    output_file (str): Path to save the output as text file (optional)
    """
    # Check if file exists
    if not os.path.exists(csv_path):
        print(f"Error: File not found at '{csv_path}'")
        sys.exit(1)
        
    # Load the dataset
    try:
        df = pd.read_csv(csv_path)
        print(f"Successfully loaded dataset with {len(df)} samples")
    except Exception as e:
        print(f"Error loading CSV file: {e}")
        sys.exit(1)
    
    # Convert is_packed to boolean if it's not already
    if df['is_packed'].dtype == 'object':
        df['is_packed'] = df['is_packed'].map({'True': True, 'False': False})
    
    # Filter out "Unknown" CPUs and handle NaN values
    df_filtered = df.copy()
    # Fill NaN values in cpu column with "Unknown (NaN)"
    df_filtered['cpu'] = df_filtered['cpu'].fillna("Unknown (NaN)")
    # Now filter out Unknown CPUs
    df_filtered = df_filtered[~df_filtered['cpu'].str.contains('Unknown', na=False)]
    print(f"Filtered dataset: {len(df_filtered)} samples (removed {len(df) - len(df_filtered)} Unknown/NaN CPU samples)")
    
    # Get CPU sample counts for sorting
    cpu_counts = df_filtered['cpu'].value_counts().to_dict()
    
    # Distribution of labels per CPU architecture, separated by packed status
    distribution = {}
    
    for cpu in df_filtered['cpu'].unique():
        distribution[cpu] = {
            'packed': {}, 
            'unpacked': {},
            'total_samples': cpu_counts[cpu]  # Store total samples for sorting
        }
        
        # Get counts for unpacked samples
        unpacked_counts = df_filtered[(df_filtered['cpu'] == cpu) & (~df_filtered['is_packed'])]['label'].value_counts().to_dict()
        distribution[cpu]['unpacked'] = unpacked_counts
        
        # Get counts for packed samples
        packed_counts = df_filtered[(df_filtered['cpu'] == cpu) & (df_filtered['is_packed'])]['label'].value_counts().to_dict()
        distribution[cpu]['packed'] = packed_counts
    
    # Sort CPUs by total samples (file size)
    sorted_cpus = sorted(distribution.keys(), key=lambda x: distribution[x]['total_samples'], reverse=True)
    
    # Prepare output content
    output_content = []
    output_content.append("==== MALWARE LABEL DISTRIBUTION BY CPU (SORTED BY SAMPLE COUNT) ====\n")
    
    for cpu in sorted_cpus:
        status_data = distribution[cpu]
        unpacked_data = status_data['unpacked']
        packed_data = status_data['packed']
        total_samples = status_data['total_samples']
        
        # Combine unpacked and packed counts for this CPU
        all_labels = set(list(unpacked_data.keys()) + list(packed_data.keys()))
        
        # Format header for this CPU
        output_content.append(f"\n[{cpu}] - Total Samples: {total_samples}")
        output_content.append(f"{'Label':<15} {'Unpacked':<10} {'Packed':<10} {'Total':<10}")
        output_content.append("-" * 45)
        
        # Format counts for each label
        cpu_total = 0
        for label in sorted(all_labels):
            unpacked_count = unpacked_data.get(label, 0)
            packed_count = packed_data.get(label, 0)
            total = unpacked_count + packed_count
            cpu_total += total
            output_content.append(f"{label:<15} {unpacked_count:<10} {packed_count:<10} {total:<10}")
        
        # Format total for this CPU
        output_content.append("-" * 45)
        output_content.append(f"{'TOTAL':<15} {sum(unpacked_data.values()):<10} {sum(packed_data.values()):<10} {cpu_total:<10}")
    
    # Join all lines with newlines
    full_output = "\n".join(output_content)
    
    # Write to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            f.write(full_output)
        print(f"Results saved to {output_file}")
    
    # Print to console
    print(full_output)
    
    return distribution

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python data_distribution.py <path_to_csv_file> [output_txt_file]")
        print("Example: python data_distribution.py /home/tommy/cross-architecture/202503_Malware.csv results.txt")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else None
    
    # Analyze the malware distribution and save to text file
    analyze_malware_distribution(csv_path, output_file)