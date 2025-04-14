#!/usr/bin/env python3
import os
import json
import csv
import subprocess
import tempfile
import sys
from multiprocessing import Pool, cpu_count
from tqdm import tqdm

def run_avclass(report_data):
    """Run AVClass on report data and return the family name."""
    try:
        # Create temporary file for the report
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            json.dump(report_data, tmp)
            tmp_path = tmp.name
        
        # Run AVClass on the temp file
        result = subprocess.run(
            ['avclass', '-f', tmp_path],
            capture_output=True,
            text=True
        )
        
        # Delete temporary file
        os.unlink(tmp_path)
        
        # Parse AVClass output (format: hash family)
        output = result.stdout.strip()
        if output and len(output.split()) > 1:
            family = output.split()[-1]
            # Check if it's a SINGLETON result
            if family.startswith("SINGLETON:"):
                return "<unknown>"
            return family
        return "<unknown>"
    except Exception as e:
        print(f"Error running AVClass: {e}")
        return "<unknown>"

def identify_cpu(data):
    """Identify CPU architecture from report data."""
    # Get all potential sources of CPU information
    gandelf = data.get('additional_info', {}).get('gandelf', {})
    exiftool = data.get('additional_info', {}).get('exiftool', {})
    magic = data.get('additional_info', {}).get('magic', '')
    
    # Extract CPU information from gandelf
    header = gandelf.get('header', {}) if gandelf else {}
    machine = header.get('machine', '')
    cpu_class = header.get('class', '')
    
    # Check if machine is valid and not unknown
    if machine and machine != '<unknown>':
        # Check for AMD architecture first
        if 'AMD' in machine and ('x86-64' in machine or 'x86_64' in machine):
            return "Advanced Micro Devices x86-64"
        # Check if architecture already includes bit information
        if any(x in machine.lower() for x in ['64', 'x86_64', 'amd64', 'aarch64']):
            return clean_arch_name(machine)
        
        # Apply bit information based on CPU class
        if 'ARM' in machine:
            return "ARM-64" if 'ELF64' in cpu_class else "ARM-32"
        elif 'MIPS' in machine:
            return "MIPS R3000-64" if 'ELF64' in cpu_class else "MIPS R3000-32"
        elif machine == 'Intel 80386':
            return "Intel i386-32"
        elif 'AMD' in machine and ('x86-64' in machine or 'x86_64' in machine):
            return "Advanced Micro Devices x86-64"
        elif 'x86' in machine or 'Intel' in machine:
            return "x86-64" if 'ELF64' in cpu_class else "x86-32"
        else:
            # For other architectures
            if 'ELF64' in cpu_class:
                return f"{machine}-64"
            elif 'ELF32' in cpu_class:
                return f"{machine}-32"
            else:
                return machine
    
    # If machine is unknown or empty, check exiftool
    cpu_type = exiftool.get('CPUType', '')
    if cpu_type and not cpu_type.startswith('Unknown'):
        arch = exiftool.get('CPUArchitecture', '')
        
        # Handle specific architectures
        if 'SuperH' in cpu_type or 'SH' in cpu_type:
            if '64' in arch:
                return "SuperH-64"
            elif '32' in arch:
                return "SuperH-32"
            else:
                return "SuperH"
        
        # Handle i386 CPU type specifically
        if cpu_type.lower() == 'i386':
            return "Intel i386-32"
            
        # Handle AMD x86-64 CPU type
        if 'amd' in cpu_type.lower() and 'x86' in cpu_type.lower():
            return "Advanced Micro Devices x86-64"
        
        # Handle SPARC CPU type
        if cpu_type.lower() == 'sparc' or 'sparc' in cpu_type.lower():
            if '32' in arch:
                return "Sparc-32"
            elif '64' in arch:
                return "Sparc-64"
            else:
                return "Sparc"
        
        # Handle generic architectures with bit information
        if '64' in arch:
            return f"{cpu_type}-64"
        elif '32' in arch:
            return f"{cpu_type}-32"
        else:
            return cpu_type
    
    # If exiftool doesn't have CPU info, check magic field
    if magic:
        # Check for specific architectures in magic string
        arch_patterns = [
            ('Renesas SH', 'SuperH'),
            ('SuperH', 'SuperH'),
            ('ARCompact', 'ARCompact'),
            ('ARC700', 'ARCompact'),
            ('ARM', 'ARM'),
            ('MIPS', 'MIPS R3000'),
            ('x86-64', 'x86-64'),
            ('x86_64', 'x86-64'),
            ('Intel 80386', 'Intel i386-32'),
            ('SPARC', 'Sparc')
        ]
        
        for pattern, arch_name in arch_patterns:
            if pattern in magic:
                # Determine bit width
                if '64-bit' in magic:
                    # Don't add redundant -64 for architectures that already include it
                    return arch_name if arch_name == 'x86-64' else f"{arch_name}-64"
                elif '32-bit' in magic:
                    return f"{arch_name}-32"
                else:
                    return arch_name
    
    # If still unknown, use CPU class if available
    if cpu_class:
        if 'ELF64' in cpu_class:
            return "<unknown>-64"
        elif 'ELF32' in cpu_class:
            return "<unknown>-32"
    
    return "<unknown>"

def clean_arch_name(arch_str):
    """Clean architecture names to avoid redundant bit information."""
    lower_arch = arch_str.lower()
    
    # Handle specific cases that already include bit information
    if 'aarch64' in lower_arch:
        return "AArch64"
    elif 'advanced micro devices x86-64' in lower_arch:
        return "Advanced Micro Devices x86-64"  # Keep the full name
    elif 'amd' in lower_arch and ('x86-64' in lower_arch or 'x86_64' in lower_arch):
        return "Advanced Micro Devices x86-64"
    elif 'x86_64' in lower_arch or 'x86-64' in lower_arch:
        return "x86-64"
    elif 'amd64' in lower_arch:
        return "AMD64"
    elif 'i386' in lower_arch:
        return "Intel i386-32"
    elif 'sparc' in lower_arch:
        if '32' in lower_arch:
            return "Sparc-32"
    
    # Return the original string for other cases
    return arch_str

def determine_if_packed(data):
    """Determine if file is packed."""
    # Check gandelf packers
    gandelf = data.get('additional_info', {}).get('gandelf', {})
    if gandelf and gandelf.get('packers'):
        return True
    
    # Check tags
    tags = data.get('tags', [])
    if 'upx' in tags or 'packed' in tags:
        return True
    
    return False

def process_file(json_file):
    """Process a single JSON file and extract required information."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Get file name/hash
        resource = data.get('resource', '<unknown>')
        
        # Get CPU architecture
        cpu = identify_cpu(data)
        
        # Check if packed
        is_packed = determine_if_packed(data)
        
        # Get family from AVClass
        family = run_avclass(data)
        
        return {
            'file_name': resource,
            'cpu': cpu,
            'label': family,
            'is_packed': is_packed
        }
    except Exception as e:
        print(f"Error processing {json_file}: {e}")
        return None

def main():
    if len(sys.argv) < 3:
        print("Usage: python script.py <reports_dir> <output_csv> [max_files]")
        sys.exit(1)
    
    reports_dir = sys.argv[1]
    output_csv = sys.argv[2]
    
    # Optional parameter to limit the number of files processed
    max_files = None
    if len(sys.argv) > 3:
        try:
            max_files = int(sys.argv[3])
        except ValueError:
            print("max_files must be an integer")
            sys.exit(1)
    
    # Find all JSON files
    json_files = []
    for root, _, files in os.walk(reports_dir):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))
    
    # Limit the number of files if specified
    if max_files is not None and max_files < len(json_files):
        print(f"Limiting to {max_files} files out of {len(json_files)} found")
        json_files = json_files[:max_files]
    else:
        print(f"Found {len(json_files)} JSON files to process")
    
    # Process files in parallel with progress bar
    num_cores = cpu_count()
    print(f"Using {num_cores} CPU cores for processing")
    
    results = []
    with Pool(processes=num_cores) as pool:
        for result in tqdm(pool.imap_unordered(process_file, json_files), total=len(json_files)):
            if result:
                results.append(result)
    
    # Write results to CSV
    if results:
        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['file_name', 'cpu', 'label', 'is_packed'])
            writer.writeheader()
            writer.writerows(results)
        
        print(f"Results written to {output_csv}")
        print(f"Processed {len(results)} files successfully")
    else:
        print("No results to write")

if __name__ == "__main__":
    main()
