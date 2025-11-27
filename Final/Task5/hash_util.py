import hashlib
import json
import os
import sys
from datetime import datetime

def compute_hashes(file_path):
    """Compute SHA-256, SHA-1, and MD5 hashes of a file"""
    hashes = {
        'sha256': '',
        'sha1': '',
        'md5': ''
    }
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            
        hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
        hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
        hashes['md5'] = hashlib.md5(file_data).hexdigest()
        
        return hashes
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def save_hashes_to_json(hashes, filename, json_file='hashes.json'):
    """Save computed hashes to a JSON file"""
    hash_data = {
        'filename': filename,
        'timestamp': datetime.now().isoformat(),
        'hashes': hashes
    }
    
    # Load existing data if file exists
    existing_data = []
    if os.path.exists(json_file):
        try:
            with open(json_file, 'r') as f:
                existing_data = json.load(f)
                if not isinstance(existing_data, list):
                    existing_data = [existing_data]
        except json.JSONDecodeError:
            existing_data = []
    
    # Add new hash entry
    existing_data.append(hash_data)
    
    # Save back to file
    with open(json_file, 'w') as f:
        json.dump(existing_data, f, indent=2)
    
    print(f"Hashes saved to {json_file}")
    return hash_data

def verify_integrity(file_path, json_file='hashes.json'):
    """Verify file integrity by comparing with stored hashes"""
    if not os.path.exists(json_file):
        print(f"Error: Hash database '{json_file}' not found.")
        return False
    
    # Compute current hashes
    current_hashes = compute_hashes(file_path)
    if not current_hashes:
        return False
    
    # Load stored hashes
    try:
        with open(json_file, 'r') as f:
            stored_data = json.load(f)
            if not isinstance(stored_data, list):
                stored_data = [stored_data]
    except (json.JSONDecodeError, FileNotFoundError):
        print(f"Error: Could not read hash database '{json_file}'.")
        return False
    
    # Find matching entries for this file
    filename = os.path.basename(file_path)
    matches = []
    
    for entry in stored_data:
        if entry.get('filename') == filename:
            matches.append(entry)
    
    if not matches:
        print(f"No stored hash found for '{filename}'")
        return False
    
    # Use the most recent entry
    latest_entry = max(matches, key=lambda x: x.get('timestamp', ''))
    stored_hashes = latest_entry.get('hashes', {})
    
    print(f"\n{'='*60}")
    print(f"INTEGRITY CHECK: {filename}")
    print(f"{'='*60}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Stored from: {latest_entry.get('timestamp', 'Unknown')}")
    print(f"{'-'*60}")
    
    # Compare each hash type
    all_match = True
    results = {}
    
    for hash_type in ['sha256', 'sha1', 'md5']:
        current_hash = current_hashes.get(hash_type, '')
        stored_hash = stored_hashes.get(hash_type, '')
        
        match = current_hash == stored_hash
        results[hash_type] = {
            'match': match,
            'current': current_hash,
            'stored': stored_hash
        }
        
        status = "✓ PASS" if match else "✗ FAIL"
        print(f"{hash_type.upper():<8}: {status}")
        
        if not match:
            all_match = False
            print(f"          Current:  {current_hash}")
            print(f"          Stored:   {stored_hash}")
    
    print(f"{'-'*60}")
    
    if all_match:
        print("🎉 INTEGRITY CHECK: PASSED - File is authentic and unchanged")
        return True
    else:
        print("🚨 INTEGRITY CHECK: FAILED - File has been modified or corrupted!")
        print("\nWARNING: The file has been tampered with or corrupted!")
        print("This could indicate:")
        print("  - Malicious modification")
        print("  - Data corruption during transfer")
        print("  - Unauthorized changes")
        return False

def create_sample_files():
    """Create original and tampered sample files for demonstration"""
    # Create original file
    original_content = """This is an important company document.
Contains confidential information about Project Phoenix.

Project Details:
- Start Date: 2024-01-15
- Team: 5 members
- Budget: $150,000
- Status: In Progress

Key Objectives:
1. Develop new encryption protocol
2. Implement secure communication
3. Test and validate security measures

This document should not be modified without authorization.
"""
    
    with open('original.txt', 'w') as f:
        f.write(original_content)
    
    # Create tampered file
    tampered_content = """This is an important company document.
Contains confidential information about Project Phoenix.

Project Details:
- Start Date: 2024-01-15
- Team: 8 members  # TAMPERED: Changed from 5 to 8
- Budget: $250,000  # TAMPERED: Increased budget
- Status: Completed  # TAMPERED: Changed status

Key Objectives:
1. Develop new encryption protocol
2. Implement secure communication
3. Test and validate security measures
4. ADDED: Deploy to production  # TAMPERED: Added objective

SECURITY BREACH: This file has been modified by unauthorized personnel!
"""
    
    with open('tampered.txt', 'w') as f:
        f.write(tampered_content)
    
    print("Sample files created:")
    print("  - original.txt (authentic file)")
    print("  - tampered.txt (modified file)")

def display_menu():
    """Display the main menu"""
    print("\n" + "="*60)
    print("🔐 HASHING & INTEGRITY CHECK UTILITY")
    print("="*60)
    print("1. Compute hashes for a file and store in database")
    print("2. Verify file integrity against stored hashes")
    print("3. Create sample files (original.txt and tampered.txt)")
    print("4. Run complete demonstration")
    print("5. Exit")
    print("-"*60)

def main():
    """Main function"""
    if len(sys.argv) > 1:
        # Command line mode
        if sys.argv[1] == 'compute':
            if len(sys.argv) > 2:
                hashes = compute_hashes(sys.argv[2])
                if hashes:
                    save_hashes_to_json(hashes, sys.argv[2])
                    print(f"\nHashes for {sys.argv[2]}:")
                    for hash_type, hash_value in hashes.items():
                        print(f"  {hash_type.upper()}: {hash_value}")
            else:
                print("Usage: python hash_util.py compute <filename>")
        
        elif sys.argv[1] == 'verify':
            if len(sys.argv) > 2:
                verify_integrity(sys.argv[2])
            else:
                print("Usage: python hash_util.py verify <filename>")
        
        elif sys.argv[1] == 'demo':
            run_demonstration()
        
        else:
            print("Usage: python hash_util.py [compute|verify|demo] <filename>")
    
    else:
        # Interactive mode
        while True:
            display_menu()
            choice = input("Select option (1-5): ").strip()
            
            if choice == '1':
                filename = input("Enter filename to hash: ").strip()
                if filename:
                    hashes = compute_hashes(filename)
                    if hashes:
                        save_hashes_to_json(hashes, filename)
                        print(f"\nComputed hashes for {filename}:")
                        for hash_type, hash_value in hashes.items():
                            print(f"  {hash_type.upper()}: {hash_value}")
                else:
                    print("No filename provided.")
            
            elif choice == '2':
                filename = input("Enter filename to verify: ").strip()
                if filename:
                    verify_integrity(filename)
                else:
                    print("No filename provided.")
            
            elif choice == '3':
                create_sample_files()
            
            elif choice == '4':
                run_demonstration()
            
            elif choice == '5':
                print("Goodbye!")
                break
            
            else:
                print("Invalid choice. Please select 1-5.")

def run_demonstration():
    """Run a complete demonstration of the utility"""
    print("\n" + "="*60)
    print("🚀 RUNNING COMPLETE DEMONSTRATION")
    print("="*60)
    
    # Step 1: Create sample files
    print("\n📝 STEP 1: Creating sample files...")
    create_sample_files()
    
    # Step 2: Compute and store hashes for original file
    print("\n🔍 STEP 2: Computing hashes for original.txt...")
    hashes = compute_hashes('original.txt')
    if hashes:
        save_hashes_to_json(hashes, 'original.txt')
        print("Original file hashes:")
        for hash_type, hash_value in hashes.items():
            print(f"  {hash_type.upper()}: {hash_value}")
    
    # Step 3: Verify original file (should pass)
    print("\n✅ STEP 3: Verifying original file (should PASS)...")
    verify_integrity('original.txt')
    
    # Step 4: Verify tampered file (should fail)
    print("\n❌ STEP 4: Verifying tampered file (should FAIL)...")
    verify_integrity('tampered.txt')
    
    # Step 5: Show file differences
    print("\n📊 STEP 5: File Comparison Summary")
    print("-"*40)
    original_size = os.path.getsize('original.txt')
    tampered_size = os.path.getsize('tampered.txt')
    print(f"Original file size: {original_size} bytes")
    print(f"Tampered file size: {tampered_size} bytes")
    print(f"Size difference: {abs(original_size - tampered_size)} bytes")
    
    print("\n" + "="*60)
    print("🎯 DEMONSTRATION COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()