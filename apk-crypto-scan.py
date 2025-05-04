import subprocess
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from termcolor import colored

def decompile_apk(apk_path, output_dir):
    """
    Decompiles the APK using APKTool and stores the result in output_dir.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    command = [r'apktool.bat', 'd', apk_path, '-o', output_dir, '-f']
    subprocess.run(command, check=True)
    print(colored(f"🔵 Decompiled APK is saved to {output_dir}", "cyan"))

def search_file_for_cryptography_issues(file_path, weak_patterns):
    """
    Search a single file for cryptographic issues.
    Returns a dictionary with issues found in the file.
    """
    issues_in_file = {}

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

        for issue, pattern in weak_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                if issue not in issues_in_file:
                    issues_in_file[issue] = []
                issues_in_file[issue].append(file_path)

    return issues_in_file

def detect_hardcoded_keys(file_path, hex_pattern, b64_pattern):
    """
    Detect long random-looking strings that might be cryptographic keys
    and check if they are used in crypto contexts (±20 lines).
    """
    issues_in_file = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
        # Find hex and base64 patterns
        hex_matches = re.findall(hex_pattern, content)
        b64_matches = re.findall(b64_pattern, content)
        
        # Combine all matches
        all_matches = hex_matches + b64_matches
        
        for match in all_matches:
            # Get surrounding context ±20 lines
            start_index = max(0, content.find(match) - 500)
            end_index = content.find(match) + len(match) + 500
            context = content[start_index:end_index]
            
            # Check if the match appears in a cryptographic context
            if re.search(r'SecretKeySpec|Cipher|MessageDigest|KeyGenerator|Mac|SecureRandom', context):
                issues_in_file.append((file_path, match, context.strip()))

    return issues_in_file

def search_weak_cryptography(code_dir):
    """
    Searches for weak cryptographic practices in the decompiled Java and smali code.
    Uses parallel scanning for efficiency.
    """
    weak_patterns = {
        'MD5 (Java)': r'MessageDigest\.getInstance\("MD5"\)',
        'SHA-1 (Java)': r'MessageDigest\.getInstance\("SHA-1"\)',
        'RC4 (Java)': r'Cipher\.getInstance\("RC4"\)',
        'DES (Java)': r'Cipher\.getInstance\("DES"\)',
        'AES/ECB (Java)': r'Cipher\.getInstance\("AES/ECB/PKCS5Padding"\)',

        # Smali patterns
        'MD5 (smali)': r'const-string [vp]\d+, "MD5"',
        'SHA-1 (smali)': r'const-string [vp]\d+, "SHA-1"',
        'RC4 (smali)': r'const-string [vp]\d+, "RC4"',
        'DES (smali)': r'const-string [vp]\d+, "DES"',
        'AES/ECB (smali)': r'const-string [vp]\d+, "AES/ECB/PKCS5Padding"',
    }

    issues = {}

    # Gather all files to be checked
    files_to_check = []
    for root, _, files in os.walk(code_dir):
        for file in files:
            if file.endswith('.java') or file.endswith('.smali'):
                files_to_check.append(os.path.join(root, file))

    # Use ThreadPoolExecutor to parallelize file checks
    with ThreadPoolExecutor() as executor:
        # Using tqdm to show progress for file scanning
        results = list(tqdm(executor.map(lambda file: search_file_for_cryptography_issues(file, weak_patterns), files_to_check), total=len(files_to_check), desc=colored("Scanning files for weak cryptography", "yellow")))
    
    # Detect hardcoded keys
    hex_pattern = r'["\']([a-fA-F0-9]{16,32})["\']'  # Hex strings of 16-32 characters
    b64_pattern = r'["\']([A-Za-z0-9+/]{24,})["\']'  # Base64 strings of 24+ characters
    key_issues = []
    
    with ThreadPoolExecutor() as executor:
        # Using tqdm to show progress for key scanning
        key_results = list(tqdm(executor.map(lambda file: detect_hardcoded_keys(file, hex_pattern, b64_pattern), files_to_check), total=len(files_to_check), desc=colored("Scanning for hardcoded keys", "yellow")))
    
    # Combine the results
    for result in results:
        for issue, file_paths in result.items():
            if issue not in issues:
                issues[issue] = []
            issues[issue].extend(file_paths)
    
    # Add hardcoded key issues
    for key_result in key_results:
        key_issues.extend(key_result)

    # Return combined results
    return issues, key_issues

def print_issues(issues, key_issues):
    """
    Prints out the found issues related to weak cryptography and hardcoded keys in colored output.
    """
    if issues:
        print(colored("\n🟡 Weak Cryptography Issues Found:", "yellow"))
        for issue, files in issues.items():
            print(colored(f"\n{issue}:", "cyan"))
            for file in set(files):  # remove duplicate file entries
                print(colored(f"  🔴 {file}", "red"))

    if key_issues:
        print(colored("\n🟡 Potential Hardcoded Keys Found:", "yellow"))
        for file_path, key, context in key_issues:
            print(colored(f"\nHardcoded Key in {file_path}:", "red"))
            print(colored(f"  Key: {key}", "cyan"))
            print(colored(f"  Context: {context[:200]}...", "green"))  # print first 200 chars for context

    if not issues and not key_issues:
        print(colored("\n🟢 No weak cryptography or hardcoded keys found.", "green"))

def main(apk_path):
    """
    Main function that takes APK file path and analyzes it for weak cryptography and hardcoded keys.
    """
    if not os.path.exists(apk_path):
        print(colored(f"Error: {apk_path} does not exist.", "red"))
        sys.exit(1)

    # Output directory for decompiled code
    output_dir = 'decompiled_apk'

    # Step 1: Decompile APK using APKTool
    decompile_apk(apk_path, output_dir)

    # Step 2: Search for weak cryptographic practices and hardcoded keys
    issues, key_issues = search_weak_cryptography(output_dir)

    # Step 3: Print issues found
    print_issues(issues, key_issues)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(colored("Usage: python check_cryptography.py <apk_file_path>", "yellow"))
        sys.exit(1)

    apk_file_path = sys.argv[1]
    main(apk_file_path)
