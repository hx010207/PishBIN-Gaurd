import pefile
import math
import re
from typing import Dict, Any, List
# import yara # Yara usage requires compiling rules, placeholder for now

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    
    for count in occurrences:
        if count == 0:
            continue
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    ascii_strings = re.findall(b'[\x20-\x7e]{' + str(min_length).encode() + b',}', data)
    unicode_strings = re.findall(b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}', data)
    
    combined = [s.decode('ascii', errors='ignore') for s in ascii_strings] + \
               [s.decode('utf-16le', errors='ignore') for s in unicode_strings]
    return list(set(combined))

def analyze_pe_local(file_content: bytes) -> Dict[str, Any]:
    """Perform localized static analysis of a PE file."""
    score = 0
    indicators = []
    suspicious_imports = []
    
    entropy_val = calculate_entropy(file_content)
    if entropy_val > 7.2:
        score += 30
        indicators.append(f"High Shannon Entropy ({entropy_val:.2f}) - packed/encrypted")
        
    strings = extract_strings(file_content)
    
    try:
        pe = pefile.PE(data=file_content)
        
        # Import Analysis
        high_risk_apis = {
            'createprocess', 'win_exec', 'shell_execute', 'virtual_alloc_ex',
            'write_process_memory', 'create_remotethread', 'get_thread_context',
            'set_thread_context', 'resume_thread', 'get_proc_address', 'load_library'
        }
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore').lower() if entry.dll else "unknown"
                for imp in entry.imports:
                    if imp.name:
                        func = imp.name.decode(errors='ignore').lower()
                        if any(api in func for api in high_risk_apis):
                            score += 15
                            suspicious_imports.append(f"{dll}!{func}")
                            
        # Section Analysis
        for section in pe.sections:
            sec_entropy = section.get_entropy()
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if sec_entropy > 7.5:
                score += 10
                indicators.append(f"Section {name} is highly obfuscated ({sec_entropy:.2f})")
                
        # Exports
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') or not pe.DIRECTORY_ENTRY_EXPORT:
            score += 10
            indicators.append("No exports (common in droppers/malware)")
            
    except Exception as e:
        indicators.append(f"PE Parsing Failed: {str(e)}")
        # Not a valid PE or corrupted, could be malicious or just a random file
        score += 10

    # Basic string hunting (IPs, URls, Commands)
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    url_pattern = re.compile(r'http[s]?://[^\s<>"]+|www\.[^\s<>"]+')
    
    ips = set()
    urls = set()
    for s in strings:
        ips.update(ip_pattern.findall(s))
        urls.update(url_pattern.findall(s))
        
    if ips:
        score += 10
        indicators.append(f"Embedded IP addresses found ({len(ips)})")
        
    # Check for obvious malware strings
    malicious_keywords = ["mimikatz", "meterpreter", "cobaltstrike", "shellcode", "inject"]
    found_malicious = [kw for kw in malicious_keywords if any(kw in s.lower() for s in strings)]
    if found_malicious:
        score += 40
        indicators.append(f"Malicious strings detected: {', '.join(found_malicious)}")
        
    return {
        "score": min(score, 100),
        "indicators": indicators,
        "suspicious_imports": suspicious_imports[:50], # Cap
        "embedded_ips": list(ips),
        "embedded_urls": list(urls)[:50]
    }
