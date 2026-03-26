import pefile
import re
import math
from typing import Dict, List

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

def extract_strings(data: bytes, min_length: int = 4) -> list:
    ascii_strings = re.findall(b'[\x20-\x7e]{' + str(min_length).encode() + b',}', data)
    unicode_strings = re.findall(b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}', data)
    
    combined = [s.decode('ascii', errors='ignore') for s in ascii_strings] + \
               [s.decode('utf-16le', errors='ignore') for s in unicode_strings]
    return list(set(combined))

def analyze_binary(file_content: bytes, filename: str) -> Dict:
    """Complete PE binary analysis with import/export extraction adapted for raw content"""
    indicators = []
    score = 0
    
    # Basic info
    entropy = calculate_entropy(file_content)
    strings = extract_strings(file_content)
    
    try:
        pe = pefile.PE(data=file_content)
        
        # 1. Extract and analyze imports
        suspicious_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors='ignore').lower() if entry.dll else "unknown"
                for import_entry in entry.imports:
                    if import_entry.name:
                        func_name = import_entry.name.decode(errors='ignore').lower()
                        
                        # High-risk APIs
                        high_risk = [
                            'createprocess', 'win_exec', 'shell_execute',
                            'net_user', 'reg_add', 'create_remotethread',
                            'virtual_alloc_ex', 'write_process_memory'
                        ]
                        
                        if any(api in func_name for api in high_risk):
                            score += 25
                            suspicious_imports.append(f"🚨 {dll_name}!{func_name}")
        
        # 2. Suspicious DLLs
        suspicious_dlls = ['urlmon.dll', 'wininet.dll', 'mshtml.dll']
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore').lower() if entry.dll else ""
                if any(susp_dll in dll for susp_dll in suspicious_dlls):
                    score += 15
                    indicators.append(f"📦 Suspicious DLL: {dll}")
        
        # 3. Exports analysis (droppers often export nothing)
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') or not pe.DIRECTORY_ENTRY_EXPORT:
            indicators.append("📤 No exports - Possible dropper pattern")
            score += 10
            
        file_info = {
            "machine_type": hex(pe.FILE_HEADER.Machine),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "file_type": "PE Binary"
        }
        total_imports = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0

    except Exception as e:
        indicators.append(f"⚠️ PE Analysis Error: {str(e)}")
        file_info = {"file_type": "Unknown/Non-PE"}
        suspicious_imports = []
        total_imports = 0

    # 4. Risk classification
    risk_level = "LOW"
    if score >= 70:
        risk_level = "CRITICAL - Confirmed malware patterns"
    elif score >= 40:
        risk_level = "HIGH - Suspicious behavior"
    elif score >= 20:
        risk_level = "MEDIUM - Review required"
    
    # URL extraction from strings
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    extracted_urls = set()
    for s in strings:
        found_urls = url_pattern.findall(s)
        for url in found_urls:
            extracted_urls.add(url)

    return {
        "filename": filename,
        "score": min(score, 100),
        "risk_level": risk_level,
        "suspicious_imports": suspicious_imports,
        "indicators": indicators,
        "total_imports": total_imports,
        "entropy": round(entropy, 2),
        "strings": list(set(list(extracted_urls)[:50])), # Cap URLs in strings
        "urls": list(extracted_urls),
        "file_info": file_info
    }
