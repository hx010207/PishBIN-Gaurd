import tldextract
import re
import math
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List

# Core suspicious URL keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'secure', 'verify', 'update', 'bank', 'paypal', 'account',
    'password', 'reset', 'confirm', 'billing', 'auth', 'signin'
]

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    occurrences = {}
    for char in text:
        occurrences[char] = occurrences.get(char, 0) + 1
    
    for count in occurrences.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def analyze_url_local(url: str) -> Dict[str, Any]:
    """Perform extreme localized analysis of a URL."""
    score = 0
    indicators = []
    
    try:
        extracted = tldextract.extract(url)
        parsed = urlparse(url)
        domain = extracted.domain
        subdomain = extracted.subdomain
        suffix = extracted.suffix
        full_domain = f"{domain}.{suffix}"
        
        # 1. IP Address usage
        try:
            ipaddress.ip_address(domain)
            score += 40
            indicators.append("IP Address used in hostname")
        except ValueError:
            pass # Not an IP
            
        # 2. Punycode (IDN attacks)
        if 'xn--' in full_domain:
            score += 35
            indicators.append("Punycode (Homograph attack)")
            
        # 3. Excessive Subdomains
        sub_parts = subdomain.split('.') if subdomain else []
        if len(sub_parts) > 2:
            score += 20
            indicators.append(f"Excessive subdomains ({len(sub_parts)} levels)")
            
        # 4. Keyword matching
        lower_url = url.lower()
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
        if found_keywords:
            weight = len(found_keywords) * 10
            score += weight
            indicators.append(f"Suspicious keywords: {', '.join(found_keywords)}")
            
        # 5. Domain Length & Randomness
        if len(full_domain) > 40:
            score += 15
            indicators.append("Suspiciously long domain")
            
        entropy = calculate_entropy(full_domain)
        if entropy > 4.5:
            score += 15
            indicators.append(f"High domain entropy ({entropy:.2f})")
            
        # 6. Typosquatting check (Very basic brand list integration)
        brands = ["google", "microsoft", "apple", "amazon", "facebook", "paypal", "netflix"]
        for brand in brands:
            dist = levenshtein_distance(domain, brand)
            if dist == 1 or dist == 2:
                # E.g. g00gle.com
                score += 30
                indicators.append(f"Possible typosquatting of {brand}")
                
        # 7. WHOIS constraints (Offline wrapper - real implementation needs active network)
        # Note: python-whois is blocking and slow, ideally run in celery.
        # Here we mock it for the pure offline fast path analyzer.
        # In a real heavy analysis, this goes to Celery.
        
    except Exception as e:
        indicators.append(f"Parsing error: {str(e)}")
        score += 50 # Unparseable URLs are inherently suspicious

    return {
        "score": min(score, 100),
        "indicators": indicators,
        "entropy": round(entropy if 'entropy' in locals() else 0, 2)
    }
