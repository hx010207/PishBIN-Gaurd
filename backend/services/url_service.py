import tldextract
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

def analyze_url_heuristics(url: str) -> Dict:
    """Complete phishing URL analysis with all PRD requirements"""
    score = 0
    indicators = []
    
    # 1. TLD extraction for precise domain parsing
    try:
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
        domain = extracted.domain
        suffix = extracted.suffix
        full_domain = f"{domain}.{suffix}"
    except:
        full_domain = urlparse(url).netloc or ""
        subdomain = ""
    
    # 2. Punycode Homograph Detection (xn-- prefix)
    if 'xn--' in full_domain:
        score += 35
        indicators.append("🚨 PUNYCODE HOMOGRAPH - Potential IDN attack")
    
    # 3. Excessive Subdomain Depth (>3 levels)
    subdomain_parts = subdomain.split('.') if subdomain else []
    if len(subdomain_parts) > 2:
        score += 25
        indicators.append(f"🔍 Excessive subdomains: {len(subdomain_parts)} levels")
    
    # 4. User-info @ symbol abuse (http://user:pass@evil.com)
    parsed = urlparse(url)
    if '@' in parsed.netloc:
        score += 30
        indicators.append("🚨 USER-INFO ABUSE - @ symbol in authority")
    
    # 5. Domain length & digit ratio
    domain_len = len(full_domain)
    digit_count = sum(1 for c in full_domain if c.isdigit())
    digit_ratio = digit_count / domain_len if domain_len > 0 else 0
    
    if domain_len > 45:
        score += 15
        indicators.append(f"📏 Suspicious domain length: {domain_len}")
    if digit_ratio > 0.25:
        score += 12
        indicators.append(f"🔢 High digit ratio: {digit_ratio:.1%}")
    
    # 6. Suspicious keywords in path/domain
    suspicious_keywords = [
        'login', 'secure', 'verify', 'update', 'bank', 'paypal', 
        'account', 'password', 'reset', 'confirm', 'billing'
    ]
    url_lower = url.lower()
    found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
    if found_keywords:
        score += 10 * len(found_keywords)
        indicators.append(f"⚠️ Suspicious keywords: {', '.join(found_keywords)}")
    
    # 7. IP Address instead of domain
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ip_pattern, full_domain.split(':')[0]):
        score += 40
        indicators.append("🌐 IP ADDRESS - Direct IP usage")
    
    # 8. Risk classification
    if score >= 70:
        risk_level = "CRITICAL"
        recommendation = "🚫 IMMEDIATE BLOCK - Confirmed phishing"
    elif score >= 45:
        risk_level = "HIGH"
        recommendation = "⚠️ HIGH RISK - Manual review required"
    elif score >= 25:
        risk_level = "MEDIUM"
        recommendation = "🔍 Monitor - Suspicious indicators"
    else:
        risk_level = "LOW"
        recommendation = "✅ Likely safe"
    
    return {
        "url": url,
        "score": min(score, 100),
        "risk": risk_level, # Mapping risk_level to risk for compatibility
        "risk_level": risk_level,
        "recommendation": recommendation,
        "indicators": indicators,
        "domain_info": {
            "subdomain": subdomain,
            "domain": full_domain,
            "is_punycode": 'xn--' in full_domain
        }
    }
