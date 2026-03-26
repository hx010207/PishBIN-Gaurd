from typing import Dict, Any, List

def calculate_ultimate_score(local_score: float, api_results: List[Dict[str, Any]], behavior_score: float = 0, reputation_score: float = 0) -> Dict[str, Any]:
    """
    Adaptive scoring algorithm.
    When external APIs are configured:   Final = 0.4*Local + 0.3*API + 0.2*Rep + 0.1*Behavior
    When no APIs are available (demo):   Final = Local score directly (100% weight)
    This prevents good local heuristics from being diluted to zero by missing API keys.
    """

    # 1. Separate valid API results from error/missing-config responses
    valid_api_results = [
        res for res in api_results
        if 'score' in res and 'error' not in res
    ]
    api_scores = [res['score'] for res in valid_api_results]

    apis_available = len(api_scores) > 0

    # 2. Calculate API Consensus (avg of top 2 hits to avoid dilution)
    consensus = 0
    if apis_available:
        sorted_scores = sorted(api_scores, reverse=True)
        top_scores = sorted_scores[:2]
        consensus = sum(top_scores) / len(top_scores)

    # 3. Adaptive weighting
    if apis_available:
        # Full formula when we have real external API data
        final_score = (
            (0.4 * local_score) +
            (0.3 * consensus) +
            (0.2 * reputation_score) +
            (0.1 * behavior_score)
        )
    else:
        # No external APIs configured — trust local heuristics 100%
        # Still blend in behavior/reputation if they're non-zero stubs
        non_api_total_weight = 1.0
        if behavior_score > 0 or reputation_score > 0:
            final_score = (0.7 * local_score) + (0.2 * reputation_score) + (0.1 * behavior_score)
        else:
            final_score = local_score

    final_score = min(max(final_score, 0), 100)

    # 4. Risk thresholds
    if final_score >= 80:
        risk_level = "CRITICAL"
        verdict = "PHISHING / MALWARE"
        mitigations = ["BLOCK IMMEDIATELY", "Report to PhishTank", "Isolate endpoint if clicked"]
    elif final_score >= 55:
        risk_level = "HIGH"
        verdict = "HIGHLY SUSPICIOUS"
        mitigations = ["BLOCK", "Manual SOC Review"]
    elif final_score >= 30:
        risk_level = "MEDIUM"
        verdict = "SUSPICIOUS"
        mitigations = ["WARN USER", "Monitor behaviour"]
    else:
        risk_level = "LOW"
        verdict = "CLEAN"
        mitigations = ["ALLOW"]

    # 5. Source labels
    sources = [res.get('verdict') for res in api_results if res.get('verdict')]
    sources.append(f"Local:{local_score:.1f}/100")
    if not apis_available:
        sources.append("⚠️ External APIs: Not Configured (local-only mode)")

    return {
        "risk_score": round(final_score, 2),
        "risk_level": risk_level,
        "verdict": verdict,
        "sources": sources,
        "mitigations": mitigations,
        "raw_components": {
            "local": local_score,
            "consensus": consensus,
            "reputation": reputation_score,
            "behavior": behavior_score,
            "apis_available": apis_available
        }
    }
