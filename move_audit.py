"""
Hierarchical multi-agent analysis for Move (Sui) contracts.
Layer 1: 3 specialized analysts
Layer 2: The Crucible (investigator + skeptic + critic)
"""
import logging
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from config import FREE_MODELS
from agents import call_model, truncate_code
from hierarchical_base import HierarchicalAuditor

if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

MOVE_SOURCES_DIR = os.environ.get(
    'MOVE_SOURCES_DIR',
    os.path.join(os.path.dirname(__file__), 'move_sources')
)

LAYER1_AGENTS = [
    {
        "key": "security_move",
        "name": "Move/Sui Security Expert",
        "model": "deepseek-chat",
        "prompt": """You are a smart contract security expert specialized in **Move** on Sui blockchain.

Your tasks:
1. Analyze code line by line for Move/Sui specific vulnerabilities
2. Focus on: Object Ownership & Transfer, ID Leakage, Type Confusion, Witness Pattern Abuse, Clock Manipulation, Abort/Assert Bypass, Dynamic Field Exploits, Tornado (Missing Store Ability), Randomness Abuse, Flash Loans, Twap Manipulation
3. For each: identify file/line, explain attack, rate severity (Critical/High/Medium/Low)
4. Provide fix code

Output:
## Security Vulnerabilities (Move/Sui)
### [Number]: [Name] — [Critical/High/Medium/Low]
- **File/Line**: [location]
- **Type**: [Object Ownership / Type Confusion / ...]
- **Attack**: [mechanism]
- **Impact**: [effect]
- **Fix**: [code + explanation]
"""
    },
    {
        "key": "logic_move",
        "name": "Sui Logic Expert",
        "model": "deepseek-chat",
        "prompt": """You are an expert in business logic and protocol design on Sui blockchain in Move.

Your tasks:
1. Analyze protocol architecture
2. Focus on: Access Control Design, Capability Pattern, Resource Scarcity, Epoch-based Logic, PTB Atomicity Assumptions, Signature/Message Verification Flaws, Cross-module Invariants, State Machine Correctness
3. Find contradictions in design assumptions
4. Find unexpected state transition paths

Output:
## Design & Logic Vulnerabilities (Move/Sui)
### [Number]: [Name] — [Critical/High/Medium/Low]
- **Component**: [location]
- **Design Issue**: [explanation]
- **Attack Path**: [steps]
- **Fix**: [suggestion]
"""
    },
    {
        "key": "economics_move",
        "name": "Sui Economics Expert",
        "model": "deepseek-chat",
        "prompt": """You are an expert in protocol economics on Sui blockchain.

Your tasks:
1. Analyze the economic model (DVault - Dual Vault)
2. Focus on: MEV Opportunities, Epoch-based Limit Bypass, Flash Loan Composability, Secure Vault Drain Paths, Security Period Rate Limit Abuse, Multi-sig Threshold Exploitation, Coin Type Parameter Attacks
3. Analyze fund flow between Active Vault and Secure Vault
4. Find economic attack paths

Output:
## Economic Vulnerabilities
### [Number]: [Name] — [Critical/High/Medium/Low]
- **Economic Model**: [explanation]
- **Exploit Scenario**: [steps]
- **Expected Profit**: [estimate]
- **Fix**: [suggestion]
"""
    },
]

LAYER2_AGENTS = [
    {
        "key": "investigator_move",
        "name": "Investigator",
        "model": "deepseek-chat",
        "prompt": """You are an investigator specialized in root cause analysis of Move/Sui vulnerabilities.

Your role: After Layer 1 analyzed the code from 3 angles (security, logic, economics):
1. Study all Layer 1 analyses
2. For each vulnerability:
   - Find the root cause
   - Link related vulnerabilities
   - Discover attack chains
   - Assess actual exploitability on Sui
3. Add new vulnerabilities from cross-referencing
4. Rate exploitability (Easy/Medium/Hard)

Output:
## Investigation Report
### [Number]: [Name]
- **Root Cause**: [analysis]
- **Exploitability**: [Easy/Medium/Hard]
- **Attack Chains**: [if any]
"""
    },
    {
        "key": "skeptic_move",
        "name": "Skeptic",
        "model": "deepseek-chat",
        "prompt": """You are a skeptic specialized in debunking false vulnerabilities in Move/Sui contracts.

Your role: Review the investigator and Layer 1 analyses:
1. **Impractical on Sui** — is the assumption unrealistic?
2. **Protected by Sui mechanisms** — does Sui ecosystem protect automatically?
3. **Severity overestimation** — is it less severe than claimed?
4. **Owner-controlled** — does it require a malicious owner?

Rate each:
- Confirmed / Suspected / Rejected
Explain why. Be harsh. Your goal: filter false positives only.
"""
    },
    {
        "key": "critic_move",
        "name": "Critic",
        "model": "deepseek-chat",
        "prompt": """You are a lead critic producing professional Bug Bounty reports for HackenProof.

Your role: After Layer 1 + investigator + skeptic:
1. Filter remaining findings
2. Assign final severity per HackenProof:
   - Critical: unauthorized fund extraction, privilege escalation, direct theft
   - High: major logic/access issues without full control
   - Medium: limited impact
   - Low: marginal issues
3. Note disagreements between analysts

Final report format (HackenProof-ready):

# [Protocol] — Security Report

## [C/H/M/L-XX]: [Title]
### Severity: **[Critical / High / Medium / Low]**
### Description
[explanation]
### Affected Contracts
- [file:line]
### Root Cause
[root cause]
### Impact
[effect]
### Proof of Concept
[attack steps]
### Remediation
[fix]

## Disagreements
[if any]

## Summary
| ID | Finding | Severity | File |
"""
    },
]


def move_hierarchical_audit(code: str) -> str:
    """Run hierarchical analysis on Move/Sui code."""
    auditor = HierarchicalAuditor(LAYER1_AGENTS, LAYER2_AGENTS,
                                   default_model="deepseek-chat",
                                   protocol_name="NAVI Astros (DVault)")

    # Override _run_agent for Move-specific fallback
    def move_run_agent(model_key: str, prompt: str, agent_name: str) -> Optional[str]:
        if model_key not in FREE_MODELS:
            logger.warning(f"Model {model_key} not found, using deepseek-chat")
            model_key = "deepseek-chat"
        model_id = FREE_MODELS[model_key]["id"]
        logger.info(f"Running {agent_name} ({model_key})...")
        try:
            return call_model(model_id, prompt, timeout=900)
        except Exception as e:
            logger.error(f"{agent_name} failed: {e}")
            try:
                fallback_id = FREE_MODELS["deepseek-chat"]["id"]
                logger.info(f"Trying fallback for {agent_name}...")
                return call_model(fallback_id, prompt, timeout=900)
            except Exception as e2:
                logger.error(f"Fallback also failed: {e2}")
                return None

    auditor._run_agent = move_run_agent
    _, _, final = auditor.run(code)
    return final


def _merge_fallback(layer1: Dict[str, str], layer2: Dict[str, str]) -> str:
    report = "# NAVI Astros (DVault) — Security Report (Hierarchical)\n\n"
    for name, text in layer1.items():
        report += f"\n### {name}\n{text[:2000]}\n---\n"
    for name, text in layer2.items():
        report += f"\n### {name}\n{text[:2000]}\n---\n"
    report += "\n\nAuto-merged report."
    return report


if __name__ == "__main__":
    combined = ''
    src_dir = MOVE_SOURCES_DIR
    for f in ['active_vault.move', 'dvault_manage.move', 'secure_vault.move', 'user_entry.move']:
        path = os.path.join(src_dir, f)
        if os.path.exists(path):
            combined += open(path, encoding='utf-8').read() + '\n\n'

    print(f'Total: {len(combined):,} chars')
    report = move_hierarchical_audit(combined)

    out_path = os.path.join(os.path.dirname(__file__), 'reports', 'move_audit_navi_astros.txt')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f'\nReport: {out_path} ({len(report):,} chars)')
    print(report[:3000])
