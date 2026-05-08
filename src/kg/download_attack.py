"""
Download MITRE ATT&CK Enterprise data in STIX 2.1 format.

=== WHAT THIS DOES ===
Downloads the official MITRE ATT&CK Enterprise knowledge base from their
public GitHub repository. ATT&CK is distributed as a single JSON file in
STIX 2.1 format (Structured Threat Information eXpression).

=== HOW IT WORKS ===
1. Fetches enterprise-attack.json from the official MITRE CTI GitHub repo
2. Saves it to data/raw/enterprise-attack.json
3. Prints a summary of what's inside (technique counts, etc.)

=== ROLE IN THE PAPER ===
This is the data source for our Security Knowledge Graph (Section 5.1).
ATT&CK provides:
- Technique nodes (e.g., T1059.001 PowerShell)
- Tactic nodes (e.g., TA0002 Execution)  
- Group nodes (e.g., APT29)
- Software nodes (e.g., Cobalt Strike)
- Relationships (Group USES Technique, Software USES Technique, etc.)

=== WHAT IS STIX 2.1? ===
STIX (Structured Threat Information eXpression) is an open standard for
representing cyber threat intelligence. Every ATT&CK object (technique,
tactic, group, software) is a STIX Domain Object (SDO) with a standardized
schema. Relationships between objects are STIX Relationship Objects (SROs).

Reference: https://oasis-open.github.io/cti-documentation/stix/intro.html

=== WHAT IS MITRE ATT&CK? ===
A globally-accessible knowledge base of adversary tactics and techniques
based on real-world observations. Organized by:
- Tactics: the "why" (adversary's goal, e.g., "Execution", "Persistence")
- Techniques: the "how" (specific method, e.g., "PowerShell", "Registry Run Keys")
- Sub-techniques: finer detail under each technique

Reference: https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf
"""

import json
import os
from pathlib import Path
from collections import Counter

import requests

# MITRE's official ATT&CK data repository
# This URL points to the latest ATT&CK Enterprise dataset in STIX 2.1 format.
# MITRE maintains this at: https://github.com/mitre-attack/attack-stix-data
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# Where to save the downloaded file
DATA_DIR = Path(__file__).parent.parent.parent / "data" / "raw"
OUTPUT_FILE = DATA_DIR / "enterprise-attack.json"


def download_attack_data() -> Path:
    """
    Download MITRE ATT&CK Enterprise STIX bundle.
    
    Returns:
        Path to the downloaded JSON file.
    
    Raises:
        requests.HTTPError: If the download fails.
    """
    # Create data directory if it doesn't exist
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Skip download if file already exists
    if OUTPUT_FILE.exists():
        print(f"[✓] ATT&CK data already exists at: {OUTPUT_FILE}")
        print(f"    Size: {OUTPUT_FILE.stat().st_size / 1024 / 1024:.1f} MB")
        return OUTPUT_FILE
    
    print(f"[↓] Downloading MITRE ATT&CK Enterprise STIX bundle...")
    print(f"    Source: {ATTACK_STIX_URL}")
    
    response = requests.get(ATTACK_STIX_URL, timeout=120)
    response.raise_for_status()
    
    # Save to disk
    OUTPUT_FILE.write_text(response.text, encoding="utf-8")
    
    size_mb = OUTPUT_FILE.stat().st_size / 1024 / 1024
    print(f"[✓] Saved to: {OUTPUT_FILE}")
    print(f"    Size: {size_mb:.1f} MB")
    
    return OUTPUT_FILE


def summarize_attack_data(filepath: Path) -> dict:
    """
    Print a summary of what's inside the ATT&CK STIX bundle.
    
    This helps you understand the data before we build the KG.
    Each STIX object has a "type" field that tells us what it is:
    - "attack-pattern"    → ATT&CK Technique
    - "x-mitre-tactic"    → ATT&CK Tactic  
    - "intrusion-set"     → ATT&CK Group (threat actor)
    - "malware"           → Malware entry
    - "tool"              → Legitimate tool used maliciously
    - "relationship"      → Link between two objects
    - "course-of-action"  → Mitigation recommendation
    
    Returns:
        Dictionary with counts per object type.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    
    # STIX bundle structure: {"type": "bundle", "objects": [...]}
    objects = bundle.get("objects", [])
    
    # Count by STIX type
    type_counts = Counter(obj.get("type", "unknown") for obj in objects)
    
    # Count active (non-revoked, non-deprecated) techniques
    active_techniques = [
        obj for obj in objects
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]
    
    # Count sub-techniques vs parent techniques
    sub_techniques = [t for t in active_techniques if t.get("x_mitre_is_subtechnique", False)]
    parent_techniques = [t for t in active_techniques if not t.get("x_mitre_is_subtechnique", False)]
    
    # Count active groups
    active_groups = [
        obj for obj in objects
        if obj.get("type") == "intrusion-set"
        and not obj.get("revoked", False)
    ]
    
    # Count relationships by type
    relationships = [obj for obj in objects if obj.get("type") == "relationship"]
    rel_types = Counter(r.get("relationship_type", "unknown") for r in relationships)
    
    # Print summary
    print("\n" + "=" * 60)
    print("MITRE ATT&CK Enterprise — Data Summary")
    print("=" * 60)
    print(f"\nTotal STIX objects: {len(objects)}")
    print(f"\nBy type:")
    for stype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        # Map STIX types to ATT&CK names for clarity
        label = {
            "attack-pattern": "Techniques",
            "x-mitre-tactic": "Tactics",
            "intrusion-set": "Groups",
            "malware": "Malware",
            "tool": "Tools",
            "relationship": "Relationships",
            "course-of-action": "Mitigations",
            "x-mitre-data-source": "Data Sources",
            "x-mitre-data-component": "Data Components",
            "x-mitre-matrix": "Matrices",
            "x-mitre-collection": "Collections",
            "identity": "Identities",
            "marking-definition": "Markings",
        }.get(stype, stype)
        print(f"  {label:25s} {count:5d}")
    
    print(f"\nActive techniques breakdown:")
    print(f"  Parent techniques:       {len(parent_techniques):5d}")
    print(f"  Sub-techniques:          {len(sub_techniques):5d}")
    print(f"  Total active:            {len(active_techniques):5d}")
    
    print(f"\nActive groups:             {len(active_groups):5d}")
    
    print(f"\nRelationship types:")
    for rtype, count in sorted(rel_types.items(), key=lambda x: -x[1]):
        print(f"  {rtype:25s} {count:5d}")
    
    print("=" * 60)
    
    return {
        "total_objects": len(objects),
        "type_counts": dict(type_counts),
        "active_techniques": len(active_techniques),
        "parent_techniques": len(parent_techniques),
        "sub_techniques": len(sub_techniques),
        "active_groups": len(active_groups),
        "relationships": len(relationships),
        "relationship_types": dict(rel_types),
    }


if __name__ == "__main__":
    filepath = download_attack_data()
    summary = summarize_attack_data(filepath)
