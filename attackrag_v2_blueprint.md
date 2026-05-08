# AttackRAG v2: Complete Paper Blueprint

> **This is the final, definitive version.** Supersedes all previous documents.

---

## Paper Title

**"Grounding Integrity: Verifiable LLM-Based Intrusion Alert Triage via Security Knowledge Graphs"**

Subtitle/running title: *AttackRAG*

---

## The Complete Architecture

```
                          ┌─────────────────────────────────┐
                          │     EXISTING INFRASTRUCTURE     │
                          │         (not your work)         │
                          │                                 │
 Network Traffic ────→  Suricata/Zeek IDS ────→ Alert JSON  │
                          │                                 │
                          └──────────────┬──────────────────┘
                                         │
                            Raw IDS Alert (JSON)
                            ┌────────────┴────────────┐
                            │ {                       │
                            │   "sid": 2024897,       │
                            │   "signature": "ET      │
                            │     EXPLOIT PowerShell  │
                            │     Download Cradle",   │
                            │   "src_ip": "10.0.1.5", │
                            │   "dst_ip": "45.33.x.x",│
                            │   "timestamp": "..."    │
                            │ }                       │
                            └────────────┬────────────┘
                                         │
  ═══════════════════════════════════════╪═══════════════════════
          YOUR SYSTEM: AttackRAG         │
  ═══════════════════════════════════════╪═══════════════════════
                                         │
                                         ▼
                          ┌──────────────────────────┐
                          │   AGENT 1: QUERY PLANNER │
                          │                          │
                          │  Input: Raw alert JSON   │
                          │                          │
                          │  Process:                │
                          │  1. Extract observables  │
                          │     (IPs, ports, sigs,   │
                          │      process names)      │
                          │  2. Classify alert type  │
                          │     using StructRAG-     │
                          │     style routing:       │
                          │     • host-centric       │
                          │     • technique-centric  │
                          │     • campaign-centric   │
                          │  3. Generate sub-        │
                          │     questions for KG     │
                          │                          │
                          │  Output: Query Plan      │
                          │  [                       │
                          │   Q1: "ATT&CK technique  │
                          │        for PowerShell    │
                          │        download cradle?" │
                          │   Q2: "Known groups      │
                          │        using T1059.001?" │
                          │   Q3: "CVEs for target   │
                          │        service?"         │
                          │   Q4: "D3FEND defenses?" │
                          │  ]                       │
                          └────────────┬─────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                          │   AGENT 2: KG RETRIEVER  │
                          │                          │
    ┌─────────────────┐   │  For each sub-question:  │
    │  SECURITY KG    │   │  1. Generate CYPHER      │
    │  (Neo4j)        │◄──│     query (PolyG-style)  │
    │                 │──►│  2. Execute against KG   │
    │  ┌───────────┐  │   │  3. Return subgraph      │
    │  │ ATT&CK    │  │   │     evidence             │
    │  │ Techniques│  │   │                          │
    │  │ ~700 nodes│  │   │  Constraint:             │
    │  ├───────────┤  │   │  Max 3-hop traversal     │
    │  │ CVE/NVD   │  │   │  (prevents expensive     │
    │  │ ~10K nodes│  │   │   queries)               │
    │  ├───────────┤  │   │                          │
    │  │ D3FEND    │  │   │  Output per question:    │
    │  │ ~200 nodes│  │   │  {                       │
    │  ├───────────┤  │   │    evidence: [...],      │
    │  │ Groups    │  │   │    kg_paths: [...],      │
    │  │ ~140 nodes│  │   │    cypher_query: "..."   │
    │  └───────────┘  │   │  }                       │
    └─────────────────┘   └────────────┬─────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                          │   AGENT 3: GI SCORER     │
                          │                          │
                          │  For each evidence piece:│
                          │                          │
                          │  GI(claim, KG) =         │
                          │    relevance(path, claim)│
                          │    × trust(source)       │
                          │    × freshness(date)     │
                          │                          │
                          │  Where:                  │
                          │  • relevance ∈ [0,1]     │
                          │    (LLM semantic match)  │
                          │  • trust ∈ [0,1]         │
                          │    (MITRE=1.0, feed=0.7) │
                          │  • freshness ∈ [0,1]     │
                          │    (exponential decay)   │
                          │                          │
                          │  Output: Scored evidence │
                          │  [                       │
                          │   {claim: "T1059.001",   │
                          │    gi_score: 0.95,       │
                          │    kg_path: "Alert→...→  │
                          │      T1059.001",         │
                          │    status: GROUNDED},    │
                          │   {claim: "APT29",       │
                          │    gi_score: 0.0,        │
                          │    status: UNGROUNDED}   │
                          │  ]                       │
                          └────────────┬─────────────┘
                                       │
                          ┌────────────┴─────────────┐
                          │                          │
                          │   GI-CONSTRAINED GATE    │
                          │   (Active GI — the key   │
                          │    novelty)              │
                          │                          │
                          │   For each scored claim: │
                          │                          │
                          │   if gi_score ≥ τ:       │
                          │     → INCLUDE as         │
                          │       [GROUNDED ✓]       │
                          │                          │
                          │   if 0 < gi_score < τ:   │
                          │     → RETRY: send back   │────┐
                          │       to Agent 2 with    │    │
                          │       reformulated query │    │ RETRY
                          │                          │    │ LOOP
                          │   if gi_score = 0        │    │ (max 2
                          │     after retry:         │    │  retries)
                          │     → ABSTAIN: mark as   │    │
                          │       [INSUFFICIENT      │    │
                          │        EVIDENCE ⚠]       │    │
                          │                          │    │
                          └────────────┬─────────────┘    │
                                       │                  │
                          Agent 2 ◄────────────────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                          │   AGENT 4: REPORT        │
                          │   GENERATOR              │
                          │                          │
                          │  Input: GI-filtered      │
                          │  evidence only           │
                          │                          │
                          │  Output format:          │
                          └──────────┬───────────────┘
                                     │
                                     ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                    TRIAGE REPORT                             │
  │  ════════════════════════════════════════════════════════    │
  │  Alert: #2024897 — "ET EXPLOIT PowerShell Download Cradle"  │
  │  Report GI Score: 0.82 (High Confidence)                    │
  │                                                             │
  │  VERDICT: ESCALATE (Confidence: 0.87)                       │
  │                                                             │
  │  REASONING CHAIN:                                           │
  │  ─────────────────                                          │
  │  1. Alert matches ATT&CK technique T1059.001 (PowerShell)  │
  │     [GROUNDED ✓ — GI: 0.95]                                │
  │     Path: (Alert)→[MATCHES]→(T1059.001)→[BELONGS_TO]→      │
  │           (TA0002: Execution)                               │
  │                                                             │
  │  2. Destination IP associated with known C2 infrastructure  │
  │     [GROUNDED ✓ — GI: 0.78]                                │
  │     Path: (45.33.x.x)→[RESOLVES_TO]→(malware-domain)→      │
  │           [USED_BY]→(Cobalt Strike)                         │
  │                                                             │
  │  3. No evidence linking this specific alert to a known      │
  │     threat group campaign                                   │
  │     [INSUFFICIENT EVIDENCE ⚠ — GI: 0.0]                    │
  │     Note: System abstained rather than hallucinating        │
  │     a group attribution                                     │
  │                                                             │
  │  DEFENSIVE RECOMMENDATIONS:                                 │
  │  4. Apply D3FEND: Process Monitoring (D3-PM)                │
  │     [GROUNDED ✓ — GI: 0.92]                                │
  │     Path: (D3-PM)→[MITIGATES]→(T1059.001)                  │
  │                                                             │
  │  5. Apply D3FEND: Network Traffic Filtering (D3-NTF)       │
  │     [GROUNDED ✓ — GI: 0.88]                                │
  │     Path: (D3-NTF)→[MITIGATES]→(T1071: App Layer Protocol) │
  └──────────────────────────────────────────────────────────────┘
```

---

## Formal Definitions: Grounding Integrity Framework

### Definition 1 — Security Claim
A **security claim** $c$ is an atomic factual assertion extracted from an LLM-generated triage report, represented as a triple:

$$c = (subject, predicate, object)$$

Examples:
- ("Alert-2024897", "indicates_technique", "T1059.001")
- ("T1059.001", "used_by_group", "APT29")
- ("Host-DC01", "runs_software", "Exchange Server 2019")

### Definition 2 — Grounding Path
A **grounding path** $p$ for claim $c$ in knowledge graph $G = (V, E)$ is a walk:

$$p = (v_1 \xrightarrow{e_1} v_2 \xrightarrow{e_2} \cdots \xrightarrow{e_{k-1}} v_k)$$

such that the semantic content of $p$ entails $c$. The set of all candidate grounding paths for $c$ is $\mathcal{P}(c, G)$.

### Definition 3 — Grounding Integrity Score (Claim-Level)
The **Grounding Integrity** of a single claim $c$ with respect to knowledge graph $G$:

$$GI(c, G) = \max_{p \in \mathcal{P}(c,G)} \; \text{rel}(p, c) \cdot \text{trust}(p) \cdot \text{fresh}(p)$$

Where:
- $\text{rel}(p, c) \in [0,1]$ — semantic relevance between the path content and the claim (computed via LLM embedding similarity)
- $\text{trust}(p) \in [0,1]$ — source reliability of the path's origin:

| Source | Trust Score |
|--------|------------|
| MITRE ATT&CK (official) | 1.0 |
| NVD/CVE (NIST) | 1.0 |
| D3FEND (MITRE) | 1.0 |
| Curated threat intel feed | 0.7 |
| Community-contributed | 0.5 |
| Auto-generated/inferred | 0.3 |

- $\text{fresh}(p) \in [0,1]$ — temporal freshness with exponential decay:
$$\text{fresh}(p) = \exp\left(-\lambda \cdot \text{age}(p)\right)$$
where $\text{age}(p)$ is the time since the KG entry was last updated, and $\lambda$ controls decay rate.

If $\mathcal{P}(c, G) = \emptyset$ (no path exists), then $GI(c, G) = 0$.

### Definition 4 — Report Grounding Integrity (Report-Level)
For a triage report $R = \{c_1, c_2, \ldots, c_n\}$ containing $n$ extracted claims:

$$GI(R, G) = \frac{1}{n} \sum_{i=1}^{n} GI(c_i, G)$$

And the **grounding coverage**:
$$\text{Coverage}(R, G) = \frac{|\{c \in R : GI(c, G) > 0\}|}{|R|}$$

### Property 1 — Hallucination Detection
A claim $c$ is classified as **potentially hallucinated** if $GI(c, G) = 0$. Under the assumption that the KG $G$ is comprehensive for the security domain:

$$GI(c, G) = 0 \implies c \text{ has no factual support in the security knowledge base}$$

The **hallucination rate** of report $R$:
$$\text{HalRate}(R) = 1 - \text{Coverage}(R, G)$$

### Property 2 — Degradation Bound Under Poisoning
If an adversary injects $k$ false relations into $G$, creating poisoned graph $G' = G \cup \{e_1^*, \ldots, e_k^*\}$, then for any false claim $c^*$ that exploits these relations:

$$GI(c^*, G') \leq \max_{i} \text{trust}(e_i^*)$$

Since poisoned entries originate from untrusted sources (trust ≤ 0.3 for auto-generated), the GI score of any poisoned claim is bounded by 0.3. **Legitimate grounded claims (trust = 1.0) always outscore poisoned claims.**

### Property 3 — Abstention Guarantee (Active GI)
Under GI-constrained generation with threshold $\tau$:

$$\forall c \in R_{\text{active}}: \; GI(c, G) \geq \tau \;\;\text{OR}\;\; c \text{ is marked [INSUFFICIENT EVIDENCE]}$$

The system **never presents an ungrounded claim as fact.** It either grounds it or explicitly abstains. This is a formal safety guarantee that no prior system provides.

---

## Security Knowledge Graph Schema

```
┌─────────────────────────────────────────────────────────────┐
│                    SECURITY KG SCHEMA                       │
│                                                             │
│   ┌──────────┐  BELONGS_TO   ┌──────────┐                 │
│   │Technique │──────────────▶│  Tactic  │                 │
│   │          │               │          │                 │
│   │ id       │               │ id       │                 │
│   │ name     │               │ name     │                 │
│   │ platforms│               │ phase    │                 │
│   └────┬─────┘               └──────────┘                 │
│        │                                                    │
│   EXPLOITED_BY ▲         USES                              │
│        │       │          │                                 │
│        ▼       │          ▼                                 │
│   ┌──────────┐ │    ┌──────────┐    ATTRIBUTED_TO          │
│   │   CVE    │ │    │  Group   │──────────────────┐        │
│   │          │ │    │          │                   │        │
│   │ cve_id   │ │    │ name     │                   ▼        │
│   │ cvss     │ │    │ aliases  │            ┌──────────┐   │
│   │ desc     │ │    │ country  │            │ Campaign │   │
│   └──────────┘ │    └────┬─────┘            │          │   │
│                │         │                  │ name     │   │
│   MITIGATED_BY │    USES │                  │ dates    │   │
│        │       │         ▼                  └──────────┘   │
│        ▼       │    ┌──────────┐                           │
│   ┌──────────┐ │    │ Software │                           │
│   │ D3FEND   │ │    │          │                           │
│   │ Defense  │─┘    │ name     │                           │
│   │          │      │ type     │ (malware/tool)            │
│   │ id       │      │ platforms│                           │
│   │ name     │      └──────────┘                           │
│   │ category │                                              │
│   └──────────┘                                              │
│                                                             │
│   Relationships:                                            │
│   • Technique -[BELONGS_TO]→ Tactic                        │
│   • Technique -[SUB_TECHNIQUE_OF]→ Technique               │
│   • Group -[USES]→ Technique                               │
│   • Group -[USES]→ Software                                │
│   • Software -[USES]→ Technique                            │
│   • CVE -[EXPLOITED_BY]→ Technique                         │
│   • D3FEND -[MITIGATES]→ Technique                         │
│   • Group -[ATTRIBUTED_TO]→ Campaign                       │
│                                                             │
│   Estimated scale:                                          │
│   ~700 techniques + ~600 software + ~140 groups +           │
│   ~10K CVEs + ~200 D3FEND = ~11,640 nodes, ~50K edges     │
└─────────────────────────────────────────────────────────────┘
```

---

## Evaluation Plan

### Experiment 1: Hallucination Rate Comparison (Main Result)

| System | Expected HalRate | Why |
|--------|-----------------|-----|
| GPT-4o zero-shot | ~40-50% | No grounding at all |
| CoT prompting | ~30-40% | Reasoning but no retrieval |
| Vanilla vector RAG | ~15-25% | Retrieves text but no structure |
| AttackRAG (passive GI) | ~5-10% | KG grounding catches most hallucinations |
| **AttackRAG (active GI)** | **~0-2%** | **Abstains instead of hallucinating** |

### Experiment 2: Triage Accuracy
- Compare escalate/investigate/dismiss decisions against ground truth
- Show that GI doesn't sacrifice accuracy for groundedness
- Metrics: Precision, Recall, F1 per verdict class

### Experiment 3: GI Validity
- Correlate GI scores with human-judged claim correctness
- Show that GI > 0.8 claims are ~95%+ factually correct
- Show that GI = 0 claims are ~90%+ hallucinated
- This validates GI as a meaningful metric

### Experiment 4: Active vs. Passive GI
- Same alerts, same KG
- Passive: generate full report, then score with GI (post-hoc)
- Active: GI-constrained gate prevents ungrounded claims (in-loop)
- Show active reduces HalRate from ~8% to ~1% with minimal accuracy loss

### Experiment 5: KG Poisoning Robustness
- Inject 1%, 5%, 10%, 20% false edges into the KG
- Measure: do poisoned facts appear in triage reports?
- Show: Property 2 holds — poisoned claims get GI ≤ 0.3 (flagged as low-confidence)
- Compare: system without trust scoring vs. with trust scoring

### Experiment 6: Ablation Studies
- Remove Agent 3 (no GI scoring) → hallucinations increase
- Remove D3FEND from KG → no defensive recommendations
- Remove CVE from KG → no vulnerability correlation
- 1-hop vs. 2-hop vs. 3-hop retrieval → quality/speed tradeoff
- Remove retry loop (active → passive) → more abstentions or more hallucinations

### Experiment 7: Efficiency
- Mean triage time per alert (target: <30 seconds)
- Token consumption vs. baselines
- KG query latency breakdown

### Experiment 8: Case Studies (3 APT Scenarios)
- Walk through 3 DARPA TC multi-stage attack campaigns
- Show complete reasoning chain for each alert in the campaign
- Demonstrate how GI correctly grounds technique identification
- Highlight cases where the system correctly abstains

---

## Expected Paper Structure (IEEE S&P Format, ~13 Pages)

| Section | Pages | Content |
|---------|-------|---------|
| **§1 Introduction** | 1.5 | Alert fatigue crisis → LLM hallucination danger → GI framework → contributions |
| **§2 Background** | 1 | MITRE ATT&CK, GraphRAG, FActScore claim verification |
| **§3 Threat Model** | 0.75 | System model, attacker model (primary + KG poisoning), trust assumptions |
| **§4 Grounding Integrity** | 1.5 | Definitions 1-4, Properties 1-3, relationship to FActScore |
| **§5 AttackRAG System** | 2.5 | KG schema, 4 agents, GI-constrained gate, retry loop |
| **§6 Evaluation** | 3.5 | Experiments 1-8, tables, figures, case studies |
| **§7 Discussion** | 0.75 | Limitations (KG coverage for zero-days), deployment, future work |
| **§8 Related Work** | 1 | CORTEX, KAIROS, ORTHRUS, GRAGPOISON, LLM-TIKG, FActScore |
| **References** | 0.5 | ~40-50 citations |

---

## Summary of Novel Contributions

| # | Contribution | Novelty Argument |
|---|-------------|-----------------|
| 1 | **Grounding Integrity framework** (Definitions 1-4, Properties 1-3) | FActScore verifies against unstructured Wikipedia text. GI verifies against structured security KG paths with trust and freshness — new formalization for security domain. |
| 2 | **GI-constrained generation** (Active GI with retry + abstention) | No prior system prevents security hallucinations at generation time. CORTEX generates then hopes for the best. You generate then verify, retry, or abstain. |
| 3 | **Adversarial robustness via trust-weighted GI** (Property 2) | GRAGPOISON attacks GraphRAG. You show GI's trust scoring naturally bounds poisoned claim scores. First defensive analysis of security-domain GraphRAG. |
| 4 | **AttackRAG system** with empirical evaluation on DARPA TC + CICIDS | First KG-grounded, GI-verified agentic alert triage system evaluated on standard security benchmarks. |
