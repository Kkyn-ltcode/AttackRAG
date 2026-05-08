# AttackRAG Master Plan: Code to Camera-Ready

**Target:** IEEE S&P 2027 Cycle 2 — November 17, 2026
**Timeline:** May 2026 → November 2026 (6 months)
**Mode:** Solo researcher + professor advisory + AI assistant

---

## Phase 0: Foundation (Week 1-2) — "Know Your Battlefield"

> Before writing ANY code, you need to deeply understand what you're building and what you're competing against.

### Step 0.1: Read the Essential Papers

| # | Paper | Venue | Why You Must Read It | Key Takeaway |
|---|-------|-------|---------------------|-------------|
| 1 | **KAIROS** — "Practical Whole-System Provenance-Based IDS" | S&P 2024 | The benchmark for temporal graph IDS at S&P. Study their evaluation methodology — you need to match this rigor. | GNN encoder-decoder on provenance graphs, anomaly scoring per edge, attack reconstruction |
| 2 | **ORTHRUS** — "High Quality of Attribution in PIDS" | USENIX Sec 2025 | Introduced "Quality of Attribution" (QoA). Your paper needs analyst-centric metrics too. | TGN variant, focus on reducing analyst investigation burden |
| 3 | **Entente** — "Cross-silo Intrusion Detection with FL" | NDSS 2026 | Shows federated graph IDS is accepted at NDSS. Uses LANL/OpTC datasets — same ones you'll use. | Reference graph synthesis, graph sketching, evaluated on LANL + OpTC |
| 4 | **GRAGPOISON** — "Poisoning GraphRAG" | S&P 2026 | **Critical.** Proves S&P PC accepts GraphRAG as a security topic. You're building the defensive counterpart. | Shared-relation exploitation in KGs, high attack success rates |
| 5 | **CORTEX** — "Collaborative LLM Agents for Alert Triage" | arXiv 2025 | The closest system to yours. Your paper must clearly differentiate (they lack KG grounding). | Multi-agent decomposition: orchestrator, behavior analysis, evidence acquisition, reasoning |
| 6 | **LLM-QGraph** — "Threat Intelligence Query Graph Construction" | IEEE 2026 | Shows LLM→KG for threat hunting is established. Your paper goes further (real-time alert triage). | LLM generates attack query graphs from CTI for log-based threat hunting |

> **How to find them:** Search paper titles on Google Scholar or Semantic Scholar. KAIROS and ORTHRUS are on the USENIX/IEEE open access archives. CORTEX is on arXiv.

> [!IMPORTANT]
> **🎓 PROFESSOR CHECKPOINT #1:** After reading these 6 papers, meet with your professor. Discuss: (1) Is the AttackRAG positioning clear vs. competitors? (2) Does your professor see any additional competitors you should read? (3) Does the scope sound right for solo work?

### Step 0.2: Understand the Core Technologies

| Technology | What It Is | What You Need to Know | Resource |
|-----------|-----------|----------------------|----------|
| **MITRE ATT&CK** | Taxonomy of adversary tactics & techniques | The 14 tactics, how techniques are organized, what a "procedure" is | [attack.mitre.org](https://attack.mitre.org/) — read the "Getting Started" page |
| **CVE / NVD** | Vulnerability database with severity scores (CVSS) | How CVE IDs work, what CVSS scores mean, how to query the NVD API | [nvd.nist.gov](https://nvd.nist.gov/) |
| **D3FEND** | MITRE's defensive technique taxonomy (counterpart to ATT&CK) | How defensive techniques map to ATT&CK techniques | [d3fend.mitre.org](https://d3fend.mitre.org/) |
| **Neo4j + CYPHER** | Graph database + query language | Basic CYPHER queries: MATCH, CREATE, MERGE, path traversal | [Neo4j GraphAcademy](https://graphacademy.neo4j.com/) — free "Neo4j Fundamentals" course (~2 hours) |
| **LangChain / LlamaIndex** | LLM orchestration frameworks | How to build agents, chains, tool-calling | [LangChain docs](https://python.langchain.com/) — "Agents" section |
| **Suricata** | Open-source IDS that generates alerts from network traffic | How to run Suricata on pcap files, read alert JSON output | [suricata.io docs](https://docs.suricata.io/) — "Quick Start" |
| **GraphRAG** | Retrieval-Augmented Generation using knowledge graphs | How it differs from vector RAG, community detection, graph traversal for retrieval | Microsoft GraphRAG paper (arXiv:2404.16130) |

### Step 0.3: Set Up Project Structure

**I will build this for you.** Clean repo structure from day 1:

```
NIDS/AttackRAG/
├── README.md
├── requirements.txt
├── config/
│   └── settings.yaml              # All configurable parameters
├── data/
│   ├── raw/                       # Downloaded datasets (gitignored)
│   ├── processed/                 # Preprocessed alerts
│   └── kg/                        # KG export files
├── src/
│   ├── kg/                        # Knowledge Graph construction
│   │   ├── build_attack_kg.py     # MITRE ATT&CK ingestion
│   │   ├── build_cve_kg.py        # CVE/NVD ingestion
│   │   ├── build_d3fend_kg.py     # D3FEND ingestion
│   │   └── schema.py              # KG schema definitions
│   ├── agents/                    # The 4 agentic pipeline agents
│   │   ├── query_planner.py       # Agent 1: Decompose alert → sub-questions
│   │   ├── kg_retriever.py        # Agent 2: CYPHER query generation + execution
│   │   ├── evidence_verifier.py   # Agent 3: Grounding score computation
│   │   └── report_generator.py    # Agent 4: Structured triage report
│   ├── pipeline/
│   │   └── triage_pipeline.py     # End-to-end orchestration
│   ├── alerts/                    # Alert preprocessing
│   │   ├── suricata_parser.py     # Parse Suricata EVE JSON
│   │   └── darpa_parser.py        # Parse DARPA TC alert format
│   └── evaluation/
│       ├── hallucination.py       # Automated hallucination detection
│       ├── accuracy.py            # Triage accuracy metrics
│       ├── poisoning.py           # KG poisoning attack simulation
│       └── ablation.py            # Ablation experiment runner
├── experiments/
│   ├── configs/                   # Experiment configurations
│   └── results/                   # Experiment outputs
├── paper/
│   ├── main.tex                   # Paper LaTeX
│   ├── figures/                   # Generated figures
│   └── tables/                    # Generated tables
└── scripts/
    ├── download_data.sh           # Download all datasets
    ├── setup_neo4j.sh             # Neo4j setup automation
    └── run_experiments.sh         # Full experiment pipeline
```

---

## Phase 1: Knowledge Graph Construction (Week 3-5)

> **Goal:** Build a comprehensive security KG in Neo4j containing ATT&CK techniques, CVE vulnerabilities, and D3FEND defenses with proper relationships.

### Step 1.1: Install & Configure Neo4j

**What:** Set up Neo4j Community Edition on your Mac.
**How:** I'll write a setup script. You run it.
**Knowledge needed:** Basic terminal commands. Neo4j runs as a local server on port 7687.

### Step 1.2: Ingest MITRE ATT&CK into Neo4j

**What:** Download ATT&CK STIX 2.1 data (JSON) and load it as nodes + relationships into Neo4j.
**How:** I'll write `build_attack_kg.py` that:
- Downloads ATT&CK Enterprise STIX bundle from GitHub
- Parses all Tactic, Technique, Sub-technique, Software, and Group objects
- Creates nodes with properties (ID, name, description, kill-chain phase)
- Creates relationships: `Technique -[BELONGS_TO]-> Tactic`, `Software -[USES]-> Technique`, `Group -[USES]-> Technique/Software`
**Knowledge needed:**
- STIX 2.1 format — read [OASIS STIX docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) (just the overview)
- ATT&CK data model — read [ATT&CK Design and Philosophy](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf) pages 1-10
**Expected output:** ~700 technique nodes, ~600 software nodes, ~140 group nodes, ~5000 relationships

### Step 1.3: Ingest CVE/NVD Data

**What:** Pull recent CVEs (2020-2026) from NVD API and link them to ATT&CK techniques.
**How:** I'll write `build_cve_kg.py` that:
- Queries NVD API 2.0 for CVEs with CVSS ≥ 7.0 (high/critical severity)
- Creates CVE nodes with properties (ID, CVSS score, description, affected products)
- Links CVEs to ATT&CK techniques via CWE mappings (CWE→CAPEC→ATT&CK)
**Knowledge needed:**
- What CVSS scores mean — [FIRST CVSS Calculator](https://www.first.org/cvss/calculator/3.1) (5 min overview)
- NVD API — [NVD API docs](https://nvd.nist.gov/developers/vulnerabilities)
**Expected output:** ~5000-10000 CVE nodes linked to techniques

### Step 1.4: Ingest D3FEND Defensive Techniques

**What:** Load MITRE D3FEND and link defensive techniques to ATT&CK attack techniques.
**How:** I'll write `build_d3fend_kg.py` that uses D3FEND's RDF/OWL ontology.
**Knowledge needed:**
- D3FEND overview — [d3fend.mitre.org](https://d3fend.mitre.org/) — browse the matrix for 10 minutes
**Expected output:** ~200 defensive technique nodes with `MITIGATES` relationships to ATT&CK techniques

### Step 1.5: Validate the KG

**What:** Run sanity checks — can we answer real security questions?
**How:** I'll write validation CYPHER queries like:
- "What techniques does APT29 use?" → should return T1059, T1078, etc.
- "What CVEs exploit T1059.001 (PowerShell)?" → should return relevant CVEs
- "What D3FEND techniques mitigate T1059.001?" → should return Process Monitoring, etc.
**Expected output:** All queries return correct, complete results

> [!IMPORTANT]
> **🎓 PROFESSOR CHECKPOINT #2:** Show your professor the KG. Demo the CYPHER queries. Ask: (1) Is the schema comprehensive enough? (2) Any missing entity types? (3) Should we include threat intel feeds (STIX/TAXII)?

---

## Phase 2: Alert Data Preparation (Week 5-7)

> **Goal:** Generate realistic IDS alerts that we'll triage with our system.

### Step 2.1: Generate Suricata Alerts from CICIDS-2017

**What:** Run Suricata IDS on CICIDS-2017 pcap files to produce real alert JSON.
**How:** I'll write scripts that:
- Download CICIDS-2017 pcap files
- Run Suricata with ET Open ruleset
- Parse EVE JSON output into structured alert objects
**Knowledge needed:**
- What an IDS alert looks like — [Suricata EVE JSON docs](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- CICIDS-2017 dataset — read the [CICIDS-2017 paper](https://www.unb.ca/cic/datasets/ids-2017.html) description page
**Expected output:** ~10,000-50,000 Suricata alerts with ground truth labels (attack type known from CICIDS labels)

### Step 2.2: Process DARPA TC E3 Alerts

**What:** Extract security-relevant events from DARPA TC Engagement 3 data.
**How:** I'll write `darpa_parser.py` to extract events that would trigger IDS alerts (suspicious process creation, network connections to C2, file modifications).
**Knowledge needed:**
- DARPA TC program overview — read the [DARPA TC webpage](https://www.darpa.mil/program/transparent-computing)
- The attack scenarios in E3 — documented in the KAIROS paper (Section 5)
**Expected output:** ~500 alert-level events with known attack ground truth

### Step 2.3: Create Alert Test Sets

**What:** Build curated test sets for experiments.
**How:** I'll create balanced sets:
- **Set A (Easy):** 200 alerts — clear attacks + obvious benign
- **Set B (Hard):** 200 alerts — subtle attacks + ambiguous benign (false-positive-heavy)
- **Set C (APT):** 50 alerts — multi-stage campaign alerts from DARPA TC
**Expected output:** 450 labeled alerts ready for pipeline evaluation

---

## Phase 3: Agentic Pipeline Implementation (Week 7-11)

> **Goal:** Build the 4-agent triage pipeline. This is the core of the paper.

### Step 3.1: Agent 1 — Query Planner

**What:** Takes a raw IDS alert and decomposes it into structured sub-questions that can be answered by the KG.
**How:** An LLM agent with a carefully engineered prompt that:
- Extracts observables from the alert (IPs, ports, process names, file paths, signatures)
- Maps observables to ATT&CK-relevant question types
- Outputs a structured query plan (JSON)
**Knowledge needed:**
- LangChain agents — [LangChain Agent docs](https://python.langchain.com/docs/modules/agents/)
- Prompt engineering — read "Prompt Engineering Guide" by DAIR.AI (free, online)
**Key design decision:** The query planner must decompose WITHOUT hallucinating. We constrain it with a fixed taxonomy of question types:
  1. `technique_identification` — "What ATT&CK technique matches these observables?"
  2. `campaign_correlation` — "What known groups/campaigns use this technique?"
  3. `vulnerability_check` — "Are there known CVEs for the affected software?"
  4. `defense_recommendation` — "What D3FEND techniques mitigate this?"
  5. `historical_context` — "Have similar alerts been seen before?"

### Step 3.2: Agent 2 — KG Retriever

**What:** Translates each sub-question into CYPHER queries, executes them against Neo4j, returns structured evidence.
**How:** An LLM generates CYPHER queries from natural language questions, constrained by the KG schema.
**Knowledge needed:**
- CYPHER query language — complete the [Neo4j free course](https://graphacademy.neo4j.com/courses/cypher-fundamentals/) (~2 hours)
- Few-shot prompting — provide the LLM with 10-15 example (question → CYPHER) pairs
**Key design decision:** **Scope-limited retrieval.** Max 3-hop traversals to prevent the LLM from generating expensive queries. This is both a performance and a security constraint.

### Step 3.3: Agent 3 — Evidence Verifier

**What:** Takes each piece of KG evidence and computes a **grounding score** (0-1) indicating how relevant and reliable it is.
**How:** Rule-based + LLM hybrid:
- **Source trust:** ATT&CK/NVD data = 1.0, threat feed data = 0.7, inferred = 0.3
- **Relevance matching:** LLM scores how well the KG evidence matches the specific alert observables (0-1)
- **Freshness:** CVEs from last 2 years score higher than old ones
- **Final grounding score:** Weighted combination
**Knowledge needed:**
- Information retrieval relevance scoring — basic concept, no deep reading needed
**This is the core novelty:** Every fact gets a grounding score. The report generator uses these scores to distinguish grounded claims from uncertain ones.

### Step 3.4: Agent 4 — Report Generator

**What:** Synthesizes all verified evidence into a structured triage report with verifiable reasoning chains.
**How:** LLM generates a report following a strict template:
```
TRIAGE REPORT — Alert #12345
═══════════════════════════════════════
VERDICT: [ESCALATE / INVESTIGATE / DISMISS]  (Confidence: 0.87)

REASONING CHAIN:
1. Alert signature matches T1059.001 (PowerShell)
   [GROUNDED ✓ — KG path: Alert→matches→T1059.001, score: 0.95]
2. T1059.001 is commonly used by APT29
   [GROUNDED ✓ — KG path: APT29→uses→T1059.001, score: 0.92]
3. Target host runs Exchange Server which has CVE-2024-XXXX
   [UNCERTAIN ⚠ — No KG evidence linking this host to Exchange, score: 0.2]

RECOMMENDED ACTIONS:
- [D3FEND] Process Monitoring (D3-PM) on HOST-DC01
  [GROUNDED ✓ — KG path: D3-PM→mitigates→T1059.001]
```
**Knowledge needed:**
- Structured output from LLMs — [LangChain Structured Output docs](https://python.langchain.com/docs/modules/model_io/output_parsers/)

### Step 3.5: End-to-End Pipeline Integration

**What:** Wire all 4 agents together into `triage_pipeline.py`.
**How:** Sequential pipeline: Alert → Agent 1 → Agent 2 → Agent 3 → Agent 4 → Report
**Expected output:** Given any raw Suricata alert JSON, produce a complete triage report with grounding annotations in <30 seconds.

> [!IMPORTANT]
> **🎓 PROFESSOR CHECKPOINT #3:** Demo the working pipeline on 5 sample alerts. Show grounded vs. ungrounded claims. Ask: (1) Is the output format useful for a SOC analyst? (2) Is the grounding mechanism convincing? (3) Any concerns about the approach?

---

## Phase 4: Evaluation (Week 11-15)

> **Goal:** Rigorous experiments proving AttackRAG reduces hallucinations and improves triage quality.

### Step 4.1: Baseline Implementations

**What:** Build comparison systems.
**How:** I'll implement:
1. **Zero-shot LLM:** Same LLM, same alert, no RAG — just "triage this alert"
2. **Vanilla RAG:** Vector-store retrieval (embed ATT&CK descriptions in ChromaDB), no KG structure
3. **CoT prompting:** LLM with chain-of-thought prompt but no retrieval
4. **Ungrounded multi-agent:** Same 4 agents but without KG (Agent 2 skipped, Agent 3 auto-passes everything)
**Knowledge needed:** Understanding of RAG basics — read the [original RAG paper](https://arxiv.org/abs/2005.11401) abstract + Section 3

### Step 4.2: Hallucination Detection Experiment

**What:** Measure what % of claims in each system's output are hallucinated.
**How:** I'll build `hallucination.py` that:
- Extracts all factual claims from generated reports (ATT&CK technique references, CVE references, group attributions)
- Checks each claim against the KG ground truth
- Computes: `hallucination_rate = ungrounded_claims / total_claims`
**Expected result:** AttackRAG hallucination rate < 5%, zero-shot LLM > 40%, vanilla RAG ~20%

### Step 4.3: Triage Accuracy Experiment

**What:** Measure correct escalate/investigate/dismiss decisions.
**How:** Compare each system's verdict against CICIDS ground truth labels and DARPA TC attack annotations.
**Metrics:** Precision, Recall, F1 for each verdict class, overall accuracy.

### Step 4.4: Adversarial KG Poisoning Experiment

**What:** Test robustness when the KG contains injected false information (GRAGPOISON scenario).
**How:** I'll build `poisoning.py` that:
- Injects N% fake relationships (e.g., fake "APT29 uses T1234" links)
- Runs the pipeline on the same alerts
- Measures how many poisoned facts propagate into triage reports
- Tests our defense mechanisms (provenance tracking, consistency checking)
**Test conditions:** 1%, 5%, 10%, 20% poisoned edges
**Knowledge needed:** Read GRAGPOISON paper (from your reading list) to understand the attack model

### Step 4.5: Ablation Studies

**What:** Prove each component matters.
**How:** Remove one component at a time:
- Without Agent 3 (no evidence verification) — do hallucinations increase?
- Without D3FEND — do defensive recommendations disappear?
- Without CVE data — do vulnerability correlations disappear?
- With 1-hop vs 2-hop vs 3-hop retrieval — what's the quality/speed tradeoff?

### Step 4.6: Case Studies

**What:** Walk through 3 DARPA TC APT scenarios in detail showing the full reasoning chain.
**How:** Select 3 representative multi-stage attacks, show the pipeline's output for each alert in the chain, demonstrate how the system correctly identifies the campaign progression.
**This replaces the user study** — qualitative deep dives that demonstrate real-world value.

> [!IMPORTANT]
> **🎓 PROFESSOR CHECKPOINT #4:** Present all experimental results. Ask: (1) Are there missing experiments a reviewer would expect? (2) Are the results strong enough for S&P? (3) Any statistical concerns?

---

## Phase 5: Paper Writing (Week 12-22, overlapping with Phase 4)

> **Goal:** Write a camera-ready quality paper. We start writing DURING experiments, not after.

### Step 5.1: Week 12-13 — Introduction + Related Work

**What:** I'll draft these sections based on our positioning analysis.
**You review:** Does the narrative flow? Does your professor find the motivation compelling?

### Step 5.2: Week 14-15 — Threat Model + System Architecture

**What:** I'll draft Sections 2-3 with architecture diagrams.
**Key:** The threat model section must be precise — this is what makes it a security paper.

### Step 5.3: Week 16-17 — Evaluation

**What:** I'll build tables and figures from your experimental results.
**You review:** Are all numbers correct? Any experiments to re-run?

### Step 5.4: Week 18-19 — Discussion + Abstract

**What:** I'll draft the discussion (limitations, deployment, future work) and abstract.
**The abstract is written LAST** — after you know your exact results.

### Step 5.5: Week 20-22 — Polish

**What:** Full revision pass. Check IEEE S&P formatting requirements. Verify all citations.

> [!IMPORTANT]
> **🎓 PROFESSOR CHECKPOINT #5:** Full paper draft review. This is the most critical checkpoint. Budget 2 weeks for professor feedback and revisions.

---

## Phase 6: Submission (Week 23-26)

### Step 6.1: Internal revision from professor feedback
### Step 6.2: Format for IEEE S&P (double-column, references, page limit)
### Step 6.3: Prepare supplementary materials (code repo, KG snapshot)
### Step 6.4: Submit by November 10 (abstract) / November 17 (paper)

---

## Summary Timeline

```
May W1-2  ████ Phase 0: Read papers, learn technologies, setup repo
May W3-5  ██████ Phase 1: Build Knowledge Graph
Jun W5-7  ████ Phase 2: Prepare alert datasets
Jun-Jul   ████████ Phase 3: Build 4-agent pipeline
Aug-Sep   ████████ Phase 4: Run all experiments
Aug-Oct   ██████████████ Phase 5: Write paper (parallel with Phase 4)
Oct-Nov   ████████ Phase 6: Polish + submit
```

---

## My Additions (Things You Didn't Ask For But Need)

### 1. Version Control
Use Git from day 1. I'll set up the repo structure. Commit after every working step.

### 2. Experiment Logging
Every experiment run gets logged with: config, random seed, timestamp, results. I'll build this into the evaluation scripts. Reviewers may ask you to reproduce results.

### 3. LLM Choice Strategy
- **Development:** Llama-3-8B via Ollama (free, fast, iterative)
- **Final experiments:** Run with BOTH Llama-3-8B AND GPT-4o — report both. Reviewers love seeing open-source vs. proprietary comparison.
- **Budget:** ~$20-30 total for GPT-4o API calls during final experiments.

### 4. Writing Style
IEEE S&P papers are typically 13 pages (double-column) + references. Every sentence must be precise. I'll follow the style of KAIROS and ORTHRUS since they were accepted recently.

### 5. Code Release Plan
Open-source the KG construction + pipeline code on GitHub at submission time. This significantly increases reviewer goodwill and citation potential.

> [!TIP]
> **Ready to start?** Say the word and I'll begin with Phase 0 Step 0.3 — setting up the project structure and writing the data download scripts. Meanwhile, start reading KAIROS and GRAGPOISON (papers #1 and #4 from the reading list).
