# AttackRAG

**Grounding Integrity: Verifiable LLM-Based Intrusion Alert Triage via Security Knowledge Graphs**

Target venue: IEEE S&P 2027 Cycle 2 (November 17, 2026)

## Setup

```bash
conda activate attackrag
pip install -r requirements.txt
```

## Project Structure

```
AttackRAG/
├── src/
│   ├── kg/           # Phase 1: Security Knowledge Graph construction
│   ├── alerts/       # Phase 2: IDS alert preprocessing
│   ├── agents/       # Phase 3: 4-agent triage pipeline
│   ├── gi/           # Grounding Integrity scoring framework
│   ├── pipeline/     # End-to-end orchestration
│   └── evaluation/   # Experiment runners
├── data/
│   ├── raw/          # Downloaded source data (gitignored)
│   └── processed/    # Preprocessed data
├── experiments/      # Experiment configs and results
├── paper/            # LaTeX paper
├── docs/             # Documentation for each component
└── scripts/          # Utility scripts
```
