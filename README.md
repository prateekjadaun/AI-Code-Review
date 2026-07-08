# PRO012 — AI-Powered Code Review Assistant

A GitHub-integrated tool that automatically reviews pull requests by detecting
code smells, security vulnerabilities, performance issues, and style violations
using fine-tuned CodeBERT and static analysis rules.

---

## Project Structure

```
ai_code_review/
├── dataset/
│   ├── generate_dataset.py       # Generates labeled training data
│   ├── code_review_dataset.json  # Full dataset (JSON)
│   └── code_review_dataset.csv   # Full dataset (CSV)
│
├── model/
│   └── train.py                  # CodeBERT fine-tuning + RuleBasedAnalyzer
│       ├── CodeReviewDataset     # PyTorch Dataset class
│       ├── CodeReviewTrainer     # Training / evaluation loop
│       ├── RuleBasedAnalyzer     # 13 regex-based detection rules
│       └── CombinedAnalyzer      # ML + Rules pipeline
│
├── github_app/
│   └── app.py                    # Flask webhook server (GitHub App)
│       ├── /webhook              # Receives pull_request events
│       ├── /analyze              # Direct REST API endpoint
│       └── /health               # Health check
│
├── frontend/
│   └── src/App.jsx               # React dashboard (Tailwind)
│
├── tests/
│   └── test_analyzer.py          # 38-test pytest suite
│
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate the dataset

```bash
python dataset/generate_dataset.py
```

### 3. Run the demo (rule-based analysis, no GPU needed)

```bash
python model/train.py
# or analyze a file:
python model/train.py --analyze your_script.py
```

### 4. Train the ML model (GPU recommended)

```bash
python model/train.py --train
```
Fine-tunes `microsoft/codebert-base` for ~5 epochs.
Saved to `model/saved_model/`.

### 5. Start the GitHub App server

```bash
cp .env.example .env
# fill in GITHUB_TOKEN and WEBHOOK_SECRET
python github_app/app.py
```

Expose via ngrok for webhook testing:
```bash
ngrok http 5000
# Set webhook URL in GitHub App settings: https://<ngrok-url>/webhook
```

### 6. Run tests

```bash
python -m pytest tests/ -v
```

---

## Dataset

| Label        | Count | Description                               |
|--------------|-------|-------------------------------------------|
| vulnerability | 17   | SQL injection, XSS, weak crypto, secrets  |
| clean         | 12   | Correct, secure implementations           |
| code_smell    |  8   | God functions, nesting, magic numbers     |
| performance   |  5   | N+1 queries, O(n²), missing cache         |
| style         |  3   | PEP 8, naming, long lines                 |

Each sample contains: `id`, `code`, `label`, `category`, `severity`, `message`, `fix`.

---

## Detection Rules (13 patterns)

| Rule ID | Category               | Severity |
|---------|------------------------|----------|
| SEC001  | sql_injection           | CRITICAL |
| SEC002  | xss                     | HIGH     |
| SEC003  | hardcoded_secrets       | CRITICAL |
| SEC004  | weak_crypto (MD5/SHA1)  | CRITICAL |
| SEC005  | command_injection        | CRITICAL |
| SEC006  | path_traversal          | HIGH     |
| SEC007  | insecure_deserialization| CRITICAL |
| SM001   | bare_except             | HIGH     |
| SM002   | magic_numbers           | LOW      |
| SM003   | todo_comment            | LOW      |
| PERF001 | n_plus_1_query          | HIGH     |
| ST001   | debug_print             | LOW      |

---

## ML Model

- **Base model:** `microsoft/codebert-base` (RoBERTa pre-trained on code)
- **Task:** 5-class sequence classification
- **Labels:** clean · code_smell · performance · style · vulnerability
- **Training:** AdamW + linear warmup, gradient clipping, 5 epochs
- **Inference:** CombinedAnalyzer merges ML predictions with rule findings

---

## API Reference

### POST /analyze

```json
{
  "code": "import hashlib\nhashlib.md5(x.encode())",
  "filename": "utils.py"
}
```

Response:
```json
{
  "file": "utils.py",
  "ml_prediction": { "label": "vulnerability", "confidence": 0.94 },
  "rule_findings": [
    {
      "rule_id": "SEC004",
      "category": "weak_crypto",
      "severity": "critical",
      "message": "MD5/SHA1 are broken for passwords...",
      "line": 2,
      "snippet": "hashlib.md5(x.encode())"
    }
  ],
  "overall_severity": "critical",
  "passed": false
}
```

---

## Tech Stack

| Layer      | Technology                      |
|------------|---------------------------------|
| ML Model   | Python, CodeBERT, Transformers  |
| Backend    | Flask, PyGitHub, requests       |
| Frontend   | React, Tailwind CSS             |
| Testing    | pytest (38 tests)               |
| Dataset    | JSON + CSV, 45 labeled samples  |
| GitHub     | Webhooks, PR Review Comments API|

---

## Team & Timeline

- **Team size:** 2 students
- **Duration:** 30 days
- **Difficulty:** High
- **Domain:** NLP / Developer Tools
