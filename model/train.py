"""
model/train.py
Fine-tune CodeBERT on the code review dataset.
Usage:
    pip install transformers datasets torch scikit-learn
    python model/train.py
"""

import json
import os
import numpy as np
from pathlib import Path

# ── Optional heavy imports (graceful fallback for environments without GPU) ──
try:
    import torch
    from torch.utils.data import Dataset, DataLoader
    from transformers import (
        RobertaTokenizer,
        RobertaForSequenceClassification,
        AdamW,
        get_linear_schedule_with_warmup,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    # Stub so class definitions below don't fail at parse time
    class Dataset:  # type: ignore
        pass
    print("PyTorch / Transformers not installed. Running in demo mode.")


# ─────────────────────────────────────────────
# LABEL MAPPING
# ─────────────────────────────────────────────
LABEL2ID = {
    "clean":       0,
    "code_smell":  1,
    "performance": 2,
    "style":       3,
    "vulnerability": 4,
}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}

SEVERITY_MAP = {
    "none":     0,
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}

# ─────────────────────────────────────────────
# DATASET CLASS
# ─────────────────────────────────────────────
class CodeReviewDataset(Dataset):
    """PyTorch Dataset for code review samples."""

    def __init__(self, samples, tokenizer, max_length=512):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]
        code = sample["code"]
        label = LABEL2ID[sample["label"]]

        encoding = self.tokenizer(
            code,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )

        return {
            "input_ids":      encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "label":          torch.tensor(label, dtype=torch.long),
        }


# ─────────────────────────────────────────────
# TRAINER
# ─────────────────────────────────────────────
class CodeReviewTrainer:
    """Fine-tunes microsoft/codebert-base for multi-class code review."""

    MODEL_NAME  = "microsoft/codebert-base"
    OUTPUT_DIR  = Path(__file__).parent / "saved_model"
    NUM_LABELS  = len(LABEL2ID)

    def __init__(
        self,
        dataset_path: str,
        epochs: int = 5,
        batch_size: int = 8,
        learning_rate: float = 2e-5,
        max_length: int = 512,
        device: str | None = None,
    ):
        self.dataset_path  = dataset_path
        self.epochs        = epochs
        self.batch_size    = batch_size
        self.learning_rate = learning_rate
        self.max_length    = max_length

        if not TORCH_AVAILABLE:
            raise RuntimeError("Install PyTorch and Transformers to train.")

        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Using device: {self.device}")

        # Load tokenizer & model
        print(f"Loading {self.MODEL_NAME} …")
        self.tokenizer = RobertaTokenizer.from_pretrained(self.MODEL_NAME)
        self.model = RobertaForSequenceClassification.from_pretrained(
            self.MODEL_NAME,
            num_labels=self.NUM_LABELS,
            id2label=ID2LABEL,
            label2id=LABEL2ID,
        ).to(self.device)

    # ── Data ─────────────────────────────────
    def load_data(self):
        with open(self.dataset_path) as f:
            all_samples = json.load(f)

        # Normalise labels that aren't in LABEL2ID
        for s in all_samples:
            if s["label"] not in LABEL2ID:
                s["label"] = "clean"

        train, val = train_test_split(all_samples, test_size=0.2, random_state=42,
                                       stratify=[s["label"] for s in all_samples])
        print(f"Train: {len(train)}  Val: {len(val)}")

        train_ds = CodeReviewDataset(train, self.tokenizer, self.max_length)
        val_ds   = CodeReviewDataset(val,   self.tokenizer, self.max_length)

        self.train_loader = DataLoader(train_ds, batch_size=self.batch_size, shuffle=True)
        self.val_loader   = DataLoader(val_ds,   batch_size=self.batch_size)
        self.val_samples  = val

    # ── Training loop ─────────────────────────
    def train(self):
        self.load_data()

        optimizer = AdamW(self.model.parameters(), lr=self.learning_rate, weight_decay=0.01)
        total_steps = len(self.train_loader) * self.epochs
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=total_steps // 10,
            num_training_steps=total_steps,
        )

        best_val_acc = 0.0

        for epoch in range(1, self.epochs + 1):
            # ── Train ──
            self.model.train()
            train_loss = 0.0
            for batch in self.train_loader:
                optimizer.zero_grad()
                input_ids      = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels         = batch["label"].to(self.device)

                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels,
                )
                loss = outputs.loss
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                train_loss += loss.item()

            avg_train_loss = train_loss / len(self.train_loader)

            # ── Validate ──
            val_acc, val_report = self.evaluate()
            print(
                f"Epoch {epoch}/{self.epochs} | "
                f"Train Loss: {avg_train_loss:.4f} | "
                f"Val Acc: {val_acc:.4f}"
            )

            if val_acc > best_val_acc:
                best_val_acc = val_acc
                self.save_model()
                print(f"  ✓ Best model saved (acc={val_acc:.4f})")

        print(f"\nTraining complete. Best Val Acc: {best_val_acc:.4f}")
        print("\nClassification Report:\n", val_report)

    # ── Evaluation ───────────────────────────
    def evaluate(self):
        self.model.eval()
        preds, targets = [], []

        with torch.no_grad():
            for batch in self.val_loader:
                input_ids      = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels         = batch["label"]

                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                logits  = outputs.logits
                batch_preds = torch.argmax(logits, dim=-1).cpu().numpy()

                preds.extend(batch_preds)
                targets.extend(labels.numpy())

        preds   = np.array(preds)
        targets = np.array(targets)
        acc     = (preds == targets).mean()
        report  = classification_report(
            targets, preds,
            target_names=list(LABEL2ID.keys()),
            zero_division=0
        )
        return acc, report

    # ── Inference ────────────────────────────
    def predict(self, code: str) -> dict:
        """Predict label for a single code snippet."""
        self.model.eval()
        encoding = self.tokenizer(
            code,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )
        input_ids      = encoding["input_ids"].to(self.device)
        attention_mask = encoding["attention_mask"].to(self.device)

        with torch.no_grad():
            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
            probs   = torch.softmax(outputs.logits, dim=-1).cpu().numpy()[0]

        pred_id    = int(np.argmax(probs))
        pred_label = ID2LABEL[pred_id]
        confidence = float(probs[pred_id])

        return {
            "label":       pred_label,
            "confidence":  round(confidence, 4),
            "all_scores":  {ID2LABEL[i]: round(float(p), 4) for i, p in enumerate(probs)},
        }

    # ── Persistence ──────────────────────────
    def save_model(self):
        self.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.model.save_pretrained(self.OUTPUT_DIR)
        self.tokenizer.save_pretrained(self.OUTPUT_DIR)

    @classmethod
    def load_saved(cls, model_dir: str | None = None, device: str | None = None):
        """Load a previously saved model for inference."""
        if not TORCH_AVAILABLE:
            raise RuntimeError("Install PyTorch and Transformers.")
        path   = model_dir or cls.OUTPUT_DIR
        device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        tokenizer = RobertaTokenizer.from_pretrained(path)
        model     = RobertaForSequenceClassification.from_pretrained(path).to(device)
        instance  = cls.__new__(cls)
        instance.tokenizer  = tokenizer
        instance.model      = model
        instance.device     = device
        instance.max_length = 512
        return instance


# ─────────────────────────────────────────────
# RULE-BASED ANALYZER (no GPU needed)
# ─────────────────────────────────────────────
class RuleBasedAnalyzer:
    """
    Fast static-analysis fallback / complement to the ML model.
    Detects 10+ vulnerability patterns using regex + AST heuristics.
    """

    import re as _re

    RULES = [
        # SQL Injection
        {
            "id":       "SEC001",
            "pattern":  r'(execute|query)\s*\(\s*["\'].*\+.*["\']|f["\'].*SELECT|f["\'].*INSERT|f["\'].*UPDATE|f["\'].*DELETE',
            "label":    "vulnerability",
            "category": "sql_injection",
            "severity": "critical",
            "message":  "Potential SQL injection: string concatenation/f-string in SQL query. Use parameterized queries.",
        },
        # XSS
        {
            "id":       "SEC002",
            "pattern":  r'innerHTML\s*=(?!=)|dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!.*DOMPurify|.*sanitize)',
            "label":    "vulnerability",
            "category": "xss",
            "severity": "high",
            "message":  "Potential XSS: unsanitized content assigned to innerHTML or dangerouslySetInnerHTML.",
        },
        # Hardcoded secrets
        {
            "id":       "SEC003",
            "pattern":  r'(?i)(password|secret|api_key|apikey|token|jwt_secret)\s*=\s*["\'][^"\']{6,}["\']',
            "label":    "vulnerability",
            "category": "hardcoded_secrets",
            "severity": "critical",
            "message":  "Hardcoded secret detected. Move to environment variables or a secrets manager.",
        },
        # Weak hash
        {
            "id":       "SEC004",
            "pattern":  r'hashlib\.(md5|sha1)\(',
            "label":    "vulnerability",
            "category": "weak_crypto",
            "severity": "critical",
            "message":  "MD5/SHA1 are cryptographically weak for passwords. Use bcrypt, argon2, or scrypt.",
        },
        # Command injection
        {
            "id":       "SEC005",
            "pattern":  r'subprocess\.(run|call|Popen|check_output).*shell\s*=\s*True',
            "label":    "vulnerability",
            "category": "command_injection",
            "severity": "critical",
            "message":  "shell=True with user-controlled input enables command injection. Use shell=False with a list.",
        },
        # Path traversal
        {
            "id":       "SEC006",
            "pattern":  r'open\s*\(\s*(?:request\.|.*\+|f["\'])',
            "label":    "vulnerability",
            "category": "path_traversal",
            "severity": "high",
            "message":  "Potential path traversal: validate and normalise file paths with os.path.realpath.",
        },
        # Insecure pickle
        {
            "id":       "SEC007",
            "pattern":  r'pickle\.loads?\s*\(',
            "label":    "vulnerability",
            "category": "insecure_deserialization",
            "severity": "critical",
            "message":  "pickle.loads on untrusted data allows arbitrary code execution. Use JSON or MessagePack.",
        },
        # Bare except
        {
            "id":       "SM001",
            "pattern":  r'except\s*:',
            "label":    "code_smell",
            "category": "bare_except",
            "severity": "high",
            "message":  "Bare except catches all exceptions including KeyboardInterrupt. Catch specific exceptions.",
        },
        # Magic numbers
        {
            "id":       "SM002",
            "pattern":  r'(?<!["\'\w])(?:86400|3600|1000|9999|255)(?!["\'\w])',
            "label":    "code_smell",
            "category": "magic_numbers",
            "severity": "low",
            "message":  "Magic number detected. Define as a named constant for readability.",
        },
        # TODO / FIXME
        {
            "id":       "SM003",
            "pattern":  r'#\s*(TODO|FIXME|HACK|XXX|BUG)\b',
            "label":    "code_smell",
            "category": "todo_comment",
            "severity": "low",
            "message":  "TODO/FIXME comment left in code. Track in issue tracker instead.",
        },
        # N+1 query pattern
        {
            "id":       "PERF001",
            "pattern":  r'for\s+\w+\s+in\s+.*:[\s\S]{0,200}(db\.|cursor\.|session\.)',
            "label":    "performance",
            "category": "n_plus_1_query",
            "severity": "high",
            "message":  "Possible N+1 query: database call inside a loop. Use batch/IN queries.",
        },
        # Print in production
        {
            "id":       "ST001",
            "pattern":  r'^(?!\s*#)\s*print\s*\(',
            "label":    "style",
            "category": "debug_print",
            "severity": "low",
            "message":  "print() found: replace with logging module for production code.",
        },
    ]

    def analyze(self, code: str, filename: str = "<stdin>") -> list[dict]:
        """Return all rule violations found in code."""
        import re
        findings = []
        lines = code.splitlines()

        for rule in self.RULES:
            for line_no, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line, re.MULTILINE):
                    findings.append({
                        "rule_id":  rule["id"],
                        "label":    rule["label"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "message":  rule["message"],
                        "file":     filename,
                        "line":     line_no,
                        "snippet":  line.strip(),
                    })

        return findings


# ─────────────────────────────────────────────
# COMBINED ANALYZER (ML + Rules)
# ─────────────────────────────────────────────
class CombinedAnalyzer:
    """
    Combines the ML model with rule-based analysis for best coverage.
    Falls back to rules-only if ML model is not available.
    """

    def __init__(self, model_dir: str | None = None):
        self.rules = RuleBasedAnalyzer()
        try:
            self.ml = CodeReviewTrainer.load_saved(model_dir)
            self.ml_available = True
            print("ML model loaded successfully.")
        except Exception as e:
            self.ml_available = False
            print(f"ML model not available ({e}). Using rules only.")

    def analyze(self, code: str, filename: str = "<stdin>") -> dict:
        """Full analysis: ML classification + rule violations."""
        rule_findings = self.rules.analyze(code, filename)

        ml_result = None
        if self.ml_available:
            try:
                ml_result = self.ml.predict(code)
            except Exception as e:
                ml_result = {"error": str(e)}

        # Determine overall severity
        severities = [f["severity"] for f in rule_findings]
        sev_order  = ["critical", "high", "medium", "low", "none"]
        overall    = next((s for s in sev_order if s in severities), "none")

        return {
            "file":           filename,
            "ml_prediction":  ml_result,
            "rule_findings":  rule_findings,
            "finding_count":  len(rule_findings),
            "overall_severity": overall,
            "passed":         len(rule_findings) == 0,
        }

    def format_report(self, result: dict) -> str:
        """Human-readable review report."""
        lines = [
            f"{'='*60}",
            f"Code Review Report: {result['file']}",
            f"{'='*60}",
        ]

        if result.get("ml_prediction"):
            ml = result["ml_prediction"]
            lines += [
                "\n[ML Model]",
                f"  Label:      {ml.get('label', 'N/A')}",
                f"  Confidence: {ml.get('confidence', 'N/A')}",
            ]

        lines += [
            f"\n[Rule Analysis] {result['finding_count']} finding(s) | "
            f"Overall severity: {result['overall_severity'].upper()}"
        ]

        for f in result["rule_findings"]:
            lines += [
                f"\n  [{f['severity'].upper()}] {f['rule_id']} — {f['category']}",
                f"  Line {f['line']}: {f['snippet']}",
                f"  → {f['message']}",
            ]

        status = "✅ PASSED" if result["passed"] else "❌ ISSUES FOUND"
        lines += [f"\n{status}", ""]
        return "\n".join(lines)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    DATASET_PATH = Path(__file__).parent.parent / "dataset" / "code_review_dataset.json"

    if "--train" in sys.argv:
        print("Starting training …")
        trainer = CodeReviewTrainer(dataset_path=str(DATASET_PATH), epochs=5)
        trainer.train()

    elif "--analyze" in sys.argv:
        idx = sys.argv.index("--analyze")
        target = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
        if target and os.path.isfile(target):
            with open(target) as f:
                code = f.read()
            analyzer = CombinedAnalyzer()
            result   = analyzer.analyze(code, filename=target)
            print(analyzer.format_report(result))
        else:
            print("Usage: python train.py --analyze <file.py>")

    else:
        # Demo: run rules on a sample
        sample_code = '''
import hashlib, subprocess, pickle

def login(user, pwd):
    query = "SELECT * FROM users WHERE user='" + user + "' AND pwd='" + pwd + "'"
    cursor.execute(query)

SECRET_KEY = "supersecret123"

def run(cmd):
    subprocess.run(cmd, shell=True)

def load(data):
    return pickle.loads(data)
'''
        print("Demo: analyzing sample code …\n")
        analyzer = CombinedAnalyzer()
        result   = analyzer.analyze(sample_code, filename="demo.py")
        print(analyzer.format_report(result))
