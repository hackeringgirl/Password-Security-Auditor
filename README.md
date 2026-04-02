# 🔐 Password Security Auditor

A cybersecurity tool that analyzes password strength, detects common/breached passwords, calculates entropy, and provides security recommendations.

## 📌 Project Overview

Weak passwords are the #1 cause of account breaches. This auditor helps individuals and organizations evaluate password security across their systems.

## 🧠 What I Built

- Analyzed 80+ passwords across strength categories
- Built a multi-factor scoring engine (length, character variety, patterns, entropy)
- Detected common/breached passwords from a known-bad list
- Calculated cryptographic entropy for each password
- Generated actionable security recommendations

## 🔑 Scoring Criteria

| Check | Points |
|-------|--------|
| Length ≥ 8 | +1 |
| Length ≥ 12 | +1 |
| Length ≥ 16 | +1 |
| Has uppercase | +1 |
| Has lowercase | +1 |
| Has digit | +1 |
| Has special char | +2 |
| Common/breached | -3 |
| Repeated chars (aaa) | -1 |
| Sequential (123, abc) | -1 |

## 📊 Strength Levels

| Level | Score | Example |
|-------|-------|---------|
| Very Weak | 0–2 | `123456`, `password` |
| Weak | 3–4 | `manya123`, `Summer2020` |
| Moderate | 5–6 | `manyaV@2024` |
| Strong | 7 | `Tr0ub4dor&3` |
| Very Strong | 8 | `T$r4&uB8#mL2!qP9` |

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python | Core language |
| Pandas | Data analysis |
| Regex | Pattern detection |
| Math | Entropy calculation |
| Matplotlib | Dashboard |

## 📁 Files

```
09-password-auditor/
├── password_security_auditor.py    # Main auditor script
├── password_audit_results.csv      # Audit results
├── password_audit_dashboard.png    # Visual dashboard
└── README.md
```

## 🚀 How to Run

```bash
pip install pandas numpy matplotlib seaborn
python password_security_auditor.py
```

## 🔍 Sample Output

```
[████████] Very Strong | Entropy: 104.2 bits | Xp7@Lm#9Kz$2Wn5!
[█████░░░] Moderate    | Entropy:  52.1 bits | M@nya#2024!
[██░░░░░░] Weak        | Entropy:  28.5 bits | manya123
[░░░░░░░░] Very Weak   | Entropy:  18.9 bits | Admin@123
```

## 💡 Key Insight

Entropy > 60 bits = secure against brute force. Entropy < 30 bits = crackable in minutes with modern hardware.

## 👩‍💻 Author

**hackeringgirl** — Built as part of my Data Analytics & Cybersecurity portfolio
