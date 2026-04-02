"""
Password Security Auditor
==========================
Analyzes password strength, detects weak/common passwords,
and provides security recommendations.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re
import math
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

# ── 1. COMMON WEAK PASSWORDS LIST ────────────────────────────────────────────

COMMON_PASSWORDS = {
    'password', '123456', '12345678', 'password1', 'qwerty', 'abc123',
    'letmein', 'monkey', 'master', 'dragon', 'pass', '1234', '12345',
    '123456789', 'welcome', 'login', 'admin', 'iloveyou', 'sunshine',
    'princess', 'football', 'hello', 'charlie', 'donald', 'password123',
    'admin123', 'test123', 'india123', 'pass123', 'qwerty123'
}

# ── 2. PASSWORD STRENGTH ANALYZER ────────────────────────────────────────────

def calculate_entropy(password):
    """Calculate password entropy (bits)"""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:,.<>?/\\|`~]', password): charset += 32
    if charset == 0:
        return 0
    return len(password) * math.log2(charset)

def analyze_password(password):
    result = {
        'password': password,
        'length': len(password),
        'has_uppercase': bool(re.search(r'[A-Z]', password)),
        'has_lowercase': bool(re.search(r'[a-z]', password)),
        'has_digit': bool(re.search(r'\d', password)),
        'has_special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:,.<>?]', password)),
        'is_common': password.lower() in COMMON_PASSWORDS,
        'has_repeat_chars': bool(re.search(r'(.)\1{2,}', password)),  # 3+ same chars
        'has_sequential': bool(re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def)', password.lower())),
        'entropy': round(calculate_entropy(password), 2),
    }

    # Strength scoring
    score = 0
    if result['length'] >= 8: score += 1
    if result['length'] >= 12: score += 1
    if result['length'] >= 16: score += 1
    if result['has_uppercase']: score += 1
    if result['has_lowercase']: score += 1
    if result['has_digit']: score += 1
    if result['has_special']: score += 2
    if result['is_common']: score -= 3
    if result['has_repeat_chars']: score -= 1
    if result['has_sequential']: score -= 1

    score = max(0, min(score, 8))
    if score <= 2:
        result['strength'] = 'Very Weak'
        result['strength_score'] = score
    elif score <= 4:
        result['strength'] = 'Weak'
        result['strength_score'] = score
    elif score <= 6:
        result['strength'] = 'Moderate'
        result['strength_score'] = score
    elif score <= 7:
        result['strength'] = 'Strong'
        result['strength_score'] = score
    else:
        result['strength'] = 'Very Strong'
        result['strength_score'] = score

    return result

# ── 3. SAMPLE PASSWORD DATASET ───────────────────────────────────────────────

sample_passwords = [
    # Very Weak
    '123456', 'password', 'qwerty', 'abc123', 'letmein', 'admin', '12345',
    'pass', 'hello', 'test', 'monkey', 'dragon', 'india123',
    # Weak
    'john1990', 'tanya123', 'summer2020', 'football1', 'Passw0rd',
    'Company1', 'January1', 'Password1',
    # Moderate
    'TanyaV@2024', 'J@nuary#01', 'S3cur3Pass', 'Blue$ky99',
    'Admin@2024', 'NetWork#7', 'MyPass#88',
    # Strong
    'Tr0ub4dor&3', 'C0rrect#Horse7', 'P@ssw0rd!23X', 'Xk9$mNpQ!2',
    'Gy5#mLpW@8', 'Bx7!nKqP#4',
    # Very Strong
    'T$r4&uB8#mL2!qP9', 'Xp7@Lm#9Kz$2Wn5!',
    'G3n3r@t3d$3cur3P@ss!', '#Tr0ub4dor&3-C0rrect',
    'K8$pQmN#4LxZ@7wR!',
]

# Also generate some programmatically
np.random.seed(42)
chars_weak = 'abcdefghijklmnop0123456789'
chars_strong = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789!@#$%^&*()'

for _ in range(30):
    length = np.random.randint(4, 8)
    sample_passwords.append(''.join(np.random.choice(list(chars_weak), length)))

for _ in range(20):
    length = np.random.randint(12, 20)
    sample_passwords.append(''.join(np.random.choice(list(chars_strong), length)))

# Analyze all passwords
results = [analyze_password(p) for p in sample_passwords]
df = pd.DataFrame(results)
df.to_csv('password_audit_results.csv', index=False)

print("✅ Password Audit Complete!")
print(f"\nPasswords Analyzed: {len(df)}")
print("\nStrength Distribution:")
print(df['strength'].value_counts())
print(f"\nCommon/Breached Passwords Found: {df['is_common'].sum()}")

# ── 4. VISUALIZATIONS ────────────────────────────────────────────────────────

fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Password Security Auditor Dashboard', fontsize=16, fontweight='bold')

# 4a. Strength Distribution
strength_order = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong']
strength_colors = ['#F44336', '#FF5722', '#FF9800', '#8BC34A', '#4CAF50']
strength_counts = df['strength'].value_counts().reindex(strength_order, fill_value=0)
axes[0, 0].bar(strength_counts.index, strength_counts.values, color=strength_colors, alpha=0.85)
axes[0, 0].set_title('Password Strength Distribution')
axes[0, 0].set_xlabel('Strength Level')
axes[0, 0].set_ylabel('Count')
axes[0, 0].tick_params(axis='x', rotation=20)
for i, v in enumerate(strength_counts.values):
    axes[0, 0].text(i, v + 0.3, str(v), ha='center', fontweight='bold')

# 4b. Password Length Distribution
axes[0, 1].hist(df['length'], bins=20, color='#2196F3', edgecolor='white', alpha=0.85)
axes[0, 1].axvline(x=8, color='orange', linestyle='--', linewidth=2, label='Min recommended (8)')
axes[0, 1].axvline(x=12, color='green', linestyle='--', linewidth=2, label='Good length (12)')
axes[0, 1].set_title('Password Length Distribution')
axes[0, 1].set_xlabel('Password Length (characters)')
axes[0, 1].set_ylabel('Count')
axes[0, 1].legend()

# 4c. Security Issues
issues = {
    'Common/Breached': df['is_common'].sum(),
    'No Uppercase': (~df['has_uppercase']).sum(),
    'No Digit': (~df['has_digit']).sum(),
    'No Special Char': (~df['has_special']).sum(),
    'Repeated Chars': df['has_repeat_chars'].sum(),
    'Sequential Pattern': df['has_sequential'].sum(),
    'Length < 8': (df['length'] < 8).sum(),
}
axes[1, 0].barh(list(issues.keys())[::-1], list(issues.values())[::-1],
                color='#F44336', alpha=0.85)
axes[1, 0].set_title('Security Issues Found')
axes[1, 0].set_xlabel('Number of Passwords Affected')

# 4d. Entropy by Strength
strength_entropy = df.groupby('strength')['entropy'].mean().reindex(strength_order, fill_value=0)
axes[1, 1].bar(strength_entropy.index, strength_entropy.values, color=strength_colors, alpha=0.85)
axes[1, 1].set_title('Average Entropy by Strength Level')
axes[1, 1].set_xlabel('Strength Level')
axes[1, 1].set_ylabel('Entropy (bits)')
axes[1, 1].tick_params(axis='x', rotation=20)
for i, v in enumerate(strength_entropy.values):
    axes[1, 1].text(i, v + 0.5, f'{v:.1f}', ha='center', fontweight='bold')

plt.tight_layout()
plt.savefig('password_audit_dashboard.png', dpi=150, bbox_inches='tight')
print("\n✅ Dashboard saved as password_audit_dashboard.png")
plt.show()

# ── 5. SECURITY RECOMMENDATIONS ──────────────────────────────────────────────

print("\n" + "="*60)
print("🔐 PASSWORD SECURITY RECOMMENDATIONS")
print("="*60)
print("""
✅ DO:
  • Use at least 12 characters
  • Mix uppercase, lowercase, digits & special characters
  • Use passphrases: "BlueSky@Mango!2024" is strong & memorable
  • Use a password manager (Bitwarden, 1Password, KeePass)
  • Enable Two-Factor Authentication (2FA) everywhere

❌ DON'T:
  • Never use: name + birth year (tanya1998), dictionary words
  • Never reuse passwords across multiple accounts
  • Never share passwords via WhatsApp or email
  • Never use keyboard patterns (qwerty, asdfgh, 123456)
""")

# Quick check example
print("="*60)
print("🔍 QUICK PASSWORD CHECK")
print("="*60)
test = ['tanya123', 'T@nya#2024!', 'Admin@123', 'Xp7@Lm#9Kz$2Wn5!']
for pwd in test:
    r = analyze_password(pwd)
    bars = '█' * r['strength_score'] + '░' * (8 - r['strength_score'])
    print(f"[{bars}] {r['strength']:<12} | Entropy: {r['entropy']:>5.1f} bits | {pwd}")
