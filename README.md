# Bluefin
I built the firewall as a single Python file, banksim_firewall.py. It has no dependencies, and its 22 built-in tests all pass (run python banksim_firewall.py).
How it works;
1.Normalize: it folds Unicode, strips zero-width characters, and flags mixed-script homoglyphs (e.g. a Cyrillic "і" in "ignore").
2.Threat scan: weighted regex rules cover injection, jailbreak, roleplay, privilege escalation, tool abuse, exfiltration, encoding evasion, and memo smuggling. The scan runs on the whole input, so memos are covered, and it also runs on de-leeted text, so "1gn0re" is caught.
3.Allowlist grammar: only strictly matched balance checks and transfers can be approved. Everything else is denied by default.
4.Transfer policy: amounts must be positive and at most $10,000. Reserved payees like "admin" are rejected. Memos are data-only: at most 40 characters, a restricted charset, and at most 8 words.
5.Fail closed: any exception returns BLOCKED.
The output is deterministic JSON with status, risk_score, threat_category, and explanation. It also includes intent and a sanitized route (tool name and parsed args) for approved requests only.
Limitations ;
•Regex rules can't catch every paraphrase. The allowlist grammar is the real safety net, because novel attacks still fail to match and get blocked.
•Homoglyph-only inputs are currently denied under the AMBIGUOUS_INPUT category rather than ENCODING_EVASION.
