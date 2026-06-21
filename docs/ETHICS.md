# Ethics & Responsible Use

This project is a **defensive** tool. It exists to help people understand
how prompt-injection attacks are constructed, encoded, and chained — so
that they can build better defences. It is not, and never has been,
intended as an offensive tool.

## What this honeypot does

- Simulates a vulnerable LLM-powered endpoint.
- **Never** follows injected instructions. Always returns a canned refusal
  for any prompt that the classifier tags as an attack.
- Records what attackers try.
- Provides a dashboard for the operator to study patterns.

## What this honeypot does NOT do

- It does not generate weaponized payloads. The `samples/payloads.md`
  catalog documents *categories* of attack, not novel exploits.
- It does not target real users. The `/v1/support` endpoint should be
  deployed only on networks where you have permission to operate, or
  on the public internet as a deliberate decoy.
- It does not exfiltrate anything. All telemetry stays local to the
  operator's SQLite + JSONL files.
- It does not call any external LLM API. The "LLM response" is a
  canned helpful reply or a canned refusal.

## If you deploy this on the public internet

You accept responsibility for:

- The bandwidth costs of being a public decoy.
- Any abuse reports that result from your IP hosting the endpoint.
- The operator obligations under your jurisdiction's computer-misuse
  laws (don't analyse traffic you collect in a way that re-victimises
  the attacker — anonymise aggressively before publishing).
- Not using the data you collect for any kind of profiling, doxxing, or
  retaliation against the attacker.

## Reporting findings

If your honeypot captures something novel — a new technique, a new
encoding trick — please consider contributing it to:

- The OWASP GenAI Security Project
  <https://genai.owasp.org/>
- The `garak` red-team probe library
  <https://github.com/NVIDIA/garak>
- Your favourite public red-team dataset (HarmBench, AdvBench, etc.)

Open an issue or PR on this repo if you have a pattern that the
classifier should be detecting but isn't — that's how the ruleset
improves.

## License

MIT. See `LICENSE`. There is no warranty. The authors are not liable
for misuse.

— Mohit Dholakiya, 2026