# Contributing to Aiglos

  The detection engine is open. The CVE database is open. Contributions are welcome.

  ## Ways to contribute

  **Add a rule family.** If you find an attack pattern not covered by T1–T36, open an issue describing the threat, the tool call vector, and a proof of concept. Well-documented submissions get a rule family and a CVE credit.

  **Improve an existing rule.** False positives, missed patterns, and CVSS scoring disputes are all valid issues. Open an issue with reproduction steps.

  **File a CVE.** See <SECURITY.md>. Every confirmed CVE against an MCP-based agent runtime gets a corresponding Aiglos rule.

  **Improve the attestation format.** The artifact schema is in `/aiglos/attest/schema.json`. If you work with SOC 2, CMMC, or FedRAMP auditors and have feedback on the format, open an issue.

  ## Setup

  ```bash
  git clone https://github.com/aiglos/aiglos
  cd aiglos
  pip install -e ".[dev]"
  pytest tests/
  ```

  ## Submitting a rule family

  1. Fork the repo
  1. Add your rule under `/aiglos/rules/T{XX}_{NAME}.py`
  1. Add tests under `/tests/test_T{XX}.py`
  1. Open a PR with: threat description, attack example, CVSS estimate, and affected frameworks
  1. Link any related CVE or public disclosure

  ## Code standards

  - Python 3.9+
  - Type hints on all public functions
  - Tests must pass before merge: `pytest tests/ -v`
  - No external dependencies in the detection engine (stdlib + regex only)

  ## License

  Contributions to the detection engine and CVE database are MIT licensed.
  The attestation layer, cloud dashboard, and compliance reporting are proprietary and not open for contribution.
  