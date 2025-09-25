## Deception and Disruption

### Deception
- **Honeypots:** Fake systems designed to attract attackers and study techniques.
- **Honeyfiles / Honeytokens:** Fake files or credentials planted to detect unauthorized access.
- **DNS Sinkholes:** Redirect malicious domain requests to a controlled system for analysis.
- **Tarpits:** Deliberately slow down attacker connections.

### Disruption
- **Active defense measures** that interfere with attacks in progress.
- Examples: Blocking malicious IP addresses, sinkholing botnet traffic, throttling suspicious requests.

**SOC Relevance:**
- Honeypot alerts can act as early-warning systems for attacker presence.
- Sinkhole logs help identify infected devices calling out to malicious domains.
- Disruption techniques are common in incident response playbooks.
