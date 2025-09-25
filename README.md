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

## Change Management

### Definition
Change management is a structured approach to ensure system changes are reviewed, tested, approved, and documented before being implemented.

### Key Steps
1. **Request for Change (RFC):** Submit change proposal.
2. **Review/Approval:** Evaluate risks, business impact, and security concerns.
3. **Testing:** Simulate in staging or test environment.
4. **Implementation:** Apply during maintenance/change window.
5. **Documentation:** Record all changes.
6. **Review/Closure:** Confirm success, rollback if needed.

### Example Changes
- Adding new firewall rules
- Applying security patches
- Updating SIEM software
- Deploying new VPN configurations

**SOC Relevance:**
- Helps SOC analysts distinguish between expected vs. unexpected alerts.
- Reduces risk of downtime or misconfiguration leading to vulnerabilities.
- Provides audit trail for investigations.

- ## Technical Change Management

### Definition
Technical change management ensures that updates to systems, networks, and security controls are carefully planned, tested, approved, and documented.

### Examples of Technical Changes
- Firewall rule modifications (e.g., opening port 443 for a new web app)
- Operating system and application patches
- Network reconfigurations (VLANs, routing, VPNs)
- Security software updates (antivirus signatures, IDS rules)
- Log configuration changes in SIEM

### Best Practices
1. Assess impact and risk before changes.
2. Test in staging environment first.
3. Require formal approval (CAB or management).
4. Schedule during maintenance windows.
5. Prepare rollback procedures.
6. Document for auditing and SOC visibility.

**SOC Relevance:**
- Analysts use change logs to validate whether new alerts are legitimate or expected.
- Prevents false positives (e.g., new firewall rule causing unusual traffic).
- Provides accountability and reduces misconfiguration risks.

