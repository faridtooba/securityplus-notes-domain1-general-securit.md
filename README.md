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

## Public Key Infrastructure (PKI)

### Definition
PKI is a framework of hardware, software, policies, and procedures that manage digital certificates and public-key encryption.

### Core Components
- **Certificate Authority (CA):** Issues trusted certificates.
- **Registration Authority (RA):** Verifies identities before certs are issued.
- **Certificates:** Bind a public key to an entity (user, server, org).
- **CRL (Certificate Revocation List):** Maintains list of revoked certs.
- **OCSP (Online Certificate Status Protocol):** Provides real-time cert validation.
- **Key Escrow / Recovery Agent:** Holds backup keys for recovery.

### Certificate Types
- **Root CA** – the top of the trust chain
- **Intermediate CA** – links the root to end-entity certs
- **End-Entity Certificates** – used by servers or users (e.g., HTTPS, email)

### SOC Relevance
- Analysts monitor logs for:
  - Expired or revoked certificates
  - TLS handshake failures
  - Untrusted or self-signed certificates
- PKI is critical for HTTPS, VPNs, secure email, and code signing.

## Encrypting Data

### Symmetric Encryption
- One key for encryption and decryption
- Very fast, used for bulk data
- Examples: AES, DES, 3DES, Blowfish

### Asymmetric Encryption
- Public key encrypts, private key decrypts
- Slower, used for key exchange and digital signatures
- Examples: RSA, ECC

### Hybrid Encryption
- Combines symmetric + asymmetric
- Example: TLS/SSL uses asymmetric to exchange a symmetric session key, then switches to symmetric for speed

### Data States
- **Data at Rest:** Stored files (disk encryption, BitLocker, LUKS)
- **Data in Transit:** Network traffic (TLS, VPNs, SSH)
- **Data in Use:** Active memory (protected by CPU-level technologies)

**SOC Relevance:**
- Monitor for expired TLS certificates and weak ciphers in logs
- Detect unusual encrypted traffic (possible data exfiltration)
- Ensure encryption policies align with compliance requirements
