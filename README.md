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

## Key Exchange

### Definition
Key exchange is the process of securely distributing encryption keys between parties.

### Methods
- **In-Band Exchange:** Keys shared over the same communication channel (less secure).
- **Out-of-Band Exchange:** Keys shared separately (e.g., phone + email).
- **Asymmetric Exchange:** Uses public/private key pairs (RSA, ECC).
- **Diffie-Hellman (DH/ECDH):** Mathematical algorithm to establish a shared key over insecure channels.

### Example: TLS Handshake
1. Client connects to server (HTTPS).
2. Server sends public key in its certificate.
3. Client generates session key, encrypts it with server’s public key.
4. Server decrypts with private key → both share symmetric session key.

**SOC Relevance:**
- Key exchange errors show up in SIEM logs (TLS handshake failures, VPN tunnel drops).
- Analysts flag deprecated methods (e.g., weak DH groups).
- Secure key exchange is critical for confidentiality in data in transit.

## Encryption Technologies

### Data at Rest
- **Full-Disk Encryption (FDE):** BitLocker, FileVault, LUKS
- **Database Encryption:** Protects sensitive records

### Data in Transit
- **TLS/SSL:** Protects HTTPS, VPNs, email
- **VPN Encryption:** IPSec, SSL VPNs
- **Wireless Encryption:** WPA3, WPA2 (legacy), WEP (deprecated)

### Email Encryption
- **S/MIME:** Uses PKI for encryption and digital signatures
- **PGP/GPG:** Uses Web of Trust for secure communications

**SOC Relevance:**
- SIEM alerts on TLS handshake failures, expired certs
- IDS/IPS monitoring for weak protocols (e.g., WEP, SSLv2)
- Compliance checks for encrypted databases, VPN logs, and secure email policies

## Obfuscation

### Definition
Obfuscation is the practice of making code or data more difficult to read, understand, or reverse-engineer without altering its functionality.

### Examples
- **Code Obfuscation:** Making source code harder to analyze.
- **Malware Obfuscation:** Attackers hide payloads in PowerShell or JavaScript.
- **Data Obfuscation:** Masking sensitive information (e.g., credit card numbers).
- **Comparison:** Encryption protects confidentiality with keys; obfuscation only adds complexity.

**SOC Relevance:**
- SIEM alerts often detect obfuscated scripts in PowerShell logs.
- Malware analysts investigate obfuscated payloads during incident response.
- Data obfuscation is also used defensively to protect sensitive fields in logs.

## Hashing and Digital Signatures

### Hashing
- One-way mathematical function → produces fixed-length digest
- Ensures **integrity**: changes in input = different hash
- Algorithms:
  - MD5: fast but broken
  - SHA-1: deprecated
  - SHA-256 / SHA-3: secure and widely used

### Digital Signatures
- Combines hashing with asymmetric encryption
- Process:
  1. Sender hashes the message
  2. Sender encrypts hash with private key (signature)
  3. Receiver decrypts signature with sender’s public key
  4. Receiver re-hashes message and compares
- Provides:
  - **Integrity**
  - **Authentication**
  - **Non-repudiation**

### Common Uses
- Email signing (S/MIME, PGP)
- Software/code signing
- TLS certificates

**SOC Relevance:**
- Analysts validate file and log integrity using hashes
- Digital signatures are checked in SIEM for invalid or self-signed certificates
- Threat hunting often includes comparing file hashes against malware databases

## Blockchain Technology

### Definition
A distributed ledger that records transactions in blocks, which are linked together using cryptographic hashes.

### Key Concepts
- **Blocks:** Store transaction data + previous block hash + timestamp
- **Hash Linking:** Each block references the previous block, making the chain tamper-resistant
- **Consensus Mechanisms:**
  - Proof of Work (PoW) – miners solve puzzles (e.g., Bitcoin)
  - Proof of Stake (PoS) – validators stake tokens (e.g., Ethereum 2.0)
- **Decentralization:** No single central authority
- **Immutability:** Once recorded, data cannot be altered without detection

### Security Benefits
- Ensures **integrity** via hashing
- Provides **non-repudiation** by permanent logging
- Enables transparent, auditable trails

**SOC Relevance:**
- Integrity verification concepts in blockchain overlap with forensic log analysis
- Useful for tracking crypto-related threats (fraud, ransomware payments)
- May support immutable SOC log storage in the future
