# Vulnerability Assessment

## Known Bluetooth CVEs

### CVE-2017-0785 (BlueBorne)
- Status: Likely vulnerable (Bluetooth 4.1 era)
- Exploitability: Requires Ubertooth hardware
- Impact: Potential RCE without pairing
- Practical Risk: LOW (needs specialized equipment)

### CVE-2019-9506 (KNOB)
- Status: Potentially vulnerable
- Exploitability: Weak encryption negotiation
- Impact: Eavesdropping on encrypted traffic
- Practical Risk: LOW (requires proximity & tools)

### CVE-2020-10135 (BIAS)
- Status: Potentially vulnerable
- Exploitability: Authentication bypass
- Impact: Device impersonation
- Practical Risk: LOW (complex attack)

## Device-Specific Vulns
- Weak PIN (0000): Non-critical (pairing only)
- No firmware updates: By design
- No debug interface: Intentional

## Overall Assessment
**Risk Level: LOW** for wireless attacks
**Risk Level: N/A** for firmware modification
