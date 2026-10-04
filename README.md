# Threat Hunt: Okta Account Takeover from Anomalous Geolocation

**Platform:** Microsoft Sentinel · KQL · Okta identity logs
**Domain:** Threat Hunting · Identity compromise · Incident response
**Detection surface:** Microsoft Sentinel (Defender portal) — `OktaV2_CL`

---

## The problem — a real-world attack, not a hypothetical

In **October 2023, Okta** itself disclosed a breach of its support case management system: an attacker used a **stolen credential** to access the system and view files uploaded by customers, including session tokens that could be used to impersonate legitimate users. Downstream, this contributed to intrusion attempts against Okta customers such as **1Password, Cloudflare, and BeyondTrust**. [1][2]

The pattern is the defining threat of modern cloud security: **identity is the perimeter**. An attacker rarely "breaks in" through a firewall anymore — they log in with a stolen credential and operate as a trusted user. Once inside an identity provider, they move fast to make their access permanent: granting themselves privilege, minting API tokens, and hijacking MFA so that even a password reset won't lock them out. The detection challenge is that these logins look legitimate — the signal is not *that* someone logged in, but *from where*, and *what they did next*.

## What this project is — and the skills it proves

This project is a **hypothesis-driven threat hunt** in Microsoft Sentinel that detects an Okta account takeover not from a fired alert, but by baselining normal behaviour and spotting the outlier. It reconstructs the full takeover chain and defines a containment response ordered to actually lock the attacker out — accounting for the persistence mechanisms a naive response would miss.

| Real-world failure | Capability this project builds |
|---|---|
| Stolen credentials produce legitimate-looking logins | Behavioural baselining to surface geographic anomalies |
| Attacker makes access permanent before anyone notices | Attack-chain reconstruction exposing persistence (API token, planted MFA) |
| Password reset leaves the attacker still inside | Containment ordered to revoke sessions + tokens + MFA, not just the password |
| Analyst confuses attacker and victim accounts | Explicit actor-vs-target disambiguation to direct response correctly |

---

## Scenario & hypothesis

Threat intelligence indicated that stolen Okta credentials for the organisation may be in circulation. If an attacker were using stolen credentials, their sign-ins would likely originate from a different geographic location than the legitimate user's normal pattern.

**Hypothesis:** An account authenticating from a country outside the organisation's baseline is a candidate for compromise.

---

## Hunt methodology

### Step 1 — Establish the baseline

Rather than starting from an alert, I baselined *where each user normally logs in from* by counting successful sign-ins per user, per country.

![Baseline hunt showing mirage logging in from RU against an all-US baseline](3.png)

```KQL
OktaV2_CL
| where EventResult == "Success"
| summarize LoginCount = count() by ActorUsername, SrcGeoCountry
| order by ActorUsername asc
```

**Result:** Every account authenticated exclusively from the US — except one:

| ActorUsername | SrcGeoCountry | LoginCount |
|---|---|---|
| psharma@pkwork.onmicrosoft.com | US | 13 |
| ceo@pkwork.onmicrosoft.com | US | 6 |
| aturner@pkwork.onmicrosoft.com | US | 5 |
| spatel@pkwork.onmicrosoft.com | US | 4 |
| jliu@pkwork.onmicrosoft.com | US | 2 |
| **mirage@pkwork.onmicrosoft.com** | **RU** | **6** |

The `mirage` account authenticating exclusively from Russia, against an otherwise all-US baseline, was the outlier worth pivoting on.

### Step 2 — Pivot on the anomalous account

I pulled every action associated with the Russian-origin activity, ordered chronologically to reconstruct the sequence of events.

```kql
OktaV2_CL
| where SrcGeoCountry == "RU"
| project TimeGenerated, ActorDisplayName, EventMessage
| order by TimeGenerated asc
```

![mirage's attack chain: super admin grant, API token creation, MFA manipulation](4.png)

---

## Findings

The pivot revealed a textbook account-takeover and tenant-seizure chain, all attributed to the `mirage` actor:

| Order | Action (`EventMessage`) | Purpose |
|---|---|---|
| 1 | User login to Okta (password) | Initial access with compromised credentials |
| 2 | Grant user super admin role | Privilege escalation — full tenant control |
| 3 | Create API token | Persistence — a credential that survives password/MFA resets |
| 4 | Enroll new TOTP factor for attacker-controlled device | Persistence — attacker's own MFA |
| 5 | Deactivate SMS factor for user Priya Sharma | Weakening a victim's MFA |
| 6 | Reset all MFA factors for user CEO PKWork | Locking the legitimate CEO out |

**Key observation — automation:** Every event carried an identical timestamp (`Aug 8, 2026 12:09:52 PM`). A human operating the Okta console cannot grant a role, mint a token, enrol a factor, and reset MFA within the same second. The uniform timestamp indicates the actions were executed by a script or API automation, not manual clicks.

**Actor vs. target:** `mirage@pkwork` is the *attacker-controlled account* performing the actions. The `CEO` and `Priya Sharma` accounts are *victims* the attacker acted upon. Distinguishing actor from target is essential so response effort is directed at the right accounts.

**Verdict:** True positive — active, in-progress tenant compromise. Critical severity.

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1078 – Valid Accounts | Password login from RU using compromised credentials |
| Privilege Escalation | T1098.003 – Account Manipulation: Additional Cloud Roles | Grant super admin role |
| Persistence | T1098.001 – Account Manipulation: Additional Cloud Credentials | Create API token |
| Persistence | T1098.005 – Account Manipulation: Device Registration | Enroll attacker-controlled TOTP factor |
| Defense Evasion | T1556.006 – Modify Authentication Process: MFA | Deactivate victim SMS factor |
| Impact | T1531 – Account Access Removal | Reset CEO's MFA to deny legitimate access |

---

## Containment & response

The critical insight driving the response order: **a password reset alone does not contain this attacker.** The API token and the attacker-enrolled TOTP factor authenticate independently of the password, and an active session persists until explicitly revoked. Containment must close *every* path back in.

**Response sequence — stop the bleeding → close the doors → clean up → preserve evidence:**

1. **Revoke active sessions** — the attacker is authenticated in real time; terminate sessions immediately so access is cut before anything else.
2. **Revoke the API token** — the backdoor that ignores password and MFA controls; without this, all other steps are bypassed.
3. **Reset the account password** — blocks re-authentication with the stolen credentials.
4. **Reset all MFA factors** — removes the attacker-enrolled TOTP so their planted factor cannot be reused; legitimate user re-enrols clean.
5. **Undo the damage** — remove the granted super-admin role, re-enable Priya Sharma's SMS factor, restore the CEO's MFA.
6. **Preserve the attacker account as evidence** — disable (do not delete) `mirage` to retain the forensic trail of what was accessed, when, and from where.

---

## Key design decisions

- **Hunt, don't wait for alerts.** The chain was surfaced by baselining normal behaviour and spotting the outlier — a proactive hunt, not a reactive response to a fired rule.
- **Containment closes every path, not just the obvious one.** Password resets do not revoke API tokens or attacker-registered MFA; sessions, tokens, and MFA factors are all addressed, in an order that cuts active access first.
- **Reset, don't merely re-enable.** Resetting MFA factors wipes attacker-planted factors; "re-enabling" MFA can leave the attacker's device attached.
- **Preserve before you purge.** The attacker account is disabled and retained for forensics, not deleted — destroying it would destroy the evidence trail.
- **Disambiguate actor from target.** Response effort is directed at the attacker-controlled account and the victim accounts separately, so remediation lands on the right objects.

---

## Future improvements

- **Operationalise as an analytics rule** — convert the baseline-and-anomaly logic into a scheduled Sentinel rule with entity mapping, so a geographic outlier raises an incident automatically.
- **Impossible-travel enrichment** — add distance/time calculation between consecutive logins to distinguish a true takeover from a VPN or legitimate travel.
- **Cross-platform correlation** — join this identity activity to endpoint and cloud telemetry to establish whether the same actor pivoted beyond Okta.
- **Automated containment playbook** — a SOAR playbook that revokes sessions and tokens and disables the account on confirmation, with destructive steps gated behind analyst approval.

---

## Skills demonstrated

· Threat hunting with KQL
· Behavioural baselining
· Pivot investigation
· Attack-chain reconstruction
· Identity-first incident response
· MITRE ATT&CK mapping
· Okta / cloud identity security

---

## References

1. Okta Security — [Tracking Unauthorized Access to Okta's Support System](https://sec.okta.com/articles/2023/10/tracking-unauthorized-access-oktas-support-system/) (October 2023).
2. BleepingComputer — [Okta says its support system was breached using stolen credentials](https://www.bleepingcomputer.com/news/security/okta-says-its-support-system-was-breached-using-stolen-credentials/) (affected customers include 1Password, Cloudflare, BeyondTrust).
