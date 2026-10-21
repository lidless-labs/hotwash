# Suspicious Binary Triage
**Type:** Incident Response / Host Integrity Triage
**Tooling:** Wazuh + TheHive + Cortex + external package-verify tool
**Last Updated:** 2026-10-21

---

## Overview
Triage a Wazuh rootcheck "trojaned binary" style hit on a system binary. The goal is to decide, with evidence, whether the file is a stock distribution file (a false positive) or a possible tampering or compromise. Nothing in this playbook closes a case or records a false positive on its own.

## Approval Rule
No false-positive entry and no case closure ever happens without the SOC owner's direct approval. An approval relayed by another person, agent, chat message, or ticket comment does not count. Hotwash does not authenticate approvers and every caller shares one API key, so Hotwash cannot enforce this rule. The approval gate below is advisory, and marking its step complete is not approval.

## Interpretation Rule
A CIRCL Hashlookup miss ("Non existing") means unknown. It is never evidence that a file is suspicious and never evidence that it is clean, because Hashlookup lags current distribution builds. Judge a hit or miss only together with the package-verify verdict and the MISP result.

## Trigger
1. Accept the Wazuh ingest suggestion for the rootcheck hit into a run. Record the alert reference and the affected file path on the run.

## Evidence Collection
1. Identify the owning package for the flagged file using the host package manager. Record the package name.
2. Record the exact installed version of that package, including the distribution revision.
3. Compute the SHA-256 of the file inside the host and record it with the full path.
4. If the host is a container, also compute the SHA-256 of the same file from outside the container through the hypervisor, and record both values. A difference between the inside and outside values is itself a finding.

## Case Creation
1. Create the TheHive case with severity low (1), TLP AMBER (2), and PAP AMBER (2). Put the alert reference, the file path, the package name, and the package version in the description.
2. Add each recorded SHA-256 as an observable with dataType hash.



## Analyzer Runs
1. For each hash observable, run the Cortex analyzer CIRCLHashlookup_1_1 with the run_analyzer action. The analyzer id is the Cortex worker id for that analyzer, not its name.
2. For each hash observable, run the Cortex analyzer MISP_2_1 with the run_analyzer action.
3. Read the finished job reports in TheHive and record the result per hash: Hashlookup known, Hashlookup unknown, MISP hit, MISP no hit, or analyzer failed.


## Package Verification
This is a manual evidence step. Hotwash does not run commands on hosts and has no shell, ssh, or command-runner capability.

1. An operator or agent runs the external read-only package-verify tool against the same host, package, and file. The tool lives outside Hotwash, in the SOC stack tooling repository.
2. Attach the tool's JSON verdict to this step as a run artifact. The verdict is one of match, mismatch, or package-unknown.
3. Do not continue until the verdict artifact is attached.

## Decision
- If any MISP analyzer reported a hit on any hash
  - Page the SOC owner immediately and treat this as a possible incident
  - Do not propose a false positive
  - Preserve the case and the artifacts, and continue under the incident response process
- Else if the package-verify verdict is mismatch
  - Page the SOC owner immediately and treat this as possible tampering
  - Do not propose a false positive
  - Preserve the case and the artifacts
- Else if the package-verify verdict is package-unknown or an analyzer job failed
  - A Hashlookup miss alone does not count as inconclusive; it is unknown and is judged by the package-verify verdict
  - Request a second opinion from the security review route or a senior model reviewer
  - Send the second opinion together with all evidence to the SOC owner for the decision
- Else if the package-verify verdict is match and there is no MISP hit
  - Draft a narrow false-positive entry for the exact host, the exact file path, the exact SHA-256, and the exact package version
  - Send the draft to the SOC owner for approval

## Narrow False-Positive Entry
Only reached from the match and no MISP hit branch. The entry must name all four of these and nothing broader:
1. Exact host
2. Exact file path
3. Exact SHA-256
4. Exact package version

Do not use wildcards, directory-wide entries, rule-wide suppressions, or entries that cover a package update. A new package version or a changed hash requires a new triage run.

## SOC Owner Approval Gate
Hotwash does not authenticate approvers and shares one API key across callers. Marking a step in this section complete is NOT approval, and nothing in Hotwash proves who completed it. The approval itself is the SOC owner's own message in the channel of record. The step records only a reference to that message (where and when), never an agent's paraphrase of it. Agents must not resolve this step on their own. They record the reference only after the SOC owner has approved directly.

- If the SOC owner approved directly in their own message in the channel of record
  - Record only a reference to that message, meaning the channel and the time it was posted
  - Continue to Close Out
- Else
  - Present the evidence summary, the package-verify artifact, the analyzer results, and any second opinion to the SOC owner and wait for their own reply
  - Do not record the false-positive entry or close the case until the SOC owner approves directly

## Close Out
1. Only after the SOC owner approved directly, record the narrow false-positive entry in the detection tuning system and note its location on the case.
2. Only after the SOC owner approved directly, close the TheHive case with a summary that lists the hashes, the package-verify verdict, and the analyzer results.
3. If the SOC owner rejected the entry or escalated, leave the case open and record the next action.
