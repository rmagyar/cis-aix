# AIX security assessment - CIS IBM AIX 7 Benchmark v1.2.0

Reference: `reference/CIS_IBM_AIX_7_Benchmark_v1.2.0-1.pdf`

| File | Purpose |
|---|---|
| `cis_collect.ksh` | ksh93 collector. Runs the audit command(s) of every recommendation (chapters 1-8, 330 probes, all 230 recommendations) and writes one evidence file. Read-only. |
| `cis_report.py` | Python 3 (standard library) report generator. Evaluates the evidence against the benchmark and writes a self-contained HTML report with findings and remediation. |
| `tests/make_synthetic.py` | Builds synthetic compliant / non-compliant evidence files to test the report generator. |

## 1. Collect (on the AIX host, as root)

    ./cis_collect.ksh -o /var/tmp            # full run (file-system-wide scans can take a long time)
    ./cis_collect.ksh -q -o /var/tmp         # quick run: skips find / and trustchk tree scans
    ./cis_collect.ksh -F /path/flrtvc.ksh    # also run FLRTVC (recommendation 7.1; may contact IBM)

Options: `-m maxlines` (default 3000 lines kept per command), `-t secs` (per command timeout, 120),
`-T secs` (timeout of the file-system-wide scans, 7200).

Output: `cis_aix7_<host>_<timestamp>.evidence` (mode 600). Nothing on the system is modified.
Password hashes are never stored (only user names for 5.1.1, 5.2.4, 5.2.8). The file still contains
configuration details: handle it as confidential.

## 2. Report (on any host with Python 3)

    python3 cis_report.py cis_aix7_<host>_<timestamp>.evidence -o report.html
    python3 cis_report.py <evidence> -o report.html --no-evidence   # smaller report without raw evidence

The report contains: system information, summary (by status, level, section), findings with the
benchmark remediation commands for every failed recommendation, manual-review items (inventories,
SUID/SGID review, firmware, FLRTVC), items that could not be evaluated, the full result table
and the collected evidence.

Result states: **Pass**, **Fail**, **Manual review** (needs a human decision, e.g. 5.1.4, 5.1.5, 7.2),
**Not collected** (quick mode, missing command, timeout, evidence not from AIX).
The compliance percentage counts only Pass and Fail.

## Notes

* Chapters 1.3, 1.4, 5.4 and 5.5 of the benchmark are informational; their evidence is shown but not scored.
* `\s` in the benchmark's grep commands is written as `[[:space:]]` (AIX grep does not know `\s`).
* Remediation commands are quoted from the benchmark. Review them and test on a non-production
  system; several (NFS, inetd, audit, sshd, password policy) can affect running services.
* Test the generator: `python3 tests/make_synthetic.py good.ev bad.ev <real.evidence>` and run
  `cis_report.py` on both files.
