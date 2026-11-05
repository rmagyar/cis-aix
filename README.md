# AIX security assessment - CIS IBM AIX 7 Benchmark v1.2.0

Reference: `reference/CIS_IBM_AIX_7_Benchmark_v1.2.0-1.pdf`

| File | Purpose |
|---|---|
| `cis_collect.ksh` | ksh93 collector. Runs the audit command(s) of every recommendation (chapters 1-8, 330 probes, all 230 recommendations) and writes one evidence file. Read-only. |
| `cis_report.py` | Python 3 (standard library) report generator. Evaluates the evidence against the benchmark and writes a self-contained HTML report with findings and remediation. |
| `cis_hardening.ksh` | ksh93 hardening script. Applies the settings that `cis_report.py` checks, safely: dry-run, backups, undo script, tighten-only permissions. Needs a human for the rules it lists as `[MANUAL]`. |
| `tests/make_synthetic.py` | Builds synthetic compliant / non-compliant evidence files to test the report generator. |
| `tests/run_mock_dryrun.sh` | Runs `cis_hardening.ksh -n` against stub AIX commands (`tests/mock_aix/bin`) on any host with ksh93 and checks that nothing is changed. |
| `tests/test_filters.sh` | Unit tests of the text filters in `cis_hardening.ksh` (sshd_config, sendmail.cf, audit config, /etc/profile, inetd.conf ...). |

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

## 3. Harden (on the AIX host, as root)

Take a `mksysb` first, then always start with a dry-run:

    ./cis_hardening.ksh -n                   # show every change, modify nothing
    ./cis_hardening.ksh                      # apply (asks for confirmation; -y skips the question)
    ./cis_hardening.ksh -s 4.5               # only the rules starting with 4.5
    ./cis_hardening.ksh -L loghost.example.com   # also configure remote syslog (8.2.2)

Verify afterwards with a new collect and report run (steps 1 and 2).

Options: `-n` dry-run, `-x` also apply the risky rules, `-y` no confirmation, `-q` skip the
file-system-wide scans, `-s prefix` rule filter, `-L host` remote syslog host, `-P path` Trusted
Execution Path (2.2), `-b dir` backup directory (default `/var/tmp/cis_hardening.<timestamp>`), `-h` help.

Safety model:

* Idempotent: a compliant rule is not touched. Every result is `[OK]`, `[APPLIED]`, `[DRY-RUN]`,
  `[SKIPPED]`, `[MANUAL]` or `[FAILED]` and the real outcome of each command is reported.
* Permissions are only tightened (new mode = current mode AND the benchmark maximum).
* Every edited file is copied to `<backup dir>/files/...` first; old attribute values are written to
  `<backup dir>/undo.ksh` (review it before running). `sshd_config` is checked with `sshd -t` and
  the sudo drop-in with `visudo -c`; both are rolled back on failure. A filter never empties a file.
* Risky rules are skipped unless `-x` is given: Trusted Execution (2.2 - 2.5), chmod of
  world / staff writable files (3.4, 3.5), IP forwarding off (4.5.6, 4.5.7), password expiry
  (5.2.5, 5.2.6), root login / `su` control (4.8.1, 4.6.3.14, 4.6.3.15), services that are running
  now (inittab, rc.tcpip and inetd entries), and legacy remote access (telnet, rsh ...) while sshd is
  not running.
* Nothing is installed or removed, and no user data is deleted: `.netrc`, `.rhosts`, `.shosts` and
  `shosts.equiv` files are moved to the backup directory.
* Sendmail and CDE rules apply only when the fileset is installed.
* Rules that need a decision (site banners, inventories, SUID review, audit file system, firmware,
  fixes, software removal) are never applied; the exact action is printed as `[MANUAL]`.

Test without AIX (needs ksh93): `tests/run_mock_dryrun.sh` and `tests/test_filters.sh`.

## Notes

* Chapters 1.3, 1.4, 5.4 and 5.5 of the benchmark are informational; their evidence is shown but not scored.
* `\s` in the benchmark's grep commands is written as `[[:space:]]` (AIX grep does not know `\s`).
* Remediation commands are quoted from the benchmark. Review them and test on a non-production
  system; several (NFS, inetd, audit, sshd, password policy) can affect running services.
* Test the generator: `python3 tests/make_synthetic.py good.ev bad.ev <real.evidence>` and run
  `cis_report.py` on both files.
