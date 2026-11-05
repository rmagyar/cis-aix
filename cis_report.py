#!/usr/bin/env python3
"""cis_report.py - HTML report generator for the CIS IBM AIX 7 Benchmark v1.2.0

Reads the evidence file written by cis_collect.ksh and produces ONE
self-contained HTML page (no scripts, no external assets) with

  * host / OS information and a summary by status, profile level and section
  * one finding per benchmark recommendation (PASS / FAIL / MANUAL /
    NOT COLLECTED) with the observed value
  * remediation recommendations (commands taken from the benchmark) for every
    failed recommendation
  * the raw evidence behind every recommendation that is not a PASS

Usage:  python3 cis_report.py EVIDENCE_FILE [-o report.html] [--no-evidence]

Only the Python 3 standard library is used.  The report contains system
configuration details - handle it as confidential.
"""
import argparse
import datetime
import html
import os
import re
import sys

VERSION = "1.0.0"
BENCHMARK = "CIS IBM AIX 7 Benchmark v1.2.0"

# ---------------------------------------------------------------------------
# Evidence parser
# ---------------------------------------------------------------------------


class Probe(object):
    def __init__(self, pid, name):
        self.id = pid
        self.name = name
        self.cmd = ""
        self.rc = None
        self.out = []
        self.err = []
        self.skipped = None
        self.truncated = None


def parse_evidence(path):
    meta, probes = {}, []
    cur, mode, eof = None, None, False
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("@@@"):
                tag, _, rest = line[3:].partition("|")
                if tag == "META":
                    k, _, v = rest.partition("|")
                    meta[k] = v
                elif tag == "BEGIN":
                    pid, _, name = rest.partition("|")
                    cur = Probe(pid, name)
                    probes.append(cur)
                    mode = None
                elif tag == "EOF":
                    eof = True
                elif cur is None:
                    continue
                elif tag == "CMD":
                    cur.cmd = rest
                elif tag == "RC":
                    try:
                        cur.rc = int(rest)
                    except ValueError:
                        cur.rc = None
                elif tag == "STDOUT":
                    mode = "out"
                elif tag == "STDERR":
                    mode = "err"
                elif tag == "TRUNCATED":
                    cur.truncated = rest
                elif tag == "SKIPPED":
                    cur.skipped = rest
                elif tag == "END":
                    mode = None
                continue
            if cur is not None and mode == "out":
                cur.out.append(line)
            elif cur is not None and mode == "err":
                cur.err.append(line)
    return meta, probes, eof


DB = {}          # (id, name) -> Probe
USED = []        # probes consulted by the evaluator that is currently running
META = {}


class NC(Exception):
    """Evidence missing / not usable: the recommendation is 'not collected'."""


MISSING_RE = re.compile(r"(^|[\s:])[\w./+-]+: (command )?not found", re.I)


def get(i, n="a"):
    p = DB.get((i, n))
    if p is None:
        raise NC("probe %s/%s is not present in the evidence file" % (i, n))
    if p not in USED:
        USED.append(p)
    return p


def ready(p):
    if p.skipped:
        raise NC(p.skipped)
    if p.rc == 124:
        raise NC("command timed out during collection")
    if p.rc == 127 or MISSING_RE.search("\n".join(p.err)):
        raise NC("command not available on the audited host (%s)" %
                 (p.err[0].strip()[:100] if p.err else "rc=127"))
    return p


def G(i, n="a"):
    return ready(get(i, n))


def L(p):
    return [l for l in p.out if l.strip()]


def text(p):
    return "\n".join(p.out)


def errtext(p):
    return "\n".join(p.err)


def excerpt(lines, n=3, width=110):
    lines = [l.strip() for l in lines if l.strip()]
    s = "; ".join(l[:width] for l in lines[:n])
    if len(lines) > n:
        s += " ... (+%d more)" % (len(lines) - n)
    return s


def is_root():
    return bool(re.match(r"uid=0\b", META.get("user", "")))


def sys_probe(name):
    p = DB.get(("SYS", name))
    if p is not None and p not in USED:
        USED.append(p)
    return p


def fileset_installed(fs):
    """True / False, or None when the inventory is not usable."""
    p = DB.get(("SYS", "lslpp_all"))
    if p is None or p.skipped or p.rc == 127 or MISSING_RE.search(errtext(p)) or not L(p):
        return None
    return bool(re.search(r"(^|:)" + re.escape(fs) + r":", text(p)))


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

def PASS(m=""):
    return ("PASS", m)


def FAIL(m=""):
    return ("FAIL", m)


def MAN(m=""):
    return ("MANUAL", m)


EVAL = {}
REM = {}


def reg(i):
    def deco(f):
        EVAL[i] = f
        return f
    return deco


def R(i, txt):
    REM[i] = txt.strip("\n")


def to_int(v):
    try:
        return int(str(v).strip().strip('"'))
    except (TypeError, ValueError):
        return None


def cmp_ok(v, op, ref):
    if v is None:
        return False
    if op == "eq":
        return v == ref
    if op == "ge":
        return v >= ref
    if op == "le":
        return v <= ref
    if op == "range":
        return ref[0] <= v <= ref[1]
    raise ValueError(op)


def optxt(op, ref):
    if op == "range":
        return "between %s and %s" % ref
    return {"eq": "=", "ge": ">=", "le": "<="}[op] + " %s" % (ref,)


# ls -l parsing ---------------------------------------------------------------

def mode_int(s):
    v = 0
    for i, ch in enumerate(s[1:10]):
        if ch in "rwxst":
            v |= 1 << (8 - i)
        if ch in "sStT":
            v |= {2: 0o4000, 5: 0o2000, 8: 0o1000}[i]
    return v


def ls_entries(p):
    ents = []
    for l in p.out:
        t = l.split()
        if len(t) >= 4 and re.match(r"^[-dlbcpsD][-rwxsStT]{9}", t[0]):
            name = t[t.index("->") - 1] if "->" in t else t[-1]
            ents.append((t[0][:10], t[2], t[3], name))
    return ents


def has_acl(p):
    return bool(re.search(r"extended permissions\s*\n?\s*enabled", text(p), re.I))


def absent(p):
    return bool(re.search(r"does not exist|No such file|0653-341|0652-033|Cannot open|not found\b.*\bdirectory|cannot access",
                          errtext(p), re.I))


# ---------------------------------------------------------------------------
# Benchmark catalog: (recommendation, title, profile level) - 230 entries
# ---------------------------------------------------------------------------
CATALOG = [
    ('2.1', 'Ensure system configuration is documented and verified regularly', 1),
    ('2.2', 'Ensure Trusted Execution Path is enabled', 2),
    ('2.3', 'Ensure Trusted Execution (TE) policies are locked', 2),
    ('2.4', 'Ensure Unauthorized Applications are reported', 1),
    ('2.5', 'Ensure Allowlist violations are enabled', 2),
    ('2.6', 'Ensure regular scans for unauthorized applications', 2),
    ('2.7', 'Ensure unused symbolic links are removed', 1),
    ('3.1', 'Ensure default user umask is configured', 1),
    ('3.2', 'Ensure world writable directories have the SVTX bit set', 1),
    ('3.3', "Ensure there are no system 'default group' writable files (objects)", 2),
    ('3.4', 'Ensure world writable files are secured', 1),
    ('3.5', 'Ensure there are no group staff writable files', 1),
    ('3.6', 'Ensure no files or directories without an owner and a group exist', 1),
    ('4.1.1.1', 'Ensure access on root user smit.log is configured', 1),
    ('4.1.1.2', 'Ensure access on /etc/group is configured', 1),
    ('4.1.1.3', 'Ensure access on /etc/inetd.conf is configured', 1),
    ('4.1.1.4', 'Ensure access on /etc/motd is configured', 1),
    ('4.1.1.5', 'Ensure access on /etc/passwd is configured', 1),
    ('4.1.1.6', 'Ensure /etc/mail/submit.cf access is configured', 1),
    ('4.1.1.7', 'Ensure access to /etc/ssh/ssh_banner is configured', 1),
    ('4.1.1.8', 'Ensure access on /etc/ssh/ssh_config is configured', 1),
    ('4.1.1.9', 'Ensure access on /etc/ssh/sshd_config is configured', 1),
    ('4.1.1.10', 'Ensure access on /var/adm/cron/at.allow is configured', 1),
    ('4.1.1.11', 'Ensure access on /var/adm/cron/cron.allow is configured', 1),
    ('4.1.1.12', 'Ensure access on /var/adm/cron/log is configured', 1),
    ('4.1.1.13', 'Ensure access on /var/ct/RMstart.log is configured', 1),
    ('4.1.1.14', 'Ensure access on /var/tmp/dpid2.log is configured', 1),
    ('4.1.1.15', 'Ensure access on /var/tmp/hostmibd.log is configured', 1),
    ('4.1.1.16', 'Ensure access on /var/tmp/snmpd.log is configured', 1),
    ('4.1.1.17', 'Ensure access is configured for commands referenced by crontab entries', 1),
    ('4.1.1.18', 'Ensure local interactive user dot files access is configured', 1),
    ('4.1.1.19', 'Ensure SUID and SGID files are reviewed', 1),
    ('4.1.1.20', 'Ensure access on /var/tmp/snmpdv3.log is configured', 1),
    ('4.1.2.1', 'Ensure local user Home directories exists', 1),
    ('4.1.2.2', 'Ensure HOME directories are owned by root or the UID specified in /etc/passwd', 1),
    ('4.1.2.3', 'Ensure Home directory write access is restricted to owner', 1),
    ('4.1.2.4', 'Ensure access on /audit and /etc/security/audit is configured', 1),
    ('4.1.2.5', 'Ensure access to /etc/security is configured', 1),
    ('4.1.2.6', 'Ensure access on /var/adm/ras is configured', 1),
    ('4.1.2.7', 'Ensure access on /var/adm/sa is configured', 1),
    ('4.1.2.8', 'Ensure access on /var/spool/cron/crontabs is configured', 1),
    ('4.1.2.9', 'Ensure access on /var/spool/cron/atjobs is configured', 1),
    ('4.1.2.10', 'Ensure all directories in root PATH access are configured', 1),
    ('4.1.2.11', 'Ensure root user has a dedicated home directory', 1),
    ('4.2.1', 'Ensure NIS client is not installed', 1),
    ('4.2.2', 'Ensure NIS server services are not in use', 1),
    ('4.2.3', 'Ensure legacy NIS markers are removed', 1),
    ('4.2.4', 'Ensure all entries in /etc/hosts.equiv are removed', 2),
    ('4.2.5', 'Ensure that host based authentication files are not present', 2),
    ('4.2.6', 'Ensure legacy remote daemon support is not available', 1),
    ('4.2.7', 'Ensure snmpd is not installed', 1),
    ('4.3.1.1', 'Ensure writesrv service is not in use', 1),
    ('4.3.1.2', 'Ensure dt service is not in use', 1),
    ('4.3.1.3', 'Ensure piobe service is not in use', 1),
    ('4.3.1.4', 'Ensure qdaemon service is not in use', 1),
    ('4.3.1.5', 'Ensure rcnfs service is not in use', 1),
    ('4.3.1.6', 'Ensure snapp is not installed', 1),
    ('4.3.1.7', 'Ensure NIM master is not installed', 1),
    ('4.3.2.1', 'Ensure inetd daemon is disabled when no additional services are required', 1),
    ('4.3.2.2', 'Ensure dhcp client services are not in use', 1),
    ('4.3.2.3', 'Ensure dhcp relay services are not in use', 1),
    ('4.3.2.4', 'Ensure dhcp server services are not in use', 1),
    ('4.3.2.5', 'Ensure gated is not in use', 1),
    ('4.3.2.6', 'Ensure hostmibd is not in use', 1),
    ('4.3.2.7', 'Ensure multicast routing is not in use', 2),
    ('4.3.2.8', 'Ensure dns server services are not in use', 1),
    ('4.3.2.9', 'Ensure portmap is not in use', 1),
    ('4.3.2.10', 'Ensure routed is not in use', 1),
    ('4.3.2.11', 'Ensure rwhod is not in use', 1),
    ('4.3.2.12', 'Ensure sendmail is not in use', 1),
    ('4.3.2.13', 'Ensure timed is not in use', 1),
    ('4.3.3.1', 'Ensure autoconf6 is not in use', 1),
    ('4.3.3.2', 'Ensure ndpd-host is not in use', 1),
    ('4.3.3.3', 'Ensure ndpd-router is not in use', 1),
    ('4.3.4.1', 'Ensure bootps daemon is not in use', 1),
    ('4.3.4.2', 'Ensure chargen daemon is not in use', 1),
    ('4.3.4.3', 'Ensure comsat daemon is not in use', 1),
    ('4.3.4.4', 'Ensure daytime daemon is not in use', 1),
    ('4.3.4.5', 'Ensure discard daemon is not in use', 1),
    ('4.3.4.6', 'Ensure echo daemon is not in use', 1),
    ('4.3.4.7', 'Ensure exec daemon is not in use', 1),
    ('4.3.4.8', 'Ensure finger daemon is not in use', 1),
    ('4.3.4.9', 'Ensure ftpd daemon is not in use', 1),
    ('4.3.4.10', 'Ensure imap2 daemon is not in use', 1),
    ('4.3.4.11', 'Ensure instsrv daemon is not in use', 1),
    ('4.3.4.12', 'Ensure klogin daemon is not in use', 1),
    ('4.3.4.13', 'Ensure kshell daemon is not in use', 1),
    ('4.3.4.14', 'Ensure netstat daemon is not in use', 1),
    ('4.3.4.15', 'Ensure ntalk daemon is not in use', 1),
    ('4.3.4.16', 'Ensure pcnfsd daemon is not in use', 1),
    ('4.3.4.17', 'Ensure pop3 daemon is not in use', 1),
    ('4.3.4.18', 'Ensure rexd daemon is not in use', 1),
    ('4.3.4.19', 'Ensure rlogin daemon is not in use', 1),
    ('4.3.4.20', 'Ensure rquotad daemon is not in use', 1),
    ('4.3.4.21', 'Ensure rstatd daemon is not in use', 1),
    ('4.3.4.22', 'Ensure rsync daemon is not in use', 1),
    ('4.3.4.23', 'Ensure rusersd daemon is not in use', 1),
    ('4.3.4.24', 'Ensure rwalld daemon is not in use', 1),
    ('4.3.4.25', 'Ensure shell daemon is not in use', 1),
    ('4.3.4.26', 'Ensure sprayd daemon is not in use', 1),
    ('4.3.4.27', 'Ensure talk daemon is not in use', 1),
    ('4.3.4.28', 'Ensure telnetd daemon is not in use', 1),
    ('4.3.4.29', 'Ensure tftpd daemon is not in use', 1),
    ('4.3.4.30', 'Ensure time daemon is not in use', 1),
    ('4.3.4.31', 'Ensure uucp daemon is not in use', 1),
    ('4.3.4.32', 'Ensure xmquery daemon is not in use', 1),
    ('4.4.1.1', 'Ensure NFS client mounts are disabled in /etc/filesystems', 1),
    ('4.4.1.2', 'Ensure NFS server services are not in use', 1),
    ('4.4.1.3', 'Ensure NFS client mounts include nosuid and nodev options', 1),
    ('4.4.1.4', 'Ensure localhost aliases do not exist in /etc/exports', 1),
    ('4.4.1.5', 'Ensure NFS exports use allow lists', 2),
    ('4.4.1.6', 'Ensure access by root over nfs is disabled or blocked', 1),
    ('4.4.1.7', 'Ensure secure RPC authentication is enabled', 2),
    ('4.4.2.1', 'Ensure File System Level encryption is enabled', 2),
    ('4.4.3.1', 'Ensure only / permits device files.', 1),
    ('4.5.1', 'Ensure sockthresh is configured', 1),
    ('4.5.2', 'Ensure bcastping is disabled', 1),
    ('4.5.3', 'Ensure clean_partial_conns is enabled', 1),
    ('4.5.4', 'Ensure directed_broadcast is disabled', 1),
    ('4.5.5', 'Ensure icmpaddressmask is disabled', 1),
    ('4.5.6', 'Ensure ipforwarding is disabled', 1),
    ('4.5.7', 'Ensure ip6forwarding is disabled', 1),
    ('4.5.8', 'Ensure ipignoreredirects is enabled', 1),
    ('4.5.9', 'Ensure ipsendredirects is disabled', 1),
    ('4.5.10', 'Ensure ipsrcrouteforward is disabled', 1),
    ('4.5.11', 'Ensure ipsrcrouterecv is disabled', 1),
    ('4.5.12', 'Ensure ipsrcroutesend is disabled', 1),
    ('4.5.13', 'Ensure ip6srcrouteforward is disabled', 1),
    ('4.5.14', 'Ensure nfs_use_reserved_ports is enabled', 1),
    ('4.5.15', 'Ensure nonlocsrcroute is disabled', 1),
    ('4.5.16', 'Ensure tcp_pmtu_discover is disabled', 1),
    ('4.5.17', 'Ensure tcp_tcpsecure is configured', 1),
    ('4.5.18', 'Ensure udp_pmtu_discover is disabled', 1),
    ('4.5.19', 'Ensure icmptimestamp is disabled', 1),
    ('4.6.1.1', 'Ensure CDE is not installed', 1),
    ('4.6.1.2', 'Ensure the cmsd service is not available', 1),
    ('4.6.1.3', 'Ensure dtlogin service is not available', 1),
    ('4.6.1.4', 'Ensure dtspc is not available', 1),
    ('4.6.1.5', 'Ensure CDE daemons have sgid and suid mode disabled', 1),
    ('4.6.1.6', 'Ensure CDE remote GUI login is disabled', 1),
    ('4.6.1.7', 'Ensure CDE screensaver lock is enabled', 1),
    ('4.6.1.8', 'Ensure CDE login screen hostname is masked', 1),
    ('4.6.1.9', 'Ensure access to /etc/dt/config/Xconfig is configured', 1),
    ('4.6.1.10', 'Ensure the file /etc/dt/config/Xservers is configured', 1),
    ('4.6.1.11', 'Ensure access to Xresources is configured', 1),
    ('4.6.2.1', 'Ensure root access to ftpd is disabled', 1),
    ('4.6.2.2', 'Ensure ftpd login banner is configured', 1),
    ('4.6.2.3', 'Ensure ftpd umask is configured', 1),
    ('4.6.3.1', 'Ensure latest version of openssh is installed', 1),
    ('4.6.3.2', 'Ensure /etc/shosts.equiv and /etc/rhosts.equiv are removed', 1),
    ('4.6.3.3', 'Ensure sftp-server arguments are configured', 1),
    ('4.6.3.4', 'Ensure sshd access is configured', 1),
    ('4.6.3.5', 'Ensure sshd Banner is configured', 1),
    ('4.6.3.6', 'Ensure sshd Ciphers are configured', 1),
    ('4.6.3.7', 'Ensure sshd HostbasedAuthentication is disabled', 1),
    ('4.6.3.8', 'Ensure sshd IgnoreRhosts is enabled', 1),
    ('4.6.3.9', 'Ensure sshd KexAlgorithms is configured', 1),
    ('4.6.3.10', 'Ensure sshd LogLevel is configured', 1),
    ('4.6.3.11', 'Ensure sshd MACs are configured', 1),
    ('4.6.3.12', 'Ensure sshd MaxAuthTries is configured', 1),
    ('4.6.3.13', 'Ensure sshd PermitEmptyPasswords is disabled', 1),
    ('4.6.3.14', 'Ensure sshd PermitRootLogin is configured', 1),
    ('4.6.3.15', 'Ensure sshd PermitRootLogin is disabled', 2),
    ('4.6.3.16', 'Ensure sshd PermitUserEnvironment is disabled', 1),
    ('4.6.3.17', 'Ensure sshd ReKeyLimit is configured', 1),
    ('4.6.3.18', 'Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured', 1),
    ('4.6.4.1', 'Ensure sendmail version information is hidden', 1),
    ('4.6.4.2', 'Ensure sendmail PrivacyOptions is configured', 1),
    ('4.6.4.3', 'Ensure access to /etc/mail/sendmail.cf is configured', 1),
    ('4.6.4.4', 'Ensure access to /var/spool/clientmqueue is configured', 1),
    ('4.6.4.5', 'Ensure access to /var/spool/mqueue is configured', 1),
    ('4.7.1', 'Ensure herald is configured', 1),
    ('4.7.2', 'Ensure logindelay is configured', 1),
    ('4.7.3', 'Ensure loginretries is configured', 1),
    ('4.7.4', 'Ensure logintimeout is configured', 1),
    ('4.7.5', 'Ensure TMOUT is configured', 1),
    ('4.7.6', 'Unattended terminal session timeout is 900 seconds (or less) - readonly', 2),
    ('4.8.1', 'Ensure root access is controlled', 1),
    ('4.8.2', 'Ensure root user default shell is ksh', 1),
    ('4.8.3', 'Ensure core dumps are disabled', 1),
    ('4.8.4', 'Ensure default path does not include current working directory', 1),
    ('4.8.5', 'Ensure root user path does not include current working directory', 1),
    ('4.8.6', 'Ensure motd is configured', 1),
    ('4.9.1', 'Ensure Address space layout randomization is enabled', 1),
    ('5.1.1', 'Ensure all local user accounts have a hashed password', 1),
    ('5.1.2', 'Ensure usernames and UIDs are unique', 1),
    ('5.1.3', 'Ensure group names and GIDs are unique', 1),
    ('5.1.4', 'Ensure an Inventory of Administrator accounts is established and maintained', 1),
    ('5.1.5', 'Ensure an Inventory of user accounts is established and maintained', 1),
    ('5.1.6', 'Ensure all local user accounts have valid stanzas in /etc/security/passwd', 1),
    ('5.2.1', 'Ensure histsize is configured', 1),
    ('5.2.2', 'Ensure minimum password age is configured', 2),
    ('5.2.3', 'Ensure password history expiry is configured', 1),
    ('5.2.4', 'Ensure passwords are controlled by password attributes', 1),
    ('5.2.5', 'Ensure maxexpired is configured', 1),
    ('5.2.6', 'Ensure password expiration is configured', 1),
    ('5.2.7', 'Ensure pwd_algorithm is configured', 1),
    ('5.2.8', 'Ensure a strong password hashing algorithm is configured', 1),
    ('5.2.9', 'Ensure minimum password length is configured', 1),
    ('5.2.10', 'Ensure number of characters changed in new password is configured', 1),
    ('5.2.11', 'Ensure minalpha is configured', 1),
    ('5.2.12', 'Ensure minother is configured', 1),
    ('5.2.13', 'Ensure password maximum repeated characters is configured', 1),
    ('5.2.14', 'Ensure mindigit is configured', 1),
    ('5.2.15', 'Ensure minloweralpha is configured', 1),
    ('5.2.16', 'Ensure minupperalpha is configured', 1),
    ('5.2.17', 'Ensure minspecialchar is configured', 1),
    ('5.3.1', 'Ensure user adm is secured', 1),
    ('5.3.2', 'Ensure user bin is secured', 1),
    ('5.3.3', 'Ensure user daemon is secured', 1),
    ('5.3.4', 'Ensure user guest is secured', 1),
    ('5.3.5', 'Ensure user lpd is secured', 1),
    ('5.3.6', 'Ensure user nobody is secured', 1),
    ('5.3.7', 'Ensure user nuucp is secured', 1),
    ('5.3.8', 'Ensure user sys is secured', 1),
    ('5.3.9', 'Ensure user uucp is secured', 1),
    ('5.3.10', 'Ensure System Accounts cannot access system using ftp.', 1),
    ('6.1.1', 'Ensure sudo is installed', 2),
    ('6.1.2', 'Ensure sudo logging is active', 2),
    ('6.1.3', 'Ensure sudo commands use pty', 2),
    ('6.2.1', 'Ensure at is restricted to authorized users', 1),
    ('6.2.2', 'Ensure access to crontab is configured', 1),
    ('7.1', 'Ensure Fix Level Recommendation Tool Vulnerability Checker Script (FLRTVC) is regularly checked', 1),
    ('7.2', 'Ensure system firmware updates are installed', 1),
    ('8.1.1', 'Ensure /audit filesystem has been created and configured', 2),
    ('8.1.2', 'Ensure Audit bin(ary) audit event collection is configured', 2),
    ('8.1.3', 'Ensure modification to TE system is audited', 1),
    ('8.2.1', 'Ensure syslog local logging is configured', 1),
    ('8.2.2', 'Ensure syslog is configured to send logs to a remote log host', 2),
    ('8.2.3', 'Ensure syslog is not configured to receive logs from a remote client', 1),
]

SECTIONS = [
    ("2", "2 Inventory and Control of Assets"),
    ("3", "3 Configure Data Protection"),
    ("4.1.1", "4.1.1 Configure Trusted Files"),
    ("4.1.2", "4.1.2 Configure Trusted Directories"),
    ("4.2", "4.2 Configure Network Services"),
    ("4.3.1", "4.3.1 Processes managed by /etc/inittab"),
    ("4.3.2", "4.3.2 Daemons managed by /etc/rc.tcpip"),
    ("4.3.3", "4.3.3 Configure IPv6"),
    ("4.3.4", "4.3.4 Services managed by inetd"),
    ("4.4.1", "4.4.1 Configure Network Filesystem (NFS)"),
    ("4.4.2", "4.4.2 Configure Filesystem Encryption"),
    ("4.4.3", "4.4.3 Configure ROOTVG"),
    ("4.5", "4.5 Configure Network Options"),
    ("4.6.1", "4.6.1 Configure Common Desktop Environment"),
    ("4.6.2", "4.6.2 Configure FTPD"),
    ("4.6.3", "4.6.3 Configure OpenSSH"),
    ("4.6.4", "4.6.4 Configure Sendmail"),
    ("4.7", "4.7 Configure Login Controls"),
    ("4.8", "4.8 Verify Integrity of Installation Settings"),
    ("4.9", "4.9 Configure Memory Options"),
    ("5.1", "5.1 Configure local accounts"),
    ("5.2", "5.2 Password Management and Controls"),
    ("5.3", "5.3 Configure System Accounts"),
    ("6.1", "6.1 Configure SUDO managed privilege escalation"),
    ("6.2", "6.2 Configure Services Management"),
    ("7", "7 Continuous Vulnerability Management"),
    ("8.1", "8.1 Configure AIX Audit"),
    ("8.2", "8.2 Configure Syslog"),
]

# Informational chapters of the benchmark: evidence is shown, nothing is scored
INFO_SECTIONS = [
    ("1.3.1", "AIX RTE Installation"),
    ("1.3.2", "AIX MKSYSB Installation"),
    ("1.3.3.1", "AIX Secure Profile Installation (Basic AIX Security - BAS)"),
    ("1.3.3.2", "Ensure SSH client and server packages are installed on AIX 7.2"),
    ("1.3.4.1", "Ensure Secure by Default is selected during the installation"),
    ("1.4", "AIX Patch Management"),
    ("5.4", "User Attributes for Active Processes"),
    ("5.5", "Disable Dormant Accounts"),
]


def section_of(rid):
    best = None
    for pfx, title in SECTIONS:
        if rid == pfx or rid.startswith(pfx + "."):
            if best is None or len(pfx) > len(best[0]):
                best = (pfx, title)
    return best[1]


def need_root():
    if not is_root():
        raise NC("collector was not run as root; the evidence is not reliable")


# ---------------------------------------------------------------------------
# Generic evaluators (factories)
# ---------------------------------------------------------------------------

def lssec_val(p, attr):
    m = re.search(r"\b" + re.escape(attr) + r"=(\"[^\"]*\"|\S*)", text(p))
    return None if not m else m.group(1).strip('"')


def numattr(rid, attr, op, ref, name="a"):
    def f():
        v = lssec_val(G(rid, name), attr)
        need = "%s %s" % (attr, optxt(op, ref))
        if v is None or v == "":
            return FAIL("%s is not set (required: %s)" % (attr, need))
        if cmp_ok(to_int(v), op, ref):
            return PASS("%s=%s" % (attr, v))
        return FAIL("%s=%s (required: %s)" % (attr, v, need))
    EVAL[rid] = f


def noval(p, name):
    m = re.search(r"^\s*" + re.escape(name) + r"\s*=\s*\"?([^\s\"]+)\"?\s*$", text(p), re.M)
    return None if not m else m.group(1)


def netopts(rid, items):
    """items: list of (option, expected int) read from probe (rid, 'a')."""
    def f():
        p = G(rid)
        bad, good = [], []
        for opt, want in items:
            v = noval(p, opt)
            if v is None:
                bad.append("%s not reported (required %s)" % (opt, want))
            elif to_int(v) != want:
                bad.append("%s=%s (required %s)" % (opt, v, want))
            else:
                good.append("%s=%s" % (opt, v))
        return FAIL("; ".join(bad)) if bad else PASS("; ".join(good))
    EVAL[rid] = f


def empty_ok(rid, names=("a",), what="no output expected", fail_what="unexpected output"):
    """PASS when every listed probe printed nothing."""
    def f():
        bad = []
        for n in names:
            p = G(rid, n)
            if L(p):
                bad.append(excerpt(L(p)))
        return FAIL("%s: %s" % (fail_what, " | ".join(bad))) if bad else PASS(what)
    EVAL[rid] = f


def fileset_absent(rid, name="a", fs=None):
    def f():
        p = G(rid, name)
        if L(p):
            return FAIL("installed: " + excerpt(L(p), 2))
        return PASS("not installed")
    EVAL[rid] = f


def perm(rid, name, owners, groups, maxmode, optional=False, label=None):
    def f():
        p = G(rid, name)
        ents = ls_entries(p)
        if not ents:
            if optional and (absent(p) or not L(p)):
                return PASS("not present - nothing to protect")
            if absent(p) or not L(p):
                return FAIL("object does not exist")
            return FAIL(excerpt(L(p)))
        m, o, g, nm = ents[0]
        bad = []
        if owners and o not in owners:
            bad.append("owner %s (expected %s)" % (o, "/".join(sorted(owners))))
        if groups and g not in groups:
            bad.append("group %s (expected %s)" % (g, "/".join(sorted(groups))))
        mi = mode_int(m) & 0o7777
        if mi & ~maxmode & 0o7777:
            bad.append("mode %04o is less restrictive than %04o" % (mi, maxmode))
        if has_acl(p):
            bad.append("extended ACL enabled")
        obs = "%s %s:%s %04o" % (nm, o, g, mi)
        return FAIL("; ".join(bad) + " [" + obs + "]") if bad else PASS(obs)
    EVAL[rid] = f


def inetd_count(rid):
    def f():
        p = G(rid)
        nums = [l.strip() for l in L(p) if l.strip().isdigit()]
        if not nums:
            raise NC("no numeric result returned: " + (excerpt(L(p)) or "empty output"))
        return PASS("0 active entries") if int(nums[0]) == 0 else FAIL("%s active inetd entries match" % nums[0])
    EVAL[rid] = f


def rctcpip_daemon(rid, daemon, svc=None):
    """a: grep of rc.tcpip (all lines), b: lssrc listing."""
    def f():
        a, b = G(rid, "a"), G(rid, "b")
        if a.rc is not None and a.rc > 1:
            raise NC("/etc/rc.tcpip could not be read: " + (errtext(a).strip()[:100]))
        bad = []
        started = [l for l in L(a) if not l.lstrip().startswith("#")]
        if started:
            bad.append("started from rc.tcpip: " + excerpt(started, 1))
        running = [l for l in L(b) if re.search(r"\bactive\s*$", l) and not re.search(r"inoperative", l)]
        if running:
            bad.append("subsystem active: " + excerpt(running, 1))
        return FAIL("; ".join(bad)) if bad else PASS("start entry disabled, subsystem not active")
    EVAL[rid] = f


def sshd_val(rid, name, key):
    p = G(rid, name)
    m = re.search(r"^\s*" + re.escape(key) + r"\s+(.*?)\s*$", text(p), re.I | re.M)
    if m:
        return m.group(1).strip('"')
    if not L(p):
        raise NC("sshd -T returned nothing for '%s' (sshd missing or not run as root?)" % key)
    return None


def ssh_flag(rid, key, want, conflict=None):
    def f():
        v = sshd_val(rid, "a", key)
        bad = []
        if v is None or v.lower() != want:
            bad.append("%s %s (required %s)" % (key, v, want))
        if conflict:
            c = G(rid, "b")
            if L(c):
                bad.append("sshd_config contains: " + excerpt(L(c), 1))
        return FAIL("; ".join(bad)) if bad else PASS("%s %s" % (key, v))
    EVAL[rid] = f


# ---------------------------------------------------------------------------
# 2 / 3  Inventory, data protection
# ---------------------------------------------------------------------------

@reg("2.1")
def _():
    a, b = G("2.1", "a"), G("2.1", "b")
    bad = []
    if not L(a):
        bad.append("no root crontab entry calling 'lsconf -v'")
    if not L(b):
        bad.append("no syslog.conf entry for syslog/inventory.log")
    return FAIL("; ".join(bad)) if bad else PASS("cron job and syslog entry present (verify frequency against site policy)")


def trustchk_vals(p):
    d = {}
    for l in L(p):
        k, _, v = l.strip().partition("=")
        d.setdefault(k.strip().upper(), v.strip())
    return d


@reg("2.2")
def _():
    d = trustchk_vals(G("2.2"))
    if not d:
        return FAIL("trustchk returned nothing")
    bad = ["%s=%s" % (k, d.get(k)) for k in ("TE", "TEP") if (d.get(k) or "").upper() != "ON"]
    return FAIL("; ".join(bad) + " (required ON)") if bad else PASS("TE=ON TEP=ON")


@reg("2.3")
def _():
    v = trustchk_vals(G("2.3")).get("LOCK_KERN_POLICIES", "")
    return PASS("LOCK_KERN_POLICIES=ON") if v.upper() == "ON" else FAIL("LOCK_KERN_POLICIES=%s (required ON)" % (v or "not reported"))


@reg("2.4")
def _():
    d = trustchk_vals(G("2.4", "a"))
    b = G("2.4", "b")
    bad = ["%s=%s" % (k, d.get(k)) for k in ("TE", "CHKEXEC") if (d.get(k) or "").upper() != "ON"]
    if not [l for l in L(b) if not l.lstrip().startswith("#")]:
        bad.append("no kern.info destination in /etc/syslog.conf")
    return FAIL("; ".join(bad)) if bad else PASS("TE=ON CHKEXEC=ON and kern.info logging configured")


@reg("2.5")
def _():
    d = trustchk_vals(G("2.5"))
    bad = []
    if d.get("STOP_UNTRUSTD", "").upper() not in ("ON", "TROJAN"):
        bad.append("stop_untrustd=%s" % (d.get("STOP_UNTRUSTD") or "not reported"))
    for k in ("STOP_ON_CHKFAIL", "TE"):
        if d.get(k, "").upper() != "ON":
            bad.append("%s=%s" % (k.lower(), d.get(k) or "not reported"))
    return FAIL("; ".join(bad)) if bad else PASS("stop_untrustd=%s stop_on_chkfail=ON te=ON" % d["STOP_UNTRUSTD"])


@reg("2.6")
def _():
    p = G("2.6")
    n = len(L(p))
    return FAIL("%d untrusted object(s) reported: %s" % (n, excerpt(L(p)))) if n else PASS("trustchk reports no untrusted objects")


empty_ok("2.7", what="no dangling symbolic links", fail_what="dangling symbolic links")


@reg("3.1")
def _():
    v = lssec_val(G("3.1"), "umask")
    if not v:
        return FAIL("umask not set in the default stanza (required 027 or more restrictive)")
    return PASS("umask=" + v) if re.match(r"^[0-7]?[2367]7$", v) else FAIL("umask=%s is insufficiently restrictive (required 027)" % v)


empty_ok("3.2", what="no world-writable directory without sticky bit", fail_what="world-writable directories without SVTX")


@reg("3.3")
def _():
    p = G("3.3")
    if any("NO_ADMIN_GROUPS_FOUND" in l for l in p.out):
        return MAN("no group with admin=true found; review manually")
    n = len(L(p))
    return FAIL("%d group-writable object(s) owned by system groups: %s" % (n, excerpt(L(p), 2))) if n else PASS("none found")


empty_ok("3.4", what="no world-writable files", fail_what="world-writable files")
empty_ok("3.5", what="no group staff writable files", fail_what="group staff writable files")
empty_ok("3.6", what="no unowned files or directories", fail_what="files/directories without owner or group")

# ---------------------------------------------------------------------------
# 4.1.1  Trusted files
# ---------------------------------------------------------------------------

perm("4.1.1.1", "a", None, None, 0o640, optional=True)
perm("4.1.1.2", "a", {"root"}, {"security"}, 0o644)
perm("4.1.1.3", "a", {"root"}, {"system"}, 0o644)
perm("4.1.1.4", "a", {"bin"}, {"bin"}, 0o644)
perm("4.1.1.5", "a", {"root"}, {"security"}, 0o644)


@reg("4.1.1.6")
def _():
    p = G("4.1.1.6", "a")
    t = text(p).strip()
    if "FILE_NOT_FOUND" in t:
        return PASS("/etc/mail/submit.cf not present - nothing to protect")
    if not re.match(r"^[0-7]{3,4}$", t):
        raise NC("could not determine mode: " + (t[:80] or errtext(p)[:80]))
    mode = int(t, 8)
    return PASS("mode %s" % t) if not (mode & ~0o640 & 0o7777) else FAIL("mode %s is less restrictive than 640" % t)


perm("4.1.1.7", "a", {"root"}, {"system"}, 0o644, optional=True)
perm("4.1.1.8", "a", {"root"}, {"system"}, 0o644, optional=True)
perm("4.1.1.9", "a", {"root"}, {"system"}, 0o644, optional=True)
perm("4.1.1.10", "a", {"root"}, {"sys"}, 0o400)
perm("4.1.1.11", "a", {"root"}, {"sys"}, 0o400)
perm("4.1.1.12", "a", {"bin"}, {"cron"}, 0o660)
for _rid in ("4.1.1.13", "4.1.1.14", "4.1.1.15", "4.1.1.16", "4.1.1.20"):
    perm(_rid, "a", {"root"}, {"system"}, 0o640, optional=True)


@reg("4.1.1.17")
def _():
    p = G("4.1.1.17")
    w = [l.strip() for l in L(p) if "WARNING" in l]
    return FAIL("%d problem(s): %s" % (len(w), excerpt(w))) if w else PASS("all commands in root's crontab are protected")


@reg("4.1.1.18")
def _():
    p = G("4.1.1.18")
    w = [t for t in ls_entries(p) if mode_int(t[0]) & 0o022]
    if w:
        return FAIL("%d dot file(s) group/world writable: %s" % (len(w), excerpt([x[3] + " " + x[0] for x in w])))
    return PASS("no group/world writable user dot files")


@reg("4.1.1.19")
def _():
    p = G("4.1.1.19")
    n = len(L(p))
    return MAN("%d SUID/SGID file(s) found - review each against site policy: %s" % (n, excerpt(L(p), 2))) if n else PASS("no SUID/SGID files")


# ---------------------------------------------------------------------------
# 4.1.2  Trusted directories
# ---------------------------------------------------------------------------

@reg("4.1.2.1")
def _():
    p = G("4.1.2.1")
    return FAIL(excerpt(L(p))) if L(p) else PASS("all HOME directories exist")


@reg("4.1.2.2")
def _():
    p = G("4.1.2.2")
    return FAIL(excerpt(L(p))) if L(p) else PASS("all HOME directories have the correct owner")


@reg("4.1.2.3")
def _():
    p = G("4.1.2.3")
    return FAIL(excerpt(L(p))) if L(p) else PASS("no HOME directory is group/world writable")


@reg("4.1.2.4")
def _():
    p = G("4.1.2.4")
    return FAIL("%d object(s) with wrong owner/group/mode: %s" % (len(L(p)), excerpt(L(p)))) if L(p) else PASS("owner root:audit, no 'other' access")


@reg("4.1.2.5")
def _():
    p = G("4.1.2.5")
    return FAIL("%d directory(ies): %s" % (len(L(p)), excerpt(L(p)))) if L(p) else PASS("all directories below /etc/security are drwxr-s---")


@reg("4.1.2.6")
def _():
    p = G("4.1.2.6")
    bad = []
    for m, o, g, nm in ls_entries(p):
        base = nm.rsplit("/", 1)[-1]
        if m[8] == "w":
            bad.append("%s world-writable" % base)
        elif m[7] == "r" and base != "SRCKeyID":
            bad.append("%s world-readable" % base)
    if not ls_entries(p):
        raise NC("no directory listing returned")
    return FAIL("%d file(s): %s" % (len(bad), excerpt(bad))) if bad else PASS("no 'other' access (SRCKeyID excepted)")


perm("4.1.2.7", "a", {"adm"}, {"adm"}, 0o755)


def _cron_dir(rid):
    def f():
        a, b, c = G(rid, "a"), G(rid, "b"), G(rid, "c")
        if re.search(r"No such file|does not exist|0652-", errtext(a)):
            raise NC("directory does not exist: " + errtext(a).strip()[:100])
        bad = [excerpt(L(x)) for x in (a, b) if L(x)]
        if any("trustchk failed" in l for l in c.out):
            bad.append("trustchk verification failed")
        return FAIL("; ".join(bad)) if bad else PASS("owner/group/modes as required, TCB entry valid")
    EVAL[rid] = f


_cron_dir("4.1.2.8")


@reg("4.1.2.9")
def _():
    a, b, c = G("4.1.2.9", "a"), G("4.1.2.9", "b"), G("4.1.2.9", "c")
    if re.search(r"No such file|does not exist|0652-", errtext(a)):
        raise NC("directory does not exist: " + errtext(a).strip()[:100])
    bad = [excerpt(L(x)) for x in (a, b) if L(x)]
    if any("trustchk failed" in l for l in c.out):
        bad.append("trustchk verification failed")
    return FAIL("; ".join(bad)) if bad else PASS("modes as required, TCB entry valid")


@reg("4.1.2.10")
def _():
    p = G("4.1.2.10")
    w = [l.strip() for l in L(p)]
    return FAIL("; ".join(w[:4])) if w else PASS("all directories in root's PATH are safe")


@reg("4.1.2.11")
def _():
    v = lssec_val(G("4.1.2.11"), "home")
    if v is None:
        raise NC("home of root not reported")
    return FAIL("root home=/ (dedicated home directory required)") if v == "/" else PASS("root home=" + v)


# ---------------------------------------------------------------------------
# 4.2  Network services
# ---------------------------------------------------------------------------

fileset_absent("4.2.1")


@reg("4.2.2")
def _():
    a = G("4.2.2", "a")
    if not L(a):
        return PASS("NIS server not installed")
    b = G("4.2.2", "b")
    if L(b):
        return MAN("NIS server installed; /var/yp/securenets present - verify it restricts clients")
    return FAIL("NIS server installed and no /var/yp/securenets")


empty_ok("4.2.3", what="no legacy NIS '+' entries", fail_what="legacy '+' entries")
empty_ok("4.2.4", what="/etc/hosts.equiv has no active entries", fail_what="active entries in /etc/hosts.equiv")
empty_ok("4.2.5", ("a", "b", "c"), what="no .netrc/.rhosts/.shosts files", fail_what="host based authentication files")
empty_ok("4.2.6", what="rcmd filesets are disabled", fail_what="rcmd files not disabled")
empty_ok("4.2.7", what="SNMP filesets not installed", fail_what="SNMP filesets installed")

# ---------------------------------------------------------------------------
# 4.3  Boot phase subsystems
# ---------------------------------------------------------------------------


@reg("4.3.1.1")
def _():
    a, b = G("4.3.1.1", "a"), G("4.3.1.1", "b")
    bad = []
    on = [l for l in L(a) if ":off:" not in l]
    if on:
        bad.append("inittab entry not 'off': " + excerpt(on, 1))
    run = [l for l in L(b) if "inoperative" not in l]
    if run:
        bad.append("writesrv running: " + excerpt(run, 1))
    return FAIL("; ".join(bad)) if bad else PASS("writesrv disabled")


empty_ok("4.3.1.2", what="no dt/dt_nogb inittab entry", fail_what="inittab")
empty_ok("4.3.1.3", what="no piobe inittab entry", fail_what="inittab")
empty_ok("4.3.1.4", what="no qdaemon inittab entry", fail_what="inittab")


@reg("4.3.1.5")
def _():
    on = [l for l in L(G("4.3.1.5")) if ":off:" not in l]
    return FAIL("rcnfs not off: " + excerpt(on)) if on else PASS("rcnfs entry off or absent")


fileset_absent("4.3.1.6")


@reg("4.3.1.7")
def _():
    p = G("4.3.1.7")
    return FAIL("NIM master/spot installed: " + excerpt(L(p), 2)) if L(p) else PASS("NIM master not installed")


@reg("4.3.2.1")
def _():
    b = G("4.3.2.1", "b")
    if b.rc is not None and b.rc > 1:
        raise NC("/etc/rc.tcpip could not be read: " + errtext(b).strip()[:100])
    started = [l for l in L(b) if not l.lstrip().startswith("#")]
    if started:
        return FAIL("inetd started from /etc/rc.tcpip: " + excerpt(started, 1) +
                    " (acceptable only when inetd services are required; then use TCP wrappers)")
    return PASS("inetd start entry is commented out (or absent)")


for _rid, _d in (("4.3.2.2", "dhcpcd"), ("4.3.2.3", "dhcprd"), ("4.3.2.4", "dhcpsd"), ("4.3.2.5", "gated"),
                 ("4.3.2.6", "hostmibd"), ("4.3.2.7", "mrouted"), ("4.3.2.8", "named"), ("4.3.2.10", "routed"),
                 ("4.3.2.11", "rwhod"), ("4.3.2.12", "sendmail"), ("4.3.2.13", "timed")):
    rctcpip_daemon(_rid, _d)


@reg("4.3.2.9")
def _():
    p = G("4.3.2.9")
    bad = []
    m = re.search(r"OTHER_RPC_SERVICES=(\d+)", text(p))
    if m and int(m.group(1)) > 0:
        bad.append("%s RPC service(s) besides portmap registered" % m.group(1))
    if [l for l in p.out if re.match(r"^portmap\s.*\bactive\s*$", l) and "inoperative" not in l]:
        bad.append("portmap subsystem is active")
    if [l for l in p.out if re.search(r"start\s+/usr/sbin/portmap", l) and not l.lstrip().startswith("#")]:
        bad.append("portmap is started from /etc/rc.tcpip")
    return FAIL("; ".join(bad)) if bad else PASS("portmap not in use")


for _rid, _d in (("4.3.3.1", "autoconf6"), ("4.3.3.2", "ndpd-host"), ("4.3.3.3", "ndpd-router")):
    def _mk(rid, d):
        def f():
            b = G(rid, "b")
            if b.rc is not None and b.rc > 1:
                raise NC("/etc/rc.tcpip could not be read: " + errtext(b).strip()[:100])
            started = [l for l in L(b) if not l.lstrip().startswith("#")]
            return FAIL("%s is started in /etc/rc.tcpip: %s" % (d, excerpt(started, 1))) if started else PASS("%s start entry commented out" % d)
        EVAL[rid] = f
    _mk(_rid, _d)

for _n in range(1, 33):
    _rid = "4.3.4.%d" % _n
    if _n in (17, 22):
        continue
    inetd_count(_rid)


@reg("4.3.4.17")
def _():
    a = G("4.3.4.17")
    sysp = sys_probe("inetd_conf")
    active = [l for l in L(sysp) if sysp and re.match(r"^\s*pop3\s", l)] if sysp else []
    if active:
        return FAIL("pop3 enabled in /etc/inetd.conf")
    return PASS("pop3 entry commented out" if L(a) else "no active pop3 entry in /etc/inetd.conf")


@reg("4.3.4.22")
def _():
    p = G("4.3.4.22")
    return FAIL("rsync active in inetd: " + excerpt(L(p), 1)) if L(p) else PASS("rsync not active in inetd")


# ---------------------------------------------------------------------------
# 4.4  Filesystem configuration
# ---------------------------------------------------------------------------

@reg("4.4.1.1")
def _():
    a, b = G("4.4.1.1", "a"), G("4.4.1.1", "b")
    bad = []
    if L(a):
        bad.append("NFS in /etc/filesystems: " + excerpt(L(a), 2))
    if L(b):
        bad.append("NFS currently mounted: " + excerpt(L(b), 2))
    return FAIL("; ".join(bad)) if bad else PASS("no NFS client mounts")


@reg("4.4.1.2")
def _():
    a, b = G("4.4.1.2", "a"), G("4.4.1.2", "b")
    bad = []
    if L(a):
        bad.append("bos.net.nfs.server installed")
    if [l for l in L(b) if not l.lstrip().startswith("#")]:
        bad.append("active exports: " + excerpt(L(b), 2))
    return FAIL("; ".join(bad)) if bad else PASS("NFS server not installed, no exports")


@reg("4.4.1.3")
def _():
    a, b = G("4.4.1.3", "a"), G("4.4.1.3", "b")
    bad = []
    if L(a):
        bad.append("without nosuid: " + excerpt(L(a), 2))
    if L(b):
        bad.append("without nodev: " + excerpt(L(b), 2))
    return FAIL("; ".join(bad)) if bad else PASS("all NFS mounts use nosuid and nodev (or none exist)")


@reg("4.4.1.4")
def _():
    a, b = G("4.4.1.4", "a"), G("4.4.1.4", "b")
    names = {"localhost", "127.0.0.1", "::1"}
    for l in L(b):
        t = l.split("#")[0].split()
        names.update(x.lower() for x in t)
    hits = []
    for l in L(a):
        if l.lstrip().startswith("#"):
            continue
        toks = {x.lower() for x in re.split(r"[\s:,=()]+", l) if x}
        if toks & names:
            hits.append(l.strip())
    return FAIL("localhost reference(s) in /etc/exports: " + excerpt(hits)) if hits else PASS("no localhost aliases in /etc/exports")


@reg("4.4.1.5")
def _():
    p = G("4.4.1.5", "a")
    nums = [l.strip() for l in L(p) if l.strip().isdigit()]
    if not nums:
        raise NC("showmount returned no count")
    return PASS("no export is open to everyone") if int(nums[0]) == 0 else FAIL("%s export(s) open to (everyone): %s" % (nums[0], excerpt(L(G("4.4.1.5", "b")), 2)))


empty_ok("4.4.1.6", what="no exports with an explicit anon= option", fail_what="exports with explicit anon=")
empty_ok("4.4.1.7", ("a", "b"), what="every export defines a secure sec= method", fail_what="exports lacking sec= or using sec=none")


@reg("4.4.2.1")
def _():
    a, b, c = G("4.4.2.1", "a"), G("4.4.2.1", "b"), G("4.4.2.1", "c")
    bad = []
    if not [l for l in L(a) if "clic.rte" in l]:
        bad.append("CLiC (clic.rte) filesets not installed")
    if not [l for l in L(b) if "crypt" in l or "clic" in l]:
        bad.append("CLiC kernel extension not loaded")
    if bad:
        return FAIL("; ".join(bad))
    return PASS("CLiC installed and loaded" + ("; EFS file system(s) present" if L(c) else "; no EFS file system defined yet"))


@reg("4.4.3.1")
def _():
    a, b = G("4.4.3.1", "a"), G("4.4.3.1", "b")
    bad = []
    if L(a):
        bad.append("lsfs: " + excerpt(L(a), 2))
    if L(b):
        bad.append("mounted: " + excerpt(L(b), 2))
    return FAIL("jfs file systems without nodev: " + "; ".join(bad)) if bad else PASS("only / permits device files")


# ---------------------------------------------------------------------------
# 4.5  Network options
# ---------------------------------------------------------------------------

for _rid, _o, _v in (("4.5.1", "sockthresh", 60), ("4.5.2", "bcastping", 0), ("4.5.3", "clean_partial_conns", 1),
                     ("4.5.4", "directed_broadcast", 0), ("4.5.5", "icmpaddressmask", 0), ("4.5.6", "ipforwarding", 0),
                     ("4.5.7", "ip6forwarding", 0), ("4.5.8", "ipignoreredirects", 1), ("4.5.9", "ipsendredirects", 0),
                     ("4.5.10", "ipsrcrouteforward", 0), ("4.5.11", "ipsrcrouterecv", 0), ("4.5.12", "ipsrcroutesend", 0),
                     ("4.5.13", "ip6srcrouteforward", 0), ("4.5.15", "nonlocsrcroute", 0), ("4.5.16", "tcp_pmtu_discover", 0),
                     ("4.5.18", "udp_pmtu_discover", 0), ("4.5.19", "icmptimestamp", 0)):
    netopts(_rid, [(_o, _v)])
netopts("4.5.14", [("portcheck", 1), ("nfs_use_reserved_ports", 1)])


@reg("4.5.17")
def _():
    p = G("4.5.17")
    m = re.search(r"tcp_tcpsecure\s*=\s*(\d+)", text(p))
    if not m:
        raise NC("tcp_tcpsecure not reported")
    return PASS("tcp_tcpsecure=7") if int(m.group(1)) == 7 else FAIL("tcp_tcpsecure=%s (required 7)" % m.group(1))


# ---------------------------------------------------------------------------
# 4.6.1  CDE
# ---------------------------------------------------------------------------

@reg("4.6.1.1")
def _():
    p = G("4.6.1.1")
    return FAIL("CDE filesets installed: " + excerpt(L(p), 2)) if L(p) else PASS("CDE (X11.Dt) not installed")


def _cde_installed():
    return fileset_installed("X11.Dt.rte") or fileset_installed("X11.Dt.lib")


def _cde_gate(rid, fn):
    def f():
        p = G("4.6.1.1")
        if not L(p):
            return PASS("CDE is not installed - not applicable")
        return fn()
    EVAL[rid] = f


_cde_gate("4.6.1.2", lambda: (lambda n: PASS("0 active cmsd entries") if n == 0 else FAIL("cmsd active in inetd"))(
    int(([l.strip() for l in L(G("4.6.1.2")) if l.strip().isdigit()] or ["-1"])[0])))
_cde_gate("4.6.1.3", lambda: FAIL("CDE start-up entry present: " + excerpt(L(G("4.6.1.3")), 2)) if L(G("4.6.1.3")) else PASS("no dt/dt_nogb inittab entry"))


@reg("4.6.1.4")
def _():
    p = G("4.6.1.4")
    sysp = sys_probe("inetd_conf")
    active = [l for l in L(sysp) if re.match(r"^\s*dtspc\s", l)] if sysp else []
    if active:
        return FAIL("dtspc is active in /etc/inetd.conf")
    return PASS("dtspc entry is not active")


@reg("4.6.1.5")
def _():
    p = G("4.6.1.5")
    if not L(p) and absent(p):
        return PASS("CDE binaries not present")
    bad = []
    for l in L(p):
        t = l.split()
        if len(t) >= 4 and re.match(r"^[-rwxsStT]{10}$", t[0]) and (t[0][3] in "sS" or t[0][6] in "sS"):
            bad.append("%s %s" % (t[0], t[-1]))
    return FAIL("suid/sgid still set: " + excerpt(bad)) if bad else PASS("no suid/sgid on CDE binaries")


def _cde_requestport():
    p = G("4.6.1.6")
    if not L(p):
        return FAIL("Dtlogin.requestPort: 0 is not set in /etc/dt/config/Xconfig")
    v = re.search(r"requestPort:\s*(\S+)", text(p))
    return PASS("Dtlogin.requestPort: 0") if v and v.group(1) == "0" else FAIL("Dtlogin.requestPort: %s (required 0)" % (v.group(1) if v else "?"))




_cde_gate("4.6.1.6", _cde_requestport)


def _cde_timeouts():
    p = G("4.6.1.7")
    t = text(p)
    if not re.search(r"Checking config file", t):
        return PASS("no CDE language directories found")
    bad = []
    if re.search(r"Missing (config file|setting)", t):
        bad += [l.strip() for l in L(p) if "Missing" in l]
    for key in ("saverTimeout", "lockTimeout"):
        for m in re.finditer(r"dtsession\*%s:\s*(\d+)" % key, t):
            if int(m.group(1)) > 15:
                bad.append("%s=%s (>15)" % (key, m.group(1)))
    return FAIL(excerpt(bad)) if bad else PASS("saverTimeout and lockTimeout are set")


_cde_gate("4.6.1.7", _cde_timeouts)


def _cde_greeting():
    p = G("4.6.1.8")
    t = text(p)
    if not re.search(r"Checking config file", t):
        return PASS("no CDE language directories found")
    bad = [l.strip() for l in L(p) if "Missing" in l]
    return FAIL(excerpt(bad)) if bad else PASS("greeting labels are set")


_cde_gate("4.6.1.8", _cde_greeting)
perm("4.6.1.9", "a", {"root"}, {"bin"}, 0o755, optional=True)


@reg("4.6.1.10")
def _():
    a, b = G("4.6.1.10", "a"), G("4.6.1.10", "b")
    if not ls_entries(a):
        return PASS("/etc/dt/config/Xservers does not exist")
    r = sub_perm("4.6.1.10", "a", {"root"}, {"bin"}, 0o755)
    bad = [r[1]] if r[0] == "FAIL" else []
    if not re.search(r"Dtlogin\*servers:\s*/etc/dt/config/Xservers", text(b)):
        bad.append("Dtlogin*servers does not use the absolute path /etc/dt/config/Xservers")
    return FAIL("; ".join(bad)) if bad else PASS("owner/mode correct and absolute path used")


def sub_perm(rid, name, owners, groups, maxmode):
    p = G(rid, name)
    ents = ls_entries(p)
    if not ents:
        return FAIL("object does not exist")
    m, o, g, nm = ents[0]
    bad = []
    if o not in owners:
        bad.append("owner " + o)
    if g not in groups:
        bad.append("group " + g)
    if mode_int(m) & ~maxmode & 0o7777:
        bad.append("mode %04o" % (mode_int(m) & 0o7777))
    return FAIL("%s: %s" % (nm, ", ".join(bad))) if bad else PASS()


@reg("4.6.1.11")
def _():
    p = G("4.6.1.11")
    ents = ls_entries(p)
    if not ents:
        return PASS("no /etc/dt/config/*/Xresources files")
    bad = []
    for m, o, g, nm in ents:
        if o != "root" or g != "sys" or mode_int(m) & ~0o644 & 0o7777:
            bad.append("%s %s %s:%s" % (nm, m, o, g))
    return FAIL(excerpt(bad)) if bad else PASS("%d file(s) root:sys, 644 or tighter" % len(ents))


# ---------------------------------------------------------------------------
# 4.6.2  ftpd
# ---------------------------------------------------------------------------

@reg("4.6.2.1")
def _():
    p = G("4.6.2.1")
    return PASS("root listed in /etc/ftpusers") if [l for l in L(p) if l.strip() == "root"] else FAIL("root is not listed in /etc/ftpusers")


def _ftp_on():
    sysp = sys_probe("inetd_conf")
    return bool(sysp and [l for l in L(sysp) if re.match(r"^\s*ftp\s", l)])


@reg("4.6.2.2")
def _():
    p = G("4.6.2.2")
    if "FTP_NOT_ENABLED_IN_INETD_CONF" in text(p):
        return PASS("ftpd not enabled in inetd.conf - not applicable")
    t = text(p)
    return PASS("banner: " + t.strip()[:100]) if re.search(r"Authorized uses only", t) else FAIL("ftpd banner is not the AUP text: " + (t.strip()[:100] or "empty"))


@reg("4.6.2.3")
def _():
    p = G("4.6.2.3")
    if "FTP_NOT_ENABLED_IN_INETD_CONF" in text(p):
        return PASS("ftpd not enabled in inetd.conf - not applicable")
    t = text(p)
    return PASS(t.strip()[:100]) if re.search(r"ftpd\s+-l\s+-u\s+0?27\b|-u\s*0?27\b", t) else FAIL("ftpd umask 027 not set: " + (t.strip()[:100] or "empty"))


# ---------------------------------------------------------------------------
# 4.6.3  OpenSSH
# ---------------------------------------------------------------------------

@reg("4.6.3.1")
def _():
    a, b, c = G("4.6.3.1", "a"), G("4.6.3.1", "b"), get("4.6.3.1", "c")
    t = (text(a) + "\n" + errtext(a) + "\n" + text(c) + "\n" + errtext(c))
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", t)
    if not m:
        raise NC("OpenSSH version not found in evidence")
    ver = "%s.%s" % (m.group(1), m.group(2))
    return PASS("OpenSSH " + ver) if int(m.group(1)) >= 9 else FAIL("OpenSSH %s is older than 9 (benchmark requires 9.x or later)" % ver)


@reg("4.6.3.2")
def _():
    p = G("4.6.3.2")
    return FAIL("present: " + excerpt([x[3] for x in ls_entries(p)])) if ls_entries(p) else PASS("/etc/[rs]hosts.equiv do not exist")


@reg("4.6.3.3")
def _():
    p = G("4.6.3.3")
    s = [l for l in L(p) if re.match(r"(?i)subsystem\s+sftp", l.strip())]
    if not s:
        raise NC("no 'subsystem sftp' line from sshd -T")
    ok = re.search(r"(?i)subsystem\s+sftp\s+(/usr/sbin/sftp-server|internal-sftp)\s+-u\s+0?27\s+-f\s+AUTH\s+-l\s+(INFO|VERBOSE)\s*$", s[0].strip())
    return PASS(s[0].strip()) if ok else FAIL(s[0].strip())


@reg("4.6.3.4")
def _():
    p = G("4.6.3.4")
    return PASS(excerpt(L(p), 2) + " (review list against site policy)") if L(p) else FAIL("no AllowUsers/AllowGroups/DenyUsers/DenyGroups configured")


@reg("4.6.3.5")
def _():
    a, b, c = G("4.6.3.5", "a"), G("4.6.3.5", "b"), get("4.6.3.5", "c")
    t = [l.strip() for l in L(a) if re.match(r"(?i)banner\b", l.strip())]
    if not t:
        raise NC("sshd -T returned no banner line")
    bad = []
    if t[0].split(None, 1)[-1] != "/etc/ssh/ssh_banner":
        bad.append("banner is '%s' (required /etc/ssh/ssh_banner)" % t[0])
    if L(b):
        bad.append("sshd_config sets Banner none")
    if not L(c) and not bad:
        bad.append("banner file is empty or missing")
    return FAIL("; ".join(bad)) if bad else PASS(t[0] + " (review banner text against site policy)")


WEAK_CIPHERS = {"3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "arcfour128",
                "arcfour256", "rijndael-cbc@lysator.liu.se", "chacha20-poly1305@openssh.com"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1-96", "umac-64@openssh.com", "hmac-md5-etm@openssh.com",
             "hmac-md5-96-etm@openssh.com", "hmac-ripemd160-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
             "umac-64-etm@openssh.com", "umac-128-etm@openssh.com"}
WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}


def _alg(rid, name, key, weak):
    def f():
        p = G(rid, name)
        t = [l for l in L(p) if l.strip().lower().startswith(key)]
        if not t:
            raise NC("sshd -T returned no '%s' line" % key)
        algs = set(t[0].split(None, 1)[1].strip().split(","))
        hit = sorted(algs & weak)
        return FAIL("weak %s enabled: %s" % (key, ", ".join(hit))) if hit else PASS("no weak %s enabled" % key)
    return f


EVAL["4.6.3.6"] = _alg("4.6.3.6", "a", "ciphers", WEAK_CIPHERS)
EVAL["4.6.3.9"] = _alg("4.6.3.9", "a", "kexalgorithms", WEAK_KEX)
EVAL["4.6.3.11"] = _alg("4.6.3.11", "a", "macs", WEAK_MACS)
ssh_flag("4.6.3.7", "hostbasedauthentication", "no", conflict=True)
ssh_flag("4.6.3.8", "ignorerhosts", "yes", conflict=True)


@reg("4.6.3.10")
def _():
    v = sshd_val("4.6.3.10", "a", "loglevel")
    return PASS("loglevel " + v) if v and v.upper() in ("INFO", "VERBOSE") else FAIL("loglevel %s (required INFO or VERBOSE)" % v)


@reg("4.6.3.12")
def _():
    v = to_int(sshd_val("4.6.3.12", "a", "maxauthtries"))
    return PASS("maxauthtries %d" % v) if v is not None and v <= 4 else FAIL("maxauthtries %s (required <= 4)" % v)


@reg("4.6.3.13")
def _():
    a, b = G("4.6.3.13", "a"), G("4.6.3.13", "b")
    v = sshd_val("4.6.3.13", "b", "permitemptypasswords")
    bad = []
    if v is None or v.lower() != "no":
        bad.append("effective permitemptypasswords=%s" % v)
    if not [l for l in L(a) if re.match(r"PermitEmptyPasswords\s+no\s*$", l.strip())]:
        bad.append("'PermitEmptyPasswords no' is not explicitly set in sshd_config")
    return FAIL("; ".join(bad)) if bad else PASS("PermitEmptyPasswords no")


def _root_login(rid, allowed):
    def f():
        a = G(rid, "a")
        v = sshd_val(rid, "b", "permitrootlogin")
        cfg = [l.split() for l in L(a) if l.startswith("PermitRootLogin")]
        bad = []
        if not cfg:
            bad.append("PermitRootLogin is not set in sshd_config")
        elif cfg[0][1] not in allowed:
            bad.append("sshd_config: %s" % " ".join(cfg[0]))
        if v is None or v not in allowed:
            bad.append("effective permitrootlogin=%s" % v)
        return FAIL("; ".join(bad) + " (allowed: %s)" % ", ".join(sorted(allowed))) if bad else PASS("PermitRootLogin " + v)
    return f


EVAL["4.6.3.14"] = _root_login("4.6.3.14", {"prohibit-password", "no", "forced-commands-only"})
EVAL["4.6.3.15"] = _root_login("4.6.3.15", {"no"})
ssh_flag("4.6.3.16", "permituserenvironment", "no")


@reg("4.6.3.17")
def _():
    v = sshd_val("4.6.3.17", "a", "rekeylimit")
    return PASS("rekeylimit " + v) if v and v.split() == ["1073741824", "3600"] else FAIL("rekeylimit %s (required 1073741824 3600)" % v)


@reg("4.6.3.18")
def _():
    p = G("4.6.3.18", "a")
    t = text(p).lower()
    vals = {}
    for k in ("clientaliveinterval", "clientalivecountmax"):
        m = re.search(r"^" + k + r"\s+(\d+)", t, re.M)
        vals[k] = int(m.group(1)) if m else None
    if all(v is None for v in vals.values()):
        raise NC("sshd -T returned no ClientAlive settings")
    bad = ["%s=%s" % (k, v) for k, v in vals.items() if not v]
    m = G("4.6.3.18", "b")
    note = " (Match blocks present - verify them with sshd -T -C user=...)" if L(m) else ""
    return FAIL("; ".join(bad) + " (both must be > 0)") if bad else PASS("clientaliveinterval=%d clientalivecountmax=%d%s" % (vals["clientaliveinterval"], vals["clientalivecountmax"], note))


# ---------------------------------------------------------------------------
# 4.6.4  sendmail
# ---------------------------------------------------------------------------

SENDMAIL_FS = "bos.net.tcp.sendmail"


def _sendmail_gate(rid):
    """PASS (not applicable) when sendmail is not installed; otherwise run the normal check."""
    inner = EVAL[rid]

    def f():
        sys_probe("lslpp_all")
        if fileset_installed(SENDMAIL_FS) is False:
            return PASS("sendmail (%s) is not installed - not applicable" % SENDMAIL_FS)
        return inner()
    EVAL[rid] = f


@reg("4.6.4.1")
def _():
    a, b = G("4.6.4.1", "a"), G("4.6.4.1", "b")
    if not L(a) and absent(a):
        return PASS("/etc/mail/sendmail.cf does not exist - nothing to check")
    t = text(a)
    bad = []
    if not L(a):
        bad.append("no 'O SmtpGreetingMessage' line in sendmail.cf")
    elif "$j Sendmail $b" in t or "$b" in t:
        bad.append("greeting reveals the sendmail version: " + t.strip()[:80])
    if "HELPFILE_EXISTS" not in text(b):
        bad.append("sendmail help file is missing")
    return FAIL("; ".join(bad)) if bad else PASS(t.strip()[:80])


@reg("4.6.4.2")
def _():
    p = G("4.6.4.2", "a")
    if not L(p) and absent(p):
        return PASS("/etc/mail/sendmail.cf does not exist - nothing to check")
    t = text(p).lower()
    miss = [o for o in ("authwarnings", "novrfy", "noexpn") if o not in t]
    if not L(p):
        return FAIL("no 'O PrivacyOptions' line in sendmail.cf")
    return FAIL("missing PrivacyOptions: " + ", ".join(miss)) if miss else PASS(text(p).strip()[:100])


perm("4.6.4.3", "a", {"root"}, {"system"}, 0o640, optional=True)
perm("4.6.4.4", "a", {"smmsp"}, {"smmsp"}, 0o770, optional=True)
perm("4.6.4.5", "a", {"root"}, None, 0o700, optional=True)

for _rid in ("4.6.4.1", "4.6.4.2", "4.6.4.3", "4.6.4.4", "4.6.4.5"):
    _sendmail_gate(_rid)

# ---------------------------------------------------------------------------
# 4.7  Login controls
# ---------------------------------------------------------------------------


@reg("4.7.1")
def _():
    v = lssec_val(G("4.7.1"), "herald")
    return PASS("herald set (compare against site policy): " + v[:80]) if v else FAIL("no default herald (login banner) configured")


numattr("4.7.2", "logindelay", "ge", 10)
numattr("4.7.3", "loginretries", "eq", 5)
numattr("4.7.4", "logintimeout", "le", 30)


def _tmout(rid, need_ro):
    def f():
        a, b, c = G(rid, "a"), G(rid, "b"), G(rid, "c")
        vals = {}
        for p in (a, b):
            for m in re.finditer(r"\b(TMOUT|TIMEOUT)=\"?(\d+)", text(p)):
                vals.setdefault(m.group(1), int(m.group(2)))
        prof = text(c)
        for m in re.finditer(r"^\s*(?:readonly\s+|export\s+)?(TMOUT|TIMEOUT)=\"?(\d+)", prof, re.M):
            vals.setdefault("profile:" + m.group(1), int(m.group(2)))
        eff = {k: v for k, v in vals.items() if not k.startswith("profile:")}
        bad = []
        if not vals:
            return FAIL("TMOUT/TIMEOUT is not configured")
        allv = list(vals.values())
        if any(v == 0 or v > 900 for v in allv):
            bad.append("value out of range (1-900): %s" % vals)
        if not any(k.endswith("TMOUT") for k in vals):
            bad.append("TMOUT is not set")
        if not any(k.endswith("TIMEOUT") for k in vals):
            bad.append("TIMEOUT is not set")
        if need_ro:
            ro = text(b) if rid == "4.7.6" else ""
            if not re.search(r"\b(TMOUT|TIMEOUT)=", ro) and not re.search(r"^\s*readonly\s+.*(TMOUT|TIMEOUT)", prof, re.M):
                bad.append("TMOUT/TIMEOUT is not read-only")
        return FAIL("; ".join(bad)) if bad else PASS(", ".join("%s=%d" % kv for kv in sorted(vals.items())))
    return f


EVAL["4.7.5"] = _tmout("4.7.5", False)
EVAL["4.7.6"] = _tmout("4.7.6", True)

# ---------------------------------------------------------------------------
# 4.8 / 4.9
# ---------------------------------------------------------------------------


@reg("4.8.1")
def _():
    p = G("4.8.1")
    t = text(p)
    m = re.search(r"\blogin=(\w+)", t), re.search(r"\brlogin=(\w+)", t), re.search(r"\bsugroups=(\S+)", t)
    bad = []
    if not m[0] or m[0].group(1) != "false":
        bad.append("login=%s" % (m[0].group(1) if m[0] else "?"))
    if not m[1] or m[1].group(1) != "false":
        bad.append("rlogin=%s" % (m[1].group(1) if m[1] else "?"))
    if not m[2] or m[2].group(1).upper() == "ALL":
        bad.append("sugroups=%s" % (m[2].group(1) if m[2] else "?"))
    return FAIL("; ".join(bad) + " (required login=false rlogin=false sugroups restricted)") if bad else PASS("login=false rlogin=false sugroups=" + m[2].group(1))


@reg("4.8.2")
def _():
    v = lssec_val(G("4.8.2"), "shell")
    return PASS("shell=" + v) if v == "/usr/bin/ksh" else FAIL("root shell=%s (required /usr/bin/ksh)" % v)


@reg("4.8.3")
def _():
    a, b = G("4.8.3", "a"), G("4.8.3", "b")
    bad = []
    for k in ("core", "core_hard"):
        v = lssec_val(a, k)
        if v != "0":
            bad.append("%s=%s (required 0)" % (k, v))
    fc = re.search(r"fullcore\s+(\S+)", text(b))
    if not fc or fc.group(1).lower() != "false":
        bad.append("fullcore=%s (required false)" % (fc.group(1) if fc else "?"))
    return FAIL("; ".join(bad)) if bad else PASS("core=0 core_hard=0 fullcore=false")


def _dotpath(s):
    return re.search(r"(^|[:=\s])\.?(:|$)|::|(^|:)\.(:|$)|:\s*$|=\s*:", s) is not None


@reg("4.8.4")
def _():
    p = G("4.8.4")
    t = " ".join(L(p))
    if not t:
        raise NC("no PATH= line in /etc/environment")
    v = t.split("=", 1)[1].strip()
    return FAIL("PATH contains '.' or an empty entry: " + v[:100]) if re.search(r"(^|:)\.?(:|$)|::|:\s*$", v) else PASS("PATH=" + v[:100])


@reg("4.8.5")
def _():
    p = G("4.8.5")
    v = " ".join(L(p)).strip()
    if not v:
        raise NC("root PATH not captured: " + errtext(p)[:80])
    return FAIL("root PATH contains '.' or an empty entry: " + v[:100]) if re.search(r"(^|:)\.?(:|$)|::|:\s*$", v) else PASS("PATH=" + v[:100])


@reg("4.8.6")
def _():
    a, b = G("4.8.6", "a"), get("4.8.6", "b")
    bad = []
    ents = ls_entries(a)
    if not ents:
        return FAIL("/etc/motd does not exist")
    if not [l for l in b.out if l.strip()]:
        bad.append("/etc/motd is empty")
    return FAIL("; ".join(bad)) if bad else PASS("/etc/motd exists with %d line(s) of text (review against site policy)" % len(L(b)))


@reg("4.9.1")
def _():
    p = G("4.9.1")
    want = {"aslr": 2, "aslr32": 0, "aslr64": 0, "aslr32r": 333, "aslr64r": 33333, "aslr_r": 0}
    got = {}
    for l in L(p):
        m = re.match(r"^\s*(\w+)\s*=\s*\"?(\d+)\"?\s*$", l)
        if m:
            got[m.group(1)] = int(m.group(2))
    if not got:
        raise NC("vmo returned no aslr values")
    bad = ["%s=%s (required %d)" % (k, got.get(k, "n/a"), v) for k, v in want.items() if got.get(k) != v]
    return FAIL("; ".join(bad)) if bad else PASS("aslr settings as required")


# ---------------------------------------------------------------------------
# 5  Account management
# ---------------------------------------------------------------------------

@reg("5.1.1")
def _():
    p = G("5.1.1")
    return FAIL("accounts with empty password: " + ", ".join(L(p)[:10])) if L(p) else PASS("no account with an empty password")


@reg("5.1.2")
def _():
    a, b = G("5.1.2", "a"), G("5.1.2", "b")
    a_, b_ = [x for x in L(a) if not x.lstrip().startswith("#")], [x for x in L(b) if not x.lstrip().startswith("#")]
    bad = []
    if a_:
        bad.append("duplicate UIDs: " + ", ".join(x.strip() for x in a_))
    if b_:
        bad.append("duplicate user names: " + ", ".join(x.strip() for x in b_))
    return FAIL("; ".join(bad)) if bad else PASS("user names and UIDs are unique")


@reg("5.1.3")
def _():
    a, b = G("5.1.3", "a"), G("5.1.3", "b")
    bad = []
    if L(a):
        bad.append("duplicate GIDs: " + ", ".join(x.strip() for x in L(a)))
    if L(b):
        bad.append("duplicate group names: " + ", ".join(x.strip() for x in L(b)))
    return FAIL("; ".join(bad)) if bad else PASS("group names and GIDs are unique")


@reg("5.1.4")
def _():
    p = G("5.1.4")
    return MAN("%d account(s) with admin=true: %s - compare with the approved administrator inventory" % (len(L(p)), excerpt([l.split()[0] for l in L(p)], 8)))


@reg("5.1.5")
def _():
    p = G("5.1.5")
    return MAN("%d account(s) with admin=false - compare with the approved user inventory" % len(L(p)))


@reg("5.1.6")
def _():
    p = G("5.1.6")
    return FAIL("pwdck reported problems: " + excerpt(L(p), 3)) if L(p) else PASS("pwdck reports no problems")


numattr("5.2.1", "histsize", "eq", 0)
numattr("5.2.2", "minage", "ge", 1)
numattr("5.2.3", "histexpire", "ge", 52)


@reg("5.2.4")
def _():
    p = G("5.2.4")
    return FAIL("NOCHECK flag set for: " + ", ".join(x.strip() for x in L(p)[:10])) if L(p) else PASS("no account has the NOCHECK flag")


numattr("5.2.5", "maxexpired", "eq", 4)
numattr("5.2.6", "maxage", "range", (1, 52))


@reg("5.2.7")
def _():
    v = lssec_val(G("5.2.7"), "pwd_algorithm")
    return PASS("pwd_algorithm=ssha512") if v == "ssha512" else FAIL("pwd_algorithm=%s (required ssha512)" % v)


@reg("5.2.8")
def _():
    p = G("5.2.8")
    sysacc = {"adm", "bin", "daemon", "invscout", "ipsec", "lp", "lpd", "nobody", "nuucp", "sshd", "sys", "uucp",
              "esa", "srvproxy", "imnadm", "anonymou", "ftp"}
    users = [u.strip() for u in L(p) if u.strip() and u.strip() not in sysacc]
    return FAIL("accounts still using the weak 'crypt' hash: " + ", ".join(users[:10])) if users else PASS("no regular account uses the crypt hash")


numattr("5.2.9", "minlen", "ge", 14)
numattr("5.2.10", "mindiff", "ge", 6)
numattr("5.2.11", "minalpha", "ge", 3)
numattr("5.2.12", "minother", "ge", 3)
numattr("5.2.13", "maxrepeats", "range", (1, 4))
numattr("5.2.14", "mindigit", "ge", 1)
numattr("5.2.15", "minloweralpha", "ge", 1)
numattr("5.2.16", "minupperalpha", "ge", 1)
numattr("5.2.17", "minspecialchar", "ge", 1)

for _n, _u in enumerate(("adm", "bin", "daemon", "guest", "lpd", "nobody", "nuucp", "sys", "uucp"), 1):
    def _mk(rid, user):
        def f():
            p = G(rid)
            t = text(p)
            if not L(p) and re.search(r"does not exist|3004-687|2520-", errtext(p)):
                return PASS("user %s does not exist" % user)
            got = {k: (re.search(r"\b" + k + r"=(\S+)", t) or [None, "?"])[1] for k in ("account_locked", "login", "rlogin")}
            want = {"account_locked": "true", "login": "false", "rlogin": "false"}
            bad = ["%s=%s" % (k, got[k]) for k in want if got[k] != want[k]]
            return FAIL("; ".join(bad) + " (required account_locked=true login=false rlogin=false)") if bad else PASS("locked, no login")
        EVAL[rid] = f
    _mk("5.3.%d" % _n, _u)


@reg("5.3.10")
def _():
    a, b = G("5.3.10", "a"), G("5.3.10", "b")
    ftp = {l.strip() for l in L(a) if not l.lstrip().startswith("#")}
    sysu = []
    for l in L(b):
        t = l.split()
        m = re.search(r"\bid=(\d+)", l)
        if m and int(m.group(1)) < 200:
            sysu.append(t[0])
    miss = sorted(u for u in sysu if u not in ftp)
    dup = sorted({u for u in ftp if [x.strip() for x in L(a)].count(u) > 1})
    bad = []
    if miss:
        bad.append("not in /etc/ftpusers: " + ", ".join(miss[:12]))
    if dup:
        bad.append("duplicate entries: " + ", ".join(dup))
    return FAIL("; ".join(bad)) if bad else PASS("all UID<200 accounts are listed in /etc/ftpusers")


# ---------------------------------------------------------------------------
# 6  Access control
# ---------------------------------------------------------------------------

def vkey(v):
    return [int(x) for x in re.findall(r"\d+", v)]


@reg("6.1.1")
def _():
    p = G("6.1.1")
    t = text(p)
    m = re.search(r"Sudo version\s+(\d+(?:\.\d+)*(?:p\d+)?)", t, re.I)
    if not m:
        if re.search(r"SUDO_PATH=\s*$", t, re.M):
            return FAIL("sudo is not installed")
        raise NC("sudo version not found")
    ver = m.group(1)
    mm = re.match(r"(\d+(?:\.\d+)*)(?:p(\d+))?", ver)
    cur = vkey(mm.group(1)) + [int(mm.group(2) or 0)]
    return PASS("sudo " + ver) if cur >= [1, 9, 17, 1] else FAIL("sudo %s is older than 1.9.17p1" % ver)


@reg("6.1.2")
def _():
    p = G("6.1.2")
    t = text(p)
    if "SUDO_PATH" in text(get("6.1.1")) and re.search(r"SUDO_PATH=\s*$", text(get("6.1.1")), re.M):
        return FAIL("sudo is not installed")
    if re.search(r"BADPRI_NONE|GOODPRI_NONE", t):
        return FAIL("syslog priority disabled: " + excerpt([l for l in L(p) if "PRI_NONE" in l], 2))
    return PASS("sudo logging not disabled" + ("; logfile configured" if "LOGFILE" in t else ""))


@reg("6.1.3")
def _():
    p = G("6.1.3")
    t = text(p)
    if re.search(r"SUDO_PATH=\s*$", text(get("6.1.1")), re.M):
        return FAIL("sudo is not installed")
    bad = []
    if not re.search(r"^USE_PTY ", t, re.M):
        bad.append("'Defaults use_pty' not set")
    if re.search(r"^NOT_USE_PTY ", t, re.M):
        bad.append("'Defaults !use_pty' present")
    return FAIL("; ".join(bad)) if bad else PASS("Defaults use_pty is set")


def _cron_allow(rid, deny_name):
    def f():
        a, b = G(rid, "a"), G(rid, "b")
        bad = []
        if ls_entries(a):
            bad.append("%s exists" % deny_name)
        users = {l.strip() for l in L(b)}
        if not users:
            bad.append("allow file is missing or empty")
        else:
            miss = [u for u in ("root", "adm") if u not in users]
            if miss:
                bad.append("allow file lacks: " + ", ".join(miss))
        return FAIL("; ".join(bad)) if bad else PASS("allow file lists %s; no deny file" % ", ".join(sorted(users)[:6]))
    EVAL[rid] = f


_cron_allow("6.2.1", "/var/adm/cron/at.deny")
_cron_allow("6.2.2", "/var/adm/cron/cron.deny")


# ---------------------------------------------------------------------------
# 7  Vulnerability management / 8  Logging and auditing
# ---------------------------------------------------------------------------

@reg("7.1")
def _():
    p = G("7.1", "a")
    t = text(p)
    if "FLRTVC_NOT_RUN" in t:
        return MAN("FLRTVC was not run by the collector (use -F flrtvc.ksh); run it and review: " + excerpt(L(get("7.1", "b")), 1))
    if re.search(r"All vulnerabilities fixed", t):
        return PASS("All vulnerabilities fixed")
    rows = [l for l in L(p) if "|" in l and not l.startswith("Fileset|") and not l.startswith("#")]
    return FAIL("%d vulnerable fileset(s) reported by FLRTVC" % len(rows)) if rows else MAN("FLRTVC output could not be interpreted - review manually")


@reg("7.2")
def _():
    p = G("7.2", "a")
    return MAN("compare firmware with IBM Fix Central: " + (excerpt(L(p), 2) or "no data (virtual partition without physical adapters?)"))


@reg("8.1.1")
def _():
    a, b, c, d, e = (G("8.1.1", x) for x in "abcde")
    cfg = text(b)
    bad = []
    if not ls_entries(a) and not re.search(r"/audit\b", text(a)):
        bad.append("/audit filesystem is missing")
    for key, want in (("binmode", "on"), ("streammode", "off")):
        m = re.search(r"^\s*%s\s*=\s*(\S+)" % key, cfg, re.M)
        if not m or m.group(1) != want:
            bad.append("audit config %s=%s (required %s)" % (key, m.group(1) if m else "unset", want))
    if lssec_val(c, "auditclasses") != "general,SRC,cron,tcpip":
        bad.append("mkuser.default auditclasses=%s (required general,SRC,cron,tcpip)" % lssec_val(c, "auditclasses"))
    if not [l for l in L(d) if "cronaudit" in l]:
        bad.append("no cronaudit crontab entry")
    if not [l for l in L(e) if l.startswith("audit:")]:
        bad.append("no audit entry in /etc/inittab")
    return FAIL("; ".join(bad)) if bad else PASS("/audit, audit config, mkuser.default, cronaudit and inittab entry present")


@reg("8.1.2")
def _():
    t = text(G("8.1.2"))
    if not t.strip():
        raise NC("/etc/security/audit/config could not be read")
    bad = []
    for key, want in (("binmode", "on"), ("streammode", "off")):
        m = re.search(r"^\s*%s\s*=\s*(\S+)" % key, t, re.M)
        if not m or m.group(1) != want:
            bad.append("%s=%s (required %s)" % (key, m.group(1) if m else "unset", want))
    for key, want in (("trail", "/audit/trail"), ("bin1", "/audit/bin1"), ("bin2", "/audit/bin2"), ("cmds", "/etc/security/audit/bincmds")):
        m = re.search(r"^\s*%s\s*=\s*(\S+)" % key, t, re.M)
        if not m or m.group(1) != want:
            bad.append("%s=%s (required %s)" % (key, m.group(1) if m else "unset", want))
    m = re.search(r"^\s*binsize\s*=\s*(\d+)", t, re.M)
    if not m or int(m.group(1)) < 10240:
        bad.append("binsize=%s (required 10240)" % (m.group(1) if m else "unset"))
    um = re.search(r"^users:\s*\n((?:[ \t]+\S.*\n?)*)", t, re.M)
    if not um or not re.search(r"^\s*root\s*=", um.group(1), re.M):
        bad.append("no audit classes defined for root in the users: stanza")
    return FAIL("; ".join(bad)) if bad else PASS("bin auditing configured as in the benchmark")


TE_EVENTS = ["TE_Untrusted", "TE_FileWrite", "TE_Policies", "TEAdd_Stnz", "TEDel_Stnz", "TESwitch_algo", "TEQuery_Stnz"]


@reg("8.1.3")
def _():
    p = G("8.1.3")
    t = text(p)
    if not L(p):
        return FAIL("class 'default' is not defined in the classes: stanza")
    miss = [e for e in TE_EVENTS if e not in t]
    return FAIL("missing events in class default: " + ", ".join(miss)) if miss else PASS("all TE events are in class default")


@reg("8.2.1")
def _():
    a, b = G("8.2.1", "a"), G("8.2.1", "b")
    t = text(a)
    ents = ls_entries(b)
    paths = {e[3] for e in ents}
    bad = []
    if not re.search(r"^auth\.info\s+\S*auth\.log", t, re.M):
        bad.append("no 'auth.info ... auth.log' rule in syslog.conf")
    if not re.search(r"^\*\.info\S*\s+\S*info\.log", t, re.M):
        bad.append("no '*.info ... info.log' rule in syslog.conf")
    for need in ("auth.log", "info.log"):
        if not any(x.endswith("/" + need) for x in paths):
            bad.append("%s does not exist" % need)
    if not any(x.endswith("/archive") for x in paths):
        bad.append("archive directory /var/log/syslog/archive does not exist")
    return FAIL("; ".join(bad)) if bad else PASS("auth.log, info.log and archive present")


@reg("8.2.2")
def _():
    p = G("8.2.2")
    n = len([l for l in L(p) if "@" in l])
    return PASS("%d remote destination(s): %s" % (n, excerpt(L(p), 2))) if n else FAIL("no remote syslog host (@host) configured")


@reg("8.2.3")
def _():
    a, b = G("8.2.3", "a"), G("8.2.3", "b")
    run = [l for l in L(a) if "/usr/sbin/syslogd" in l or re.search(r"\bsyslogd\b", l)]
    if not run:
        return FAIL("syslogd is not running")
    if any(re.search(r"syslogd\s+.*-r\b", l) for l in run):
        return PASS("syslogd -r : " + run[0].strip()[-60:])
    return FAIL("syslogd is running without the -r flag: " + run[0].strip()[-60:])


# ---------------------------------------------------------------------------
# Informational chapters
# ---------------------------------------------------------------------------

INFO_PROBES = {
    "1.3.1": ["1.3.1"], "1.3.2": ["1.3.2"], "1.3.3.1": ["1.3.3.1"], "1.3.3.2": ["1.3.3.2"],
    "1.3.4.1": ["1.3.4.1"], "1.4": ["1.4"], "5.4": ["5.4"], "5.5": ["5.5"],
}


# ---------------------------------------------------------------------------
# Remediation (commands taken from the benchmark's Remediation sections)
# ---------------------------------------------------------------------------

R("2.1", """Schedule a regular system configuration extract and log it to syslog:
/usr/bin/mkdir -p /var/log/syslog && /usr/bin/touch /var/log/syslog/inventory.log
print "local1.info /var/log/syslog/inventory.log rotate time 1d files 30 compress" >> /etc/syslog.conf
refresh -s syslogd || startsrc -s syslogd
print "0 0 * * * /usr/sbin/lsconf -v | /usr/bin/logger -p local1.info -t Inventory" >> /var/spool/cron/crontabs/root
(frequency and facility may follow site policy)""")
R("2.2", """Disable TE/TEP, define the trusted path, then enable both (e.g. SecurePath="/usr/bin:/usr/sbin"):
trustchk -p TE=OFF TEP=OFF
trustchk -p TEP=${SecurePath}
trustchk -p TE=ON TEP=ON""")
R("2.3", "trustchk -p LOCK_KERN_POLICIES=ON")
R("2.4", """/usr/sbin/trustchk -p TE=ON CHKEXEC=ON
/usr/bin/mkdir -p /var/log/syslog && /usr/bin/touch /var/log/syslog/kernel.log
print "kern.info /var/log/syslog/kernel.log rotate time 1d files 30 compress" >> /etc/syslog.conf
/usr/bin/refresh -s syslogd || /usr/bin/startsrc -s syslogd""")
R("2.5", """trustchk -p stop_untrustd=on stop_on_chkfail=on te=on
(or stop_untrustd=trojan)""")
R("2.6", """Review each object reported by:  trustchk -i -n tree / 2>&1 >/dev/null | grep untrusted
Then remove the offending object, add it to the TSD (trustchk -a) or correct its attributes.""")
R("2.7", "find -L / \\( -fstype jfs -o -fstype jfs2 \\) -type l | xargs rm   # review the list first (find ... -type l -ls)")
R("3.1", "chsec -f /etc/security/user -s default -a umask=027")
R("3.2", """Review: find / \\( -fstype jfs -o -fstype jfs2 \\) -type d -perm -o+w ! -perm -1000 -ls
For each directory that must stay world writable:  chmod o+t <dir>""")
R("3.3", """Review the objects (find -L / ... -group <admin group> -ls) and remove group write where not required:
chmod g-w <file>""")
R("3.4", "find / \\( -fstype jfs -o -fstype jfs2 \\) -type f -perm -o+w -exec chmod o-w {} +")
R("3.5", "find / \\( -fstype jfs -o -fstype jfs2 \\) -type f -perm -g+w -group staff -exec chmod g-w {} +")
R("3.6", """chown <owner> <file>; chgrp <group> <file>
or remove the object:  rm -f <file>""")
R("4.1.1.1", """HOME=~root; [ "$HOME" != "/" ] && HOME=$HOME/
chmod u=rw,g=r,o-rwx ${HOME}smit.log""")
R("4.1.1.2", "chown root:security /etc/group; chmod u=rw,go=r /etc/group")
R("4.1.1.3", "chmod u=rw,go=r /etc/inetd.conf; chown root:system /etc/inetd.conf; trustchk -u /etc/inetd.conf mode=644")
R("4.1.1.4", "chown bin:bin /etc/motd; chmod u=rw,go=r /etc/motd")
R("4.1.1.5", "chown root:security /etc/passwd; chmod u=rw,go=r /etc/passwd")
R("4.1.1.6", "chmod u=rw,g=r,o= /etc/mail/submit.cf")
R("4.1.1.7", "chown root:system /etc/ssh/ssh_banner; chmod u=rw,go=r /etc/ssh/ssh_banner")
R("4.1.1.8", "chmod u-x,go-wx /etc/ssh/ssh_config; chown root:system /etc/ssh/ssh_config")
R("4.1.1.9", "chown root:system /etc/ssh/sshd_config; chmod u=rw,go=r /etc/ssh/sshd_config")
R("4.1.1.10", "chown root:sys /var/adm/cron/at.allow; chmod u=r,go= /var/adm/cron/at.allow")
R("4.1.1.11", "chown root:sys /var/adm/cron/cron.allow; chmod u=r,go= /var/adm/cron/cron.allow")
R("4.1.1.12", "chmod ug=rw,o= /var/adm/cron/log; chown bin:cron /var/adm/cron/log")
for _f, _i in (("/var/ct/RMstart.log", "13"), ("/var/tmp/dpid2.log", "14"), ("/var/tmp/hostmibd.log", "15"),
               ("/var/tmp/snmpd.log", "16"), ("/var/tmp/snmpdv3.log", "20")):
    R("4.1.1." + _i, "/usr/bin/chown root:system %s; /usr/bin/chmod u-x,g-wx,o-rwx %s" % (_f, _f))
R("4.1.1.17", """Make every command in root's crontab (and every directory above it) owned by root/bin and not group/world writable:
chown root <path>; chmod go-w <path>""")
R("4.1.1.18", "chmod go-w <home>/.<dotfile>   # for every file listed in the evidence")
R("4.1.1.19", """Un-mount non-local file systems and CD-ROM media (unmount <mount point>), re-run
find / \\( -fstype jfs -o -fstype jfs2 \\) \\( -perm -04000 -o -perm -02000 \\) -type f -ls
and remove the s-bit from programs that do not need it:  chmod ug-s <file>""")
R("4.1.2.1", "Lock accounts (UID >= 200) whose HOME does not exist, or create the directory:  chuser account_locked=true <user>")
R("4.1.2.2", """chown <user> <HOME_DIRECTORY>      # or lock the account / delete the directory""")
R("4.1.2.3", "chmod go-w <HOME_DIRECTORY>; echo | aclput <HOME_DIRECTORY>   # also remove extended ACLs")
R("4.1.2.4", """AUDITDIRS="/etc/security/audit /audit"
find ${AUDITDIRS} | grep -v 'lost+found' | xargs chown root:audit
find ${AUDITDIRS} -type d | grep -v 'lost+found' | xargs chmod g-w,o-rwx
find ${AUDITDIRS} ! -type d | grep -v 'lost+found' | xargs chmod u-x,g-wx,o-rwx""")
R("4.1.2.5", """EXCLUDE="security/(aixpert|audit|ice)"
for D in $(find /etc/security -type d | egrep -v "$EXCLUDE"); do
  find $D | egrep -v "$EXCLUDE" | xargs chown root:security
  find $D -type d | egrep -v "$EXCLUDE" | xargs chmod g-w+s,o-rwx
  find $D -type f | egrep -v "$EXCLUDE" | xargs chmod u-x,g-wx,o-rwx
done""")
R("4.1.2.6", "/usr/bin/chmod o-rw /var/adm/ras/*   # SRCKeyID may stay world readable")
R("4.1.2.7", "chown adm:adm /var/adm/sa; chmod u=rwx,go=rx /var/adm/sa")
R("4.1.2.8", """echo | aclput /var/spool/cron/crontabs
chmod -R o= /var/spool/cron/crontabs
chown bin:cron /var/spool/cron/crontabs; chgrp -R cron /var/spool/cron/crontabs
chmod ug=rwx,o= /var/spool/cron/crontabs; chmod a-w /var/spool/cron/crontabs
trustchk -a /var/spool/cron/crontabs size=VOLATILE >/dev/null 2>&1 || trustchk -u /var/spool/cron/crontabs owner=bin group=cron mode=770""")
R("4.1.2.9", """echo | aclput /var/spool/cron/atjobs
chmod -R o= /var/spool/cron/atjobs
chown bin:cron /var/spool/cron/atjobs
trustchk -a /var/spool/cron/atjobs size=VOLATILE >/dev/null 2>&1 || trustchk -u /var/spool/cron/atjobs owner=bin group=cron mode=770""")
R("4.1.2.10", "Remove '.', empty and relative entries from root's PATH and make each directory root/bin owned and not group/world writable:  chmod go-w <dir>")
R("4.1.2.11", """mkdir /root; chown root:system /root; chmod 0700 /root
chuser home=/root root""")
R("4.2.1", "stopsrc -g yp; installp -u bos.net.nis.client")
R("4.2.2", "stopsrc -g yp; installp -u bos.net.nis.server   # or restrict clients in /var/yp/securenets if NIS is required")
R("4.2.3", "Delete the '+' lines:  vi /etc/passwd; vi /etc/group")
R("4.2.4", """sed '/^\\s*$/d; s/^\\(\\s*[^#].*\\)/#\\1/' /etc/hosts.equiv > /etc/hosts.equiv.work
mv /etc/hosts.equiv.work /etc/hosts.equiv; chown root:system /etc/hosts.equiv; chmod 644 /etc/hosts.equiv""")
R("4.2.5", """find / \\( -fstype jfs -o -fstype jfs2 \\) -name ".netrc" -exec rm {} \\;
find / \\( -fstype jfs -o -fstype jfs2 \\) -name ".rhosts" -exec rm {} \\;
find / \\( -fstype jfs -o -fstype jfs2 \\) -name ".shosts" -exec rm {} \\;""")
R("4.2.6", """Disable the files of bos.net.tcp.rcmd and bos.net.tcp.rcmd_server (chmod 0, remove ACL, update TCB):
for f in $(lslpp -f bos.net.tcp.rcmd_server bos.net.tcp.rcmd | egrep "^ +/" | awk '{print $1}'); do
  [ -L $f ] || { echo | aclput $f; chmod 0 $f; trustchk -u $f mode=0 >/dev/null 2>&1; }
done""")
R("4.2.7", "installp -ug bos.net.tcp.snmp bos.net.tcp.snmpd")
R("4.3.1.1", """/usr/sbin/chitab "writesrv:23456789:off:/usr/bin/startsrc -swritesrv"
/usr/bin/stopsrc -s writesrv""")
R("4.3.1.2", "rmitab dt; rmitab dt_nogb")
R("4.3.1.3", "rmitab piobe")
R("4.3.1.4", "rmitab qdaemon")
R("4.3.1.5", """chitab "rcnfs:23456789:off:/etc/rc.nfs > /dev/console 2>&1 # Start NFS Daemons"
stopsrc -g nfs""")
R("4.3.1.6", "installp -u bos.net.snapp")
R("4.3.1.7", "installp -u bos.sysmgt.nim.master bos.sysmgt.nim.spot")
R("4.3.2.1", """Review active services first (lssrc -ls inetd); if none are required:
/usr/sbin/chrctcp -d inetd; stopsrc -s inetd
(if services are required keep inetd and protect them with TCP wrappers)""")
for _i, _d, _fs in (("2", "dhcpcd dhcpcd6", "bos.net.tcp.dhcp bos.net.tcp.client"), ("3", "dhcprd", "bos.net.tcp.dhcpd bos.net.tcp.server"),
                    ("4", "dhcpsd", "bos.net.tcp.dhcpd bos.net.tcp.server"), ("5", "gated", "bos.net.tcp.gated bos.net.tcp.server"),
                    ("6", "hostmibd", "bos.net.tcp.snmpd bos.net.tcp.server"), ("8", "named", "bos.net.tcp.bind bos.net.tcp.server bind.rte"),
                    ("11", "rwhod", "bos.net.tcp.rcmd_server bos.net.tcp.server"), ("12", "sendmail", "bos.net.tcp.sendmail bos.net.tcp.server"),
                    ("13", "timed", "bos.net.tcp.timed bos.net.tcp.server")):
    R("4.3.2." + _i, "installp -u %s      # remove the software if possible, otherwise:\nfor d in %s; do /usr/sbin/chrctcp -d $d; /usr/bin/stopsrc -s $d; done" % (_fs, _d))
for _i, _d in (("7", "mrouted"), ("10", "routed")):
    R("4.3.2." + _i, "/usr/sbin/chrctcp -d %s; /usr/bin/stopsrc -s %s" % (_d, _d))
R("4.3.2.9", """Stop the RPC services first, then disable portmap:
sed -e 's/^\\[ -z "$portmap_pid"/#&/' /etc/rc.tcpip > /var/tmp/rc.tcpip.new && cp /var/tmp/rc.tcpip.new /etc/rc.tcpip
stopsrc -s portmap
chitab "rcnfs:23456789:off:/etc/rc.nfs > /dev/console 2>&1 # Start NFS Daemons\"""")
for _i, _d in (("1", "autoconf6"), ("2", "ndpd-host"), ("3", "ndpd-router")):
    R("4.3.3." + _i, "chrctcp -d " + _d)
_INETD = {1: ("bootps", "udp"), 2: ("chargen", "udp"), 3: ("comsat", "udp"), 4: ("daytime", "tcp udp"), 5: ("discard", "udp"),
          6: ("echo", "tcp udp"), 7: ("exec", "tcp6"), 8: ("finger", "tcp"), 9: ("ftp", "tcp6"), 10: ("imap2", "tcp"),
          11: ("instsrv", "tcp"), 12: ("klogin", "tcp"), 13: ("kshell", "tcp"), 14: ("netstat", "tcp"), 15: ("ntalk", "udp"),
          16: ("pcnfsd", "udp"), 17: ("pop3", "tcp"), 18: ("rexd", "tcp"), 19: ("login", "tcp6"), 20: ("rquotad", "udp"),
          21: ("rstatd", "udp"), 22: ("rsync", "tcp"), 23: ("rusersd", "udp"), 24: ("rwalld", "udp"), 25: ("shell", "tcp6"),
          26: ("sprayd", "udp"), 27: ("talk", "udp"), 28: ("telnet", "tcp6"), 29: ("tftp", "udp6"), 30: ("time", "tcp udp"),
          31: ("uucp", "tcp"), 32: ("xmquery", "udp")}
for _n, (_s, _pp) in _INETD.items():
    _cmds = "\n".join("chsubserver -r inetd -C /etc/inetd.conf -d -v '%s' -p %s" % (_s, x) for x in _pp.split())
    R("4.3.4.%d" % _n, _cmds + "\nrefresh -s inetd" + ("\n(or remove the software: installp -u rsync.rte)" if _n == 22 else ""))
R("4.4.1.1", """Unmount and remove all NFS client mounts from /etc/filesystems (rmnfsmnt -f <mount point>), then:
stopsrc -g nfs""")
R("4.4.1.2", "Remove all exports (cat /etc/exports must be empty/absent), then:  installp -u bos.net.nfs.server; rm /etc/exports")
R("4.4.1.3", """lsnfsmnt -l | egrep -v "^Name" | grep -v "nosuid" | while read remote server mntpnt rest; do
  chnfsmnt -d ${remote} -f ${mntpnt} -h ${server} -y -z
done""")
R("4.4.1.4", """cp -p /etc/exports /etc/exports.pre_cis
vi /etc/exports      # remove localhost / localhost aliases from the access= lists
exportfs -a""")
R("4.4.1.5", """Give every export an explicit client list, e.g. modify '/export/repo (everyone)' to:
chnfsexp -d /export/repo -c <client1>:<client2>""")
R("4.4.1.6", """lsnfsexp | grep -v 'anon=-1' | grep anon= | while read fs rest; do chnfsexp -d ${fs} -a -2; done""")
R("4.4.1.7", "chnfsexp -d <fs> -S <sec>      # sec = sys | dh | krb5 | krb5i | krb5p; never 'none'")
R("4.4.2.1", """Install the CLiC fileset from the AIX expansion pack and load the kernel extension, then enable EFS:
/usr/lib/instl/sm_inst installp_cmd -a -Q -d /tmp -f clic.rte -c -N -g -X -G -Y
efsenable -a""")
R("4.4.3.1", """mount | grep jfs | egrep -v "/dev/hd4|nodev" | while read lv fs jfs m d t options; do mount -o remount,${options},nodev $fs; done
chfs -a options=nodev <file system>      # persistent, for every file system except /""")
for _n, (_o, _v) in {1: ("sockthresh", 60), 2: ("bcastping", 0), 3: ("clean_partial_conns", 1), 4: ("directed_broadcast", 0),
                     5: ("icmpaddressmask", 0), 6: ("ipforwarding", 0), 7: ("ip6forwarding", 0), 8: ("ipignoreredirects", 1),
                     9: ("ipsendredirects", 0), 10: ("ipsrcrouteforward", 0), 11: ("ipsrcrouterecv", 0), 12: ("ipsrcroutesend", 0),
                     13: ("ip6srcrouteforward", 0), 15: ("nonlocsrcroute", 0), 16: ("tcp_pmtu_discover", 0), 17: ("tcp_tcpsecure", 7),
                     18: ("udp_pmtu_discover", 0), 19: ("icmptimestamp", 0)}.items():
    R("4.5.%d" % _n, "no -p -o %s=%d" % (_o, _v))
R("4.5.14", "nfso -p -o portcheck=1; nfso -p -o nfs_use_reserved_ports=1")
R("4.6.1.1", "installp -up <fileset>   # preview, then:  installp -ug <fileset>   (for each X11.Dt fileset)")
R("4.6.1.2", "chsubserver -r inetd -C /etc/inetd.conf -d -v 'cmsd' -p 'sunrpc_udp'; refresh -s inetd")
R("4.6.1.3", "/usr/dt/bin/dtconfig -d; /usr/dt/bin/dtconfig -kill")
R("4.6.1.4", "chsubserver -r inetd -C /etc/inetd.conf -d -v 'dtspc' -p 'tcp'; refresh -s inetd")
R("4.6.1.5", "chmod ug-s /usr/dt/bin/dtaction /usr/dt/bin/dtappgather /usr/dt/bin/dtprintinfo /usr/dt/bin/dtsession")
R("4.6.1.6", """mkdir -p /etc/dt/config; [ -f /etc/dt/config/Xconfig ] || cp /usr/dt/config/Xconfig /etc/dt/config
vi /etc/dt/config/Xconfig     # replace '#  Dtlogin.requestPort:  0' with 'Dtlogin.requestPort:  0'""")
R("4.6.1.7", """For every /usr/dt/config/*/sys.resources copy it to /etc/dt/config/<lang>/sys.resources and set:
dtsession*saverTimeout: 15
dtsession*lockTimeout: 15""")
R("4.6.1.8", """For every /usr/dt/config/*/Xresources copy it to /etc/dt/config/<lang>/Xresources and add:
Dtlogin*greeting.labelString: Authorized uses only. All activity may be monitored and reported.
Dtlogin*greeting.persLabelString: Authorized uses only. All activity may be monitored and reported.""")
R("4.6.1.9", "chown root:bin /etc/dt/config/Xconfig; chmod go-w /etc/dt/config/Xconfig")
R("4.6.1.10", """vi /etc/dt/config/Xconfig      # Dtlogin*servers: /etc/dt/config/Xservers
chown root:bin /etc/dt/config/Xservers; chmod go-w /etc/dt/config/Xservers""")
R("4.6.1.11", "chown root:sys /etc/dt/config/*/Xresources; chmod u-x,go-wx /etc/dt/config/*/Xresources")
R("4.6.2.1", 'echo "root" >> /etc/ftpusers')
R("4.6.2.2", """lslpp -L bos.msg.en_US.net.tcp.client      # install it if missing
dspcat -g /usr/lib/nls/msg/en_US/ftpd.cat > /tmp/ftpd.tmp
sed 's/"%s FTP server (%s) ready."/"%s Authorized uses only. All activity may be monitored and reported"/' /tmp/ftpd.tmp > /tmp/ftpd.msg
gencat /usr/lib/nls/msg/en_US/ftpd.cat /tmp/ftpd.msg""")
R("4.6.2.3", 'chsubserver -c -v ftp -p tcp "ftpd -l -u 027" && refresh -s inetd')
R("4.6.3.1", "Install OpenSSH 9.9 (or later) from the IBM AIX Web Download Pack, then restart sshd:  stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.2", "rm -f /etc/shosts.equiv /etc/rhosts.equiv")
R("4.6.3.3", """Subsystem sftp /usr/sbin/sftp-server -u 027 -f AUTH -l INFO     (in /etc/ssh/sshd_config; VERBOSE or internal-sftp also accepted)
stopsrc -s sshd; startsrc -s sshd""")
R("4.6.3.4", """Add to /etc/ssh/sshd_config (above any Match block) one of: AllowUsers <list> | AllowGroups <list> | DenyUsers <list> | DenyGroups <list>
stopsrc -s sshd; startsrc -s sshd""")
R("4.6.3.5", """Banner /etc/ssh/ssh_banner      (in /etc/ssh/sshd_config, above any Match block; fill the file with the site warning text)
stopsrc -s sshd; startsrc -s sshd""")
R("4.6.3.6", """Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com      (in /etc/ssh/sshd_config)
stopsrc -s sshd; startsrc -s sshd""")
R("4.6.3.7", "HostbasedAuthentication no      (in /etc/ssh/sshd_config, above Match blocks); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.8", "IgnoreRhosts yes      (in /etc/ssh/sshd_config, above Match blocks); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.9", """KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
(in /etc/ssh/sshd_config); stopsrc -s sshd; startsrc -s sshd""")
R("4.6.3.10", "LogLevel INFO      (or VERBOSE; in /etc/ssh/sshd_config, above Match blocks); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.11", """MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com
(in /etc/ssh/sshd_config); stopsrc -s sshd; startsrc -s sshd""")
R("4.6.3.12", "MaxAuthTries 4      (in /etc/ssh/sshd_config); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.13", "PermitEmptyPasswords no      (uncomment/set in /etc/ssh/sshd_config); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.14", "PermitRootLogin prohibit-password      (or no / forced-commands-only; in /etc/ssh/sshd_config); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.15", "PermitRootLogin no      (in /etc/ssh/sshd_config); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.16", "PermitUserEnvironment no      (in /etc/ssh/sshd_config); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.17", "RekeyLimit 1G 3600      (in /etc/ssh/sshd_config); stopsrc -s sshd; startsrc -s sshd")
R("4.6.3.18", """ClientAliveInterval 15
ClientAliveCountMax 3      (example values, set above any Include/Match entries in /etc/ssh/sshd_config)""")
R("4.6.4.1", """cp -p /etc/mail/sendmail.cf /etc/mail/sendmail.cf.pre_cis
vi /etc/mail/sendmail.cf      # O SmtpGreetingMessage=mailerready
test -e /etc/mail/helpfile || touch /etc/mail/helpfile""")
R("4.6.4.2", "vi /etc/mail/sendmail.cf      # O PrivacyOptions=authwarnings noexpn novrfy")
R("4.6.4.3", "chmod u=rw,g=r,o= /etc/mail/sendmail.cf; chown root.system /etc/mail/sendmail.cf; trustchk -u /etc/mail/sendmail.cf mode owner group")
R("4.6.4.4", "chmod ug=rwx,o= /var/spool/clientmqueue; chown smmsp.smmsp /var/spool/clientmqueue")
R("4.6.4.5", "chmod u=rwx,go= /var/spool/mqueue; chown root /var/spool/mqueue")
R("4.7.1", """chsec -f /etc/security/login.cfg -s default -a herald="Authorized users only. All activity may be monitored and reported.\\\\nlogin: \"""")
R("4.7.2", "chsec -f /etc/security/login.cfg -s default -a logindelay=10")
R("4.7.3", "chsec -f /etc/security/user -s default -a loginretries=5")
R("4.7.4", "chsec -f /etc/security/login.cfg -s usw -a logintimeout=30")
_TMOUT_CHECK = """# check for TMOUT/TIMEOUT first: a variable that is already read-only (current shell or /etc/profile) is skipped
for v in TMOUT TIMEOUT; do
  if readonly | /usr/bin/egrep -q "(^|[[:space:]])${v}=" || /usr/bin/egrep -q "^[[:space:]]*readonly[[:space:]].*${v}" /etc/profile; then
    echo "${v} is already read-only - skipping"
  elif /usr/bin/egrep -q "^[[:space:]]*${v}=" /etc/profile; then
    sed "s/^[[:space:]]*${v}=.*/${v}=900/" /etc/profile > /var/tmp/profile.$$ && cp /var/tmp/profile.$$ /etc/profile; rm -f /var/tmp/profile.$$
  else
    echo "${v}=900" >> /etc/profile
  fi
done"""
R("4.7.5", _TMOUT_CHECK + """
/usr/bin/egrep -q "^export TMOUT TIMEOUT" /etc/profile || echo "export TMOUT TIMEOUT" >> /etc/profile      # export must be the last statement""")
R("4.7.6", _TMOUT_CHECK + """
for v in TMOUT TIMEOUT; do
  readonly | /usr/bin/egrep -q "(^|[[:space:]])${v}=" || /usr/bin/egrep -q "^[[:space:]]*readonly[[:space:]].*${v}" /etc/profile || echo "readonly ${v}" >> /etc/profile
done
/usr/bin/egrep -q "^export TMOUT TIMEOUT" /etc/profile || echo "export TMOUT TIMEOUT" >> /etc/profile      # export must be the last statement""")
R("4.8.1", """lsgroup SUADMIN >/dev/null || mkgroup -a SUADMIN
chuser login=false rlogin=false sugroups=SUADMIN root""")
R("4.8.2", "chuser shell=/usr/bin/ksh root")
R("4.8.3", """chsec -f /etc/security/limits -s default -a core=0 -a core_hard=0
chdev -l sys0 -a fullcore=false""")
R("4.8.4", "vi /etc/environment      # remove '.' and empty (::) entries from PATH")
R("4.8.5", "Remove '.' and '::' from the PATH set in root's initialisation files (e.g. /.profile, /etc/profile, /etc/environment).")
R("4.8.6", """touch /etc/motd; chmod u=rw,go=r /etc/motd; chown bin:bin /etc/motd
Fill /etc/motd with the site 'authorized use only / activity is monitored' notice.""")
R("4.9.1", "/usr/sbin/vmo -r -o aslr=2 -o aslr32=0 -o aslr32r=333 -o aslr64=0 -o aslr64r=33333 -o aslr_r=0      # reboot required")
R("5.1.1", """for user in $(egrep -p "password = +$" /etc/security/passwd | awk '/:/ {print $1;}' | tr -d :); do
  chuser account_locked=true expires=0101000070 ${user}
  echo "$user:*" | chpasswd -e -f ADMCHG
done""")
R("5.1.2", "Rename or remove duplicate accounts / assign unique IDs (chuser id=<new uid> <user>) after checking file ownership.")
R("5.1.3", "Rename or remove duplicate groups / assign unique IDs (chgroup id=<new gid> <group>) after checking file ownership.")
R("5.1.4", "Establish and maintain an approved list of administrator accounts (lsuser -R files -a admin ALL | grep admin=true).")
R("5.1.5", "Establish and maintain an approved list of regular user accounts (lsuser -R files -a admin ALL | grep admin=false).")
R("5.1.6", "pwdck -t ALL      # interactive; or  pwdck -y ALL  to fix all errors automatically")
R("5.2.1", "chsec -f /etc/security/user -s default -a histsize=0")
R("5.2.2", "chsec -f /etc/security/user -s default -a minage=1")
R("5.2.3", "chsec -f /etc/security/user -s default -a histexpire=52")
R("5.2.4", """grep -p NOCHECK /etc/security/passwd | egrep ":$" | sed -e 's/://' | while read USER; do
  pwdadm -c $USER; pwdadm -f ADMCHG $USER
done""")
R("5.2.5", "chsec -f /etc/security/user -s default -a maxexpired=4")
R("5.2.6", "chsec -f /etc/security/user -s default -a maxage=52      # any value from 1 to 52 per site policy")
R("5.2.7", "chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=ssha512")
R("5.2.8", "for each affected user (regular accounts only):  pwdadm -c <user>; pwdadm -f ADMCHG <user>      # forces a new password hashed with pwd_algorithm")
R("5.2.9", "chsec -f /etc/security/user -s default -a minlen=14      # requires pwd_algorithm=ssha512 first (5.2.7)")
R("5.2.10", "chsec -f /etc/security/user -s default -a mindiff=6")
R("5.2.11", "chsec -f /etc/security/user -s default -a minalpha=3")
R("5.2.12", "chsec -f /etc/security/user -s default -a minother=3")
R("5.2.13", "chsec -f /etc/security/user -s default -a maxrepeats=4")
R("5.2.14", "chsec -f /etc/security/user -s default -a mindigit=1")
R("5.2.15", "chsec -f /etc/security/user -s default -a minloweralpha=1")
R("5.2.16", "chsec -f /etc/security/user -s default -a minupperalpha=1")
R("5.2.17", "chsec -f /etc/security/user -s default -a minspecialchar=1")
for _n, _u in enumerate(("adm", "bin", "daemon", "guest", "lpd", "nobody", "nuucp", "sys", "uucp"), 1):
    R("5.3.%d" % _n, "chuser account_locked=true login=false rlogin=false " + _u)
R("5.3.10", """lsuser -c ALL | grep -v ^#name | cut -f1 -d: | while read NAME; do
  [ $(lsuser -f $NAME | grep id | cut -f2 -d=) -lt 200 ] && grep -qx $NAME /etc/ftpusers || echo $NAME >> /etc/ftpusers
done      # review the list before appending; remove duplicate lines""")
R("6.1.1", "Install the latest sudo (1.9.17p1 or later) from the AIX Toolbox / your distribution.")
R("6.1.2", """visudo -f /etc/sudoers      # remove 'Defaults syslog_badpri=none' and 'Defaults syslog_goodpri=none'
or configure a dedicated log:  Defaults logfile="/var/log/sudo.log\"""")
R("6.1.3", "visudo -f /etc/sudoers      # add 'Defaults use_pty' and remove every '!use_pty'")
R("6.2.1", """rm /var/adm/cron/at.deny
print "root\\nadm" > /var/adm/cron/at.allow      # if it does not exist; otherwise ensure root and adm are listed
chown root:sys /var/adm/cron/at.allow; chmod u=r,go= /var/adm/cron/at.allow""")
R("6.2.2", """rm /var/adm/cron/cron.deny
print "root\\nadm" > /var/adm/cron/cron.allow      # if it does not exist; otherwise ensure root and adm are listed
chown root:sys /var/adm/cron/cron.allow; chmod u=r,go= /var/adm/cron/cron.allow""")
R("7.1", "Run flrtvc.ksh regularly (cis_collect.ksh -F <path>), review the reported APARs/bulletins and install the fixes from IBM Fix Central.")
R("7.2", "Compare the installed firmware with the latest level on IBM Fix Central for the hardware model and apply the update per IBM instructions.")
R("8.1.1", """mklv -y auditlv -t jfs2 -u 1 -c 1 rootvg 1 hdisk0; crfs -v jfs2 -d auditlv -m /audit -A yes -t no; mount /audit
vi /etc/security/audit/config      # start: binmode = on, streammode = off; bin: trail=/audit/trail bin1=/audit/bin1 bin2=/audit/bin2 binsize=10240 cmds=/etc/security/audit/bincmds; users: root = general,SRC,mail,cron,tcpip,ipsec,lvm
chsec -f /usr/lib/security/mkuser.default -s user -a auditclasses=general,SRC,cron,tcpip
print "0 * * * * /etc/security/aixpert/bin/cronaudit" | crontab -   # append to the existing root crontab instead (crontab -e)
mkitab "audit:2:boot:audit start > /dev/console 2>&1 # Start audit\"""")
R("8.1.2", """Configure /etc/security/audit/config (binmode = on, streammode = off, bin: trail/bin1/bin2 in /audit, binsize = 10240,
cmds = /etc/security/audit/bincmds, users: root = general,SRC,mail,cron,tcpip,ipsec,lvm) - see 8.1.1 for the complete procedure.""")
R("8.1.3", """vi /etc/security/audit/config      # in the 'classes:' stanza
default = TE_Untrusted,TE_FileWrite,TE_Policies,TEAdd_Stnz,TEDel_Stnz,TESwitch_algo,TEQuery_Stnz""")
R("8.2.1", """printf "auth.info\\t\\t/var/log/syslog/auth.log rotate time 1d files 30 compress archive /var/log/syslog/archive\\n" >> /etc/syslog.conf
printf "*.info;local4.none\\t/var/log/syslog/info.log rotate time 1d files 30 compress archive /var/log/syslog/archive\\n" >> /etc/syslog.conf
mkdir -p /var/log/syslog/archive; touch /var/log/syslog/auth.log /var/log/syslog/info.log
chown root:system /var/log/syslog/auth.log; chmod u=rw,go= /var/log/syslog/auth.log
refresh -s syslogd""")
R("8.2.2", """printf "auth.info\\t\\t@<IP address of remote syslog server>\\n" >> /etc/syslog.conf
printf "*.info;auth.none\\t@<IP address of remote syslog server>\\n" >> /etc/syslog.conf
refresh -s syslogd""")
R("8.2.3", "/usr/bin/chssys -s syslogd -a \"-r\"; /usr/bin/stopsrc -s syslogd; /usr/bin/startsrc -s syslogd")


# ---------------------------------------------------------------------------
# Evaluation driver
# ---------------------------------------------------------------------------

class Finding(object):
    def __init__(self, rid, title, level):
        self.id, self.title, self.level = rid, title, level
        self.status, self.detail, self.probes = "NC", "", []


def evaluate():
    out = []
    for rid, title, level in CATALOG:
        f = Finding(rid, title, level)
        del USED[:]
        fn = EVAL.get(rid)
        try:
            if fn is None:
                raise NC("no evaluator for this recommendation")
            f.status, f.detail = fn()
        except NC as e:
            f.status, f.detail = "NC", str(e)
        except Exception as e:                                # defensive: never abort the report
            f.status, f.detail = "NC", "evaluation error: %s: %s" % (type(e).__name__, e)
        f.probes = list(USED)
        out.append(f)
    return out


STATUS_LABEL = {"PASS": "Pass", "FAIL": "Fail", "MANUAL": "Manual review", "NC": "Not collected"}
STATUS_ORDER = ["FAIL", "MANUAL", "NC", "PASS"]

CSS = """
body{font:14px/1.6 -apple-system,"Segoe UI",system-ui,sans-serif;color:#1f2328;background:#fff;margin:0}
main{max-width:1000px;margin:0 auto;padding:24px 20px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:32px 0 10px;border-bottom:1px solid #e5e7eb;padding-bottom:4px}
h3{font-size:14px;margin:18px 0 4px}
.muted{color:#57606a} .small{font-size:12px}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #e5e7eb;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#f7f8fa} td.n{text-align:right;white-space:nowrap}
.s{font-weight:600;white-space:nowrap} .PASS{color:#1a7f37} .FAIL{color:#cf222e} .MANUAL{color:#9a6700} .NC{color:#57606a}
pre{background:#f7f8fa;border:1px solid #e5e7eb;padding:8px;overflow-x:auto;font:12px/1.45 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word;margin:4px 0}
details{margin:4px 0} summary{cursor:pointer;color:#3b82d4}
.box{background:#f7f8fa;border:1px solid #e5e7eb;padding:10px 12px}
.bar{display:flex;height:12px;border:1px solid #e5e7eb;margin:6px 0}
.bar span{display:block;height:100%}
footer{margin-top:40px;padding-top:10px;border-top:1px solid #e5e7eb;color:#57606a;font-size:12px;text-align:center}
.rem{margin:0 0 14px}
"""

COLORS = {"PASS": "#1a7f37", "FAIL": "#cf222e", "MANUAL": "#d4a72c", "NC": "#9aa1a9"}


def esc(s):
    return html.escape(str(s), quote=True)


def evidence_html(probes, max_lines=40):
    parts = []
    for p in probes:
        head = "%s/%s   rc=%s" % (p.id, p.name, "?" if p.rc is None else p.rc)
        if p.skipped:
            body = "[skipped] " + p.skipped
        else:
            lines = p.out[:max_lines]
            body = "\n".join(lines)
            if len(p.out) > max_lines:
                body += "\n... (%d more lines in the evidence file)" % (len(p.out) - max_lines)
            if p.truncated:
                body += "\n[collector truncated output at %s lines]" % p.truncated
            if p.err:
                body += "\n[stderr] " + "\n[stderr] ".join(p.err[:5])
        parts.append("<div class=small><b>%s</b> <span class=muted>$ %s</span></div><pre>%s</pre>" % (esc(head), esc(p.cmd[:300]), esc(body or "(no output)")))
    return "".join(parts)


def render(findings, meta, args, evidence_complete):
    cnt = {k: 0 for k in STATUS_ORDER}
    for f in findings:
        cnt[f.status] += 1
    scored = cnt["PASS"] + cnt["FAIL"]
    pct = (100.0 * cnt["PASS"] / scored) if scored else 0.0
    total = len(findings)

    def bar(c, t):
        return "".join('<span style="width:%.2f%%;background:%s" title="%s: %d"></span>' % (100.0 * c[k] / t, COLORS[k], STATUS_LABEL[k], c[k])
                       for k in STATUS_ORDER if c[k] and t)

    H = []
    a = H.append
    a("<!DOCTYPE html><html lang=en><head><meta charset=utf-8><title>%s - %s</title><style>%s</style></head><body><main>" % (
        esc(BENCHMARK), esc(meta.get("hostname", "")), CSS))
    a("<h1>AIX security assessment report</h1>")
    a("<div class=muted>%s &middot; generated %s by cis_report.py %s</div>" % (esc(BENCHMARK), datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), VERSION))

    a("<h2>System</h2><table>")
    for k, label in (("hostname", "Host"), ("uname", "uname"), ("oslevel_s", "AIX level (oslevel -s)"), ("collected_at", "Collected at"),
                     ("user", "Collected as"), ("tool", "Collector"), ("quick", "Quick mode (-q)")):
        v = meta.get(k, "")
        if k == "quick":
            v = "yes - file-system-wide scans were skipped" if v == "1" else "no"
        a("<tr><th style='width:30%%'>%s</th><td>%s</td></tr>" % (label, esc(v) or "<span class=muted>n/a</span>"))
    a("</table>")
    notes = []
    if not evidence_complete:
        notes.append("The evidence file has no end marker (@@@EOF): the collection was interrupted or the file is truncated.")
    if not meta.get("oslevel", "").strip() and not meta.get("oslevel_s", "").strip():
        notes.append("No AIX level was recorded - the evidence was probably not collected on an AIX system, most results will be 'Not collected'.")
    if not is_root():
        notes.append("The collector was not run as root; protected files and commands are incomplete and results may be misleading.")
    for n in notes:
        a("<div class=box><b>Note:</b> %s</div>" % esc(n))

    a("<h2>Summary</h2>")
    a("<p><b>Compliance of the evaluated recommendations: %.1f%%</b> <span class=muted>(%d pass / %d pass+fail; manual and not-collected items are excluded)</span></p>" % (pct, cnt["PASS"], scored))
    a("<div class=bar>%s</div>" % bar(cnt, total))
    a("<table><tr><th>Status</th><th>Recommendations</th><th>Level 1</th><th>Level 2</th></tr>")
    for k in STATUS_ORDER:
        a("<tr><td class='s %s'>%s</td><td class=n>%d</td><td class=n>%d</td><td class=n>%d</td></tr>" % (
            k, STATUS_LABEL[k], cnt[k], len([f for f in findings if f.status == k and f.level == 1]), len([f for f in findings if f.status == k and f.level == 2])))
    a("<tr><th>Total</th><th class=n>%d</th><th class=n>%d</th><th class=n>%d</th></tr></table>" % (total, len([f for f in findings if f.level == 1]), len([f for f in findings if f.level == 2])))

    a("<h3>By benchmark section</h3><table><tr><th>Section</th><th>Pass</th><th>Fail</th><th>Manual</th><th>Not collected</th></tr>")
    for pfx, title in SECTIONS:
        fs = [f for f in findings if section_of(f.id) == title]
        if not fs:
            continue
        c = {k: len([f for f in fs if f.status == k]) for k in STATUS_ORDER}
        a("<tr><td>%s</td><td class=n>%d</td><td class='n FAIL'>%d</td><td class=n>%d</td><td class=n>%d</td></tr>" % (esc(title), c["PASS"], c["FAIL"], c["MANUAL"], c["NC"]))
    a("</table>")

    fails = [f for f in findings if f.status == "FAIL"]
    a("<h2>Findings and remediation (%d failed)</h2>" % len(fails))
    if not fails:
        a("<p>No recommendation failed.</p>")
    a("<p class=muted>Level 1 items are listed first. Review every command before use; changes can affect production workloads. "
      "Commands are quoted from the remediation sections of the benchmark; test them on a non-production system first.</p>")
    for lvl in (1, 2):
        sel = [f for f in fails if f.level == lvl]
        if not sel:
            continue
        a("<h3>Level %d (%d)</h3>" % (lvl, len(sel)))
        for f in sel:
            a("<div class=rem><b>%s</b> %s <span class=muted>- %s</span><br><span class=small>Finding: %s</span>" % (
                esc(f.id), esc(f.title), esc(section_of(f.id)), esc(f.detail)))
            a("<pre>%s</pre>" % esc(REM.get(f.id, "See the benchmark remediation section.")))
            if not args.no_evidence and f.probes:
                a("<details><summary>evidence</summary>%s</details>" % evidence_html(f.probes))
            a("</div>")

    man = [f for f in findings if f.status == "MANUAL"]
    a("<h2>Manual review required (%d)</h2><table><tr><th>Id</th><th>Recommendation</th><th>What to check</th></tr>" % len(man))
    for f in man:
        a("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (esc(f.id), esc(f.title), esc(f.detail)))
    a("</table>")

    nc = [f for f in findings if f.status == "NC"]
    a("<h2>Not collected / not evaluable (%d)</h2>" % len(nc))
    a("<p class=muted>The evidence did not allow a verdict. Typical reasons: quick mode, a missing command, a timeout, or evidence not collected on AIX.</p>")
    a("<table><tr><th>Id</th><th>Recommendation</th><th>Reason</th></tr>")
    for f in nc:
        a("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (esc(f.id), esc(f.title), esc(f.detail)))
    a("</table>")

    a("<h2>All recommendations</h2><table><tr><th>Id</th><th>Lvl</th><th>Recommendation</th><th>Status</th><th>Observed</th></tr>")
    for f in findings:
        a("<tr><td>%s</td><td class=n>%d</td><td>%s</td><td class='s %s'>%s</td><td class=small>%s</td></tr>" % (
            esc(f.id), f.level, esc(f.title), f.status, STATUS_LABEL[f.status], esc(f.detail[:300])))
    a("</table>")

    a("<h2>Informational chapters of the benchmark</h2>")
    a("<p class=muted>Chapters 1.3, 1.4, 5.4 and 5.5 contain no scored recommendation. The collected facts are shown for reference.</p>")
    for sid, title in INFO_SECTIONS:
        ps = [p for p in DB.values() if p.id == sid]
        a("<details><summary>%s %s</summary>%s</details>" % (esc(sid), esc(title), evidence_html(ps) if ps else "<p class=muted>no evidence</p>"))

    if not args.no_evidence:
        passed = [f for f in findings if f.status == "PASS"]
        a("<h2>Evidence of passed items</h2><details><summary>%d items</summary>" % len(passed))
        for f in passed:
            a("<h3>%s %s</h3>%s" % (esc(f.id), esc(f.title), evidence_html(f.probes, 15)))
        a("</details>")

    a("<footer>Confidential: this report contains system configuration details of %s. Made with IBM Bob.</footer>" % esc(meta.get("hostname", "")))
    a("</main></body></html>")
    return "\n".join(H)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate an HTML report from cis_collect.ksh evidence (%s)." % BENCHMARK)
    ap.add_argument("evidence", help="evidence file written by cis_collect.ksh")
    ap.add_argument("-o", "--output", default="cis_aix7_report.html", help="HTML file to write (default: %(default)s)")
    ap.add_argument("--no-evidence", action="store_true", help="omit the raw evidence from the report")
    args = ap.parse_args(argv)

    try:
        meta, probes, eof = parse_evidence(args.evidence)
    except OSError as e:
        print("cannot read %s: %s" % (args.evidence, e), file=sys.stderr)
        return 1
    if not probes:
        print("%s does not look like a cis_collect.ksh evidence file" % args.evidence, file=sys.stderr)
        return 1
    META.update(meta)
    for p in probes:
        DB[(p.id, p.name)] = p
    findings = evaluate()
    page = render(findings, meta, args, eof)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(page)
    c = {k: len([f for f in findings if f.status == k]) for k in STATUS_ORDER}
    print("%d recommendations: %d pass, %d fail, %d manual, %d not collected -> %s" % (
        len(findings), c["PASS"], c["FAIL"], c["MANUAL"], c["NC"], args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
