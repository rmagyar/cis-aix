#!/usr/bin/ksh93
#
# cis_hardening.ksh - Safe hardening for the CIS IBM AIX 7 Benchmark v1.2.0
#
# Companion of cis_collect.ksh / cis_report.py: every setting applied here is
# the one that cis_report.py evaluates (chapters 2 - 8, 230 recommendations).
#
# SAFETY MODEL
#   * Dry-run (-n) shows every change without making it.  Do this first.
#   * Idempotent: a rule that is already compliant is left untouched.
#   * Permissions are only ever TIGHTENED (new mode = current mode AND maximum).
#   * Every file that is edited is copied first to the backup directory; every
#     attribute change records the old value in an undo script (undo.ksh).
#   * Edited config files are validated (sshd -t, visudo -c) and rolled back
#     automatically when the validation fails.
#   * Rules that could cut off access or break running workloads are SKIPPED
#     unless the matching service is idle or you pass -x (see below).
#   * Rules that need a human decision (site text, hosts, disks, removal of
#     software, accounts, SUID review ...) are never applied; they are listed
#     as [MANUAL] with the exact action to take.
#   * Nothing is installed or removed (no installp -u), no user data is deleted
#     (host-based auth files are moved into the backup directory).
#
# Usage: cis_hardening.ksh [-n] [-x] [-y] [-q] [-s prefix] [-L loghost]
#                          [-P securepath] [-b backupdir]
#   -n            dry-run: report what would be changed, change nothing
#   -x            also apply the RISKY rules (listed below); implies that you
#                 have console access and a mksysb
#   -y            do not ask for confirmation
#   -q            quick: skip the file-system-wide scans (3.2 3.4 3.5 4.2.5)
#   -s prefix     only rules whose id equals / starts with prefix (e.g. 4.5)
#   -L loghost    remote syslog host for 8.2.2 (otherwise 8.2.2 is manual)
#   -P securepath Trusted Execution Path for 2.2     (default /usr/bin:/usr/sbin)
#   -b dir        backup / undo directory   (default /var/tmp/cis_hardening.<ts>)
#   -h            this help
#
# RISKY rules (applied only with -x, or when the service is not running):
#   2.2 2.3 2.4(CHKEXEC) 2.5 Trusted Execution       4.4.3.1 live remount nodev
#   3.4 3.5 chmod of world / staff writable files     4.5.6 4.5.7 forwarding off
#   4.1.2.11 root home                                4.6.1.3 kill dtlogin
#   4.6.3.14/15 PermitRootLogin (without root ssh key) 4.8.1 root login/su control
#   5.1.1 lock empty-password accounts                5.2.5 5.2.6 password expiry
#   services in use: inittab / rc.tcpip / inetd entries of daemons that are
#   running now (qdaemon, rcnfs, named, routed, sendmail, portmap, inetd ...)
#   remote access via inetd (telnet ftp rlogin rsh rexec ...) needs sshd active
#
# Run as root on the AIX host.  Take a mksysb first.  Verify afterwards with
#   cis_collect.ksh && python3 cis_report.py <evidence> -o report.html
#

VERSION="1.0.0"
BENCHMARK="CIS IBM AIX 7 Benchmark v1.2.0"

PATH=/usr/bin:/bin:/etc:/usr/sbin:/usr/ucb:/sbin:/usr/local/bin:/opt/freeware/bin
export PATH
umask 022

DRYRUN=0
RISKY=0
ASSUME_YES=0
QUICK=0
FILTER=""
LOGHOST=""
SECUREPATH="/usr/bin:/usr/sbin"
STAMP=$(date '+%Y%m%d_%H%M%S')
BACKUP_DIR="/var/tmp/cis_hardening.$STAMP"

while getopts "nxyqs:L:P:b:h" opt; do
    case $opt in
        n) DRYRUN=1 ;;
        x) RISKY=1 ;;
        y) ASSUME_YES=1 ;;
        q) QUICK=1 ;;
        s) FILTER=$OPTARG ;;
        L) LOGHOST=$OPTARG ;;
        P) SECUREPATH=$OPTARG ;;
        b) BACKUP_DIR=$OPTARG ;;
        h) sed -n '2,/^# Run as root/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) sed -n '/^# Usage:/,/^#   -h/p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    esac
done

LOG="$BACKUP_DIR/cis_hardening.log"
UNDO="$BACKUP_DIR/undo.ksh"
WORK="$BACKUP_DIR/work"

N_APPLIED=0 N_OK=0 N_MANUAL=0 N_FAILED=0 N_SKIPPED=0 N_DRY=0
SSHD_CHANGED=0
REBOOT_NEEDED=0

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
if [[ $(uname -s 2>/dev/null) != AIX ]]; then
    print -u2 "ERROR: this script is for AIX (detected: $(uname -s 2>/dev/null))."
    exit 1
fi
if [[ $(id -u 2>/dev/null) != 0 ]]; then
    print -u2 "ERROR: run as root."
    exit 1
fi

mkdir -p "$BACKUP_DIR" "$WORK" || { print -u2 "ERROR: cannot create $BACKUP_DIR"; exit 1; }
chmod 700 "$BACKUP_DIR" "$WORK"
: > "$LOG"
if (( ! DRYRUN )); then
    {
        print "#!/usr/bin/ksh93"
        print "# Undo information written by cis_hardening.ksh $VERSION on $(hostname) at $STAMP"
        print "# Review before running.  Edited files are restored with:  cp -p <backup> <original>"
        print "# Backup root: $BACKUP_DIR/files"
    } > "$UNDO"
    chmod 700 "$UNDO"
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
say() { print -r -- "$*"; print -r -- "$*" >> "$LOG"; }

hdr() { say ""; say "=== $* ==="; }

ok() {      say "  [OK]       $1: $2";                     ((N_OK=N_OK + 1)); }
info() {    say "  [INFO]     $1: $2"; }
manual() {  say "  [MANUAL]   $1: $2";                     ((N_MANUAL=N_MANUAL + 1)); }
skipped() { say "  [SKIPPED]  $1: $2";                     ((N_SKIPPED=N_SKIPPED + 1)); }
failed() {  say "  [FAILED]   $1: $2";                     ((N_FAILED=N_FAILED + 1)); }

in_scope() {
    [[ -z $FILTER ]] && return 0
    [[ $1 == "$FILTER" || $1 == "$FILTER".* ]] && return 0
    return 1
}

# do_change <rule> <description> <command> [args...]
#   Runs the command (a program or a function of this script) - or only
#   announces it in dry-run mode - and reports the real outcome.
do_change() {
    typeset rid=$1 desc=$2 out rc
    shift 2
    if (( DRYRUN )); then
        say "  [DRY-RUN]  $rid: would $desc"
        ((N_DRY=N_DRY + 1))
        return 0
    fi
    out=$("$@" 2>&1)
    rc=$?
    if (( rc == 0 )); then
        say "  [APPLIED]  $rid: $desc"
        ((N_APPLIED=N_APPLIED + 1))
    else
        failed "$rid" "$desc (rc=$rc) $out"
    fi
    return $rc
}

# risky_ok <rule> <why> : true when -x was given, otherwise reports and returns 1
risky_ok() {
    (( RISKY )) && return 0
    skipped "$1" "risky - $2 (re-run with -x to apply)"
    return 1
}

# ---------------------------------------------------------------------------
# System queries
# ---------------------------------------------------------------------------
svc_active() {
    lssrc -s "$1" 2>/dev/null | awk 'NR == 2 && $NF == "active" { f = 1 } END { exit !f }'
}
fs_installed() { lslpp -Lc "$1" > /dev/null 2>&1; }
user_exists() { lsuser "$1" > /dev/null 2>&1; }
proc_running() { ps -e -o comm 2> /dev/null | awk -v p="$1" '$1 == p || $1 ~ ("/" p "$") { f = 1 } END { exit !f }'; }

# can_disable <rule> <svc> : refuse to switch off something that is running now
can_disable() {
    if svc_active "$2" || proc_running "$2"; then
        (( RISKY )) && return 0
        skipped "$1" "$2 is running now - not disabled (re-run with -x if it is not needed)"
        return 1
    fi
    return 0
}

sshd_usable() { svc_active sshd || proc_running sshd; }

# remote_ok <rule> <what> : legacy remote-access service may only go when sshd is up
remote_ok() {
    sshd_usable && return 0
    (( RISKY )) && return 0
    skipped "$1" "$2 is a remote access path and sshd is not running - kept to avoid lock-out"
    return 1
}

mode_of() { perl -e 'printf "%04o", (stat $ARGV[0])[2] & 07777' "$1" 2> /dev/null; }
owner_of() { ls -ld "$1" 2> /dev/null | awk '{ print $3 }'; }
group_of() { ls -ld "$1" 2> /dev/null | awk '{ print $4 }'; }

# ---------------------------------------------------------------------------
# Backup / undo / edit primitives (used through do_change)
# ---------------------------------------------------------------------------
backup_file() {
    typeset f=$1 t="$BACKUP_DIR/files$1"
    [[ -e $f && ! -e $t ]] || return 0
    mkdir -p "$(dirname "$t")" && cp -p "$f" "$t"
}

undo_note() { (( DRYRUN )) || print -r -- "$*" >> "$UNDO"; }

# file_filter <file> <cmd...> : file = output of "cmd < file"; never empties a file
file_filter() {
    typeset f=$1 tmp="$WORK/ff.$$"
    shift
    backup_file "$f"
    "$@" < "$f" > "$tmp" || { rm -f "$tmp"; return 1; }
    if [[ -s $f && ! -s $tmp ]]; then
        rm -f "$tmp"
        return 1
    fi
    cat "$tmp" > "$f"
    typeset rc=$?
    rm -f "$tmp"
    return $rc
}

# file_append <file> <line> : append a line (creating the file, fixing a missing final newline)
file_append() {
    typeset f=$1
    shift
    backup_file "$f"
    if [[ -s $f && -n $(tail -c 1 "$f" 2> /dev/null) ]]; then
        print >> "$f"
    fi
    print -r -- "$*" >> "$f"
}

# fix_perm <rule> <path> <owner|-> <group|-> <maxmode-octal>
#   chown/chgrp when different; chmod to (current AND max) so that a mode can
#   never become less restrictive.  Missing objects are fine.
fix_perm() {
    typeset rid=$1 p=$2 own=$3 grp=$4 max=$5 cur new
    in_scope "$rid" || return 0
    if [[ ! -e $p ]]; then
        ok "$rid" "$p does not exist - nothing to protect"
        return 0
    fi
    if [[ $own != - && $(owner_of "$p") != "$own" ]]; then
        if user_exists "$own"; then
            undo_note "chown $(owner_of "$p") '$p'"
            do_change "$rid" "chown $own $p" chown "$own" "$p"
        else
            failed "$rid" "owner $own does not exist - $p not changed"
        fi
    fi
    if [[ $grp != - && $(group_of "$p") != "$grp" ]]; then
        if lsgroup "$grp" > /dev/null 2>&1; then
            undo_note "chgrp $(group_of "$p") '$p'"
            do_change "$rid" "chgrp $grp $p" chgrp "$grp" "$p"
        else
            failed "$rid" "group $grp does not exist - $p not changed"
        fi
    fi
    cur=$(mode_of "$p")
    if [[ -z $cur ]]; then
        failed "$rid" "cannot read mode of $p (perl missing?)"
        return 0
    fi
    new=$(printf '%04o' $(( 8#$cur & 8#$max )))
    if [[ $new == "$cur" ]]; then
        ok "$rid" "$p $(owner_of "$p"):$(group_of "$p") $cur (maximum $max)"
    else
        undo_note "chmod $cur '$p'"
        do_change "$rid" "chmod $new $p (was $cur)" chmod "$new" "$p"
    fi
}

# ---------------------------------------------------------------------------
# Attribute helpers
# ---------------------------------------------------------------------------
sec_get() { lssec -f "$1" -s "$2" -a "$3" 2> /dev/null | awk -v a="$3" '{ for (i = 1; i <= NF; i++) if (index($i, a "=") == 1) { print substr($i, length(a) + 2); exit } }'; }

# sec_num <rule> <file> <stanza> <attr> <min> <max> <target> [risky-reason]
#   compliant when min <= current <= max, otherwise set to target
sec_num() {
    typeset rid=$1 f=$2 st=$3 at=$4 lo=$5 hi=$6 tgt=$7 why=$8 cur
    in_scope "$rid" || return 0
    cur=$(sec_get "$f" "$st" "$at")
    if [[ $cur == +([0-9]) ]] && (( cur >= lo && cur <= hi )); then
        ok "$rid" "$at=$cur"
        return 0
    fi
    if [[ -n $why ]]; then
        risky_ok "$rid" "$why" || return 0
    fi
    undo_note "chsec -f $f -s $st -a $at=${cur}"
    do_change "$rid" "chsec $f $st $at=$tgt (was '${cur}')" chsec -f "$f" -s "$st" -a "$at=$tgt"
}

# no_set <rule> <tool> <option> <value> [risky-reason]
net_set() {
    typeset rid=$1 tool=$2 opt=$3 want=$4 why=$5 cur
    in_scope "$rid" || return 0
    cur=$($tool -o "$opt" 2> /dev/null | awk '{ print $3 }')
    if [[ -z $cur ]]; then
        info "$rid" "$tool does not know '$opt' on this AIX level - skipped"
        return 0
    fi
    if [[ $cur == "$want" ]]; then
        ok "$rid" "$opt=$cur"
        return 0
    fi
    if [[ -n $why ]]; then
        risky_ok "$rid" "$why" || return 0
    fi
    undo_note "$tool -p -o $opt=$cur"
    do_change "$rid" "$tool -p -o $opt=$want (was $cur)" $tool -p -o "$opt=$want"
}

# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------
hdr "cis_hardening.ksh $VERSION - $BENCHMARK"
say "Host: $(hostname)   Date: $(date)"
say "Backup/undo dir: $BACKUP_DIR"
(( DRYRUN )) && say "MODE: DRY-RUN - nothing will be changed"
(( RISKY )) && say "MODE: -x RISKY rules enabled"
[[ -n $FILTER ]] && say "Filter: $FILTER"

if (( ! DRYRUN && ! ASSUME_YES )); then
    say ""
    say "This will modify the system configuration.  A mksysb is strongly recommended."
    printf 'Continue? (yes/no) '
    read answer
    [[ $answer == yes ]] || { say "Aborted."; exit 1; }
fi

# No command may wait for keyboard input from here on (e.g. vmo/no/schedo prompt
# for confirmation; their output is captured, so the script would look stuck).
exec 0< /dev/null

# ===========================================================================
# 2 Inventory and control of assets
# ===========================================================================
hdr "2 Inventory and Control of Assets"

syslog_rule() {   # syslog_rule <rule> <selector> <logfile> <extra>
    typeset rid=$1 sel=$2 lf=$3 ex=$4
    if grep -v '^[[:space:]]*#' /etc/syslog.conf 2> /dev/null | grep -qF -- "$lf"; then
        ok "$rid" "syslog.conf already logs to $lf"
        return 0
    fi
    do_change "$rid" "create $lf" syslog_mkfile "$lf"
    do_change "$rid" "add '$sel $lf' to /etc/syslog.conf" file_append /etc/syslog.conf \
        "$(printf '%s\t%s rotate time 1d files 30 compress%s' "$sel" "$lf" "$ex")"
    SYSLOG_REFRESH=1
}
syslog_mkfile() {
    mkdir -p "$(dirname "$1")" || return 1
    [[ -e $1 ]] || touch "$1" || return 1
    chown root:system "$1"
    chmod 640 "$1"
}
SYSLOG_REFRESH=0

if in_scope 2.1; then
    if crontab -l 2> /dev/null | grep -q "/usr/sbin/lsconf -v"; then
        ok 2.1 "root crontab already runs lsconf -v"
    else
        add_inventory_cron() {
            crontab -l > "$WORK/cron.root" 2> /dev/null
            cp "$WORK/cron.root" "$BACKUP_DIR/crontab.root.before" 2> /dev/null
            print '0 0 * * * /usr/sbin/lsconf -v | /usr/bin/logger -p local1.info -t Inventory' >> "$WORK/cron.root"
            crontab "$WORK/cron.root"
        }
        do_change 2.1 "add lsconf -v job to root crontab" add_inventory_cron
    fi
    syslog_rule 2.1 local1.info /var/log/syslog/inventory.log ""
fi

# Trusted Execution (Level 2, can stop the system from running programs) -----
te_val() { trustchk -p "$1" 2> /dev/null | awk -F= -v k="$1" 'toupper($1) == toupper(k) { print toupper($2) }'; }

te_enable_path() {
    trustchk -p TE=OFF TEP=OFF && trustchk -p "TEP=$SECUREPATH" && trustchk -p TE=ON TEP=ON
}

if in_scope 2.2; then
    if [[ $(te_val TE) == ON && $(te_val TEP) == ON ]]; then
        ok 2.2 "TE=ON TEP=ON"
    elif risky_ok 2.2 "TEP=$SECUREPATH blocks execution of programs outside that path; TE needs a signed trust database"; then
        do_change 2.2 "enable TE/TEP with TEP=$SECUREPATH" te_enable_path
    fi
fi

if in_scope 2.3; then
    if [[ $(te_val LOCK_KERN_POLICIES) == ON ]]; then
        ok 2.3 "LOCK_KERN_POLICIES=ON"
    elif risky_ok 2.3 "policies stay locked until reboot"; then
        do_change 2.3 "trustchk -p LOCK_KERN_POLICIES=ON" trustchk -p LOCK_KERN_POLICIES=ON
    fi
fi

if in_scope 2.4; then
    syslog_rule 2.4 kern.info /var/log/syslog/kernel.log ""
    if [[ $(te_val TE) == ON && $(te_val CHKEXEC) == ON ]]; then
        ok 2.4 "TE=ON CHKEXEC=ON"
    elif risky_ok 2.4 "CHKEXEC=ON refuses to run programs failing the trust check"; then
        do_change 2.4 "trustchk -p TE=ON CHKEXEC=ON" trustchk -p TE=ON CHKEXEC=ON
    fi
fi

if in_scope 2.5; then
    if [[ $(te_val STOP_UNTRUSTD) == @(ON|TROJAN) && $(te_val STOP_ON_CHKFAIL) == ON && $(te_val TE) == ON ]]; then
        ok 2.5 "stop_untrustd / stop_on_chkfail / te enabled"
    elif risky_ok 2.5 "stops untrusted programs and aborts on check failures"; then
        do_change 2.5 "trustchk -p stop_untrustd=on stop_on_chkfail=on te=on" trustchk -p stop_untrustd=on stop_on_chkfail=on te=on
    fi
fi

in_scope 2.6 && manual 2.6 "review 'trustchk -i -n tree / 2>&1 >/dev/null | grep untrusted' and fix, remove or add (trustchk -a) each object"
in_scope 2.7 && manual 2.7 "review 'find -L / \\( -fstype jfs -o -fstype jfs2 \\) -type l -ls' and remove dangling links"

# ===========================================================================
# 3 Data protection
# ===========================================================================
hdr "3 Configure Data Protection"

if in_scope 3.1; then
    cur=$(sec_get /etc/security/user default umask)
    if [[ $cur == +([0-7]) ]] && [[ $cur == ?(0)[2-7]7 ]]; then
        ok 3.1 "umask=$cur"
    else
        undo_note "chsec -f /etc/security/user -s default -a umask=$cur"
        do_change 3.1 "default umask 027 (was '$cur')" chsec -f /etc/security/user -s default -a umask=027
    fi
fi

# fs_scan_chmod <rule> <label> <find-expr...> -- <chmod-arg>
#   lists the objects first (kept in the backup dir with their old modes), then chmods them
scan_and_chmod() {
    typeset rid=$1 chm=$2 list="$BACKUP_DIR/$1.objects"
    shift 2
    find / \( -fstype jfs -o -fstype jfs2 \) "$@" -ls 2> /dev/null > "$list"
    [[ -s $list ]] || return 0
    awk '{ print $NF }' "$list" | while read -r o; do
        [[ -e $o ]] && chmod "$chm" "$o"
    done
}

fs_rule() {
    typeset rid=$1 label=$2 chm=$3
    shift 3
    in_scope "$rid" || return 0
    if (( QUICK )); then
        skipped "$rid" "quick mode - file-system-wide scan not run"
        return 0
    fi
    typeset n
    n=$(find / \( -fstype jfs -o -fstype jfs2 \) "$@" -print 2> /dev/null | wc -l | tr -d ' ')
    if (( n == 0 )); then
        ok "$rid" "no $label"
    else
        do_change "$rid" "chmod $chm on $n $label (old modes listed in $BACKUP_DIR/$rid.objects)" scan_and_chmod "$rid" "$chm" "$@"
    fi
}

fs_rule 3.2 "world-writable directories without sticky bit" o+t -type d -perm -o+w ! -perm -1000
in_scope 3.3 && manual 3.3 "review group-writable objects of admin groups (find -L / ... -group <admin group> -ls) and chmod g-w where not required"
if in_scope 3.4; then
    risky_ok 3.4 "world-writable files may be used on purpose by applications" \
        && fs_rule 3.4 "world-writable files" o-w -type f -perm -o+w
fi
if in_scope 3.5; then
    risky_ok 3.5 "group staff may write to files that applications rely on" \
        && fs_rule 3.5 "group-staff-writable files" g-w -type f -perm -g+w -group staff
fi
in_scope 3.6 && manual 3.6 "find / \\( -fstype jfs -o -fstype jfs2 \\) \\( -nouser -o -nogroup \\) -ls ; chown/chgrp or remove each object"

# ===========================================================================
# 4.1.1 Trusted files
# ===========================================================================
hdr "4.1.1 Configure Trusted Files"

SMIT=~root
[[ $SMIT != / ]] && SMIT=$SMIT/
fix_perm 4.1.1.1  "${SMIT}smit.log"       -      -        0640
fix_perm 4.1.1.2  /etc/group              root   security 0644
fix_perm 4.1.1.3  /etc/inetd.conf         root   system   0644
fix_perm 4.1.1.4  /etc/motd               bin    bin      0644
fix_perm 4.1.1.5  /etc/passwd             root   security 0644
fix_perm 4.1.1.6  /etc/mail/submit.cf     -      -        0640
fix_perm 4.1.1.7  /etc/ssh/ssh_banner     root   system   0644
fix_perm 4.1.1.8  /etc/ssh/ssh_config     root   system   0644
fix_perm 4.1.1.9  /etc/ssh/sshd_config    root   system   0644
fix_perm 4.1.1.10 /var/adm/cron/at.allow  root   sys      0400
fix_perm 4.1.1.11 /var/adm/cron/cron.allow root  sys      0400
fix_perm 4.1.1.12 /var/adm/cron/log       bin    cron     0660
fix_perm 4.1.1.13 /var/ct/RMstart.log     root   system   0640
fix_perm 4.1.1.14 /var/tmp/dpid2.log      root   system   0640
fix_perm 4.1.1.15 /var/tmp/hostmibd.log   root   system   0640
fix_perm 4.1.1.16 /var/tmp/snmpd.log      root   system   0640
fix_perm 4.1.1.20 /var/tmp/snmpdv3.log    root   system   0640

in_scope 4.1.1.17 && manual 4.1.1.17 "make every command in root's crontab (and its parent directories) root/bin owned and not group/world writable"

if in_scope 4.1.1.18; then
    # user dot files of local users: remove group/other write only
    n=0
    lsuser -c -a home ALL 2> /dev/null | grep -v '^#' | cut -d: -f2 | egrep -v '^/$|/etc|/bin|/var|/usr|^/dev/null$' | sort -u |
    while read -r hd; do
        [[ -d $hd ]] || continue
        ls -a "$hd" 2> /dev/null | egrep '^\.[a-z]' | while read -r f; do
            [[ -f $hd/$f && ! -L $hd/$f ]] || continue
            m=$(ls -ld "$hd/$f" | cut -c1-10)
            if [[ ${m:5:1} == w || ${m:8:1} == w ]]; then
                undo_note "chmod $(mode_of "$hd/$f") '$hd/$f'"
                do_change 4.1.1.18 "chmod go-w $hd/$f" chmod go-w "$hd/$f"
                ((n=n + 1))
            fi
        done
    done
    (( n )) || ok 4.1.1.18 "no group/other writable user dot files"
fi

in_scope 4.1.1.19 && manual 4.1.1.19 "review 'find / \\( -fstype jfs -o -fstype jfs2 \\) \\( -perm -04000 -o -perm -02000 \\) -type f -ls'; chmod ug-s what is not needed"

# ===========================================================================
# 4.1.2 Trusted directories
# ===========================================================================
hdr "4.1.2 Configure Trusted Directories"

if in_scope 4.1.2.1; then
    manual 4.1.2.1 "lock (chuser account_locked=true) or give a HOME to local accounts (uid>=200) whose HOME is missing"
fi
in_scope 4.1.2.2 && manual 4.1.2.2 "HOME directories must belong to the account or root: chown <user> <HOME> (decision per account)"

if in_scope 4.1.2.3; then
    lsuser -c -a id home ALL 2> /dev/null | grep -v '^#' | while IFS=: read -r u uid hd; do
        [[ $uid == +([0-9]) ]] && (( uid >= 200 )) || continue
        [[ $hd == / || $hd == /dev/null || ! -d $hd ]] && continue
        m=$(ls -ld "$hd" | cut -c1-10)
        if [[ ${m:5:1} == w || ${m:8:1} == w ]]; then
            undo_note "chmod $(mode_of "$hd") '$hd'"
            do_change 4.1.2.3 "chmod go-w $hd (HOME of $u)" chmod go-w "$hd"
        fi
    done
    ok 4.1.2.3 "HOME directories checked (extended ACLs: check 'aclget <home>' manually)"
fi

secure_tree() {   # secure_tree <owner:group> <dir-chmod> <file-chmod> <dir...>
    typeset og=$1 dm=$2 fm=$3 d
    shift 3
    for d in "$@"; do
        [[ -d $d ]] || continue
        find "$d" | grep -v 'lost+found' | while read -r o; do chown "$og" "$o"; done
        find "$d" -type d | grep -v 'lost+found' | while read -r o; do chmod $dm "$o"; done
        find "$d" ! -type d | grep -v 'lost+found' | while read -r o; do chmod $fm "$o"; done
    done
}

if in_scope 4.1.2.4; then
    n=$(find /etc/security/audit /audit \( -perm -4 -o -perm -2 -o -perm -1 \) -o ! -user root -o ! -group audit 2> /dev/null | wc -l | tr -d ' ')
    if (( n == 0 )); then
        ok 4.1.2.4 "/audit and /etc/security/audit are root:audit without 'other' access"
    elif lsgroup audit > /dev/null 2>&1; then
        do_change 4.1.2.4 "root:audit, g-w,o-rwx on directories and u-x,g-wx,o-rwx on files in /audit /etc/security/audit ($n objects)" \
            secure_tree root:audit g-w,o-rwx u-x,g-wx,o-rwx /etc/security/audit /audit
    fi
fi

secure_etc_security() {
    typeset d o
    find /etc/security -type d | egrep -v 'security/(aixpert|audit|ice)' | while read -r d; do
        find "$d" | egrep -v 'security/(aixpert|audit|ice)' | while read -r o; do chown root:security "$o"; done
        find "$d" -type d | egrep -v 'security/(aixpert|audit|ice)' | while read -r o; do chmod g-w+s,o-rwx "$o"; done
        find "$d" -type f | egrep -v 'security/(aixpert|audit|ice)' | while read -r o; do chmod u-x,g-wx,o-rwx "$o"; done
    done
}
if in_scope 4.1.2.5; then
    n=$(find /etc/security -type d 2> /dev/null | egrep -v 'security/(aixpert|audit|ice)' | xargs ls -led 2> /dev/null | awk '{ print $1 }' | egrep -vc 'dr[w-]x[r-]-[sS-]----')
    if (( n == 0 )); then
        ok 4.1.2.5 "directories below /etc/security are drwxr-s---"
    else
        do_change 4.1.2.5 "root:security, g-w+s,o-rwx on $n directories below /etc/security" secure_etc_security
    fi
fi

ras_fix() {
    ls /var/adm/ras 2> /dev/null | while read -r f; do chmod o-rw "/var/adm/ras/$f"; done
}
if in_scope 4.1.2.6; then
    n=$(ls -l /var/adm/ras 2> /dev/null | awk 'NR > 1 && $NF != "SRCKeyID" && (substr($1, 8, 1) == "r" || substr($1, 9, 1) == "w") { c++ } END { print c + 0 }')
    if (( n == 0 )); then
        ok 4.1.2.6 "/var/adm/ras has no 'other' access (SRCKeyID excepted)"
    else
        ls -l /var/adm/ras > "$BACKUP_DIR/4.1.2.6.before.txt" 2> /dev/null
        do_change 4.1.2.6 "chmod o-rw on $n objects in /var/adm/ras (listing in 4.1.2.6.before.txt)" ras_fix
    fi
fi

fix_perm 4.1.2.7 /var/adm/sa adm adm 0755

cron_dir_fix() {   # cron_dir_fix <dir>
    typeset d=$1
    echo | aclput "$d" 2> /dev/null
    chmod -R o= "$d"
    chown bin:cron "$d"
    chgrp -R cron "$d"
    chmod ug=rwx,o= "$d"
    trustchk -a "$d" size=VOLATILE > /dev/null 2>&1 || trustchk -u "$d" owner=bin group=cron mode=770 > /dev/null 2>&1
    return 0
}
for _cd in "4.1.2.8:/var/spool/cron/crontabs" "4.1.2.9:/var/spool/cron/atjobs"; do
    _r=${_cd%%:*}
    _d=${_cd#*:}
    in_scope "$_r" || continue
    [[ -d $_d ]] || { ok "$_r" "$_d does not exist"; continue; }
    n=$(find "$_d" \( -perm -4 -o -perm -2 -o -perm -1 -o -perm -200000000 \) -o ! -group cron 2> /dev/null | wc -l | tr -d ' ')
    if (( n == 0 )) && [[ $(owner_of "$_d") == bin ]]; then
        ok "$_r" "$_d bin:cron without 'other' access"
    else
        ls -ld "$_d" >> "$BACKUP_DIR/perms.before.txt" 2> /dev/null
        do_change "$_r" "bin:cron, o= on $_d ($n deviating objects)" cron_dir_fix "$_d"
    fi
done

in_scope 4.1.2.10 && manual 4.1.2.10 "remove '.', empty and relative entries from root's PATH (/etc/environment, /etc/profile, /.profile) and make each directory root/bin owned, not g/o writable"

if in_scope 4.1.2.11; then
    if [[ $(sec_get /etc/security/user root home) == / || $(lsuser -a home root 2> /dev/null | awk '{ sub(/home=/, "", $2); print $2 }') == / ]]; then
        if risky_ok 4.1.2.11 "root's HOME moves away from / (dot files in / are no longer read at login)"; then
            mk_root_home() { mkdir -p /root && chown root:system /root && chmod 0700 /root && chuser home=/root root; }
            undo_note "chuser home=/ root"
            do_change 4.1.2.11 "create /root (0700) and set root's home to /root" mk_root_home
        fi
    else
        ok 4.1.2.11 "root has a dedicated home directory"
    fi
fi

# ===========================================================================
# 4.2 Network services
# ===========================================================================
hdr "4.2 Configure Network Services"

for _p in "4.2.1:bos.net.nis.client" "4.2.2:bos.net.nis.server" "4.2.7:bos.net.tcp.snmp bos.net.tcp.snmpd"; do
    _r=${_p%%:*}
    in_scope "$_r" || continue
    _found=""
    for _f in ${_p#*:}; do fs_installed "$_f" && _found="$_found $_f"; done
    if [[ -z $_found ]]; then
        ok "$_r" "software not installed"
    else
        manual "$_r" "installed:$_found - software is never removed automatically; 'installp -ug ...' if it is not needed"
    fi
done

strip_plus() { grep -v '^+'; }
if in_scope 4.2.3; then
    for _f in /etc/passwd /etc/group; do
        if grep -q '^+' "$_f" 2> /dev/null; then
            if svc_active ypbind || proc_running ypbind; then
                skipped 4.2.3 "NIS client (ypbind) is running - '+' entries in $_f kept"
            else
                do_change 4.2.3 "remove '+' entries from $_f" file_filter "$_f" strip_plus
            fi
        else
            ok 4.2.3 "no '+' entries in $_f"
        fi
    done
fi

comment_active() { awk '/^[ \t]*$/ { next } /^[ \t]*#/ { print; next } { print "#" $0 }'; }
if in_scope 4.2.4; then
    if grep -v '^[[:space:]]*#' /etc/hosts.equiv 2> /dev/null | grep -qv '^[[:space:]]*$'; then
        do_change 4.2.4 "comment out the active entries of /etc/hosts.equiv" file_filter /etc/hosts.equiv comment_active
    else
        ok 4.2.4 "/etc/hosts.equiv has no active entries"
    fi
fi

move_to_backup() {
    typeset f=$1 t="$BACKUP_DIR/files$1"
    mkdir -p "$(dirname "$t")" && cp -p "$f" "$t" && rm -f "$f"
}
if in_scope 4.2.5; then
    if (( QUICK )); then
        skipped 4.2.5 "quick mode - file-system-wide scan not run"
    else
        n=0
        for _n in .netrc .rhosts .shosts shosts.equiv; do
            find / \( -fstype jfs -o -fstype jfs2 \) -name "$_n" -type f -print 2> /dev/null | while read -r f; do
                ((n=n + 1))
                do_change 4.2.5 "move $f to the backup directory" move_to_backup "$f"
            done
        done
        (( n )) || ok 4.2.5 "no host based authentication files found"
    fi
fi

rcmd_off() { echo | aclput "$1" 2> /dev/null; chmod 0 "$1" && trustchk -u "$1" mode=0 > /dev/null 2>&1; return 0; }
if in_scope 4.2.6; then
    if remote_ok 4.2.6 "disabling rsh/rlogin/rexec files"; then
        n=0
        for _fs in bos.net.tcp.rcmd_server bos.net.tcp.rcmd; do
            fs_installed "$_fs" || continue
            lslpp -f "$_fs" 2> /dev/null | egrep '^ +/' | awk '{ print $1 }' | while read -r f; do
                [[ -L $f || ! -e $f ]] && continue
                m=$(ls -ld "$f" | cut -c1-10)
                [[ $m == ?--------- ]] && continue
                undo_note "chmod $(mode_of "$f") '$f'"
                ((n=n + 1))
                do_change 4.2.6 "chmod 0 $f (rcmd fileset $_fs)" rcmd_off "$f"
            done
        done
        (( n )) || ok 4.2.6 "legacy rcmd files already disabled or not installed"
    fi
fi

# ===========================================================================
# 4.3.1 /etc/inittab
# ===========================================================================
hdr "4.3.1 Processes managed by /etc/inittab"

itab_off() {
    typeset e new
    e=$(lsitab "$1") || return 1
    new=$(print -r -- "$e" | sed 's/^\([^:]*:[^:]*:\)[^:]*:/\1off:/')
    chitab "$new"
}
itab_remove() { rmitab "$1"; }

if in_scope 4.3.1.1; then
    e=$(lsitab writesrv 2> /dev/null)
    if [[ -z $e || $e == *:off:* ]]; then
        ok 4.3.1.1 "writesrv inittab entry off or absent"
    else
        undo_note "chitab '$e'"
        do_change 4.3.1.1 "set the writesrv inittab entry to off" itab_off writesrv
    fi
    svc_active writesrv && do_change 4.3.1.1 "stop writesrv" stopsrc -s writesrv
fi

if in_scope 4.3.1.2; then
    for _l in dt dt_nogb; do
        e=$(lsitab $_l 2> /dev/null)
        [[ -z $e ]] && continue
        if proc_running dtlogin && (( ! RISKY )); then
            skipped 4.3.1.2 "dtlogin is running - inittab entry '$_l' kept"
        else
            undo_note "mkitab '$e'"
            do_change 4.3.1.2 "remove inittab entry $_l" itab_remove $_l
        fi
    done
    lsitab dt > /dev/null 2>&1 || lsitab dt_nogb > /dev/null 2>&1 || ok 4.3.1.2 "no dt/dt_nogb inittab entry"
fi

for _pair in "4.3.1.3:piobe:qdaemon" "4.3.1.4:qdaemon:qdaemon"; do
    _r=${_pair%%:*}
    _l=${_pair#*:}
    _l=${_l%%:*}
    _s=${_pair##*:}
    in_scope "$_r" || continue
    e=$(lsitab "$_l" 2> /dev/null)
    if [[ -z $e ]]; then
        ok "$_r" "no $_l inittab entry"
    elif can_disable "$_r" "$_s"; then
        undo_note "mkitab '$e'"
        do_change "$_r" "remove inittab entry $_l" itab_remove "$_l"
    fi
done

if in_scope 4.3.1.5; then
    e=$(lsitab rcnfs 2> /dev/null)
    if [[ -z $e || $e == *:off:* ]]; then
        ok 4.3.1.5 "rcnfs inittab entry off or absent"
    else
        nfs_in_use=0
        mount 2> /dev/null | grep -q ' nfs' && nfs_in_use=1
        grep -v '^[[:space:]]*#' /etc/exports 2> /dev/null | grep -q '[^[:space:]]' && nfs_in_use=1
        if (( nfs_in_use && ! RISKY )); then
            skipped 4.3.1.5 "NFS mounts or exports exist - rcnfs kept (re-run with -x)"
        else
            undo_note "chitab '$e'"
            do_change 4.3.1.5 "set the rcnfs inittab entry to off" itab_off rcnfs
            svc_active nfsd && do_change 4.3.1.5 "stop the nfs group" stopsrc -g nfs
        fi
    fi
fi

for _p in "4.3.1.6:bos.net.snapp" "4.3.1.7:bos.sysmgt.nim.master bos.sysmgt.nim.spot"; do
    _r=${_p%%:*}
    in_scope "$_r" || continue
    _found=""
    for _f in ${_p#*:}; do fs_installed "$_f" && _found="$_found $_f"; done
    if [[ -z $_found ]]; then ok "$_r" "software not installed"
    else manual "$_r" "installed:$_found - remove with installp -u if not needed"; fi
done

# ===========================================================================
# 4.3.2 /etc/rc.tcpip
# ===========================================================================
hdr "4.3.2 Daemons managed by /etc/rc.tcpip"

rc_active() { grep -v '^[[:space:]]*#' /etc/rc.tcpip 2> /dev/null | grep -q "start[[:blank:]]*$1"; }

# rctcp_off <rule> <daemon-path> <subsystem> [chrctcp-name]
rctcp_off() {
    typeset rid=$1 path=$2 svc=$3 nm=${4:-$3}
    in_scope "$rid" || return 0
    if ! rc_active "$path" && ! svc_active "$svc"; then
        ok "$rid" "$svc not started from rc.tcpip and not running"
        return 0
    fi
    can_disable "$rid" "$svc" || return 0
    if rc_active "$path"; then
        undo_note "chrctcp -a $nm"
        do_change "$rid" "chrctcp -d $nm (comment out the rc.tcpip start entry)" chrctcp -d "$nm"
    fi
    svc_active "$svc" && do_change "$rid" "stopsrc -s $svc" stopsrc -s "$svc"
}

# 4.3.2.1 inetd is handled after 4.3.4 (it depends on the inetd services)
rctcp_off 4.3.2.2  /usr/sbin/dhcpcd   dhcpcd
rctcp_off 4.3.2.3  /usr/sbin/dhcprd   dhcprd
rctcp_off 4.3.2.4  /usr/sbin/dhcpsd   dhcpsd
rctcp_off 4.3.2.5  /usr/sbin/gated    gated
rctcp_off 4.3.2.6  /usr/sbin/hostmibd hostmibd
rctcp_off 4.3.2.7  /usr/sbin/mrouted  mrouted
rctcp_off 4.3.2.8  /usr/sbin/named    named

portmap_off() {
    awk '/^[ \t]*start[ \t]+\/usr\/sbin\/portmap/ { print "#" $0; next } { print }'
}
if in_scope 4.3.2.9; then
    if ! rc_active /usr/sbin/portmap && ! svc_active portmap; then
        ok 4.3.2.9 "portmap not started and not running"
    else
        others=$(rpcinfo -p localhost 2> /dev/null | egrep -v '(program)|(portmap)|(status)|(nsm)|(pyramid)' | wc -l | tr -d ' ')
        if (( others > 0 && ! RISKY )); then
            skipped 4.3.2.9 "$others other RPC service(s) are registered - portmap kept (stop them first)"
        else
            rc_active /usr/sbin/portmap && do_change 4.3.2.9 "comment out the portmap start in /etc/rc.tcpip" file_filter /etc/rc.tcpip portmap_off
            svc_active portmap && do_change 4.3.2.9 "stopsrc -s portmap" stopsrc -s portmap
        fi
    fi
fi

rctcp_off 4.3.2.10 /usr/sbin/routed   routed
rctcp_off 4.3.2.11 /usr/sbin/rwhod    rwhod
rctcp_off 4.3.2.12 /usr/lib/sendmail  sendmail sendmail
rctcp_off 4.3.2.13 /usr/sbin/timed    timed

# ===========================================================================
# 4.3.3 IPv6
# ===========================================================================
hdr "4.3.3 Configure IPv6"

ipv6_in_use() { ifconfig -a 2> /dev/null | awk '/inet6/ && $2 !~ /^::1/ && tolower($2) !~ /^fe80/ { f = 1 } END { exit !f }'; }
for _p in "4.3.3.1:/usr/sbin/autoconf6:autoconf6" "4.3.3.2:/usr/sbin/ndpd-host:ndpd-host" "4.3.3.3:/usr/sbin/ndpd-router:ndpd-router"; do
    _r=${_p%%:*}
    _rest=${_p#*:}
    _path=${_rest%%:*}
    _nm=${_rest##*:}
    in_scope "$_r" || continue
    if ! rc_active "$_path" && ! svc_active "$_nm"; then
        ok "$_r" "$_nm not started and not running"
    elif ipv6_in_use && (( ! RISKY )); then
        skipped "$_r" "global IPv6 addresses are configured - $_nm kept (re-run with -x)"
    else
        rc_active "$_path" && do_change "$_r" "chrctcp -d $_nm" chrctcp -d "$_nm"
        svc_active "$_nm" && do_change "$_r" "stopsrc -s $_nm" stopsrc -s "$_nm"
    fi
done

# ===========================================================================
# 4.3.4 inetd services
# ===========================================================================
hdr "4.3.4 Services managed by inetd"

INETD_CHANGED=0
inetd_active() {   # inetd_active <service> <proto>
    grep -v '^[[:space:]]*#' /etc/inetd.conf 2> /dev/null | awk -v s="$1" -v p="$2" '$1 == s && $3 == p { f = 1 } END { exit !f }'
}
inetd_off() { chsubserver -r inetd -C /etc/inetd.conf -d -v "$1" -p "$2"; }

# inetd_rule <rule> <remote:0|1> <service> <proto> [<service> <proto> ...]
inetd_rule() {
    typeset rid=$1 remote=$2 svc proto any=0
    shift 2
    in_scope "$rid" || return 0
    while (( $# >= 2 )); do
        svc=$1 proto=$2
        shift 2
        inetd_active "$svc" "$proto" || continue
        any=1
        if (( remote )) && ! remote_ok "$rid" "$svc"; then continue; fi
        backup_file /etc/inetd.conf
        do_change "$rid" "chsubserver -d $svc/$proto (inetd.conf backed up)" inetd_off "$svc" "$proto" && INETD_CHANGED=1
    done
    (( any )) || ok "$rid" "no active inetd entry"
}

inetd_rule 4.3.4.1  0 bootps udp
inetd_rule 4.3.4.2  0 chargen udp
inetd_rule 4.3.4.3  0 comsat udp
inetd_rule 4.3.4.4  0 daytime tcp daytime udp
inetd_rule 4.3.4.5  0 discard udp
inetd_rule 4.3.4.6  0 echo tcp echo udp
inetd_rule 4.3.4.7  1 exec tcp6
inetd_rule 4.3.4.8  0 finger tcp
inetd_rule 4.3.4.9  1 ftp tcp6
inetd_rule 4.3.4.10 0 imap2 tcp
inetd_rule 4.3.4.11 0 instsrv tcp
inetd_rule 4.3.4.12 1 klogin tcp
inetd_rule 4.3.4.13 1 kshell tcp
inetd_rule 4.3.4.14 0 netstat tcp
inetd_rule 4.3.4.15 0 ntalk udp
inetd_rule 4.3.4.16 0 pcnfsd udp
inetd_rule 4.3.4.17 0 pop3 tcp
inetd_rule 4.3.4.18 0 rexd tcp
inetd_rule 4.3.4.19 1 login tcp6
inetd_rule 4.3.4.20 0 rquotad udp
inetd_rule 4.3.4.21 0 rstatd udp
inetd_rule 4.3.4.22 0 rsync tcp
inetd_rule 4.3.4.23 0 rusersd udp
inetd_rule 4.3.4.24 0 rwalld udp
inetd_rule 4.3.4.25 1 shell tcp6
inetd_rule 4.3.4.26 0 sprayd udp
inetd_rule 4.3.4.27 0 talk udp
inetd_rule 4.3.4.28 1 telnet tcp6
inetd_rule 4.3.4.29 0 tftp udp6
inetd_rule 4.3.4.30 0 time tcp time udp
inetd_rule 4.3.4.31 0 uucp tcp
inetd_rule 4.3.4.32 0 xmquery udp

if (( INETD_CHANGED )) && svc_active inetd; then
    do_change 4.3.4 "refresh -s inetd" refresh -s inetd
fi

# 4.3.2.1: inetd itself, only when no service is left in inetd.conf
if in_scope 4.3.2.1; then
    left=$(grep -v '^[[:space:]]*#' /etc/inetd.conf 2> /dev/null | grep -vc '^[[:space:]]*$')
    if ! rc_active /usr/sbin/inetd && ! svc_active inetd; then
        ok 4.3.2.1 "inetd not started and not running"
    elif (( left > 0 && ! RISKY )); then
        skipped 4.3.2.1 "$left service(s) remain active in /etc/inetd.conf - inetd kept (protect them with TCP wrappers or disable them)"
    else
        rc_active /usr/sbin/inetd && do_change 4.3.2.1 "chrctcp -d inetd" chrctcp -d inetd
        svc_active inetd && do_change 4.3.2.1 "stopsrc -s inetd" stopsrc -s inetd
    fi
fi

# ===========================================================================
# 4.4 Filesystem configuration
# ===========================================================================
hdr "4.4 Filesystem Configuration"

in_scope 4.4.1.1 && manual 4.4.1.1 "remove NFS client mounts (rmnfsmnt -f <mountpoint>), then stopsrc -g nfs"
in_scope 4.4.1.2 && manual 4.4.1.2 "remove exports from /etc/exports and installp -u bos.net.nfs.server if NFS server is not needed"
in_scope 4.4.1.3 && manual 4.4.1.3 "chnfsmnt -d <remote> -f <mountpoint> -h <server> -y -z   (nosuid,nodev for every NFS mount)"
in_scope 4.4.1.4 && manual 4.4.1.4 "remove localhost / localhost aliases from the access lists in /etc/exports, then exportfs -a"
in_scope 4.4.1.5 && manual 4.4.1.5 "give every export an explicit client list: chnfsexp -d <fs> -c <client1>:<client2>"
in_scope 4.4.1.6 && manual 4.4.1.6 "chnfsexp -d <fs> -a -2 for exports with an explicit anon= (root access decision per export)"
in_scope 4.4.1.7 && manual 4.4.1.7 "chnfsexp -d <fs> -S <sys|dh|krb5|krb5i|krb5p> (never none)"
in_scope 4.4.2.1 && manual 4.4.2.1 "install clic.rte from the AIX expansion pack, then efsenable -a"

nodev_fix() {   # nodev_fix <mountpoint> <existing-options>
    typeset mp=$1 opts=$2 new
    if [[ -z $opts || $opts == - ]]; then new=nodev; else new="$opts,nodev"; fi
    chfs -a options="$new" "$mp"
}
if in_scope 4.4.3.1; then
    n=0
    lsfs 2> /dev/null | awk 'NR > 1 && $4 ~ /^jfs/ && $3 != "/" { print $3, $6 }' | while read -r mp opts; do
        [[ $opts == *nodev* ]] && continue
        [[ $mp == - ]] && continue
        [[ $opts == "-" || $opts == "yes" || $opts == "no" || $opts == "--" ]] && opts=""
        undo_note "# 4.4.3.1: options of $mp were '$opts' (chfs -a options=<old> $mp)"
        do_change 4.4.3.1 "add nodev to the options of $mp (persistent, effective at next mount)" nodev_fix "$mp" "$opts"
        ((n=n + 1))
        if mount 2> /dev/null | awk -v m="$mp" '$2 == m { f = 1 } END { exit !f }'; then
            if (( RISKY )); then
                do_change 4.4.3.1 "mount -o remount,nodev $mp" mount -o remount,nodev "$mp"
            else
                info 4.4.3.1 "$mp is mounted without nodev until remount (use -x or: mount -o remount,nodev $mp)"
            fi
        fi
    done
    (( n )) || ok 4.4.3.1 "all jfs/jfs2 file systems except / already have nodev"
fi

# ===========================================================================
# 4.5 Network options
# ===========================================================================
hdr "4.5 Configure Network Options"

net_set 4.5.1  no sockthresh          60
net_set 4.5.2  no bcastping           0
net_set 4.5.3  no clean_partial_conns 1
net_set 4.5.4  no directed_broadcast  0
net_set 4.5.5  no icmpaddressmask     0
net_set 4.5.6  no ipforwarding        0 "this host may be a router / VIOS / gateway"
net_set 4.5.7  no ip6forwarding       0 "this host may be a router"
net_set 4.5.8  no ipignoreredirects   1
net_set 4.5.9  no ipsendredirects     0
net_set 4.5.10 no ipsrcrouteforward   0
net_set 4.5.11 no ipsrcrouterecv      0
net_set 4.5.12 no ipsrcroutesend      0
net_set 4.5.13 no ip6srcrouteforward  0
net_set 4.5.14 nfso portcheck              1
net_set 4.5.14 nfso nfs_use_reserved_ports 1
net_set 4.5.15 no nonlocsrcroute      0
net_set 4.5.16 no tcp_pmtu_discover   0
net_set 4.5.17 no tcp_tcpsecure       7
net_set 4.5.18 no udp_pmtu_discover   0
net_set 4.5.19 no icmptimestamp       0

# ===========================================================================
# 4.6.1 CDE
# ===========================================================================
hdr "4.6.1 Common Desktop Environment"

if fs_installed X11.Dt.rte || fs_installed X11.Dt.lib; then
    in_scope 4.6.1.1 && manual 4.6.1.1 "CDE is installed: installp -ug X11.Dt.* (preview with installp -up) if no graphical console is needed"

    if in_scope 4.6.1.2; then
        if inetd_active cmsd sunrpc_udp; then
            do_change 4.6.1.2 "chsubserver -d cmsd/sunrpc_udp" inetd_off cmsd sunrpc_udp && svc_active inetd && refresh -s inetd > /dev/null 2>&1
        else
            ok 4.6.1.2 "cmsd not active in inetd.conf"
        fi
    fi

    if in_scope 4.6.1.3; then
        if lsitab dt > /dev/null 2>&1 || lsitab dt_nogb > /dev/null 2>&1; then
            if proc_running dtlogin && (( ! RISKY )); then
                skipped 4.6.1.3 "dtlogin is running - not disabled (re-run with -x)"
            else
                do_change 4.6.1.3 "dtconfig -d (disable dtlogin at boot)" /usr/dt/bin/dtconfig -d
                proc_running dtlogin && do_change 4.6.1.3 "dtconfig -kill" /usr/dt/bin/dtconfig -kill
            fi
        else
            ok 4.6.1.3 "dtlogin not started from inittab"
        fi
    fi

    if in_scope 4.6.1.4; then
        if inetd_active dtspc tcp; then
            do_change 4.6.1.4 "chsubserver -d dtspc/tcp" inetd_off dtspc tcp && svc_active inetd && refresh -s inetd > /dev/null 2>&1
        else
            ok 4.6.1.4 "dtspc not active in inetd.conf"
        fi
    fi

    if in_scope 4.6.1.5; then
        _any=0
        for _b in dtaction dtappgather dtprintinfo dtsession; do
            [[ -f /usr/dt/bin/$_b ]] || continue
            m=$(ls -ld "/usr/dt/bin/$_b" | cut -c1-10)
            if [[ ${m:3:1} == [sS] || ${m:6:1} == [sS] ]]; then
                _any=1
                undo_note "chmod $(mode_of /usr/dt/bin/$_b) /usr/dt/bin/$_b"
                do_change 4.6.1.5 "chmod ug-s /usr/dt/bin/$_b" chmod ug-s "/usr/dt/bin/$_b"
            fi
        done
        (( _any )) || ok 4.6.1.5 "CDE daemons without suid/sgid"
    fi

    if in_scope 4.6.1.6; then
        if grep -q '^Dtlogin.requestPort:[[:space:]]*0' /etc/dt/config/Xconfig 2> /dev/null; then
            ok 4.6.1.6 "Dtlogin.requestPort: 0"
        else
            cde_port_edit() {
                awk '/^#*[ \t]*Dtlogin.requestPort:/ { if (!d) print "Dtlogin.requestPort:  0"; d = 1; next }
                     { print } END { if (!d) print "Dtlogin.requestPort:  0" }'
            }
            cde_port() {
                mkdir -p /etc/dt/config
                [[ -f /etc/dt/config/Xconfig ]] || cp /usr/dt/config/Xconfig /etc/dt/config/Xconfig || return 1
                file_filter /etc/dt/config/Xconfig cde_port_edit
            }
            do_change 4.6.1.6 "set Dtlogin.requestPort: 0 in /etc/dt/config/Xconfig" cde_port
        fi
    fi
    in_scope 4.6.1.7 && manual 4.6.1.7 "copy /usr/dt/config/*/sys.resources to /etc/dt/config/<lang>/ and set dtsession*saverTimeout: 15 and dtsession*lockTimeout: 15"
    in_scope 4.6.1.8 && manual 4.6.1.8 "copy /usr/dt/config/*/Xresources to /etc/dt/config/<lang>/ and set Dtlogin*greeting.labelString / persLabelString to the site banner"
    fix_perm 4.6.1.9 /etc/dt/config/Xconfig root bin 0755
    in_scope 4.6.1.10 && manual 4.6.1.10 "Dtlogin*servers: /etc/dt/config/Xservers in /etc/dt/config/Xconfig; Xservers root:bin, go-w"
    if in_scope 4.6.1.11; then
        for _x in /etc/dt/config/*/Xresources; do
            [[ -f $_x ]] || continue
            fix_perm 4.6.1.11 "$_x" root sys 0644
        done
    fi
else
    in_scope 4.6.1 && ok 4.6.1 "CDE (X11.Dt) is not installed - rules not applicable"
fi

# ===========================================================================
# 4.6.2 FTPD
# ===========================================================================
hdr "4.6.2 Configure FTPD"

if in_scope 4.6.2.1; then
    if grep -qx root /etc/ftpusers 2> /dev/null; then ok 4.6.2.1 "root listed in /etc/ftpusers"
    else do_change 4.6.2.1 "add root to /etc/ftpusers" file_append /etc/ftpusers root; fi
fi

ftp_umask() { awk '$1 == "ftp" && $0 !~ /-u[ ]*0?27/ { print $0 " -u 027"; next } { print }'; }
if in_scope 4.6.2.2; then
    if inetd_active ftp tcp6 || inetd_active ftp tcp; then
        manual 4.6.2.2 "ftpd is enabled: replace the greeting in ftpd.cat (dspcat/gencat, see benchmark) - or disable ftp (4.3.4.9)"
    else
        ok 4.6.2.2 "ftpd not enabled in inetd.conf - not applicable"
    fi
fi
if in_scope 4.6.2.3; then
    if inetd_active ftp tcp6 || inetd_active ftp tcp; then
        if grep -v '^[[:space:]]*#' /etc/inetd.conf | grep '^ftp[[:blank:]]' | grep -q -- '-u[ ]*0\{0,1\}27'; then
            ok 4.6.2.3 "ftpd umask 027"
        else
            do_change 4.6.2.3 "add -u 027 to the ftp entry of /etc/inetd.conf" file_filter /etc/inetd.conf ftp_umask
            svc_active inetd && refresh -s inetd > /dev/null 2>&1
        fi
    else
        ok 4.6.2.3 "ftpd not enabled in inetd.conf - not applicable"
    fi
fi

# ===========================================================================
# 4.6.3 OpenSSH
# ===========================================================================
hdr "4.6.3 Configure OpenSSH"

SSHD_CFG=/etc/ssh/sshd_config

# value of KEY before the first Match block (first occurrence wins in sshd)
sshd_get() {
    awk -v k="$1" '
        BEGIN { lk = tolower(k) }
        { t = $0; sub(/^[ \t]+/, "", t) }
        tolower(t) ~ /^match[ \t]/ { exit }
        t ~ /^#/ || t == "" { next }
        { n = split(t, a, /[ \t=]+/); if (tolower(a[1]) == lk) { sub(/^[^ \t=]+[ \t=]+/, "", t); sub(/[ \t]+$/, "", t); gsub(/"/, "", t); print t; exit } }' "$SSHD_CFG" 2> /dev/null
}

# set KEY VALUE above any Match block, replacing the existing line(s)
sshd_edit() {
    awk -v k="$KEY" -v v="$VAL" '
        BEGIN { lk = tolower(k); done = 0; inmatch = 0 }
        { t = $0; sub(/^[ \t]+/, "", t) }
        !inmatch && tolower(t) ~ /^match[ \t]/ { if (!done) { print k " " v; done = 1 } inmatch = 1; print; next }
        !inmatch && t !~ /^#/ && t != "" { split(t, a, /[ \t=]+/); if (tolower(a[1]) == lk) { if (!done) { print k " " v; done = 1 } next } }
        { print }
        END { if (!done) print k " " v }'
}
sshd_apply() { KEY=$1 VAL=$2 file_filter "$SSHD_CFG" sshd_edit; }

# sshd_rule <rule> <key> <value> [risky-reason]
sshd_rule() {
    typeset rid=$1 key=$2 val=$3 why=$4 cur
    in_scope "$rid" || return 0
    cur=$(sshd_get "$key")
    if [[ $(print -r -- "$cur" | tr 'A-Z' 'a-z') == "$(print -r -- "$val" | tr 'A-Z' 'a-z')" ]]; then
        ok "$rid" "sshd_config: $key $cur"
        return 0
    fi
    if [[ -n $why ]]; then
        risky_ok "$rid" "$why" || return 0
    fi
    undo_note "# $rid: sshd_config $key was '$cur' (original file: $BACKUP_DIR/files$SSHD_CFG)"
    do_change "$rid" "sshd_config: $key $val (was '${cur:-unset}')" sshd_apply "$key" "$val" && SSHD_CHANGED=1
}

sftp_edit() {
    awk -v want="-u 027 -f AUTH -l INFO" '
        { t = $0; sub(/^[ \t]+/, "", t) }
        tolower(t) ~ /^subsystem[ \t]+sftp[ \t]/ && !seen { split(t, a, /[ \t]+/); print "Subsystem sftp " a[3] " " want; seen = 1; next }
        { print }
        END { if (!seen) print "Subsystem sftp /usr/sbin/sftp-server " want }'
}

ssh_ver() { ssh -V 2>&1 | sed -n 's/^OpenSSH_\([0-9]*\)\.\([0-9]*\).*/\1 \2/p'; }

if [[ -f $SSHD_CFG ]]; then
    in_scope 4.6.3.1 && manual 4.6.3.1 "OpenSSH $(ssh_ver | tr ' ' .) installed; the benchmark requires 9.x - install the current OpenSSH from the AIX Web Download Pack"

    if in_scope 4.6.3.2; then
        for _f in /etc/shosts.equiv /etc/rhosts.equiv; do
            if [[ -f $_f ]]; then do_change 4.6.3.2 "move $_f to the backup directory" move_to_backup "$_f"
            else ok 4.6.3.2 "$_f does not exist"; fi
        done
    fi

    if in_scope 4.6.3.3; then
        cur=$(grep -i '^[[:space:]]*Subsystem[[:space:]]\{1,\}sftp' "$SSHD_CFG" | head -1)
        if print -r -- "$cur" | grep -Eq -- '-u[ ]*0?27.*-f[ ]*AUTH.*-l[ ]*(INFO|VERBOSE)\s*$|-u[ ]*0?27.*-f[ ]*AUTH.*-l[ ]*(INFO|VERBOSE)[[:space:]]*$'; then
            ok 4.6.3.3 "sftp subsystem: $cur"
        else
            do_change 4.6.3.3 "set 'Subsystem sftp ... -u 027 -f AUTH -l INFO'" file_filter "$SSHD_CFG" sftp_edit && SSHD_CHANGED=1
        fi
    fi

    in_scope 4.6.3.4 && manual 4.6.3.4 "add AllowUsers/AllowGroups/DenyUsers/DenyGroups (site policy) above any Match block - a wrong list locks users out"

    if in_scope 4.6.3.5; then
        if [[ ! -s /etc/ssh/ssh_banner ]]; then
            do_change 4.6.3.5 "create /etc/ssh/ssh_banner with a generic notice (adapt to site policy)" file_append /etc/ssh/ssh_banner \
                "Authorized uses only. All activity may be monitored and reported."
            do_change 4.6.3.5 "chown root:system, chmod 644 /etc/ssh/ssh_banner" sh -c 'chown root:system /etc/ssh/ssh_banner && chmod 644 /etc/ssh/ssh_banner'
        fi
        sshd_rule 4.6.3.5 Banner /etc/ssh/ssh_banner
    fi

    if in_scope 4.6.3.6 || in_scope 4.6.3.9 || in_scope 4.6.3.11; then
        # shellcheck disable=SC2046
        set -- $(ssh_ver)
        if [[ -n $1 ]] && (( $1 > 7 || ($1 == 7 && $2 >= 5) )); then
            sshd_rule 4.6.3.6  Ciphers "-3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com"
            sshd_rule 4.6.3.9  KexAlgorithms "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"
            sshd_rule 4.6.3.11 MACs "-hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com"
        else
            manual 4.6.3.6 "OpenSSH older than 7.5 (or unknown): set Ciphers / KexAlgorithms (4.6.3.9) / MACs (4.6.3.11) explicitly after upgrading (4.6.3.1)"
        fi
    fi

    sshd_rule 4.6.3.7  HostbasedAuthentication no
    sshd_rule 4.6.3.8  IgnoreRhosts yes
    sshd_rule 4.6.3.10 LogLevel INFO
    sshd_rule 4.6.3.12 MaxAuthTries 4
    sshd_rule 4.6.3.13 PermitEmptyPasswords no

    if in_scope 4.6.3.14; then
        cur=$(sshd_get PermitRootLogin)
        if [[ $cur == @(prohibit-password|no|forced-commands-only) ]]; then
            ok 4.6.3.14 "PermitRootLogin $cur"
        elif [[ -s ~root/.ssh/authorized_keys ]] || (( RISKY )); then
            sshd_rule 4.6.3.14 PermitRootLogin prohibit-password
        else
            skipped 4.6.3.14 "root has no ~/.ssh/authorized_keys - 'prohibit-password' could lock out remote root (install a key, or use -x)"
        fi
    fi
    if in_scope 4.6.3.15; then
        sshd_rule 4.6.3.15 PermitRootLogin no "disables all remote root logins; make sure an administrator account with su/sudo works"
    fi
    sshd_rule 4.6.3.16 PermitUserEnvironment no
    sshd_rule 4.6.3.17 RekeyLimit "1G 3600"
    if in_scope 4.6.3.18; then
        sshd_rule 4.6.3.18 ClientAliveInterval 15
        sshd_rule 4.6.3.18 ClientAliveCountMax 3
    fi

    if (( SSHD_CHANGED && ! DRYRUN )); then
        if sshd -t -f "$SSHD_CFG" > /dev/null 2>&1; then
            ok 4.6.3 "sshd -t accepts the new configuration"
            if sshd_usable; then
                if [[ -s /var/run/sshd.pid ]]; then
                    do_change 4.6.3 "reload sshd (SIGHUP, existing sessions stay up)" kill -HUP "$(cat /var/run/sshd.pid)"
                else
                    do_change 4.6.3 "restart sshd" sh -c 'stopsrc -s sshd; sleep 1; startsrc -s sshd'
                fi
            fi
        else
            failed 4.6.3 "sshd -t REJECTED the new configuration - restoring $BACKUP_DIR/files$SSHD_CFG"
            cp -p "$BACKUP_DIR/files$SSHD_CFG" "$SSHD_CFG" && say "  [ROLLBACK] sshd_config restored"
        fi
    fi
else
    in_scope 4.6.3 && info 4.6.3 "$SSHD_CFG not found - OpenSSH rules not applicable"
fi

# ===========================================================================
# 4.6.4 Sendmail  (only when sendmail is installed; missing files are fine)
# ===========================================================================
hdr "4.6.4 Configure Sendmail"

sm_cf=/etc/mail/sendmail.cf
sm_opt_edit() {   # KEY and VAL from the environment: replace or append an "O" option line
    awk -v k="$KEY" -v v="$VAL" '
        $0 ~ ("^O " k "=") { if (!done) { print "O " k "=" v; done = 1 } next }
        { print }
        END { if (!done) print "O " k "=" v }'
}
sm_set() { KEY=$1 VAL=$2 file_filter "$sm_cf" sm_opt_edit; }

if fs_installed bos.net.tcp.sendmail; then
    SM_CHANGED=0
    if [[ -f $sm_cf ]]; then
        if in_scope 4.6.4.1; then
            cur=$(grep -i '^O SmtpGreetingMessage' "$sm_cf" | head -1)
            if [[ -n $cur && $cur != *'$b'* && $cur != *'$j Sendmail'* ]]; then
                ok 4.6.4.1 "$cur"
            else
                do_change 4.6.4.1 "O SmtpGreetingMessage=mailerready" sm_set SmtpGreetingMessage mailerready && SM_CHANGED=1
            fi
            if [[ -e /etc/mail/helpfile ]]; then ok 4.6.4.1 "/etc/mail/helpfile exists"
            else do_change 4.6.4.1 "create /etc/mail/helpfile" touch /etc/mail/helpfile; fi
        fi
        if in_scope 4.6.4.2; then
            cur=$(grep -i '^O PrivacyOptions' "$sm_cf" | head -1 | tr 'A-Z' 'a-z')
            if [[ $cur == *authwarnings* && $cur == *novrfy* && $cur == *noexpn* ]]; then
                ok 4.6.4.2 "PrivacyOptions: $cur"
            else
                do_change 4.6.4.2 "O PrivacyOptions=authwarnings noexpn novrfy" sm_set PrivacyOptions "authwarnings noexpn novrfy" && SM_CHANGED=1
            fi
        fi
        if (( SM_CHANGED && ! DRYRUN )) && svc_active sendmail; then
            do_change 4.6.4 "refresh -s sendmail" refresh -s sendmail
        fi
    else
        in_scope 4.6.4 && ok 4.6.4.1 "$sm_cf does not exist - nothing to check (4.6.4.1 - 4.6.4.3)"
    fi
    fix_perm 4.6.4.3 /etc/mail/sendmail.cf root system 0640
    fix_perm 4.6.4.4 /var/spool/clientmqueue smmsp smmsp 0770
    fix_perm 4.6.4.5 /var/spool/mqueue root - 0700
else
    in_scope 4.6.4 && ok 4.6.4 "sendmail (bos.net.tcp.sendmail) is not installed - rules not applicable"
fi

# ===========================================================================
# 4.7 Login controls
# ===========================================================================
hdr "4.7 Configure Login Controls"

HERALD="Authorized users only. All activity may be monitored and reported.\\nlogin: "
if in_scope 4.7.1; then
    cur=$(sec_get /etc/security/login.cfg default herald)
    if [[ -n $cur ]]; then
        ok 4.7.1 "herald already set (check the text against site policy)"
    else
        do_change 4.7.1 "set a generic herald (adapt to site policy)" chsec -f /etc/security/login.cfg -s default -a "herald=$HERALD"
    fi
fi
sec_num 4.7.2 /etc/security/login.cfg default logindelay    10 99999 10
sec_num 4.7.3 /etc/security/user      default loginretries   5     5  5
sec_num 4.7.4 /etc/security/login.cfg usw     logintimeout   1    30 30

tmout_edit() {   # VAR from environment; replaces [readonly|export] VAR=n by VAR=900
    awk -v v="$VAR" '
        $0 ~ ("^[ \t]*((readonly|export)[ \t]+)?" v "=") { if (!done) { print v "=900"; done = 1 } next }
        { print }
        END { if (!done) print v "=900" }'
}
tmout_apply() { VAR=$1 file_filter /etc/profile tmout_edit; }
tmout_export() {
    grep -v '^export TMOUT TIMEOUT' /etc/profile > "$WORK/profile.noexp" &&
    print 'export TMOUT TIMEOUT' >> "$WORK/profile.noexp" &&
    file_filter /etc/profile cat "$WORK/profile.noexp"
}
tmout_ro() { file_append /etc/profile "readonly $1"; }
tmout_fix() {   # tmout_fix <rule> <readonly:0|1>
    typeset rid=$1 ro=$2 v changed=0
    for v in TMOUT TIMEOUT; do
        # a value of 1-900 is already compliant (also when written as readonly/export VAR=n)
        grep -Eq "^[[:space:]]*((readonly|export)[[:space:]]+)?$v=\"?([1-9]|[1-9][0-9]|[1-8][0-9][0-9]|900)\"?[[:space:]]*(#.*)?\$" /etc/profile 2> /dev/null && continue
        do_change "$rid" "set $v=900 in /etc/profile" tmout_apply "$v"
        changed=1
    done
    if (( ro )); then
        for v in TMOUT TIMEOUT; do
            grep -Eq "^[[:space:]]*readonly[[:space:]]+(.*[[:space:]])?$v([[:space:]=]|\$)" /etc/profile 2> /dev/null && continue
            do_change "$rid" "readonly $v in /etc/profile" tmout_ro "$v"
            changed=1
        done
    fi
    if (( ! changed )) && [[ $(tail -1 /etc/profile 2> /dev/null) == "export TMOUT TIMEOUT" ]]; then
        ok "$rid" "TMOUT/TIMEOUT configured in /etc/profile"
        return 0
    fi
    do_change "$rid" "put 'export TMOUT TIMEOUT' at the end of /etc/profile" tmout_export
}
if in_scope 4.7.5; then tmout_fix 4.7.5 0; fi
if in_scope 4.7.6; then tmout_fix 4.7.6 1; fi

# ===========================================================================
# 4.8 Installation settings
# ===========================================================================
hdr "4.8 Verify Integrity of Installation Settings"

if in_scope 4.8.1; then
    l=$(lsuser -a login root 2> /dev/null | sed 's/.*login=//')
    r=$(lsuser -a rlogin root 2> /dev/null | sed 's/.*rlogin=//')
    s=$(lsuser -a sugroups root 2> /dev/null | sed 's/.*sugroups=//')
    if [[ $l == false && $r == false && -n $s && $s != ALL ]]; then
        ok 4.8.1 "root: login=false rlogin=false sugroups=$s"
    elif risky_ok 4.8.1 "login=false stops direct root logins and sugroups limits who may su: you could lose root access"; then
        members=$(lsgroup -a users SUADMIN 2> /dev/null | sed 's/.*users=//')
        if [[ -z $members ]]; then
            failed 4.8.1 "group SUADMIN has no members - refusing to change root (add an administrator: chgroup users=<admin> SUADMIN)"
            lsgroup SUADMIN > /dev/null 2>&1 || do_change 4.8.1 "create group SUADMIN" mkgroup -a SUADMIN
        else
            undo_note "chuser login=$l rlogin=$r sugroups=$s root"
            do_change 4.8.1 "chuser login=false rlogin=false sugroups=SUADMIN root (members: $members)" chuser login=false rlogin=false sugroups=SUADMIN root
        fi
    fi
fi

if in_scope 4.8.2; then
    cur=$(lsuser -a shell root 2> /dev/null | sed 's/.*shell=//')
    if [[ $cur == /usr/bin/ksh ]]; then ok 4.8.2 "root shell /usr/bin/ksh"
    else undo_note "chuser shell=$cur root"; do_change 4.8.2 "root shell /usr/bin/ksh (was $cur)" chuser shell=/usr/bin/ksh root; fi
fi

if in_scope 4.8.3; then
    sec_num 4.8.3 /etc/security/limits default core 0 0 0
    sec_num 4.8.3 /etc/security/limits default core_hard 0 0 0
    cur=$(lsattr -El sys0 -a fullcore 2> /dev/null | awk '{ print $2 }')
    if [[ $cur == false ]]; then ok 4.8.3 "fullcore=false"
    else undo_note "chdev -l sys0 -a fullcore=$cur"; do_change 4.8.3 "chdev -l sys0 -a fullcore=false" chdev -l sys0 -a fullcore=false; fi
fi

in_scope 4.8.4 && manual 4.8.4 "remove '.' and empty entries from PATH= in /etc/environment (check: grep '^PATH=' /etc/environment)"
in_scope 4.8.5 && manual 4.8.5 "remove '.' / '::' from root's PATH in /etc/environment, /etc/profile, /.profile (check: su - root -c 'echo \$PATH')"

if in_scope 4.8.6; then
    [[ -e /etc/motd ]] || do_change 4.8.6 "create /etc/motd" touch /etc/motd
    if [[ ! -s /etc/motd ]]; then
        do_change 4.8.6 "write a generic notice to /etc/motd (adapt to site policy)" file_append /etc/motd \
            "Authorized uses only. All activity may be monitored and reported."
    else
        ok 4.8.6 "/etc/motd has content (check the text against site policy)"
    fi
fi

# ===========================================================================
# 4.9 Memory options
# ===========================================================================
hdr "4.9 Configure Memory Options"

# vmo asks "Are you sure? (y/n)" for restricted tunables (aslr32r, aslr64r, aslr_r); the
# output of do_change is captured, so the prompt would be invisible and the script would hang.
aslr_apply() { print y | vmo -r -o aslr=2 -o aslr32=0 -o aslr32r=333 -o aslr64=0 -o aslr64r=33333 -o aslr_r=0; }
if in_scope 4.9.1; then
    bad=0
    for _kv in aslr=2 aslr32=0 aslr64=0 aslr32r=333 aslr64r=33333 aslr_r=0; do
        k=${_kv%%=*}
        w=${_kv##*=}
        c=$(vmo -r -o "$k" 2> /dev/null | awk '{ print $3 }')
        [[ -z $c ]] && c=$(vmo -aF 2> /dev/null | awk -v k="$k" '$1 == k { print $3 }')
        [[ $c == "$w" ]] || bad=1
    done
    if (( bad )); then
        do_change 4.9.1 "vmo -r aslr settings (take effect after the next reboot)" aslr_apply && REBOOT_NEEDED=1
    else
        ok 4.9.1 "ASLR settings correct"
    fi
fi

# ===========================================================================
# 5 Account management
# ===========================================================================
hdr "5 Account Management"

if in_scope 5.1.1; then
    empty=$(egrep -p 'password = +$' /etc/security/passwd 2> /dev/null | grep ':' | awk -F: '{ print $1 }')
    if [[ -z $empty ]]; then
        ok 5.1.1 "no account with an empty password"
    elif risky_ok 5.1.1 "locking an account that is used without password (service / batch accounts)"; then
        lock_empty() { chuser account_locked=true expires=0101000070 "$1" && print "$1:*" | chpasswd -e -f ADMCHG; }
        for u in $empty; do
            undo_note "# 5.1.1: $u had an empty password - unlock: chuser account_locked=false expires=0 $u"
            do_change 5.1.1 "lock account $u (empty password)" lock_empty "$u"
        done
    fi
fi
in_scope 5.1.2 && manual 5.1.2 "duplicate user names / UIDs: check 'cut -d: -f3 /etc/passwd | sort -n | uniq -d' and fix after checking file ownership"
in_scope 5.1.3 && manual 5.1.3 "duplicate group names / GIDs: check /etc/group and fix after checking file ownership"
in_scope 5.1.4 && manual 5.1.4 "maintain an approved inventory of administrator accounts (lsuser -R files -a admin ALL | grep admin=true)"
in_scope 5.1.5 && manual 5.1.5 "maintain an approved inventory of regular accounts (lsuser -R files -a admin ALL | grep admin=false)"
in_scope 5.1.6 && manual 5.1.6 "run 'pwdck -n ALL' and fix the reported stanzas (pwdck -y ALL repairs automatically and may delete entries)"

U=/etc/security/user
sec_num 5.2.1  $U default histsize        0     0     0
sec_num 5.2.2  $U default minage          1 99999     1
sec_num 5.2.3  $U default histexpire     52 99999    52
in_scope 5.2.4 && manual 5.2.4 "accounts with the NOCHECK flag: pwdadm -c <user>; pwdadm -f ADMCHG <user> (forces a password change)"
sec_num 5.2.5  $U default maxexpired      4     4     4 "an account whose password is older than maxage+maxexpired weeks is locked at the next login"
sec_num 5.2.6  $U default maxage          1    52    52 "every password older than 52 weeks expires at once; users and batch accounts may be locked out"

if in_scope 5.2.7; then
    cur=$(sec_get /etc/security/login.cfg usw pwd_algorithm)
    if [[ $cur == ssha512 ]]; then
        ok 5.2.7 "pwd_algorithm=ssha512"
    else
        undo_note "chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=$cur"
        do_change 5.2.7 "pwd_algorithm=ssha512 (was '$cur'; existing hashes stay valid, new passwords use ssha512)" chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=ssha512
    fi
fi
in_scope 5.2.8 && manual 5.2.8 "accounts still using the 13-character crypt hash must get a new password: pwdadm -c <user>; pwdadm -f ADMCHG <user>"

# minlen 14 is only valid with a long hash algorithm (ssha512), never before 5.2.7
if in_scope 5.2.9; then
    if [[ $(sec_get /etc/security/login.cfg usw pwd_algorithm) == ssha512 ]] || (( DRYRUN )); then
        sec_num 5.2.9 $U default minlen 14 99999 14
    else
        skipped 5.2.9 "pwd_algorithm is not ssha512 - minlen 14 would make password changes fail"
    fi
fi
sec_num 5.2.10 $U default mindiff         6 99999     6
sec_num 5.2.11 $U default minalpha        3 99999     3
sec_num 5.2.12 $U default minother        3 99999     3
sec_num 5.2.13 $U default maxrepeats      1     4     4
sec_num 5.2.14 $U default mindigit        1 99999     1
sec_num 5.2.15 $U default minloweralpha   1 99999     1
sec_num 5.2.16 $U default minupperalpha   1 99999     1
sec_num 5.2.17 $U default minspecialchar  1 99999     1

lock_sys() { chuser account_locked=true login=false rlogin=false "$1"; }
_n=0
for _u in adm bin daemon guest lpd nobody nuucp sys uucp; do
    ((_n=_n + 1))
    in_scope "5.3.$_n" || continue
    if ! user_exists "$_u"; then
        ok "5.3.$_n" "user $_u does not exist"
        continue
    fi
    a=$(lsuser -a account_locked login rlogin "$_u" 2> /dev/null)
    if [[ $a == *account_locked=true* && $a == *login=false* && $a == *rlogin=false* ]]; then
        ok "5.3.$_n" "$_u locked, no login"
    else
        undo_note "chuser $(print -r -- "$a" | sed 's/^[^ ]* //') $_u"
        do_change "5.3.$_n" "lock $_u (account_locked=true login=false rlogin=false)" lock_sys "$_u"
    fi
done

if in_scope 5.3.10; then
    n=0
    lsuser -c -a id ALL 2> /dev/null | grep -v '^#' | while IFS=: read -r u uid; do
        [[ $uid == +([0-9]) ]] && (( uid < 200 )) || continue
        grep -qx "$u" /etc/ftpusers 2> /dev/null && continue
        ((n=n + 1))
        do_change 5.3.10 "add $u (uid $uid) to /etc/ftpusers" file_append /etc/ftpusers "$u"
    done
    (( n )) || ok 5.3.10 "/etc/ftpusers lists all accounts with uid < 200"
fi

# ===========================================================================
# 6 Access control
# ===========================================================================
hdr "6 Access Control Management"

in_scope 6.1.1 && {
    if command -v sudo > /dev/null 2>&1; then info 6.1.1 "sudo present: $(sudo --version 2> /dev/null | head -1) (benchmark: 1.9.17p1 or later - update from the AIX Toolbox)"
    else manual 6.1.1 "sudo is not installed - install 1.9.17p1 or later from the AIX Toolbox"; fi
}

SUDOERS=""
for _s in /etc/sudoers /opt/freeware/etc/sudoers; do [[ -f $_s ]] && { SUDOERS=$_s; break; }; done

if in_scope 6.1.2; then
    if [[ -z $SUDOERS ]]; then
        ok 6.1.2 "no sudoers file - not applicable"
    elif grep -Eqi '^[[:space:]]*Defaults[[:space:]]+syslog_(bad|good)pri=none' $SUDOERS $SUDOERS.d/* 2> /dev/null; then
        manual 6.1.2 "remove 'Defaults syslog_badpri=none' / 'syslog_goodpri=none' with visudo (or add Defaults logfile=)"
    else
        ok 6.1.2 "sudo logging is not disabled"
    fi
fi

sudo_pty_dropin() {
    typeset f="$SUDOERS.d/cis_use_pty" t="$WORK/sudoers.cis"
    print 'Defaults use_pty' > "$t"
    visudo -c -f "$t" > /dev/null 2>&1 || return 1
    mkdir -p "$SUDOERS.d" && cp "$t" "$f" && chmod 440 "$f" && chown root:system "$f" 2> /dev/null
    if ! visudo -c > /dev/null 2>&1; then rm -f "$f"; return 1; fi
}
if in_scope 6.1.3; then
    if [[ -z $SUDOERS ]]; then
        ok 6.1.3 "no sudoers file - not applicable"
    elif grep -Eqi '^[[:space:]]*Defaults[[:space:]]+([^#]*[[:space:],])?!use_pty' $SUDOERS $SUDOERS.d/* 2> /dev/null; then
        manual 6.1.3 "remove the '!use_pty' setting with visudo"
    elif grep -Eqi '^[[:space:]]*Defaults[[:space:]]+([^#]*[[:space:],])?use_pty' $SUDOERS $SUDOERS.d/* 2> /dev/null; then
        ok 6.1.3 "Defaults use_pty is set"
    elif grep -Eq '^[#@]includedir' "$SUDOERS" 2> /dev/null; then
        do_change 6.1.3 "add 'Defaults use_pty' as $SUDOERS.d/cis_use_pty (validated with visudo -c)" sudo_pty_dropin
    else
        manual 6.1.3 "add 'Defaults use_pty' with visudo ($SUDOERS has no includedir)"
    fi
fi

# cron / at allow lists: root, adm and every user that already has jobs stay allowed
allow_users() {   # allow_users <spooldir>
    # shellcheck disable=SC2010
    ls "$1" 2> /dev/null | grep -v '[.]' | grep -v '^$'
}
allow_fix() {   # allow_fix <allowfile> <deny> <users...>
    typeset af=$1 df=$2 u
    shift 2
    [[ -f $df ]] && { backup_file "$df"; rm -f "$df"; }
    backup_file "$af"
    [[ -f $af ]] || : > "$af"
    for u in "$@"; do
        grep -qx "$u" "$af" || print -r -- "$u" >> "$af"
    done
    chown root:sys "$af" && chmod 400 "$af"
}
cron_rule() {   # cron_rule <rule> <deny> <allow> <spooldir>
    typeset rid=$1 df=$2 af=$3 sp=$4 u need="" users
    in_scope "$rid" || return 0
    users=$(allow_users "$sp")
    # shellcheck disable=SC2086
    for u in root adm $users; do
        user_exists "$u" || continue
        grep -qx "$u" "$af" 2> /dev/null || need="$need $u"
    done
    if [[ ! -f $df && -z $need && -f $af ]]; then
        ok "$rid" "$af lists the required users, $df absent"
        return 0
    fi
    # shellcheck disable=SC2086
    do_change "$rid" "remove $df (backed up), allow:$need in $af (users with existing jobs are kept)" \
        allow_fix "$af" "$df" root adm $users
}
cron_rule 6.2.1 /var/adm/cron/at.deny   /var/adm/cron/at.allow   /var/spool/cron/atjobs
cron_rule 6.2.2 /var/adm/cron/cron.deny /var/adm/cron/cron.allow /var/spool/cron/crontabs

# ===========================================================================
# 7 Vulnerability management
# ===========================================================================
hdr "7 Continuous Vulnerability Management"
in_scope 7.1 && manual 7.1 "run FLRTVC regularly (cis_collect.ksh -F <flrtvc.ksh>), review the APARs and install fixes from IBM Fix Central"
in_scope 7.2 && manual 7.2 "compare the installed firmware (lsmcode -c) with IBM Fix Central and update per IBM instructions"

# ===========================================================================
# 8 Logging and auditing
# ===========================================================================
hdr "8 Logging and Auditing"

in_scope 8.1.1 && manual 8.1.1 "create the /audit file system (needs a disk / LV), audit config, mkuser.default auditclasses, cronaudit job and inittab entry - see benchmark 8.1.1"
in_scope 8.1.2 && manual 8.1.2 "configure bin auditing in /etc/security/audit/config (binmode=on streammode=off, /audit trail/bin1/bin2, binsize=10240) - needs /audit from 8.1.1"

TE_EVENTS="TE_Untrusted TE_FileWrite TE_Policies TEAdd_Stnz TEDel_Stnz TESwitch_algo TEQuery_Stnz"
audit_te_edit() {   # merge the TE events into class "default" of the classes: stanza
    awk -v ev="$TE_EVENTS" '
        BEGIN { n = split(ev, E, " "); blanks = "" }
        function newdefault(   i, l) { l = "\tdefault = "; for (i = 1; i <= n; i++) l = l E[i] (i < n ? "," : ""); return l }
        /^classes:/ { inc = 1; print; next }
        inc && /^[ \t]*$/ { blanks = blanks $0 "\n"; next }
        inc && /^[a-z_]+:/ { if (!done) { print newdefault(); done = 1 } printf "%s", blanks; blanks = ""; inc = 0; print; next }
        inc && /^[ \t]+default[ \t]*=/ {
            line = $0; sub(/^[ \t]+default[ \t]*=[ \t]*/, "", line); sub(/[ \t]+$/, "", line)
            for (i = 1; i <= n; i++) if (index("," line ",", "," E[i] ",") == 0) line = line (line == "" ? "" : ",") E[i]
            print "\tdefault = " line; done = 1; next }
        inc { printf "%s", blanks; blanks = "" }
        { print }
        END { if (inc && !done) print newdefault(); printf "%s", blanks }'
}
if in_scope 8.1.3; then
    cfg=/etc/security/audit/config
    if [[ ! -f $cfg ]]; then
        manual 8.1.3 "$cfg does not exist - configure auditing (8.1.1) first"
    else
        cur=$(grep -p 'classes:' "$cfg" 2> /dev/null | grep 'default =')
        miss=""
        for e in $TE_EVENTS; do [[ $cur == *$e* ]] || miss="$miss $e"; done
        if [[ -z $miss && -n $cur ]]; then
            ok 8.1.3 "all TE events are in audit class default"
        else
            do_change 8.1.3 "add TE events to audit class default (missing:${miss:- class})" file_filter "$cfg" audit_te_edit
        fi
    fi
fi

if in_scope 8.2.1; then
    mkdir_arch() { mkdir -p /var/log/syslog/archive && chmod 750 /var/log/syslog/archive; }
    [[ -d /var/log/syslog/archive ]] || do_change 8.2.1 "create /var/log/syslog/archive" mkdir_arch
    syslog_rule 8.2.1 auth.info /var/log/syslog/auth.log " archive /var/log/syslog/archive"
    syslog_rule 8.2.1 '*.info;local4.none' /var/log/syslog/info.log " archive /var/log/syslog/archive"
fi
if (( SYSLOG_REFRESH && ! DRYRUN )) && svc_active syslogd; then
    do_change 8 "refresh -s syslogd (new syslog.conf rules)" refresh -s syslogd
fi

remote_syslog() {
    file_append /etc/syslog.conf "$(printf 'auth.info\t@%s' "$1")" &&
    file_append /etc/syslog.conf "$(printf '*.info;auth.none\t@%s' "$1")"
}
if in_scope 8.2.2; then
    if grep -v '^[[:space:]]*#' /etc/syslog.conf 2> /dev/null | grep -q '@'; then
        ok 8.2.2 "remote syslog destination configured"
    elif [[ -n $LOGHOST ]]; then
        do_change 8.2.2 "forward auth.info and *.info to @$LOGHOST" remote_syslog "$LOGHOST" &&
            { svc_active syslogd && do_change 8.2.2 "refresh -s syslogd" refresh -s syslogd; }
    else
        manual 8.2.2 "no remote syslog host given: re-run with -L <loghost> or add 'auth.info @<host>' / '*.info;auth.none @<host>' to /etc/syslog.conf"
    fi
fi

syslogd_r() {
    typeset args
    args=$(lssrc -S -s syslogd | awk -F: 'NR == 2 { print $3 }')
    chssys -s syslogd -a "$args -r" || return 1
    svc_active syslogd && { stopsrc -s syslogd; sleep 1; startsrc -s syslogd; }
    return 0
}
if in_scope 8.2.3; then
    if ps -ef 2> /dev/null | grep '[s]yslogd' | grep -Eq -- '[[:space:]]-r([[:space:]]|$)'; then
        ok 8.2.3 "syslogd runs with -r"
    elif lssrc -S -s syslogd 2> /dev/null | awk -F: 'NR == 2 { print $3 }' | grep -q -- '-r'; then
        ok 8.2.3 "syslogd subsystem is configured with -r (restart syslogd to activate)"
    else
        do_change 8.2.3 "chssys -s syslogd -a '... -r' and restart syslogd" syslogd_r
    fi
fi

# ===========================================================================
# Summary
# ===========================================================================
hdr "Summary"
say "  Applied:                 $N_APPLIED"
(( DRYRUN )) && say "  Would apply (dry-run):   $N_DRY"
say "  Already compliant:       $N_OK"
say "  Skipped (risky / in use): $N_SKIPPED"
say "  Manual action required:  $N_MANUAL"
say "  Failed:                  $N_FAILED"
say ""
say "  Log:    $LOG"
(( DRYRUN )) || say "  Undo:   $UNDO   (edited files: $BACKUP_DIR/files)"
(( REBOOT_NEEDED )) && say "  REBOOT required for the 4.9.1 (ASLR) settings."
say ""
say "  Next: re-run cis_collect.ksh and cis_report.py to verify; handle the [MANUAL] and [SKIPPED] items."
(( N_FAILED > 0 )) && exit 1
exit 0
