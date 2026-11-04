#!/usr/bin/ksh93
#
# cis_collect.ksh - Evidence collector for the CIS IBM AIX 7 Benchmark v1.2.0
#
# Runs the audit commands of EVERY recommendation of the benchmark (sections
# 1 - 8) and stores command, exit code, stdout and stderr in a single
# plain-text evidence file.  No judgement is made here: scoring, findings and
# remediation advice are produced off-box by cis_report.py.
#
# * READ-ONLY: nothing on the system is modified (only the evidence file and a
#   temporary work directory under /var/tmp are written).
# * Run as root (many audits read /etc/security/*, run trustchk, sshd -T ...).
# * Password hashes are never stored: where the benchmark greps hashes
#   (5.1.1, 5.2.4, 5.2.8) only the affected user names are recorded.
# * Deviation from the benchmark text: "\s" (not understood by the AIX grep)
#   is written as "[[:space:]]".
#
# Usage: cis_collect.ksh [-o outdir] [-q] [-m maxlines] [-t secs] [-T secs]
#                        [-F /path/to/flrtvc.ksh]
#   -o outdir   directory for the evidence file          (default /var/tmp)
#   -q          quick: skip the file-system-wide scans (find / ..., trustchk
#               tree).  Those recommendations are reported as "not collected"
#   -m maxlines max stdout lines kept per command        (default 3000)
#   -t secs     timeout per command                      (default 120)
#   -T secs     timeout for file-system-wide scans       (default 7200)
#   -F path     run FLRTVC (recommendation 7.1).  NOTE: flrtvc.ksh may contact
#               IBM over the network; it is only run when -F is given.
#

VERSION="1.0.0"
BENCHMARK="CIS IBM AIX 7 Benchmark v1.2.0"

ORIG_PATH="$PATH"
PATH=/usr/bin:/bin:/etc:/usr/sbin:/usr/ucb:/sbin:/usr/local/bin:/opt/freeware/bin
export PATH
umask 077

OUTDIR=/var/tmp
QUICK=0
MAXLINES=3000
CMD_TIMEOUT=120
SCAN_TIMEOUT=7200
FLRTVC=""

while getopts "o:qm:t:T:F:h" opt; do
    case $opt in
        o) OUTDIR=$OPTARG ;;
        q) QUICK=1 ;;
        m) MAXLINES=$OPTARG ;;
        t) CMD_TIMEOUT=$OPTARG ;;
        T) SCAN_TIMEOUT=$OPTARG ;;
        F) FLRTVC=$OPTARG ;;
        *) sed -n '2,/^#$/p;/^# Usage/,/^#$/p' "$0" | sed 's/^# \{0,1\}//' | head -30
           exit 2 ;;
    esac
done

HOST=$(hostname 2>/dev/null | cut -d. -f1)
STAMP=$(date '+%Y%m%d_%H%M%S')
OUT="$OUTDIR/cis_aix7_${HOST}_${STAMP}.evidence"
WORK="/var/tmp/cis_collect.$$"
COUNT=0

mkdir -p "$OUTDIR" || { print -u2 "cannot create $OUTDIR"; exit 1; }
mkdir "$WORK" || { print -u2 "cannot create $WORK"; exit 1; }
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT TERM HUP
: > "$OUT" || exit 1

if [[ $(id -u 2>/dev/null) != 0 ]]; then
    print -u2 "WARNING: not running as root - many audits will be incomplete."
fi

# ---------------------------------------------------------------------------
# Framework
# ---------------------------------------------------------------------------
function emit { print -r -- "$*" >> "$OUT"; }

# kill a process and all of its descendants (used for the per-command timeout)
function kill_tree {
    typeset p=$1 c
    for c in $(ps -ef 2>/dev/null | awk -v p="$p" '$3 == p { print $2 }'); do
        kill_tree "$c"
    done
    kill -9 "$p" 2>/dev/null
}

# probe <id> <name> <command> [timeout]
#   Runs <command> with eval, in a subshell, stdin = /dev/null.
function probe {
    typeset id=$1 name=$2 cmd=$3 to=${4:-$CMD_TIMEOUT}
    typeset o="$WORK/stdout" e="$WORK/stderr" mark="$WORK/timedout"
    typeset rc=0 pid wpid n

    COUNT=$((COUNT + 1))
    print -u2 "[${COUNT}] ${id} ${name}"
    rm -f "$mark"
    : > "$o"; : > "$e"

    ( eval "$cmd" ) > "$o" 2> "$e" < /dev/null &
    pid=$!
    ( sleep "$to"; : > "$mark"; kill_tree "$pid" ) > /dev/null 2>&1 &
    wpid=$!
    wait "$pid" 2> /dev/null
    rc=$?
    kill_tree "$wpid" > /dev/null 2>&1
    wait "$wpid" 2> /dev/null
    if [[ -f "$mark" ]]; then
        rc=124
        print "command timed out after ${to}s" >> "$e"
    fi

    n=$(wc -l < "$o" | tr -d ' ')
    emit "@@@BEGIN|$id|$name"
    emit "@@@CMD|$cmd"
    emit "@@@RC|$rc"
    emit "@@@STDOUT"
    head -n "$MAXLINES" "$o" | awk '{ sub(/^@@@/, " @@@"); print }' >> "$OUT"
    (( n > MAXLINES )) && emit "@@@TRUNCATED|$n"
    emit "@@@STDERR"
    head -n 40 "$e" | awk '{ sub(/^@@@/, " @@@"); print }' >> "$OUT"
    emit "@@@END"
}

# file-system-wide scans can be skipped with -q
function heavy {
    if (( QUICK )); then
        COUNT=$((COUNT + 1))
        emit "@@@BEGIN|$1|$2"
        emit "@@@CMD|$3"
        emit "@@@SKIPPED|quick mode (-q): file-system-wide scan not executed"
        emit "@@@END"
    else
        probe "$1" "$2" "$3" "$SCAN_TIMEOUT"
    fi
}

# metadata
function meta { emit "@@@META|$1|$2"; }

# ls -led <path> as probe 'a' (or given name)
function lsp { probe "$1" "${3:-a}" "ls -led $2"; }

# ---------------------------------------------------------------------------
# Compound audits (taken from / equivalent to the benchmark's audit scripts)
# ---------------------------------------------------------------------------

# 3.3 find group-writable objects owned by one of the admin=true groups
function c_3_3 {
    typeset -a args grp
    typeset g rest first=1 n=0
    lsgroup -a admin ALL 2>/dev/null | grep true | while read g rest; do
        grp[$n]=$g; n=$((n + 1))
    done
    if (( n == 0 )); then print "NO_ADMIN_GROUPS_FOUND"; return 0; fi
    args=( / \( -fstype jfs -o -fstype jfs2 \) ! -type d -perm -g+w \( )
    for g in "${grp[@]}"; do
        (( first )) || args[${#args[@]}]=-o
        args[${#args[@]}]=-group
        args[${#args[@]}]=$g
        first=0
    done
    args[${#args[@]}]=\)
    args[${#args[@]}]=-ls
    find -L "${args[@]}"
}

# 4.1.1.6 octal mode of /etc/mail/submit.cf (benchmark uses perl stat)
function c_submit_mode {
    [[ -e /etc/mail/submit.cf ]] || { print "FILE_NOT_FOUND"; return 0; }
    perl -e 'printf "%o\n",(stat shift)[2] & 07777' /etc/mail/submit.cf
}

# 4.1.1.1 smit.log of root
function c_smit {
    typeset H=~root
    [[ $H != "/" ]] && H=$H/
    ls -led "${H}smit.log"
}

# print G (group writable), W (world writable), O<owner> for a path
function pflags {
    typeset p=$1 m ow
    m=$(ls -ld "$p" 2>/dev/null | cut -c1-10)
    ow=$(ls -ld "$p" 2>/dev/null | awk '{print $3}')
    [[ ${m:5:1} == w ]] && print " WARNING $p is group writable"
    [[ ${m:8:1} == w ]] && print " WARNING $p is world writable"
    [[ $ow != @(root|bin) ]] && print " WARNING $p is not owned by root or bin"
}

# 4.1.1.17 commands referenced by root's crontab (walks up the path)
function c_cron_cmds {
    typeset CMD
    crontab -l 2>/dev/null | egrep -v '^[[:space:]]*#' | awk '{print $6}' | grep "^/" | sort -u |
    while read CMD; do
        while [[ -a ${CMD} && -n ${CMD} ]]; do
            pflags "$CMD"
            CMD=${CMD%/*}
        done
    done
}

# 4.1.1.18 list user dot files in the home directories of local users
function c_dotfiles {
    typeset hd f
    lsuser -a home ALL 2>/dev/null | cut -f2 -d= | egrep -v "^/$|/etc|/bin|/var|/usr|/usr/sys" |
    while read hd; do
        if [[ -d $hd ]]; then
            print "Listing all user configuration files in '$hd'"
            ls -a "$hd" | egrep "^\.[a-z]" | while read f; do
                [[ -f "$hd/$f" ]] && ls -l "$hd/$f"
            done
        else
            print "ERROR - no home directory for '$hd'"
        fi
    done
}

# 4.1.2.1 accounts (uid >= 200, not locked) without HOME directory
function c_home_exists {
    typeset name ids homes locks rest uid home locked
    lsuser -R files -a id home account_locked ALL 2>/dev/null |
    while read name ids homes locks rest; do
        uid=$(echo ${ids} | cut -f2 -d=)
        [[ ${uid} -ge 200 ]] || continue
        home=$(echo ${homes} | cut -f2 -d=)
        locked=$(echo ${locks} | cut -f2 -d=)
        [[ ${locked} == "true" ]] && continue
        [[ ! -d ${home} ]] && print "Recommend Lock Account [${name}]: Missing HOME at: ${home}"
    done
}

# 4.1.2.2 HOME owned by the account (or root)
function c_home_owner {
    typeset name ids homes locks rest uid home locked
    lsuser -R files -a id home account_locked ALL 2>/dev/null |
    while read name ids homes locks rest; do
        uid=$(echo ${ids} | cut -f2 -d=)
        [[ ${uid} -ge 200 ]] || continue
        home=$(echo ${homes} | cut -f2 -d=)
        locked=$(echo ${locks} | cut -f2 -d=)
        [[ ${home} == "/dev/null" || ${locked} == "true" ]] && continue
        if [[ ! -d ${home} ]]; then
            print "${home} does not exist; Recommend Lock Account [${name}]"
            continue
        fi
        /usr/bin/perl -e '
            $user=$ARGV[0]; $hd=$ARGV[1]; $uid=$ARGV[2]; $huid=((stat $hd)[4]);
            if ($huid != $uid && $huid != 0) { exit(1); }' "${name}" "${home}" "${uid}" ||
            print "Recommend Lock Account: ${name} does not own ${home}"
    done
}

# 4.1.2.3 HOME write access restricted to owner (mode bits and ACL)
function c_home_write {
    typeset name ids homes rest uid home
    lsuser -R files -a id home ALL 2>/dev/null |
    while read name ids homes rest; do
        uid=$(echo ${ids} | cut -f2 -d=)
        [[ ${uid} -ge 200 ]] || continue
        home=$(echo ${homes} | cut -f2 -d=)
        [[ ${home} == "/dev/null" ]] && continue
        if [[ ! -d ${home} ]]; then
            print "${home} does not exist; recommend to lock account named [${name}]"
        elif [[ ${home} != "/" ]]; then
            /usr/bin/perl -e '$f=$ARGV[0]; $m=(stat $f)[2];
                printf("Recommend chmod on: %s: to remove group or world write mode\n", $f) if $m & 022;
                printf("Recommend remove ACL on: %s\n", $f) if $m & 0200000000;
                exit($m & 0200000022)' "${home}" ||
                (ls -led "${home}" && (aclget "${home}" | grep -ip Enabled))
        fi
    done
}

# 4.1.2.5 directories below /etc/security
function c_etcsec_dirs {
    find /etc/security -type d 2>/dev/null | egrep -v "security/(aixpert|audit|ice)" | sort |
        xargs ls -led 2>/dev/null | awk '{print $1 " " $3 " " $4 " " $9}' |
        egrep -v "dr[w-]x[r-]-[sS-]----"
}

# 4.1.2.10 directories in the PATH of the user running the collector (root)
function c_rootpath {
    typeset d first
    print -r -- "$ORIG_PATH" | awk -F: '{ n = split($0, d, ":"); for (i = 1; i <= n; i++) print i ":" d[i] }' |
    while IFS=: read cnt d; do
        if [[ -z $d ]]; then print "Current Directory not allowed in \$PATH (empty entry #$cnt)"; continue; fi
        first=${d:0:1}
        if [[ $first != "/" ]]; then print "PATH directories must begin with '/', $d not allowed"; continue; fi
        if [[ ! -d $d ]]; then print "Non-existant directory $d in \$PATH"; continue; fi
        pflags "$d"
    done
}

# 4.2.6 permissions of all files of the legacy rcmd filesets
function c_rcmd {
    typeset fileset fn rest
    for fileset in bos.net.tcp.rcmd_server bos.net.tcp.rcmd; do
        lslpp -L ${fileset} > /dev/null 2>&1 || continue
        lslpp -f ${fileset} | egrep "^ +\/" | while read fn rest; do
            test -L "${fn}" && continue
            test -d "${fn}" && ls -led "${fn}" | egrep -v "^d----------"
            test -f "${fn}" && ls -led "${fn}" | egrep -v "^-----------"
        done
    done
}

# 4.3.2.9 portmap / RPC services (audit mode of the benchmark script)
function c_portmap {
    typeset n
    n=$(rpcinfo -p localhost 2>/dev/null | egrep -v "(program)|(portmap)|(status)|(nsm)|(pyramid)" | wc -l | tr -d ' ')
    print "OTHER_RPC_SERVICES=$n"
    rpcinfo -p localhost 2>/dev/null | egrep -v "(program)|(portmap)|(status)|(nsm)|(pyramid)"
    lssrc -s portmap 2>/dev/null | tail -n 1
    grep "start[[:blank:]]/usr/sbin/portmap" /etc/rc.tcpip
}

# 4.6.1.7 / 4.6.1.8 CDE per-language resource files
function c_cde_sysres {
    typeset file etc_file
    for file in /usr/dt/config/*/sys.resources; do
        [[ -f $file ]] || continue
        etc_file=$(echo $file | sed -e s/usr/etc/)
        print "Checking config file $etc_file"
        if [[ ! -f $etc_file ]]; then
            print "Missing config file $etc_file"
        else
            grep 'dtsession\*saverTimeout:' $etc_file || print "Missing setting dtsession*saverTimeout"
            grep 'dtsession\*lockTimeout:' $etc_file || print "Missing setting dtsession*lockTimeout"
        fi
    done
}
function c_cde_xres {
    typeset file etc_file
    for file in /usr/dt/config/*/Xresources; do
        [[ -f $file ]] || continue
        etc_file=$(echo $file | sed -e s/usr/etc/)
        print "Checking config file $etc_file"
        if [[ ! -f $etc_file ]]; then
            print "Missing config file $etc_file"
        else
            grep 'Dtlogin\*greeting.labelString:' $etc_file || print "Missing setting greeting.labelString"
            grep 'Dtlogin\*greeting.persLabelString:' $etc_file || print "Missing setting greeting.persLabelString"
        fi
    done
}

# 4.6.2.2 / 4.6.2.3 ftp daemon banner and umask (only if ftp is in inetd.conf)
function c_ftp_banner {
    if [[ $(grep -c "^ftp[[:blank:]]" /etc/inetd.conf 2>/dev/null) -gt 0 ]]; then
        lslpp -L "bos.msg.en_US.net.tcp.client" > /dev/null && print $(dspcat /usr/lib/nls/msg/en_US/ftpd.cat 1 9)
    else
        print "FTP_NOT_ENABLED_IN_INETD_CONF"
    fi
}
function c_ftp_umask {
    if [[ $(grep -c "^ftp[[:blank:]]" /etc/inetd.conf 2>/dev/null) -gt 0 ]]; then
        grep "^ftp[[:blank:]]" /etc/inetd.conf | awk '{print $6, $7, $8, $9, $10}'
    else
        print "FTP_NOT_ENABLED_IN_INETD_CONF"
    fi
}

# 4.6.3.9 effective sshd configuration for a root login from this host
function c_sshd_kex {
    typeset h a
    h=$(hostname)
    a=$(grep "$h" /etc/hosts 2>/dev/null | awk 'NR==1 {print $1}')
    [[ -z $a ]] && a=127.0.0.1
    sshd -T -C user=root -C host="$h" -C addr="$a" 2>&1 | grep kexalgorithms ||
        sshd -T 2>&1 | grep kexalgorithms
}

# 4.6.3.1 banner of the installed sshd (inetd mode, stdin = /dev/null)
function c_sshd_banner { sshd -i < /dev/null 2>&1 | head -n 1; }

# 5.1.1 accounts with an empty password field (names only)
function c_blankpw {
    egrep -p "password = +\$" /etc/security/passwd 2>/dev/null | grep ":" | awk -F: '{ print $1 }'
}

# 5.2.4 accounts with the NOCHECK flag (names only)
function c_nocheck {
    grep -p NOCHECK /etc/security/passwd 2>/dev/null | egrep ":\$" | sed -e 's/://'
}

# 5.2.8 accounts that still use the 13 character "crypt" hash (names only,
#       the hash itself is never printed)
function c_cryptpw {
    awk '
        /^[^ \t*#][^:]*:[ \t]*$/ { u = $1; sub(/:$/, "", u) }
        /^[ \t]*password[ \t]*=[ \t]*/ {
            h = $0; sub(/^[ \t]*password[ \t]*=[ \t]*/, "", h); sub(/[ \t]+$/, "", h)
            if (length(h) == 13) print u
        }' /etc/security/passwd 2>/dev/null
}

# 8.2.1 existence of the log files that /etc/syslog.conf writes to
function c_syslog_files {
    typeset f
    egrep -v "(^[[:space:]]*$)|(^[[:space:]]*#)" /etc/syslog.conf 2>/dev/null | awk '{print $2}' | grep '^/' | sort -u |
    while read f; do ls -ld "$f"; done
    ls -ld /var/log/syslog/archive
}

# sudoers files (AIX Toolbox keeps them below /opt/freeware too)
function sudo_files {
    typeset f
    for f in /etc/sudoers /etc/sudoers.d/* /opt/freeware/etc/sudoers /opt/freeware/etc/sudoers.d/*; do
        [[ -f $f ]] && print "$f"
    done
}
function c_sudo_ver { typeset s; s=$(command -v sudo 2>/dev/null); print "SUDO_PATH=$s"; [[ -n $s ]] && $s --version 2>&1 | head -n 2; }
function c_sudo_log {
    typeset f
    for f in $(sudo_files); do
        grep -Ei '^[[:space:]]*Defaults[[:space:]]+syslog_badpri=none' $f | sed "s|^|BADPRI_NONE $f: |"
        grep -Ei '^[[:space:]]*Defaults[[:space:]]+syslog_goodpri=none' $f | sed "s|^|GOODPRI_NONE $f: |"
        grep -Ei '^[[:space:]]*Defaults[[:space:]]+logfile=[^[:space:]]+' $f | sed "s|^|LOGFILE $f: |"
    done
}
function c_sudo_pty {
    typeset f
    for f in $(sudo_files); do
        egrep -i '^[[:space:]]*Defaults[[:space:]]+([^#]*[[:space:],])?use_pty([[:space:],#]|$)' $f | sed "s|^|USE_PTY $f: |"
        egrep -i '^[[:space:]]*Defaults[[:space:]]+([^#]*[[:space:],])?!use_pty([[:space:],#]|$)' $f | sed "s|^|NOT_USE_PTY $f: |"
    done
}

# 7.1 FLRTVC (only with -F)
function c_flrtvc {
    if [[ -n $FLRTVC && -f $FLRTVC ]]; then
        ksh "$FLRTVC" 2>&1
    else
        print "FLRTVC_NOT_RUN (use -F /path/to/flrtvc.ksh)"
        ls -l /usr/local/bin/flrtvc.ksh /opt/freeware/bin/flrtvc.ksh /usr/bin/flrtvc.ksh \
              /usr/sbin/flrtvc.ksh /root/flrtvc.ksh /tmp/flrtvc.ksh /var/tmp/flrtvc.ksh 2>/dev/null
    fi
}

# inetd check helper: list of active (uncommented) inetd.conf entries
function c_inetd_conf { grep -v '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -v '^[[:space:]]*$'; }

# ===========================================================================
# MAIN
# ===========================================================================
meta tool "cis_collect.ksh $VERSION"
meta benchmark "$BENCHMARK"
meta hostname "$(hostname 2>/dev/null)"
meta collected_at "$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null)"
meta uname "$(uname -a 2>/dev/null)"
meta oslevel "$(oslevel 2>/dev/null)"
meta oslevel_s "$(oslevel -s 2>/dev/null)"
meta user "$(id 2>/dev/null)"
meta quick "$QUICK"

# ---- shared evidence used by several recommendations ------------------------
probe SYS inetd_conf  c_inetd_conf
probe SYS inetd_lssrc 'lssrc -ls inetd'
probe SYS rc_tcpip    'grep -v "^[[:space:]]*#" /etc/rc.tcpip'
probe SYS lssrc_all   'lssrc -a'
probe SYS lsitab_all  'lsitab -a'
probe SYS lslpp_all   'lslpp -Lc'
probe SYS ps_ef       'ps -ef'
probe SYS filesystems 'lsfs'
probe SYS mount       'mount'
probe SYS ifconfig    'ifconfig -a'
probe SYS lsuser_all  'lsuser -R files -a id home shell account_locked login rlogin su sugroups admin expires maxage time_last_login unsuccessful_login_count ALL'
probe SYS lsconf      'lsconf'
probe SYS lsvg        'lsvg -o'

# ---- 1 Benchmark Organization --------------------------------------------
probe 1.3.1 a 'oslevel -s; lslpp -l bos.rte bos.rte.install'
probe 1.3.2 a 'ls -l /image.data /bosinst.data /var/adm/ras/bosinst.data; lsvg -l rootvg'
probe 1.3.3.1 a 'ls -l /usr/sys/inst.data/sys_bundles/CC_EVAL.BOS.autoi /usr/sys/inst.data/sys_bundles/CC_EVAL.Graphics.bnd /usr/sys/inst.data/sys_bundles/CC_EVAL.DocServices.bnd'
probe 1.3.3.1 b 'lsattr -El sys0 -a enhanced_RBAC; grep -n echo /etc/pse.conf'
probe 1.3.3.1 c 'lsitab httpdlite; lsitab writesrv; lsitab mkatmpvc; lsitab atmsvcd'
probe 1.3.3.1 d 'grep -E "start[[:blank:]]/usr/sbin/(snmpd|hostmibd|snmpmibd|aixmibd|muxatmd)" /etc/rc.tcpip'
probe 1.3.3.1 e 'nfso -a | egrep "(portcheck|nfs_use_reserved_ports)[[:blank:]]="; ifconfig lo0; ls -l /dev/console* /etc/security/aixpert/log/firstboot.log'
probe 1.3.3.2 a 'oslevel; lslpp -L openssh.base.client openssh.base.server openssh.license'
probe 1.3.4.1 a 'oslevel; lslpp -L bos.net.tcp.client bos.net.tcp.client_core bos.net.tcp.server bos.net.tcp.server_core bos.net.tcp.telnet'
probe 1.3.4.1 b 'ls -l /etc/security/aixpert/log/firstboot.log /usr/sbin/telnetd /usr/bin/telnet /usr/bin/ftp /usr/sbin/ftpd /usr/sbin/rshd /usr/sbin/rlogind'
probe 1.3.4.1 c 'aixpert -c' 600
probe 1.4 a 'oslevel -s; oslevel -r; uname -a'
probe 1.4 b 'emgr -l'
probe 1.4 c 'oslevel -sq'
probe 1.4 d 'lslpp -h bos.rte'
probe 1.4 e 'instfix -i | grep -E "AIX_ML|SP_|_SP"'
probe 1.4 f 'who -b; uptime'

# ---- 2 Inventory and Control of Assets -------------------------------------
probe 2.1 a '/usr/bin/crontab -l | /usr/bin/egrep "/usr/sbin/lsconf -v"'
probe 2.1 b '/usr/bin/egrep "syslog/inventory.log " /etc/syslog.conf'
probe 2.2 a 'trustchk -p TE TEP'
probe 2.3 a 'trustchk -p LOCK_KERN_POLICIES'
probe 2.4 a '/usr/sbin/trustchk -p TE CHKEXEC'
probe 2.4 b '/usr/bin/grep "kern.info" /etc/syslog.conf'
probe 2.5 a 'trustchk -p stop_untrustd stop_on_chkfail te'
heavy 2.6 a 'trustchk -i -n tree / 2>&1 >/dev/null | grep untrusted'
heavy 2.7 a 'find -L / \( -fstype jfs -o -fstype jfs2 \) -type l -ls'

# ---- 3 Configure Data Protection --------------------------------------------
probe 3.1 a 'lssec -f /etc/security/user -s default -a umask'
heavy 3.2 a 'find / \( -fstype jfs -o -fstype jfs2 \) -type d -perm -o+w ! -perm -1000 -ls'
heavy 3.3 a c_3_3
heavy 3.4 a 'find / \( -fstype jfs -o -fstype jfs2 \) -type f -perm -o+w -ls'
heavy 3.5 a 'find / \( -fstype jfs -o -fstype jfs2 \) -type f -perm -g+w -group staff -ls'
heavy 3.6 a '/usr/bin/find / \( -fstype jfs -o -fstype jfs2 \) \( -type d -o -type f \) \( -nouser -o -nogroup \) -ls'

# ---- 4.1.1 Trusted Files ------------------------------------------------------
probe 4.1.1.1 a c_smit
lsp 4.1.1.2 /etc/group
lsp 4.1.1.3 /etc/inetd.conf
lsp 4.1.1.4 /etc/motd
lsp 4.1.1.5 /etc/passwd
probe 4.1.1.6 a c_submit_mode
lsp 4.1.1.6 /etc/mail/submit.cf b
lsp 4.1.1.7 /etc/ssh/ssh_banner
lsp 4.1.1.8 /etc/ssh/ssh_config
lsp 4.1.1.9 /etc/ssh/sshd_config
lsp 4.1.1.10 /var/adm/cron/at.allow
lsp 4.1.1.11 /var/adm/cron/cron.allow
lsp 4.1.1.12 /var/adm/cron/log
lsp 4.1.1.13 /var/ct/RMstart.log
lsp 4.1.1.14 /var/tmp/dpid2.log
lsp 4.1.1.15 /var/tmp/hostmibd.log
lsp 4.1.1.16 /var/tmp/snmpd.log
probe 4.1.1.17 a c_cron_cmds
probe 4.1.1.18 a c_dotfiles
heavy 4.1.1.19 a 'find / \( -fstype jfs -o -fstype jfs2 \) \( -perm -04000 -o -perm -02000 \) -type f -ls'
lsp 4.1.1.20 /var/tmp/snmpdv3.log

# ---- 4.1.2 Trusted Directories -------------------------------------------------
probe 4.1.2.1 a c_home_exists
probe 4.1.2.2 a c_home_owner
probe 4.1.2.3 a c_home_write
probe 4.1.2.4 a 'find /etc/security/audit /audit \( -perm -4 -o -perm -2 -o -perm -1 \) -o ! -user root -o ! -group audit'
probe 4.1.2.5 a c_etcsec_dirs
probe 4.1.2.6 a '/usr/bin/ls -l /var/adm/ras'
lsp 4.1.2.7 /var/adm/sa
probe 4.1.2.8 a 'find /var/spool/cron/crontabs -type d -prune \( -perm -4 -o -perm -2 -o -perm -1 -o -perm -200000000 \) -o ! -user bin -o ! -group cron'
probe 4.1.2.8 b 'find /var/spool/cron/crontabs \( -perm -4 -o -perm -2 -o -perm -1 -o -perm -200000000 \) -o ! -group cron'
probe 4.1.2.8 c 'trustchk -n /var/spool/cron/crontabs >/dev/null 2>&1 || echo trustchk failed'
probe 4.1.2.9 a 'find /var/spool/cron/atjobs -type d -prune \( -perm -4 -o -perm -2 -o -perm -1 -o -perm -200000000 \)'
probe 4.1.2.9 b 'find /var/spool/cron/atjobs ! -type d -perm -2'
probe 4.1.2.9 c 'trustchk -n /var/spool/cron/atjobs >/dev/null 2>&1 || echo trustchk failed'
probe 4.1.2.10 a c_rootpath
probe 4.1.2.11 a 'lsuser -a home root'

# ---- 4.2 Network Services --------------------------------------------------------
probe 4.2.1 a 'lslpp -L | grep "bos.net.nis.client"'
probe 4.2.2 a 'lslpp -L | grep "bos.net.nis.server"'
probe 4.2.2 b 'cat /var/yp/securenets'
probe 4.2.3 a 'grep "^+" /etc/passwd /etc/group'
probe 4.2.4 a 'grep -v "^[[:space:]]*#" /etc/hosts.equiv | grep -v "^[[:space:]]*$"'
probe 4.2.5 a 'find / \( -fstype jfs -o -fstype jfs2 \) -name ".netrc" -print'
probe 4.2.5 b 'find / \( -fstype jfs -o -fstype jfs2 \) -name ".rhosts" -print'
probe 4.2.5 c 'find / \( -fstype jfs -o -fstype jfs2 \) -name ".shosts" -print'
probe 4.2.6 a c_rcmd
probe 4.2.7 a 'lslpp -Lcq bos.net.tcp.snmp >/dev/null 2>&1 && echo " - SNMP client fileset exists on the system"; lslpp -Lcq bos.net.tcp.snmpd >/dev/null 2>&1 && echo " - SNMP server fileset exists on the system"'

# ---- 4.3.1 /etc/inittab -------------------------------------------------------------
probe 4.3.1.1 a '/usr/sbin/lsitab writesrv'
probe 4.3.1.1 b '/usr/bin/lssrc -s writesrv | /usr/bin/tail -n1'
probe 4.3.1.2 a 'lsitab dt; lsitab dt_nogb'
probe 4.3.1.3 a 'lsitab piobe'
probe 4.3.1.4 a 'lsitab qdaemon'
probe 4.3.1.5 a 'lsitab rcnfs'
probe 4.3.1.6 a 'lslpp -L | grep -i bos.net.snapp'
probe 4.3.1.7 a '(lslpp -Lc bos.sysmgt.nim.master bos.sysmgt.nim.spot | grep sysmgt.nim) && echo "NIM master and/or spot installed"'

# ---- 4.3.2 /etc/rc.tcpip --------------------------------------------------------------
probe 4.3.2.1 a 'grep "^#start[[:blank:]]/usr/sbin/inetd" /etc/rc.tcpip'
probe 4.3.2.1 b 'grep "start[[:blank:]]/usr/sbin/inetd" /etc/rc.tcpip'
probe 4.3.2.1 c 'lssrc -ls inetd'
probe 4.3.2.2 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/dhcpcd" /etc/rc.tcpip'
probe 4.3.2.2 b '/usr/bin/lssrc -a | /usr/bin/grep dhcpcd'
probe 4.3.2.3 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/dhcprd" /etc/rc.tcpip'
probe 4.3.2.3 b '/usr/bin/lssrc -a | /usr/bin/grep dhcprd'
probe 4.3.2.4 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/dhcpsd" /etc/rc.tcpip'
probe 4.3.2.4 b '/usr/bin/lssrc -a | /usr/bin/grep dhcpsd'
probe 4.3.2.5 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/gated" /etc/rc.tcpip'
probe 4.3.2.5 b '/usr/bin/lssrc -a | /usr/bin/grep gated'
probe 4.3.2.6 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/hostmibd" /etc/rc.tcpip'
probe 4.3.2.6 b '/usr/bin/lssrc -a | /usr/bin/grep hostmibd'
probe 4.3.2.7 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/mrouted" /etc/rc.tcpip'
probe 4.3.2.7 b '/usr/bin/lssrc -s mrouted'
probe 4.3.2.8 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/named" /etc/rc.tcpip'
probe 4.3.2.8 b '/usr/bin/lssrc -a | /usr/bin/grep named'
probe 4.3.2.9 a c_portmap
probe 4.3.2.10 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/routed" /etc/rc.tcpip'
probe 4.3.2.10 b '/usr/bin/lssrc -s routed'
probe 4.3.2.11 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/rwhod" /etc/rc.tcpip'
probe 4.3.2.11 b '/usr/bin/lssrc -a | /usr/bin/grep rwhod'
probe 4.3.2.12 a '/usr/bin/grep "start[[:blank:]]/usr/lib/sendmail" /etc/rc.tcpip'
probe 4.3.2.12 b '/usr/bin/lssrc -a | /usr/bin/grep sendmail'
probe 4.3.2.13 a '/usr/bin/grep "start[[:blank:]]/usr/sbin/timed" /etc/rc.tcpip'
probe 4.3.2.13 b '/usr/bin/lssrc -a | /usr/bin/grep timed'

# ---- 4.3.3 IPv6 ------------------------------------------------------------------------
probe 4.3.3.1 a 'grep "^#start[[:blank:]]/usr/sbin/autoconf6" /etc/rc.tcpip'
probe 4.3.3.1 b 'grep "start[[:blank:]]/usr/sbin/autoconf6" /etc/rc.tcpip'
probe 4.3.3.2 a 'grep "^#start[[:blank:]]/usr/sbin/ndpd-host" /etc/rc.tcpip'
probe 4.3.3.2 b 'grep "start[[:blank:]]/usr/sbin/ndpd-host" /etc/rc.tcpip'
probe 4.3.3.3 a 'grep "^#start[[:blank:]]/usr/sbin/ndpd-router" /etc/rc.tcpip'
probe 4.3.3.3 b 'grep "start[[:blank:]]/usr/sbin/ndpd-router" /etc/rc.tcpip'

# ---- 4.3.4 inetd services ---------------------------------------------------------------
probe 4.3.4.1  a 'lssrc -s inetd -l | grep bootps | wc -l'
probe 4.3.4.2  a 'lssrc -s inetd -l | grep chargen | wc -l'
probe 4.3.4.3  a 'lssrc -s inetd -l | grep comsat | wc -l'
probe 4.3.4.4  a 'lssrc -s inetd -l | grep daytime | wc -l'
probe 4.3.4.5  a 'lssrc -s inetd -l | grep discard | wc -l'
probe 4.3.4.6  a 'lssrc -s inetd -l | grep echo | wc -l'
probe 4.3.4.7  a 'lssrc -s inetd -l | grep exec | wc -l'
probe 4.3.4.8  a 'lssrc -s inetd -l | grep finger | wc -l'
probe 4.3.4.9  a 'lssrc -s inetd -l | grep -v tftp | grep ftp | wc -l'
probe 4.3.4.10 a 'lssrc -s inetd -l | grep imap2 | wc -l'
probe 4.3.4.11 a 'lssrc -s inetd -l | grep instsrv | wc -l'
probe 4.3.4.12 a 'lssrc -s inetd -l | grep klogin | wc -l'
probe 4.3.4.13 a 'lssrc -s inetd -l | grep kshell | wc -l'
probe 4.3.4.14 a 'lssrc -s inetd -l | grep netstat | wc -l'
probe 4.3.4.15 a 'lssrc -s inetd -l | grep ntalk | wc -l'
probe 4.3.4.16 a 'lssrc -s inetd -l | grep pcnfsd | wc -l'
probe 4.3.4.17 a 'grep "^#pop3[[:blank:]]" /etc/inetd.conf'
probe 4.3.4.18 a 'lssrc -s inetd -l | grep "[[:blank:]]rexd" | wc -l'
probe 4.3.4.19 a "/usr/bin/lssrc -s inetd -l | /usr/bin/grep '^rlogin' | wc -l"
probe 4.3.4.20 a 'lssrc -s inetd -l | grep "[[:blank:]]rquotad" | wc -l'
probe 4.3.4.21 a 'lssrc -s inetd -l | grep rstatd | wc -l'
probe 4.3.4.22 a '/usr/bin/lssrc -s inetd -l | /usr/bin/grep rsync'
probe 4.3.4.23 a 'lssrc -s inetd -l | grep "[[:blank:]]rusersd" | wc -l'
probe 4.3.4.24 a 'lssrc -s inetd -l | grep "[[:blank:]]rwalld" | wc -l'
probe 4.3.4.25 a 'lssrc -s inetd -l | grep "[[:blank:]]shell" | wc -l'
probe 4.3.4.26 a 'lssrc -s inetd -l | grep sprayd | wc -l'
probe 4.3.4.27 a 'lssrc -s inetd -l | grep "[[:blank:]]talk" | wc -l'
probe 4.3.4.28 a 'lssrc -s inetd -l | grep telnet | wc -l'
probe 4.3.4.29 a 'lssrc -s inetd -l | grep "[[:blank:]]tftp" | wc -l'
probe 4.3.4.30 a 'lssrc -s inetd -l | grep "[[:blank:]]time" | wc -l'
probe 4.3.4.31 a 'lssrc -s inetd -l | grep "[[:blank:]]uucp" | wc -l'
probe 4.3.4.32 a 'lssrc -s inetd -l | grep "[[:blank:]]xmquery" | wc -l'

# ---- 4.4 Filesystem Configuration ----------------------------------------------------------
probe 4.4.1.1 a '/usr/bin/grep -p nfs /etc/filesystems'
probe 4.4.1.1 b 'mount | grep nfs'
probe 4.4.1.2 a 'lslpp -L | grep bos.net.nfs.server'
probe 4.4.1.2 b 'cat /etc/exports'
probe 4.4.1.3 a 'lsnfsmnt -l | /usr/bin/egrep -v "^Name" | /usr/bin/grep -v "nosuid"'
probe 4.4.1.3 b 'lsnfsmnt -l | /usr/bin/egrep -v "^Name" | /usr/bin/grep -v "nodev"'
probe 4.4.1.4 a 'cat /etc/exports'
probe 4.4.1.4 b 'grep -E "^[[:space:]]*(127\.0\.0\.1|::1)[[:space:]]" /etc/hosts'
probe 4.4.1.5 a 'showmount -e | grep "(everyone)" | wc -l'
probe 4.4.1.5 b 'showmount -e'
probe 4.4.1.6 a "lsnfsexp | grep -v 'anon=-1' | grep anon="
probe 4.4.1.7 a 'lsnfsexp | grep sec= | grep none'
probe 4.4.1.7 b 'lsnfsexp | grep -v sec='
probe 4.4.2.1 a 'lslpp -L | grep "clic"'
probe 4.4.2.1 b 'genkex | grep crypt'
probe 4.4.2.1 c 'lsfs -q | grep -i efs'
probe 4.4.3.1 a 'lsfs | /usr/bin/grep jfs | /usr/bin/egrep -v "/dev/hd4|nodev"'
probe 4.4.3.1 b 'mount | /usr/bin/grep jfs | /usr/bin/egrep -v "/dev/hd4|nodev"'

# ---- 4.5 Network Options ---------------------------------------------------------------------
probe 4.5.1  a 'no -a | grep "sockthresh[[:blank:]]="'
probe 4.5.2  a 'no -a | grep "bcastping[[:blank:]]="'
probe 4.5.3  a 'no -a | grep "clean_partial_conns[[:blank:]]="'
probe 4.5.4  a 'no -a | grep "directed_broadcast[[:blank:]]="'
probe 4.5.5  a 'no -a | grep "icmpaddressmask[[:blank:]]="'
probe 4.5.6  a 'no -a | grep "ipforwarding[[:blank:]]="'
probe 4.5.7  a 'no -a | grep "ip6forwarding[[:blank:]]="'
probe 4.5.8  a 'no -a | grep "ipignoreredirects[[:blank:]]="'
probe 4.5.9  a 'no -a | grep "ipsendredirects[[:blank:]]="'
probe 4.5.10 a 'no -a | grep "ipsrcrouteforward[[:blank:]]="'
probe 4.5.11 a 'no -a | grep "ipsrcrouterecv[[:blank:]]="'
probe 4.5.12 a 'no -a | grep "ipsrcroutesend[[:blank:]]="'
probe 4.5.13 a 'no -a | grep "ip6srcrouteforward[[:blank:]]="'
probe 4.5.14 a 'nfso -a | egrep "(portcheck|nfs_use_reserved_ports)[[:blank:]]="'
probe 4.5.15 a 'no -a | grep "nonlocsrcroute[[:blank:]]="'
probe 4.5.16 a 'no -a | grep "tcp_pmtu_discover[[:blank:]]="'
probe 4.5.17 a 'no -o tcp_tcpsecure'
probe 4.5.18 a 'no -a | grep "udp_pmtu_discover[[:blank:]]="'
probe 4.5.19 a 'no -a | grep "icmptimestamp[[:blank:]]="'

# ---- 4.6.1 CDE ----------------------------------------------------------------------------------
probe 4.6.1.1  a 'lslpp -L | grep -i X11.Dt'
probe 4.6.1.2  a 'lssrc -s inetd -l | grep cms | wc -l'
probe 4.6.1.3  a 'lsitab dt; lsitab dt_nogb'
probe 4.6.1.4  a 'grep "^#dtspc[[:blank:]]" /etc/inetd.conf'
probe 4.6.1.5  a 'ls -l /usr/dt/bin/dtaction /usr/dt/bin/dtappgather /usr/dt/bin/dtprintinfo /usr/dt/bin/dtsession | awk "{print \$1 \" \" \$3 \" \" \$4 \" \" \$9}"'
probe 4.6.1.6  a 'grep "^Dtlogin.requestPort:[[:space:]]" /etc/dt/config/Xconfig'
probe 4.6.1.7  a c_cde_sysres
probe 4.6.1.8  a c_cde_xres
lsp 4.6.1.9 /etc/dt/config/Xconfig
lsp 4.6.1.10 /etc/dt/config/Xservers
probe 4.6.1.10 b "/usr/bin/egrep '^[[:space:]]*Dtlogin' /etc/dt/config/Xconfig"
probe 4.6.1.11 a 'ls -le /etc/dt/config/*/Xresources'

# ---- 4.6.2 FTPD ----------------------------------------------------------------------------------
probe 4.6.2.1 a 'grep "root" /etc/ftpusers'
probe 4.6.2.2 a c_ftp_banner
probe 4.6.2.3 a c_ftp_umask

# ---- 4.6.3 OpenSSH -------------------------------------------------------------------------------
probe 4.6.3.1 a 'ssh -V 2>&1'
probe 4.6.3.1 b 'lslpp -L openssh.base.server openssh.base.client'
probe 4.6.3.1 c c_sshd_banner 20
probe 4.6.3.2 a 'ls -l /etc/[rs]hosts.equiv'
probe 4.6.3.3 a '/usr/sbin/sshd -T | /usr/bin/egrep -i "subsystem sftp"'
probe 4.6.3.4 a '/usr/sbin/sshd -T | /usr/bin/egrep -i "^(AllowUsers|AllowGroups|DenyUsers|DenyGroups)[[:blank:]]"'
probe 4.6.3.5 a 'sshd -T | /usr/bin/egrep -i "^banner[[:blank:]]"'
probe 4.6.3.5 b "/usr/bin/egrep -i '^[[:space:]]*Banner[[:space:]]+\"?none' /etc/ssh/sshd_config"
probe 4.6.3.5 c 'f=$(sshd -T | awk "\$1 == \"banner\" {print \$2}"); [ -n "$f" ] && [ -e "$f" ] && cat "$f"'
probe 4.6.3.6 a 'sshd -T | /usr/bin/egrep -i "^ciphers[[:blank:]]"'
probe 4.6.3.7 a 'sshd -T | grep hostbasedauthentication'
probe 4.6.3.7 b "/usr/bin/egrep -i '^[[:space:]]*HostbasedAuthentication[[:space:]]+\"?yes' /etc/ssh/sshd_config"
probe 4.6.3.8 a 'sshd -T | grep ignorerhosts'
probe 4.6.3.8 b "/usr/bin/egrep -i '^[[:space:]]*IgnoreRhosts[[:space:]]+\"?no' /etc/ssh/sshd_config"
probe 4.6.3.9 a c_sshd_kex
probe 4.6.3.10 a 'sshd -T | grep loglevel'
probe 4.6.3.11 a 'sshd -T | /usr/bin/egrep -i "^macs[[:blank:]]"'
probe 4.6.3.12 a 'sshd -T | grep maxauthtries'
probe 4.6.3.13 a 'grep "^PermitEmptyPasswords[[:blank:]]" /etc/ssh/sshd_config'
probe 4.6.3.13 b 'sshd -T | grep permitemptypasswords'
probe 4.6.3.14 a '/usr/bin/egrep "^PermitRootLogin" /etc/ssh/sshd_config'
probe 4.6.3.14 b 'sshd -T | grep permitrootlogin'
probe 4.6.3.15 a '/usr/bin/egrep "^PermitRootLogin" /etc/ssh/sshd_config'
probe 4.6.3.15 b 'sshd -T | grep permitrootlogin'
probe 4.6.3.16 a 'sshd -T | grep permituserenvironment'
probe 4.6.3.17 a 'sshd -T | grep rekeylimit'
probe 4.6.3.18 a '/usr/sbin/sshd -T | /usr/bin/egrep -i "(clientaliveinterval|clientalivecountmax)"'
probe 4.6.3.18 b '/usr/bin/egrep -i "^[[:space:]]*Match" /etc/ssh/sshd_config'

# ---- 4.6.4 Sendmail ------------------------------------------------------------------------------
probe 4.6.4.1 a '/usr/bin/egrep -i "^O SmtpGreetingMessage" /etc/mail/sendmail.cf'
probe 4.6.4.1 b 'test -e /etc/mail/helpfile && echo HELPFILE_EXISTS || echo "Sendmail HELP file is missing"'
probe 4.6.4.2 a '/usr/bin/egrep -i "^O PrivacyOptions" /etc/mail/sendmail.cf'
lsp 4.6.4.3 /etc/mail/sendmail.cf
lsp 4.6.4.4 /var/spool/clientmqueue
lsp 4.6.4.5 /var/spool/mqueue

# ---- 4.7 Login Controls ----------------------------------------------------------------------------
probe 4.7.1 a 'lssec -f /etc/security/login.cfg -s default -a herald'
probe 4.7.2 a 'lssec -f /etc/security/login.cfg -s default -a logindelay'
probe 4.7.3 a 'lssec -f /etc/security/user -s default -a loginretries'
probe 4.7.4 a 'lssec -f /etc/security/login.cfg -s usw -a logintimeout'
probe 4.7.5 a 'export | /usr/bin/egrep -e "TMOUT|TIMEOUT"'
probe 4.7.5 b 'ksh93 -l -c "export | /usr/bin/egrep -e \"TMOUT|TIMEOUT\""'
probe 4.7.5 c '/usr/bin/egrep -e "TMOUT|TIMEOUT|^[[:space:]]*(export|readonly)" /etc/profile'
probe 4.7.6 a 'readonly | /usr/bin/egrep -e "TMOUT|TIMEOUT"'
probe 4.7.6 b 'ksh93 -l -c "readonly | /usr/bin/egrep -e \"TMOUT|TIMEOUT\""'
probe 4.7.6 c '/usr/bin/egrep -e "TMOUT|TIMEOUT|^[[:space:]]*(export|readonly)" /etc/profile'

# ---- 4.8 Verify Integrity of Installation Settings ------------------------------------------------------
probe 4.8.1 a 'lsuser -a login rlogin su sugroups root'
probe 4.8.2 a 'lsuser -a shell root'
probe 4.8.3 a 'lssec -f /etc/security/limits -s default -a core -a core_hard'
probe 4.8.3 b 'lsattr -El sys0 -a fullcore'
probe 4.8.4 a 'grep "^PATH=" /etc/environment'
probe 4.8.5 a "su - root -c 'echo \${PATH}'"
lsp 4.8.6 /etc/motd
probe 4.8.6 b 'cat /etc/motd'

# ---- 4.9 Memory Options ------------------------------------------------------------------------------------
probe 4.9.1 a '/usr/sbin/vmo -aF | grep aslr'

# ---- 5 Account Management ------------------------------------------------------------------------------------
probe 5.1.1 a c_blankpw
probe 5.1.2 a 'cut -d: -f 3 /etc/passwd | sort -n | uniq -d'
probe 5.1.2 b 'cut -d: -f 1 /etc/passwd | sort | uniq -d'
probe 5.1.3 a 'cut -d: -f 1,3 /etc/group | sort -u | cut -d: -f 2 | sort -n | uniq -d'
probe 5.1.3 b 'cut -d: -f 1,3 /etc/group | sort -u | cut -d: -f 1 | sort | uniq -d'
probe 5.1.4 a 'lsuser -R files -a admin ALL | grep "admin=true"'
probe 5.1.5 a 'lsuser -R files -a admin ALL | grep "admin=false"'
probe 5.1.6 a 'pwdck -n ALL'
probe 5.2.1  a 'lssec -f /etc/security/user -s default -a histsize'
probe 5.2.2  a 'lssec -f /etc/security/user -s default -a minage'
probe 5.2.3  a 'lssec -f /etc/security/user -s default -a histexpire'
probe 5.2.4  a c_nocheck
probe 5.2.5  a 'lssec -f /etc/security/user -s default -a maxexpired'
probe 5.2.6  a 'lssec -f /etc/security/user -s default -a maxage'
probe 5.2.7  a 'lssec -f /etc/security/login.cfg -s usw -a pwd_algorithm'
probe 5.2.8  a c_cryptpw
probe 5.2.9  a 'lssec -f /etc/security/user -s default -a minlen'
probe 5.2.10 a 'lssec -f /etc/security/user -s default -a mindiff'
probe 5.2.11 a 'lssec -f /etc/security/user -s default -a minalpha'
probe 5.2.12 a 'lssec -f /etc/security/user -s default -a minother'
probe 5.2.13 a 'lssec -f /etc/security/user -s default -a maxrepeats'
probe 5.2.14 a 'lssec -f /etc/security/user -s default -a mindigit'
probe 5.2.15 a 'lssec -f /etc/security/user -s default -a minloweralpha'
probe 5.2.16 a 'lssec -f /etc/security/user -s default -a minupperalpha'
probe 5.2.17 a 'lssec -f /etc/security/user -s default -a minspecialchar'
probe 5.3.1  a 'lsuser -a account_locked login rlogin adm'
probe 5.3.2  a 'lsuser -a account_locked login rlogin bin'
probe 5.3.3  a 'lsuser -a account_locked login rlogin daemon'
probe 5.3.4  a 'lsuser -a account_locked login rlogin guest'
probe 5.3.5  a 'lsuser -a account_locked login rlogin lpd'
probe 5.3.6  a 'lsuser -a account_locked login rlogin nobody'
probe 5.3.7  a 'lsuser -a account_locked login rlogin nuucp'
probe 5.3.8  a 'lsuser -a account_locked login rlogin sys'
probe 5.3.9  a 'lsuser -a account_locked login rlogin uucp'
probe 5.3.10 a 'cat /etc/ftpusers'
probe 5.3.10 b 'lsuser -a id ALL'
probe 5.4 a 'lssec -f /etc/security/user -s default -a umask -a loginretries -a histsize -a minage -a maxage -a maxexpired -a minlen -a mindiff -a minalpha -a minother -a maxrepeats -a mindigit -a minloweralpha -a minupperalpha -a minspecialchar -a histexpire -a rlogin -a login -a su -a core -a fsize -a cpu -a data -a stack -a rss'
probe 5.4 b 'lsuser -R files -a umask maxage minage minlen histsize histexpire loginretries ALL'
probe 5.5 a 'lsuser -R files -a maxage maxexpired expires time_last_login unsuccessful_login_count lastupdate ALL'

# ---- 6 Access Control Management -----------------------------------------------------------------------------------
probe 6.1.1 a c_sudo_ver
probe 6.1.2 a c_sudo_log
probe 6.1.3 a c_sudo_pty
probe 6.2.1 a '/usr/bin/ls /var/adm/cron/at.deny'
probe 6.2.1 b '/usr/bin/cat /var/adm/cron/at.allow'
probe 6.2.2 a '/usr/bin/ls /var/adm/cron/cron.deny'
probe 6.2.2 b '/usr/bin/cat /var/adm/cron/cron.allow'

# ---- 7 Continuous Vulnerability Management ----------------------------------------------------------------------------
probe 7.1 a c_flrtvc 1800
probe 7.1 b 'oslevel -s; emgr -l'
probe 7.2 a '/usr/sbin/lsconf 2> /dev/null | /usr/bin/grep -E "System Model|Firmware"'
probe 7.2 b 'lsmcode -c'
probe 7.2 c 'lsdev -Cc adapter'

# ---- 8 Logging and Auditing -----------------------------------------------------------------------------------------------
probe 8.1.1 a 'lsfs /audit'
probe 8.1.1 b 'cat /etc/security/audit/config'
probe 8.1.1 c 'lssec -f /usr/lib/security/mkuser.default -s user -a auditclasses'
probe 8.1.1 d 'crontab -l | grep "cronaudit"'
probe 8.1.1 e 'lsitab audit'
probe 8.1.2 a 'cat /etc/security/audit/config'
probe 8.1.3 a '/usr/bin/grep -p classes: /etc/security/audit/config | /usr/bin/egrep "default ="'
probe 8.2.1 a '/usr/bin/egrep -v "(^$)|(^#)" /etc/syslog.conf'
probe 8.2.1 b c_syslog_files
probe 8.2.2 a "grep -v '^[[:space:]]*#' /etc/syslog.conf | grep '@'"
probe 8.2.3 a '/usr/bin/ps -ef | grep "syslogd" | grep -v grep'
probe 8.2.3 b 'lssrc -S -s syslogd'

# ---------------------------------------------------------------------------
meta probes "$COUNT"
meta finished_at "$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null)"
emit "@@@EOF"
chmod 600 "$OUT" 2>/dev/null

print -u2 ""
print -u2 "Done: $COUNT commands executed."
print -u2 "Evidence file: $OUT"
print -u2 "(contains system configuration details - handle as confidential)"
print -u2 "Next: python3 cis_report.py \"$OUT\" -o report.html"
exit 0
