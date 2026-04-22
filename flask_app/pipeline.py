import sys, json, re, argparse, os

SEVERITY_WEIGHTS = {
    'hidden_process':    40,
    'malfind_hit':       30,
    'suspicious_network':25,
    'known_malware_name':20,
    'unusual_parent':    15,
    'correlation_bonus': 25,
}

SEVERITY_LEVELS = [
    (80, 'CRITICAL'),
    (55, 'HIGH'),
    (30, 'MEDIUM'),
    (0,  'LOW'),
]

KNOWN_MALWARE_NAMES = [
    'mimikatz', 'meterpreter', 'cobalt', 'empire', 'powersploit',
    'psexec', 'nc.exe', 'ncat', 'netcat', 'wcry', 'wannacry',
]

MAX_SCORE = 200  # FIX #6 — actual cap constant used in scoring


def _detect_vol_format(path):
    """
    Peek at the first non-comment, non-empty line of a pslist/psscan file
    and decide whether it is Vol3 format (PID first column, integer) or
    Vol2 format (process name first column).

    Vol3 header example:  PID   PPID  ImageFileName ...
    Vol3 data example  :  4     0     System        ...
    Vol2 header example:  Offset(V)  Name  PID ...
    Vol2 data example  :  0xffff...  System  4 ...
    """
    if not os.path.exists(path):
        return 'vol2'  # safe default
    with open(path, errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('*') or line.startswith('/'):
                continue
            parts = line.split()
            if not parts:
                continue
            # Vol3 data rows start with a plain integer PID
            if parts[0].isdigit():
                return 'vol3'
            # Vol3 header row
            if parts[0].upper() == 'PID':
                return 'vol3'
            # Anything else (Offset(...), process name, etc.) → vol2
            return 'vol2'
    return 'vol2'


def _parse_proc_file(path):
    """
    FIX #4 — unified parser that handles both Vol2 and Vol3 column layouts.

    Vol3 columns: PID  PPID  ImageFileName  Offset  Threads  Handles ...
    Vol2 columns: Offset(V)  Name  PID  PPID  Thds  Hnds ...
    Returns dict of {pid_str: process_name}
    """
    procs = {}
    if not os.path.exists(path):
        return procs

    fmt = _detect_vol_format(path)

    with open(path, errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Skip header / comment lines
            if line.startswith('*') or line.startswith('/'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue

            if fmt == 'vol3':
                # Skip the header row itself
                if parts[0].upper() == 'PID':
                    continue
                if not parts[0].isdigit():
                    continue
                pid  = parts[0]
                # Col 2 is ImageFileName in Vol3 pslist/psscan
                name = parts[2] if len(parts) > 2 else 'unknown'
                procs[pid] = name

            else:  # vol2
                # Skip header rows (Offset(V), 'Offset', dashes)
                if parts[0].startswith('Offset') or set(parts[0]) == {'-'}:
                    continue
                name = parts[0]
                # First all-digit token after the name is the PID
                pid = None
                for p in parts[1:]:
                    if p.isdigit():
                        pid = p
                        break
                if pid:
                    procs[pid] = name

    return procs


def parse_pslist(path):
    return _parse_proc_file(path)


def parse_psscan(path):
    return _parse_proc_file(path)


def find_hidden_processes(pslist, psscan):
    hidden = []
    for pid, name in psscan.items():
        if pid not in pslist:
            hidden.append({
                'pid': pid,
                'name': name,
                'reason': 'Present in psscan but absent from pslist — indicates rootkit hiding'
            })
    return hidden


def parse_malfind(path):
    hits = []
    if not os.path.exists(path):
        return hits
    current = {}
    with open(path, errors='replace') as f:
        for line in f:
            if 'Process:' in line:
                if current and current.get('rwx'):
                    hits.append(current)
                current = {'process': line.strip()}
            elif 'Protection:' in line and 'PAGE_EXECUTE_READWRITE' in line:
                current['rwx'] = True
                current['protection'] = line.strip()
    if current and current.get('rwx'):
        hits.append(current)
    return hits


def parse_netscan(path):
    connections = []
    if not os.path.exists(path):
        return connections
    with open(path, errors='replace') as f:
        for line in f:
            line = line.strip()
            if ('ESTABLISHED' in line or 'LISTENING' in line) and not line.startswith('/'):
                connections.append(line)
    return connections


def check_malware_names(pslist, psscan):
    hits = []
    all_procs = {**pslist, **psscan}
    for pid, name in all_procs.items():
        for m in KNOWN_MALWARE_NAMES:
            if m.lower() in name.lower():
                hits.append({'pid': pid, 'name': name, 'matched': m})
    return hits


def correlate(dump_id, report_dir):
    findings = []
    score    = 0

    pslist  = parse_pslist(f"{report_dir}/pslist.txt")
    psscan  = parse_psscan(f"{report_dir}/psscan.txt")
    hidden  = find_hidden_processes(pslist, psscan)

    malfind_path  = f"{report_dir}/malfind.txt"
    malfind_hits  = parse_malfind(malfind_path) if os.path.exists(malfind_path) else []

    netscan_path   = f"{report_dir}/netscan.txt"
    network_conns  = parse_netscan(netscan_path) if os.path.exists(netscan_path) else []

    malware_name_hits = check_malware_names(pslist, psscan)

    # Score hidden processes
    for h in hidden:
        score += SEVERITY_WEIGHTS['hidden_process']
        findings.append({'type': 'hidden_process', 'detail': h,
                         'score': SEVERITY_WEIGHTS['hidden_process']})

    # Score malfind RWX hits
    for m in malfind_hits:
        score += SEVERITY_WEIGHTS['malfind_hit']
        findings.append({'type': 'malfind_hit', 'detail': m,
                         'score': SEVERITY_WEIGHTS['malfind_hit']})

    # Score known malware process names
    for m in malware_name_hits:
        score += SEVERITY_WEIGHTS['known_malware_name']
        findings.append({'type': 'known_malware_name', 'detail': m,
                         'score': SEVERITY_WEIGHTS['known_malware_name']})

    # Score suspicious outbound connections (non-local, non-loopback)
    suspicious_conns = [
        c for c in network_conns
        if '127.0.0.1' not in c and '0.0.0.0' not in c and 'LISTENING' not in c
    ]
    for c in suspicious_conns[:5]:   # cap individual contributions to avoid inflation
        score += SEVERITY_WEIGHTS['suspicious_network']
        findings.append({'type': 'suspicious_network', 'detail': c,
                         'score': SEVERITY_WEIGHTS['suspicious_network']})

    # Correlation bonus: hidden proc + malfind in same PID
    hidden_pids = {h['pid'] for h in hidden}
    for m in malfind_hits:
        pid_match = re.search(r'PID[:\s]+(\d+)', m.get('process', ''))
        if pid_match and pid_match.group(1) in hidden_pids:
            score += SEVERITY_WEIGHTS['correlation_bonus']
            findings.append({
                'type': 'correlation_bonus',
                'detail': (
                    f"Hidden process PID {pid_match.group(1)} also has RWX memory injection "
                    f"— strongly indicates active rootkit/shellcode"
                ),
                'score': SEVERITY_WEIGHTS['correlation_bonus']
            })

    # FIX #6 — actually apply the cap that was only a comment before
    score = min(score, MAX_SCORE)

    severity = 'LOW'
    for threshold, level in SEVERITY_LEVELS:
        if score >= threshold:
            severity = level
            break

    result = {
        'dump_id':           dump_id,
        'total_score':       score,
        'max_score':         MAX_SCORE,
        'severity':          severity,
        'findings':          findings,
        'hidden_processes':  hidden,
        'malfind_hits':      malfind_hits,
        'network_connections': network_conns,
        'malware_name_hits': malware_name_hits,
        'process_count':     len(pslist),
        'psscan_count':      len(psscan),
        'connection_count':  len(network_conns),
    }

    with open(f"{report_dir}/correlation.json", 'w') as f:
        json.dump(result, f, indent=2)

    # Persist findings to DB
    try:
        sys.path.insert(0, '/app')
        from models import save_findings, update_dump_status
        save_findings(dump_id, findings, severity)
        update_dump_status(dump_id, 'COMPLETE')
    except Exception as e:
        print(f"DB write skipped: {e}")

    print(f"Severity: {severity} (score: {score}/{MAX_SCORE})")
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command')
    parser.add_argument('--dump-id')
    parser.add_argument('--report-dir')
    args = parser.parse_args()
    if args.command == 'correlate':
        correlate(args.dump_id, args.report_dir)