from flask import Flask, request, jsonify, render_template, send_file, abort, Response
from werkzeug.utils import secure_filename
import os, hashlib, uuid, threading, json
from models import (
    init_db, create_case, get_all_cases, create_dump, get_case,
    get_dump, get_findings, get_results, update_dump_status,
    update_case_status, log_result, get_dump_with_case
)

app = Flask(__name__)

# FIX #3 — single source of truth for paths; Jenkins Jenkinsfile uses the same roots
app.config['UPLOAD_FOLDER'] = os.environ.get('DUMP_FOLDER',   '/app/dumps')
app.config['REPORT_FOLDER'] = os.environ.get('REPORT_FOLDER', '/app/reports')
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 * 1024   # 4 GB

ALLOWED_EXTENSIONS = {'mem', 'raw', 'lime', 'dmp', 'vmem'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def write_status(report_dir, status):
    os.makedirs(report_dir, exist_ok=True)
    with open(f"{report_dir}/status.txt", 'w') as f:
        f.write(status)


# ─── INLINE ANALYSIS (used when Jenkins is not reachable) ────────────────────

def run_analysis(dump_id, filename, report_dir):
    """Run full analysis pipeline in a background thread (fallback when Jenkins unavailable)."""
    os.makedirs(report_dir, exist_ok=True)
    try:
        update_dump_status(dump_id, 'ANALYZING')
        write_status(report_dir, 'ANALYZING')

        dump_path  = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_hash  = sha256_file(dump_path)

        with open(f"{report_dir}/integrity.log", 'w') as f:
            f.write(f"SHA256:{file_hash}\n")
        log_result(dump_id, 'integrity', f"{report_dir}/integrity.log")

        vol_version = detect_and_run_volatility(dump_id, dump_path, report_dir)
        update_dump_status(dump_id, 'CORRELATING', vol_version=vol_version)
        write_status(report_dir, 'CORRELATING')

        from pipeline import correlate
        correlate(dump_id, report_dir)
        log_result(dump_id, 'correlation', f"{report_dir}/correlation.json")

        write_status(report_dir, 'REPORTING')
        from report_gen import generate_report
        dump_info = get_dump_with_case(dump_id) or {}
        generate_report(
            dump_id, report_dir,
            case_name  = dump_info.get('case_name', 'Unknown Case'),
            analyst    = dump_info.get('analyst',   'Unknown'),
            filename   = dump_info.get('filename',  filename),
            vol_version= vol_version,
            sha256     = file_hash
        )
        log_result(dump_id, 'report_gen', f"{report_dir}/report.html")

        update_dump_status(dump_id, 'COMPLETE')
        write_status(report_dir, 'COMPLETE')

    except Exception as e:
        update_dump_status(dump_id, 'FAILED')
        write_status(report_dir, f'FAILED: {str(e)[:200]}')
        log_result(dump_id, 'pipeline', '', success=0, error_msg=str(e))
        print(f"[ERROR] Analysis failed for {dump_id}: {e}")


def detect_and_run_volatility(dump_id, dump_path, report_dir):
    """Try Vol3, fall back to Vol2, then demo data. Returns version string used."""
    in_docker = os.path.exists('/app')

    if try_volatility3(dump_path, report_dir, in_docker):
        return 'volatility3'
    if try_volatility2(dump_path, report_dir, in_docker):
        return 'volatility2'

    generate_demo_data(dump_id, dump_path, report_dir)
    return 'demo-mode'


def try_volatility3(dump_path, report_dir, in_docker):
    import subprocess
    prefix = ['docker', 'exec', 'memsuite_vol3'] if in_docker else []
    base   = prefix + ['python3', '-m', 'volatility3', '-f', dump_path]

    try:
        r = subprocess.run(base + ['windows.pslist'], capture_output=True, text=True, timeout=120)
        if r.returncode == 0 and r.stdout.strip():
            _write_plugin_output(report_dir, 'pslist.txt', r.stdout)

            for plugin, outfile in [
                (['windows.psscan'],  'psscan.txt'),
                (['windows.netscan'], 'netscan.txt'),
                (['windows.malfind'], 'malfind.txt'),
            ]:
                timeout = 180 if 'malfind' in plugin[0] else 120
                r2 = subprocess.run(base + plugin, capture_output=True, text=True, timeout=timeout)
                _write_plugin_output(report_dir, outfile, r2.stdout if r2.returncode == 0 else '')
            return True
    except Exception as e:
        print(f"[Vol3] failed: {e}")
    return False


def try_volatility2(dump_path, report_dir, in_docker):
    """
    FIX #2 — detect profile with imageinfo before running any plugin.
    FIX #1 — use bare plugin names (pslist, psscan, …) not windows.* prefixes.
    """
    import subprocess
    prefix = ['docker', 'exec', 'memsuite_vol2'] if in_docker else []
    base   = prefix + ['python', '/opt/volatility/vol.py', '-f', dump_path]

    try:
        # Sanity-check that vol2 is available
        r = subprocess.run(base + ['--info'], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return False

        # FIX #2 — always run imageinfo to get the right profile
        info = subprocess.run(base + ['imageinfo'], capture_output=True, text=True, timeout=90)
        profile = 'Win7SP1x86'   # safe fallback
        for line in info.stdout.splitlines():
            if 'Suggested Profile' in line and ':' in line:
                suggested = line.split(':', 1)[1].strip().split(',')[0].strip()
                if suggested:
                    profile = suggested
                    break

        print(f"[Vol2] using profile: {profile}")
        # Save detected profile for Jenkins/reporting to read
        with open(f"{report_dir}/profile.txt", 'w') as f:
            f.write(profile)

        base_p = base + [f'--profile={profile}']

        # FIX #1 — vol2 plugin names have no 'windows.' prefix
        for plugin, outfile in [
            ('pslist',  'pslist.txt'),
            ('psscan',  'psscan.txt'),
            ('netscan', 'netscan.txt'),
            ('malfind', 'malfind.txt'),
        ]:
            timeout = 180 if plugin == 'malfind' else 120
            r2 = subprocess.run(base_p + [plugin], capture_output=True, text=True, timeout=timeout)
            _write_plugin_output(
                report_dir, outfile,
                r2.stdout if r2.returncode == 0 else f'ERROR: {r2.stderr[:200]}'
            )
        return True

    except Exception as e:
        print(f"[Vol2] failed: {e}")
    return False


def _write_plugin_output(report_dir, filename, content):
    with open(os.path.join(report_dir, filename), 'w') as f:
        f.write(content)


def generate_demo_data(dump_id, dump_path, report_dir):
    """Generate realistic demo data for development/testing without a real Volatility install."""
    pslist_data = """Volatility Foundation Volatility Framework 2.6
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start
------------------ -------------------- ------ ------ ------ -------- ------ ------
0xfffffa8000ca0040 System                    4      0     89      573 ------      0
0xfffffa8001a15040 smss.exe                248      4      2       29 ------      0
0xfffffa8001d77060 csrss.exe               332    324      9      399      0      0
0xfffffa8001e00060 wininit.exe             380    324      3       76      0      0
0xfffffa8001e92060 csrss.exe               392    372      9      420      1      0
0xfffffa8001ed6060 winlogon.exe            428    372      4      114      1      0
0xfffffa8001f60550 services.exe            492    380      9      211      0      0
0xfffffa8001f91570 lsass.exe               500    380      7      597      0      0
0xfffffa8001f9b060 lsm.exe                 508    380     10      149      0      0
0xfffffa8002080060 svchost.exe             616    492     10      362      0      0
0xfffffa80020bb060 svchost.exe             680    492      7      274      0      0
0xfffffa8002103060 svchost.exe             776    492     20      499      0      0
0xfffffa8002265060 svchost.exe             852    492     33      878      0      0
0xfffffa80022cd060 svchost.exe             988    492     21      490      0      0
0xfffffa80023e7060 svchost.exe            1080    492     24      377      0      0
0xfffffa80023fd390 spoolsv.exe            1220    492     13      277      0      0
0xfffffa8002453060 svchost.exe            1256    492     18      306      0      0
0xfffffa80024f8060 cmd.exe                1364    852      1       20      0      0
0xfffffa8002510b30 taskhost.exe           1508    492      8      161      1      0
0xfffffa80025ba060 dwm.exe                1580    852      4       72      1      0
0xfffffa8002676b30 explorer.exe           1692   1664     21      879      1      0
0xfffffa8002703b30 VBoxTray.exe           1844   1692      9      140      1      0
0xfffffa80027a6b30 SearchIndexer.         2104    492     14      666      0      0
0xfffffa8002805470 wmpnetwk.exe           2248    492      9      224      0      0
0xfffffa8002904830 notepad.exe            2616   1692      1       57      1      0
"""
    psscan_data = pslist_data + (
        "0xfffffa8002a77430 svchost.exe             416    492      6       95      0      0\n"
        "0xfffffa8002b44060 WmiPrvSE.exe           2780    616      8      130      0      0\n"
        "0xfffffa8002c12300 mim.exe                3012   1692      2       47      1      0\n"
        "0xfffffa8002d08060 nc.exe                 3156   3012      1       18      0      0\n"
    )
    netscan_data = (
        "Proto  LocalAddr       LocalPort ForeignAddr      ForeignPort State            Pid   Owner\n"
        "TCPv4  192.168.1.105   49200     203.0.113.42     4444        ESTABLISHED      3156  nc.exe\n"
        "TCPv4  192.168.1.105   49201     10.10.10.50      443         ESTABLISHED      2780  WmiPrvSE.exe\n"
        "TCPv4  0.0.0.0         445       0.0.0.0          0           LISTENING        4     System\n"
        "TCPv4  0.0.0.0         3389      0.0.0.0          0           LISTENING        1080  svchost.exe\n"
    )
    malfind_data = (
        "Process: mim.exe Pid: 3012 Address: 0x3f0000\n"
        "Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE\n"
        "Flags: PrivateMemory: 1, Protection: 6\n\n"
        "4d 5a 90 00 03 00 00 00  MZ......\n\n"
        "Process: nc.exe Pid: 3156 Address: 0x400000\n"
        "Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE\n"
        "Flags: PrivateMemory: 1, Protection: 6\n\n"
        "4d 5a e8 00 00 00 00 5b  MZ.....[\\n"
    )

    for fname, content in [
        ('pslist.txt',  pslist_data),
        ('psscan.txt',  psscan_data),
        ('netscan.txt', netscan_data),
        ('malfind.txt', malfind_data),
    ]:
        _write_plugin_output(report_dir, fname, content)


def trigger_jenkins(dump_id, filename):
    """Trigger the memsuite-analysis Jenkins job via its API."""
    try:
        import requests as req
        token = os.environ.get('JENKINS_TOKEN', '')
        base  = 'http://memsuite_jenkins:8080'
        auth  = ('admin', token)

        # Try to get a CSRF crumb (some Jenkins configs need it, some don't)
        headers = {}
        try:
            crumb_r = req.get(f'{base}/crumbIssuer/api/json', auth=auth, timeout=3)
            if crumb_r.status_code == 200:
                cd = crumb_r.json()
                headers[cd['crumbRequestField']] = cd['crumb']
        except Exception:
            pass  # CSRF disabled in JCasC — fine to continue without crumb

        r = req.post(
            f'{base}/job/memsuite-analysis/buildWithParameters',
            params={'DUMP_ID': dump_id, 'DUMP_FILE': filename, 'VOL_VERSION': 'auto'},
            auth=auth,
            headers=headers,
            timeout=5
        )
        r.raise_for_status()
        print(f'[Jenkins] triggered build for {dump_id} — HTTP {r.status_code}')
    except Exception as e:
        print(f'[Jenkins] trigger failed: {e}')


# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/cases', methods=['GET'])
def list_cases():
    return jsonify(get_all_cases())


@app.route('/api/cases', methods=['POST'])
def create_new_case():
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Case name required'}), 400
    case_id = str(uuid.uuid4())
    create_case(case_id, data.get('name', ''), data.get('analyst', ''), data.get('description', ''))
    return jsonify({'case_id': case_id, 'name': data.get('name')})


@app.route('/api/cases/<case_id>', methods=['GET'])
def view_case(case_id):
    case = get_case(case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    return jsonify(case)


@app.route('/api/upload', methods=['POST'])
def upload_dump():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file     = request.files['file']
    case_id  = request.form.get('case_id', '')
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': f'Unsupported file type. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    dump_id     = str(uuid.uuid4())
    safe_name   = secure_filename(file.filename)
    stored_name = f"{dump_id[:8]}_{safe_name}"
    filepath    = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
    file.save(filepath)

    file_hash = sha256_file(filepath)
    create_dump(dump_id, case_id if case_id else None, stored_name, filepath, file_hash)

    report_dir = os.path.join(app.config['REPORT_FOLDER'], dump_id)
    os.makedirs(report_dir, exist_ok=True)
    write_status(report_dir, 'QUEUED')

    # Try Jenkins first; fall back to inline thread if unreachable
    jenkins_available = False
    try:
        import requests as req
        r = req.get("http://memsuite_jenkins:8080/", timeout=2)
        jenkins_available = r.status_code < 500
    except Exception:
        pass

    if jenkins_available:
        trigger_jenkins(dump_id, stored_name)
    else:
        t = threading.Thread(
            target=run_analysis,
            args=(dump_id, stored_name, report_dir),
            daemon=True
        )
        t.start()

    return jsonify({
        'dump_id':  dump_id,
        'sha256':   file_hash,
        'status':   'QUEUED',
        'filename': safe_name,
        'case_id':  case_id
    })


@app.route('/api/status/<dump_id>', methods=['GET'])
def check_status(dump_id):
    report_dir  = os.path.join(app.config['REPORT_FOLDER'], dump_id)
    status_path = f"{report_dir}/status.txt"
    if os.path.exists(status_path):
        with open(status_path) as f:
            status = f.read().strip()
        return jsonify({'status': status, 'dump_id': dump_id})
    # Fall back to DB
    d = get_dump(dump_id)
    if d:
        return jsonify({'status': d.get('status', 'QUEUED'), 'dump_id': dump_id})
    return jsonify({'status': 'NOT_FOUND'}), 404


# FIX #5 — internal endpoint so Jenkins post-failure hook can update DB status
@app.route('/api/internal/status', methods=['POST'])
def internal_status_update():
    """Called by Jenkins post-failure curl to keep DB in sync with status.txt."""
    data    = request.json or {}
    dump_id = data.get('dump_id', '').strip()
    status  = data.get('status', '').strip().upper()
    allowed = {'FAILED', 'COMPLETE', 'ANALYZING', 'CORRELATING', 'REPORTING', 'QUEUED'}
    if not dump_id or status not in allowed:
        return jsonify({'error': 'Invalid payload'}), 400
    update_dump_status(dump_id, status)
    return jsonify({'ok': True})


@app.route('/api/results/<dump_id>', methods=['GET'])
def get_dump_results(dump_id):
    dump = get_dump_with_case(dump_id)
    if not dump:
        return jsonify({'error': 'Dump not found'}), 404
    findings    = get_findings(dump_id)
    results     = get_results(dump_id)
    corr_path   = os.path.join(app.config['REPORT_FOLDER'], dump_id, 'correlation.json')
    correlation = {}
    if os.path.exists(corr_path):
        with open(corr_path) as f:
            correlation = json.load(f)
    return jsonify({
        'dump':        dump,
        'findings':    findings,
        'results':     results,
        'correlation': correlation
    })


@app.route('/api/report/<dump_id>/html', methods=['GET'])
def view_report_html(dump_id):
    report_path = os.path.join(app.config['REPORT_FOLDER'], dump_id, 'report.html')
    if os.path.exists(report_path):
        with open(report_path) as f:
            content = f.read()
        return Response(content, mimetype='text/html')
    return jsonify({'error': 'Report not ready'}), 404


@app.route('/api/report/<dump_id>/pdf', methods=['GET'])
def download_report_pdf(dump_id):
    report_path = os.path.join(app.config['REPORT_FOLDER'], dump_id, 'report.pdf')
    if os.path.exists(report_path):
        dump  = get_dump(dump_id)
        fname = f"memsuite_report_{dump_id[:8]}.pdf"
        return send_file(report_path, as_attachment=True, download_name=fname,
                         mimetype='application/pdf')
    return jsonify({'error': 'PDF report not ready'}), 404


@app.route('/api/report/<dump_id>/generate', methods=['POST'])
def regenerate_report(dump_id):
    """Force-regenerate report for a given dump_id."""
    report_dir = os.path.join(app.config['REPORT_FOLDER'], dump_id)
    if not os.path.exists(report_dir):
        return jsonify({'error': 'No analysis data found for this dump'}), 404
    try:
        from report_gen import generate_report
        dump_info         = get_dump_with_case(dump_id) or {}
        html_path, pdf_path = generate_report(
            dump_id, report_dir,
            case_name   = dump_info.get('case_name', 'Unknown Case'),
            analyst     = dump_info.get('analyst',   'Unknown'),
            filename    = dump_info.get('filename',  ''),
            vol_version = dump_info.get('vol_version', ''),
            sha256      = dump_info.get('sha256',    '')
        )
        return jsonify({'html': bool(html_path), 'pdf': bool(pdf_path), 'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)