#!/usr/bin/env python3
# ======================================================================
# verify_sandbox_conformance.py — version 1.0
# Executable reference sandbox self-test. Not production certification.
# ======================================================================
from __future__ import annotations
import argparse, json, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from trusted_execution import run_command


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument('--output'); args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='aps_sandbox_conformance_') as raw:
        root=Path(raw); subprocess.run(['git','init','-q','-b','main'],cwd=root,check=True)
        subprocess.run(['git','config','user.email','sandbox@example.invalid'],cwd=root,check=True)
        subprocess.run(['git','config','user.name','Sandbox Conformance'],cwd=root,check=True)
        secret=root.parent/'sandbox-secret.txt'; secret.write_text('secret',encoding='utf-8'); secret.chmod(0o600)
        probe=root/'probe.py'; probe.write_text('''import json, os, socket, subprocess, sys\nfrom pathlib import Path\nr={"key":os.environ.get("APS_TRUSTED_ATTESTATION_KEY"),"proc_entries":len(list(Path("/proc").glob("[0-9]*")))}\ntry: r["deny_read"]="VALUE:"+Path(sys.argv[1]).read_text()\nexcept Exception as e: r["deny_read"]="BLOCKED:"+type(e).__name__\ntry: socket.socket().connect(("1.1.1.1",53)); r["network"]="SUCCEEDED"\nexcept Exception as e: r["network"]="BLOCKED:"+type(e).__name__\nprint(json.dumps(r,sort_keys=True))\n''',encoding='utf-8')
        subprocess.run(['git','add','.'],cwd=root,check=True); subprocess.run(['git','commit','-qm','probe'],cwd=root,check=True)
        head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
        evidence=run_command(root,[sys.executable,'probe.py',str(secret)],check_id='sandbox_conformance',head_sha=head,deny_paths=[str(secret)],require_sandbox=True)
        observed=json.loads(evidence['stdout'].strip()) if evidence['stdout'].strip() else {}
        findings=[]
        if evidence['status']!='PASS': findings.extend(evidence['findings'])
        if observed.get('key') is not None: findings.append('SANDBOX_SECRET_EXPOSED')
        if observed.get('proc_entries') != 0: findings.append('SANDBOX_HOST_PROC_EXPOSED')
        if observed.get('deny_read') == 'VALUE:secret': findings.append('SANDBOX_DENY_PATH_EXPOSED')
        if not str(observed.get('network','')).startswith('BLOCKED:'): findings.append('SANDBOX_NETWORK_EXPOSED')
        report={'status':'PASS' if not findings else 'FAIL','sandbox_mode':evidence.get('sandbox_mode'),'findings':findings,'observed':observed}
        if args.output: Path(args.output).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print(json.dumps(report,indent=2,sort_keys=True))
        return 0 if not findings else 1

if __name__ == '__main__': raise SystemExit(main())
