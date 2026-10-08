#!/usr/bin/env python3
"""Compile the exact optional ksud functions against deterministic Rust mocks."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import uuid

HERE=Path(__file__).resolve().parent
def extract(text,name):
    masked=re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',lambda m:re.sub(r'[^\n]',' ',m[0]),text,flags=re.S)
    matches=list(re.finditer(r'^(?:pub )?fn '+name+r'\([^;{]*\)\s*(?:->[^;{]+)?\{',masked,re.M))
    assert len(matches)==1,(name,len(matches))
    m=matches[0];pos=m.end();depth=1
    while depth:
        depth+=(masked[pos]=='{')-(masked[pos]=='}');pos+=1
    return text[m.start():pos]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ksu',type=Path,required=True)
    p.add_argument('--work-dir',type=Path,required=True)
    p.add_argument('--rustc',default='rustc')
    p.add_argument('--gnu-lld',type=Path,help='Windows GNU host: ld.lld.exe with Rust self-contained CRT')
    a=p.parse_args();root=a.work_dir.resolve()/('ksud-'+uuid.uuid4().hex);root.mkdir(parents=True)
    calls=(a.ksu/'userspace/ksud/src/android/ksucalls.rs').read_text()
    su=(a.ksu/'userspace/ksud/src/android/su.rs').read_text()
    unload=(a.ksu/'userspace/ksud/src/android/unload.rs').read_text()
    body=extract(su,'root_shell')
    assert body.index('claim_inherited_driver_fd()') < body.index('env::args()')
    assert 'KERNEL_SU_UAPI_VERSION = 2;' in (a.ksu/'uapi/supercall.h').read_text()
    code=(HERE/'ksud.rs.in').read_text()
    for key,value in {'SCAN':extract(calls,'scan_driver_fd'),'CLAIM':extract(calls,'claim_inherited_driver_fd'),
                      'WRAP':extract(su,'wrap_tty'),'UNLOAD':extract(unload,'is_ksu_fd_name')}.items():
        assert code.count(f'@@{key}@@')==1;code=code.replace(f'@@{key}@@',value)
    cases=['scan-priority','scan-legacy','scan-fake-name','scan-empty','scan-denied','claim-cached','unload-names',
           'tty-ok','tty-not-tty','tty-eacces','wrapper-not-tty','wrapper-failure','dup-failure']
    def compile_run(text,name,mutant=False):
        src=root/(name+'.rs');src.write_text(text,encoding='utf-8');exe=root/(name+('.exe' if a.gnu_lld else ''))
        args=[a.rustc,'--edition=2024',str(src),'-o',str(exe)]
        if a.gnu_lld:args+=['-C','linker='+str(a.gnu_lld.resolve()),'-C','linker-flavor=ld','-C','link-self-contained=yes']
        r=subprocess.run(args,capture_output=True,text=True)
        if r.returncode:raise RuntimeError(r.stderr)
        failures=[]
        for case in cases:
            r=subprocess.run([str(exe),case],capture_output=True,text=True)
            if r.returncode:failures.append(case)
        if bool(failures)!=mutant:raise RuntimeError(f'{name}: unexpected failures {failures}')
        print(f'{name}: '+(f'mutation rejected by {failures}' if mutant else f'{len(cases)} scenarios passed'))
    compile_run(code,'ksud-production')
    mutations={
        'mutant-eacces':('io::Error::last_os_error().raw_os_error() != Some(libc::EACCES)','true'),
        'mutant-dup-leak':('let dup_errno = unsafe { *libc::__errno() };\n        unsafe { libc::close(new_fd) };','let dup_errno = unsafe { *libc::__errno() };'),
        'mutant-fd-name':('target_str == DRIVER_FD_NAME','target_str.contains("[ksu_driver]")'),
        'mutant-fd-priority':('return Ok(Some(fd_num));','continue;'),
    }
    for name,(old,new) in mutations.items():
        assert code.count(old)==1,name;compile_run(code.replace(old,new),name,True)
    (root/'result.json').write_text(json.dumps({'scenarios_passed':len(cases),'mutations_rejected':len(mutations),
       'claim_before_arguments':True,'uapi':2,'limitation':'Exact functions with mocked libc, procfs and driver calls; no complete Android ksud or APK build.'},indent=2)+'\n')
    print(f'PASS: optional ksud Rust source tests; results: {root}')

if __name__=='__main__':main()
