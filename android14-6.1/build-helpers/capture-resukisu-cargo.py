#!/usr/bin/env python3
"""Tap Cargo stdout before cargo-ndk 4.1.2 consumes its JSON messages.

Use this as CARGO when invoking cargo-ndk directly. Cargo's subcommand launcher
overwrites CARGO, so `CARGO=... cargo ndk` cannot install this tap. The NDK
wrapper still supplies all compiler, linker, bindgen and Android settings.
"""
import os
from pathlib import Path
import subprocess
import sys


def main(args):
    real_cargo = Path(os.environ['RESUKISU_REAL_CARGO']).resolve(strict=True)
    if real_cargo == Path(__file__).resolve():
        raise RuntimeError('Cargo capture cannot invoke itself')
    environment = os.environ.copy()
    environment['CARGO'] = str(real_cargo)
    command = [str(real_cargo), *args]
    if 'build' not in args:
        # cargo-ndk also invokes cargo metadata; never mix that JSON into the
        # one build stream used to attest the generated bindings.
        return subprocess.call(command, env=environment)
    formats = [arg.split('=', 1)[1] for arg in args
               if arg.startswith('--message-format=')]
    formats += [args[i + 1] for i, arg in enumerate(args[:-1])
                if arg == '--message-format']
    if formats != ['json-render-diagnostics']:
        raise RuntimeError('Expected cargo-ndk JSON build message format')
    # Exclusive creation rejects stale receipts and a second build invocation.
    with Path(os.environ['RESUKISU_CARGO_MESSAGES']).open('xb') as recording:
        with subprocess.Popen(command, env=environment, stdout=subprocess.PIPE) as child:
            for chunk in iter(lambda: child.stdout.read1(65536), b''):
                recording.write(chunk)
                recording.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            status = child.wait()
    return status if status >= 0 else 128 - status


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, KeyError, RuntimeError) as error:
        print(f'Cargo capture failed: {error}', file=sys.stderr)
        sys.exit(1)
