#!/usr/bin/env python3
"""Regression tests for Cargo-reported ksud bindings paths and UAPI5 rejection."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import bakasu_35212_uapi as audit


class BindingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        # Deliberately outside every assumed Cargo release/build layout.
        self.out = self.root / 'intermediates/custom-cargo-layout/ksud-generated'
        self.out.mkdir(parents=True)
        self.bindings = self.out / 'bindings.rs'
        self.valid = ('pub const KERNEL_SU_UAPI_VERSION: __u32 = 5;\n'
                      'pub const EVENT_SERVICES: _bindgen_ty_4 = 4;\n')
        self.bindings.write_text(self.valid, encoding='utf-8')
        self.messages_path = self.root / 'ksud-build-messages.jsonl'
        self.package = 'path+file:///checkout/userspace/ksud#0.1.0'
        self.messages = [
            dict(reason='compiler-artifact', package_id=self.package,
                 manifest_path=str(self.root / 'userspace/ksud/Cargo.toml'),
                 target=dict(kind=['custom-build']), fresh=False),
            dict(reason='build-script-executed', package_id=self.package, out_dir=str(self.out)),
            dict(reason='build-finished', success=True),
        ]

    def verify(self):
        self.messages_path.write_text('\n'.join(json.dumps(m) for m in self.messages) + '\n', encoding='utf-8')
        return audit.verify_bindings(self.root, self.messages_path)

    def test_uses_reported_out_dir_without_assuming_layout(self):
        result = self.verify()
        self.assertEqual(result['path'], str(self.bindings))
        self.assertEqual(result['package_id'], self.package)
        self.assertEqual(result['uapi_version'], 5)

    def test_accepts_real_bindgen_0732_output_without_rustfmt(self):
        self.valid = (Path(__file__).parent / 'fixtures/resukisu-35203-bindgen-0.73.2.rs').read_text(encoding='utf-8')
        self.bindings.write_text(self.valid, encoding='utf-8')
        result = self.verify()
        self.assertEqual(result['uapi_version'], 5)
        self.assertEqual(result['event_services'], 4)

    def test_rejects_stale_uapi_in_real_bindgen_output(self):
        text = (Path(__file__).parent / 'fixtures/resukisu-35203-bindgen-0.73.2.rs').read_text(encoding='utf-8')
        self.bindings.write_text(text.replace('KERNEL_SU_UAPI_VERSION : __u32 = 5 ;',
                                              'KERNEL_SU_UAPI_VERSION : __u32 = 4 ;'), encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'KERNEL_SU_UAPI_VERSION=5'):
            self.verify()

    def test_rejects_wrong_service_in_real_bindgen_output(self):
        text = (Path(__file__).parent / 'fixtures/resukisu-35203-bindgen-0.73.2.rs').read_text(encoding='utf-8')
        self.bindings.write_text(text.replace('EVENT_SERVICES : _bindgen_ty_26 = 4 ;',
                                              'EVENT_SERVICES : _bindgen_ty_26 = 3 ;'), encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'EVENT_SERVICES=4'):
            self.verify()

    def test_ignores_stale_bindings_in_the_old_assumed_directory(self):
        stale = self.root / 'userspace/ksud/target/aarch64-linux-android/release/build/ksud-stale/out/bindings.rs'
        stale.parent.mkdir(parents=True)
        stale.write_text(self.valid.replace('= 5;', '= 4;'), encoding='utf-8')
        self.assertEqual(self.verify()['path'], str(self.bindings))

    def test_does_not_substitute_unreported_valid_bindings(self):
        other = self.out.parent / 'unreported/bindings.rs'
        other.parent.mkdir()
        other.write_text(self.valid, encoding='utf-8')
        self.bindings.write_text(self.valid.replace('= 5;', '= 4;'), encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'KERNEL_SU_UAPI_VERSION=5'):
            self.verify()

    def test_rejects_missing_or_wrong_service_constant(self):
        for text in (self.valid.splitlines()[0], self.valid.replace('= 4;', '= 3;')):
            self.bindings.write_text(text, encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'EVENT_SERVICES=4'):
                self.verify()

    def test_requires_this_build_messages(self):
        with self.assertRaisesRegex(RuntimeError, 'requires messages'):
            audit.verify_bindings(self.root)

    def test_rejects_missing_bindings(self):
        self.bindings.unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_rejects_failed_or_missing_build_completion(self):
        self.messages[-1]['success'] = False
        with self.assertRaisesRegex(RuntimeError, 'successful ksud build'):
            self.verify()
        self.messages.pop()
        with self.assertRaisesRegex(RuntimeError, 'successful ksud build'):
            self.verify()

    def test_rejects_dependency_build_script(self):
        self.messages[0]['manifest_path'] = str(self.root / 'dependency/Cargo.toml')
        with self.assertRaisesRegex(RuntimeError, 'local ksud build script'):
            self.verify()

    def test_rejects_missing_or_ambiguous_ksud_out_dir(self):
        original = self.messages[1]
        self.messages[1] = dict(reason='build-script-executed', package_id='another-package', out_dir=str(self.out))
        with self.assertRaisesRegex(RuntimeError, 'exactly one ksud OUT_DIR'):
            self.verify()
        self.messages[1] = original
        self.messages.insert(2, dict(original, out_dir=str(self.out.parent)))
        with self.assertRaisesRegex(RuntimeError, 'exactly one ksud OUT_DIR'):
            self.verify()

    def test_recorded_subprocess_stream_attests_bindings_before_ndk_filter(self):
        payload = '\n'.join(json.dumps(m) for m in self.messages) + '\n'
        result = run_capture(self.messages_path, payload.encode('utf-8'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload.encode('utf-8'))
        # cargo-ndk 4.1.2 does not forward these messages to its own stdout.
        forwarded = [m for m in audit.cargo_messages(result.stdout.decode().splitlines())
                     if m['reason'] in ('compiler-message', 'text-line')]
        self.assertEqual(forwarded, [])
        self.assertEqual(audit.verify_bindings(self.root, self.messages_path)['path'], str(self.bindings))


def run_capture(recording, payload, status=0, cargo_args=None, executable=None):
    environment = os.environ.copy()
    environment.update(RESUKISU_REAL_CARGO=str(Path(sys.executable).resolve()),
                       RESUKISU_CARGO_MESSAGES=str(recording),
                       CAPTURE_PAYLOAD=payload.hex(), CAPTURE_STATUS=str(status),
                       _CARGO_NDK_LINK_TARGET='--target=aarch64-linux-android26',
                       CC_aarch64_linux_android='/unchanged/ndk/clang')
    script = (
        'import os,sys; '
        'assert os.environ["CARGO"] == os.environ["RESUKISU_REAL_CARGO"]; '
        'assert os.environ["_CARGO_NDK_LINK_TARGET"] == "--target=aarch64-linux-android26"; '
        'assert os.environ["CC_aarch64_linux_android"] == "/unchanged/ndk/clang"; '
        'sys.stdout.buffer.write(bytes.fromhex(os.environ["CAPTURE_PAYLOAD"])); '
        'sys.stdout.buffer.flush(); '
        'sys.stderr.buffer.write(b"original compiler diagnostic\\n"); '
        'sys.exit(int(os.environ["CAPTURE_STATUS"]))'
    )
    arguments = ['build', '--locked', '--release', '--message-format', 'json-render-diagnostics']
    launcher = ([str(executable)] if executable is not None else
                [sys.executable, str(Path(__file__).with_name('capture-resukisu-cargo.py'))])
    return subprocess.run(
        [*launcher, '-c', script, *(arguments if cargo_args is None else cargo_args)],
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.recording = Path(self.temp.name) / 'build-messages.jsonl'

    def test_preserves_all_stdout_bytes_stderr_environment_and_success(self):
        payload = b'{"reason":"build-finished","success":true}\nraw:\x00\xff\n'
        result = run_capture(self.recording, payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(self.recording.read_bytes(), payload)
        self.assertEqual(result.stderr, b'original compiler diagnostic\n')

    def test_propagates_build_failure_and_keeps_failed_messages(self):
        payload = b'{"reason":"build-finished","success":false}\n'
        result = run_capture(self.recording, payload, status=101)
        self.assertEqual(result.returncode, 101, result.stderr)
        self.assertEqual(self.recording.read_bytes(), payload)

    def test_metadata_passes_through_without_creating_build_receipt(self):
        payload = b'{"packages":[]}\n'
        result = run_capture(self.recording, payload, cargo_args=['metadata', '--no-deps'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload)
        self.assertFalse(self.recording.exists())

    def test_refuses_to_overwrite_stale_or_duplicate_capture(self):
        original = b'previous build stream'
        self.recording.write_bytes(original)
        result = run_capture(self.recording, b'new build stream')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(self.recording.read_bytes(), original)

    def test_rejects_build_without_json_output(self):
        result = run_capture(self.recording, b'not JSON', cargo_args=['build', '--release'])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Expected cargo-ndk JSON', result.stderr)
        self.assertFalse(self.recording.exists())

    def test_accepts_single_joined_message_format_argument(self):
        result = run_capture(self.recording, b'raw JSON\n',
                             cargo_args=['build', '--message-format=json-render-diagnostics'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.recording.read_bytes(), b'raw JSON\n')

    @unittest.skipIf(os.name == 'nt', 'Executable shebang is a Linux runner contract')
    def test_linux_executable_shebang_for_cargo_ndk_subprocess(self):
        executable = self.recording.with_name('capture-cargo')
        executable.write_bytes(Path(__file__).with_name('capture-resukisu-cargo.py').read_bytes())
        executable.chmod(0o755)
        result = run_capture(self.recording, b'Linux executable stream\n', executable=executable)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.recording.read_bytes(), b'Linux executable stream\n')

    @unittest.skipUnless(os.environ.get('RESUKISU_TEST_CARGO_NDK'), 'Requires installed cargo-ndk and NDK')
    def test_pinned_cargo_ndk_exposes_internal_build_messages(self):
        # Exercise the actual installed wrapper with real Cargo metadata and a
        # tiny stub build. No Android compilation or dependencies are needed.
        root = self.recording.parent
        (root / 'Cargo.toml').write_text(
            '[package]\nname="capture-smoke"\nversion="0.0.0"\nedition="2024"\n'
            '[[bin]]\nname="capture-smoke"\npath="main.rs"\n', encoding='utf-8')
        (root / 'main.rs').write_text('fn main() {}\n', encoding='utf-8')
        executable = root / 'capture-cargo'
        executable.write_bytes(Path(__file__).with_name('capture-resukisu-cargo.py').read_bytes())
        executable.chmod(0o755)
        fake_cargo = root / 'stub-cargo'
        fake_cargo.write_text('''#!/usr/bin/env python3
import json, os, subprocess, sys
args = sys.argv[1:]
if 'build' not in args:
    environment = os.environ.copy()
    environment['CARGO'] = os.environ['RESUKISU_TEST_REAL_CARGO']
    sys.exit(subprocess.call([environment['CARGO'], *args], env=environment))
assert '--locked' in args and '--release' in args
assert args[args.index('--target') + 1] == 'aarch64-linux-android'
assert os.environ['_CARGO_NDK_LINK_TARGET'] == '--target=aarch64-linux-android26'
assert os.environ['_CARGO_NDK_LINK_CLANG']
assert os.environ['BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android']
print(json.dumps(dict(reason='build-script-executed', package_id='capture-smoke 0.0.0',
                     linked_libs=[], linked_paths=[], cfgs=[], env=[],
                     out_dir=os.environ['CAPTURE_SMOKE_OUT_DIR'])))
print(json.dumps(dict(reason='build-finished', success=True)))
''', encoding='utf-8')
        fake_cargo.chmod(0o755)
        environment = os.environ.copy()
        environment.update(CARGO=str(executable), RESUKISU_REAL_CARGO=str(fake_cargo),
                           RESUKISU_CARGO_MESSAGES=str(self.recording),
                           CAPTURE_SMOKE_OUT_DIR=str(root / 'generated'))
        ndk_binary = Path(os.environ['RESUKISU_TEST_CARGO_NDK']).resolve(strict=True)
        environment['PATH'] = str(ndk_binary.parent) + os.pathsep + environment['PATH']
        ndk_args = ['ndk', '-P', '26', '-t', 'arm64-v8a', 'build', '--locked', '--release']
        # Reproduce the exact CI failure: PATH finds the binary, but version
        # 4.1.2 canonicalizes the bare argv[0] relative to the package directory.
        bare = subprocess.run(['cargo-ndk', *ndk_args], cwd=root, env=environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertNotEqual(bare.returncode, 0)
        self.assertIn(b'Failed to canonicalize absolute path to cargo-ndk', bare.stdout + bare.stderr)
        self.assertFalse(self.recording.exists())
        result = subprocess.run(
            [str(ndk_binary), *ndk_args], cwd=root, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        messages = list(audit.cargo_messages(self.recording.read_text().splitlines()))
        self.assertEqual([m['reason'] for m in messages], ['build-script-executed', 'build-finished'])
        self.assertEqual(messages[0]['out_dir'], str(root / 'generated'))
        self.assertIs(messages[1]['success'], True)
        self.assertNotIn(b'build-script-executed', result.stdout)


if __name__ == '__main__':
    unittest.main()
