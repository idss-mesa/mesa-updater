"""install-tools.sh against a local HTTP server: no network, no real tools."""
import functools
import hashlib
import http.server
import io
import os
import platform
import subprocess
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "install-tools.sh"
REAL_LOCK = ROOT / "ci" / "tools.lock"
HELLO = (ROOT / "tests" / "fixtures" / "tools" / "hello.sh").read_bytes()
HOST = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
OTHER = "arm64" if HOST == "amd64" else "amd64"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def tar_gz(members):
    """members: name -> bytes (regular file, mode 0755) or ('link', target)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            if isinstance(content, tuple):
                info.type, info.linkname = tarfile.SYMTYPE, content[1]
                tar.addfile(info)
            else:
                info.size, info.mode = len(content), 0o755
                tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


class InstallToolsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.www = self.tmp / "www"
        self.www.mkdir()
        self.dest = self.tmp / "dest"
        self.lock = self.tmp / "tools.lock"
        self.requests = []

        test = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, fmt, *args):
                test.requests.append(self.path)

        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), functools.partial(Handler, directory=str(self.www)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.base = f"http://127.0.0.1:{server.server_address[1]}"

    def serve(self, name, data):
        (self.www / name).write_bytes(data)
        return f"{self.base}/{name}", sha256(data)

    def write_lock(self, *rows):
        lines = ["# name\tversion\tarch\turl\tsha256\tmember", ""]
        lines += ["\t".join(row) for row in rows]
        self.lock.write_text("\n".join(lines) + "\n")

    def run_script(self, *args, machine=None):
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
        env["TOOLS_LOCK"] = str(self.lock)
        if machine:
            stubs = self.tmp / "stubs"
            stubs.mkdir(exist_ok=True)
            uname = stubs / "uname"
            uname.write_text(f"#!/bin/sh\necho {machine}\n")
            uname.chmod(0o755)
            env["PATH"] = f"{stubs}:{env['PATH']}"
        return subprocess.run([str(SCRIPT), "--dest", str(self.dest), *args],
                              capture_output=True, text=True, env=env, cwd=self.tmp)

    def installed(self):
        return sorted(p.name for p in self.dest.iterdir())

    def run_ok(self, *args):
        result = self.run_script(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def assert_nothing_installed(self, result, code, *needles):
        self.assertEqual(result.returncode, code, result.stderr)
        for needle in needles:
            self.assertIn(needle, result.stderr)
        self.assertFalse(self.dest.exists(), "nothing may be left in the destination")

    def test_bare_binary(self):
        url, digest = self.serve("hello-linux", HELLO)
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "-"),
                        ("hello", "1.2.3", OTHER, f"{self.base}/absent", "0" * 64, "-"))
        result = self.run_script("hello")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.installed(), ["hello"])
        self.assertEqual((self.dest / "hello").read_bytes(), HELLO)
        self.assertEqual(subprocess.check_output([str(self.dest / "hello")], text=True), "hello 1.2.3\n")
        self.assertEqual(self.requests, ["/hello-linux"])

    def test_tar_gz_member(self):
        archive = tar_gz({"hello-1.2.3/README.md": b"docs\n", "hello-1.2.3/bin/hello": HELLO,
                          "hello-1.2.3/bin/other": b"not wanted\n"})
        url, digest = self.serve("hello.tar.gz", archive)
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "hello-1.2.3/bin/hello"))
        result = self.run_script("hello")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.installed(), [".archives", "hello"])
        self.assertEqual(subprocess.check_output([str(self.dest / "hello")], text=True), "hello 1.2.3\n")
        # the archive is kept: it is what the lock's hash can be checked against later
        self.assertEqual([(p.name, sha256(p.read_bytes())) for p in (self.dest / ".archives").iterdir()],
                         [("hello.tar.gz", digest)])

    def test_installs_everything_by_default_then_skips_what_is_installed(self):
        url1, digest1 = self.serve("hello-linux", HELLO)
        url2, digest2 = self.serve("bye.tar.gz", tar_gz({"bye": b"#!/bin/sh\necho bye 0.1\n"}))
        self.write_lock(("hello", "1.2.3", HOST, url1, digest1, "-"), ("bye", "0.1", HOST, url2, digest2, "bye"))
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.installed(), [".archives", "bye", "hello"])
        self.assertEqual(sorted(self.requests), ["/bye.tar.gz", "/hello-linux"])

        self.assertEqual(self.run_ok(), "hello 1.2.3: already installed\nbye 0.1: already installed\n")
        self.assertEqual(len(self.requests), 2, "an installed tool is not downloaded again")

        # A new pin replaces the binary and its manifest line; the other tool stays.
        url3, digest3 = self.serve("hello-2", b"#!/bin/sh\necho hello 2.0.0\n")
        self.write_lock(("hello", "2.0.0", HOST, url3, digest3, "-"), ("bye", "0.1", HOST, url2, digest2, "bye"))
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(subprocess.check_output([str(self.dest / "hello")], text=True), "hello 2.0.0\n")
        self.assertEqual(subprocess.check_output([str(self.dest / "bye")], text=True), "bye 0.1\n")
        self.assertEqual(self.requests[2:], ["/hello-2"])

        # ... and a new archive replaces the kept one
        url4, digest4 = self.serve("bye-2.tar.gz", tar_gz({"bye": b"#!/bin/sh\necho bye 0.2\n"}))
        self.write_lock(("hello", "2.0.0", HOST, url3, digest3, "-"), ("bye", "0.2", HOST, url4, digest4, "bye"))
        self.assertEqual(self.run_ok(), f"hello 2.0.0: already installed\nbye 0.2: installed {self.dest}/bye\n")
        self.assertEqual(subprocess.check_output([str(self.dest / "bye")], text=True), "bye 0.2\n")
        self.assertEqual([p.name for p in (self.dest / ".archives").iterdir()], ["bye.tar.gz"])
        self.assertEqual(self.installed(), [".archives", "bye", "hello"])
        self.assertEqual(self.run_ok().count("already installed"), 2)
        self.assertEqual(self.requests[3:], ["/bye-2.tar.gz"])

    def test_reinstalls_when_the_binary_is_gone(self):
        url, digest = self.serve("hello-linux", HELLO)
        url2, digest2 = self.serve("bye.tar.gz", tar_gz({"bye": b"#!/bin/sh\necho bye 0.1\n"}))
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "-"), ("bye", "0.1", HOST, url2, digest2, "bye"))
        self.run_ok()
        (self.dest / "hello").unlink()
        (self.dest / "bye").unlink()
        self.assertEqual(self.run_ok().count(": installed "), 2)
        for name in ("hello", "bye"):
            self.assertTrue(os.access(self.dest / name, os.X_OK))
        # the bare binary is fetched again, the other comes out of the kept (and re-verified) archive
        self.assertEqual(self.requests, ["/hello-linux", "/bye.tar.gz", "/hello-linux"])

    def test_replaced_bare_binary_is_not_reported_as_installed(self):
        url, digest = self.serve("hello-linux", HELLO)
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "-"))
        self.run_ok()
        evil = self.dest / "hello"
        evil.write_text("#!/bin/sh\necho EVIL\n")  # same name, same mode, anything else in --dest untouched
        self.assertEqual(self.run_ok(), f"hello 1.2.3: installed {self.dest}/hello\n")
        self.assertEqual((self.dest / "hello").read_bytes(), HELLO)
        self.assertEqual(self.run_ok(), "hello 1.2.3: already installed\n")
        # a symlink in its place is not the tool either, whatever it points to
        evil.unlink()
        other = self.tmp / "elsewhere"
        other.write_bytes(HELLO)
        other.chmod(0o755)
        evil.symlink_to(other)
        self.assertEqual(self.run_ok(), f"hello 1.2.3: installed {self.dest}/hello\n")
        self.assertFalse(evil.is_symlink())
        # the mode is part of "installed"
        evil.chmod(0o644)
        self.assertIn(": installed ", self.run_ok())
        self.assertTrue(os.access(evil, os.X_OK))

    def test_replaced_archive_member_is_not_reported_as_installed(self):
        archive = tar_gz({"hello-1.2.3/bin/hello": HELLO})
        url, digest = self.serve("hello.tar.gz", archive)
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "hello-1.2.3/bin/hello"))
        self.run_ok()
        kept = self.dest / ".archives" / "hello.tar.gz"
        evil = tar_gz({"hello-1.2.3/bin/hello": b"#!/bin/sh\necho EVIL\n"})

        (self.dest / "hello").write_text("#!/bin/sh\necho EVIL\n")
        self.assertEqual(self.run_ok(), f"hello 1.2.3: installed {self.dest}/hello\n")
        self.assertEqual((self.dest / "hello").read_bytes(), HELLO)
        self.assertEqual(len(self.requests), 1, "restored from the kept archive")

        # binary and kept archive replaced together: the lock's hash is not in --dest
        (self.dest / "hello").write_text("#!/bin/sh\necho EVIL\n")
        kept.write_bytes(evil)
        self.assertEqual(self.run_ok(), f"hello 1.2.3: installed {self.dest}/hello\n")
        self.assertEqual(((self.dest / "hello").read_bytes(), kept.read_bytes()), (HELLO, archive))
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.run_ok(), "hello 1.2.3: already installed\n")
        self.assertEqual(len(self.requests), 2)

        # a kept archive with another hash is never unpacked: with the download gone the run fails
        kept.write_bytes(evil)
        (self.www / "hello.tar.gz").unlink()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn("download failed", result.stderr)
        self.assertEqual((self.dest / "hello").read_bytes(), HELLO)

    def test_files_from_an_older_install_tools_are_not_trusted(self):
        # The first version recorded "name<TAB>version<TAB>sha" in .installed and skipped on that alone.
        url, digest = self.serve("hello.tar.gz", tar_gz({"hello": HELLO}))
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "hello"))
        self.dest.mkdir()
        (self.dest / ".installed").write_text(f"hello\t1.2.3\t{digest}\n")
        (self.dest / "hello").write_text("#!/bin/sh\necho EVIL\n")
        (self.dest / "hello").chmod(0o755)
        self.assertEqual(self.run_ok(), f"hello 1.2.3: installed {self.dest}/hello\n")
        self.assertEqual((self.dest / "hello").read_bytes(), HELLO)

    def test_hash_mismatch_leaves_nothing(self):
        url, _ = self.serve("hello-linux", HELLO)
        self.write_lock(("hello", "1.2.3", HOST, url, "0" * 64, "-"))
        result = self.run_script("hello")
        self.assert_nothing_installed(result, 1, "sha256 mismatch", "0" * 64, sha256(HELLO))

    def test_hash_mismatch_in_a_tar_gz_is_caught_before_extraction(self):
        # Archives that cannot give the member: unpacking one first would fail with another message.
        for label, data in (("member missing", tar_gz({"README": b"x"})), ("not an archive", b"<html>404</html>"),
                            ("member present", tar_gz({"hello": HELLO}))):
            with self.subTest(label):
                url, _ = self.serve("hello.tar.gz", data)
                self.write_lock(("hello", "1.2.3", HOST, url, "0" * 64, "hello"))
                result = self.run_script("hello")
                self.assert_nothing_installed(result, 1, "sha256 mismatch", sha256(data))
                self.assertNotIn("cannot extract", result.stderr)
                self.assertNotIn("tar:", result.stderr)

    def test_one_bad_hash_installs_none_of_the_requested_tools(self):
        url1, digest1 = self.serve("hello-linux", HELLO)
        url2, _ = self.serve("bye", b"tampered\n")
        self.write_lock(("hello", "1.2.3", HOST, url1, digest1, "-"), ("bye", "0.1", HOST, url2, "1" * 64, "-"))
        self.assert_nothing_installed(self.run_script(), 1, "bye 0.1", "sha256 mismatch")

    def test_hash_mismatch_keeps_the_previous_install(self):
        url, digest = self.serve("hello-linux", HELLO)
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "-"))
        self.run_script()
        url2, _ = self.serve("hello-2", b"#!/bin/sh\necho tampered\n")
        self.write_lock(("hello", "2.0.0", HOST, url2, "2" * 64, "-"))
        self.assertEqual(self.run_script().returncode, 1)
        self.assertEqual(self.installed(), ["hello"])
        self.assertEqual((self.dest / "hello").read_bytes(), HELLO)

    def test_unknown_tool(self):
        url, digest = self.serve("hello-linux", HELLO)
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "-"))
        self.assert_nothing_installed(self.run_script("hello", "nosuchtool"), 2, "unknown tool 'nosuchtool'")
        self.assertEqual(self.requests, [])

    def test_tool_without_an_entry_for_this_architecture(self):
        url, digest = self.serve("hello-linux", HELLO)
        self.write_lock(("hello", "1.2.3", OTHER, url, digest, "-"))
        self.assert_nothing_installed(self.run_script("hello"), 2, f"no {HOST} entry for 'hello'")

    def test_machine_name_selects_the_lock_architecture(self):
        url_arm, digest_arm = self.serve("hello-arm64", b"#!/bin/sh\necho arm64\n")
        url_amd, digest_amd = self.serve("hello-amd64", b"#!/bin/sh\necho amd64\n")
        self.write_lock(("hello", "1", "amd64", url_amd, digest_amd, "-"),
                        ("hello", "1", "arm64", url_arm, digest_arm, "-"))
        for machine, arch in (("aarch64", "arm64"), ("x86_64", "amd64")):
            self.assertEqual(self.run_script(machine=machine).returncode, 0)
            self.assertEqual(subprocess.check_output(["sh", str(self.dest / "hello")], text=True), arch + "\n")
            (self.dest / "hello").unlink()

    def test_unknown_architecture(self):
        url, digest = self.serve("hello-linux", HELLO)
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "-"))
        result = self.run_script("hello", machine="riscv64")
        self.assert_nothing_installed(result, 2, "unsupported architecture 'riscv64'")

    def test_member_missing_from_archive(self):
        url, digest = self.serve("hello.tar.gz", tar_gz({"README.md": b"docs\n"}))
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "hello"))
        self.assert_nothing_installed(self.run_script("hello"), 1, "cannot extract 'hello'")

    def test_symlink_member_is_refused(self):
        url, digest = self.serve("hello.tar.gz", tar_gz({"hello": ("link", "/bin/sh")}))
        self.write_lock(("hello", "1.2.3", HOST, url, digest, "hello"))
        self.assert_nothing_installed(self.run_script("hello"), 1, "not a regular file")

    def test_download_failure(self):
        self.write_lock(("hello", "1.2.3", HOST, f"{self.base}/absent", "0" * 64, "-"))
        self.assert_nothing_installed(self.run_script("hello"), 1, "download failed")

    def test_malformed_lock_lines_are_reported_with_file_and_line(self):
        url, digest = self.serve("hello-linux", HELLO)
        good = ("hello", "1.2.3", HOST, url, digest, "-")
        cases = {
            "5 fields": good[:5],
            "empty field": ("hello", "", HOST, url, digest, "-"),
            "bad arch": ("hello", "1.2.3", "x86_64", url, digest, "-"),
            "short hash": ("hello", "1.2.3", HOST, url, digest[:40], "-"),
            "uppercase hash": ("hello", "1.2.3", HOST, url, digest.upper(), "-"),
            "file url": ("hello", "1.2.3", HOST, "file:///etc/passwd", digest, "-"),
            "name with slash": ("../hello", "1.2.3", HOST, url, digest, "-"),
            "member escapes": ("hello", "1.2.3", HOST, url, digest, "../../etc/passwd"),
            "member escapes inside": ("hello", "1.2.3", HOST, url, digest, "a/../../hello"),
            "absolute member": ("hello", "1.2.3", HOST, url, digest, "/usr/bin/hello"),
            "member looks like an option": ("hello", "1.2.3", HOST, url, digest, "--to-command=sh"),
        }
        for label, row in cases.items():
            with self.subTest(label):
                self.write_lock(row)
                self.assert_nothing_installed(self.run_script("hello"), 2, f"{self.lock}:3: ")
        with self.subTest("duplicate entry"):
            self.write_lock(good, good)
            self.assert_nothing_installed(self.run_script("hello"), 2, f"{self.lock}:4: second entry")
        self.assertEqual(self.requests, [], "a bad lock is rejected before any download")

    def test_missing_lock_and_bad_options(self):
        self.assert_nothing_installed(self.run_script("hello"), 2, "cannot read lock file")
        self.write_lock()
        self.assert_nothing_installed(self.run_script(), 2, "lists no tools")
        self.assert_nothing_installed(self.run_script("--frobnicate"), 2, "unknown option")


class RealLockTest(unittest.TestCase):
    """ci/tools.lock itself: complete, and accepted by the script's parser."""

    def rows(self):
        lines = REAL_LOCK.read_text().splitlines()
        return [line.split("\t") for line in lines if line and not line.startswith("#")]

    def test_every_tool_is_pinned_for_both_architectures(self):
        rows = self.rows()
        self.assertEqual({(r[0], r[1]) for r in rows},
                         {("syft", "1.57.1"), ("cosign", "v3.1.4"), ("oras", "1.3.6"),
                          ("crane", "v0.22.1"), ("uv", "0.13.7"), ("grype", "v0.121.3")})
        self.assertEqual(sorted((r[0], r[2]) for r in rows),
                         sorted((name, arch) for name in {r[0] for r in rows} for arch in ("amd64", "arm64")))
        for name, version, arch, url, digest, member in rows:
            self.assertTrue(url.startswith("https://github.com/"), url)
            self.assertIn(f"/releases/download/{version}/" if name in ("cosign", "crane", "uv", "grype")
                          else f"/releases/download/v{version}/", url)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            marker = {"amd64": ("amd64", "x86_64"), "arm64": ("arm64", "aarch64")}[arch]
            self.assertTrue(any(m in url.rsplit("/", 1)[1] for m in marker), url)
        self.assertEqual(len({r[4] for r in rows}), len(rows), "every artifact has its own hash")

    def test_script_accepts_the_real_lock(self):
        env = {k: v for k, v in os.environ.items() if k != "TOOLS_LOCK"}
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([str(SCRIPT), "--dest", f"{tmp}/bin", "nosuchtool"],
                                    capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(f"unknown tool 'nosuchtool' (not in {REAL_LOCK.parent}", result.stderr)
            self.assertFalse(Path(tmp, "bin").exists())


if __name__ == "__main__":
    unittest.main()
