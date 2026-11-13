"""Tests for ci/sbom_probe.py. No Docker needed: the conda records under
fixtures/probe/rootfs are real conda-meta records cut from mesa-cli (file
lists trimmed), and the docker CLI is replaced by a fake or a stub script."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tracemalloc
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import sbom_probe  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "probe")
ROOTFS = os.path.join(FIXTURES, "rootfs")
LOCKS = os.path.join(FIXTURES, "locks.cdx.json")
BASE, GEO = "/opt/conda", "/opt/conda/envs/geospatial"
IMAGE = "harbor.cyverse.org/vice/mesa-cli:latest"

# Real output of the pin commands in mesa-cli:latest.
REAL_OUTPUTS = {
    "go version": (0, "go version go1.27.3 linux/amd64\n"),
    "tini --version": (0, "tini version 0.19.0 - git.de40ad0\n"),
    "ttyd --version": (0, "ttyd version 1.7.7-40e79c7\n"),
}


def tar_bytes(build):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        build(tar)
    return buf.getvalue()


def add_bytes(tar, name, data, **attrs):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for key, value in attrs.items():
        setattr(info, key, value)
    tar.addfile(info, io.BytesIO(data))


def fixture_tar():
    """What `tar -cf - /opt/conda/envs/geospatial/conda-meta /opt/conda/conda-meta` gives."""
    def build(tar):
        for prefix in (GEO, BASE):
            tar.add(os.path.join(ROOTFS, prefix.lstrip("/"), "conda-meta"),
                    arcname=prefix.lstrip("/") + "/conda-meta")
    return tar_bytes(build)


def read(data):
    return sbom_probe.read_conda_tar(io.BufferedReader(io.BytesIO(data)))


def record(prefix, filename):
    with open(os.path.join(ROOTFS, prefix.lstrip("/"), "conda-meta", filename), encoding="utf-8") as f:
        return json.load(f)


def props(component):
    return {p["name"]: p["value"] for p in component["properties"]}


class CondaComponentTest(unittest.TestCase):
    def test_conda_package(self):
        c = sbom_probe.conda_component(record(BASE, "python-3.13.18-hf47f18c_100_cp313.json"), BASE)
        purl = "pkg:conda/python@3.13.18?build=hf47f18c_100_cp313&channel=conda-forge&subdir=linux-64&type=conda"
        self.assertEqual(c["purl"], purl)
        self.assertEqual(c["bom-ref"], purl + "#/opt/conda")
        self.assertEqual((c["type"], c["name"], c["version"]), ("library", "python", "3.13.18"))
        rec = record(BASE, "python-3.13.18-hf47f18c_100_cp313.json")
        self.assertEqual(c["hashes"], [{"alg": "SHA-256", "content": rec["sha256"]},
                                       {"alg": "MD5", "content": rec["md5"]}])
        self.assertEqual(c["externalReferences"], [{
            "type": "distribution",
            "url": "https://conda.anaconda.org/conda-forge/linux-64/python-3.13.18-hf47f18c_100_cp313.conda"}])
        self.assertEqual(c["properties"], [{"name": "mesa:probe:prefix", "value": "/opt/conda"}])

    def test_tar_bz2_noarch_package(self):
        c = sbom_probe.conda_component(record(BASE, "defusedxml-0.7.1-pyhd8ed1ab_0.json"), BASE)
        self.assertEqual(
            c["purl"],
            "pkg:conda/defusedxml@0.7.1?build=pyhd8ed1ab_0&channel=conda-forge&subdir=noarch&type=tar.bz2")

    def test_purl_matches_the_lock_component(self):
        with open(LOCKS, encoding="utf-8") as f:
            lock = [c for c in json.load(f)["components"] if c["name"] == "python"][0]
        c = sbom_probe.conda_component(record(BASE, "python-3.13.18-hf47f18c_100_cp313.json"), BASE)
        self.assertEqual((c["purl"], c["bom-ref"]), (lock["purl"], lock["bom-ref"]))

    def test_channel_and_type_without_url(self):
        rec = record(GEO, "laszip-3.4.3-h9c3ff4c_2.json")
        del rec["url"]
        want = "pkg:conda/laszip@3.4.3?build=h9c3ff4c_2&channel=conda-forge&subdir=linux-64&type=tar.bz2"
        for channel in ("conda-forge", "https://conda.anaconda.org/conda-forge",
                        "https://conda.anaconda.org/conda-forge/linux-64/"):
            rec["channel"] = channel
            c = sbom_probe.conda_component(rec, GEO)
            self.assertEqual(c["purl"], want, channel)
            self.assertNotIn("externalReferences", c)

    def test_channel_with_several_segments(self):
        rec = record(BASE, "tzdata-2026e-h5d301ff_0.json")
        for channel in ("pkgs/main", "conda-forge/label/python_rc"):
            rec["url"] = f"https://repo.anaconda.com/{channel}/noarch/tzdata-2026e-h5d301ff_0.conda"
            self.assertIn(f"&channel={channel}&subdir=noarch&type=conda",
                          sbom_probe.conda_component(rec, BASE)["purl"])
            del rec["url"]  # same answer from the record's channel field
            rec["channel"] = f"https://repo.anaconda.com/{channel}/noarch"
            self.assertIn(f"&channel={channel}&subdir=noarch&type=conda",
                          sbom_probe.conda_component(rec, BASE)["purl"])

    def test_unknown_fields_are_left_out_not_guessed(self):
        c = sbom_probe.conda_component(
            {"name": "local-pkg", "version": "1!2.0+abc", "build": "0", "sha256": "xyz", "md5": 5,
             "url": "not a url", "channel": None}, "/srv/env")
        self.assertEqual(c["purl"], "pkg:conda/local-pkg@1%212.0%2Babc?build=0")
        self.assertEqual(c["bom-ref"], "pkg:conda/local-pkg@1%212.0%2Babc?build=0#/srv/env")
        self.assertNotIn("hashes", c)
        self.assertNotIn("externalReferences", c)

    def test_unparsable_url_and_channel(self):
        rec = dict(record(GEO, "laszip-3.4.3-h9c3ff4c_2.json"), url="http://[::1/a/b/c.conda", channel="//[x")
        self.assertEqual(sbom_probe.conda_component(rec, GEO)["purl"],
                         "pkg:conda/laszip@3.4.3?build=h9c3ff4c_2&subdir=linux-64&type=tar.bz2")

    def test_malformed_records(self):
        good = record(BASE, "openssl-3.6.5-h781a0a9_0.json")
        for bad in (None, [], "x", 3, {}, {**good, "version": None}, {**good, "name": ""},
                    {**good, "build": ["h781a0a9_0"]}, {**good, "name": "n" * 300}):
            self.assertIsNone(sbom_probe.conda_component(bad, BASE))
        self.assertIsNotNone(sbom_probe.conda_component(good, BASE))


class ReadCondaTarTest(unittest.TestCase):
    def test_real_records(self):
        prefixes, skipped = read(fixture_tar())
        self.assertEqual(skipped, 0)
        self.assertEqual({p: len(c) for p, c in prefixes.items()}, {BASE: 11, GEO: 10})
        for prefix, components in prefixes.items():
            for c in components:
                self.assertEqual(props(c), {"mesa:probe:prefix": prefix})
                self.assertTrue(c["bom-ref"].endswith("#" + prefix))
                self.assertRegex(c["purl"], r"^pkg:conda/[^@?]+@[^?]+\?build=[^&]+&channel=conda-forge"
                                            r"&subdir=(linux-64|noarch)&type=(conda|tar\.bz2)$")
                self.assertEqual([h["alg"] for h in c["hashes"]], ["SHA-256", "MD5"])
        # the same package in two prefixes stays two components
        refs = [c["bom-ref"] for cs in prefixes.values() for c in cs if c["name"] == "openssl"]
        self.assertEqual(len(refs), 2)
        self.assertEqual(len(set(refs)), 2)
        names = {c["name"]: c["version"] for c in prefixes[GEO]}
        self.assertEqual(names["python"], "3.10.22")
        self.assertEqual(names["python-dateutil"], "2.9.0.post0")

    def test_no_conda_in_image(self):
        self.assertEqual(read(b""), ({}, 0))

    def test_empty_prefix_is_reported(self):
        def build(tar):
            info = tarfile.TarInfo("srv/env/conda-meta")
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
            add_bytes(tar, "srv/env/conda-meta/history", b"==> 2026-11-01 <==\n")
        self.assertEqual(read(tar_bytes(build)), ({"/srv/env": []}, 0))

    def test_malformed_records_are_skipped_and_counted(self):
        good = json.dumps(record(BASE, "mamba-2.10.0-hdf28c64_3.json")).encode()

        def build(tar):
            meta = "opt/conda/conda-meta/"
            add_bytes(tar, meta + "mamba-2.10.0-hdf28c64_3.json", good)
            add_bytes(tar, meta + "truncated.json", good[:200])
            add_bytes(tar, meta + "list.json", b"[1, 2]")
            add_bytes(tar, meta + "binary.json", b"\xff\xfe\x00")
            add_bytes(tar, meta + "deep.json", b"[" * 200000)
            add_bytes(tar, meta + "noversion.json", b'{"name": "x", "build": "0"}')
            add_bytes(tar, meta + "symlink.json", b"", type=tarfile.SYMTYPE, linkname="/etc/passwd")
            add_bytes(tar, meta + "dangling.json", b"", type=tarfile.LNKTYPE, linkname="etc/passwd")
            add_bytes(tar, meta + "pinned", b"python 3.13.*\n")  # not a record: ignored
            add_bytes(tar, meta + "sub/nested.json", good)  # not directly in conda-meta
            add_bytes(tar, "opt/conda/pkgs/cache/x.json", good)
        prefixes, skipped = read(tar_bytes(build))
        self.assertEqual([c["name"] for c in prefixes[BASE]], ["mamba"])
        self.assertEqual(list(prefixes), [BASE])
        self.assertEqual(skipped, 7)

    def test_oversize_record_is_skipped(self):
        with mock.patch.object(sbom_probe, "MAX_RECORD_BYTES", 2000):
            prefixes, skipped = read(fixture_tar())
        self.assertGreater(skipped, 0)
        self.assertEqual(skipped + sum(len(c) for c in prefixes.values()), 21)

    def test_too_many_records(self):
        with mock.patch.object(sbom_probe, "MAX_RECORDS", 5):
            with self.assertRaisesRegex(sbom_probe.ProbeError, "more than 5 conda records"):
                read(fixture_tar())

    def test_hard_link_to_an_earlier_record(self):
        name = "ca-certificates-2026.10.23-hbd8a1cb_0.json"
        data = json.dumps(record(BASE, name)).encode()

        def build(tar):
            add_bytes(tar, "opt/conda/conda-meta/" + name, data)
            add_bytes(tar, "opt/conda/envs/geospatial/conda-meta/" + name, b"",
                      type=tarfile.LNKTYPE, linkname="opt/conda/conda-meta/" + name)
        prefixes, skipped = read(tar_bytes(build))
        self.assertEqual(skipped, 0)
        self.assertEqual(prefixes[GEO][0]["purl"], prefixes[BASE][0]["purl"])
        self.assertTrue(prefixes[GEO][0]["bom-ref"].endswith("#" + GEO))

    def test_concatenated_archives(self):
        def one(prefix):
            return tar_bytes(lambda tar: tar.add(
                os.path.join(ROOTFS, prefix.lstrip("/"), "conda-meta"),
                arcname=prefix.lstrip("/") + "/conda-meta"))
        prefixes, _ = read(one(BASE) + one(GEO))
        self.assertEqual({p: len(c) for p, c in prefixes.items()}, {BASE: 11, GEO: 10})

    def test_truncated_stream(self):
        data = tar_bytes(lambda tar: add_bytes(
            tar, "opt/conda/conda-meta/x.json", b'{"name": "x"}' + b" " * 4000))
        with self.assertRaisesRegex(sbom_probe.ProbeError, "not a readable tar"):
            read(data[:512 + 1000])  # header, then the record cut short

    def test_record_fields_are_kept_at_a_bounded_size(self):
        # 20 valid records with a 2 MiB channel each: one is in memory while it is parsed,
        # none of the oversized values afterwards
        def build(tar):
            for i in range(20):
                add_bytes(tar, f"opt/conda/conda-meta/p{i}-1-0.json", json.dumps(
                    {"name": f"p{i}", "version": "1", "build": "0", "subdir": "noarch",
                     "channel": "c" * (2 << 20), "files": ["f"] * 1000}).encode())
        stream = io.BufferedReader(io.BytesIO(tar_bytes(build)))
        tracemalloc.start()
        try:
            prefixes, skipped = sbom_probe.read_conda_tar(stream)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual((len(prefixes[BASE]), skipped), (20, 0))
        self.assertEqual(prefixes[BASE][0]["purl"], "pkg:conda/p0@1?build=0&subdir=noarch")
        self.assertLess(peak, 20 << 20)

    def endless(self, header, limit=64 << 20):
        """A stream of one tar header and then filler for as long as it is read (up to limit)."""
        test = self

        class Raw(io.RawIOBase):
            served = 0

            def readable(self):
                return True

            def readinto(self, buf):
                test.assertLess(self.served, limit, "the reader keeps buffering what the image sends")
                data = header[self.served:self.served + len(buf)] or b"A" * len(buf)
                buf[:len(data)] = data
                self.served += len(data)
                return len(data)
        raw = Raw()
        return raw, io.BufferedReader(raw)

    def test_oversized_tar_extension_headers_are_refused_not_buffered(self):
        # one GNU long-name (or pax) header that claims 8 GiB; tarfile would read it whole
        for kind in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XHDTYPE, tarfile.XGLTYPE):
            with self.subTest(kind):
                info = tarfile.TarInfo("././@LongLink")
                info.type, info.size = kind, 8 << 30
                raw, stream = self.endless(info.tobuf(tarfile.GNU_FORMAT))
                with self.assertRaisesRegex(sbom_probe.ProbeError, "tar header of 8589934592 bytes"):
                    sbom_probe.read_conda_tar(stream)
                self.assertLess(raw.served, 1 << 20)

    def test_sparse_members_are_refused(self):
        info = tarfile.TarInfo("opt/conda/conda-meta/x.json")
        info.type = tarfile.GNUTYPE_SPARSE
        raw, stream = self.endless(info.tobuf(tarfile.GNU_FORMAT))
        with self.assertRaisesRegex(sbom_probe.ProbeError, "sparse member"):
            sbom_probe.read_conda_tar(stream)
        # pax form: the map follows the header, as many numbers as the stream says
        pax = tarfile.TarInfo("opt/conda/conda-meta/x.json").tobuf(tarfile.PAX_FORMAT)
        info = tarfile.TarInfo("opt/conda/conda-meta/x.json")
        info.pax_headers = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.name": "x",
                            "GNU.sparse.realsize": "1"}
        header = info.tobuf(tarfile.PAX_FORMAT) + b"99999999999\n" + b"1\n" * 250
        self.assertNotEqual(header[:512], pax[:512])
        raw, stream = self.endless(header)
        with self.assertRaisesRegex(sbom_probe.ProbeError, "sparse member"):
            sbom_probe.read_conda_tar(stream)
        self.assertLess(raw.served, 1 << 20)

    def test_long_names_as_tar_writes_them_still_work(self):
        name = "long-package-name-" * 12 + "1.0-0.json"  # GNU tar: a LongLink header; pax: a path record
        good = json.dumps(record(BASE, "mamba-2.10.0-hdf28c64_3.json")).encode()
        for fmt in (tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w", format=fmt) as tar:
                add_bytes(tar, "opt/conda/envs/geospatial/conda-meta/" + name, good)
            prefixes, skipped = read(buf.getvalue())
            self.assertEqual(([c["name"] for c in prefixes[GEO]], skipped), (["mamba"], 0))

    def test_path_tricks_stay_labels(self):
        good = json.dumps(record(BASE, "mamba-2.10.0-hdf28c64_3.json")).encode()
        prefixes, _ = read(tar_bytes(
            lambda tar: add_bytes(tar, "../../opt/./x/../conda/conda-meta/m.json", good)))
        self.assertEqual(list(prefixes), [BASE])


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, "ci", "sbom_from_locks.py")),
                     "ci/sbom_from_locks.py not present")
class SameFormAsTheLockTest(unittest.TestCase):
    """An explicit lock of the fixture prefix, run through sbom_from_locks.py,
    must give the purls, bom-refs, hashes and URLs the probe gives."""

    def test_probe_components_equal_lock_components(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        os.mkdir(os.path.join(tmp, "sbom"))
        meta = os.path.join(ROOTFS, GEO.lstrip("/"), "conda-meta")
        records = [record(GEO, name) for name in sorted(os.listdir(meta))]
        with open(os.path.join(tmp, "sbom", "geospatial.lock"), "w", encoding="utf-8") as f:
            f.write("@EXPLICIT\n" + "".join(f"{r['url']}#sha256:{r['sha256']}\n" for r in records))
        with open(os.path.join(tmp, "sbom", "locks.tsv"), "w", encoding="utf-8") as f:
            f.write(f"conda\tcpu\tamd64\tsbom/geospatial.lock\t{GEO}\n")
        out = os.path.join(tmp, "locks.cdx.json")
        done = subprocess.run(
            [sys.executable, os.path.join(ROOT, "ci", "sbom_from_locks.py"), "--repo-root", tmp,
             "--variant", "cpu", "--arch", "amd64", "-o", out], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        with open(out, encoding="utf-8") as f:
            lock = json.load(f)["components"]

        def view(components):
            return sorted((c["bom-ref"], c["purl"], c["name"], c["version"],
                           [h["content"] for h in c["hashes"] if h["alg"] == "SHA-256"],
                           c["externalReferences"]) for c in components)
        self.assertEqual(len(lock), 10)
        self.assertEqual(view(lock), view(read(fixture_tar())[0][GEO]))


@unittest.skipUnless(shutil.which("find") and shutil.which("tar"), "needs find and tar")
class CondaScriptTest(unittest.TestCase):
    """The discovery script, run by the host's sh on a directory tree instead of /."""

    def test_every_conda_meta_directory_is_found(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        root = os.path.realpath(tmp)
        source = os.path.join(ROOTFS, "opt", "conda", "conda-meta", "tzdata-2026e-h5d301ff_0.json")
        found = ["/opt/conda", "/opt/conda/envs/geospatial",  # nested: both
                 "/var/lib/extra-env", "/config/miniconda3", "/data/env",  # anywhere, not a list of roots
                 "/opt/a/b/c/d/e/f/g/h/env"]  # at any depth
        pruned = ["/proc/1/root/opt/conda", "/sys/env", "/dev/shm/env"]
        for prefix in found + pruned:
            os.makedirs(root + prefix + "/conda-meta")
            shutil.copy(source, root + prefix + "/conda-meta")
        os.makedirs(root + "/opt/conda/pkgs/conda-meta-not/x")  # not a conda-meta directory
        script = sbom_probe.conda_script(root, [root + p for p in sbom_probe.CONDA_PRUNE])
        done = subprocess.run(["/bin/sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.assertEqual(done.returncode, 0)
        prefixes, skipped = read(done.stdout)
        self.assertEqual(skipped, 0)
        self.assertEqual({p: [c["name"] for c in cs] for p, cs in prefixes.items()},
                         {root + p: ["tzdata"] for p in found})

    def test_the_image_is_searched_from_the_root(self):
        self.assertEqual(sbom_probe.conda_script(),
                         "exec find / \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o "
                         "-type d -name conda-meta -prune -exec tar -cf - {} +\n")

    def test_nothing_found_is_empty_output(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        done = subprocess.run(["/bin/sh", "-c", sbom_probe.conda_script(tmp, ["/proc"])], stdout=subprocess.PIPE)
        self.assertEqual((done.returncode, read(done.stdout)), (0, ({}, 0)))


class VersionInTest(unittest.TestCase):
    def test_real_outputs(self):
        self.assertTrue(sbom_probe.version_in("1.27.3", "go version go1.27.3 linux/amd64"))
        self.assertTrue(sbom_probe.version_in("0.19.0", "tini version 0.19.0 - git.de40ad0"))
        self.assertTrue(sbom_probe.version_in("1.7.7", "ttyd version 1.7.7-40e79c7"))
        self.assertTrue(sbom_probe.version_in("0.12.5", '"clientVersion": "v0.12.5",'))
        self.assertTrue(sbom_probe.version_in("22.23.4", "v22.23.4"))

    def test_leading_v_of_the_lock_version_is_optional(self):
        self.assertTrue(sbom_probe.version_in("v0.19.0", "tini version 0.19.0 - git.de40ad0"))
        self.assertTrue(sbom_probe.version_in("v0.12.5", '"clientVersion": "v0.12.5",'))
        self.assertFalse(sbom_probe.version_in("v0.19.0", "tini version 0.19.1"))
        self.assertFalse(sbom_probe.version_in("v0.19.0", "tini version 10.19.0"))
        # one 'v', and only before a digit; a git commit is compared as it is
        self.assertFalse(sbom_probe.version_in("vv1.0", "tool 1.0"))
        self.assertTrue(sbom_probe.version_in("vnext", "tool vnext"))
        self.assertFalse(sbom_probe.version_in("vnext", "tool next"))
        commit = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"
        self.assertTrue(sbom_probe.version_in(commit, f"irods-mcp-server (commit {commit})"))

    def test_not_part_of_a_longer_version(self):
        self.assertFalse(sbom_probe.version_in("1.7.70", "ttyd version 1.7.7-40e79c7"))
        self.assertFalse(sbom_probe.version_in("1.27.3", "go version go1.27.30 linux/amd64"))
        self.assertFalse(sbom_probe.version_in("1.27.3", "go version go11.27.3 linux/amd64"))
        self.assertFalse(sbom_probe.version_in("1.27", "go version go1.27.3 linux/amd64"))
        self.assertFalse(sbom_probe.version_in("27.3", "go version go1.27.3 linux/amd64"))
        self.assertFalse(sbom_probe.version_in("", "anything"))

    def test_version_is_not_a_regex(self):
        self.assertFalse(sbom_probe.version_in("1.2.3", "1x2y3"))
        self.assertTrue(sbom_probe.version_in("2.0+cu126", "torch 2.0+cu126."))


class PinTest(unittest.TestCase):
    def setUp(self):
        self.pins = sbom_probe.load_pins(LOCKS)

    def test_only_components_with_a_probe(self):
        self.assertEqual([p["name"] for p in self.pins], ["tini", "go", "ttyd"])

    def probe(self, name, status, output):
        pin = [p for p in self.pins if p["name"] == name][0]
        before = json.dumps(pin)
        calls = []

        def run(command):
            calls.append(command)
            return status, output
        result = sbom_probe.probe_pin(pin, run)
        self.assertEqual(calls, [props(pin)["mesa:lock:probe"]])
        self.assertEqual(json.dumps(pin), before)  # the lock component is not modified
        # the component again: same fields, two properties more
        self.assertEqual({k: v for k, v in result.items() if k != "properties"},
                         {k: v for k, v in pin.items() if k != "properties"})
        self.assertEqual(result["properties"][:-2], pin["properties"])
        self.assertEqual([p["name"] for p in result["properties"][-2:]],
                         ["mesa:probe:result", "mesa:probe:output"])
        return props(result)["mesa:probe:result"], props(result)["mesa:probe:output"]

    def test_ok(self):
        self.assertEqual(self.probe("go", *REAL_OUTPUTS["go version"]),
                         ("ok", "go version go1.27.3 linux/amd64"))
        self.assertEqual(self.probe("tini", *REAL_OUTPUTS["tini --version"]),
                         ("ok", "tini version 0.19.0 - git.de40ad0"))

    def test_wrong_version(self):
        self.assertEqual(self.probe("ttyd", *REAL_OUTPUTS["ttyd --version"]),
                         ("mismatch", "ttyd version 1.7.7-40e79c7"))

    def test_command_fails(self):
        # real output of `tini --version` in mesa-kasm, which has no tini
        self.assertEqual(self.probe("tini", 127, "/bin/sh: 1: tini: not found\n"),
                         ("mismatch", "exit 127: /bin/sh: 1: tini: not found"))
        # a failing command is a mismatch even when it prints the version
        self.assertEqual(self.probe("tini", 1, "tini version 0.19.0")[0], "mismatch")

    def test_timeout(self):
        self.assertEqual(self.probe("go", None, "go version go1.27.3"),
                         ("mismatch", "timeout after 30s: go version go1.27.3"))

    def test_output_is_cut_to_200_characters(self):
        result, output = self.probe("go", 0, "x" * 500 + " go1.27.3")
        self.assertEqual((result, output), ("ok", "x" * 200))

    def test_component_without_version(self):
        pin = dict(self.pins[0], version="")
        result = sbom_probe.probe_pin(pin, lambda command: self.fail("must not run"))
        self.assertEqual(props(result)["mesa:probe:result"], "mismatch")
        self.assertEqual(props(result)["mesa:probe:output"], "lock component has no version")


class FakeContainer:
    """Replaces sbom_probe.Container: canned tar bytes and command outputs."""
    tar = b""
    outputs = REAL_OUTPUTS

    def __init__(self, docker, image):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    @contextlib.contextmanager
    def conda_tar(self):
        yield io.BufferedReader(io.BytesIO(self.tar))

    def run(self, command):
        return self.outputs[command]


class CliCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.out = os.path.join(self.tmp, "probe.cdx.json")

    def main(self, *args):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                status = sbom_probe.main(list(args))
            except SystemExit as e:  # argparse
                status = e.code
        return status, err.getvalue()


class MainTest(CliCase):
    def run_fake(self, locks=LOCKS, tar=None):
        fake = type("Fake", (FakeContainer,), {"tar": fixture_tar() if tar is None else tar})
        with mock.patch.object(sbom_probe, "Container", fake):
            return self.main("--image", IMAGE, "--locks-sbom", locks, "-o", self.out)

    def test_document(self):
        status, err = self.run_fake()
        self.assertEqual(status, 0, err)
        with open(self.out, encoding="utf-8") as f:
            text = f.read()
        doc = json.loads(text)
        self.assertEqual((doc["bomFormat"], doc["specVersion"], doc["version"]), ("CycloneDX", "1.6", 1))
        self.assertEqual(doc["metadata"]["properties"], [
            {"name": "mesa:probe:image", "value": IMAGE},
            {"name": "mesa:probe:skipped", "value": "0"}])
        components = doc["components"]
        self.assertEqual(len(components), 21 + 3)
        keys = [(c["purl"], c["bom-ref"]) for c in components]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len({c["bom-ref"] for c in components}), len(components))
        results = {c["name"]: props(c)["mesa:probe:result"] for c in components
                   if "mesa:probe:result" in props(c)}
        self.assertEqual(results, {"go": "ok", "tini": "ok", "ttyd": "mismatch"})
        self.assertIn("conda /opt/conda: 11 packages", err)
        self.assertIn("conda /opt/conda/envs/geospatial: 10 packages", err)
        self.assertIn("pin ttyd 1.7.70: mismatch (ttyd version 1.7.7-40e79c7)", err)
        # deterministic: no timestamp, no serial number, same bytes again
        self.assertNotIn("serialNumber", doc)
        self.assertNotIn("timestamp", doc["metadata"])
        self.assertEqual(self.run_fake()[0], 0)
        with open(self.out, encoding="utf-8") as f:
            self.assertEqual(f.read(), text)

    def test_skipped_count_in_metadata(self):
        def build(tar):
            add_bytes(tar, "opt/conda/conda-meta/broken.json", b"{")
            add_bytes(tar, "opt/conda/conda-meta/empty.json", b"")
        status, err = self.run_fake(tar=tar_bytes(build))
        self.assertEqual(status, 0, err)
        with open(self.out, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertIn({"name": "mesa:probe:skipped", "value": "2"}, doc["metadata"]["properties"])
        self.assertIn("2 records skipped", err)

    def write(self, text):
        path = os.path.join(self.tmp, "locks.cdx.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_malformed_locks_sbom(self):
        path = self.write('{\n  "bomFormat": "CycloneDX",\n  "components": [\n    {"name": }\n]}')
        status, err = self.run_fake(locks=path)
        self.assertEqual(status, 2)
        self.assertIn(path + ":4: ", err)
        self.assertFalse(os.path.exists(self.out))

    def test_bad_locks_sbom_structure(self):
        cases = {
            "[]": "not a CycloneDX document",
            '{"components": []}': "not a CycloneDX document",
            '{"bomFormat": "CycloneDX", "components": {}}': "not a CycloneDX document",
            '{"bomFormat": "CycloneDX", "components": [1]}': "components[0] is not an object",
            '{"bomFormat": "CycloneDX", "components": [{"properties": '
            '[{"name": "mesa:lock:probe", "value": " "}]}]}': "components[0]: mesa:lock:probe",
        }
        for text, message in cases.items():
            status, err = self.run_fake(locks=self.write(text))
            self.assertEqual(status, 2, text)
            self.assertIn(message, err)

    def test_locks_sbom_nested_too_deeply(self):
        path = self.write("[" * 100000 + "]" * 100000)
        status, err = self.run_fake(locks=path)
        self.assertEqual((status, err), (2, f"sbom_probe: {path}: invalid JSON: nested too deeply\n"))

    def test_missing_locks_sbom(self):
        status, err = self.run_fake(locks=os.path.join(self.tmp, "nope.json"))
        self.assertEqual(status, 2)
        self.assertIn("nope.json: No such file or directory", err)

    def test_bad_arguments(self):
        self.assertEqual(self.main("--image", IMAGE)[0], 2)
        status, err = self.run_fake_image("--privileged")
        self.assertEqual(status, 2)
        self.assertIn("not an image reference", err)

    def run_fake_image(self, image):
        with mock.patch.object(sbom_probe, "Container", FakeContainer):
            return self.main("--image=" + image, "--locks-sbom", LOCKS, "-o", self.out)

    def test_unwritable_output(self):
        self.out = os.path.join(self.tmp, "missing-dir", "probe.cdx.json")
        status, err = self.run_fake()
        self.assertEqual(status, 2)
        self.assertIn("probe.cdx.json: No such file or directory", err)


class DockerCliTest(CliCase):
    """The real Container class against a stub docker executable."""

    def setUp(self):
        super().setUp()
        self.docker = os.path.join(self.tmp, "docker")
        with open(os.path.join(FIXTURES, "fake_docker.py"), encoding="utf-8") as f:
            stub = f.read()
        with open(self.docker, "w", encoding="utf-8") as f:
            f.write("#!" + sys.executable + "\n" + stub)
        os.chmod(self.docker, os.stat(self.docker).st_mode | stat.S_IXUSR)
        self.put("conda.tar", fixture_tar())
        self.put("outputs.json", json.dumps(
            {cmd: {"status": status, "out": out} for cmd, (status, out) in REAL_OUTPUTS.items()}))

    def put(self, name, data):
        with open(os.path.join(self.tmp, name), "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())

    def run_stub(self):
        return self.main("--image", IMAGE, "--locks-sbom", LOCKS, "-o", self.out, "--docker", self.docker)

    def log(self):
        with open(os.path.join(self.tmp, "log"), encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def components(self):
        with open(self.out, encoding="utf-8") as f:
            return json.load(f)["components"]

    def test_docker_invocations(self):
        status, err = self.run_stub()
        self.assertEqual(status, 0, err)
        self.assertEqual(len(self.components()), 21 + 3)
        run, conda, *pins = self.log()
        name = run[run.index("--name") + 1]
        self.assertRegex(name, r"^mesa-probe-[0-9a-f]{16}$")
        # one container: no network, entrypoint overridden, CMD replaced, no GPU
        self.assertEqual(run, ["run", "--rm", "-i", "--name", name, "--network", "none",
                               "--entrypoint", "/bin/sh", IMAGE, "-s"])
        self.assertEqual(conda, ["exec", "--user", "0:0", name, "/bin/sh", "-c", sbom_probe.conda_script()])
        # each pin command is one argv element for the image's sh, in the same container
        self.assertEqual(pins, [["exec", name, "/bin/sh", "-c", command] for command in
                                ("tini --version", "go version", "ttyd --version")])

    def test_image_cannot_start(self):
        self.put("no-start", "")
        status, err = self.run_stub()
        self.assertEqual(status, 1)
        self.assertIn("cannot start /bin/sh in a container of " + IMAGE, err)
        self.assertFalse(os.path.exists(self.out))

    def test_container_that_never_answers(self):
        # a /bin/sh that ignores its input, or prints without ever ending the line
        for mode, detail in (("hang", ": no answer within 1s"), ("flood", "")):
            with self.subTest(mode):
                self.put("run.mode", mode)
                started = time.monotonic()
                with mock.patch.object(sbom_probe, "START_TIMEOUT", 1):
                    status, err = self.run_stub()
                self.assertLess(time.monotonic() - started, 30)
                self.assertEqual((status, err), (
                    1, f"sbom_probe: cannot start /bin/sh in a container of {IMAGE}{detail}\n"))
                self.assertFalse(os.path.exists(self.out))
                run, remove = self.log()[-2:]  # the container is removed, not left to its sh
                self.assertEqual(remove, ["rm", "-f", run[run.index("--name") + 1]])

    def test_docker_not_installed(self):
        self.docker = os.path.join(self.tmp, "no-such-docker")
        status, err = self.run_stub()
        self.assertEqual(status, 1)
        self.assertIn("cannot run", err)

    def test_conda_command_fails(self):
        self.put("conda.status", "2")
        status, err = self.run_stub()
        self.assertEqual(status, 1)
        self.assertIn("conda probe failed in the image (exit 2): tar: Removing leading", err)

    def test_no_conda_in_image(self):
        os.remove(os.path.join(self.tmp, "conda.tar"))
        status, err = self.run_stub()
        self.assertEqual(status, 0, err)
        self.assertEqual(len(self.components()), 3)
        self.assertIn("conda: 0 prefixes, 0 records skipped", err)

    def results(self):
        return {c["name"]: (props(c)["mesa:probe:result"], props(c)["mesa:probe:output"])
                for c in self.components() if "mesa:probe:result" in props(c)}

    def test_pin_timeout(self):
        self.put("outputs.json", json.dumps({
            "tini --version": {"out": "tini version 0.19.0", "sleep": 120},
            "go version": {"out": "go version go1.27.3 linux/amd64\n"},
            "ttyd --version": {"out": "ttyd: not found\n", "status": 127}}))
        # Only the hanging command gets a short limit: every command is a new process of
        # the stub, and on a loaded machine starting one can take longer than that.
        real_exec = sbom_probe.Container._exec

        def quick_for_tini(container, script, timeout, *args, **kwargs):
            return real_exec(container, script, 0.5 if script == "tini --version" else timeout, *args, **kwargs)

        with mock.patch.object(sbom_probe.Container, "_exec", quick_for_tini):
            status, err = self.run_stub()
        self.assertEqual(status, 0, err)
        self.assertEqual(self.results(), {
            "tini": ("mismatch", "timeout after 30s: "),
            "go": ("ok", "go version go1.27.3 linux/amd64"),
            "ttyd": ("mismatch", "exit 127: ttyd: not found")})

    def test_pin_output_is_bounded(self):
        self.put("outputs.json", json.dumps({
            "tini --version": {"out": "\x1b[31mtini version 0.19.0\n" + "y" * 3_000_000},
            # the version only appears after the part that is read
            "go version": {"out": "y" * 100_000 + "go1.27.3"},
            "ttyd --version": {"out": ""}}))
        status, err = self.run_stub()
        self.assertEqual(status, 0, err)
        results = self.results()
        self.assertEqual(results["tini"][0], "ok")
        self.assertEqual(len(results["tini"][1]), 200)
        self.assertEqual(results["go"], ("mismatch", "y" * 200))
        self.assertEqual(results["ttyd"], ("mismatch", ""))
        self.assertNotIn("\x1b", err)  # control characters never reach the terminal


if __name__ == "__main__":
    unittest.main()
