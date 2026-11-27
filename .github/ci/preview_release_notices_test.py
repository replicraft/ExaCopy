"""Verify exact archived notice bytes and the pinned upstream supplements."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import preview_release_notices as notices


class PreviewNoticesTests(unittest.TestCase):
    def test_cache_archive_checksum_and_notice_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            folder = cache / "registry/cache/index.crates.io-fixture"
            folder.mkdir(parents=True)
            archive = folder / "fixture-1.2.3.crate"
            sources = {
                "Cargo.toml": b'[package]\nname="fixture"\nversion="1.2.3"\nlicense-file="LICENSE"\n',
                "LICENSE": b"fixture notice with retained line endings\r\n",
            }
            with tarfile.open(archive, "w:gz") as bundle:
                for name, body in sources.items():
                    member = tarfile.TarInfo(f"fixture-1.2.3/{name}")
                    member.size = len(body)
                    bundle.addfile(member, io.BytesIO(body))
            with self.assertRaisesRegex(ValueError, "missing exact cached registry archive"):
                notices.registry_notices(cache, "fixture", "1.2.3", "0" * 64)
            result, source, upstream = notices.registry_notices(cache, "fixture", "1.2.3", notices.digest(archive.read_bytes()))
            self.assertEqual(result, {"LICENSE": sources["LICENSE"]})
            self.assertIsNone(upstream)
            self.assertTrue(source.endswith("/fixture-1.2.3.crate"))

    def test_vendor_license_requires_exact_upstream_vcs_revision(self):
        for (name, version), (_, revision, paths) in notices.UPSTREAM.items():
            for checkout in (revision, "f" * 40):
                with self.subTest(name=name, checkout=checkout):
                    body = f'{{"git":{{"sha1":"{checkout}"}}}}'.encode()
                    archive = io.BytesIO()
                    with tarfile.open(fileobj=archive, mode="w") as bundle:
                        metadata = tarfile.TarInfo(f"{name}-{version}/.cargo_vcs_info.json")
                        metadata.size = len(body)
                        bundle.addfile(metadata, io.BytesIO(body))
                    archive.seek(0)
                    with tarfile.open(fileobj=archive) as bundle:
                        if checkout != revision:
                            with self.assertRaisesRegex(ValueError, "revision differs"):
                                notices.upstream_notices(bundle, f"{name}-{version}", name, version)
                            continue
                        texts, source = notices.upstream_notices(bundle, f"{name}-{version}", name, version)
                        self.assertEqual(set(texts), {f"upstream/{path}" for path in paths})
                        self.assertTrue(source.endswith(f"/{revision}"))


if __name__ == "__main__":
    unittest.main()
