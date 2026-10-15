"""Regression checks for native-compatible synthetic SSN fixtures."""

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fixtures", ROOT / "demo" / "generators" / "generate_fixtures.py"
)
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)


class FixtureGeneratorTests(unittest.TestCase):
    def test_ssn_boundaries_use_distinct_values_with_local_context(self):
        for count in (0, 1, 198, 199, 200, 201, 250):
            with self.subTest(count=count):
                body = fixtures.ssn_records(count)
                values = re.findall(r"\b321-54-\d{4}\b", body)
                self.assertEqual(len(values), count)
                self.assertEqual(len(set(values)), count)
                self.assertTrue(all("SSN:" in line for line in body.splitlines()))
                self.assertNotIn("123-45-6789", body)

    def test_pdf_keeps_all_200_records_across_multiple_pages(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boundary.pdf"
            body = fixtures.ssn_records(200)
            fixtures.write_pdf(path, body)
            pdf = path.read_bytes().decode("latin-1")
            self.assertIn("/Count 5", pdf)
            for line in body.splitlines():
                self.assertEqual(pdf.count(f"({line}) Tj"), 1)
            startxref = int(re.search(r"startxref\n(\d+)", pdf).group(1))
            self.assertTrue(pdf[startxref:].startswith("xref\n"))
            offsets = re.findall(r"(?m)^(\d{10}) 00000 n ", pdf)
            for number, offset in enumerate(offsets, start=1):
                self.assertTrue(pdf[int(offset):].startswith(f"{number} 0 obj\n"))


if __name__ == "__main__":
    unittest.main()
