"""Contract checks for the deep and Memcheck target matrices."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "fuzz_str_to_char": "corpus",
    "fuzz_pack_headers": "corpus_pack_headers",
}
WORKFLOWS = {
    "ci-deep.yml": "fuzz",
    "valgrind.yml": "memcheck-fuzz-corpus",
}


def job_body(source, job):
    pattern = re.compile(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [\w-]+:\n|\Z)")
    match = pattern.search(source)
    if not match:
        raise AssertionError(f"missing job: {job}")
    return match.group(1)


def target_matrix(job):
    match = re.search(r"(?ms)^      matrix:\n(.*?)(?=^    \S|\Z)", job)
    if not match:
        raise AssertionError("missing target matrix")
    rows = re.findall(
        r"(?m)^          - target: ([a-z_]+)\n            corpus: ([a-z_]+)$",
        match.group(1),
    )
    if len(rows) != 2 or dict(rows) != EXPECTED:
        raise AssertionError(f"expected both target/corpus pairs, got {rows}")
    return rows


class FuzzWorkflowContract(unittest.TestCase):
    def test_both_targets_and_their_own_corpora(self):
        for filename, job_name in WORKFLOWS.items():
            with self.subTest(filename=filename):
                path = ROOT / ".github/workflows" / filename
                body = job_body(path.read_text(), job_name)
                target_matrix(body)
                self.assertIn("run: bash fuzz/build.sh\n", body)
                self.assertIn("${{ matrix.target }}", body)
                self.assertIn("${{ matrix.corpus }}", body)
                self.assertIn("if: always()", body)
                if filename == "ci-deep.yml":
                    self.assertIn(
                        "FUZZ_BIN: ${{ github.workspace }}/fuzz/${{ matrix.target }}", body
                    )
                    self.assertIn(
                        "CORPUS_DIR: ${{ github.workspace }}/fuzz/${{ matrix.corpus }}", body
                    )
                    self.assertIn('bash fuzz/run.sh "$FUZZ_SECS" "$FUZZ_JOBS"', body)
                    self.assertIn("fuzz-deep-log-${{ matrix.target }}", body)
                    self.assertIn("fuzz-corpus-${{ matrix.target }}", body)
                else:
                    self.assertIn("corpus=(fuzz/${{ matrix.corpus }}/*)", body)
                    self.assertIn(
                        '"$GITHUB_WORKSPACE/fuzz/${{ matrix.target }}" "${corpus[@]}"', body
                    )
                    self.assertIn("valgrind-log-${{ matrix.target }}", body)
                    self.assertIn("set -euo pipefail", body)

    def test_omitted_target_is_rejected(self):
        for filename, job_name in WORKFLOWS.items():
            source = (ROOT / ".github/workflows" / filename).read_text()
            body = job_body(source, job_name)
            missing = body.replace(
                "          - target: fuzz_pack_headers\n"
                "            corpus: corpus_pack_headers\n",
                "",
            )
            with self.subTest(filename=filename), self.assertRaisesRegex(
                AssertionError, "expected both target/corpus pairs"
            ):
                target_matrix(missing)

    def test_wrong_corpus_and_duplicate_target_are_rejected(self):
        for filename, job_name in WORKFLOWS.items():
            body = job_body((ROOT / ".github/workflows" / filename).read_text(), job_name)
            for defect, changed in (
                ("wrong corpus", body.replace("corpus: corpus_pack_headers", "corpus: corpus")),
                (
                    "duplicate target",
                    body.replace("target: fuzz_pack_headers", "target: fuzz_str_to_char"),
                ),
            ):
                with self.subTest(filename=filename, defect=defect), self.assertRaisesRegex(
                    AssertionError, "expected both target/corpus pairs"
                ):
                    target_matrix(changed)


if __name__ == "__main__":
    unittest.main()
