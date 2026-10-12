"""The by-hand run's reading of a report PDF (C6.4): its page count, whether
the six headings come in the issue's order, then its text as pypdf gives it,
whitespace folded. Run from cloud/ (pypdf is a dev dependency there):

    uv run --no-sync python docs/api/cloud-lab/c6.4-harness/c64-pdf-text.py <file.pdf>
"""

import re
import sys

from pypdf import PdfReader

HEADINGS = ("Summary", "Test log", "Failures", "Method", "Integrity", "Framework mapping")


def main(path: str) -> int:
    reader = PdfReader(path)
    text = re.sub(r"\s+", " ", " ".join(page.extract_text() for page in reader.pages))
    positions = [text.find(heading) for heading in HEADINGS]
    print(f"pages {len(reader.pages)}")
    print("the six headings in order:", "yes" if positions == sorted(positions) and all(p >= 0 for p in positions) else "NO")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
