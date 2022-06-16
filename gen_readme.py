#!/usr/bin/env python3

import subprocess
from pathlib import Path

import synocli

file = Path(__file__).resolve().parent / "README.md"

requirements = (Path(__file__).resolve().parent / "requirements.txt").read_text()

p = subprocess.run(["./synocli.py", "-h"], stdout=subprocess.PIPE)
usage = p.stdout.decode()

readme = "## " + synocli.DESCRIPTION.split('\n')[0] + "\n" + synocli.README_MD.format(
    USAGE=usage,
    REQUIREMENTS=requirements,
    INTERACTIVE_MODE_HELP=synocli.INTERACTIVE_MODE_HELP)

file.write_text(readme)

print("[*] DONE, wrote %s" % file)
