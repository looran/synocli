#!/usr/bin/env python3

import subprocess
from pathlib import Path

import synocli

file = Path(__file__).resolve().parent / "README.md"

requirements = (Path(__file__).resolve().parent / "requirements.txt").read_text()

p = subprocess.run(["./synocli.py", "-h"], stdout=subprocess.PIPE)
usage = p.stdout.decode()

readme = synocli.README_MD.format(
    USAGE=usage,
    REQUIREMENTS=requirements,
    INTERACTIVE_MODE_HELP=synocli.INTERACTIVE_MODE_HELP)

text = """## synocli - {description}
{readme}""".format(description=synocli.DESCRIPTION.split('\n')[0], readme=readme)

file.write_text(text)

print("[*] DONE, wrote %s" % file)
