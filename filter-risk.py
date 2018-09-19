#!/usr/bin/python3

import glob
import subprocess

plugin_paths = glob.glob("nessus-samples/*.nasl") + glob.glob("nessus-samples/*.nbin")

for path in plugin_paths:
    xml = subprocess.check_output(["/opt/nessus/bin/nasl", "-VVVVV", path])

