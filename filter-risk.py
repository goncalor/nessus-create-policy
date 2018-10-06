#!/usr/bin/python3

import glob
import subprocess
import xml.etree.ElementTree as ET
import sys
import os.path
import re

# TODO: check that sys.argv[1] is a directory and ends in /
nasl_paths = glob.glob(sys.argv[1] + "*.nasl")
nbin_paths = glob.glob(sys.argv[1] + "*.nbin")

plugins_info = {}

p_id = re.compile('script_id\((?P<script_id>.*)\)')
for path in nasl_paths:
    with open(path) as f:
        t = f.read()
    info = {}

    m = p_id.search(t)
    info['script_id'] = m.group(1) if m else None

    plugins_info[os.path.basename(path)] = info

for path in nbin_paths:
    # it should be more efficient to call 'nasl' with multiple files
    xml = subprocess.check_output(["/opt/nessus/bin/nasl", "-VVVVV", path])
    root = ET.fromstring(xml)

    info = {}
    try:
        info['script_id'] = root.find('script_id').text
    except:
        info['script_id'] = None

    try:
        info['script_name'] = root.find('script_name').text
    except:
        info['script_name'] = None

    try:
        info['risk_factor'] = root.find(
                'attributes/attribute[name="risk_factor"]/value').text
    except:
        info['risk_factor'] = None

    info['dependencies'] = [dep.text for dep in root.findall('dependencies/dependency')]

    plugins_info[os.path.basename(path)] = info

print(plugins_info)
