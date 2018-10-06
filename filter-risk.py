#!/usr/bin/python3

import glob
import subprocess
import xml.etree.ElementTree as ET
import sys
import os.path
import re
from cvss import CVSS2, CVSS3

# TODO: check that sys.argv[1] is a directory and ends in /
nasl_paths = glob.glob(sys.argv[1] + "*.nasl")
nbin_paths = glob.glob(sys.argv[1] + "*.nbin")

plugins_info = {}

p_id = re.compile('script_id\((?P<script_id>.*)\)')
p_name = re.compile('script_name\([^"]*"(?P<script_name>.*)"\)')
p_name_alt = re.compile('name\[".*"\].*"(?P<script_name>.*)"')
p_cvss2 = re.compile('script_set_cvss_base_vector\([^"]*"CVSS2#(?P<cvss2_vect>.*)"\)')
p_cvss3 = re.compile('script_set_cvss3_base_vector\([^"]*"(?P<cvss2_vect>.*)"\)')
# TODO: some plugins have a risk_factor instead of CVSS
for path in nasl_paths:
    with open(path) as f:
        t = f.read()
    info = {}

    m = p_id.search(t)
    info['script_id'] = m.group(1) if m else None

    m = p_name.search(t)
    m = m if m else p_name_alt.search(t)
    info['script_name'] = m.group(1) if m else None

    m = p_cvss2.search(t)
    info['cvss2'] = float(CVSS2(m.group(1).strip()).base_score) if m else None
    m = p_cvss3.search(t)
    info['cvss3'] = float(CVSS3(m.group(1).strip()).base_score) if m else None

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
