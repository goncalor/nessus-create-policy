#!/usr/bin/python3

import glob
import subprocess
import xml.etree.ElementTree as ET
import sys

# TODO: check that sys.argv[1] is a directory and ends in /
nasl_paths = glob.glob(sys.argv[1] + "*.nasl")
nbin_paths = glob.glob(sys.argv[1] + "*.nbin")

plugins_info = {}

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
        info['risk_factor'] = root.find(
                'attributes/attribute[name="risk_factor"]/value').text
    except:
        info['risk_factor'] = None

    plugins_info[path] = info

print(plugins_info)
