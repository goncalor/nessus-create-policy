#!/usr/bin/python3

import glob
import subprocess
import xml.etree.ElementTree as ET
import sys

# TODO: check that sys.argv[1] is a directory and ends in /
nasl_paths = glob.glob(sys.argv[1] + "*.nasl")
nbin_paths = glob.glob(sys.argv[1] + "*.nbin")

for path in nbin_paths:
    # it should be more efficient to call 'nasl' with multiple files
    xml = subprocess.check_output(["/opt/nessus/bin/nasl", "-VVVVV", path])

    root = ET.fromstring(xml)
    try:
        risk_factor = root.find('attributes/attribute[name="risk_factor"]/value').text
    except:
        risk_factor = None

    if risk_factor!='Critical' and risk_factor!='High':
        continue

    script_id = root.find('script_id').text
    print(';'.join([script_id, risk_factor]))
