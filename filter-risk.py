#!/usr/bin/python3

import glob
import subprocess
import xml.etree.ElementTree as ET

plugin_paths = glob.glob("nessus-samples/*.nasl") + glob.glob("nessus-samples/*.nbin")

for path in plugin_paths:
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
