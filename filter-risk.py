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
