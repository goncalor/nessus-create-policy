#!/usr/bin/python3

import subprocess
import xml.etree.ElementTree as ET
import os.path
import re
from cvss import CVSS2, CVSS3

p_id = re.compile('script_id\((?P<script_id>.*)\)')
p_name = re.compile('''script_name\([^"']*["'](?P<script_name>.*)["']\)''')
p_name_alt = re.compile('name\[".*"\].*"(?P<script_name>.*)"')
p_cvss2 = re.compile('script_set_cvss_base_vector\([^"]*"CVSS2#(?P<cvss2_vect>.*)"\)')
# TODO: add cvss2 alternative for cases where script_set_attribute is used
p_cvss3 = re.compile('script_set_cvss3_base_vector\([^"]*"(?P<cvss2_vect>.*)"\)')
p_risk_factor = re.compile(
        '''script_set_attribute\([^)]+risk_factor[^)]+["']([^"']+)["']\s*\)''',
        re.DOTALL)
p_deps = re.compile('script_dependencies\((?P<script_deps>.+?)\)', re.DOTALL)

def extract_nasl_info(nasl_paths):
    plugins_info = {}
    for path in nasl_paths:
        with open(path) as f:
            t = f.read()
        info = {}

        m = p_id.search(t)
        info['script_id'] = m.group(1) if m else None

        m = p_name.search(t)
        m = m if m else p_name_alt.search(t)
        info['script_name'] = m.group(1) if m else None

        # some CVSS strings have leading/trailing spaces, hence the use of strip()
        m = p_cvss2.search(t)
        info['cvss2'] = float(CVSS2(m.group(1).strip()).base_score) if m else None
        m = p_cvss3.search(t)
        info['cvss3'] = float(CVSS3(m.group(1).strip()).base_score) if m else None

        m = p_risk_factor.search(t)
        info['risk_factor'] = m.group(1) if m else None

        m = p_deps.search(t)
        info['dependencies'] = [d.strip(''' "'\n\t''')
                for d in m.group(1).split(',')] if m else []

        plugins_info[os.path.basename(path)] = info

    return plugins_info

def extract_nbin_info(nbin_paths):
    plugins_info = {}
    for path in nbin_paths:
        # it should be more efficient to call 'nasl' with multiple files
        xml = subprocess.check_output(['/opt/nessus/bin/nasl', '-VVVVV', path])
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

        # TODO: extract these if needed in the future
        info['cvss2'] = None
        info['cvss3'] = None

        try:
            info['risk_factor'] = root.find(
                    'attributes/attribute[name="risk_factor"]/value').text
        except:
            info['risk_factor'] = None

        info['dependencies'] = [dep.text
                for dep in root.findall('dependencies/dependency')]

        plugins_info[os.path.basename(path)] = info

    return plugins_info

if __name__ == '__main__':
    import glob
    import sys
    from pprint import pprint
    # TODO: check that sys.argv[1] is a directory and ends in /
    nasl_paths = glob.glob(sys.argv[1] + '*.nasl')
    nbin_paths = glob.glob(sys.argv[1] + '*.nbin')

    info = {**extract_nasl_info(nasl_paths), **extract_nbin_info(nbin_paths)}
    pprint(info)
