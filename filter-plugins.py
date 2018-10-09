#!/usr/bin/python3

import plugin_info
import argparse
import glob
import sys

known_severities = ['info', 'low', 'medium', 'high', 'critical']

parser = argparse.ArgumentParser(
        description='Filter Nessus plugins according to severity and name')
parser.add_argument('--severity', default=','.join(known_severities),
        type=lambda s: {sev for sev in s.split(',')},
        help='''severities to consider, specified as a comma separated list.
        Allowed values: info, low, medium, high, critical. Example:
        high,critical. Default: %(default)s''')
parser.add_argument('plugin_dir', metavar='plugin_dir', nargs='?', type=str,
        help='directory containing Nessus plugin scripts. Default: %(default)s',
        default='/opt/nessus/lib/nessus/plugins/')
args = parser.parse_args()

if not all([sev in known_severities for sev in args.severity]):
    print('ERROR: unknown severity value', file=sys.stderr)
    parser.print_help()
    sys.exit(1)

# Capitalise the first character of each severity
args.severity = {sev.title() for sev in args.severity}

def calc_severity(info):
    cvss2 = info['cvss2']
    cvss3 = info['cvss3']
    risk = info['risk_factor']

    if risk:
        if risk == 'None':
            return 'Info'
        return risk

    # As of October 2018 all scripts that have a CVSS3 vector also have CVSS2.
    # Therefore, CVSS3 needs to be tested first to have any effect at all
    if cvss3:
        if cvss3 >= 9.0:
            return 'Critical'
        elif cvss3 >= 7.0:
            return 'High'
        elif cvss3 >= 4.0:
            return 'Medium'
        else:
            return 'Low'

    if cvss2:
        if cvss2 >= 9.0:
            return 'Critical'
        elif cvss2 >= 7.0:
            return 'High'
        elif cvss2 >= 4.0:
            return 'Medium'
        else:
            return 'Low'

    return None

def find_deps(info, plugins, deps):
    for p in plugins:
        try:
            # TODO: use sets to represent dependencies
            neigh = set(info[p]['dependencies'])
        except:
            print('WARN: missing information on plugin ' + p, file=sys.stderr)
            continue
        s = neigh - deps
        deps.update(s)
        find_deps(info, s, deps)


nasl_paths = glob.glob(args.plugin_dir + '*.nasl')
nbin_paths = glob.glob(args.plugin_dir + '*.nbin')
print('Parsing .nasl files... ', end='', flush=True)
info = plugin_info.extract_nasl_info(nasl_paths)
print('Done')
print('Parsing .nbin files... ', end='', flush=True)
info = {**info, **plugin_info.extract_nbin_info(nbin_paths)}
print('Done')

filtered = set()
for p in info:
    if calc_severity(info[p]) in args.severity:
        filtered.add(p)

# Recursively find dependencies for the plugins of interest
deps = set()
find_deps(info, filtered, deps)

for p in filtered | deps:
    try:
        print('{};{};{}'.format(info[p]['script_id'], p, calc_severity(info[p])))
    except KeyError:
        pass
