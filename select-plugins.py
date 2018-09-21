#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import csv
import sys
import argparse
import os.path

parser = argparse.ArgumentParser(description='Edit a .nessus policy file to select individual plugins')
parser.add_argument("plugin_ids_file", metavar="<file.csv>", type=str, help="file with the IDs for plugins to select")
parser.add_argument("input_nessus_file", metavar="<file_in.nessus>", type=str, help="input .nessus file")
parser.add_argument("output_nessus_file", metavar="<file_out.nessus>", type=str, help="output .nessus file")

args = parser.parse_args()

for file in [args.input_nessus_file, args.plugin_ids_file]:
    if not os.path.isfile(file):
        print("'{}' does not exist".format(file))
        sys.exit(1)

with open(args.plugin_ids_file, newline='') as csvfile:
    plugin_ids = [row[0] for row in csv.reader(csvfile, delimiter=';', quotechar='|') if row[0].isdigit()]
    nr_plugins = len(plugin_ids)
    # remove duplicate plugins
    plugin_ids = list(set(plugin_ids))
    if len(plugin_ids) != nr_plugins:
        print('WARN: Found duplicate plugin IDs', file=sys.stderr)
        nr_plugins = len(plugin_ids)

try:
    tree = ET.parse(args.input_nessus_file)
    root = tree.getroot()
except:
    print('ERROR: Bad .nessus input file', file=sys.stderr)
    sys.exit(1)

# create an empty IndividualPluginSelection
policy = root.find('Policy')
individual_plugins = policy.find('IndividualPluginSelection')
if individual_plugins:
    policy.remove(individual_plugins)
individual_plugins = ET.Element('IndividualPluginSelection')
policy.append(individual_plugins)

# enable only the needed plugins
for id in plugin_ids:
    item = ET.fromstring('<PluginItem><PluginId>{}</PluginId><Status>enabled</Status></PluginItem>'.format(id))
    individual_plugins.append(item)

# mark all plugin families' statuses as mixed
family_selection = policy.find('FamilySelection')
for fam_item in family_selection:
    fam_status = fam_item.find('Status')
    fam_item.remove(fam_status)
    fam_item.append(ET.fromstring('<Status>mixed</Status>'))

# TODO: if no output file is provided output to stdout
tree.write(args.output_nessus_file)
print('Wrote output file {}'.format(args.output_nessus_file))
