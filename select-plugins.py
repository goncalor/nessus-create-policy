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
    csvreader = csv.reader(csvfile, delimiter=';', quotechar='|')

    # FIXME: check if a header is present

    plugin_ids = [row[0] for row in csv.reader(csvfile, delimiter=';', quotechar='|') if row[0].isdigit()]

try:
    tree = ET.parse(args.input_nessus_file)
    root = tree.getroot()
except:
    print("ERROR: Bad .nessus input file")
    sys.exit(1)

# create an empty IndividualPluginSelection
policy = root.find('Policy')
individual_plugins = policy.find('IndividualPluginSelection')
if individual_plugins:
    policy.remove(individual_plugins)
individual_plugins = ET.Element('IndividualPluginSelection')
policy.append(individual_plugins)

for id in plugin_ids:
    item = ET.fromstring('<PluginItem><PluginId>{}</PluginId><Status>enabled</Status></PluginItem>'.format(id))
    individual_plugins.append(item)

family_selection = policy.find('FamilySelection')
for fam_item in family_selection:
    fam_status = fam_item.find('Status')
    fam_item.remove(fam_status)
    fam_item.append(ET.fromstring('<Status>mixed</Status>'))

# TODO: if no output file is provided output to stdout
tree.write(args.output_nessus_file)
