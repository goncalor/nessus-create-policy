#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import csv
import sys
import argparse
import os.path

parser = argparse.ArgumentParser(description='Edit a .nessus policy file to select individual plugins')
parser.add_argument("plugin_ids_file", metavar="<file.csv>", type=str, help="file with the IDs for plugins to select")
parser.add_argument("input_nessus_file", metavar="<file.nessus>", type=str, help="input .nessus file")

args = parser.parse_args()

for file in [args.input_nessus_file, args.plugin_ids_file]:
    if not os.path.isfile(file):
        print("'{}' does not exist".format(file))
        sys.exit(1)

with open(args.plugin_ids_file, newline='') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=';', quotechar='|')

    # FIXME: check if a header is present

    for row in csv.reader(csvfile, delimiter=';', quotechar='|'):
        print(row)
