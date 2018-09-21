#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import csv
import argparse
import os.path

parser = argparse.ArgumentParser(description='Edit a .nessus policy file to select individual plugins')
parser.add_argument("plugin_ids_file", metavar="<file.csv>", type=str, help="file with the IDs for plugins to select")
parser.add_argument("input_nessus_file", metavar="<file.nessus>", type=str, help="input .nessus file")

args = parser.parse_args()
