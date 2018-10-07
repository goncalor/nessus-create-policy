#!/usr/bin/python3

import glob
import sys
import plugin_info

def calc_severity(info):
    cvss2 = info['cvss2']
    cvss3 = info['cvss3']
    risk = info['risk_factor']

    if cvss2:
        if cvss2 >= 9.0:
            return 'Critical'
        elif cvss2 >= 7.0:
            return 'High'
        elif cvss2 >= 4.0:
            return 'Medium'
        else:
            return 'Low'

    if cvss3:
        if cvss3 >= 9.0:
            return 'Critical'
        elif cvss3 >= 7.0:
            return 'High'
        elif cvss3 >= 4.0:
            return 'Medium'
        else:
            return 'Low'

    if risk:
        if risk == 'None':
            return 'Info'
        return risk

    return None
