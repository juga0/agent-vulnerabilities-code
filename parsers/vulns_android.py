#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Functions to obtain Android vulnerabilities from the output of \
cve-search json."""

from os.path import abspath, dirname, join
import yaml
import json
import logging
logger = logging.getLogger(__name__)
logging.basicConfig()
logger.setLevel(logging.DEBUG)

CPE_NAME_ANDROID = 'google:android'

BASE_PATH = dirname(abspath(__file__))
CVE_SEARCH_JSON_OUTPUT_REL_PATH = \
    'example_data/cve-search_google_android_output.json'
CVE_SEARCH_JSON_OUTPUT_PATH = join(BASE_PATH, CVE_SEARCH_JSON_OUTPUT_REL_PATH)
DATA_DIR = 'example_data'
ANDROVULNS_YAML_FILE = 'android_%s_vulnerabilities_output.yaml'
ANDROVULNS_YAML_PATH = join(BASE_PATH, DATA_DIR, ANDROVULNS_YAML_FILE)

def textual_cvss(cvss_score):
    if cvss_score == 0:
        return 'None'
    elif 0.1 <= cvss_score <= 3.9:
        return 'Medium'
    elif 4.0 <= cvss_score <= 6.9:
        return 'High'
    elif 9.0 <= cvss_score <= 10.0:
        return 'Critical'
    return 'Not known'


def obtain_andro_vulns(json_path, andro_version=None):
    with open(json_path) as f:
        json_data = json.load(f)
    androvulnslist = []
    for vuln in json_data:
        vuln_confs_no_version = [':'.join(vuln_version.split(':')[3:5]) \
            for vuln_version in vuln.get('vulnerable_configuration')] + \
            [':'.join(vuln_version.split(':')[2:4]) \
            for vuln_version in vuln.get('vulnerable_configuration_cpe_2_2')]
        if CPE_NAME_ANDROID in vuln_confs_no_version:
            androvulndict = {}
            versions = list(set([':'.join(vuln_version.split(':')[5:]) \
                for vuln_version in vuln.get('vulnerable_configuration')] + \
                [':'.join(vuln_version.split(':')[4:]) \
                for vuln_version in vuln.get('vulnerable_configuration_cpe_2_2')]))
            if andro_version:
                if andro_version in versions:
                    androvulndict = {
                        'cve': vuln.get('id'),
                        'summary': vuln.get('summary'),
                        'severity': textual_cvss(vuln.get('cvss'))
                    }
            else:
                logger.debug('no version')
                androvulndict = {
                        'cve': vuln.get('id'),
                        'versions': versions,
                        'severity': textual_cvss(vuln.get('cvss'))
                }
            androvulnslist.append(androvulndict)
    return androvulnslist


def write_yaml(vulnslist, yaml_path):
    yamlvulns = yaml.safe_dump(vulnslist)
    with open(yaml_path, 'w') as f:
        f.write(yamlvulns)
    return yamlvulns



def obtain_cve(json_path, cve_id):
    with open(json_path) as f:
        json_data = json.load(f)
    vulns = [v for v in json_data if v.get('id') == cve_id]
    return vulns


def main():
    # TODO: take version from command line argument
    andro_version = '2.3.5'
    andro_version = 'None'
    androvulnslist = obtain_andro_vulns(CVE_SEARCH_JSON_OUTPUT_PATH, andro_version)
    logger.debug(ANDROVULNS_YAML_PATH)
    # FIXME path
    if andro_version:
        yaml_path = ANDROVULNS_YAML_PATH % andro_version
    else:
        yaml_path = ANDROVULNS_YAML_PATH % ''
    logger.debug(yaml_path)
    yamlvulnslist = write_yaml(androvulnslist, yaml_path)

if __name__ == "__main__":
    main()
