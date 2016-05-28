#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Functions to parse the output of cve-search json."""
from os.path import abspath, dirname, join
import json
import logging

logger = logging.getLogger(__name__)
logging.basicConfig()
logger.setLevel(logging.DEBUG)

NO_ANDROID_VENDORS = ['microsoft', 'novell', 'apple', 'redhat', 'adobe',
                      'linux','koushik_dutta', 'conectiva', 'chainfire',
                      'androidsu']
BASE_PATH = dirname(abspath(__file__))
CVE_SEARCH_JSON_OUTPUT_REL_PATH = \
    'example_data/cve-search_google_android_output.json'
CVE_SEARCH_JSON_OUTPUT_PATH = join(BASE_PATH, CVE_SEARCH_JSON_OUTPUT_REL_PATH)


def obtain_list_vendor_product_dict(json_path):
    cpelistdict = []
    with open(json_path) as f:
        json_data = json.load(f)
    for vuln in json_data:
        list_cpe = vuln['vulnerable_configuration']
        for cpe in list_cpe:
            d = {'vendor': None, 'product': None, 'version':None}
            d['vendor'], d['product'], d['version'] = cpe.split(':')[3:]
            cpelistdict.append(d)
    return cpelistdict


def obtain_vendor_product_dict(json_path):
    vendorproductdict = {}
    with open(json_path) as f:
        json_data = json.load(f)
    for vuln in json_data:
        list_cpe = vuln['vulnerable_configuration']
        for cpe in list_cpe:
            cpe_list = cpe.split(':')
            if vendorproductdict.get(cpe_list[3]):
                vendorproductdict[cpe_list[3]].add(cpe_list[4])
            else:
                vendorproductdict[cpe_list[3]] = set([cpe_list[4]])
    for key in NO_ANDROID_VENDORS:
        del vendorproductdict[key]
    logger.info('vendorproductdict keys %s', vendorproductdict.keys())
    return vendorproductdict


def main():
    vendorproductdict = obtain_vendor_product_dict(CVE_SEARCH_JSON_OUTPUT_PATH)
    print vendorproductdict


if __name__ == "__main__":
    main()
