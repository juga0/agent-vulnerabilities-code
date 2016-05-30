#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from cve_search_parser import obtain_vendor_product_dict
from deps_parser import obtain_package_app
from fuzzywuzzy import fuzz
logger = logging.getLogger(__name__)
logging.basicConfig()
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.INFO)

THRESHOLD = 50
JSON_PATH = 'cve_search_parse/example_data/cve-search_google_android_output.json'
DEPS_PATH = 'deps2json/example_data/deps-signal-android-v3.15.2.txt'

def compare_cpe_packages(json_path, deps_path):
    vendorproductdict = obtain_vendor_product_dict(json_path)
    packageappdict = obtain_package_app(deps_path)
    for vendor, products in vendorproductdict.items():
        for package, apps in packageappdict.items():
            for product in products:
                for app in apps:
                    logger.debug('comparing vendor %s with package %s',
                                 vendor, package)
                    if package.find(vendor) > -1:
                        logger.info('package %s has vendor %s in name',
                                    package, vendor)
                    logger.debug('comparing vendor %s with app %s', vendor,
                                 app)
                    if app.find(vendor) > -1:
                        logger.info('app %s has vendor %s in name', app,
                                    vendor)
                    logger.debug('comparing product %s with package %s',
                                 product, package)
                    if package.find(product) > -1:
                        logger.info('package %s has product %s in name',
                                    package, product)
                    logger.debug('comparing product %s with app %s', product,
                                 app)
                    if app.find(product) > -1:
                        logger.info('app %s has product %s in name', app,
                                    product)


def compare_cpe_packages_fuzzy(json_path, deps_path):
    vendorproductdict = obtain_vendor_product_dict(json_path)
    packageappdict = obtain_package_app(deps_path)
    for vendor, products in vendorproductdict.items():
        for package, apps in packageappdict.items():
            for product in products:
                for app in apps:
                    logger.debug('comparing vendor %s with package %s',
                                 vendor, package)
                    ratio = fuzz.token_sort_ratio(package, vendor)
                    if ratio > THRESHOLD:
                        logger.info('package %s and vendor %s has ratio %s',
                                    package, vendor, ratio)
                    logger.debug('comparing vendor %s with app %s', vendor,
                                 app)
                    ratio = fuzz.token_sort_ratio(app, vendor)
                    if ratio > THRESHOLD:
                        logger.info('app %s and vendor %s in has ratio %s', app,
                                    vendor, ratio)
                    logger.debug('comparing product %s with package %s',
                                 product, package)
                    ratio = fuzz.token_sort_ratio(package, product)
                    if ratio > THRESHOLD:
                        logger.info('package %s and product %s has ratio %s',
                                    package, product, ratio)
                    logger.debug('comparing product %s with app %s', product,
                                 app)
                    ratio = fuzz.token_sort_ratio(app, product)
                    if ratio > THRESHOLD:
                        logger.info('app %s and product %s has ratio %s', app,
                                    product, ratio)



def main():
    compare_cpe_packages_fuzzy(JSON_PATH, DEPS_PATH)
    compare_cpe_packages(JSON_PATH, DEPS_PATH)

if __name__ == "__main__":
    main()
