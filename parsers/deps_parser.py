"""Functions to parse the output of gradlew."""
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml
import re
import logging

logger = logging.getLogger(__name__)
logging.basicConfig()
# logger.setLevel(logging.DEBUG)

DEPS_PATH = 'example_data/deps-signal-android-v3.15.2.txt'
YAML_PATH = 'example_data/deps-signal-android-v3.15.2.yaml'


def deps2listdict(deps_path):
    """Convert the output of gradlew to a list of dicts"""
    deps_list_dict = []
    with open(deps_path) as f:
        depslines = f.readlines()
    for l in depslines:
        logger.debug('line: %s', l)
        d = {}
        text = re.findall(r'^(?:\W+)(\S+)', l)
        if text:
            text = text[0].split(':')
            d['vendor'], d['library'], d['version'] = text
            deps_list_dict.append(d)
            logger.debug('dependency parsed %s', text)
        else:
            print 'could not parse dependency'
    return deps_list_dict


def obtain_package_app_dict(deps_path):
    """Convert the output of gradlew to a dict of lists"""
    packageappdict = {}
    with open(deps_path) as f:
        depslines = f.readlines()
    for l in depslines:
        logger.debug('line: %s', l)
        text = re.findall(r'^(?:\W+)(\S+)', l)
        if text:
            packageapplist = text[0].split(':')
            if packageappdict.get(packageapplist[0]):
                packageappdict[packageapplist[0]].add(packageapplist[1])
            else:
                packageappdict[packageapplist[0]] = set([packageapplist[1]])
    return packageappdict


def listdict2yaml(list_dict, yaml_path):
    """Convert a list of dictionaries to yaml"""
    yaml_text = yaml.safe_dump(list_dict)
    with open(yaml_path, 'w') as f:
        f.write(yaml_text)


def main():
    deps_list_dict = deps2listdict(DEPS_PATH)
    listdict2yaml(deps_list_dict, YAML_PATH)

if __name__ == "__main__":
    main()
