#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Functions to ..."""

from os.path import abspath, dirname, join
import yaml
import json
from markdown import markdown
import requests
import logging
logger = logging.getLogger(__name__)
logging.basicConfig()
logger.setLevel(logging.DEBUG)

# TODO: move constants to settings or main arguments
BASE_PATH = dirname(abspath(__file__))
DATA_DIR = 'example_data'
GH_API_URL = 'https://api.github.com'
GH_REPOS_REL_URL = '/repos'
# FIXME: read this data from other repo
GH_REPO_REL_URL = 'WhisperSystems/Signal-Android'
GH_ISSUES_REL_URL = '/issues'
GH_PAG = '?per_page=100&page={0}&state=all'
GH_ISSUES_URL = GH_API_URL + GH_REPOS_REL_URL + \
                '/' + GH_REPO_REL_URL + \
                GH_ISSUES_REL_URL + \
                GH_PAG
GH_ISSUES_URL = GH_ISSUES_URL.format("1")
GH_ORD = '&sort=created&order=asc'
KEYWORD = 'CVE'
GH_SEARCH_ISSUES_URL = GH_API_URL + '/search/issues?q={0}+repo:{1}'.format(
                       KEYWORD, GH_REPO_REL_URL) + GH_ORD + GH_PAG.format("1")
JSON_EXT = '.json'
YAML_EXT = '.yaml'
GH_OUTPUT_FILE = GH_REPO_REL_URL.replace('/', '_')
GH_OUTPUT_JSON_FILE = GH_OUTPUT_FILE + JSON_EXT
GH_OUTPUT_JSON_PATH = join(BASE_PATH, DATA_DIR, GH_OUTPUT_JSON_FILE)
GH_KEYWORD_FILE = GH_OUTPUT_FILE + '_' + KEYWORD
GH_KEYWORD_JSON_FILE = GH_KEYWORD_FILE + JSON_EXT
GH_KEYWORD_JSON_PATH = join(BASE_PATH, DATA_DIR, GH_KEYWORD_JSON_FILE)
GH_KEYWORD_YAML_FILE = GH_KEYWORD_FILE + YAML_EXT
GH_KEYWORD_YAML_PATH = join(BASE_PATH, DATA_DIR, GH_KEYWORD_YAML_FILE)


def request_search_issues(url):
    # FIXME: is it needed pagination?
    r = requests.get(url)
    result_json = r.json()
    if result_json.get('total_count') > 0:
        return result_json.get('items')
    return []


def request_issues(url):
    logger.debug('url: %s' % url)
    next_url = url
    logging.debug('next url %s' % next_url)
    issues = []
    while next_url:
        r = requests.get(next_url)
        next_url = r.links.get('next', None)
        issues.append(r.json())
    return issues


def read_json(path):
    with open(path) as f:
        obj = json.load(f)
    return obj


def obtain_issues(url, path, request=True):
    if request:
        issues = request_search_issues(url)
        write_json(issues, path)
    else:
        issues = read_json(path)
    logger.debug('number of issues in %s is %s: ' % (path, len(issues)))
    return issues


def create_cve_issue(issue):
    cve_issue = {'url': issue['url'],
                 'html_url': issue['html_url'],
                 'title': issue['title'],
                 'body': issue['body'],
                 'number': issue['number'],
                 'comments_url': issue['comments_url'],
                 'created_at': issue['created_at'],
                 'updated_at': issue['updated_at']}
    return cve_issue


def parse_issues(issues, keyword='CVE'):
    logger.debug('parsing %s issues' % len(issues))
    logger.debug('searching for issues with keyword %s' % keyword)
    cve_issues = [create_cve_issue(i) for i in issues
                  if (keyword in i.get('body') or keyword in i.get('title'))]
    logger.debug('found %s issues with keyword %s' %
                 (len(cve_issues), keyword))
    return cve_issues


def write_json(dictionary, filepath):
    with open(filepath, 'w') as f:
        json.dump(dictionary, f)


def write_yaml(dictionary, filepath):
    with open(filepath, 'w') as f:
        f.write(yaml.safe_dump(dictionary))


def write_issues(issues, cve_issues_path, format='json'):
    if format == 'json':
        write_json(issues, cve_issues_path)
    else:
        write_yaml(issues, cve_issues_path)


def main():
    issues = obtain_issues(GH_SEARCH_ISSUES_URL, GH_OUTPUT_JSON_PATH)
    # cve_issues = parse_issues(issues, keyword='CVE')
    write_issues(issues, GH_KEYWORD_JSON_PATH)


if __name__ == '__main__':
    main()
