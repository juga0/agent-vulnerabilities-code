#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Functions to ..."""

import sys
from github_config import AGENTS_MODULE_PATH
sys.path.append(AGENTS_MODULE_PATH)
import requests
from agents_common.json_utils import write_json
from agents_common.yaml_utils import write_yaml
import logging

logger = logging.getLogger(__name__)
logging.basicConfig()
logger.setLevel(logging.DEBUG)

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


def obtain_issues(url, path, request=True):
    logger.debug('path %s' % path)
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


def write_issues(issues, cve_issues_path, format='json'):
    logger.debug('cve_issues_path %s' % cve_issues_path)
    if format == 'json':
        write_json(issues, cve_issues_path)
    else:
        write_yaml(issues, cve_issues_path)
