#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Functions to ..."""

import sys
from os.path import join, isdir
from os import makedirs
from github_config import AGENTS_MODULE_PATH
sys.path.append(AGENTS_MODULE_PATH)
from agents_common.policies_util import obtain_yaml, commit_push_if_changes, \
    create_data_file_path, ismorpio
from agents_common.git_ssh_utils import write_ssh_keys, write_ssh_command, \
    write_ssh_key_server
from agents_common.git_utils import pull_or_clone
from github_utils import obtain_issues, write_issues, parse_issues

import logging

logger = logging.getLogger(__name__)
logging.basicConfig()
logger.setLevel(logging.DEBUG)

from github_config import ISSUES_RULES_REPO_PATH, ISSUES_RULES_REPO_URL, \
    ISSUES_RULES_REPO_BRANCH, ISSUES_DATA_REPO_PATH, ISSUES_DATA_REPO_URL, \
    ISSUES_DATA_REPO_BRANCH, ISSUES_DATA_REPO_NAME, METADATA_PATH, \
    ISSUES_RULES_REPO_FILENAME,  YAML_EXT, JSON_EXT, ISSUES_DATA_TEMP_PATH
from agents_common.common_config import SSH_PATH, MORPH_SSH_PRIV_KEY_ENV, \
    MORPH_SSH_PUB_KEY_ENV, SSH_PRIV_KEY_PATH, SSH_PUB_KEY_PATH, \
    GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL, GIT_SSH_COMMAND_PATH, GIT_SSH_COMMAND, \
    GIT_SSH_COMMAND_MORPHIO, GITHUB_SSH_PUB_KEY, SSH_PUB_KEY_SERVER_PATH



def main():

    # Write ssh keys and command neede for git
    write_ssh_keys(SSH_PATH, MORPH_SSH_PRIV_KEY_ENV, MORPH_SSH_PUB_KEY_ENV,
                   SSH_PRIV_KEY_PATH, SSH_PUB_KEY_PATH)

    if ismorpio():
        write_ssh_command(GIT_SSH_COMMAND_PATH, GIT_SSH_COMMAND_MORPHIO)
    else:
        write_ssh_command(GIT_SSH_COMMAND_PATH, GIT_SSH_COMMAND)

    write_ssh_key_server(GITHUB_SSH_PUB_KEY, SSH_PUB_KEY_SERVER_PATH)

    # Obtain the data repositories configuration
    # TODO: not doing for now, replaced with XXX
    # repos_conf = obtain_yaml(CONFIG_REPO_PATH, CONFIG_REPO_URL,
    #                          CONFIG_REPO_BRANCH, CONFIG_PATH)

    # Obtain the rules from the rules repository
    rules = obtain_yaml(ISSUES_RULES_REPO_PATH, ISSUES_RULES_REPO_URL,
                        ISSUES_RULES_REPO_BRANCH,
                        file_path=ISSUES_RULES_REPO_FILENAME,
                        git_ssh_command_path=GIT_SSH_COMMAND_PATH)
    logger.debug('rules %s' % rules)

    # # Pull or clone the data repos
    # repos = []
    # for repo_conf in repos_conf:
    #     logger.debug('repo name %s' % repo_conf.get('name'))
    #     repo = pull_or_clone(ISSUES_DATA_REPO_PATH, repo_conf.get('url'),
    #                          ISSUES_DATA_REPO_BRANCH, repo_conf.get('name'),
    #                          GIT_SSH_COMMAND_PATH, False)
    #     repos.append(repo)

    repo = pull_or_clone(ISSUES_DATA_REPO_PATH, ISSUES_DATA_REPO_URL,
                     ISSUES_DATA_REPO_BRANCH, ISSUES_DATA_REPO_NAME,
                     GIT_SSH_COMMAND_PATH, False)

    for rule in rules:
        logger.debug('rule %s' % rule)
        issues_temp_path = join(ISSUES_DATA_TEMP_PATH, rule['name'] + JSON_EXT)
        logger.debug('issues_temp_path %s' % issues_temp_path)
        if not isdir(ISSUES_DATA_TEMP_PATH):
            makedirs(ISSUES_DATA_TEMP_PATH)
            logger.debug('created  %s' % ISSUES_DATA_TEMP_PATH)
        issues = obtain_issues(rule['issues_search_url'], issues_temp_path)
        cve_issues = parse_issues(issues, keyword='CVE')
        #issues_path = create_data_file_path(rule, ISSUES_DATA_REPO_PATH)
        issues_path = join(ISSUES_DATA_REPO_PATH,  rule['name'] + YAML_EXT)
        logger.debug('issues_path %s' % issues_path)
        write_issues(cve_issues, issues_path, 'yaml')

    # for repo in repos:
    commit_push_if_changes(repo, GIT_AUTHOR_NAME, GIT_AUTHOR_EMAIL,
                               GIT_SSH_COMMAND_PATH, ISSUES_RULES_REPO_BRANCH,
                               METADATA_PATH)



if __name__ == '__main__':
    main()
