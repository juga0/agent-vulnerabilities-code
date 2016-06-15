from os.path import join, abspath, dirname

BASE_PATH = abspath(__file__)
# BASE_PATH = abspath('.')
ROOT_PATH = dirname(BASE_PATH)
PROJECT_PATH = dirname(ROOT_PATH)
ROOT_PROJECT_PATH = dirname(PROJECT_PATH)
AGENTS_MODULE_DIR = 'agents-common-code'
AGENTS_MODULE_PATH = join(ROOT_PROJECT_PATH, AGENTS_MODULE_DIR)

ISSUES_RULES_REPO_PATH = join(PROJECT_PATH, 'agent-vulnerabilities-issues')
ISSUES_RULES_REPO_FILENAME = join(ISSUES_RULES_REPO_PATH, 'repos_issues.yml')
# ISSUES_RULES_REPO_URL = 'git@code.iilab.org:openintegrity-agents/agent-vulnerabilities-issues.git'
                         # https://code.iilab.org/openintegrity-agents/agent-vulnerabilities-issues
ISSUES_RULES_REPO_URL = 'git@github.com:juga0/agent-vulnerabilities-issues.git'
ISSUES_RULES_REPO_BRANCH = 'master'

JSON_EXT = '.json'
YAML_EXT = '.yaml'

ISSUES_DATA_REPO_NAME = 'agent-vulnerabilities-issues-data'
ISSUES_DATA_REPO_PATH = join(PROJECT_PATH, ISSUES_DATA_REPO_NAME)
ISSUES_DATA_TEMP_PATH = join(PROJECT_PATH, 'tmp')
# ISSUES_DATA_REPO_URL = "git@code.iilab.org:openintegrity-agents/agent-vulnerabilities-issues-data.git"
ISSUES_DATA_REPO_URL = "git@github.com:juga0/agent-vulnerabilities-issues-data.git"
ISSUES_DATA_REPO_BRANCH = 'master'

METADATA_PATH = join(ISSUES_DATA_REPO_PATH, 'metadata.yml')

try:
    from config_local import *
except:
    print "no local config"
