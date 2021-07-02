'''
Akond Rahman 
Constants to make Taintible work 
July 01, 2021 
'''

FILE_READ_FLAG               = 'r'
YAML_EXTENSION               = 'yaml'
YML_EXTENSION                = 'yml'
CSV_ENCODING                 = 'latin-1'
WEIRD_PATHS                  = ['github/workflows/', '.github/', '.travis.yml']
ASI_MAMA                     = 'ASI MAMA ASI '


PORTS_KEYWORD                = 'ports'
PORT_KEYWORD                 = 'port'
CONTAINER_PORT_KEYWORD       = 'containerPort'
TARGET_PORT_KEYWORD          = 'targetPort'
PROTOCOL_KEYWORD             = 'protocol'
SSH_PORT_KEYWORD             = 'ssh_port'


SSH_DEFAULT_PORT_VAL         = 22
SSH_KEYWORD                  = 'SSH'
HTTP_DEFAULT_PORT_VAL        = 80
HTTP_KEYWORD                 = 'HTTP'
HTTPS_DEFAULT_PORT_VAL       = 443
HTTPS_KEYWORD                = 'HTTPS'
MONGO_DEFAULT_PORT_VAL       = 27017 
MONGO_KEYWORD                = 'MONGO'


FILE_READ_MODE               = 'r'
NEWLINE_CONSTANT             = '\n'
COMMENT_SYMBOL               = '#'
CWE_SUSP_COMMENT_LIST        = ['hack', 'fixme', 'later', 'todo', 'to-do', 'bug'  ]
DEBUG_KW                     = 'debug' 
NULL_SYMBOL                  = ''
WHITESPACE_SYMBOL            = ' '


QUOTE_SYMBOL                 = "'"
IP_ADDRESS_PATTERN           = '0.0.0.0'
HTTP_PATTERN                 = 'http://'
HTTPS_PATTERN                = 'https://'
VALID_CONFIG_DEFAULT         = 'VALID_CONFIG_SAMPLE_PLACEHOLDER' 
YUM_KW                       = 'yum'
DUMMY_ASCII                  = 0
ALLOWABLE_TYPES              = [ bool, int, str ]
ALLOWABLE_INSECURE_HTTP_STRS = [ HTTP_PATTERN ] 
REPO_STRS_V1                 = ['.dmg', '.rpm', '.tzr.gz', '.tgz', '.zip', '.tar', '.rar']
REPO_STRS_V2                 = ['mirrors.fedoraproject.org', 'repos.', 'releases/', '_repository_base']
UNALLOWED_HTTP_STRS          = ['.org', '.edu'] + REPO_STRS_V1 

VALID_PASSWORD_STRS          = ['password', 'passwd', 'pass', 'rootpw']
INVALID_PASSWORD_STRS        = ['vault_', 'vaulted_'] 
VALID_USERNAME_STRS          = ['user']
INVALID_USERNAME_STRS        = ['become_user', 'remote_user', 'vault_', 'vaulted_']
VALID_PRIVATE_STRS           = ['pvt', 'priv']
VALID_KEY_STRS               = ['cert', 'key', 'rsa', 'secret', 'ssl']
INVALID_KEY_STRS             = ['vault_', 'vaulted_'] 

INTEG_KW_LIST                = ['gpgcheck', 'check_sha', 'checksum', 'checksha'] 
NO_KEYWORD                   = 'no'
VAR_REFF_PATTERN             = '{{' 

