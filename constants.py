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
VALID_CONFIG_DEFAULT         = 'VALID_CONFIG_SAMPLE_PLACEHOLDER' 
YUM_KW                       = 'yum'
DUMMY_ASCII                  = 0
ALLOWABLE_TYPES              = [ bool, int, str ]
