'''
Akond Rahman 
July 01 , 2021 
Constants needed to execute test cases 
'''
_common_error_string = 'MUST BE '
_DICT_STRING         = 'Dictionary' 
_LIST_STRING         = 'List of dictionaries'  

parsing_resource1    = '_TEST_ARTIFACTS/conf.satperf.yaml'
parsing_resource2    = '_TEST_ARTIFACTS/satutils.satellite.yaml'
parsing_resource3    = '_TEST_ARTIFACTS/pacman.yaml' 


default_port_script1 = '_TEST_ARTIFACTS/pacman.default.port1.yaml'
default_port_script2 = '_TEST_ARTIFACTS/pacman.default.port2.yaml'
default_port_script3 = '_TEST_ARTIFACTS/pacman.default.port3.yaml'
default_port_script4 = '_TEST_ARTIFACTS/pacman.default.port4.yaml'
default_port_script5 = '_TEST_ARTIFACTS/roles.tp.default.port.yaml'
default_port_script6 = '_TEST_ARTIFACTS/roles.fp.default.port.yaml'


inavlid_ip_script1   = '_TEST_ARTIFACTS/1.invalid.ip.yaml'
inavlid_ip_script2   = '_TEST_ARTIFACTS/2.invalid.ip.yaml'

insecure_http_script1= '_TEST_ARTIFACTS/http.calico.main.yaml'     

fp_empty_pass_yaml1  = '_TEST_ARTIFACTS/fp.empty.password.yaml'
fp_empty_pass_yaml2  = '_TEST_ARTIFACTS/fp2.empty.pwd.yaml'
fp_empty_pass_yaml3  = '_TEST_ARTIFACTS/fp3.empty.pwd.yaml'

tp_no_integ_yaml1    = '_TEST_ARTIFACTS/no.integ1.yaml'
tp_no_integ_yaml2    = '_TEST_ARTIFACTS/no.integ2.yaml'
tp_no_integ_yaml3    = '_TEST_ARTIFACTS/no.integ3.yaml'
tp_value_url         = 'https://mirrors.fedoraproject.org/mirrorlist?repo=epel-7&arch=$basearch'
tp_var_reff_value    = '{{foreman_plugin_repository_base}}'

tp_secret_yaml       = '_TEST_ARTIFACTS/secret.tp.satperf.yaml'
root_pwd_str         = 'rootpw'
var_pattern_str      = '{{'
sample_var_name      = 'satperf_private_key'
fp_secret_yaml1      = '_TEST_ARTIFACTS/secret.fp1.satperf.yaml'
fp_secret_yaml2      = '_TEST_ARTIFACTS/secret.fp2.satperf.yaml'
fp_secret_yaml3      = '_TEST_ARTIFACTS/secret.fp3.satperf.yaml'
fp_secret_yaml4      = '_TEST_ARTIFACTS/secret.fp4.satperf.yaml'
fp_secret_yaml5      = '_TEST_ARTIFACTS/secret.fp5.satperf.yaml'
fp_secret_yaml6      = '_TEST_ARTIFACTS/secret.fp6.satperf.yaml'
another_tp_secret_y  = '_TEST_ARTIFACTS/tp.secret.cleanup.yaml'
root_user_str        = 'root'

SOURCE_TYPE_PLAY     = 'PLAY'
SOURCE_TYPE_NON_PLAY = 'NON_PLAY'
PLAY_NAME_CONSTANT   = 'name'
INVALID_IP_CONSTANT  = '0.0.0.0/0'
VIP_KEYWORD          = 'vip'
SSH_PORT             = '22'

graph_secret_yaml    = '_TEST_ARTIFACTS/graph.playbooks.cleanup.crs.yaml'

cross_tp_secret_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/conf/satperf.yaml'
org_dir              = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/'
KATELLO_USER         = 'katello_user' 
KATELLO_PASS         = 'katello_password'
NOKATELLO_MESSAGE    = 'NO KATELLO STUFF !!! '
RHSM_USER            = 'rhsm_user' 
RHSM_MESSAGE         = 'RHSM_USER in list !!!'
RHSM_PASS            = 'rhsm_pass' 
RHSM_P_MESSAGE       = 'NO RHSM_PASS in list !!!'
cross_existence_yaml1= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/satutils.yaml'
cross_existence_yaml2= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/continuous-rex.yaml'
FILE_MISSING_MESSAGE = 'an exsiting file '
cross_existence_yaml3= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-setup.yaml'
cross_existence_yaml4= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/rex.yaml'
cross_existence_yaml5= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/sync-repositories.yaml'
cross_existence_yaml6= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-big-setup.yaml'
cross_existence_yaml7= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/hammer-list.yaml'
cross_existence_yaml8= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-single-setup.yaml'
cross_existence_yaml9= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-big-test.yaml'
cross_existence_yam10= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/soak-tests/daily-cv-ops.yaml'
