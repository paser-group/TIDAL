'''
Akond Rahman 
July 01, 2021 
Module to detect security weaknesses 
'''
import parser 
import constants 
import graph 


def getDefaultPortCount( yaml_content_dic ):
    res_dic = {}
    counter = 0 

    temp_key_lis, temp_ports_ls = [] , []
    parser.getKeyRecursively( yaml_content_dic, temp_key_lis  )
    only_keys = [x_[0] for x_ in temp_key_lis]

    # print( only_keys )
    # if constants.PORTS_KEYWORD in yaml_content_dic  :
    #     temp_ports_ls = yaml_content_dic[constants.PORTS_KEYWORD]
    if constants.PORTS_KEYWORD in only_keys: 
        vals_for_key  = [] 
        parser.getValsFromKey( yaml_content_dic, constants.PORTS_KEYWORD, vals_for_key )
        temp_ports_ls = vals_for_key
    elif constants.SSH_PORT_KEYWORD in only_keys:
        temp_ports_ls = [] 
        temp_ports_ls.append( [ { constants.SSH_PORT_KEYWORD  :  yaml_content_dic[ constants.SSH_PORT_KEYWORD ] } ] )
    # print( temp_ports_ls )
    for temp_ports in temp_ports_ls:
        for temp_port in temp_ports: 
            # if( constants.PORT_KEYWORD in temp_port or constants.TARGET_PORT_KEYWORD in temp_port ) and ( constants.PROTOCOL_KEYWORD in temp_port ) : 
            if( constants.PORT_KEYWORD in temp_port  ) and ( constants.PROTOCOL_KEYWORD in temp_port ) : 
                port_value = temp_port[constants.PORT_KEYWORD] 
                port_proto = temp_port[constants.PROTOCOL_KEYWORD]

                if ( port_value == constants.HTTP_DEFAULT_PORT_VAL ) and ( port_proto == constants.HTTP_KEYWORD ) : 
                    counter += 1 
                    res_dic[counter] = ( port_value, port_proto )                                    
                elif ( port_value == constants.HTTPS_DEFAULT_PORT_VAL ) and ( port_proto == constants.HTTPS_KEYWORD ) : 
                    counter += 1 
                    res_dic[counter] = ( port_value, port_proto )                                    
                elif ( port_value == constants.SSH_DEFAULT_PORT_VAL ) and ( port_proto == constants.SSH_KEYWORD ) : 
                    counter += 1 
                    res_dic[counter] = ( port_value, port_proto )                                    
            elif( constants.PORT_KEYWORD in temp_port ):
                port_value = temp_port[constants.PORT_KEYWORD]
                if( port_value == constants.MONGO_DEFAULT_PORT_VAL ): 
                    counter += 1 
                    res_dic[counter] = ( port_value, constants.MONGO_KEYWORD )                                    
            elif( constants.CONTAINER_PORT_KEYWORD in temp_port ):
                port_value = temp_port[constants.CONTAINER_PORT_KEYWORD]
                if( port_value == constants.MONGO_DEFAULT_PORT_VAL ): 
                    counter += 1 
                    res_dic[counter] = ( port_value, constants.MONGO_KEYWORD )  
            elif( constants.SSH_PORT_KEYWORD in temp_port ):
                port_value = temp_port[constants.SSH_PORT_KEYWORD]
                if( port_value == constants.SSH_DEFAULT_PORT_VAL ): 
                    counter += 1 
                    res_dic[counter] = ( port_value, constants.SSH_KEYWORD )  
    # print(res_dic) 
    return res_dic 



def getSuspComments( file_ ):  
    comment_ls    =  []
    data_as_ls    =  parser.getContentAsList( file_ )  
    comment_as_ls = [z.split( constants.COMMENT_SYMBOL )[1:] for z in data_as_ls if (constants.COMMENT_SYMBOL in z)  ] 
    for comment_item in comment_as_ls:
        comment   = constants.WHITESPACE_SYMBOL.join( comment_item  )
        comment   = comment.lower() 
        if(any(x_ in comment for x_ in constants.CWE_SUSP_COMMENT_LIST )) and ( constants.DEBUG_KW not in comment ) :
            comment_ls.append(  comment )
    return comment_ls  


def sanitizeConfigVals(config_data):
    valid_config_data = constants.VALID_CONFIG_DEFAULT 
    if any(isinstance( config_data, x_  ) for x_ in constants.ALLOWABLE_TYPES )  :
        if isinstance(config_data, bool) or isinstance( config_data, int ) :
            config_data = str( config_data )
        if(constants.IP_ADDRESS_PATTERN in config_data) and (constants.YUM_KW not in config_data) :
            valid_config_data = config_data.replace(constants.QUOTE_SYMBOL, constants.NULL_SYMBOL)
        elif(  constants.HTTP_PATTERN in config_data ):
            valid_config_data = config_data.replace(constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL)   
        elif(  constants.HTTPS_PATTERN in config_data ):
            valid_config_data = config_data.replace(constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL)   
        elif(  constants.VAR_REFF_PATTERN in config_data ):
            valid_config_data = config_data.replace(constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL)   
        elif(  (isinstance( config_data, str )) and ( len(config_data) > 0 ) ):
            valid_config_data = config_data.replace(constants.WHITESPACE_SYMBOL, constants.NULL_SYMBOL)   
    return valid_config_data  

def getASCIIValues(config_data):
    data_ascii        = constants.DUMMY_ASCII  
    valid_config_data = sanitizeConfigVals( config_data )
    data_value        =  valid_config_data.strip() 
    data_ascii        = sum([ ord(y_) for y_ in data_value ])     
    return data_ascii



def getInvalidIPCount( yaml_dict ):
    res_dic_to_ret = {}
    all_val_lis    = parser.getValuesRecursively( yaml_dict )
    counter        = 0 
    for val_ in all_val_lis:
        val_ = sanitizeConfigVals( val_ )
        if( constants.IP_ADDRESS_PATTERN in val_ ):
            val_ascii    =   getASCIIValues( val_ )
            if val_ascii == 330 or val_ascii == 425:  
                counter          += 1
                res_dic_to_ret[counter] = val_ 
    # print(res_dic_to_ret) 
    return res_dic_to_ret  

def getInsecureHTTPCount( yaml_dict ):
    res_dic_to_ret = {}
    all_val_lis    = parser.getValuesRecursively( yaml_dict )
    counter        = 0 
    # print( all_val_lis )
    for val_ in all_val_lis:
        val_filtered    =   sanitizeConfigVals( val_  ) 
        # print( val_filtered )
        if( any( z_ in val_filtered for z_ in constants.ALLOWABLE_INSECURE_HTTP_STRS ) ) and ( any( y_ in val_filtered for y_ in constants.UNALLOWED_HTTP_STRS )  == False ): 
            counter += 1 
            res_dic_to_ret[counter] = val_filtered
    # print(res_dic_to_ret) 
    return res_dic_to_ret  

def getEmptyPasswordCount(yaml_dict): 
    res_dic  = {} 
    counter  = 0
    key_lis  = [] 
    parser.getKeyRecursively( yaml_dict, key_lis )
    only_keys= [ z_[0] for z_ in key_lis ]
    for k_  in only_keys :
        if ( any( z_ in k_ for z_ in constants.VALID_PASSWORD_STRS ) ): 
            val_holder = [] 
            parser.getValsFromKey(yaml_dict, k_, val_holder ) 
            for unfiltered_config_val in val_holder:
                config_val = sanitizeConfigVals( unfiltered_config_val )
                if (isinstance(config_val, str  ) ) and ( len(config_val) == 0  ) : 
                    counter += 1 
                    res_dic[ counter ] = ( k_, config_val )
    # print( res_dic )
    return res_dic


def getSimilarDepthKeys(all_keys , depth):
    lis2ret = [] 
    for k_, v_ in all_keys.items(): 
        if depth == v_:
            lis2ret.append( k_  )
    return lis2ret


def getIntegViolationCount( yaml_dic ):
    res_dic  , counter = {} , 0 
    all_keys = []
    parser.getKeyRecursively(yaml_dic, all_keys)
    the_keys = {x_[0]:x_[1] for x_ in all_keys} 
    for key_, depth  in the_keys.items():
        if( any( str_ in key_ for str_ in constants.INTEG_KW_LIST ) ):
            key_vals = [] 
            parser.getValsFromKey(yaml_dic, key_, key_vals )
            if ( constants.NO_KEYWORD in key_vals ) or (False in key_vals) or (0 in key_vals):
                target_depth  = depth 
                similar_keys  =  getSimilarDepthKeys( the_keys, target_depth  ) 
                for k_ in similar_keys: 
                    vals_of_simialr_keys = [] 
                    parser.getValsFromKey( yaml_dic, k_, vals_of_simialr_keys )
                    for similar_key_value in vals_of_simialr_keys: 
                        # print( key_, k_, similar_key_value , type(similar_key_value) ) 
                        similar_key_value = sanitizeConfigVals( similar_key_value ) 
                        if ( any( z_  in similar_key_value for z_ in constants.REPO_STRS_V1 ) or any( z_  in similar_key_value for z_ in constants.REPO_STRS_V2 )  ) and ( (constants.HTTP_PATTERN in similar_key_value) or ( constants.HTTPS_PATTERN in similar_key_value) or ( constants.VAR_REFF_PATTERN in similar_key_value ) ):
                            counter +=1 
                            res_dic[counter] = ( key_, key_vals, k_, similar_key_value )
    # print( res_dic )
    return res_dic


def getUsernameCount( yaml_dict ):
    res_dic  = {} 
    counter  = 0
    key_lis  = [] 
    parser.getKeyRecursively( yaml_dict, key_lis )
    only_keys= [T_[0] for T_ in key_lis] 
    for k_  in only_keys :
        # print( k_  )
        if ( any( z_ in k_ for z_ in constants.VALID_USERNAME_STRS ) ) and ( any( y_ in k_ for y_ in constants.INVALID_USERNAME_STRS ) == False  ): 
            val_holder = [] 
            parser.getValsFromKey(yaml_dict, k_, val_holder ) 
            # print( k_, val_holder )
            for unfiltered_config_val in val_holder:
                if isinstance( unfiltered_config_val, str ):
                    config_val = sanitizeConfigVals( unfiltered_config_val )
                    if (isinstance(config_val, str  ) ) and ( len(config_val) > 0  ) : 
                        counter += 1 
                        res_dic[ counter ] = ( k_, config_val )
    # print( res_dic )
    return res_dic    

def getPasswordCount( yaml_dict ):
    res_dic  = {} 
    counter  = 0
    key_lis  = [] 
    parser.getKeyRecursively( yaml_dict, key_lis )
    only_keys= [T_[0] for T_ in key_lis] 
    for k_  in only_keys :
        if ( any( z_ in k_ for z_ in constants.VALID_PASSWORD_STRS ) ) and ( any( x_ in k_ for x_ in constants.INVALID_PASSWORD_STRS ) == False ) : 
            val_holder = [] 
            parser.getValsFromKey(yaml_dict, k_, val_holder ) 
            for unfiltered_config_val in val_holder:
                if isinstance( unfiltered_config_val, str ):
                    config_val = sanitizeConfigVals( unfiltered_config_val )
                    if (isinstance(config_val, str  ) ) and ( len(config_val) > 0  ) : 
                        counter += 1 
                        res_dic[ counter ] = ( k_, config_val )
    # print( res_dic )
    return res_dic    



def getPrivKeyCount( yaml_dict ):
    res_dic  = {} 
    counter  = 0
    key_lis  = [] 
    parser.getKeyRecursively( yaml_dict, key_lis )
    only_keys= [T_[0] for T_ in key_lis] 
    for k_  in only_keys :
        if ( any( z_ in k_ for z_ in constants.VALID_PRIVATE_STRS ) ) and ( any( t_ in k_ for t_ in constants.VALID_KEY_STRS ) ) and ( any( x_ in k_ for x_ in constants.INVALID_KEY_STRS ) == False ) : 
            val_holder = [] 
            parser.getValsFromKey(yaml_dict, k_, val_holder ) 
            for unfiltered_config_val in val_holder:
                if isinstance( unfiltered_config_val, str ):
                    config_val = sanitizeConfigVals( unfiltered_config_val )
                    if (isinstance(config_val, str  ) ) and ( len(config_val) > 0  ) : 
                        counter += 1 
                        res_dic[ counter ] = ( k_, config_val )
    # print( res_dic )
    return res_dic    
def getSecretCount(  yam_dict ):
    user_res_dic = getUsernameCount( yam_dict )
    pass_res_dic = getPasswordCount( yam_dict )
    key_res_dic  = getPrivKeyCount( yam_dict )
    res_lis      = [ user_res_dic, pass_res_dic, key_res_dic ]
    # print(res_lis)
    return res_lis


def scanSingleScriptForAllTypes( script_path , org_dir ):
    yamL_ds  = parser.loadYAML( script_path  )
    susp_comments, port_res_dic , ip_res_dic , http_res_dic , empty_pwd_dic , no_integ_dic, secret_dic_ls = [], {}, {}, {}, {}, {}, []
    if( isinstance(yamL_ds, list) ):
        for dic in yamL_ds:
            # print( dic )
            port_res_dic = getDefaultPortCount( dic )
            ip_res_dic   = getInvalidIPCount( dic )
            http_res_dic = getInsecureHTTPCount( dic )
            empty_pwd_dic= getEmptyPasswordCount( dic )
            no_integ_dic = getIntegViolationCount ( dic )
            secret_dic_ls= getSecretCount( dic )
            '''
            Once done with pattern matching we need to check if instances are 
            used by a play 
            '''
            http_usage_di= graph.getPlayUsage( dic, http_res_dic )
            inv_ip_use_di= graph.getPlayUsage( dic, ip_res_dic )              
            emp_pwd_use_d= graph.getPlayUsage( dic, empty_pwd_dic )  
            port_use_dic = graph.getPlayUsage( dic, port_res_dic )
            no_int_use_d = graph.getPlayUsage( dic, no_integ_dic )
            secret_use_ls= [ graph.getSecretPlayUsage(dic, secret_dic_ls[0]), graph.getSecretPlayUsage(dic, secret_dic_ls[1]), graph.getSecretPlayUsage(dic, secret_dic_ls[2]) ]
            '''
            We also need to do cross script taint tracking 
            '''
            cross_uname_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[0])
            cross_passw_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[1])
            cross_prike_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[2])  

    elif ( isinstance(  yamL_ds, dict)  ):
        # print( yamL_ds )
        port_res_dic     = getDefaultPortCount( yamL_ds )
        ip_res_dic       = getInvalidIPCount( yamL_ds )
        http_res_dic     = getInsecureHTTPCount( yamL_ds )
        empty_pwd_dic    = getEmptyPasswordCount( yamL_ds )  
        no_integ_dic     = getIntegViolationCount ( yamL_ds )              
        secret_dic_ls    = getSecretCount( yamL_ds )
        '''
        Once done with pattern matching we need to check if instances are 
        used by a play 
        '''
        http_usage_di= graph.getPlayUsage( yamL_ds, http_res_dic )      
        inv_ip_use_di= graph.getPlayUsage( yamL_ds, ip_res_dic )  
        emp_pwd_use_d= graph.getPlayUsage( yamL_ds, empty_pwd_dic )  
        port_use_dic = graph.getPlayUsage( yamL_ds, port_res_dic )
        no_int_use_d = graph.getPlayUsage( yamL_ds , no_integ_dic )        
        secret_use_ls= [ graph.getSecretPlayUsage(yamL_ds, secret_dic_ls[0]), graph.getSecretPlayUsage(yamL_ds, secret_dic_ls[1]), graph.getSecretPlayUsage(yamL_ds, secret_dic_ls[2]) ]
        '''
        We also need to do cross script taint tracking 
        '''
        # print(  )
        cross_uname_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[0])
        cross_passw_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[1])
        cross_prike_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[2])  
 
        for k_, v_ in cross_prike_di.items(): 
                print( k_, v_[2] )
                print( v_[1], constants.PRINT_COLON_HELPER , v_[3] )
                print( '=' * 100  )

    '''
    Let us also detect suspicious comments 
    '''
    susp_comments  = getSuspComments( script_path )
    # print(susp_comments)



    


if __name__=='__main__':
        # test_ports_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/pacman-service.yaml'
        # test_ports_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/mongo-deployment-rs.yaml'
        # test_ports_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/mongo-rs.yaml'
        # test_ports_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/mongo-service.yaml'
        # test_ports_yaml   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/config/defaults/main.yaml'
        # fp_ports_yaml   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/roles/heketi-install/tasks/main.yaml'

        # test_comments_yaml = '_TEST_ARTIFACTS/roles.tp.default.port.yaml'
        # test_comments_yaml = '_TEST_ARTIFACTS/conf.satperf.yaml'

        # test_invalid_ip_yml= '_TEST_ARTIFACTS/roles.tp.default.port.yaml'
        # test_invalid_ip_yml= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/carlosthe19916@openshift-ansible/playbooks/openstack/openshift-cluster/files/heat_stack.yaml'
        # test_invalid_ip_yml= '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/playbooks/openstack/openshift-cluster/files/heat_stack.yaml'

        # test_no_integ = '_TEST_ARTIFACTS/no.integ3.yaml'

        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/aws-ansible/playbooks/roles/non-atomic-docker-storage-setup/tasks/main.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/node-change-labels/tasks/main.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/gcp/ansible/playbooks/roles/ssl-certificate-delete/defaults/main.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/gcp/ansible/playbooks/roles/ssl-certificate/defaults/main.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/roles/cloud-provider-setup/tasks/main.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-tools/ansible/playbooks/adhoc/metrics_setup/files/metrics.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/common/roles/scalelab-nic-cleanup/tasks/main.yaml'
        # test_secret_fp_yaml  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/containerized/roles/install-openshift-oc/tasks/main.yaml'
        # test_secret_fp_yaml  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/docker/docker-purge-storage.yaml'
        # test_secret_fp_yaml  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/ocp-install.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/kvm-hosts/check.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/kvm-hosts/host.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/kvm-hosts/install-vms.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/monitoring/grafana.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/monitoring/graphite.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/remove-satellite.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/satellite-remove-hosts.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/client-scripts.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/roles/client-scripts/tasks/main.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/capsules.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/satellite-populate.yaml'
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-big-test.yaml'

        # test_secret_tp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/cleanup-crs.yaml'
        # test_secret_tp_yaml   = '_TEST_ARTIFACTS/tp.secret.cleanup.yaml'
        # test_secret_tp_yaml   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/conf/satperf.yaml'
        test_secret_tp_yaml  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/3.9/playbooks/vars/main.yaml'

        # test_http_yml = '_TEST_ARTIFACTS/conf.satperf.yaml'
        # test_http_yml = '_TEST_ARTIFACTS/http.calico.main.yaml'

        # test_invalid_ip_yml= '_TEST_ARTIFACTS/1.invalid.ip.yaml'
        # test_invalid_ip_yml= '_TEST_ARTIFACTS/2.invalid.ip.yaml'
        # test_invalid_ip_yml= '_TEST_ARTIFACTS/roles.tp.default.port.yaml'

        # test_empty_pwd_yml  = '_TEST_ARTIFACTS/fp.empty.password.yaml'
        # test_empty_pwd_yml = '_TEST_ARTIFACTS/fp2.empty.pwd.yaml'
        # test_empty_pwd_yml = '_TEST_ARTIFACTS/fp3.empty.pwd.yaml'

        # test_ports_yaml   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/config/defaults/main.yaml'
        # test_ports_yaml   = '_TEST_ARTIFACTS/roles.tp.default.port.yaml'

        # test_no_integ = '_TEST_ARTIFACTS/no.integ3.yaml'

        org_path = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/'
        scanSingleScriptForAllTypes( test_secret_tp_yaml, org_path ) 
