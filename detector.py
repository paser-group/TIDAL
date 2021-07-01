'''
Akond Rahman 
July 01, 2021 
Module to detect secuirty weaknesses 
'''
import parser 
import constants 


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


def scanSingleScriptForAllTypes( script_path ):
    yamL_ds  = parser.loadYAML( script_path  )
    if( isinstance(yamL_ds, list) ):
        for dic in yamL_ds:
            # print( dic )
            port_res_dic =  getDefaultPortCount( dic )
    elif ( isinstance(  yamL_ds, dict)  ):
        # print( yamL_ds )
        port_res_dic = getDefaultPortCount( yamL_ds )
    '''
    Let us detect suspicious comments 
    '''
    susp_comments  = getSuspComments( script_path )
    print(susp_comments)
    


if __name__=='__main__':
        # test_ports_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/pacman-service.yaml'
        # test_ports_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/mongo-deployment-rs.yaml'
        # test_ports_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/mongo-rs.yaml'
        # test_ports_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/mongo-service.yaml'
        # test_ports_yaml   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/config/defaults/main.yaml'
        # fp_ports_yaml   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/roles/heketi-install/tasks/main.yaml'

        test_comments_yaml = '_TEST_ARTIFACTS/roles.tp.default.port.yaml'
        test_comments_yaml = '_TEST_ARTIFACTS/conf.satperf.yaml'
        scanSingleScriptForAllTypes( test_comments_yaml )
