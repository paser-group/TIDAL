'''
Akond Rahman 
July 01, 2021 
Module to detect security weaknesses 
'''
from collections.abc import Iterable
import parser 
import constants 
import graph 
import numpy as np 
import pandas as pd 
import os 


def filterVal(str_):

    msg_commit = str_.replace('\r', constants.WHITESPACE_SYMBOL)
    msg_commit = msg_commit.replace('\n', constants.WHITESPACE_SYMBOL)
    msg_commit = msg_commit.replace(',',  constants.WHITESPACE_SYMBOL)    
    msg_commit = msg_commit.replace('\t', constants.WHITESPACE_SYMBOL)
    msg_commit = msg_commit.replace('&',  constants.WHITESPACE_SYMBOL)  
    msg_commit = msg_commit.replace('=',  constants.WHITESPACE_SYMBOL)
    msg_commit = msg_commit.lower()         

    return msg_commit

def getDefaultPortCount( yaml_content_dic ):
    res_dic = {}
    counter = 0 

    temp_key_lis, temp_ports_ls = [] , []
    parser.getKeyRecursively( yaml_content_dic, temp_key_lis  )
    only_keys = [x_[0] for x_ in temp_key_lis]
    only_keys = [ sanitizeConfigKeys(var) for var in only_keys  ]
    only_keys = np.unique( only_keys )

    if constants.PORTS_KEYWORD in only_keys: 
        vals_for_key  = [] 
        parser.getValsFromKey( yaml_content_dic, constants.PORTS_KEYWORD, vals_for_key )
        temp_ports_ls =  vals_for_key
    elif constants.SSH_PORT_KEYWORD in only_keys:
        temp_ports_ls = [] 
        temp_ports_ls.append( [ { constants.SSH_PORT_KEYWORD  :  constants.SSH_DEFAULT_PORT_VAL } ] )
    for temp_ports in temp_ports_ls:
        if ( isinstance( temp_ports, list  ) ):
            for temp_port in temp_ports: 
                if ( isinstance( temp_port, Iterable  ) ):                
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
    only_keys = [ z_[0] for z_ in key_lis ]
    only_keys = [ sanitizeConfigKeys(var) for var in only_keys  ]
    only_keys = np.unique( only_keys )    
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
        key_ = sanitizeConfigKeys( key_ )
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
    res_dic   = {} 
    counter   = 0
    key_lis   = [] 
    parser.getKeyRecursively( yaml_dict, key_lis )
    only_keys = [T_[0] for T_ in key_lis] 
    only_keys = [ sanitizeConfigKeys(var) for var in only_keys  ]
    only_keys = np.unique( only_keys )        
    for k_  in only_keys :
        # print( k_  )
        if ( any( z_ in k_ for z_ in constants.VALID_USERNAME_STRS ) ) and ( any( y_ in k_ for y_ in constants.INVALID_USERNAME_STRS ) == False  ): 
            val_holder = [] 
            parser.getValsFromKey(yaml_dict, k_, val_holder ) 
            # print( k_, val_holder )
            for unfiltered_config_val in val_holder:
                if isinstance( unfiltered_config_val, str ):
                    config_val = sanitizeConfigVals( unfiltered_config_val )
                    if (isinstance(config_val, str  ) ) and ( len(config_val) > 0  ) and ( config_val != constants.VALID_CONFIG_DEFAULT ) and ( constants.VAR_REFF_PATTERN not in config_val ) and (constants.OTHER_VAR_REFF_PATTERN not in config_val): 
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
    only_keys = [ sanitizeConfigKeys(var) for var in only_keys  ]
    only_keys = np.unique( only_keys )        
    for k_  in only_keys :
        if ( any( z_ in k_ for z_ in constants.VALID_PASSWORD_STRS ) ) and ( any( x_ in k_ for x_ in constants.INVALID_PASSWORD_STRS ) == False ) : 
            val_holder = [] 
            parser.getValsFromKey(yaml_dict, k_, val_holder ) 
            for unfiltered_config_val in val_holder:
                if isinstance( unfiltered_config_val, str ):
                    config_val = sanitizeConfigVals( unfiltered_config_val )
                    if (isinstance(config_val, str  ) ) and ( len(config_val) > 0  ) and ( config_val != constants.VALID_CONFIG_DEFAULT ) and ( constants.VAR_REFF_PATTERN not in config_val ) and (constants.OTHER_VAR_REFF_PATTERN not in config_val): 
                        counter += 1 
                        res_dic[ counter ] = ( k_, config_val )
    # print( res_dic )
    return res_dic    



def getPrivKeyCount( yaml_dict ):
    res_dic   = {} 
    counter   = 0
    key_lis   = [] 
    parser.getKeyRecursively( yaml_dict, key_lis )
    only_keys = [T_[0] for T_ in key_lis] 
    only_keys = [ sanitizeConfigKeys(var) for var in only_keys  ]
    only_keys = np.unique( only_keys )        
    for k_  in only_keys :
        if ( any( z_ in k_ for z_ in constants.VALID_PRIVATE_STRS ) ) and ( any( t_ in k_ for t_ in constants.VALID_KEY_STRS ) ) and ( any( x_ in k_ for x_ in constants.INVALID_KEY_STRS ) == False )  : 
            val_holder = [] 
            parser.getValsFromKey(yaml_dict, k_, val_holder ) 
            for unfiltered_config_val in val_holder:
                if isinstance( unfiltered_config_val, str ):
                    config_val = sanitizeConfigVals( unfiltered_config_val )
                    if (isinstance(config_val, str  ) ) and ( len(config_val) > 0  ) and ( config_val != constants.VALID_CONFIG_DEFAULT ) and ( constants.VAR_REFF_PATTERN not in config_val ) and (constants.OTHER_VAR_REFF_PATTERN not in config_val) : 
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


def scanSingleScriptForAllTypes( script_path , org_dir, need_speed_flag ):
    yamL_ds  = parser.loadYAML( script_path  )
    final_result_tuple, susp_comments = None , [] 
    http_res_dic, ip_res_dic,      empty_pwd_dic,  port_res_dic,   no_integ_dic, secret_dic_ls    = {}, {}, {}, {}, {}, []
    http_usage_di, inv_ip_use_di,  emp_pwd_use_d,  port_use_dic,   no_int_use_d, secret_use_ls    = {}, {}, {}, {}, {}, []  
    cross_http_di, cross_inv_ip_d, cross_empt_p_d, cross_port_p_d, cross_int_no_d, cross_secre_ls = {}, {}, {}, {}, {}, []  

    if( isinstance(yamL_ds, list) ):
        for dic in yamL_ds:
            play_status  = constants.SOURCE_TYPE_NON_PLAY 
            # print( dic )
            port_res_dic = getDefaultPortCount( dic )
            ip_res_dic   = getInvalidIPCount( dic )
            http_res_dic = getInsecureHTTPCount( dic )
            empty_pwd_dic= getEmptyPasswordCount( dic )
            no_integ_dic = getIntegViolationCount ( dic )
            secret_dic_ls= getSecretCount( dic )
            # print( secret_dic_ls ) 
            # print( '='*100 )                    
            '''
            Once done with pattern matching we need to check if instances are 
            used by a play 
            '''
            http_usage_di= graph.getPlayUsage( dic, http_res_dic )
            # print( http_usage_di ) 
            # print( '='*100 )
            inv_ip_use_di= graph.getPlayUsage( dic, ip_res_dic )     
            # print( inv_ip_use_di )         
            emp_pwd_use_d= graph.getPlayUsage( dic, empty_pwd_dic )  
            port_use_dic = graph.getPlayUsage( dic, port_res_dic )
            no_int_use_d = graph.getNoIntegPlayUsage(  no_integ_dic )
            # print( no_integ_dic  )
            # print( no_int_use_d )
            secret_use_ls= [ graph.getSecretPlayUsage(dic, secret_dic_ls[0]), graph.getSecretPlayUsage(dic, secret_dic_ls[1]), graph.getSecretPlayUsage(dic, secret_dic_ls[2]) ]
            if ( constants.PLAY_NAME_CONSTANT in dic ):
                play_status = constants.SOURCE_TYPE_PLAY 
            '''
            We also need to do cross script taint tracking 
            '''
            # secret 
            cross_uname_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[0], need_speed_flag)
            cross_passw_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[1], need_speed_flag)
            cross_prike_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[2], need_speed_flag) 
            cross_secre_ls= [ cross_uname_di, cross_passw_di, cross_prike_di ] 
            # insecure HTTP 
            cross_http_di = graph.getCrossReffs( org_dir, script_path, http_usage_di, need_speed_flag )
            # print( cross_http_di )
            # print('='*100)
            # invalid ip usage 
            cross_inv_ip_d= graph.getCrossReffs( org_dir, script_path, inv_ip_use_di, need_speed_flag )    
            # empty password usage 
            cross_empt_p_d= graph.getCrossReffs( org_dir, script_path, emp_pwd_use_d, need_speed_flag )    
            # cross port usage 
            cross_port_p_d= graph.getCrossReffs( org_dir, script_path, port_use_dic, need_speed_flag )     
            # cross no integrity check usage 
            cross_int_no_d= graph.getCrossReffs( org_dir, script_path, no_int_use_d, need_speed_flag )  
            # each entry in the tuple is a dict : the dict has the following keys: weakness type, raw count, tp count, 
            # cross script dict if the weakness is used in a different script, 
            # affected play count  , and used dict i.e. if the weakness is used in the same script 
            final_result_tuple = ( 
                               getSummaryWhenName( constants.RESULT_USERNAME,     secret_dic_ls[0],  cross_secre_ls[0], secret_use_ls[0]), 
                               getSummaryWhenName( constants.RESULT_PASSWORD,     secret_dic_ls[1],  cross_secre_ls[1], secret_use_ls[1]), 
                               getSummaryWhenName( constants.RESULT_PRIVATE_KEY,  secret_dic_ls[2],  cross_secre_ls[2], secret_use_ls[2]),                                
                               getSummaryWhenName( constants.RESULT_INSECURE_HTTP,http_res_dic    ,  cross_http_di    , http_usage_di  ),   
                               getSummaryWhenName( constants.RESULT_INVALID_IP,   ip_res_dic      ,  cross_inv_ip_d   , inv_ip_use_di  ),   
                               getSummaryWhenName( constants.RESULT_EMPTY_PWD,    empty_pwd_dic   ,  cross_empt_p_d   , emp_pwd_use_d  ),   
                               getSummaryWhenName( constants.RESULT_DEFAULT_PORT, port_res_dic    ,  cross_port_p_d   , port_use_dic  ),   
                               getSummaryWhenName( constants.RESULT_NO_INTEG,     no_integ_dic    ,  cross_int_no_d   , no_int_use_d  ),   
                            )

            


    elif ( isinstance(  yamL_ds, dict)  ):
        # print( yamL_ds )
        port_res_dic     = getDefaultPortCount( yamL_ds )
        ip_res_dic       = getInvalidIPCount( yamL_ds )
        http_res_dic     = getInsecureHTTPCount( yamL_ds )
        empty_pwd_dic    = getEmptyPasswordCount( yamL_ds )  
        no_integ_dic     = getIntegViolationCount ( yamL_ds )              
        secret_dic_ls    = getSecretCount( yamL_ds )
        # print( secret_dic_ls ) 
        # print( '*'*100 )        
        '''
        Once done with pattern matching we need to check if instances are 
        used by a play 
        '''
        http_usage_di= graph.getPlayUsage( yamL_ds, http_res_dic )      
        # print(http_usage_di)
        # print('*'*100)
        inv_ip_use_di= graph.getPlayUsage( yamL_ds, ip_res_dic )  
        # print( inv_ip_use_di )
        emp_pwd_use_d= graph.getPlayUsage( yamL_ds, empty_pwd_dic )  
        port_use_dic = graph.getPlayUsage( yamL_ds, port_res_dic )
        # print( port_use_dic )
        no_int_use_d = graph.getNoIntegPlayUsage(  no_integ_dic )        
        # print( no_int_use_d ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yamL_ds, secret_dic_ls[0]), graph.getSecretPlayUsage(yamL_ds, secret_dic_ls[1]), graph.getSecretPlayUsage(yamL_ds, secret_dic_ls[2]) ]
        '''
        We also need to do cross script taint tracking 
        '''
        # cross secret usage 
        cross_uname_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[0], need_speed_flag)
        cross_passw_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[1], need_speed_flag)
        cross_prike_di= graph.getCrossReffs(org_dir, script_path, secret_use_ls[2], need_speed_flag)  
        cross_secre_ls= [ cross_uname_di, cross_passw_di, cross_prike_di ] 
        # cross http usage 
        cross_http_di = graph.getCrossReffs( org_dir, script_path, http_usage_di, need_speed_flag )
        # cross invalid ip usage 
        cross_inv_ip_d= graph.getCrossReffs( org_dir, script_path, inv_ip_use_di, need_speed_flag )
        # cross empty password usage 
        cross_empt_p_d= graph.getCrossReffs( org_dir, script_path, emp_pwd_use_d, need_speed_flag )
        # cross port usage 
        cross_port_p_d= graph.getCrossReffs( org_dir, script_path, port_use_dic, need_speed_flag )
        # cross no integrity check usage 
        cross_int_no_d= graph.getCrossReffs( org_dir, script_path, no_int_use_d, need_speed_flag )
        # each entry in the tuple is a dict : the dict has the following keys: weakness type, raw count, tp count, cross script dict, 
        # affected play count  
        final_result_tuple = ( 
                               getSummary( constants.RESULT_USERNAME,     secret_dic_ls[0],  cross_secre_ls[0], secret_use_ls[0] ), 
                               getSummary( constants.RESULT_PASSWORD,     secret_dic_ls[1],  cross_secre_ls[1], secret_use_ls[1] ), 
                               getSummary( constants.RESULT_PRIVATE_KEY,  secret_dic_ls[2],  cross_secre_ls[2], secret_use_ls[2] ),                                
                               getSummary( constants.RESULT_INSECURE_HTTP,http_res_dic    ,  cross_http_di    , http_usage_di     ),   
                               getSummary( constants.RESULT_INVALID_IP,   ip_res_dic      ,  cross_inv_ip_d   , inv_ip_use_di ),   
                               getSummary( constants.RESULT_EMPTY_PWD,    empty_pwd_dic   ,  cross_empt_p_d   , emp_pwd_use_d  ),   
                               getSummary( constants.RESULT_DEFAULT_PORT, port_res_dic    ,  cross_port_p_d   , port_use_dic  ),   
                               getSummary( constants.RESULT_NO_INTEG,     no_integ_dic    ,  cross_int_no_d   , no_int_use_d  ),   
                            )
        


    '''
    Let us also detect suspicious comments 
    '''
    susp_comments  = getSuspComments( script_path )
    # print(susp_comments)
    '''
    TEST PURPOSE
    '''
    weak_play_list = getPlayNamePerWeakness( final_result_tuple )
    '''
    Results for each will be saved as a tuple: first tuple is  a list with values for 
    6 types of weaknesses, the second eleemnt of the tuple is the number of susp. comments 
    third element of tuple is weak_play_list that stores what weaknesses map to what plays 
    '''
    # print( final_result_tuple[0]  )
    final_per_script_result = ( final_result_tuple , len( susp_comments ), weak_play_list )

    return final_per_script_result 
def getPlayNamePerWeakness(tuple_of_dicts):
    ls2ret = []

    for dict_ in tuple_of_dicts:
            weak_type =  dict_[ constants.RESULT_TYPE   ]
            used_dict =  dict_[ constants.USED_DICT_KEY ] 
            cross_dic =  dict_[ constants.RESULT_CROSS_SCRIPT_DICT ] 
            weak_cnt  =  dict_[constants.RESULT_TP_COUNT]
            if weak_cnt > 0: 
                # print(used_dict) 
                for prop_count, values in cross_dic.items(): 
                    propagated_value  = values[-1]
                    propagated_script = values[-2]
                    # print( propagated_script )
                    ya_di   = parser.loadYAML( propagated_script )
                    keyOfValList = parser.getKeysBasedOnValue(ya_di, propagated_value)
                    # print(keyOfValList) 
                    # print(  len(keyOfValList) )
                    #we will take the last 2 keys that are affected by the weakness 
                    # expecting key of value list to have newlines and special characters 
                    filtered_val = filterVal( keyOfValList[-1]   )
                    if ( len(keyOfValList) > 1 ): 
                        ls2ret.append( ( weak_type, propagated_script,  keyOfValList[-2], filtered_val )  )
                    # print('='*25)
    return ls2ret





def getSummary( weakness_type,  detcted_dict , cross_script_dict , used_dict  ):
    dic2ret = {} 
    tp_cnt  = 0 
    dic2ret[ constants.RESULT_TYPE  ]           = weakness_type 
    raw_cnt                                     = len( detcted_dict )
    dic2ret[constants.RESULT_RAW_COUNT]         = raw_cnt
    keys_in_cross_dict                          = [ z_[1] for z_ in   cross_script_dict.values() ] 
    # print( used_dict ) 
    # print( '*'*50 )
    # print( cross_script_dict )
    # print( keys_in_cross_dict )
    ### this counts the keys with weaknesses  that are in the source script 
    ### not adding used dict , as we are only cosnidering cross script 
    tp_cnt                                      = len( np.unique( keys_in_cross_dict ) ) 
    '''
    This is a hack. We are noticing raw_count to be lower than that true positive count. 
    So is raw count >= 1 and true positive count >=1 and raw_count > tp_count , 
    then we need to reset true positive count to raw count 
    '''
    if (tp_cnt > raw_cnt) and (raw_cnt >= 1) and (tp_cnt >= 1 ) : 
        tp_cnt = raw_cnt 
    dic2ret[constants.RESULT_TP_COUNT]          = tp_cnt
    dic2ret[constants.RESULT_CROSS_SCRIPT_DICT] = cross_script_dict  
    used_in_play_dict                           = {k:v for k, v in used_dict.items() if v[3] == constants.SOURCE_TYPE_PLAY   }
    affceted_play_count                         = len( used_in_play_dict ) + len( cross_script_dict )
    dic2ret[constants.AFFECT_PLAY_COUNT]        = affceted_play_count      
    dic2ret[constants.USED_DICT_KEY]            = used_dict
    # if( len(detcted_dict) > 0  ):
    #     print( dic2ret )    
    # print(weakness_type)
    # print( used_dict )
    # print(used_in_play_dict)
    '''
    format of cross_script_dict:
    script_path, key_from_src, yaml_, ya_va 
    '''
    # print('='*100)
    # print(weakness_type)
    # print(dic2ret)
    # print('='*100)
    return dic2ret
    

def getSummaryWhenName( weakness_type,  detcted_dict , cross_script_dict , used_dict  ):
    dic2ret                                     = {} 
    tp_cnt                                      = 0 
    dic2ret[ constants.RESULT_TYPE  ]           = weakness_type 
    raw_cnt                                     = len( detcted_dict )
    dic2ret[constants.RESULT_RAW_COUNT]         = raw_cnt
    keys_in_cross_dict                          = [ z_[1] for z_ in   cross_script_dict.values() ] 
    ###  adding used dict , as we are  cosnidering cross script and within script 
    tp_cnt                                      = len( np.unique( keys_in_cross_dict ) ) + len( used_dict )
    '''
    This is a hack. We are noticing raw_count to be lower than that true positive count. 
    So is raw count >= 1 and true positive count >=1 and raw_count > tp_count , 
    then we need to reset true positive count to raw count 
    '''
    if (tp_cnt > raw_cnt) and (raw_cnt >= 1) and (tp_cnt >= 1 ) : 
        tp_cnt = raw_cnt     
    dic2ret[constants.RESULT_TP_COUNT]          = tp_cnt
    dic2ret[constants.RESULT_CROSS_SCRIPT_DICT] = cross_script_dict  
    affceted_play_count                         = len( used_dict ) + len( cross_script_dict )
    dic2ret[constants.AFFECT_PLAY_COUNT]        = affceted_play_count      
    dic2ret[constants.USED_DICT_KEY]            = used_dict

    return dic2ret




def getYAMLFiles(path_to_dir):
    valid_  = [] 
    for root_, dirs, files_ in os.walk( path_to_dir ):
       for file_ in files_:
           full_p_file = os.path.join(root_, file_)
           if(os.path.exists(full_p_file)):
             if (full_p_file.endswith( constants.YML_EXTENSION  )  or full_p_file.endswith( constants.YAML_EXTENSION  )  ):
                if(parser.checkIfWeirdYAML ( full_p_file  )  == False):   
                    valid_.append(full_p_file)
    return valid_ 


def getOriginalWeaknessCount( dir_, yml,  tuple_of_dicts ):
    unam_coun, pass_coun, priv_coun, ip_addr_coun = 0, 0, 0, 0 
    http_coun, port_coun, emp_pwd_c, no_integ_cou = 0, 0, 0, 0    

    for dict_ in tuple_of_dicts:
            if constants.RESULT_USERNAME == dict_[constants.WEAKNESS_KW]: 
                unam_coun    = unam_coun + dict_[ constants.RESULT_RAW_COUNT ]
            if constants.RESULT_PASSWORD == dict_[constants.WEAKNESS_KW]: 
                pass_coun    = pass_coun + dict_[ constants.RESULT_RAW_COUNT ]
            if constants.RESULT_PRIVATE_KEY == dict_[constants.WEAKNESS_KW]: 
                priv_coun    = priv_coun + dict_[ constants.RESULT_RAW_COUNT ]
            if constants.RESULT_INVALID_IP == dict_[constants.WEAKNESS_KW] : 
                ip_addr_coun = ip_addr_coun + dict_[ constants.RESULT_RAW_COUNT ]                        
            if constants.RESULT_INSECURE_HTTP == dict_[constants.WEAKNESS_KW] : 
                http_coun    = http_coun + dict_[ constants.RESULT_RAW_COUNT ]  
            if constants.RESULT_DEFAULT_PORT == dict_[constants.WEAKNESS_KW]: 
                port_coun    = port_coun + dict_[ constants.RESULT_RAW_COUNT ]              
            if constants.RESULT_EMPTY_PWD == dict_[constants.WEAKNESS_KW]: 
                emp_pwd_c    = emp_pwd_c + dict_[ constants.RESULT_RAW_COUNT ]   
            if constants.RESULT_NO_INTEG == dict_[constants.WEAKNESS_KW]: 
                no_integ_cou = no_integ_cou + dict_[ constants.RESULT_RAW_COUNT ]    

    tup_ = ( dir_, yml, unam_coun, pass_coun, priv_coun, ip_addr_coun, http_coun, port_coun, emp_pwd_c, no_integ_cou )                
    return tup_ 




def scanMultipleScript4AllTypes( dir2scan , need4speed ):
    all_content       = [] 
    orig_content      = [] # to keep track of all original weaknesses , propagated and non-propagated 
    all_yml_files     = getYAMLFiles(dir2scan)
    file_counter      = 0 
    weak_play_content = []
    for yml_ in all_yml_files:
        '''
        Need to filter out `.github/workflows.yml files`  
        '''
        if(parser.checkIfWeirdYAML ( yml_  )  == False):   
            file_counter                                  = file_counter + 1   
            tuple_of_dicts, susp_coun  , weak_play_map       = scanSingleScriptForAllTypes(yml_, dir2scan, need4speed )
            unam_coun, pass_coun, priv_coun, ip_addr_cou = 0, 0, 0, 0 
            http_coun, port_coun, emp_pwd_c, integ_cou = 0, 0, 0, 0    
            print( yml_ + constants.WHITESPACE_SYMBOL + str( file_counter ) + constants.OUT_OF_STR + str( len(all_yml_files) ) )

            uname_dict = tuple_of_dicts[0]
            unam_coun  = uname_dict[ constants.RESULT_TP_COUNT ]

            passw_dict = tuple_of_dicts[1]
            pass_coun  = passw_dict[ constants.RESULT_TP_COUNT ]

            privk_dict = tuple_of_dicts[2]
            priv_coun  = priv_coun + privk_dict[ constants.RESULT_TP_COUNT ]

            ihttp_dict = tuple_of_dicts[3]
            http_coun  = ihttp_dict[ constants.RESULT_TP_COUNT ]  

            invai_dict = tuple_of_dicts[4]
            ip_addr_cou= invai_dict[ constants.RESULT_TP_COUNT ] 

            empty_dict = tuple_of_dicts[5]
            emp_pwd_c  = empty_dict[ constants.RESULT_TP_COUNT ]   

            dport_dict = tuple_of_dicts[6]
            port_coun  = dport_dict[constants.RESULT_TP_COUNT]

            integ_dict = tuple_of_dicts[7]
            integ_cou  = integ_dict[ constants.RESULT_TP_COUNT ]  

            '''
            TODO
            '''
            orig_weakness_tuple  = getOriginalWeaknessCount( dir2scan, yml_, tuple_of_dicts )
            orig_content.append( orig_weakness_tuple )
            '''
            TODO: play names 
            '''
            tup_ = ( dir2scan, yml_, susp_coun, unam_coun, pass_coun, priv_coun, ip_addr_cou, http_coun, port_coun, emp_pwd_c, integ_cou )
            all_content.append( tup_ ) 
            weak_play_content = weak_play_content + weak_play_map
    all_dir_yml_res = pd.DataFrame( all_content ) 
    '''
    To Track Original Weaknesses
    '''
    orig_weakness_df= pd.DataFrame( orig_content  )
    '''
    To Track Weakness Plays
    '''
    weakness_play_df = pd.DataFrame( weak_play_content )
    
    return all_dir_yml_res , orig_weakness_df, weakness_play_df



def sanitizeConfigKeys(config_key):
    if (isinstance( config_key  , str )  == False ) :
        valid_config_key_   = constants.DEFAULT_CONFIG_KEY
    else: 
        valid_config_key_   = config_key 
    return valid_config_key_ 

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
        # test_secret_fp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/tests/puppet-big-test.yaml'

        # test_secret_tp_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/vmware-ansible/playbooks/cleanup-crs.yaml'
        # test_secret_tp_yaml   = '_TEST_ARTIFACTS/tp.secret.cleanup.yaml'

        # test_secret_tp_yaml  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/reference-architecture/3.9/playbooks/vars/main.yaml'

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
        '''
        Shortlist to test out full script analysis 
        '''
        test_no_integ         = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/katello/roles/add_katello_repos/tasks/main.yaml'
        test_secret_fp_yaml   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/d34dh0r53@os-ansible-deployment/playbooks/roles/os_heat/files/templates/AWS_RDS_DBInstance.yaml'
        test_secret_tp_yaml   = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/conf/satperf.yaml'
        test_ports            = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/laincloud@lain/playbooks/roles/config/defaults/main.yaml'
        test_secret_name      = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/debops@debops/roles/debops.netbox/defaults/main.yml'
        test_http_fp_yaml     = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-tools/openshift/installer/atomic-openshift-3.11/roles/openshift_examples/files/examples/latest/xpaas-templates/rhpam70-prod-immutable-kieserver.yaml'
        
        org_path              = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/'        
        per_script_res        =  scanSingleScriptForAllTypes( test_secret_name , org_path, False ) 
        
        # print( len( per_script_res [0]  ) )
        # print( per_script_res[0] )


        # org_dire              = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-ansi/'        
        # org_dire              = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/test-ansi/'        
        # lol = scanMultipleScript4AllTypes( org_dire , False ) 
        # print( lol.head() )
        # print( lol.shape )
        # OUTPUT_FILE_CSV = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output-taintible/V1_TEST_TP_OUTPUT.csv'
        # lol.to_csv( OUTPUT_FILE_CSV, header= constants.CSV_HEADER , index=False, encoding= constants.CSV_ENCODING ) 
        
