'''
Akond Rahman 
July 02, 2021 
Code to create data dependence graphs 
'''
import parser 
import constants 
import detector 
import os 
import numpy as np 

def getPlayUsage( full_dic, weakness_dic ):
    res_dic = {} 
    count   = 0 
    # print(full_dic)
    # print(weakness_dic)
    all_dict_vals = parser.getValuesRecursively( full_dic )
    all_dict_vals = list( all_dict_vals )   
    all_dict_vals = [ detector.sanitizeConfigVals( z_ ) for z_ in all_dict_vals ]
    all_dict_keys = [] 
    parser.getKeyRecursively(full_dic, all_dict_keys)
    real_keys     = [z_[0] for z_ in all_dict_keys]
    src_key       = constants.NULL_SYMBOL 
    for _, val_ in weakness_dic.items():
        # SSH dicts are stored in tuples to keep tack of the protocol 
        if (isinstance( val_, tuple ) ):
            if( len( val_ ) == 2 ):
                val_    = val_[0]  ## port value , val_[1] is the protocol 
                val_ = str( val_ ) ## ports are stored as Integer , need to convert to String 
            elif( len( val_ ) == 4 ):
                src_key = val_[0]
                val_ = val_[3]                
        # print( val_, all_dict_vals )
        # if val_ in all_dict_vals: 
        # we are not considering `{{  }}` as hard-coded strings so this extra check 
        if (val_ in all_dict_vals) and ( constants.VAR_REFF_PATTERN not in val_ ) and ( constants.OTHER_VAR_REFF_PATTERN not in val_) and (constants.ANSIBLE_LOOKUP_KEYWORD not in val_) : 
            # print( val_, all_dict_vals, real_keys, len(real_keys) )
            keyOfValList = parser.getKeysBasedOnValue(full_dic, val_)
            # print( val_, keyOfValList ) 
            if isinstance( keyOfValList, list ):
                keyOfValList = [ x for x in keyOfValList if x!= val_ ] ## the config. value of interest is also in the list so need to exclude it 
                keyOfValList = [ temp for temp in keyOfValList if temp != constants.INVALID_YAML_KEY_INDEX_STR] ## need to filter '0', as '0' is included in parsing 
                if ( src_key != constants.NULL_SYMBOL ):
                    keyOfValList.append( src_key )
                count += 1 
                res_dic[count] = ( val_, keyOfValList , constants.DUMMY_LIST_INDEX, constants.SOURCE_TYPE_NON_PLAY )            
            else:
                if constants.PLAY_NAME_CONSTANT in real_keys :
                    count += 1 
                    res_dic[count] = ( val_, real_keys, real_keys.index( constants.PLAY_NAME_CONSTANT ), constants.SOURCE_TYPE_PLAY )
                else: 
                    count += 1 
                    res_dic[count] = ( val_, keyOfValList , constants.DUMMY_LIST_INDEX, constants.SOURCE_TYPE_NON_PLAY )                                    
    # print( res_dic )
    return res_dic 

def checkIfValidSecretName(  name_ ):
    fl = False
    if( any( y_ in name_ for y_ in constants.VALID_USERNAME_STRS ) ):
        fl = True 
    elif( any( y_ in name_ for y_ in constants.VALID_PASSWORD_STRS ) ):
        fl = True 
    elif( any( y_ in name_ for y_ in constants.VALID_PRIVATE_STRS ) ):
        fl = True 
    return fl 


def getSecretPlayUsage( full_dic, weakness_dic ):
    res_dic = {} 
    count   = 0 
    # print(full_dic)
    # print(weakness_dic)
    all_dict_vals = parser.getValuesRecursively( full_dic )
    all_dict_vals = list( all_dict_vals )   
    all_dict_vals = [ detector.sanitizeConfigVals( z_ ) for z_ in all_dict_vals ]
    all_dict_keys = [] 
    parser.getKeyRecursively(full_dic, all_dict_keys)
    real_keys     = [z_[0] for z_ in all_dict_keys]
    src_key       = constants.NULL_SYMBOL 
    for _, val_ in weakness_dic.items():
        # SSH dicts are stored in tuples to keep tack of the protocol 
        if (isinstance( val_, tuple ) ):
            if( len( val_ ) == 2 ):
                src_key = val_[0]
                val_    = val_[1]
                val_    = str( val_ ) ## the second element of the tuple is value 
        # print( val_, all_dict_vals )
        # if val_ in all_dict_vals: 
        # we are not considering `{{  }}` as hard-coded strings so this extra check 
        # we are also not considering lookup() 
        if (val_ in all_dict_vals) and ( constants.VAR_REFF_PATTERN not in val_ ) and ( constants.OTHER_VAR_REFF_PATTERN not in val_) and (constants.ANSIBLE_LOOKUP_KEYWORD not in val_) : 
            # print( val_, all_dict_vals, real_keys, len(real_keys) )
            keyOfValList = parser.getKeysBasedOnValue(full_dic, val_)
            # print( src_key,  val_, keyOfValList ) 
            count += 1 
            if isinstance( keyOfValList, list ):
                keyOfValList = [ x for x in keyOfValList if x!= val_ ] ## the config. value of interest is also in the list so need to exclude it 
                keyOfValList = [ temp for temp in keyOfValList if temp != constants.INVALID_YAML_KEY_INDEX_STR] ## need to filter '0', as '0' is included in parsing 
                keyOfValList = [ detector.sanitizeConfigKeys( kName ) for kName in keyOfValList ]
                keyOfValList = [key_name for key_name in keyOfValList if checkIfValidSecretName( key_name ) ]
                if ( src_key != constants.NULL_SYMBOL ):
                    # print(src_key)
                    keyOfValList.append( src_key )
                res_dic[count] = ( val_, keyOfValList , constants.DUMMY_LIST_INDEX, constants.SOURCE_TYPE_NON_PLAY )            
            else:
                if constants.PLAY_NAME_CONSTANT in real_keys :
                    res_dic[count] = ( val_, real_keys, real_keys.index( constants.PLAY_NAME_CONSTANT ), constants.SOURCE_TYPE_PLAY )
                else: 
                    res_dic[count] = ( val_, keyOfValList , constants.DUMMY_LIST_INDEX, constants.SOURCE_TYPE_NON_PLAY )                                    
    # print( res_dic )
    return res_dic 

def getYAMLFiles(path_to_dir):
    valid_  = [] 
    if os.path.exists( path_to_dir ):
        for root_, dirs, files_ in os.walk( path_to_dir ):
            for file_ in files_:
                full_p_file = os.path.join(root_, file_)
                if(os.path.exists(full_p_file)):
                    if (full_p_file.endswith( constants.YAML_EXTENSION  ) or full_p_file.endswith( constants.YML_EXTENSION  )  ):
                        valid_.append(full_p_file)
    return valid_ 

def getPlayYamls( yaml_list ):
    lis2ret = [] 
    for yaml_path_ in yaml_list:
        parsed_yaml = parser.loadYAML( yaml_path_ )
        if( isinstance( parsed_yaml, list ) ):
            for dic in parsed_yaml: 
                if constants.PLAY_NAME_CONSTANT in dic: 
                    lis2ret.append( yaml_path_ )
        elif( isinstance(parsed_yaml, dict)  ): 
                if constants.PLAY_NAME_CONSTANT in parsed_yaml: 
                    lis2ret.append( yaml_path_ )
    return lis2ret


def checkIfValidReff( src_key, val2inspect ):
    val_ret      = False 
    search_term1 = constants.VAR_REFF_PATTERN + src_key + constants.OTHER_VAR_REFF_PATTERN 
    search_term2 = constants.PLUS_SYMBOL + src_key + constants.PLUS_SYMBOL
    val2inspect  = val2inspect.replace( constants.WHITESPACE_SYMBOL ,  constants.NULL_SYMBOL )
    if( any( x_ in val2inspect for x_ in constants.WRONG_CROSS_KEYWORDS ) == False ) and ( ( search_term1 in val2inspect ) or (search_term2 in val2inspect )  ) :
        val_ret = True  
    return val_ret
    


def getDirFromScriptPath(s_path, org_dir):
    temp_script     = s_path 
    script_src_repo = temp_script.replace( org_dir, constants.NULL_SYMBOL )
    # print( script_path, script_src_repo )
    splitted_things = script_src_repo.split( constants.SLASH_SYMBOL )
    # print( splitted_things )
    script_src_root = splitted_things[0]
    dir2search      = org_dir + script_src_root     
    return dir2search

def getCrossReffs(org_dir, script_path, prelim_graph_dic, speedup_flag ):
    res_cnt = 0 
    res_dic = {} 
    for counter, tuple_ in prelim_graph_dic.items():
        valu_, key_lis, _, type_ = tuple_
        # print(key_lis)
        key_lis = np.unique( key_lis )
        if type_ == constants.SOURCE_TYPE_NON_PLAY:
            if speedup_flag:
                #TODO
                print('SPEEDUP_ZONE')
            else:
                dir2search      = getDirFromScriptPath( script_path, org_dir )
                '''
                get YAMLs from directory of current YAML 
                '''
                yamls_in_dir    = getYAMLFiles( dir2search )
                for yaml_ in yamls_in_dir:
                    # print( script_path,  yaml_, key_lis  )
                    ya_di   = parser.loadYAML( yaml_ )
                    ya_vals = parser.getValuesRecursively( ya_di )
                    # print( ya_vals )
                    # print( key_lis )
                    for ya_va in ya_vals:
                        if( isinstance( ya_va, str ) ):
                            for key_ in key_lis:
                                key_from_src = str( key_ )
                                # if( constants.KATELLO_KEYWORD in key_from_src ):
                                #     print( key_from_src, ya_va )
                                '''
                                keys will be refernced using `{{ var_name }}` format 
                                '''
                                if ( key_from_src in ya_va )  and ( constants.VAR_REFF_PATTERN in ya_va ) and ( constants.OTHER_VAR_REFF_PATTERN in ya_va ) and ( checkIfValidReff( key_from_src, ya_va ) ) :
                                    res_cnt += 1
                                    '''
                                    Structure of result dicts 
                                    key = counter : indicates use of the hard-coded value by a play , e.g. counter = 5 , means the value was used in 5 plays 
                                    values = (src_script, src_val, sink_script, sink_val)
                                    '''
                                    res_dic[ res_cnt ] = ( script_path, key_from_src, yaml_, ya_va  )
                                    # keyOfValList = parser.getKeysBasedOnValue(ya_di, ya_va)
                                    # print( yaml_,   ya_va, key_from_src , keyOfValList  )
                                    # if ( constants.PLAY_NAME_CONSTANT in keyOfValList ):
                                    #     print( yaml_,   ya_va, key_from_src , keyOfValList  )
    return res_dic 



def getNoIntegPlayUsage(  weakness_dic ): 
    res_dic = {} 
    for counter_, values_ in weakness_dic.items():
        res_dic[counter_] = ( values_[3]  , [ values_[2] ] , constants.DUMMY_LIST_INDEX , constants.SOURCE_TYPE_PLAY )
    return res_dic 