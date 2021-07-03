'''
Akond Rahman 
July 02, 2021 
Code to create data dependence graphs 
'''
import parser 
import constants 
import detector 

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
    for key_, val_ in weakness_dic.items():
        # SSH dicts are stored in tuples to keep tack of the protocol 
        if (isinstance( val_, tuple ) ):
            if( len( val_ ) == 2 ):
                val_ = val_[0]
                val_ = str( val_ ) ## ports are stored as Integer , need to convert to String 
            elif( len( val_ ) == 4 ):
                val_ = val_[3]                
        # print( val_, all_dict_vals )
        if val_ in all_dict_vals: 
            # print( val_, all_dict_vals, real_keys, len(real_keys) )
            keyOfValList = parser.getKeysBasedOnValue(full_dic, val_)
            # print( val_, keyOfValList ) 
            if isinstance( keyOfValList, list ):
                keyOfValList = [ x for x in keyOfValList if x!= val_ ] ## the config. value of intesrest is also in the list so need to exclude it 
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
    for key_, val_ in weakness_dic.items():
        # SSH dicts are stored in tuples to keep tack of the protocol 
        if (isinstance( val_, tuple ) ):
            if( len( val_ ) == 2 ):
                val_ = val_[1]
                val_ = str( val_ ) ## the second element of the tuple is value 
        # print( val_, all_dict_vals )
        if val_ in all_dict_vals: 
            # print( val_, all_dict_vals, real_keys, len(real_keys) )
            keyOfValList = parser.getKeysBasedOnValue(full_dic, val_)
            # print( val_, keyOfValList ) 
            if isinstance( keyOfValList, list ):
                keyOfValList = [ x for x in keyOfValList if x!= val_ ] ## the config. value of intesrest is also in the list so need to exclude it 
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