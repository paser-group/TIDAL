'''
The parsing module to build Taintible
Akond Rahman 
July 01, 2021 
'''

import yaml 
import constants 

def checkIfWeirdYAML(yaml_script):
    '''
    to filter invalid YAMLs such as ./github/workflows/ 
    '''
    val = False
    if ( any(x_ in yaml_script for x_ in constants.WEIRD_PATHS  ) ):
        val = True 
    return val 

def loadYAML( script_ ):
    '''
    returns a dict or  a list of dicts 
    '''
    dict2ret = {}
    with open(script_, constants.FILE_READ_FLAG  ) as yml_content :
        try:
            dict2ret =   yaml.safe_load(yml_content) 
        except yaml.YAMLError as exc:
            print( constants.NULL_SYMBOL  )    
    return dict2ret 

def getKeyRecursively(  dict_, list2hold,  depth_ = 0  ) :
    '''
    gives you ALL keys in a regular/nested dictionary 
    returns output as a list 
    '''
    if  isinstance(dict_, dict) :
        for key_, val_ in sorted(dict_.items(), key = lambda x: x[0] if ( isinstance(x[0], str) ) else str(x[0])  ):    
            if isinstance(val_, dict):
                list2hold.append( (key_, depth_) )
                depth_ += 1 
                getKeyRecursively( val_, list2hold,  depth_ ) 
            elif isinstance(val_, list):
                for listItem in val_:
                        if( isinstance( listItem, dict ) ):
                            list2hold.append( (key_, depth_) )
                            depth_ += 1 
                            getKeyRecursively( listItem, list2hold,  depth_ )     
            else: 
                list2hold.append( (key_, depth_) )                


def getValsFromKey(dict_, target, list_holder  ):
    '''
    If you give a key, then this function gets the corresponding values 
    Multiple values are returned if there are keys with the same name  
    '''    
    if ( isinstance( dict_, dict ) ):
        for key, value in dict_.items():
            # print( key, len(key) , target, len( target ), value  )
            if key == target:
                list_holder.append( value )
            else: 
                if isinstance(value, dict):
                    getValsFromKey(value, target, list_holder)
                elif isinstance(value, list):
                    for ls in value:
                        getValsFromKey(ls, target, list_holder)


def getContentAsList(path2File):
    data = None 
    with open(path2File, constants.FILE_READ_MODE) as file_:
        try:
            data = file_.read()
        except UnicodeDecodeError as err_:
            data = constants.NULL_SYMBOL
            print( str( err_ ) )
    data_ls = data.split(constants.NEWLINE_CONSTANT) 
    return data_ls 


def getValuesRecursively(  dict_   ) :
    '''
    gives you ALL values in a dictionary 
    '''
    if  isinstance(dict_, dict) :
        for val_ in dict_.values():
            yield from getValuesRecursively(val_) 
    elif isinstance(dict_, list):
        for v_ in dict_:
            yield from getValuesRecursively(v_)
    else: 
        yield dict_

def getKeysBasedOnValue(dic_, value):
  '''
  If you give a value, then this function gets the corresponding key, and the keys that call the key 
  i.e. the whole hierarchy
  Returns None if no value is found  
  '''
  if dic_ == value:
    return [dic_]
  elif isinstance(dic_, dict):
    for k, v in dic_.items():
      p = getKeysBasedOnValue(v, value)
      if p:
        return [k] + p
  elif isinstance(dic_, list):
    lst = dic_
    for i in range(len(lst)):
      p = getKeysBasedOnValue(lst[i], value)
      if p:
        return [str(i)] + p


if __name__=='__main__':
    test_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/openshift@openshift-ansible-contrib/misc/gce-federation/files/pacman-service.yaml'
    # test_yaml = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/playbooks/satellite/satutils.yaml'
    # test_yaml  = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/redhat-performance@satellite-performance/conf/satperf.yaml'
    the_dic   = loadYAML( test_yaml )
    print( the_dic )
    lis_      = [] 
    getKeyRecursively(the_dic, lis_)
    # print(  lis_   )
    val_list = [] 
    getValsFromKey( the_dic, 'spec', val_list )
    print( val_list )