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
            print( constants.YAML_SKIPPING_TEXT  )    
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