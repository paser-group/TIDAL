'''
Akond Rahman 
July 02, 2021 
Module to test graphs 
'''

import unittest 
import _TEST_CONSTANTS
import parser
import graph 
import detector
import numpy as np 
import pandas as pd 


class TestCrossSecretGraphs( unittest.TestCase ):

    def testCrossSecret1(self):     
        oracle_value = 251
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(oracle_value, len( cross_uname_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossSecret2(self):     
        oracle_value = 251
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(oracle_value, len( cross_pass_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret3(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_keys_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[2], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(oracle_value, len( cross_keys_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret4(self):     
        oracle_value = _TEST_CONSTANTS.NOKATELLO_MESSAGE
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        uname_vars   = cross_uname_d.values()
        unames       = np.unique( [ name[1] for name  in uname_vars ]  ) 
        # print( unames )
        self.assertTrue( _TEST_CONSTANTS.KATELLO_USER not in unames ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret5(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        uname_vars   = cross_uname_d.values()
        unames       = np.unique( [ name[1] for name  in uname_vars ]  ) 
        self.assertEqual(  oracle_value , len(unames)  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret6(self):     
        oracle_value = _TEST_CONSTANTS.RHSM_MESSAGE
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        uname_vars   = cross_uname_d.values()
        unames       = np.unique( [ name[1] for name  in uname_vars ]  ) 
        self.assertTrue( _TEST_CONSTANTS.RHSM_USER  in unames ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret7(self):     
        oracle_value = 49
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        uname_vars   = cross_uname_d.values()
        files        = np.unique( [ name[2] for name  in uname_vars ]  ) 
        self.assertEqual(  oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossSecret8(self):     
        oracle_value = 49
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        files        = np.unique( [ name[2] for name in dic_values ] )
        self.assertEqual(oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret9(self):     
        oracle_value = _TEST_CONSTANTS.KATELLO_PASS
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        var_names    = np.unique( [ name[1] for name in dic_values ] )
        # print( var_names )
        self.assertTrue( oracle_value not in var_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.NOKATELLO_MESSAGE  ) 

    def testCrossSecret10(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_keys_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[2], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_keys_di.values() 
        # print( dic_values )
        files        = np.unique( [ name[2] for name in dic_values ] )
        self.assertEqual(oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret11(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml1 not  in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret12(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml2 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret13(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml3 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret14(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertFalse( _TEST_CONSTANTS.cross_existence_yam10 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret15(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml9 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret16(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml8 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret17(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml7 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret18(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_unam_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_unam_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml6 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret19(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_unam_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_unam_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml5 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )      

    def testCrossSecret20(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_unam_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_unam_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml4 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )              

    def testCrossSecret21(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_secret_yamlX
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(  oracle_value, len( cross_uname_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret22(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_secret_yamlX
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[2], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(  oracle_value, len( cross_uname_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret23(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.cross_secret_yamlX
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(  oracle_value, len( cross_pass_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret24(self):     
        scriptName   = _TEST_CONSTANTS.cross_secret_yamlX
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1], _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        dic_values   = cross_pass_di.values() 
        # print( cross_pass_di )
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yam11 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )              


class TestCrossHTTPGraphs( unittest.TestCase ):

    def testCrossHTTP1(self):     
        oracle_value = 3
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        self.assertEqual(oracle_value, len( cross_http_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossHTTP2(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        files        = np.unique( [ x_[2] for x_ in cross_http_d.values() ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yam12 in files  ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  ) 


    def testCrossHTTP3(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        values       = cross_http_d.values()  
        keys         = np.unique( [t_[1] for t_ in values ] )
        # print(keys)
        self.assertTrue( _TEST_CONSTANTS.cross_existence_key1 in keys  ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.KEY_MISSING_MESSAGE  ) 


    def testCrossHTTP4(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        values       = cross_http_d.values()  
        keys         = np.unique( [t_[1] for t_ in values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_key2 in keys  ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.KEY_MISSING_MESSAGE  ) 

    def testCrossHTTP5(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        values       = cross_http_d.values()  
        files        = np.unique( [t_[2] for t_ in values ] )
        self.assertFalse( _TEST_CONSTANTS.cross_existence_yam13 in files  ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.KEY_MISSING_MESSAGE  ) 


class TestCrossInvalidIPGraphs( unittest.TestCase ):

    def testCrossInvalidIP1(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_secret_yaml_IP 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        ip_resr_dic  = detector.getInvalidIPCount ( yaml_as_dict )
        ip_use_dict  = graph.getPlayUsage( yaml_as_dict,  ip_resr_dic )
        cross_ip_dic = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  ip_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        self.assertEqual(oracle_value, len( cross_ip_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossInvalidIP2(self):     
        oracle_value = 0 
        scriptName   = _TEST_CONSTANTS.cross_secret_yaml_IP 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        ip_resr_dic  = detector.getInvalidIPCount ( yaml_as_dict )
        ip_use_dict  = graph.getPlayUsage( yaml_as_dict,  ip_resr_dic )
        cross_ip_dic = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  ip_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        files        = np.unique( [c_[2] for c_ in  cross_ip_dic.values() ] )
        self.assertEqual(oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossInvalidIP3(self):     
        '''
        The test script used here includes an inavlid IP address, which is used by a play in the same script so result will 
        be zero, as no cross references 
        '''
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_invalid_ip_yaml
        yaml_as_dict = parser.loadYAML( scriptName ) 
        ip_resr_dic  = detector.getInvalidIPCount ( yaml_as_dict )
        ip_use_dict  = graph.getPlayUsage( yaml_as_dict,  ip_resr_dic )
        cross_ip_dic = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  ip_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        self.assertEqual(oracle_value, len( cross_ip_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

class TestCrossEmptyPassGraphs( unittest.TestCase ):

    def testCrossEmptyPass1(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_empty_pass_yaml
        yaml_as_dict = parser.loadYAML( scriptName ) 
        emp_pass_dic = detector.getEmptyPasswordCount( yaml_as_dict )
        emp_use_dict = graph.getPlayUsage( yaml_as_dict,  emp_pass_dic )
        cross_emp_dic= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  emp_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        self.assertEqual(oracle_value, len( cross_emp_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossEmptyPass2(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_empty_pass_yaml
        yaml_as_dict = parser.loadYAML( scriptName ) 
        emp_pass_dic = detector.getEmptyPasswordCount( yaml_as_dict )
        emp_use_dict = graph.getPlayUsage( yaml_as_dict,  emp_pass_dic )
        cross_emp_dic= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  emp_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        files        = np.unique( [ t_[2] for t_ in cross_emp_dic.values() ] )
        self.assertEqual(oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


class TestCrossDefaultPortGraphs( unittest.TestCase ):

    def testCrossDefaultPort1(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_port_yaml
        yaml_as_dict = parser.loadYAML( scriptName ) 
        port_cnt_dic = detector.getDefaultPortCount( yaml_as_dict )
        port_use_dict= graph.getPlayUsage( yaml_as_dict,  port_cnt_dic )
        cross_port_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  port_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        self.assertEqual(oracle_value, len( cross_port_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossDefaultPort2(self):     
        scriptName   = _TEST_CONSTANTS.cross_port_yaml
        yaml_as_dict = parser.loadYAML( scriptName ) 
        port_cnt_dic = detector.getDefaultPortCount( yaml_as_dict )
        port_use_dict= graph.getPlayUsage( yaml_as_dict,  port_cnt_dic )
        cross_port_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  port_use_dict , _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        files        = np.unique( [x_[2] for x_ in cross_port_di.values()] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml9 not  in files ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  ) 


class TestCrossNoIntegrityGraphs( unittest.TestCase ):

    def testCrossNoIntegrity1(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_no_inte_yaml1
        yaml_as_dict = parser.loadYAML( scriptName ) 
        inte_cnt_dic = detector.getIntegViolationCount ( yaml_as_dict )
        inte_use_dict= graph.getNoIntegPlayUsage(  inte_cnt_dic )
        cross_inte_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  inte_use_dict, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG )
        self.assertEqual(oracle_value, len( cross_inte_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossNoIntegrity2(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_no_inte_yaml2
        yaml_as_dict = parser.loadYAML( scriptName ) 
        inte_cnt_dic = detector.getIntegViolationCount ( yaml_as_dict )
        inte_use_dict= graph.getNoIntegPlayUsage(  inte_cnt_dic )
        cross_inte_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  inte_use_dict , _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(oracle_value, len( cross_inte_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossNoIntegrity3(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_no_inte_yaml3
        yaml_as_dict = parser.loadYAML( scriptName ) 
        inte_cnt_dic = detector.getIntegViolationCount ( yaml_as_dict )
        inte_use_dict= graph.getNoIntegPlayUsage(  inte_cnt_dic )
        cross_inte_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  inte_use_dict , _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(oracle_value, len( cross_inte_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


class TestResultCollecton( unittest.TestCase ):

    def testResultGen(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.result_gen_script1
        res_         = detector.scanSingleScriptForAllTypes( scriptName , _TEST_CONSTANTS.org_path, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        self.assertEqual(oracle_value, len( res_ ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testResultGenSuspComment(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.result_gen_script1
        res_         = detector.scanSingleScriptForAllTypes( scriptName , _TEST_CONSTANTS.org_path, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        # the second element is numbe rof suspcious comments 
        self.assertEqual(oracle_value,  res_[1]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testResultGenPorts(self):     
        oracle_val1  = 1
        oracle_val2  = 0
        scriptName   = _TEST_CONSTANTS.result_gen_port_scri
        res_         = detector.scanSingleScriptForAllTypes( scriptName , _TEST_CONSTANTS.org_path, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        res_others   = res_[0][0]
        for weakness_dic in res_others:
            if _TEST_CONSTANTS.RESULT_DEFAULT_PORT in weakness_dic:
                self.assertEqual(oracle_val1,  weakness_dic[ _TEST_CONSTANTS.RAW_COUNT_KEYWORD ],  _TEST_CONSTANTS._common_error_string + str(oracle_val1)  ) 
                self.assertEqual(oracle_val2,  weakness_dic[ _TEST_CONSTANTS.TP_COUNT_KEYWORD ],  _TEST_CONSTANTS._common_error_string + str(oracle_val2)  ) 
    def testResultSecrets(self):     
        oracle_val1  = 251
        oracle_val2  = 251
        oracle_val3  = 3 
        scriptName   = _TEST_CONSTANTS.result_gen_script2
        res_         = detector.scanSingleScriptForAllTypes( scriptName , _TEST_CONSTANTS.org_path, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        res_others   = res_[0][0]
        for weakness_dic in res_others:
            if _TEST_CONSTANTS.RESULT_USERNAME in weakness_dic:
                self.assertEqual(oracle_val1,  weakness_dic[ _TEST_CONSTANTS.AFFECTED_KEYWORD ],  _TEST_CONSTANTS._common_error_string + str(oracle_val1)  ) 
            if _TEST_CONSTANTS.RESULT_PASSWORD in weakness_dic:
                self.assertEqual(oracle_val2,  weakness_dic[ _TEST_CONSTANTS.AFFECTED_KEYWORD ],  _TEST_CONSTANTS._common_error_string + str(oracle_val2)  ) 
            if _TEST_CONSTANTS.RESULT_PRIVATE_KEY in weakness_dic:
                self.assertEqual(oracle_val3,  weakness_dic[ _TEST_CONSTANTS.AFFECTED_KEYWORD ],  _TEST_CONSTANTS._common_error_string + str(oracle_val3)  ) 

    def testResultNoInteg(self):     
        oracle_val1  = 1
        oracle_val2  = 1
        oracle_val3  = 10
        scriptName   = _TEST_CONSTANTS.result_gen_no_integ
        res_         = detector.scanSingleScriptForAllTypes( scriptName , _TEST_CONSTANTS.org_path, _TEST_CONSTANTS.NEED_FOR_SPEED_FLAG)
        res_others   = res_[0][0]
        self.assertEqual(  oracle_val3, len( res_[0] ), _TEST_CONSTANTS._common_error_string + str (oracle_val3)  )
        for weakness_dic in res_others:
            if _TEST_CONSTANTS.NO_INTEG_KEYWORD in weakness_dic:
                self.assertEqual(oracle_val1,  weakness_dic[ _TEST_CONSTANTS.RAW_COUNT_KEYWORD ],  _TEST_CONSTANTS._common_error_string + str(oracle_val1)  ) 
                self.assertEqual(oracle_val2,  weakness_dic[ _TEST_CONSTANTS.TP_COUNT_KEYWORD ],  _TEST_CONSTANTS._common_error_string + str(oracle_val1)  ) 



class TestResultDataframe( unittest.TestCase ):        

    def testDataframeRows(self):     
        oracle_value = 257 
        df_res_      = pd.read_csv( _TEST_CONSTANTS.TEST_OUTPUT_CSV ) 
        self.assertEqual(oracle_value, df_res_.shape[0] ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testDataframeNoInteg(self):     
        oracle_value = 7
        df_res_      = pd.read_csv( _TEST_CONSTANTS.TEST_OUTPUT_CSV ) 
        file_df_     = df_res_ [ df_res_[_TEST_CONSTANTS.YAML_KEY] == _TEST_CONSTANTS.TEST_NO_INTEG_FILE ]
        self.assertEqual(oracle_value, file_df_[ _TEST_CONSTANTS.NO_INTEG_KEYWORD ].tolist()[0] ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testDataframeUsername(self):     
        oracle_value = 2
        df_res_      = pd.read_csv( _TEST_CONSTANTS.TEST_OUTPUT_CSV ) 
        file_df_     = df_res_ [ df_res_[ _TEST_CONSTANTS.YAML_KEY ] == _TEST_CONSTANTS.SATPERF_TEST_FILE ]
        self.assertEqual(oracle_value, file_df_[ _TEST_CONSTANTS.RESULT_USERNAME ].tolist()[0] ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testDataframePassword(self):     
        oracle_value = 2
        df_res_      = pd.read_csv( _TEST_CONSTANTS.TEST_OUTPUT_CSV ) 
        file_df_     = df_res_ [ df_res_[ _TEST_CONSTANTS.YAML_KEY ] == _TEST_CONSTANTS.SATPERF_TEST_FILE ]
        self.assertEqual(oracle_value, file_df_[ _TEST_CONSTANTS.RESULT_PASSWORD ].tolist()[0] ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 
    def testDataframeInsecureHTTP(self):     
        oracle_value = 3
        df_res_      = pd.read_csv( _TEST_CONSTANTS.TEST_OUTPUT_CSV ) 
        file_df_     = df_res_ [ df_res_[ _TEST_CONSTANTS.YAML_KEY ] == _TEST_CONSTANTS.SATPERF_TEST_FILE ]
        self.assertEqual(oracle_value, file_df_[ _TEST_CONSTANTS.HTTP_HEADER ].tolist()[0] ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


if __name__ == '__main__':
    unittest.main() 