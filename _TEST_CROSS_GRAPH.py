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


class TestCrossSecretGraphs( unittest.TestCase ):

    def testCrossSecret1(self):     
        oracle_value = 251
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        self.assertEqual(oracle_value, len( cross_uname_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossSecret2(self):     
        oracle_value = 251
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        self.assertEqual(oracle_value, len( cross_pass_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret3(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_keys_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[2])
        self.assertEqual(oracle_value, len( cross_keys_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret4(self):     
        oracle_value = _TEST_CONSTANTS.NOKATELLO_MESSAGE
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
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
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        uname_vars   = cross_uname_d.values()
        unames       = np.unique( [ name[1] for name  in uname_vars ]  ) 
        self.assertEqual(  oracle_value , len(unames)  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret6(self):     
        oracle_value = _TEST_CONSTANTS.RHSM_MESSAGE
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        uname_vars   = cross_uname_d.values()
        unames       = np.unique( [ name[1] for name  in uname_vars ]  ) 
        self.assertTrue( _TEST_CONSTANTS.RHSM_USER  in unames ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret7(self):     
        oracle_value = 49
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        uname_vars   = cross_uname_d.values()
        files        = np.unique( [ name[2] for name  in uname_vars ]  ) 
        self.assertEqual(  oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossSecret8(self):     
        oracle_value = 49
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        dic_values   = cross_pass_di.values() 
        files        = np.unique( [ name[2] for name in dic_values ] )
        self.assertEqual(oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret9(self):     
        oracle_value = _TEST_CONSTANTS.KATELLO_PASS
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
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
        cross_keys_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[2])
        dic_values   = cross_keys_di.values() 
        # print( dic_values )
        files        = np.unique( [ name[2] for name in dic_values ] )
        self.assertEqual(oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret11(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml1 not  in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret12(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml2 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret13(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml3 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret14(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertFalse( _TEST_CONSTANTS.cross_existence_yam10 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret15(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml9 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret16(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml8 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret17(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        dic_values   = cross_pass_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml7 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret18(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_unam_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        dic_values   = cross_unam_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml6 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )         

    def testCrossSecret19(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_unam_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        dic_values   = cross_unam_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml5 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )      

    def testCrossSecret20(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_unam_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        dic_values   = cross_unam_di.values() 
        file_names   = np.unique( [ name[2] for name in dic_values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yaml4 in file_names ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  )              

    def testCrossSecret21(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_secret_yamlX
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        self.assertEqual(  oracle_value, len( cross_uname_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret22(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_secret_yamlX
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[2])
        self.assertEqual(  oracle_value, len( cross_uname_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret23(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.cross_secret_yamlX
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        self.assertEqual(  oracle_value, len( cross_pass_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret24(self):     
        scriptName   = _TEST_CONSTANTS.cross_secret_yamlX
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
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
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict )
        self.assertEqual(oracle_value, len( cross_http_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossHTTP2(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict )
        files        = np.unique( [ x_[2] for x_ in cross_http_d.values() ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_yam12 in files  ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.FILE_MISSING_MESSAGE  ) 


    def testCrossHTTP3(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict )
        values       = cross_http_d.values()  
        keys         = np.unique( [t_[1] for t_ in values ] )
        # print(keys)
        self.assertTrue( _TEST_CONSTANTS.cross_existence_key1 in keys  ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.KEY_MISSING_MESSAGE  ) 


    def testCrossHTTP4(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict )
        values       = cross_http_d.values()  
        keys         = np.unique( [t_[1] for t_ in values ] )
        self.assertTrue( _TEST_CONSTANTS.cross_existence_key2 in keys  ,  _TEST_CONSTANTS._common_error_string + _TEST_CONSTANTS.KEY_MISSING_MESSAGE  ) 

    def testCrossHTTP5(self):     
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_resr_dic= detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dict= graph.getPlayUsage( yaml_as_dict,  http_resr_dic )
        cross_http_d = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  http_use_dict )
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
        cross_ip_dic = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  ip_use_dict )
        self.assertEqual(oracle_value, len( cross_ip_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossInvalidIP2(self):     
        oracle_value = 0 
        scriptName   = _TEST_CONSTANTS.cross_secret_yaml_IP 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        ip_resr_dic  = detector.getInvalidIPCount ( yaml_as_dict )
        ip_use_dict  = graph.getPlayUsage( yaml_as_dict,  ip_resr_dic )
        cross_ip_dic = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  ip_use_dict )
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
        cross_ip_dic = graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  ip_use_dict )
        self.assertEqual(oracle_value, len( cross_ip_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

class TestCrossEmptyPassGraphs( unittest.TestCase ):

    def testCrossEmptyPass1(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_empty_pass_yaml
        yaml_as_dict = parser.loadYAML( scriptName ) 
        emp_pass_dic = detector.getEmptyPasswordCount( yaml_as_dict )
        emp_use_dict = graph.getPlayUsage( yaml_as_dict,  emp_pass_dic )
        cross_emp_dic= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  emp_use_dict )
        self.assertEqual(oracle_value, len( cross_emp_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossEmptyPass2(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.cross_empty_pass_yaml
        yaml_as_dict = parser.loadYAML( scriptName ) 
        emp_pass_dic = detector.getEmptyPasswordCount( yaml_as_dict )
        emp_use_dict = graph.getPlayUsage( yaml_as_dict,  emp_pass_dic )
        cross_emp_dic= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName,  emp_use_dict )
        files        = np.unique( [ t_[2] for t_ in cross_emp_dic.values() ] )
        self.assertEqual(oracle_value, len( files ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

if __name__ == '__main__':
    unittest.main() 