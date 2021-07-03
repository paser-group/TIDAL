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

class TestCrossGraphs( unittest.TestCase ):

    def testCrossSecret1(self):     
        oracle_value = 377
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_uname_d= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[0])
        self.assertEqual(oracle_value, len( cross_uname_d ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


    def testCrossSecret2(self):     
        oracle_value = 377
        scriptName   = _TEST_CONSTANTS.cross_tp_secret_yaml 
        yaml_as_dict = parser.loadYAML( scriptName ) 
        secret_dic_ls= detector.getSecretCount( yaml_as_dict ) 
        secret_use_ls= [ graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[0]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[1]), graph.getSecretPlayUsage(yaml_as_dict, secret_dic_ls[2]) ]                
        cross_pass_di= graph.getCrossReffs(_TEST_CONSTANTS.org_dir, scriptName, secret_use_ls[1])
        self.assertEqual(oracle_value, len( cross_pass_di ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testCrossSecret3(self):     
        oracle_value = 4
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


if __name__ == '__main__':
    unittest.main() 