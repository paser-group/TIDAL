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

class TestPlayGraphs( unittest.TestCase ):

    def testHTTP1(self):     
        oracle_value = 4
        scriptName   = _TEST_CONSTANTS.parsing_resource1
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_res_dic = detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dic = graph.getPlayUsage( yaml_as_dict, http_res_dic )
        self.assertEqual(oracle_value, len( http_use_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testHTTP2(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.parsing_resource1
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_res_dic = detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dic = graph.getPlayUsage( yaml_as_dict, http_res_dic )
        # print( http_use_dic )
        self.assertEqual(oracle_value, len( http_use_dic[4][1]  ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testHTTP3(self):     
        oracle_value = _TEST_CONSTANTS.SOURCE_TYPE_NON_PLAY
        scriptName   = _TEST_CONSTANTS.parsing_resource1
        yaml_as_dict = parser.loadYAML( scriptName ) 
        http_res_dic = detector.getInsecureHTTPCount( yaml_as_dict )
        http_use_dic = graph.getPlayUsage( yaml_as_dict, http_res_dic )
        self.assertEqual(oracle_value,  http_use_dic[3][3]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testHTTP4(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.insecure_http_script1
        dic_lis      = parser.loadYAML( scriptName ) 
        for yaml_as_dict in dic_lis:
            http_res_dic = detector.getInsecureHTTPCount( yaml_as_dict )
            if len( http_res_dic )  > 0 :
                # print( http_res_dic )
                http_use_dic = graph.getPlayUsage( yaml_as_dict, http_res_dic )
                # print( http_use_dic )
                # check if the index in the key list gives you `name` aka the 'PLAY_NAME_CONSTANT'
                self.assertEqual(oracle_value,  len( http_use_dic )  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testInvalidIP1(self):     
        oracle_value   = _TEST_CONSTANTS.INVALID_IP_CONSTANT
        scriptName     = _TEST_CONSTANTS.inavlid_ip_script1
        yaml_as_dict   = parser.loadYAML( scriptName ) 
        inv_ip_res_dic = detector.getInvalidIPCount ( yaml_as_dict )
        inv_ip_use_dic = graph.getPlayUsage( yaml_as_dict, inv_ip_res_dic )
        self.assertEqual(oracle_value,  inv_ip_use_dic[1][0]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testInvalidIP2(self):     
        oracle_value   = _TEST_CONSTANTS.VIP_KEYWORD
        scriptName     = _TEST_CONSTANTS.default_port_script5
        yaml_as_dict   = parser.loadYAML( scriptName ) 
        inv_ip_res_dic = detector.getInvalidIPCount ( yaml_as_dict )
        inv_ip_use_dic = graph.getPlayUsage( yaml_as_dict, inv_ip_res_dic )
        # check if the index in the key list gives you `vip` aka the 'VIP_KEYWORD'
        self.assertEqual(oracle_value,  inv_ip_use_dic[1][1][ inv_ip_use_dic[1][2] ]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testEmptyPassword(self):     
        oracle_value = 0 
        scriptName   = _TEST_CONSTANTS.fp_empty_pass_yaml3
        dic_lis      = parser.loadYAML( scriptName ) 
        for yaml_as_dict in dic_lis:
            empty_pwd_res_dic = detector.getEmptyPasswordCount( yaml_as_dict )
            empty_pwd_use_dic = graph.getPlayUsage( yaml_as_dict, empty_pwd_res_dic )
            self.assertEqual(oracle_value,  len( empty_pwd_use_dic  )  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testDefaultPort(self):     
        oracle_value   = _TEST_CONSTANTS.SSH_PORT
        scriptName     = _TEST_CONSTANTS.default_port_script5
        yaml_as_dict   = parser.loadYAML( scriptName ) 
        port_res_dic   = detector.getDefaultPortCount ( yaml_as_dict )
        port_use_dic   = graph.getPlayUsage( yaml_as_dict, port_res_dic )

        self.assertEqual(oracle_value,  port_use_dic[1][0]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testNoInteg1(self):     
        oracle_value   = _TEST_CONSTANTS.tp_value_url
        scriptName     = _TEST_CONSTANTS.tp_no_integ_yaml1
        dic_lis        = parser.loadYAML( scriptName )
        # print(dic_lis)
        yaml_as_dict   = dic_lis[0] 
        integ_res_dic  = detector.getIntegViolationCount ( yaml_as_dict )
        integ_use_dic  = graph.getPlayUsage( yaml_as_dict, integ_res_dic )

        self.assertEqual(oracle_value,  integ_use_dic[1][0]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testNoInteg2(self):     
        oracle_value   = 0
        scriptName     = _TEST_CONSTANTS.tp_no_integ_yaml3
        dic_lis        = parser.loadYAML( scriptName )
        for yaml_as_dict in dic_lis:
            integ_res_dic  = detector.getIntegViolationCount ( yaml_as_dict )
            if( len(integ_res_dic) > 0 ):
                integ_use_dic  = graph.getPlayUsage( yaml_as_dict, integ_res_dic )
                # print( integ_use_dic, len( integ_use_dic ) )
                self.assertEqual(oracle_value,  len( integ_use_dic )  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testSecret1(self):     
        oracle_value   = _TEST_CONSTANTS.SOURCE_TYPE_NON_PLAY
        scriptName     = _TEST_CONSTANTS.graph_secret_yaml
        list_dict      = parser.loadYAML( scriptName ) 
        yaml_as_dict   = list_dict[1]
        secret_res_lis = detector.getSecretCount ( yaml_as_dict )
        user_use_dic   = graph.getSecretPlayUsage( yaml_as_dict, secret_res_lis[0] ) 
        self.assertEqual(oracle_value,  user_use_dic[1][3]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )                  

    def testSecret2(self):     
        oracle_value   = 0 
        scriptName     = _TEST_CONSTANTS.graph_secret_yaml
        list_dict      = parser.loadYAML( scriptName ) 
        yaml_as_dict   = list_dict[3]
        secret_res_lis = detector.getSecretCount ( yaml_as_dict )
        pwd_use_dic    = graph.getSecretPlayUsage( yaml_as_dict, secret_res_lis[1] ) 
        # print( pwd_use_dic )
        self.assertEqual(oracle_value,  len( pwd_use_dic )  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )    

    def testSecret3(self):     
        oracle_value   = _TEST_CONSTANTS.SOURCE_TYPE_NON_PLAY
        scriptName     = _TEST_CONSTANTS.tp_secret_yaml
        yaml_as_dict   = parser.loadYAML( scriptName ) 
        secret_res_lis = detector.getSecretCount ( yaml_as_dict )
        pwd_use_dic    = graph.getSecretPlayUsage( yaml_as_dict, secret_res_lis[1] ) 
        # print( pwd_use_dic )
        self.assertEqual(oracle_value,  pwd_use_dic[1][3]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )    

if __name__ == '__main__':
    unittest.main()