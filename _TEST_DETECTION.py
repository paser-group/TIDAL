'''
Akond Rahman 
July 01, 2021 
Module to test detection  
'''

import unittest 
import _TEST_CONSTANTS
import detector
import parser

class TestDefaultPortDetection( unittest.TestCase ):

    def testTrueDefaultPort1(self):     
        '''
        Test for TCP , 22 isnot the default port for TCP 
        '''
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.default_port_script1 
        yaml_as_dict = parser.loadYAML( scriptName )
        res_dic      = detector.getDefaultPortCount( yaml_as_dict )
        self.assertEqual(oracle_value, len(res_dic) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  


    def testTrueDefaultPort2(self):     
        oracle_value = 1 
        scriptName   = _TEST_CONSTANTS.default_port_script2
        yaml_as_dict = parser.loadYAML( scriptName )
        res_dic      = detector.getDefaultPortCount( yaml_as_dict )
        self.assertEqual(oracle_value, len(res_dic) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testTrueDefaultPort3(self):     
        oracle_value = 1 
        scriptName   = _TEST_CONSTANTS.default_port_script3
        yaml_as_dict = parser.loadYAML( scriptName )
        res_dic      = detector.getDefaultPortCount( yaml_as_dict )
        self.assertEqual(oracle_value, len(res_dic) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testTrueDefaultPort4(self):     
        oracle_value = 1 
        scriptName   = _TEST_CONSTANTS.default_port_script4
        yaml_as_dict = parser.loadYAML( scriptName )
        res_dic      = detector.getDefaultPortCount( yaml_as_dict )
        self.assertEqual(oracle_value, len(res_dic) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )                  

    def testTrueDefaultPort5(self):     
        oracle_value = 1 
        scriptName   = _TEST_CONSTANTS.default_port_script5
        yaml_as_dict = parser.loadYAML( scriptName )
        res_dic      = detector.getDefaultPortCount( yaml_as_dict )
        self.assertEqual(oracle_value, len(res_dic) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testTrueDefaultPort6(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.default_port_script6
        yaml_as_dict = parser.loadYAML( scriptName )
        res_dic      = detector.getDefaultPortCount( yaml_as_dict )
        self.assertEqual(oracle_value, len(res_dic) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )                          

class TestSuspiciousCommentDetection( unittest.TestCase ):

    def testTrueSusp1(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.default_port_script5 
        res_ls       = detector.getSuspComments( scriptName )
        self.assertEqual(oracle_value, len(res_ls) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testFalseSusp1(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.parsing_resource1  
        res_ls       = detector.getSuspComments( scriptName )
        self.assertEqual(oracle_value, len(res_ls) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  


class TestInvalidIPDetection( unittest.TestCase ):

    def testTrueInvalidIP1(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.default_port_script5 
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getInvalidIPCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testTrueInvalidIP2(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.inavlid_ip_script1 
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getInvalidIPCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testTrueInvalidIP3(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.inavlid_ip_script2 
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getInvalidIPCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )          



class TestHTTPDetection( unittest.TestCase ):

    def testTrueInsecureHTTP1(self):     
        oracle_value = 4
        scriptName   = _TEST_CONSTANTS.parsing_resource1 
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getInsecureHTTPCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testTrueInsecureHTTP2(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.default_port_script6 
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getInsecureHTTPCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )  

    def testTrueInsecureHTTP3(self):     
        oracle_value = 2
        scriptName   = _TEST_CONSTANTS.insecure_http_script1  
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getInsecureHTTPCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )          



class TestEmptyPassDetection( unittest.TestCase ):

    def testFPEmpty1(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.fp_empty_pass_yaml1
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getEmptyPasswordCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testFPEmpty2(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.fp_empty_pass_yaml2
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getEmptyPasswordCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testFPEmpty3(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.fp_empty_pass_yaml3
        dic_         = parser.loadYAML( scriptName )
        res_dic      = detector.getEmptyPasswordCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )                 

if __name__ == '__main__':
    unittest.main()