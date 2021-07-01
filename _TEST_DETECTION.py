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

if __name__ == '__main__':
    unittest.main()