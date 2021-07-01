'''
Akond Rahman 
July 01, 2021 
Module to test parsing 
'''

import unittest 
import _TEST_CONSTANTS
import parser

class TestParsing( unittest.TestCase ):

    def testKeyExtraction1(self):     
        oracle_value = 79 
        scriptName   = _TEST_CONSTANTS.parsing_resource1
        yaml_as_dict = parser.loadYAML( scriptName )
        self.assertEqual(oracle_value, len(yaml_as_dict) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )   

    def testReturnInstance1(self):     
        oracle_value = _TEST_CONSTANTS._DICT_STRING
        scriptName   = _TEST_CONSTANTS.parsing_resource1
        yaml_as_dict = parser.loadYAML( scriptName )
        self.assertTrue( isinstance( yaml_as_dict, dict ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )   

    def testReturnInstance2(self):     
        oracle_value = _TEST_CONSTANTS._LIST_STRING 
        scriptName   = _TEST_CONSTANTS.parsing_resource2
        yaml_as_dict = parser.loadYAML( scriptName )
        self.assertTrue( isinstance( yaml_as_dict, list ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )   

    def testKeyExtraction2(self):     
        oracle_value = 4
        scriptName   = _TEST_CONSTANTS.parsing_resource3
        yaml_as_dict = parser.loadYAML( scriptName )
        self.assertEqual(oracle_value, len(yaml_as_dict) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )   

    def testReturnInstance3(self):     
        oracle_value = _TEST_CONSTANTS._LIST_STRING
        scriptName   = _TEST_CONSTANTS.parsing_resource3
        yaml_as_dict = parser.loadYAML( scriptName )
        temp_as_list = [] 
        parser.getKeyRecursively( yaml_as_dict, temp_as_list )
        self.assertTrue( isinstance( temp_as_list , list ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )   

    def testKeyExtraction3(self):     
        oracle_value = 14
        scriptName   = _TEST_CONSTANTS.parsing_resource3
        yaml_as_dict = parser.loadYAML( scriptName )
        temp_as_list = [] 
        parser.getKeyRecursively( yaml_as_dict, temp_as_list )
        self.assertEqual(oracle_value, len( temp_as_list ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )   


if __name__ == '__main__':
    unittest.main()