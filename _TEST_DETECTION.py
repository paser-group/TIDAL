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



class TestNoIntegDetection( unittest.TestCase ):
    def testNoInteg1(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.tp_no_integ_yaml1
        lis_dic_     = parser.loadYAML( scriptName ) ## gives a list of dicts 
        dic_         = lis_dic_[0] ## get data for the first dict 
        res_dic      = detector.getIntegViolationCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testNoInteg2(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.tp_no_integ_yaml2 
        lis_dic_     = parser.loadYAML( scriptName ) ## gives a list of dicts 
        dic_         = lis_dic_[0] ## get data for the first dict 
        res_dic      = detector.getIntegViolationCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testNoInteg3(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.tp_no_integ_yaml3
        lis_dic_     = parser.loadYAML( scriptName ) ## gives a list of dicts 
        dic_         = lis_dic_[-3] ## get data for the first dict 
        res_dic      = detector.getIntegViolationCount ( dic_  )
        self.assertEqual(oracle_value, len(res_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testNoIntegVal1(self):     
        oracle_value = _TEST_CONSTANTS.tp_value_url
        scriptName   = _TEST_CONSTANTS.tp_no_integ_yaml2 
        lis_dic_     = parser.loadYAML( scriptName ) ## gives a list of dicts 
        dic_         = lis_dic_[0] ## get data for the first dict 
        res_dic      = detector.getIntegViolationCount ( dic_  )
        self.assertEqual(oracle_value, res_dic[1][-1] ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testNoIntegVal2(self):     
        oracle_value = _TEST_CONSTANTS.tp_var_reff_value 
        scriptName   = _TEST_CONSTANTS.tp_no_integ_yaml3
        lis_dic_     = parser.loadYAML( scriptName ) ## gives a list of dicts 
        dic_         = lis_dic_[-3] ## get data for the first dict 
        res_dic      = detector.getIntegViolationCount ( dic_  )
        self.assertEqual(oracle_value, res_dic[1][-1] ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


class TestTPSecretDetection( unittest.TestCase ):
    def testTP_SecretSingleDict(self):     
        oracle_value = 3
        scriptName   = _TEST_CONSTANTS.tp_secret_yaml
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testTP_Usernames(self):     
        oracle_value = 3
        scriptName   = _TEST_CONSTANTS.tp_secret_yaml
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic[0] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testTP_Password1(self):     
        oracle_value = 4
        scriptName   = _TEST_CONSTANTS.tp_secret_yaml
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic[1] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testTP_Password2(self):     
        oracle_value = _TEST_CONSTANTS.sat_pas_str 
        scriptName   = _TEST_CONSTANTS.tp_secret_yaml
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, lis_dic[1][4][0]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testTP_PrivateKey1(self):     
        oracle_value = 1
        scriptName   = _TEST_CONSTANTS.tp_secret_yaml
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic[2] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testTP_PrivateKey2(self):     
        oracle_value = _TEST_CONSTANTS.changeme_str
        scriptName   = _TEST_CONSTANTS.tp_secret_yaml
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        # print(lis_dic)
        self.assertTrue(oracle_value in lis_dic[1][1][-1]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testTP_PrivateKey3(self):     
        oracle_value = _TEST_CONSTANTS.sample_var_name 
        scriptName   = _TEST_CONSTANTS.tp_secret_yaml
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        # print(lis_dic)
        self.assertEqual(oracle_value, lis_dic[2][1][0]  ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )    

    def testTP_SecretDictList1(self):     
        oracle_value = _TEST_CONSTANTS.root_user_str 
        scriptName   = _TEST_CONSTANTS.another_tp_secret_y
        lis_dic_     = parser.loadYAML( scriptName ) 
        res_dic      = detector.getSecretCount ( lis_dic_[0]  )
        self.assertEqual(oracle_value, res_dic[0][1][1] ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )              

    def testTP_SecretDictList2(self):     
        oracle_value = 1 
        scriptName   = _TEST_CONSTANTS.another_tp_secret_y
        lis_dic_     = parser.loadYAML( scriptName ) 
        res_dic      = detector.getSecretCount ( lis_dic_[0]  )
        self.assertEqual(oracle_value, len( res_dic[0] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  )              


class TestFPSecretDetection( unittest.TestCase ):
    def testFP_SecretDict1(self):     
        oracle_value = 3
        scriptName   = _TEST_CONSTANTS.fp_secret_yaml1 
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testFP_SecretDict2(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.fp_secret_yaml2 
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic[0] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testFP_SecretDict3(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.fp_secret_yaml3
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic[1] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testFP_SecretDict4(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.fp_secret_yaml4
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic[2] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 
    def testFP_SecretDict5(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.fp_secret_yaml5
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic[0] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 

    def testFP_SecretDict6(self):     
        oracle_value = 0
        scriptName   = _TEST_CONSTANTS.fp_secret_yaml6
        dic_         = parser.loadYAML( scriptName ) 
        lis_dic      = detector.getSecretCount ( dic_  )
        self.assertEqual(oracle_value, len(lis_dic[1] ) ,  _TEST_CONSTANTS._common_error_string + str(oracle_value)  ) 


if __name__ == '__main__':
    unittest.main()