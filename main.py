'''
Akond Rahman 
July 07, 2021 
The main runner script 
'''
import detector
import constants 
import time 
import  datetime 

def giveTimeStamp():
  tsObj = time.time()
  strToret = datetime.datetime.fromtimestamp(tsObj).strftime(constants.TIME_FORMAT) 
  return strToret

if __name__=='__main__':
        t1              = time.monotonic()
        speedup_flag    = False ## Abandoning speedup experiments  

        # org_dire        = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/test-ansi/'        
        # OUTPUT_FILE_CSV = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output-taintible/V4_TEST_TP_OUTPUT.csv'

        org_dire        = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ostk-ansi/'        
        OUTPUT_FILE_CSV = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output-taintible/V4_OSTK_TP_OUTPUT.csv'

        # org_dire        = '/Users/arahman/PRIOR_NCSU/SECU_REPOS/ghub-ansi/'        
        # OUTPUT_FILE_CSV = '/Users/arahman/Documents/OneDriveWingUp/OneDrive-TennesseeTechUniversity/Research/IaC/FixFalsePositive/output-taintible/V3_GHUB_TP_OUTPUT.csv'

        file_res_df      =  detector.scanMultipleScript4AllTypes( org_dire , speedup_flag )
        file_res_df.to_csv( OUTPUT_FILE_CSV, header= constants.CSV_HEADER , index=False, encoding= constants.CSV_ENCODING )     

        t2               = time.monotonic()
        time_diff        = round( (t2 - t1 ) / 60, 5) 
        print( constants.COMMENT_SYMBOL * 100  )                       
        print( constants.DURATION_STRING.format(time_diff) )
        print( constants.COMMENT_SYMBOL * 100  )                        