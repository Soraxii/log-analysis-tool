#!/usr/bin/python3
# Amr Ahmed
import re
import os 
import sys

def log_parsing(file):
    ''' takes the log file as input and parses through it then adds it to a dictionary'''
    with open(file, 'r') as logs:

        data={
            'category':{},
            'time':[],
            'failed_users':{},
            'success_log':{},
            'warnings':[],
            'num_events':0
        }
    #this pattern searches for the timestamps and codes
        pattern= r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([A-Z]+): '

        for line in logs:

            data['num_events']+=1
            
            match= re.search(pattern,line.strip())

            if match:

                timestamp= match.group(1)
                code= match.group(2)

                data['time'].append(timestamp)
                

                if code not in data['category'].keys():

                    data['category'][code]=1

                else:

                    data['category'][code]+=1

    #this pattern will search for failed login attempts and record the users and thier IP address

                failed_match = re.search(r'Failed login attempt for user \'([a-zA-Z0-9]*)\' from IP (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$',line)
                if failed_match:
                    failed_user=failed_match.group(1)
                    failed_ip=failed_match.group(2)

                    if failed_user not in data['failed_users'].keys():

                        data['failed_users'][failed_user]=failed_ip

    # this pattern will show the users that successfully logged in
                users_logged = re.search(r'User \'([a-zA-Z0-9]*)\' logged in from IP (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$',line)

                if users_logged:

                    success_user = users_logged.group(1)
                    logged_ip = users_logged.group(2)

                    if success_user not in data['success_log'].keys():

                        data['success_log'][success_user]=logged_ip

                    else:

                        continue



    #this pattern will match for any warning and store it

                syswarn = re.search(r'WARNING: ([\w\s\d\%\/\(\)]*)',line.strip())

                if syswarn:

                    data['warnings'].append(syswarn.group(1))
    return data 
            
def generate_report(data):  
        '''generates a report based on the data parsed from the log file'''

        print("=== Log Analysis Report === ")
        print(f'Time Range: {data['time'][0]} to {data['time'][-1]}')
        print("Past Logins:")
        for suser,sip in data['success_log'].items():
            print(f'-User \'{suser}\' from IP {sip}')
        print(f'Total Events: {data['num_events']}')
        for code, amount in data['category'].items():
            print(f'-{code}: {amount}')
        
        print('\n')
        print('=== Security Events === ')
        print("Failed Logins:")
        for fuser,fip in data['failed_users'].items():
            print(f'-User \'{fuser}\' from IP {fip} ')


        print('\n')
        print('=== System Alerts === ')
        for i in range(len(data['warnings'])):

            print(f'{i+1}. {data['warnings'][i]}')
    


def main():
    '''Main function that starts the script execution.'''
    log_file = 'app_logs.txt'
    
    if not os.path.exists(log_file):
        sys.exit(f"ERROR: {log_file} doesn't exist")
    
    # Parses the log file and gets all the data
    log_data = log_parsing(log_file)
    
    # Generates and prints the report
    generate_report(log_data)

if __name__ == "__main__":
    main()      