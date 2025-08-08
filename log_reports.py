#!/usr/bin/python3
# Amr Ahmed
import re

with open('app_logs.txt', 'r') as logs:

    category={}
    time=[]
    failed_users={}
    success_log={}
    warnings=[]
    num_events=0
#this pattern searches for the timestamps and codes
    pattern= r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([A-Z]+): '

    for line in logs:

        num_events+=1
        
        match= re.search(pattern,line.strip())

        if match:

            timestamp= match.group(1)
            code= match.group(2)

            time.append(timestamp)
            

            if code not in category.keys():

                category[code]=1

            else:

                category[code]+=1

#this pattern will search for failed login attempts and record the user and thier IP address

            failed_match = re.search(r'Failed login attempt for user \'([a-zA-Z0-9]*)\' from IP (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$',line)
            if failed_match:
                user=failed_match.group(1)
                ip=failed_match.group(2)

                if user not in failed_users.keys():

                    failed_users[user]=ip

                else:

                    continue

# this pattern will show the users that successfully logged in
            users_logged = re.search(r'User \'([a-zA-Z0-9]*)\' logged in from IP (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$',line)

            if users_logged:

                userr = users_logged.group(1)
                ipp = users_logged.group(2)

                if userr not in success_log.keys():

                    success_log[userr]=ipp

                else:

                    continue



#this pattern will match for any warning and store it

            syswarn = re.search(r'WARNING: ([\w\s\d\%\/\(\)]*)',line.strip())

            if syswarn:

                warnings.append(syswarn.group(1))
            
    
# code output

    print("=== Log Analysis Report === ")
    print(f'Time Range: {time[0]} to {time[-1]}')
    print("Past Logins:")
    for user,ip in success_log.items():
        print(f'-User \'{user}\' from IP {ip}')
    print(f'Total Events: {num_events}')
    for code, amount in category.items():
        print(f'-{code}: {amount}')
    
    print('\n')
    print('=== Security Events === ')
    print("Failed Logins:")
    for user,ip in failed_users.items():
        print(f'-User \'{user}\' from IP {ip} ')


    print('\n')
    print('=== System Alerts === ')
    for i in range(len(warnings)):

        print(f'{i+1}. {warnings[i]}')

    


        