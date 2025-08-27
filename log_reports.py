#!/usr/bin/python3
# Amr Ahmed
import re
import os 
import sys
from datetime import datetime
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
import io
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

def log_parsing(file):
    ''' takes the log file as input and parses through it then adds it to a dictionary'''
    try:

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
    except Exception as e:
        print(f"Error occured while parsing log file: {e}")
        return None
            
def generate_report(data):  
    '''generates an in-memory PDF report based on the data parsed from the log file'''
    try:
        buffer = io.BytesIO() #creates in-memort byte stream  
        doc = SimpleDocTemplate(buffer)

        style = getSampleStyleSheet()

        elements = []

        title = Paragraph("Log Analysis Report",style['title'])
        elements.append(title)
        elements.append(Spacer(1,12))

        intro=Paragraph(f"This report summarizes the log analysis from {data['time'][0]} to {data['time'][-1]}",style['BodyText'])
        elements.append(intro)
        elements.append(Spacer(1,12))

        elements.append(Paragraph(f"Total Number of Events: {data['num_events']}",style['Heading2']))
        elements.append(Spacer(1,12))

        for code, amt in data['category'].items():
            elements.append(Paragraph(f"-{code}: {amt}",style['BodyText']))
        elements.append(Spacer(1,12))

        elements.append(Paragraph(f"Successful Logins:",style['Heading2']))
        elements.append(Spacer(1,12))

        for succes_u,succes_ip in data['success_log'].items():
            elements.append(Paragraph(f"-{succes_u}: {succes_ip}",style['BodyText']))
        elements.append(Spacer(1,12))

        elements.append(Paragraph(f"Failed Logins:",style['Heading2']))
        elements.append(Spacer(1,12))

        for failed_u, failed_ip in data['failed_users'].items():
            elements.append(Paragraph(f"-{failed_u}: {failed_ip}",style['BodyText']))
        elements.append(Spacer(1,12))

        elements.append(Paragraph(f"Security Alerts",style['Heading2']))
        elements.append(Spacer(1,12))

        for i in range(len(data['warnings'])):
            elements.append(Paragraph(f"{i+1}. {data['warnings'][i]}",style['BodyText']))

        elements.append(Spacer(1,12))

        doc.build(elements)
        buffer.seek(0) #moves the cursor to the beginning
        return buffer

    except Exception as e:

        print(f"an error occurred while creating the PDF file: {e}")
        return None
    
def send_email(smtp_server, sender_email, sender_password, recipient_email, subject, body, attachment_stream):
    '''takes the parameters and then sends an email using them '''
    try:
    
        #create multipart email message
        msg = MIMEMultipart()
        msg['From']=sender_email
        msg['To']=recipient_email
        msg['Subject']=subject

        #attach email body
        msg.attach(MIMEText(body,'plain'))

        #attach report PDF file
        timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
        attach_name = f"Log_report_{timestamp}.pdf"
        part =MIMEApplication(attachment_stream.read(), Name = attach_name)
        part['Content-Disposition'] = f'attachment: filename="{attach_name}"'
        msg.attach(part)

        print("email created")

        #connect to the smtp server and sends the email
        smtp_port = 587
        with smtplib.SMTP(smtp_server,smtp_port) as server:
            server.starttls() # Upgrade the connection to a secure encrypted SSL/TLS connection
            server.login(sender_email,sender_password) #logs in to the SMTP server
            server.send_message(msg) # sends the email
            print("Email sent succesfully!")

    except Exception as e:
        print(f"Failed to send Email: {e}")

def main():
    '''Main function that starts the script execution.'''
    log_file = 'app_logs.txt'
    
    if not os.path.exists(log_file):
        sys.exit(f"ERROR: {log_file} doesn't exist")
    
    # Parses the log file and gets all the data
    log_data = log_parsing(log_file)

    if log_data is None:
        sys.exit("Failed to parse the log data")

    # Generates report in-memory
    print("Generating Report...")
    report_stream = generate_report(log_data)
    
    if report_stream:
        print(f"Report generation completed")

        smtp_server = "" #format: smtp.server.com could be smtp.gmail/outlook/yahoo/etc.com
        sender_email = "" #email address the report will be sent from
        sender_password = "" #generate an app password and paste the 16-character code
        recipient_email = "" #email address the report will be sent to
        subject = "Log Analysis Report"
        body = 'Please find the attached log analysis report.'
        
        send_email(smtp_server, sender_email, sender_password, recipient_email, subject, body, report_stream)
    else:
        print("Failed to generate report")

if __name__ == "__main__":
    main()      