import email
import sys
import re
import time
import gspread
import getpass
import hashlib
import os
from oauth2client.service_account import ServiceAccountCredentials
from tqdm import tqdm
from imaplib import IMAP4_SSL
from virus_total_apis import PublicApi

# Set Globals
_userEmail = ''
_password = ''
IMAP_URL = 'imap.gmail.com'
EMAIL_REGEX = '([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'
API_KEY = '5564d68d38f3af0e4f2ed58de5d564691d1be234ca8c8e02cbe2153b323e705a'

# Database
scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
creds = ServiceAccountCredentials.from_json_keyfile_name('client_secret.json', scope)
client = gspread.authorize(creds)
sheet = client.open('database').sheet1
whitelistedContacts = sheet.row_values(1)
blacklistedContacts = sheet.row_values(2)
badWordsArray = sheet.row_values(3)
fileTypesArray = sheet.row_values(4)

def delete_email(con, email_id):
    con.store(email_id, '+FLAGS', '\\Deleted')
    con.expunge()

def is_contain_black_listed_sender(con, extract_mail, email_id): 
    if extract_mail in blacklistedContacts:
        print("\n---> System filtered-out an email from {}. Reason: blacklisted contact\n".
                format(extract_mail))
        delete_email(con, email_id)
        return True
    return False    

def is_contain_forbidden_file_type(con, extract_mail, file_type, email_id):
    if file_type in fileTypesArray:
        delete_email(con, email_id)
        print("\n---> System filtered-out an email from {}. Reason: forbidden attachment file type {}\n".
                format(extract_mail, file_type))
        return True
    return False            

def is_file_contain_forbidden_words(con, extract_mail, email_id, file_name):
    if file_name in badWordsArray:        
        delete_email(con, email_id)
        print("\n---> System filtered-out an email from {}. Reason: attachment name is forbidden\n".
                format(extract_mail, file_name))
        return True
    return False    

def is_mail_contain_forbidden_words(con, extract_mail, email_id, subject, body):
    body_as_array = list(body.split(" "))
    subject_as_array = list(subject.split(" "))
    mail_as_words = body_as_array + subject_as_array
    length = len(mail_as_words)
    i = 0
    detected = False
    while not detected and i < length:
        word = mail_as_words[i]
        if word in badWordsArray:        
            delete_email(con, email_id)
            print("\n---> System filtered-out an email from {}. Reason: forbidden word detected\n".
                    format(extract_mail, word))
            detected = True
        i = i + 1
    return detected

def is_contain_unknown_contact(con, extract_mail, email_id):
    if extract_mail not in whitelistedContacts:
        print("\n---> You have email from: {} , which is not a known contact.\n"
                        "How would you like to handle this?\n"
                        "[1] Delete this message, no further actions\n"
                        "[2] Delete this message and add this person to blacklist\n"
                        "[3] Accept this message, no further actions\n"
                        "[4] Accept this message and add this person to whitelist\n".
                        format(extract_mail))
        while True:
            try:  
                choice = int(input())
                if choice > 0 and choice < 5:    
                    if choice < 3:
                        delete_email(con, email_id)
                        if choice == 2:
                            blacklistedContacts.append(extract_mail)
                            sheet.delete_rows(2)
                            sheet.insert_row(blacklistedContacts, 2)
                        return True  # need to continue in main loop
                    elif choice == 3:
                        return False
                    else:       # choice == 4:
                        whitelistedContacts.append(extract_mail)
                        sheet.delete_rows(1)
                        sheet.insert_row(whitelistedContacts, 1)
                        return False
                else:
                    raise ValueError()
            except ValueError:
                print("Error: Please choose a valid option from menu\n")     
                continue
            except KeyboardInterrupt:
                exit_system()  
    return False

def is_dangerous(con, file_to_scan, extract_mail, email_id, file_name):
    try:
        virus_total_scanner = PublicApi(API_KEY)
        response = virus_total_scanner.scan_file(file_to_scan, from_disk=False)
        time.sleep(1)
        f_md5 = hashlib.md5(file_to_scan).hexdigest()
        response  = virus_total_scanner.get_file_report(f_md5)
        if response['results']['positives'] > 0:
            delete_email(con, email_id)
            print("\n---> System filtered-out an email from {}. Reason: dangerous attachment detected\n".
                    format(extract_mail))
            return True
    except Exception as e:
        print('Scan file Failed: {}'.format(e))

    download_attachment(file_name, file_to_scan)        
    return False

def download_attachment(file_name, file_to_scan):
    choice = input("\n---> This mail has an attachment. Do you want to download it? Y/N\n")
    if choice == 'Y':
        if not os.path.isdir(os.path.join(os.getcwd(), "Attachments")):
            os.mkdir(os.path.join(os.getcwd(), "Attachments"))
        file_path = os.path.join(os.getcwd(), "Attachments", file_name)
        fp = open(file_path, 'wb')
        fp.write(file_to_scan)
        fp.close()
        print("\n---> Attachement downloaded {}\n". format(file_name))

def read_emails():
    con = IMAP4_SSL(IMAP_URL)
    try:
        con.login(_userEmail, _password)
        con.select('Inbox')
        _, data = con.search(None, '(UNSEEN)')
        mail_ids = data[0]
        id_list = mail_ids.split()
        ans = ''
        if len(id_list) == 0:
            print("\nFinished!\nNo new emails found")
            con.logout()
            return    
        
        for email_id in tqdm(reversed(id_list), desc='\nFetching your emails ', total=len(id_list)):
            _, email_data = con.fetch(email_id, '(RFC822)')
            # converts byte literal to string removing b''
            raw_email = email_data[0][1].decode("utf-8")
            email_msg = email.message_from_string(raw_email)
            extract_mail = re.findall(EMAIL_REGEX, email_msg['From'])[0]
            
            if is_contain_black_listed_sender(con, extract_mail, email_id):                         ## action 1
                continue
            
            if is_contain_unknown_contact(con, extract_mail, email_id):                             ## action 2
                continue
            
            is_offensive = False
            for part in email_msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue 

                file_type = part.get_content_type()
                if is_contain_forbidden_file_type(con, extract_mail, file_type, email_id):          ## action 3
                    is_offensive = True
                    break
                
                file_name = part.get_filename().split('.')[0]
                if is_file_contain_forbidden_words(con, extract_mail, email_id, file_name):         ## action 4
                    is_offensive = True
                    break

                file_data = part.get_payload(decode=True)
                if is_dangerous(con, file_data, extract_mail, email_id, part.get_filename()):                            ## action 5
                    is_offensive = True
                    break

            if is_offensive:
                continue 

            subject = email_msg['Subject']
            body = extract_email_body_message(email_msg)
            if is_mail_contain_forbidden_words(con, extract_mail, email_id, subject, body):         ## action 6
                continue

            # Email passed all validationד, add it to mailbox
            ans += '\n----------------------- ' \
                   '\nEmail From: {}' \
                   '\nEmail Subject: {}' \
                   '\nDate: {}' \
                   '\nBody: {}'.format(extract_mail, subject, ' '.join(email_msg['Date'].split()[:5]),
                                       body)
        time.sleep(1)
        if ans == '':
            print('\nFinished!\nNo new emails found')
        else:     
            print('\nFinished!\nYour Mailbox:{}'.format(ans).expandtabs(15))
    
    except Exception as e:
        print('DEBUG: read_mailbox() Failed: {} '.format(e))

    con.logout()

def extract_email_body_message(email_msg):
    body = ''
    if email_msg.is_multipart():
        for payload in email_msg.walk():
            if payload.get_content_type() == 'text/plain':
                body += payload.get_payload()
    elif email_msg.get_content_type() == 'text/plain':
        body = email_msg.get_payload()

    return body

def update_whitelist():
    print("\nYour current whitelisted contacts are:")
    handle_generic_list(whitelistedContacts, 1)

def update_blacklist():
    print("\nYour current blacklisted contacts are:")
    handle_generic_list(blacklistedContacts, 2)

def update_words():
    print("\nYour current forbidden words are:")
    handle_generic_list(badWordsArray, 3)

def update_file_types():
    print("\nYour current forbidden files are:")
    handle_generic_list(fileTypesArray, 4)

def handle_generic_list(lst, lst_id):
    # display choosen list
    i = 0
    for item in lst:
        print("[{}] {}".format(i, item))     
        i = i + 1

    print("\nWhat would you like to do with this list?\n"
          "[1] Remove an item from this list\n"
          "[2] Add an item to this list\n"
          "[3] Return to main menu")  

    while True:
        try:
            data = int(input())
            if data < 1 or data > 3:
                raise ValueError()
            else:
                break
        except ValueError:
            print("Error: Unkown option, please try again\n")     
            continue
        except KeyboardInterrupt:
            exit_system()        

    if data == 1:
        print("\nPlease provide the id of the item you want to remove\n"
            "[Note: Typing any negative number will cancel this operation]")       
        while True:
            try:
                j = int(input())
                if j < 0:
                    return
                elif j > i:
                    raise ValueError()     

                del lst[j]
                sheet.delete_rows(lst_id)
                sheet.insert_row(lst, lst_id)
                break
            except ValueError:
                print("Error: Please choose index in range\n")     
                continue
            except gspread.exceptions.GSpreadException:
                print("Error: Failed to update list, please try again later\n")     
                continue
            except KeyboardInterrupt:
                exit_system()   
    elif data == 2:
        print("\nPlease provide the item that you want to add\n")
        while True:
            try:
                item = input()
                lst.append(item)
                sheet.delete_rows(lst_id)
                sheet.insert_row(lst, lst_id)
                break
            except gspread.exceptions.GSpreadException:
                print("Error: Failed to update list, please try again later\n")
                continue
            except KeyboardInterrupt:
                exit_system() 
    else:   # data == 3, return to main menu
        return    

    print("Successfully updated list") 

def exit_system():
    sys.exit()

def command_handler():
    return {1: read_emails,
            2: update_whitelist,
            3: update_blacklist,
            4: update_words,
            5: update_file_types,
            6: exit_system
            }

def main_menu():
    while True:
        print("\nWhat would you like to do?\n"
              "[1] Read unread messages\n"
              "[2] Update whitelisted contacts\n"
              "[3] Update blacklisted contacts\n"
              "[4] Update forbidden words list\n"
              "[5] Update forbidden attachment files types list\n"
              "[6] Exit")
        while True:
            try:  
                prompt = int(input())
                if prompt > 0 and prompt < 7:    
                    command_handler().get(prompt)()
                    break
                else:
                   raise ValueError()
            except ValueError:
                print("Error: Please choose a valid option from menu\n")     
                continue
            except KeyboardInterrupt:
                exit_system()  

def login():
    global _userEmail, _password
    attempt = 0
    conn = IMAP4_SSL(IMAP_URL)
    while attempt < 2:
        try: 
            email = input("Email:")
            password = getpass.getpass()
            conn.login(email, password)
            # save globals
            _userEmail = email
            _password = password
            break
        except IMAP4_SSL.error: 
            print('Incorrect email or password, please try again')
            attempt = attempt + 1
        except KeyboardInterrupt:
            exit_system()    
    conn.logout()
    if attempt == 2:
        print('To many failed login attempts, exiting program ...')
        exit_system()

if __name__ == '__main__':
    login()
    main_menu()
