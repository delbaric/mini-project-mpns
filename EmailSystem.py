import imaplib
import email
import sys
import re
import time
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from tqdm import tqdm

# Set Globals
_user = 'minimpns@gmail.com'
_password = 'linor!@#'
_imap_url = 'imap.gmail.com'
EMAIL_REGEX = '([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'

# Database
scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
creds = ServiceAccountCredentials.from_json_keyfile_name('client_secret.json', scope)
client = gspread.authorize(creds)
sheet = client.open('database').sheet1
whitelistedContacts = sheet.row_values(1)
blacklistedContacts = sheet.row_values(2)
badWordsArray = sheet.row_values(3)
fileTypesArray = sheet.row_values(4)


def read_emails(con):
    con = imaplib.IMAP4_SSL(_imap_url)
    con.login(_user, _password)

    try:
        con.select('Inbox')
        _, data = con.search(None, 'ALL')
        mail_ids = data[0]
        id_list = mail_ids.split()
        ans = ''
        if len(id_list) == 0:
            print("No emails found - can not perform Read on an empty mailbox")
            return
        for email_id in tqdm(reversed(id_list), desc='fetching your emails\n', total=len(id_list)):
            _, email_data = con.fetch(email_id, '(RFC822)')
            # converts byte literal to string removing b''
            raw_email = email_data[0][1].decode("utf-8")
            email_msg = email.message_from_string(raw_email)
            extract_mail = re.findall(EMAIL_REGEX, email_msg['From'])[0]
            if extract_mail in blacklistedContacts:
                print("\n---> System filtered-out an email from {}. Reason: blacklisted contact\n".
                      format(extract_mail))
                con.store(email_id, '+FLAGS', '\\Deleted')
                con.expunge()
                continue
            if extract_mail not in whitelistedContacts:
                print("\n---> You have email from: {} , which is not a known contact.\n"
                      "How would you like to handle this?\n"
                      "[1] Delete this message, no further actions\n"
                      "[2] Delete this message and add this person to blacklist\n"
                      "[3] Accept this message, no further actions\n"
                      "[4] Accept this message and add this person to whitelist\n".
                      format(extract_mail))
                choice = input()
                if choice == '1 || 2':
                    con.store(email_id, '+FLAGS', '\\Deleted')
                    con.expunge()
                    if choice == '2':
                        blacklistedContacts.append(extract_mail)
                        sheet.delete_row(2)
                        sheet.insert_row(blacklistedContacts, 2)
                    continue
                if choice == '4':
                    whitelistedContacts.append(extract_mail)
                    sheet.delete_row(1)
                    sheet.insert_row(whitelistedContacts, 1)
            for part in email_msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue
                file_type = part.get_content_type()
                if file_type in fileTypesArray:
                    con.store(email_id, '+FLAGS', '\\Deleted')
                    con.expunge()
                    print("\n---> System filtered-out an email from {}. Reason: forbidden attachment file type {}\n".
                          format(extract_mail, file_type))
                    continue
            body = extract_email_body_message(email_msg)
            subject = email_msg['Subject']
            body_as_array = list(body.split(" "))
            subject_as_array = list(subject.split(" "))
            mail_as_words = body_as_array + subject_as_array
            length = len(mail_as_words)
            i = 0
            detected = False
            while not detected and i < length:
                word = mail_as_words[i]
                if word in badWordsArray:
                    con.store(email_id, '+FLAGS', '\\Deleted')
                    con.expunge()
                    print("\n---> System filtered-out an email from {}. Reason: forbidden word detected: '{}'\n".
                          format(extract_mail, word))
                    detected = True
                i = i + 1
            if detected:
                continue

            ans += 'Email From: {}\n' \
                   'Email Subject: {}\n' \
                   'Date: {}\n' \
                   'Body: {}\n'.format(extract_mail, subject, ' '.join(email_msg['Date'].split()[:5]),
                                       body)
        time.sleep(1)
        print('\tYour mailbox:\n\n{}'.format(ans).expandtabs(15))
    except Exception as e:
        print('DEBUG: read_mailbox() Failed: {} '.format(e))

    con.logout()


def extract_email_body_message(email_msg):
    body = ''
    if email_msg.is_multipart():
        for payload in email_msg.get_payload():
            if payload.get_content_type() == 'text/plain':
                body += payload.get_payload()
    elif email_msg.get_content_type() == 'text/plain':
        body = email_msg.get_payload()

    return body


def update_whitelist():
    print("Your current whitelisted contacts are: \n")
    handle_generic_list(whitelistedContacts, 1)


def update_blacklist():
    print("Your current blacklisted contacts are: \n")
    handle_generic_list(blacklistedContacts, 2)


def update_words():
    print("Your current whitelisted contacts are: \n")
    handle_generic_list(badWordsArray, 3)


def update_file_types():
    print("Your current whitelisted contacts are: \n")
    handle_generic_list(fileTypesArray, 4)


def handle_generic_list(lst, lst_id):
    i = 0
    for item in lst:
        print("[{}] {}\n".format(i, item))
        i = i + 1
    print("What would you like to do with this list?\n"
          "[1] remove an item from this list\n"
          "[2] add an item to this list")
    if input() == '1':
        print("please provide the id of the item you want to remove")
        i = input()
        del lst[int(i)]
        sheet.delete_row(lst_id)
        sheet.insert_row(lst, lst_id)
    else:
        print("please provide the item that you want to add")
        item = input()
        lst.append(item)
        sheet.delete_row(lst_id)
        sheet.insert_row(lst, lst_id)
    print("Successfully updated list")


def exit_system():
    sys.exit()


def command_handler():
    return {'1': read_emails,
            '2': update_whitelist,
            '3': update_blacklist,
            '4': update_words,
            '5': update_file_types,
            '6': exit_system
            }


def ui():
    while True:
        print("What would you like to do?\n"
              "[1] read\n"
              "[2] update whitelisted contacts\n"
              "[3] update blacklisted contacts\n"
              "[4] update forbidden words list\n"
              "[5] update forbidden attachment files types list\n"
              "[6] exit")
        prompt = input()
        command_handler().get(prompt)()


if __name__ == '__main__':
    ui()
