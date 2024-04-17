from flask import Flask, render_template, request, redirect, session, jsonify, abort
from email.message import EmailMessage
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from dateutil import tz
import email, smtplib, imaplib, binascii, datetime, os

app = Flask(__name__)

app.secret_key = os.urandom(24)

logged_in = False
smtp_server = 'smtp.gmail.com'
imap_server = 'imap.gmail.com'

def encrypt_message(message, key):
    cipher = Blowfish.new(key.encode(), Blowfish.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), Blowfish.block_size))
    iv = cipher.iv
    ciphertext = (binascii.hexlify(ciphertext).decode())
    iv = (binascii.hexlify(iv).decode())

    return (ciphertext, iv)

def decrypt_message(ciphertext, iv, key):
    ciphertext = (binascii.unhexlify(ciphertext.encode()))
    iv = (binascii.unhexlify(iv.encode()))
    cipher = Blowfish.new(key.encode(), Blowfish.MODE_CBC, iv=iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), Blowfish.block_size).decode()
    return decrypted_message

@app.route('/')
def index():
    try:
        if session['logged_in'] != True:
            return render_template('main.html')
        else:
            return render_template('main2.html', username=session['username'], server=session['mail'])
    except:
        return render_template('main.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    status = 1
    if request.method == 'POST':
        user_srv = request.form['username'].split('@')
        username = user_srv[0]
        password = request.form['password']

        session['server_smtp'] = smtp_server
        session['server_imap'] = imap_server
        session['mail'] = user_srv[1]
        session['username'] = username
        session['password'] = password
        try:
            if check_auth(username, password) == True:
                session['logged_in'] = True
                return redirect('/')
            else:
                status = 0
        except:
                status = 0

    return render_template('login.html', status=status)

def check_auth(user, passwd):
    global smtp_con

    try:
        smtp_con = smtplib.SMTP_SSL(session['server_smtp'])
        if smtp_con.login(user, passwd):
            return True
        else:
            return False
    except:
        return False

@app.route('/logout')
def logout():
    try:
        session.clear()
        smtp_con.quit()
        imap_con.logout()
        return redirect('/login')
    except:
        session.clear()
        return redirect('/login')

@app.route('/send_email', methods=['GET', 'POST'])
def send_email():
    global smtp_con
    status = None

    try:
        if session['logged_in'] != True:
            return redirect('/login')
    except:
        return 'Something went wrong. Please try again later.'

    try:
        if request.method == 'POST':

            smtp_con = smtplib.SMTP_SSL(session['server_smtp'])
            smtp_con.login(session['username'], session['password'])

            # Get the form data from the request
            sender = request.form['sender']
            recipient = request.form['recipient']
            subject = request.form['subject']
            message = request.form['message']
            key = request.form['key']

            # Create the message object and set its headers
            message_obj = EmailMessage()
            message_obj['From'] = sender
            message_obj['To'] = recipient
            message_obj['Subject'] = subject
            now = datetime.datetime.now(tz=tz.gettz('Asia/Jakarta'))
            tz_info = now.strftime('%Z')
            tz_offset = now.strftime('%z')
            
            message_obj['Date'] = now.strftime("%a, %d %b %Y %H:%M:%S {} {}".format(tz_offset, tz_info))

            if request.form.get('encrypt'):
                cipher,iv = encrypt_message(message, key)
                message = "---Encrypted---\n" + cipher + iv
                
            message_obj.set_content(message)

            # Send the message
            try:
                smtp_con.send_message(message_obj)
                status = 1
            except:
                status = 0

    except Exception as e:
        return f'Error sending email: {e}'

    return render_template('send_email.html', username=session['username'], server=session['mail'], status=status)

def get_email():
    global imap_con

    try:
         imap_con = imaplib.IMAP4_SSL(session['server_imap'])
         imap_con.login(session['username'], session['password'])

         # Select inbox folder
         imap_con.select('inbox')

         # Search for all messages in the inbox
         _, message_numbers = imap_con.search(None, 'ALL')
         message_numbers = message_numbers[0].split()[:-10:-1]

         messages = []
         # Get all messages details and store in a list of dictionary
         for message_number in message_numbers:
              _, message_data = imap_con.fetch(message_number, '(RFC822)')
              raw_message = email.message_from_bytes(message_data[0][1])
              message_id = int(message_number)

              message = {
                   'id': message_id,
                   'status': '',
                   'sender': raw_message['From'],
                   'subject': f"Subject: {raw_message['Subject']}",
                   'date': raw_message['Date'],
                   'body': '',
              }

              if raw_message.is_multipart():
                   for part in raw_message.walk():
                        content_type = part.get_content_type()
                        if content_type == 'text/plain':
                             message['body'] = part.get_payload(decode=True).decode('utf-8')
              else:
                   message['body'] = raw_message.get_payload(decode=True).decode('utf-8')

              if message['body'].split()[0] == '---Encrypted---':
                   message['status'] = 'Encrypted'
              else:
                   message['status'] = 'Unencrypted'

              messages.append(message)

         return messages

    except:
         return "Failed to fetch inboxes"

@app.route('/inbox', methods=['GET', 'POST'])
def inbox():
    try:
        if session['logged_in'] != True:
            return redirect('/login')
        mail = get_email()
        emails = mail
    except:
        return 'Something went wrong. Please try again later.'

    if request.method == 'POST':
        message_id = request.form['messageId']
        key = request.form['key']
        try:
            if session['logged_in'] != True:
                return redirect('/login')
            for i in range(len(emails)):
                if emails[i]['id'] == int(message_id):
                    cipher_len = len(emails[i]['body'].split()[1])
                    cipher = emails[i]['body'].split()[1][:cipher_len-16]
                    iv = emails[i]['body'].split()[1][cipher_len-16::]
                    emails[i]['body'] = decrypt_message(cipher, iv, key)
                    emails[i]['status'] = 'Decrypted'
                    return jsonify({'body': emails[i]['body']})

        except Exception as e:
            return abort(403, "Bad Request: Decryption failed")

    return render_template('inbox.html', username=session['username'], messages=emails)

@app.route('/delete_email', methods=['POST'])
def delete_email():
    try:
        if session['logged_in'] != True:
            return redirect('/login')

        if request.method == 'POST':
            mail_ids = request.form.getlist('mail-id[]')

            # Connect to the IMAP server
            imap_con = imaplib.IMAP4_SSL(session['server_imap'])
            imap_con.login(session['username'], session['password'])

            # Select the inbox folder
            imap_con.select('inbox')

            # Mark the messages as deleted
            for mail_id in mail_ids:
                imap_con.store(str(mail_id), '+FLAGS', '\\Deleted')
            imap_con.expunge()

            return jsonify({'success': 1})
    except:
        return 'Failed to delete the email'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
