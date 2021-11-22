from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, Response
from flask_mail import Mail, Message
from app import db
from flask_login import login_user
from models import User, Contact
from flask_login import login_user, logout_user, login_required, current_user
from flask import Markup
from Crypto import Random
from Crypto.Cipher import AES
from werkzeug.utils import secure_filename
import os
import struct
import random
import binascii
import string
import os.path
import hashlib
import smtplib
import datetime
from resources import get_bucket, get_bucket_v2, get_buckets_list, create_s3_bucket
from app import app

auth = Blueprint('auth', __name__)
app_root = os.path.dirname(os.path.abspath(__file__))

app.config["MAIL_SERVER"]='smtp.gmail.com'  
app.config["MAIL_PORT"] = 465      
app.config["MAIL_USERNAME"] = 'your-email-id'  
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app) 

def decryption_file(key, filename, chunk_size=24*1024):
    output_filename = os.path.splitext(filename)[0]
    filesize = os.path.getsize(filename)
    print(filesize)
    with open(filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(output_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)
 
 
def encryption_file(key, filename, target, chunk_size=64*1024):

    newfile = os.path.split(filename)[1]
    output_filename = os.path.join(target, newfile + '.enc')

    iv = Random.new().read(AES.block_size)
    print(iv)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(filename)

    with open(filename, 'rb') as inputfile:
        with open(output_filename, 'wb') as outputfile:
            outputfile.write(struct.pack('<Q', filesize))
            outputfile.write(iv)
            while True:
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                outputfile.write(encryptor.encrypt(chunk))

@auth.route('/login')
def login():
    return render_template('home/login.html')

@auth.route('/signup')
def signup():
    return render_template('home/signup.html')

@auth.route('/contact', methods=['POST'])
def contact_post():
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    print(name, email, message)
    if(len(name)<=3 or len(email)<=5 or len(message)<=10):
        flash('Please enter all the fields.', 'info')
        return redirect(url_for('contact'))
    else:
        contact_msg = Contact(name=name, email=email, message=message)
        db.session.add(contact_msg)
        db.session.commit()   
        flash('Message has been successfully sent.', 'success')
    return redirect(url_for('contact'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index')) 

@auth.route('/signup',methods=['POST'])
def signup_post():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('pass')
    cpassword = request.form.get('passConf')
    print(name, email, password, cpassword)

    if(email == '' or name == '' or password == ''):
        flash('Please enter all the fields.', 'info')
        return redirect(url_for('auth.signup'))
    user = User.query.filter_by(email=email).first() 
    if(user):
        flash(Markup('Email address already exists. Please go to <a href="http://127.0.0.1:5000/login" class="alert-link">Login Page</a>'), 'link')
        return redirect(url_for('auth.signup'))
    otp = random.randint(100000,999999) 
    msg = Message('OTP Verification for Secure Cloud Storage Signup', sender = 'e-mail', recipients = [email])  
    msg.body = 'Your OTP for Signup Verification of Secure Cloud Storage (Valid for 5 mins) is: '+str(otp)+'\nPlease do not share with anyone!' 
    mail.send(msg)
    registered_on = datetime.datetime.now()
    new_user = User(email=email, name=name, otp=otp, registered_on=registered_on, password=generate_password_hash(password, method='sha256'),keydir="{}")
    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()   
    return redirect(url_for('auth.validate', email=email))

@auth.route('/validate/<email>',methods=["GET","POST"])  
def validate(email):   
    if(request.method == 'GET'):
        return render_template('home/validate.html', email=email)
    else:
        from app import current_user
        user = User.query.filter_by(email=email).first()
        otp = user.otp 
        user_otp = request.form['otpcode']
        if(user_otp == ''):
            flash('OTP field is left blank.', 'info')
            return redirect(url_for('auth.validate', email=email))
        if(str(otp) == user_otp): 
            c = datetime.datetime.now() - user.registered_on 
            if((c.total_seconds()/60) > 5):
                flash('Your OTP has expired!', 'danger')
                return redirect(url_for('auth.validate', email=email))
            else:
                user.verified = True
                uid = user.id
                uemail = user.email
                getEmail = uemail.split('@')[0]
                print(uid, uemail)
                user.bucket_name = 'id-' + str(uid) +'-'+ str(getEmail)
                print(user.bucket_name)
                res = create_s3_bucket(user.bucket_name)
                if (res):
                    flash('Your account has been created.', 'success')
                else:
                    flash('please try again creating your account', 'warning')
                db.session.commit()
                flash('Congrats! Your account has been Verified!', 'success')
                return redirect(url_for('auth.login'))
        flash('Please Enter the Correct OTP!', 'warning')
        return redirect(url_for('auth.validate', email=email))

@auth.route('/generate/<email>')
def generate(email): 
    user = User.query.filter_by(email=email).first()
    otp = random.randint(100000,999999) 
    msg = Message('OTP Verification for Secure Cloud Storage Signup', sender = 'your-email-id', recipients = [email])  
    msg.body = 'Your OTP for Signup Verification of Secure Cloud Storage (Valid for 5 mins) is: '+str(otp)+'\nPlease do not share with anyone!' 
    mail.send(msg)
    user.otp = otp
    user.registered_on = datetime.datetime.now()
    db.session.commit()
    flash('OTP has been resent', 'info')
    return redirect(url_for('auth.validate', email=email))

@auth.route('/passverify/<email>',methods=["GET","POST"])  
def passverify(email):   
    if(request.method == 'GET'):
        return render_template('home/passwordVerify.html', email=email)
    else:
        from app import current_user
        user = User.query.filter_by(email=email).first()
        otp = user.otp 
        user_otp = request.form['otpcode'] 
        if(user_otp == ''):
            flash('OTP field is left blank.', 'info')
            return redirect(url_for('auth.passverify', email=email))
        if(str(otp) == user_otp): 
            c = datetime.datetime.now() - user.registered_on 
            if((c.total_seconds()/60) > 5):
                flash('Your OTP has expired!', 'danger')
                return redirect(url_for('auth.passverify', email=email))
            else:
                user.verified = True
                db.session.commit()
                flash('Congrats! Your account has been Verified!')
                return redirect(url_for('auth.changepassword', email=email))
        flash('Please Enter the Correct OTP!', 'danger')
        return redirect(url_for('auth.passverify', email=email))

@auth.route('/generate1/<email>')  
def generate1(email): 
    user = User.query.filter_by(email=email).first()
    otp = random.randint(100000,999999) 
    msg = Message('OTP Verification for Secure Cloud Storage Signup', sender = 'your-email-id', recipients = [email])  
    msg.body = 'Your OTP for Signup Verification of Secure Cloud Storage (Valid for 5 mins) is: '+str(otp)+'\nPlease do not share with anyone!' 
    mail.send(msg)
    user.otp = otp
    user.registered_on = datetime.datetime.now()
    db.session.commit()
    flash('OTP has been resent', 'info')
    return redirect(url_for('auth.passverify', email=email))

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again!', 'danger')
        return redirect(url_for('auth.login'))
    if(user.verified!= True):
        flash('Please Verify your Email!', 'warning')
        return redirect(url_for('auth.validate', email=email))
    login_user(user, remember=remember)
    return redirect(url_for('auth.dashboard'))


@auth.route('/forgetpassword', methods=["GET","POST"])
def forgetPassword():
    if(request.method == 'GET'):
        return render_template('home/forgetPassword.html')
    else:
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        print(user)
        if(email == ''):
            flash('Email field is left blank.', 'danger')
            return redirect(url_for('auth.forgetPassword'))
        if(user):
        # user = User.query.filter_by(email=email).first()
            otp = random.randint(100000,999999) 
            msg = Message('OTP Verification for Secure Cloud Storage Signup', sender = 'your-email-id', recipients = [email])  
            msg.body = 'Your OTP for Signup Verification of Secure Cloud Storage (Valid for 5 mins) is: '+str(otp)+'\nPlease do not share with anyone!' 
            mail.send(msg)
            user.otp = otp
            user.registered_on = datetime.datetime.now()
            db.session.commit()
            flash('OTP has been sent', 'info')
            return redirect(url_for('auth.passverify', email=email))
        else:
            flash('Please enter a correct email.', 'danger')
            return redirect(url_for('auth.forgetPassword'))

@auth.route('/changepassword/<email>', methods=["GET", "POST"])
def changepassword(email):
    from app import current_user
    if(request.method == 'GET'):
        return render_template('home/changepassword.html')
    else:
        new_psw = request.form.get('newpass')
        con_psw = request.form.get('newpassConf')
        if(new_psw == '' or con_psw == ''):
            flash('Password field is left blank.', 'danger')
            return redirect(url_for('auth.changePasswd'))
        if(new_psw != con_psw):
            flash('Passwords do not match', 'danger')
            return redirect(url_for('auth.changePasswd'))
        passhash = generate_password_hash(new_psw, method='sha256')
        user = User.query.filter_by(email=email).first()
        user.password = passhash
        try:
            db.session.commit()
        except:
            flash('Technical error, failed to update', 'danger')
            return redirect(url_for('auth.changepassword'))
        flash('Successfully Updated!', 'success')
        return redirect(url_for('auth.login'))

    
@auth.route('/dashboard')
@login_required
def dashboard():
    files = get_bucket_v2()
    print(files)
    print(len(files))
    if len(files) == 0:
        return render_template('user/dashboard.html', name=current_user.name, files=files)
    else:
        return render_template('user/dashboard.html', name=current_user.name, files=files[:5])

@auth.route('/files')
@login_required
def files():
    my_bucket = get_bucket()
    summaries = my_bucket.objects.all()

    total_count = 0
    for key in summaries:
        total_count += 1
        if total_count == 1:
            break
    print(total_count)

    return render_template('user/files.html', files=summaries, obj_count=total_count)

@auth.route('/deleteaccount')
@login_required
def deleteAccount():
	return render_template('user/deleteAccount.html')

@auth.route('/settings')
@login_required
def account_set():
	return render_template('user/settings.html')

@auth.route('/changeemail', methods=["GET", "POST"])
@login_required
def changeEmail():
    from app import current_user
    if(request.method == 'GET'):
        return render_template('user/changeEmail.html')
    else:
        new_email = request.form.get('email')
        if(new_email == ''):
            flash('Email field is left blank.', 'info')
            return redirect(url_for('auth.changeEmail'))

        user = User.query.get_or_404(current_user.id)
        user.email = new_email
        try:
            db.session.commit()
        except:
            flash('Technical error, failed to update', 'danger')
            return redirect(url_for('auth.changeEmail'))
        flash('Successfully Updated!', 'success')
        return redirect(url_for('auth.changeEmail'))

@auth.route('/changepasswd', methods=["GET", "POST"])
@login_required
def changePasswd():
    from app import current_user
    if(request.method == 'GET'):
        return render_template('user/changePasswd.html')
    else:
        new_psw = request.form.get('newpass')
        con_psw = request.form.get('newpassConf')
        if(new_psw == '' or con_psw == ''):
            flash('Password field is left blank.', 'info')
            return redirect(url_for('auth.changePasswd'))
        if(new_psw != con_psw):
            flash('Passwords do not match', 'info')
            return redirect(url_for('auth.changePasswd'))
        passhash = generate_password_hash(new_psw, method='sha256')
        user = User.query.get_or_404(current_user.id)
        user.password = passhash
        try:
            db.session.commit()
        except:
            flash('Technical error, failed to update', 'danger')
            return redirect(url_for('auth.changePasswd'))
        flash('Successfully Updated!', 'success')
        return redirect(url_for('auth.changePasswd'))


@auth.route('/cancel account')
def cancel():
    from app import current_user
    if current_user is None:
        return redirect(url_for('index'))
    try:
        db.session.delete(current_user)
        db.session.commit()
    except:
        return 'unable to delete the user.'
    flash('Your account has been deleted', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/enc_upload', methods=['POST'])
@login_required
def enc_upload():
    from app import current_user
    user = User.query.get_or_404(current_user.id)
    source = os.path.join(app_root,'uploads')
    if(not os.path.exists(source)):
        os.makedirs(source)
    target = os.path.join(app_root, 'encrypted')
    if(not os.path.exists(target)):
        os.makedirs(target)
    print(source, target)
    file = request.files['file']
    if(file.filename==''):
        flash('No file selected', 'info')
    if(file):
        loc0 = os.path.join(source,file.filename)
        file.save(loc0)

        res = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 20))
        res1 = bytes(res, 'utf-8') 
        key = hashlib.sha256(res1).digest()

        encryption_file(key, loc0, target) # encrypts file
        loc = os.path.join(target,file.filename+".enc")
        print(loc)

        my_bucket = get_bucket()
        my_bucket.Object(file.filename+".enc").put(Body=open(loc,'rb'))

        source1 = os.path.join(app_root, 'keys')
        if(not os.path.exists(source1)):
            os.makedirs(source1)
        source2 = os.path.join(source1, file.filename+".enc key.txt")
        keydir = eval(user.keydir)
        keydir[file.filename+".enc"] = key
        user.keydir = str(keydir)
        db.session.commit()
        with open(source2, "w") as file1:    
            file1.write(res)
        file1.close()
        flash('File uploaded successfully', 'success')
        return send_file(source2, as_attachment=True)
    return redirect(url_for('auth.files'))

@auth.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files['file']
    if(file.filename==''):
        flash('No file selected', 'info')
    if(file):
        my_bucket = get_bucket()
        my_bucket.Object(file.filename).put(Body=file)
        flash('File uploaded successfully', 'success')
    return redirect(url_for('auth.files'))

@auth.route('/delete', methods=['POST'])
@login_required
def delete():
    key = request.form['key']
    my_bucket = get_bucket()
    my_bucket.Object(key).delete()
    page_val = request.form['delFile']
    if(page_val=='dashboard'):
        flash('File deleted successfully', 'success')
        return redirect(url_for('auth.dashboard'))
    elif(page_val=='fileVal'):
        flash('File deleted successfully', 'success')
        return redirect(url_for('auth.files'))


@auth.route('/download', methods=['POST'])
@login_required
def download():
    from app import current_user
    user = User.query.get_or_404(current_user.id)
    key = request.form['key']
    print(key)
    if('.enc' == key[-4:]):
        user.download = key
        db.session.commit()
        return redirect(url_for('auth.downloadFile', filename=key))
    elif('.enc' != key[-4:]):
        my_bucket = get_bucket()
        file_obj = my_bucket.Object(key).get()
        flash('File Downloaded Successsfully', 'success')
        
        return Response(
        file_obj['Body'].read(),
        mimetype='text/plain',
        headers={"Content-Disposition": "attachment;filename={}".format(key)}
        )

@auth.route('/downloadfile/<filename>')
@login_required
def downloadFile(filename):
    return render_template('user/downloadFile.html', filename=filename)

@auth.route('/downloadFile/<filename>', methods=['POST'])
@login_required
def downloadFile_post(filename):
    from app import current_user
    seckey = request.form['seckey']
    seckey = bytes(seckey, 'utf-8') 
    seckey = hashlib.sha256(seckey).digest()
    user = User.query.get_or_404(current_user.id)
    key = user.download # filename
    keydir = eval(user.keydir)
    source = os.path.join(app_root,'uploads')

    target = os.path.join(app_root, 'downloads')
    if(not os.path.exists(target)):
        os.makedirs(target)

    downloadfile  = os.path.join(target, filename)
    my_bucket = get_bucket()
    my_bucket.download_file(filename, downloadfile)
    
    loc = os.path.join(target, filename)
    decryption_file(seckey, loc)

    if(keydir[key]==seckey):
        loc0 = os.path.join(target,key[:-4])
        flash('File Successfully downloaded', 'success')
        return send_file(loc0, as_attachment=True)
    else:
        flash('Please Enter the Correct Key', 'danger')
        return redirect(url_for('auth.downloadFile', filename=filename))
    

@auth.route('/key/<filename>', methods=["GET", "POST"])
@login_required
def forgotKey(filename):
    if(request.method == 'GET'):
        return render_template('user/forgetKey.html', filename=filename) 
    else:
        password = request.form.get('password')
        from app import current_user

        if(password == ''):
            flash('Password field is left blank.', 'info')
            return redirect(url_for('auth.forgotKey', filename=filename))
        user = User.query.get_or_404(current_user.id)

        if check_password_hash(user.password, password):
            keydir = eval(user.keydir)
            print(keydir)
            if filename in keydir:
                val = keydir[filename]
                source = os.path.join(app_root,'keys')
                loc0 = os.path.join(source, filename + " key.txt")
                flash('Key send Successfully', 'success')
                return send_file(loc0, as_attachment=True)

            flash('password match', 'success')
            return redirect(url_for('auth.forgotKey', filename=filename))
        else:
            flash('Incorrect Password, enter again', 'danger')
            return redirect(url_for('auth.forgotKey', filename=filename))


        
        
        



