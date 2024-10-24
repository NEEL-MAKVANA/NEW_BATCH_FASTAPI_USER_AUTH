from database.database import SessionLocal
from src.models.user import User
from fastapi import HTTPException
from passlib.context import CryptContext

db=SessionLocal()




def find_same_email(email:str):
    find_same_email = db.query(User).filter(User.email == email).first()
    

    if find_same_email:
        if find_same_email.is_active == True:
            raise HTTPException(status_code=400, detail="Email already exists")
        if find_same_email.is_active == False:
            raise HTTPException(status_code=400, detail="Email already exist but this account is deleted try with different email")





def find_same_username(username:str):
    find_same_username = db.query(User).filter(User.username == username and User.is_active==True).first()

    if find_same_username:
        if find_same_username.is_active == True:
            raise HTTPException(status_code=400, detail="Username already exists")
        if find_same_username.is_active == False:
            raise HTTPException(status_code=400, detail="Username already exists but this account is deleted try with different username")





# -------------------- CREATE A PASSLIB CONTEXT ----------------#
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ----------------- CHECK WHETHER THE HASH PASSWORD AND USER ENTERED PASSWORD IS SAME OR NOT? -------------#
def pass_checker(user_pass, hash_pass):
    if pwd_context.verify(user_pass, hash_pass):
        return True
    else:
        raise HTTPException(status_code=401, detail="Password is incorrect")









import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import SENDER_EMAIL,EMAIL_PASSWORD

def send_email(receiver, subject, body):

    # SMTP Configuration (for Gmail)
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = SENDER_EMAIL
    smtp_pass = EMAIL_PASSWORD

    #build the mail system to send someone
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = receiver
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    #now try to send the mail to receiver 

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(SENDER_EMAIL, receiver, msg.as_string())
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error: {e}")





from config import SECRET_KEY,ALGORITHM
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import HTTPException, status


def get_token(id:str,username: str, email: str):

    payload = {
        "id": id,
        "username": username,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=30),  # Expiration claim
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token}



def decode_token(token: str):
    try:
        # This will throw an ExpiredSignatureError if the token has expired
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id = payload.get("id")
        email = payload.get("email")
        username = payload.get("username")
        if not id or not username or not email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid token",
            )
        return id , username , email
    
    except jwt.ExpiredSignatureError:
        # Token has expired
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        # Any other token-related error
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token",
        )




