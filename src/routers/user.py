from fastapi import APIRouter,HTTPException
from database.database import SessionLocal
from src.models.user import User,OTP
from src.schemas.user import RegisterUserSchema,GetAllUserSchema,UpdateUserSchema
import uuid
from src.utils.user import find_same_email,find_same_username,pwd_context,send_email,get_token,pass_checker
import random


user_router = APIRouter()

db = SessionLocal()









@user_router.post("/register_user")
def register_user(user:RegisterUserSchema):
    """add the relevent conditions or steps

    1. same username valo data koie nakhyo to ???????
    2. same email valo data koie nakhyo to ???????"""

    new_user = User(
        id = str(uuid.uuid4()),
        username = user.username,
        email = user.email,
        password = pwd_context.hash(user.password)
    )

    find_minimum_one_entry = db.query(User).first()
    if find_minimum_one_entry:
        find_same_email(user.email)
        find_same_username(user.username)
   

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return "User Register Successfully now go for the verification"




@user_router.get("/get_all_users",response_model=list[GetAllUserSchema])
def get_all_users():
    """
    mare su badha jj user ni list aapavani ?
    na badha ni nai aapavani 
    to ?
    etala jj user ni aapavani list ke je is_active true hoi is_deleted false hoi and is_verified true hoi ha ke na ?
    
    """
    all_user_with_condition = db.query(User).filter(User.is_active == True, User.is_deleted == False, User.is_verified == True).all() 
    if not all_user_with_condition:
        raise HTTPException(status_code=400, detail="No user found")
    return all_user_with_condition




@user_router.get("/get_user/{user_id}", response_model=GetAllUserSchema)
def get_user(user_id:str):
    """
    1. to check whether the user exist with is_active == true is_deleted == False and is_verified == True
    2. if not then raise the exception
    3. if exist then return the user
    """

    find_user = db.query(User).filter(User.id == user_id,User.is_active == True , User.is_deleted == False , User.is_verified == True).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")

    return find_user




@user_router.patch("/update_user/{user_id}")
def update_user(user_id:str, user:UpdateUserSchema):
    """
    1. pela to mare gotavano ke user exist kare che ke nai 
    2. if jo karato hoi to thik baki exception raise karavanu right ?
    3. if same email valo data koie nakhyo to ???????
    4. if same username valo data koie nakhyo to ???????
    
    """

    find_user = db.query(User).filter(User.id == user_id,User.is_active == True , User.is_verified == True , User.is_deleted == False).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    new_userschema_without_none = user.model_dump(x=True)

    for key,value in new_userschema_without_none.items():
        if key == "password":
            setattr(find_user,key,pwd_context.hash(value))
        else:
            find_same_email(value)
            find_same_username(value)
            setattr(find_user,key,value)

    db.commit()
    db.refresh(find_user)
    
    return {"message":"user update successfully","data":find_user}




@user_router.delete("/delete_user/{user_id}",response_model=GetAllUserSchema)
def delete_user(user_id:str):
    """
    1. to check whether the user exist or not
    2. if not then raise the exception
    3. if exist then delete the user
    4. if already deleted then raise the exception
    """

    find_user = db.query(User).filter(User.id == user_id,User.is_active == True , User.is_verified == True ).first()

    if not find_user:
        raise HTTPException(status_code=400, detail="User not found")

    if find_user.is_deleted == True:
        raise HTTPException(status_code=400, detail="User already deleted")
    

  

    find_user.is_deleted = True
    find_user.is_active = False
    find_user.is_verified = False
    db.commit()
    db.refresh(find_user)

    return {"message":"user deleted successfully","data":find_user}



@user_router.post("/generate_otp")
def generate_otp(email:str):
    find_user_with_email = db.query(User).filter(User.email == email,User.is_active == True,User.is_verified == False , User.is_deleted == False).first()

    if not find_user_with_email:
        raise HTTPException(status_code=400, detail="User not found")
    
    random_otp = random.randint(1000,9999)
    print("---------------------------------------")
    print(random_otp)
    print("---------------------------------------")

    new_otp = OTP(
        id = str(uuid.uuid4()),
        user_id = find_user_with_email.id,
        email = find_user_with_email.email,
        otp = random_otp
    )

    send_email(find_user_with_email.email, "Test Email", f"Otp is {random_otp}")

    db.add(new_otp)
    db.commit()
    db.refresh(new_otp)
    return "OTP generated successfully"



@user_router.get("/verify_otp")
def verify_otp(email:str, otp:str):
    find_user_with_email = db.query(User).filter(User.email == email, User.is_active == True, User.is_verified == False, User.is_deleted == False).first()

    if not find_user_with_email:
        raise HTTPException(status_code=400, detail="User not found")

    find_otp = db.query(OTP).filter(OTP.email == email, OTP.otp == otp).first()

    if not find_otp:
        raise HTTPException(status_code=400, detail="OTP not found")

    find_user_with_email.is_verified = True
    db.delete(find_otp)
    db.commit()
    db.refresh(find_user_with_email)

    return "OTP verified successfully"



@user_router.get("/login_user")
def login_user(email:str, password:str):
    find_user_with_email = db.query(User).filter(User.email == email, User.is_active == True, User.is_verified == True, User.is_deleted == False).first()

    if not find_user_with_email:
        raise HTTPException(status_code=400, detail="User not found")

    pass_checker(password, find_user_with_email.password)
      
    access_token = get_token(find_user_with_email.id, find_user_with_email.username, find_user_with_email.email)

    return access_token






