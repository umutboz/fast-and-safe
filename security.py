#!/usr/bin/env python
# -*- coding: utf-8 -*-

############################################################
# Security
############################################################
# Author: Umut Boz
# Copyright (c) 2022, https://github.com/umutboz
# Email: umut.boz@outlook.com
############################################################
# Version: 1.0.0
############################################################


from datetime import datetime,  timedelta
from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Union


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "dd2863a75e2cec0435f6e1325019804b9eb4a1349f8de5dd129d6c7e6eb4b7e3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

auth_users_db = {
    "tester": {
        "username": "tester",
        "full_name": "Tester",
        "email": "tester@gmail.com",
        "hashed_password": "$2y$10$RvXxgJ2EBCGnGCiDnWIpmePpBVEXwwzdeQNSQ497Y4.S5t3O0WrDO",
        "disabled": False
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    print("enter verify_password")
    try:
        pwd_verify_context = pwd_context.verify(plain_password, hashed_password)
        print("pwd_verify_context: ", pwd_verify_context)
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        print("pwd_verify_context ", e)
        return None



def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(users_db, username: str, password: str):
    print("enter authenticate")
    user = get_user(users_db, username)
    print("enter authenticate", user.username)
    if not user:
        print('User not found')
        return False
    if not verify_password(password, user.hashed_password):
        print('Password is not correct')
        return False
    print('User is authenticated')
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(auth_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user