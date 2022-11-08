#!/usr/bin/env python
# -*- coding: utf-8 -*-

############################################################
# Enums
############################################################
# Author: Umut Boz
# Copyright (c) 2022, https://github.com/umutboz
# Email: umut.boz@outlook.com
############################################################
# Version: 0.1.0
############################################################


from fastapi import Depends, FastAPI
import uvicorn
from datetime import datetime, timedelta
from fastapi import FastAPI, Header, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from starlette.responses import Response
from security import authenticate_user, auth_users_db, ACCESS_TOKEN_EXPIRE_MINUTES
from security import Token, User, create_access_token, get_current_active_user


app = FastAPI()


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if not form_data:
        print("?",form_data.username, form_data.password)
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response
    try:
        print("!",form_data.username, form_data.password)
        user = authenticate_user(auth_users_db, form_data.username, form_data.password)
        if not user:
            print("!",form_data.username, form_data.password)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

    except:
        print("! exception", form_data.username, form_data.password)
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response



@app.get("/")
def root():
    return {"message": "Welcome to Test App for Security"}


@app.get("/search")
async def search(query:str, current_user: User = Depends(get_current_active_user)):
    if query == "apple":
        return {"message": "found apple in search"}
    else:
        return {"message": query + " not found in search"}



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)

