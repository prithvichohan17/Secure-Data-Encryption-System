from unittest import result
from altair import Key
import streamlit as st
import hashlib
import  json
import os 
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# == data infromation of user ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"

LOCKOUT_DURATUON = 60


# === section login details ===

if "authenticated_user" not in st.session_state:
    st.session_state.autenticated_user = None 

    
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = None 

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None 

# === if data is load ===
def load_data():
    if os .path.exists(DATA_FILE):
        with open (DATA_FILE,"r") as f:
            return  json.load(f)
    return {}

def save_data(data):
        with open (DATA_FILE,"w") as f:
            json.dump(data,f)

def generate_key(passkey):
            key = pbkdf2_hmac('sha256', passkey.encode(),SALT,100000)
            return urlsafe_b64encode(key)
        
def hash_password(password):
     return hashlib.pbkdf2_hmac('sha256',password.encode(), SALT,100000).hex()

# === cryptography.Fernet used ===
def encrypt_text(text,key):
     cipher = Fernet(generate_key(key))
     return cipher.encryp(text.encode()).decode()

def decrypt_text(encrypt_text):
     try:
          cipher = Fernet(generate_key(Key))
          return cipher.decrpyt(encrypt_text.encode()).decode()
     except:
            return None
stored_data = load_data()

# === navigation bar ===
st.title("🔐 secure Data Encryption")
menu =["Home","Register","Login","Store Data","Retrieve Data"]
choice = st.sidebar.selectbox("Navigaation", menu)

if choice == "Home":
     st.subheader("welcome To My 🔐 Data Encryption system Using stramlit")
     st.markdown("Develop a Streamlit-based secure data storage and retrieval system where:" \
     "Users store data with a unique passkey." \
     "Users decrypt data by providing the correct passkey." \
     "Multiple failed attempts result in a forced reauthorization (login page)." \
     "The system operates entirely in memory without external databases.")

     # === user registration ===
elif choice == "Register":
    st.subheader("✏️ Register New User")
    username = st.text_input("choose Username")
    password = st.text_input("choose pessword",type="password")

    if st.button("Register"):
        if username and password:
                if username in stored_data:
                    st.warning("⚠️ User already exisits.")
                else:
                    stored_data[username] = {
                         "password": hash_password,
                         "data": []
                    }
                    save_data(stored_data)
                    st.success("✅ User register successfully!")
        else:
             st.error("Both fields are required.")
    elif choice == "login":
        st.subheader("🔑 User-login")
         
        if time.time() <st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time -time.time())
            st.error(f"⏱️ Too many failed attempts. please wait {remaining} second.")
        else:
              username = st.text_input("Username")
              password = st.text_input("password", type="password")
             
        if st.button("login"):
            if username in stored_data and stored_data [username]["password"] == hash_password(password):
                  st.session_state.authenticated_user = username
                  st.session_state.failed_attempts = 0
                  st.success(f"✅ Welcome {"username"}!")
            else:
                st.success_state.failed_attempts += 1
                remaining  = 3 - st.seccess_state.failed_attempts 
                st.error(f"❌ Invaild Credentails! Attempls left: {remaining}")

                if st.session_state.failed_attempls >= 3:
                    st.seccion_state.lockout_time = time.time + LOCKOUT_DURATUON
                    st.error("🔴 To many failed attempls.locked for 60 seconds")
                    st.stop()

# === data store section 
elif choice == "Store Data":
    if  not st.seccion_state.authenticated_user:
        st.warning("🔐 please login frist.")
    else:
         st.subheader(" 📦Store Encrpyted Data ")
         data = st.text_area("Enter data to encrpty")
         passkey = st.text_input("Encryption key (passphrease)", type="password")

         if st.button("Encrypt And Save"):
                if data and passkey:
                    encryted = encrypt_text(data,passkey)
                    stored_data[st.session_state.authenticated_user]["data"].append(encryted)
                    save_data(stored_data)
                    st.success(" Data encrypted and save suessfully!")

                else:
                   st.error("All field are requried to fill.")

# === data retieve data secion ===
elif choice == "Retieve Data":
    if not st.session_state.authenticated_user:
          st.warning("please login frist")
        
    else:
        st.subheader("🔎 Retieve data")
        user_data = stored_data.get(st.session_state.authenicated_user,{}).get("data",[])

    if not user_data:
         st.info("No data Found!")
    else:
        st.write("Encryted Data Enteries:")
        for i, item in enumerate(user_data):
              st.code(item,language ="text")

        encrypted_input = st.text_area("Enter Encrypted Text")

        if st.button("Decrypt"):
             st.success(f"Decrypted: {result}")
        else:
             st.error("❌ Incorrect passkey or corrupted data.")
