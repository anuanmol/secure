import streamlit as st
import numpy as np
import pandas as pd 
from PIL import Image
import streamlit.components.v1 as components
import random 
import string
import hashlib
import os
from cryptography.fernet import Fernet

def main():

    st.title('Secure it !')
    st.write("\n")
    st.write("\n")

    html_temp = """
            <div>
            <p style="font-size:16px; color:grey">&copy;2020 Secure with Anmol</p>
            </div>
    """

    c1, c2= st.beta_columns(2)
    with c2:
        st.markdown('Encrypt/Hash')
        s1 = Image.open('sha.jpg')
        st.image(s1, width=300)
    with c1:
        st.markdown("Password generator")
        im = Image.open('thread-lock.jpeg')
        st.image(im, width=300)

    menu = ["-","Password","Hash","Encrypt/Decrypt"]
    choice = st.sidebar.selectbox(
        "Select",menu
    )

    st.sidebar.markdown(html_temp, unsafe_allow_html=True)

    if choice == "Password":
        st.title('Random Password generator')
        # im = Image.open('thread-lock.jpeg')
        # st.image(im)
        x = st.selectbox(
            'Enter the length of password: ',
            [5, 6, 7, 8, 9, 10]
        )

        st.header(
            'Select options to include'
        )
        st.write("\n")
        col1, col2, col3, col4 = st.beta_columns(4)
        with col1:
            a = st.checkbox(
                'A-Z'
            )
        with col2:
            b = st.checkbox(
                'a-z'
            )
        with col3:
            c = st.checkbox(
                '0-9'
            )
        with col4:
            d = st.checkbox(
                "#$%&'()*+,-./:;<=>?@[]^_`{|}~"
            )

        # computing random password
        
        def code(length = x):
            char = ''
            if a == True:
                char = string.ascii_uppercase
            if b == True:
                char = string.ascii_lowercase 
            if c == True:
                char = string.digits
            if d == True:
                char = string.punctuation
            if a == True and b == True:
                char = string.ascii_uppercase + string.ascii_lowercase
            if a == True and c == True:
                char = string.ascii_uppercase + string.digits
            if a == True and d == True:
                char = string.ascii_uppercase + string.punctuation
            if b == True and c == True:
                char = string.ascii_lowercase + string.digits
            if b == True and d == True:
                char = string.ascii_lowercase + string.punctuation
            if c == True and d == True:
                char = string.digits + string.punctuation
            if d == True and a == True and b == True:
                char = string.ascii_uppercase + string.punctuation + string.ascii_lowercase
            if c == True and a == True and b == True:
                char = string.ascii_uppercase + string.digits + string.ascii_lowercase
            if d == True and c == True and a == True and b == True:
                char = string.ascii_uppercase + string.digits + string.ascii_lowercase + string.punctuation
            return ''.join(random.choice(char) for x in range(length))
        
        pss = None
        try:
            pss = code()
        except IndexError:
            st.write("Cannot choose from an empty sequence")
        st.subheader(
            'Random password is:'
        )
        st.header(pss)



    elif choice == "Hash":
        st.title(
            'Generate hash'
        )
        sel = st.selectbox(
            'Select the type of input',
            ["-","Text", "Password"]
        )
        if sel == "Text":
            inp1 = st.text_input(
                'Enter text'
            )
            st.button('Hash')
            hinput1 = hashlib.sha256(inp1.encode())
            hashed_256 = hinput1.hexdigest()

            linput1 = hashlib.sha1(inp1.encode())
            hashed_1 = linput1.hexdigest()

            kinput1 = hashlib.md5(inp1.encode())
            md_hashed = kinput1.hexdigest()

            st.subheader(
                'Hash generated are'
            )
            r1, r2 = st.beta_columns(2)
            with r1:
                st.subheader('SHA-256')
            with r2:    
                st.subheader(hashed_256)

            r3, r4 = st.beta_columns(2)
            with r3:
                st.subheader('SHA-1')
            with r4:
                st.subheader(hashed_1)

            r5, r6 = st.beta_columns(2)
            with r5:
                st.subheader('MD5')
            with r6:
                st.subheader(md_hashed)

            

        elif sel == "Password":
            inp2 = st.text_input("Password:", value="", type="password")
            st.button('Hash')
            hinput2 = hashlib.sha256(inp2.encode())
            hashed2_256 = hinput2.hexdigest()

            linput2 = hashlib.sha1(inp2.encode())
            hashed2_1 = linput2.hexdigest()

            kinput2 = hashlib.md5(inp2.encode())
            md_hashed2 = kinput2.hexdigest()

            st.subheader(
                'Hash generated are'
            )
            r1, r2 = st.beta_columns(2)
            with r1:
                st.subheader('SHA-256')
            with r2:    
                st.subheader(hashed2_256)

            r3, r4 = st.beta_columns(2)
            with r3:
                st.subheader('SHA-1')
            with r4:
                st.subheader(hashed2_1)

            r5, r6 = st.beta_columns(2)
            with r5:
                st.subheader('MD5')
            with r6:
                st.subheader(md_hashed2)

    elif choice == "Encrypt/Decrypt":

        ed = st.selectbox(
            'Select for encryption/decryption',
            ["-","Encrypt","Decrypt"]
        )
        if ed == "Encrypt":
            en = st.text_input('Enter message :',type="password")
            st.button('Encrypt')
            key = Fernet.generate_key()
            # k = write_key
            #with open("secret.key","wb") as key_file:
            #key_file.write(key)
            
            mes = en.encode()
            f = Fernet(key)
            encrypted = f.encrypt(mes)
            #decrypted = f.decrypt(encrypted)

            r7, r8 = st.beta_columns(2)
            with r7:
                st.subheader("Encrypted message is")
            with r8:
                st.write(encrypted)

            r9, r10 = st.beta_columns(2)
            with r9:
                st.subheader("Encryption key is")
            with r10:
                st.write(key)
            # st.subheader(decrypted)

        if ed == "Decrypt":
            st.write("Will be added soon")
        

if __name__== "__main__":
    main()
