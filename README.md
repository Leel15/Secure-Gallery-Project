# 🔐 Secure Gallery Project

## Overview
**Secure Gallery** is a Python-based application designed to protect user photos using **AES encryption**.  
The system ensures that all uploaded images remain **private, encrypted, and secure**, while providing a **smooth and intuitive user experience**.  
It combines **security**, **usability**, and **modern design** to create a safe space for users to store and view their personal photos.

---

## Objective

The main goal of this project is to develop a **secure photo gallery system** that:

- Protects user data confidentiality through AES encryption.  
- Allows users to upload, encrypt, store, and decrypt their photos safely.  
- Provides a simple and user-friendly interface for authentication and photo management.  

---

## Key Features

- User Interface
Simple and modern design, Easy navigation between **Login**, **Register**, **Upload**, and **Gallery** windows.  

- User Authentication
Secure login and registration system with password validation, Prevents unauthorized access to encrypted photos.  

- Photo Upload & Storage
Users can upload images from their local device, Each uploaded image is automatically **encrypted using AES** before being stored locally.  

- AES Encryption & Decryption
**AES (Advanced Encryption Standard)** is implemented to protect image files, Only authenticated users can decrypt and view their photos.  

- Secure Retrieval
Decrypted images are displayed **temporarily** during the active session, All images remain encrypted in storage to ensure privacy.  
