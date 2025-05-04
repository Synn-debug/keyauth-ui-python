import customtkinter as ctk
import tkinter.messagebox as messagebox
from datetime import datetime
import json
import os
import hashlib
from keyauth import api
import sys
import requests
from authentication import *

def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest

keyauthapp = api(
    name="",
    ownerid="",
    secret="",
    version="1.0",
    hash_to_check=getchecksum()
)

# Read Discord webhook from config
if os.path.exists("config.json"):
    with open("config.json") as f:
        config = json.load(f)
        webhook_url = config.get("webhook", "")
else:
    webhook_url = ""

# Send webhook log
def send_webhook_log(event, username=None, password=None, key=None, success=True, error_message=None):
    if not webhook_url:
        return

    fields = []

    if username:
        fields.append({"name": "Username", "value": username, "inline": False})
    if password:
        fields.append({"name": "Password", "value": password, "inline": False})
    if key:
        fields.append({"name": "License Key", "value": key, "inline": False})
    if error_message:
        fields.append({"name": "Error", "value": error_message, "inline": False})

    payload = {
        "username": "Loader Logger",
        "embeds": [
            {
                "title": f"{event} {'Success' if success else 'Failure'}",
                "color": 3066993 if success else 15158332,
                "fields": fields,
                "footer": {"text": "Loader Logs"},
            }
        ],
    }

    try:
        requests.post(webhook_url, json=payload)
    except Exception:
        pass

# GUI Setup
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")
root = ctk.CTk()
root.title("KeyAuth Loader")
root.geometry("500x500")

# Functions
def get_subscription_info():
    subscriptions = keyauthapp.user_data.subscriptions
    if not subscriptions:
        return "N/A", "N/A"
    expiry_timestamp = int(subscriptions[0]["expiry"])
    expiry_datetime = datetime.utcfromtimestamp(expiry_timestamp)
    formatted_expiration = expiry_datetime.strftime("%Y-%m-%d %H:%M:%S UTC")
    days_remaining = (expiry_datetime - datetime.utcnow()).days
    return formatted_expiration, days_remaining

def license_user():
    license_key = entry_license.get()
    if not license_key:
        messagebox.showerror("Error", "Please enter a license key.")
        return
    try:
        keyauthapp.license(license_key)
        formatted_expiration, days_remaining = get_subscription_info()
        expiration_label.configure(text=f"Key Expiration: {formatted_expiration} ({days_remaining} days left)")
        send_webhook_log(event="License Auth", key=license_key, success=True)
        messagebox.showinfo("License Success", "License authentication successful.")
    except Exception as e:
        send_webhook_log(event="License Auth", key=license_key, success=False, error_message=str(e))
        messagebox.showerror("License Failed", str(e))

def login_user():
    username = entry_username.get()
    password = entry_password.get()
    code = entry_2fa.get()
    if not username or not password:
        messagebox.showerror("Error", "Please enter both username and password.")
        return
    try:
        keyauthapp.login(username, password, code)
        formatted_expiration, days_remaining = get_subscription_info()
        expiration_label.configure(text=f"Key Expiration: {formatted_expiration} ({days_remaining} days left)")
        send_webhook_log(event="Login", username=username, password=password, success=True)
        messagebox.showinfo("Login Success", f"Welcome {username}!")
    except Exception as e:
        send_webhook_log(event="Login", username=username, password=password, success=False, error_message=str(e))
        messagebox.showerror("Login Failed", str(e))

def register_user():
    username = entry_username.get()
    password = entry_password.get()
    license_key = entry_license.get()
    if not username or not password or not license_key:
        messagebox.showerror("Error", "Please fill out all fields.")
        return
    try:
        keyauthapp.register(username, password, license_key)
        formatted_expiration, days_remaining = get_subscription_info()
        expiration_label.configure(text=f"Key Expiration: {formatted_expiration} ({days_remaining} days left)")
        send_webhook_log(event="Register", username=username, password=password, key=license_key, success=True)
        messagebox.showinfo("Register Success", f"Welcome {username}!")
    except Exception as e:
        send_webhook_log(event="Register", username=username, password=password, key=license_key, success=False, error_message=str(e))
        messagebox.showerror("Register Failed", str(e))

def upgrade_user():
    username = entry_username.get()
    license_key = entry_license.get()
    if not username or not license_key:
        messagebox.showerror("Error", "Please enter both username and license.")
        return
    try:
        keyauthapp.upgrade(username, license_key)
        send_webhook_log(event="Upgrade", username=username, key=license_key, success=True)
        messagebox.showinfo("Upgrade Success", f"{username} upgraded successfully.")
    except Exception as e:
        send_webhook_log(event="Upgrade", username=username, key=license_key, success=False, error_message=str(e))
        messagebox.showerror("Upgrade Failed", str(e))

# Widgets
title_label = ctk.CTkLabel(root, text="KeyAuth Loader", font=("Arial", 24))
title_label.pack(pady=20)

entry_username = ctk.CTkEntry(root, placeholder_text="Username")
entry_username.pack(pady=5)

entry_password = ctk.CTkEntry(root, placeholder_text="Password", show="*")
entry_password.pack(pady=5)

entry_2fa = ctk.CTkEntry(root, placeholder_text="2FA Code (optional)")
entry_2fa.pack(pady=5)

entry_license = ctk.CTkEntry(root, placeholder_text="License Key")
entry_license.pack(pady=5)

login_button = ctk.CTkButton(root, text="Login", command=login_user)
login_button.pack(pady=5)

register_button = ctk.CTkButton(root, text="Register", command=register_user)
register_button.pack(pady=5)

upgrade_button = ctk.CTkButton(root, text="Upgrade", command=upgrade_user)
upgrade_button.pack(pady=5)

license_button = ctk.CTkButton(root, text="License", command=license_user)
license_button.pack(pady=5)

expiration_label = ctk.CTkLabel(root, text="")
expiration_label.pack(pady=20)

root.mainloop()
