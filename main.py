import math
import time
import requests
import json
import email
import smtplib
import logging

from config import *
from datetime import datetime
from string import Template
from logging.handlers import TimedRotatingFileHandler

class VTIQuotaLimiter:

    def __init__(self, send_mail = False):
    
        self.deleted_users = self.load_file(DELETED_USERS, [])
        self.warned_users = self.load_file(WARNED_USERS, [])
        self.quota_conf = json.load(open(QUOTA_CONF, 'r'))
        self.logger = logging.getLogger("VTIQuotaLimiter")
        self.logger.setLevel(logging.INFO)
        handler = TimedRotatingFileHandler(LOG_FILE, when="d", interval=90)
        self.logger.addHandler(handler)
        self.group_id = GROUP_ID
        self.weeks_count = (datetime.now().day - 1) // 7 + 1
        self.base_url = f"https://www.virustotal.com/api/v3/groups/{self.group_id}/"
        if send_mail:
            self.company_name = COMPANY_NAME
            self.sender_name = SENDER_NAME
            self.sender_email = SENDER_EMAIL
            self.contact_email = CONTACT_EMAIL
            self.smtp_client = smtplib.SMTP(SMTP_HOST, SMTP_PORT, local_hostname=LOCAL_HOSTNAME)
        self.send_mail = send_mail
        self.users = self.list_group_users()


    def run(self):
        self.clean_deleted_user_list()
        if self.is_new_quota_period() and not self.was_ran_new_week(): # First days of the week needs to run once
            self.log_message("First run on first day of the week, reintegrating users that did not exceed their quota for the week.")
            self.add_users_back()
            self.reset_warned()
            open(RAN_THIS_WEEK, 'w').write(datetime.now().strftime("%Y-%m-%d"))
        warned = 0
        removed = 0
        for user in self.users:
            user_quota = self.get_user_quota(user['attributes']["email"])
            if self.remove_user_if_quota_exceeded(user, user_quota):
                removed += 1
            if self.warn_user_if_warn_quota_reached(user, user_quota):
                warned += 1
        self.log_message(f"Warned {warned} users and removed {removed} users from the group.")
        json.dump(self.deleted_users, open(DELETED_USERS, 'w'), indent=4)
        json.dump(self.warned_users, open(WARNED_USERS, 'w'), indent=4)


    def clean_deleted_user_list(self) -> None:
        cleaned_list = []
        for user in self.deleted_users:
            if not any(user['email'] == u['attributes']['email'] for u in self.users):
                cleaned_list.append(user)
            else:
                self.log_message(f"User {user['email']} is back in the group, removing him from the deleted list.")
        self.deleted_users = cleaned_list


    def get_user_quota(self, user_email: str) -> int:
        user_quota = self.quota_conf['intelligence_quota_weekly'].get(user_email)
        if user_quota is None:
            user_quota = self.quota_conf['default_intelligence_weekly_quota']
        return user_quota


    def was_ran_new_week(self) -> bool:
        try:
            last_first_day_run = open(RAN_THIS_WEEK, 'r').read()
        except FileNotFoundError:
            last_first_day_run = None
        today = datetime.now().strftime("%Y-%m-%d")
        if last_first_day_run == today:
            return True
        return False


    def reset_warned(self):
        open(WARNED_USERS, 'w').close()


    @staticmethod
    def load_file(file_path, default_value=None):
        try:
            return json.load(open(file_path, 'r'))
        except:
            return default_value

    @staticmethod
    def get_headers() -> dict:
        return {
            "x-apikey": API_KEY,
            "content-type": "application/json"
        }


    def log_message(self,message: str) -> None:
        self.logger.info(f'[{datetime.now()}]: {message}')


    @staticmethod
    def is_new_quota_period() -> bool:
        today = datetime.now()
        if ((today.day - 1) % 7) == 0:
            return True
        else:
            return False


    def list_group_users(self) -> list:
        header = self.get_headers()
        url = self.base_url + "users?limit=40"
        users = []
        response = requests.get(url, headers=header)
        while True:
            jres = response.json()
            users += jres["data"]
            if jres["links"].get("next"):
                response = requests.get(jres["links"]["next"], headers=header)
            else:
                break 
        return users


    def remove_user_from_group(self, user_id: str) -> bool:
        url = self.base_url + f"relationships/users/{user_id}"
        response = requests.delete(url, headers=self.get_headers())
        if response.status_code == 200:
            self.log_message(f"Removed user {user_id} from group {self.group_id}")
            return True
        elif response.status_code == 400:
            self.log_message(f"User {user_id} failed to be removed from {self.group_id}")
            return False
        else:
            error_msg = json.loads(response.text).get('error',{}).get('message','')
            self.log_message(
                f"Unexcepted status code {response.status_code} : User {user_id} failed to be removed from {self.group_id} with message {error_msg}")
            return False


    def add_users_back(self):
        self.log_message(f"{len(self.deleted_users)} users are currently removed from the group, checking if users should be reinstated.")
        deleted_users = []
        for user in self.deleted_users:
            user_quota = self.get_user_quota(user['email'])
            if not self.is_quota_exceeded(user['current_usage'], user_quota):
                if self.add_users_to_group(user['email'], GROUP_ID):
                    self.send_reintegrated_email(user['email'], self.weeks_count * user_quota, user['current_usage'])
                else:
                    deleted_users.append(user)
            else:
                deleted_users.append(user)
        self.log_message(f"{len(deleted_users)} users are still removed from the group.")
        self.deleted_users = deleted_users


    def add_users_to_group(self, user_email: str, group_id: str) -> bool:
        url = f"https://www.virustotal.com/api/v3/groups/{group_id}/relationships/users"
        payload = {"data": [{'id': user_email, 'type': 'user'}]}
        response = requests.post(url, headers=self.get_headers(), json=payload)
        if response.status_code == 200:
            self.log_message(f"Added user {user_email} to group {group_id}")
            return True
        else:
            error_msg = json.loads(response.text).get('error',{}).get('message','')
            self.log_message(
                f"Unexpected status code {response.status_code} : Failed to add user {user_email} to group {group_id} with message {error_msg}")
        return False


    def is_quota_exceeded(self, used, user_quota) -> bool:
        if used >= (self.weeks_count * user_quota):
            return True
        return False


    def is_warn_reached(self, used, user_quota) -> bool:
        if used >= WARN_LEVEL * (self.weeks_count * user_quota):
            return True
        return False


    def is_user_deleted(self, user_email: str) -> bool:
        return any(user_email == user["email"] for user in self.deleted_users)


    def warn_user_if_warn_quota_reached(self, user, user_quota):
        if self.is_warn_reached(user['attributes']['quotas']['intelligence_searches_monthly']['used'], user_quota):
            if not user['attributes']['email'] in self.warned_users and not self.is_user_deleted(user['attributes']['email']):
                self.log_message(
                    f"User {user['id']} with email {user['attributes']['email']} from group {GROUP_ID} WARNED"
                    f" -> exceeded quota of {WARN_LEVEL * (self.weeks_count * user_quota)}")
                
                self.warned_users.append(user['attributes']['email'])
                self.send_warn_email(
                    user['attributes']['email'],
                    user['attributes']['quotas']['intelligence_searches_monthly']['used'],
                    self.weeks_count * user_quota
                )
                return True
        return False


    def remove_user_if_quota_exceeded(self, user, user_quota) -> bool:
        if self.is_quota_exceeded(user['attributes']['quotas']['intelligence_searches_monthly']['used'], user_quota):
            self.log_message(
                f"User {user['id']} with email {user['attributes']['email']} from group {GROUP_ID} DELETED"
                f" -> exceeded quota of {(self.weeks_count * user_quota)}")
            
            self.deleted_users.append({
                'email': user['attributes']['email'],
                'current_usage': user['attributes']['quotas']['intelligence_searches_monthly']['used']
            })
            self.remove_user_from_group(user['id'])
            self.send_delete_email(
                user['attributes']['email'],
                user['attributes']['quotas']['intelligence_searches_monthly']['used'],
                self.weeks_count * user_quota
            )
            return True
        return False


    def send_reintegrated_email(self, email, current_quota, current_usage):
        if not self.send_mail:
            return
        mapping = {
            'to_email': email,
            'subject': f'[IMPORTANT] VirusTotal Enterprise - You have been reintegrated in {self.group_id}',
            'company_name': self.company_name,
            'sender_name': self.sender_name,
            'contact_email': self.contact_email,
            'current_quota': current_quota,
            'current_usage': current_usage
        }
        body_template = open('mail/reintegrated_template.txt', 'r').read()
        self.format_and_send_email(email, mapping, body_template)


    def send_delete_email(self, email, quota_used, quota_allowed):
        if not self.send_mail:
            return
        mapping = {
            'to_email': email,
            'subject': f'[IMPORTANT] VirusTotal Enterprise - You have been removed from {self.group_id}',
            'quota_used': quota_used,
            'quota_allowed': quota_allowed,
            'company_name': self.company_name,
            'sender_name': self.sender_name,
            'contact_email': self.contact_email,
        }
        body_template = open('mail/delete_template.txt', 'r').read()
        self.format_and_send_email(email, mapping, body_template)


    def send_warn_email(self, email, quota_used, quota_allowed):
        if not self.send_mail:
            return
        
        mapping = {
            'to_email': email,
            'subject': f'[WARNING] VirusTotal Enterprise - {self.group_id} Intelligence search quota usage > {math.floor(WARN_LEVEL * 100)}%',
            'warn_rate': math.floor(WARN_LEVEL * 100),
            'quota_used': quota_used,
            'quota_allowed': quota_allowed,
            'company_name': self.company_name,
            'sender_name': self.sender_name,
            'contact_email': self.contact_email,
        }
        body_template = open('mail/warn_template.txt', 'r').read()
        self.format_and_send_email(email, mapping, body_template)


    def format_and_send_email(self, user_email, mapping, body_template):
        message = email.message.EmailMessage()
        message.set_default_type("text/plain")
        src = Template(body_template)
        body = src.substitute(mapping)
        message.set_content(body)
        
        message["From"] = self.sender_email
        message["To"] = [user_email]
        message["cc"] = MAIL_CC
        message["Subject"] =  mapping['subject']
        
        try:
            self.smtp_client.send_message(message)
            self.log_message(f"Email sent to {user_email}")
        except Exception as e:
            self.log_message(f"ERROR: fail to send email to {user_email} --> ERROR: \"{e}\".")

def main():
    vti_quota_limiter = VTIQuotaLimiter(send_mail=SEND_MAIL)
    vti_quota_limiter.run()

if __name__ == "__main__":
    main()
