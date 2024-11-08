#!/usr/bin/env python

import boto3
import json
import os
from botocore.exceptions import ClientError

def get_secret(secret_name, region_name):
    client = boto3.client('secretsmanager', region_name=region_name)
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret = response['SecretString']
        return secret
    except ClientError as e:
        print(f"Error retrieving secret: {e}")
        return None

def get_instances(region, tag_key, tag_value):
    ec2_client = boto3.client('ec2', region_name=region)
    instances = ec2_client.describe_instances(
        Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]
    )
    return instances['Reservations']

def save_ssh_key(ssh_key_content, key_path):
    try:
        with open(key_path, 'w') as f:
            f.write(ssh_key_content)
        os.chmod(key_path, 0o600)  
    except Exception as e:
        print(f"Error saving SSH key: {e}")

def create_inventory():
    inventory = {
        "all": {
            "hosts": {}
        }
    }
    
    region = "ap-south-1"  #
    
    linux_instances = get_instances(region, "Name", "linux-sysinfo")
    windows_instances = get_instances(region, "Name", "windows-sysinfo")
    
    linux_secret = get_secret("linux-ssh-key", region)  
    windows_secret = get_secret("windows-admin-password", region)  

    ssh_key_path = "./private_key.pem"  
    
    for reservation in linux_instances:
        for instance in reservation['Instances']:
            instance_id = instance['PublicIpAddress']
            save_ssh_key(linux_secret, ssh_key_path)
            
            inventory["all"]["hosts"][instance_id] = {
                "ansible_user": "ec2-user",  
                "ansible_ssh_private_key_file": ssh_key_path,  
                "ansible_connection": "ssh",
                "ansible_become": True,
                "ansible_host": instance['PublicIpAddress']
            }

    for reservation in windows_instances:
        for instance in reservation['Instances']:
            instance_id = instance['PublicIpAddress']
            
            # Add instance to the "hosts" dictionary in the "all" group
            inventory["all"]["hosts"][instance_id] = {
                "ansible_user": "Administrator",  
                "ansible_password": windows_secret,  
                "ansible_connection": "winrm",
                "ansible_winrm_transport": "ntlm",
                "ansible_winrm_scheme": "http",
                "ansible_winrm_port": 5985,
                "ansible_winrm_server_cert_validation": "ignore",
                "ansible_host": instance['PublicIpAddress']
            }

    return json.dumps(inventory, indent=4)

if __name__ == "__main__":
    print(create_inventory())
