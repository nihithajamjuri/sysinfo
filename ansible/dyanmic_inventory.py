#!/usr/bin/env python

import boto3
import json
import os
from botocore.exceptions import ClientError

def get_secret(secret_name, region_name):
    """Fetch the secret from AWS Secrets Manager."""
    client = boto3.client('secretsmanager', region_name=region_name)
    try:
        # Retrieve the secret value
        response = client.get_secret_value(SecretId=secret_name)
        # Secrets Manager returns the secret as a string
        secret = response['SecretString']
        return json.loads(secret)
    except ClientError as e:
        print(f"Error retrieving secret: {e}")
        return None

def get_instances(region, tag_key, tag_value):
    """Fetch EC2 instances based on the specified tag."""
    ec2_client = boto3.client('ec2', region_name=region)
    instances = ec2_client.describe_instances(
        Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}]
    )
    return instances['Reservations']

def save_ssh_key(ssh_key_content, key_path):
    """Save SSH private key to a file."""
    try:
        with open(key_path, 'w') as f:
            f.write(ssh_key_content)
        os.chmod(key_path, 600)  # Set permissions to be readable only by the owner
        print(f"SSH key saved to {key_path}")
    except Exception as e:
        print(f"Error saving SSH key: {e}")

def create_inventory():
    """Generate dynamic Ansible inventory."""
    inventory = {"_meta": {"hostvars": {}}}
    
    # AWS Region
    region = "ap-south-1"  # Update with your AWS region
    
    # Fetch EC2 instances for Linux and Windows
    linux_instances = get_instances(region, "linux-sysinfo", "true")
    windows_instances = get_instances(region, "windows-sysinfo", "true")
    
    # Fetch secrets for SSH key and Windows password from Secrets Manager
    linux_secret = get_secret("linux-ssh-key", region)  # Secret name for Linux SSH key
    windows_secret = get_secret("windows-admin-password", region)  # Secret name for Windows password

    # Path to save the SSH private key
    ssh_key_path = "private_key.pem"  # Update this path to where you want the .pem file
    
    # Process Linux instances
    for reservation in linux_instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            # Save SSH key to a .pem file
            save_ssh_key(linux_secret, ssh_key_path)
            
            inventory[instance_id] = {"ansible_host": instance['PublicIpAddress']}
            inventory["_meta"]["hostvars"][instance_id] = {
                "ansible_user": "ec2-user",  # Default user for Amazon Linux
                "ansible_ssh_private_key_file": ssh_key_path,  # Use the saved SSH key
                "ansible_connection": "ssh",
                "ansible_become": True
            }

    # Process Windows instances
    for reservation in windows_instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            inventory[instance_id] = {"ansible_host": instance['PublicIpAddress']}
            inventory["_meta"]["hostvars"][instance_id] = {
                "ansible_user": "Administrator",  # Default user for Windows
                "ansible_password": windows_secret,  # Windows admin password from Secrets Manager
                "ansible_connection": "winrm",
                "ansible_winrm_transport": "ntlm",
                "ansible_winrm_server_cert_validation": "ignore"
            }

    return json.dumps(inventory, indent=4)

if __name__ == "__main__":
    print(create_inventory())

