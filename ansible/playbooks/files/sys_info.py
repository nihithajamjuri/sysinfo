import socket
import platform
import os

def get_sys_info():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    os_type = platform.system()
    os_version = platform.version()

    print("Details..")
    print(f"Hostname: {hostname}")
    print(f"IP Address: {ip_address}")
    print(f"Operating System: {os_type}")
    print(f"OS Version: {os_version}")

if __name__ == "__main__":
    get_sys_info()
