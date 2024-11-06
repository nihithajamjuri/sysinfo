#!/bin/bash

# Check if the system is Linux or Windows
if [ -f /etc/os-release ]; then
  # It's a Linux-based system
  export OS_TYPE="Linux"
  export dest="/home/ec2-user"
  echo "OS_TYPE is set to Linux"
elif [ -f "C:\Windows\System32\cmd.exe" ]; then
  # It's a Windows-based system
  export OS_TYPE="Windows"
  export dest="c:\temp"
  echo "OS_TYPE is set to Windows"
else
  echo "Unable to determine OS type. Exiting."
  exit 1
fi

# Save the OS_TYPE to a temporary file for future reference
#echo "OS_TYPE=$OS_TYPE" > /tmp/os_type.txt  # For Linux-based instances
