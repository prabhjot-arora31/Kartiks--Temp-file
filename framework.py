# NETWORKING FRAMEWORK

# Importing Libraries/Modules
import socket
import os
import subprocess
import string
import random
import struct
import binascii
from pyfiglet import Figlet
from termcolor import colored

os.system('cls') # For clearing out screen

# result = pyfiglet.figlet_format("Networking Framework",font = "banner3-D")
# print(result)
f = Figlet(font = 'banner3-D',width = 200)
print(colored(f.renderText('NetFramework'),'blue'))

# g = Figlet()
# print(colored(g.renderText('By - Kartik Iyer'),'red'))
print("-------------------------------------------------------------------------------------------------------------------------------")

def Banner(ip,port):
    s = socket.socket()
    try:
        socket.setdefaulttimeout(5)
        s.connect((ip,port))
        recieve = s.recv(1024)
        print(recieve)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except:
        print("Connection to this port closed or refused.")
        print("-------------------------------------------------------------------------------------------------------------------------------")

def PortScan(ip,port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        socket.setdefaulttimeout(5)
        if s.connect_ex((ip,port)):
            print("Port is closed")
            print("-------------------------------------------------------------------------------------------------------------------------------")
        else:
            print("Port is open")
            print("-------------------------------------------------------------------------------------------------------------------------------")
    except:
        print("Connection to this port is refused.")
        print("-------------------------------------------------------------------------------------------------------------------------------")

def Ping(hostname):
    ping = os.system('ping' +hostname)
    try:
        socket.setdefaulttimeout(5)
        if ping == 0:
            print("Host is up")
            print("-------------------------------------------------------------------------------------------------------------------------------")
        else:
            print("Host is down")
            print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print(e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def Listener(ip,port):
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.bind((ip,port))
        print(f'Binded to port {port} with ip {ip}')
        s.listen(5)
        print(f'Server is listening on port {port}...')
        while True:
            c,addr = s.accept()
            print(f'Got a connection from {addr}')
            message = "Thank you for connecting with us.."
            c.send(message.encode())
            c.close()
            print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print(e)
        print("-------------------------------------------------------------------------------------------------------------------------------")
   
def Wifi(interface):
    try:
        command = subprocess.check_output(['netsh',interface,'show','network'])
        decoded = command.decode('ascii')
        print(decoded)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except:
        print(f"No interface found with name {interface}.Check your adaptor name again")
        print("-------------------------------------------------------------------------------------------------------------------------------")

def Caesar(plain_text,shift):
    try:
        alphabet = string.ascii_lowercase
        shifted = alphabet[shift:] + alphabet[:shift]
        table = str.maketrans(alphabet,shifted)
        encrypted = plain_text.translate(table)
        print("The encrypted string is:",encrypted)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print(e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def PasswordGen(length):
    try:
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        numbers = "123456789"
        symbols = "[]{}()*;/,-_+%@$^!&"

        all = lower + upper + numbers + symbols
        Password = "".join(random.sample(all,length))
        print("Your generated password is:",Password)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print(e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def Domain(domain):
    try:
        result = subprocess.check_output(['tracert',domain])
        decoded = result.decode('ascii')
        print(decoded)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except:
        print("Cannot trace the route")
        print("-------------------------------------------------------------------------------------------------------------------------------")

def DNSlookup(domain):
    try:
        result = subprocess.check_output(['nslookup',domain])
        decode = result.decode('ascii')
        print(decode)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print(e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def IP_req():
    try:
        print("Here's your system's IP configurations")
        result = os.system(('ipconfig'))
        print(result)
        print("-------------------------------------------------------------------------------------------------------------------------------")
    except Exception as e:
        print(e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def ARP():
    try:
        ip = input("Enter ip address to change: ")
        mac_addr = input("Enter MAC address: ")
        if mac_addr == "":
            print("MAC addr could not be empty")
            mac_addr = input("Enter MAC address: ")
            result = subprocess.check_output(['arp','-s',ip,mac_addr])
            print(result.decode('ascii'))
            view = input("Do you wish to view the current ARP cache? (yes/no): ")
            if view == "yes":
                view_cache = subprocess.check_output(['arp','-a'])
                print(view_cache.decode('ascii'))
            elif view == "no":
                print("Quitting")
                print("-------------------------------------------------------------------------------------------------------------------------------")
            else:
                print("Enter either yes or no")
        else:
            result = subprocess.check_output(['arp','-s',ip,mac_addr])
            print(result.decode('ascii'))
            view = input("Do you wish to view the current ARP cache? (yes/no): ")
            if view == "yes":
                view_cache = subprocess.check_output(['arp','-a'])
                print(view_cache.decode('ascii'))
            elif view == "no":
                print("Quitting")
                print("-------------------------------------------------------------------------------------------------------------------------------")
            else:
                print("Enter either yes or no")
       
    except Exception as e:
        print(e)
        print("-------------------------------------------------------------------------------------------------------------------------------")

def main():
    # print()
    print("[+] LIST: ")
    print("-------------------------------------------------------------------------------------------------------------------------------")
    print("[+] Press '1' for Banner Grabbing")
    print("[+] Press '2' for Port Scanning")
    print("[+] Press '3' for Pinging a Domain")
    print("[+] Press '4' for Listening on a Specific Port")
    print("[+] Press '5' for Checking Wifi Networks")
    print("[+] Press '6' for Caesar Encryption")
    print("[+] Press '7' for Password Generation")
    print("[+] Press '8' for Tracerouting ")
    print("[+] Press '9' for DNS lookup ")
    print("[+] Press '10' for Viewing your System's IP ")
    print("[+] Press '11' for Changing IP and MAC addr (Administrator)")
    print("[+] Enter 'quit' for Quitting the Framework")
    # print("[+] Press '12' for Packet Sniffing")
    print("-------------------------------------------------------------------------------------------------------------------------------")

    while True:
        choice = int(input("[+] Enter your choice: "))
        print("-------------------------------------------------------------------------------------------------------------------------------")

        if choice == 1:
            ip = input("[+] Enter ip address: ")
            port = int(input("[+] Specify port: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Banner(ip,port)
        elif choice == 2:
            ip = input("[+] Enter ip address: ")
            port = int(input("[+] Specify port: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")
            PortScan(ip,port)
        elif choice == 3:
            hostname = input("[+] Enter ip address/domain: ")
            print("-------------------------------------------------------------------------------------------------------------------------------")

            Ping(hostname)
        elif choice == 4:
            ip = input("[+] Enter ip: ")
            port = int(input("[+] Specify a port to listen: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")

            Listener(ip,port)
        elif choice == 5:
            interface = input("[+] Enter your interface name: ")
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Wifi(interface)
        elif choice == 6:
            plain_text = input("[+] Enter word/string to encrypt: ")
            shift = int(input("[+] Enter the shift value: "))
            print("-------------------------------------------------------------------------------------------------------------------------------")
            Caesar(plain_text,shift)
        elif choice == 7:
            length = int(input("Enter the length of the password to be generated: "))
            PasswordGen(length)
        elif choice == 8:
            domain = input("Enter the domain/ip address: ")
            Domain(domain)
        elif choice == 9:
            domain = input("Enter the domain/ip address: ")
            DNSlookup(domain)
        elif choice == 10:
            IP_req()
        elif choice == 11:
            ARP()
        choice = str(choice)
        if choice==str(choice):
            if choice == "quit":
                print("Bye! Hope to see you soon...")
                ("-------------------------------------------------------------------------------------------------------------------------------")
                break
        else:
            print("Enter valid number")
main()

   

