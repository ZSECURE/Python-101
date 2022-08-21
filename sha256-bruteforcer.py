#!/usr/local/bin/python3
from pwn import *
import sys

if len(sys.argv) != 3:
	print("\n")
	print("Invalid arguments!")
	print(">> {} <sha256sum> <path-to-wordlist>".format(sys.argv[0]))
	print("\n")
	exit()

user_supplied_hash = sys.argv[1]
password_file = sys.argv[2]
# password_file = "/usr/share/wordlists/rockyou.txt"
attempts = 0

with log.progress("Attempting to crack: {} !\n".format(user_supplied_hash)) as p:
	with open(password_file, "r", encoding='latin-1') as password_list:
		for password in password_list:
			password = password.strip("\n").encode('latin-1')
			password_hash = sha256sumhex(password)
			p.status("[{}] {}".format(attempts, password.decode('latin-1'), password_hash))
			if password_hash == user_supplied_hash:
				p.success("Password hash found after {} attempts! {} hashes to {} !".format(attempts, password.decode('latin-1'), user_supplied_hash))
				exit()
			attempts += 1
		p.failure("Password hash not found!")
