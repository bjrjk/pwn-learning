#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64
context(arch = "i386",os = "linux", log_level = "debug")


p = process('./pwns')
elf = ELF('./pwns')

p.recvuntil("May be I can know if you give me some data[Y/N]")
confirm = "Y"
p.sendline(confirm)

test_payload = ""
for i in range(256):
    test_payload += chr(i)
for i in range(256):
    test_payload += chr(i)
test_payload = base64.b64encode(test_payload)

p.sendline(test_payload)

with open("test.txt", "w") as f:
    f.write(confirm + "\n")
    f.write(test_payload + "\n")

p.interactive()
