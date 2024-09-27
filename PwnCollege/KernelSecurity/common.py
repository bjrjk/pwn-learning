from pwn import asm, disasm, util
import struct

def i2f(x):
    return struct.unpack('!d', struct.pack('!Q', x))[0]

def f2i(x):
    return struct.unpack('!Q', struct.pack('!d', x))[0]

def dump_machine_code(assembly: str):
    machine_code = asm(assembly)
    print("Assembly:")
    print(assembly)
    print("Byte Array:", list(machine_code))
    padding = b"\xcc" * ((4 - len(machine_code)) % 4)
    unpacked_signed_array = util.packing.unpack_many(machine_code + padding, 32, endian='little', sign=True)
    unpacked_unsigned_array = util.packing.unpack_many(machine_code + padding, 32, endian='little', sign=False)
    print("Signed DWord Array:", unpacked_signed_array)
    print("Unsigned DWord Array:", unpacked_unsigned_array)
    print("Hex DWord Array:", list(map(hex, unpacked_unsigned_array)))
    padding = b"\xcc" * ((8 - len(machine_code)) % 8)
    unpacked_signed_array = util.packing.unpack_many(machine_code + padding, 64, endian='little', sign=True)
    unpacked_unsigned_array = util.packing.unpack_many(machine_code + padding, 64, endian='little', sign=False)
    print("Signed QWord Array:", unpacked_signed_array)
    print("Unsigned QWord Array:", unpacked_unsigned_array)
    print("Hex QWord Array:", list(map(hex, unpacked_unsigned_array)))
    print("Double Array:", list(map(i2f, unpacked_unsigned_array)))
    print("Disassembled-assembly:")
    print(disasm(machine_code))
    return machine_code