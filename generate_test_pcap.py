import struct, socket, time, random

def _mac(n): return bytes([0x00,0x00,0x00,0x00,0x00,n&0xFF])
def _ip(a): return socket.inet_aton(a)

def _build(src_ip,dst_ip,sport,dport,proto,payload):
    if proto=="TCP":
        tcp=struct.pack("!HHIIBBHHH",sport,dport,random.randint(1,2**32-1),0,0x50,0x018,65535,0,0)
        ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(tcp)+len(payload),random.randint(1,65535),0x4000,64,6,0,socket.inet_aton(src_ip),socket.inet_aton(dst_ip))
        eth=_mac(2)+_mac(1)+struct.pack("!H",0x0800)
        return eth+ip+tcp+payload
    else:
        udp=struct.pack("!HHHH",sport,dport,8+len(payload),0)
        ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+8+len(payload),random.randint(1,65535),0x4000,64,17,0,socket.inet_aton(src_ip),socket.inet_aton(dst_ip))
        eth=_mac(2)+_mac(1)+struct.pack("!H",0x0800)
        return eth+ip+udp+payload

def tls_sni(sni):
    sni=sni.encode()
    sni_ext=struct.pack("!H",len(sni)+3)+b"\x00"+struct.pack("!H",len(sni))+sni
    ext=struct.pack("!HH",0x0000,len(sni_ext))+sni_ext
    ext_block=struct.pack("!H",len(ext))+ext
    ch=b"\x03\x03"+bytes(32)+b"\x00"+b"\x00\x02\xc0\x2c\x01\x00"+ext_block
    hs=b"\x01"+struct.pack(">I",len(ch))[1:]+ch
    return b"\x16\x03\x01"+struct.pack("!H",len(hs))+hs

def dns_query(name):
    labels=b""
    for p in name.split("."):
        e=p.encode(); labels+=bytes([len(e)])+e
    labels+=b"\x00"
    return struct.pack("!HHHHHH",random.randint(1,65535),0x0100,1,0,0,0)+labels+struct.pack("!HH",1,1)

def http_req(host,path="/"):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()

def write_pcap(filename,packets):
    with open(filename,"wb") as f:
        f.write(struct.pack("<IHHiIII",0xA1B2C3D4,2,4,0,0,65535,1))
        ts=time.time()
        for raw in packets:
            ts+=random.uniform(0.0001,0.005)
            s=int(ts); u=int((ts-s)*1000000)
            f.write(struct.pack("<IIII",s,u,len(raw),len(raw)))
            f.write(raw)

c="192.168.1.42"
s=lambda n:f"203.0.113.{n}"
pkts=[]

for _ in range(15):
    pkts.append(_build(c,s(10),54321,443,"TCP",tls_sni("r3---sn-youtube.googlevideo.com")))
    pkts.append(_build(c,s(10),54321,443,"TCP",bytes(random.randint(5000,50000))))

for _ in range(5):
    pkts.append(_build(c,s(20),55000,443,"TCP",tls_sni("www.pornhub.com")))

for _ in range(5):
    pkts.append(_build(c,s(30),55100,443,"TCP",tls_sni("store.steampowered.com")))

pkts.append(_build(c,s(40),55200,80,"TCP",http_req("secure.bankofamerica-login.com","/login")))
pkts.append(_build(c,s(50),55300,4444,"TCP",b"A"*32))

for h in ["google.com","github.com","stackoverflow.com","cloudflare.com"]:
    pkts.append(_build(c,"8.8.8.8",12345,53,"UDP",dns_query(h)))

for _ in range(10):
    pkts.append(_build(c,s(60),55400,443,"TCP",tls_sni("www.google.com")))

for _ in range(8):
    pkts.append(_build(c,s(70),55500,443,"TCP",tls_sni("github.com")))

random.shuffle(pkts)
write_pcap("test_dpi.pcap",pkts)
print(f"Generated {len(pkts)} packets → test_dpi.pcap")