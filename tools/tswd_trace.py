import sys, struct
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def find(path):
    d=open(path,'rb').read(); lfa=u32(d,0x3c); nsec=u16(d,lfa+6); optsz=u16(d,lfa+20); st=lfa+24+optsz
    for i in range(nsec):
        o=st+i*40
        if d[o:o+8].rstrip(b'\0')==b'.cwdebug':
            rp=u32(d,o+20); loc=d[rp:rp+32]; return d[u32(loc,24):u32(loc,24)+u32(loc,16)]
blob=find(sys.argv[1])
dirv=[u32(blob,8+4*i) for i in range(12)]
SB=dirv[8]
def at(off,n=16): return ' '.join(f'{x:02x}' for x in blob[SB+off:SB+off+n])
def tag4(off): return blob[SB+off+4] if SB+off+4<len(blob) else -1

# GLO:CAMEFROM typeRef = 0x3bc22 (a 0x03 record). dump it and follow its refs.
tr=0x3bc22
print(f"type record @{tr:#x} (tag@0={blob[SB+tr]:#x}): {at(tr,28)}")
# read refs after the leading 2 bytes (03 00), as u32 list
o=SB+tr+2
print("refs in 0x03 record and what they point to:")
for k in range(8):
    ref=u32(blob,o+4*k)
    if not (0<ref<(dirv[11]-SB)): break
    print(f"   ref={ref:#x}  tag@+4={tag4(ref):#04x}  bytes: {at(ref,16)}")
