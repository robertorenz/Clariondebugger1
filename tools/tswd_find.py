"""Find a global var record by name and dump its record + type chain."""
import sys, struct
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def i32(b,o): return struct.unpack_from('<i',b,o)[0]
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def find(path):
    d=open(path,'rb').read(); lfa=u32(d,0x3c); nsec=u16(d,lfa+6); optsz=u16(d,lfa+20); st=lfa+24+optsz
    for i in range(nsec):
        o=st+i*40
        if d[o:o+8].rstrip(b'\0')==b'.cwdebug':
            rp=u32(d,o+20); loc=d[rp:rp+32]; return d[u32(loc,24):u32(loc,24)+u32(loc,16)]
blob=find(sys.argv[1]); target=sys.argv[2].encode()
dirv=[u32(blob,8+4*i) for i in range(12)]
NB=dirv[6]; SB=dirv[8]; AM=dirv[11]; nameSz=SB-NB
# find name offset(s) of target in name table
nameOff=None
o=NB
while o<SB:
    e=blob.index(0,o)
    if blob[o:e]==target: nameOff=o-NB; break
    o=e+1
print(f"name {target!r} at nameOff={nameOff:#x}" if nameOff is not None else "name not found")
def raw(off,n): return ' '.join(f'{x:02x}' for x in blob[off:off+n])
def cstr(noff):
    try: e=blob.index(0,NB+noff); return blob[NB+noff:e].decode('latin1')
    except: return '?'
# scan for tag-0x04 var record whose nameOff field == found offset
o=SB
while o+13<AM:
    if blob[o]==0x04 and u32(blob,o+5)==nameOff:
        typeRef=u32(blob,o+1); rva=u32(blob,o+9)
        print(f"\nVAR record @stream {o-SB:#x}: typeRef={typeRef:#x} rva={0x400000+rva:#x}")
        print(f"   record bytes: {raw(o-2, 24)}")
        # dump type record at typeRef, tag at +4
        t=SB+typeRef
        print(f"   type record @{typeRef:#x}: {raw(t,28)}")
        print(f"   tag@+4 = {blob[t+4]:#x}")
        break
    o+=1
else:
    print("var record not found by nameOff scan")
