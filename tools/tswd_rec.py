import sys, struct
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def find_blob(path):
    d=open(path,'rb').read(); lfa=u32(d,0x3c); nsec=u16(d,lfa+6); optsz=u16(d,lfa+20); st=lfa+24+optsz
    for i in range(nsec):
        o=st+i*40
        if d[o:o+8].rstrip(b'\0')==b'.cwdebug':
            rp=u32(d,o+20); loc=d[rp:rp+32]; return d[u32(loc,24):u32(loc,24)+u32(loc,16)]
def cstr(b,o):
    try: e=b.index(0,o); return b[o:e].decode('latin1')
    except: return '?'
blob=find_blob(sys.argv[1])
dirv=[u32(blob,8+4*i) for i in range(12)]
NB=dirv[6]; SB=dirv[8]; AM=dirv[11]; AMC=dirv[10]

def dump(ref,n=28):
    o=SB+ref
    raw=' '.join(f'{x:02x}' for x in blob[o:o+n])
    return raw

# dump records for a few address-map entries with their rva + tag@+4
print("=== sample records (rva, ref, byte[0], byte[4]=tag, raw) ===")
seen={}
for i in range(AMC):
    e=AM+i*8; rva=u32(blob,e); ref=u32(blob,e+4)
    tag = blob[SB+ref+4] if SB+ref+4<len(blob) else -1
    if tag not in seen:
        seen[tag]=0
    if seen[tag]<3:
        seen[tag]+=1
        print(f"\ntag={tag:#04x} rva={0x400000+rva:#x} ref={ref:#x}")
        print(f"   {dump(ref,32)}")

# scan the name table for user procedure-looking names (Browse/Update/Main/Form/Report)
print("\n=== user-ish procedure names in name table ===")
keys=(b'Main',b'Browse',b'Update',b'Form',b'Report',b'Window',b'Frame',b'Splash',b'Menu')
o=NB; cnt=0
end=SB
names=blob[NB:SB].split(b'\x00')
off=NB
for nm in names:
    if nm and any(k.lower() in nm.lower() for k in keys) and len(nm)<40:
        s=nm.decode('latin1','replace')
        if not s.startswith('?'):
            print(f"   @{off-NB:#x} {s}")
            cnt+=1
            if cnt>40: break
    off+=len(nm)+1
