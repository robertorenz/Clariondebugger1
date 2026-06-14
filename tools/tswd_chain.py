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
NB=dirv[6]; SB=dirv[8]; AM=dirv[11]
def raw(ref,n=24): return ' '.join(f'{x:02x}' for x in blob[SB+ref:SB+ref+n])
def tagof(ref): return blob[SB+ref+4] if 0<=SB+ref+4<len(blob) else -1

def show(ref, depth=0, seen=None):
    if seen is None: seen=set()
    if ref in seen or depth>4: return
    seen.add(ref)
    t=tagof(ref)
    print("  "*depth + f"ref={ref:#x} tag@+4={t:#x}  raw={raw(ref,20)}")
    # if tag is the array/string composite or group, decode; if it's a wrapper, follow refs
    if t in (0x11,0x12,0x13,0x14,0x18,0x08,0x23,0x24): return  # leaf-ish, stop
    # otherwise follow plausible refs in the next 6 dwords
    for k in range(6):
        v=u32(blob,SB+ref+4+4*k) if SB+ref+8+4*k<len(blob) else 0
        if 0<v<(AM-SB):
            show(v, depth+1, seen)

print("=== GLO:CAMEFROM typeRef 0x3bc22 chain ===")
show(0x3bc22)

# search name table for file record buffers
print("\n=== names containing ':RECORD' or 'RECORD' (file buffers) ===")
names=blob[NB:SB].split(b'\x00'); off=NB; cnt=0
for nm in names:
    s=nm.decode('latin1','replace')
    if ('RECORD' in s.upper() or s.upper().endswith(':R')) and len(s)<40 and not s.startswith('?'):
        print(f"   @{off-NB:#x} {s}"); cnt+=1
        if cnt>30: break
    off+=len(nm)+1
print(f"(total record-ish names: {cnt})")
