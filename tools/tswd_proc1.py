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
NB=dirv[6]; SB=dirv[8]; AM=dirv[11]
# find name offset
nameOff=None; o=NB
while o<SB:
    e=blob.index(0,o)
    if blob[o:e]==target: nameOff=o-NB; break
    o=e+1
print(f"{target!r} nameOff={nameOff:#x}")
def cstr(noff):
    try: e=blob.index(0,NB+noff); return blob[NB+noff:e].decode('latin1')
    except: return '?'
# scan for tag 0x05 proc whose nameOff (o+5) matches
o=SB
while o+30<AM:
    if blob[o]==0x05 and u32(blob,o+5)==nameOff:
        print(f"\nPROC tag@{o-SB:#x}")
        print("  bytes:", ' '.join(f'{x:02x}' for x in blob[o:o+64]))
        retT=u32(blob,o+1); nm=u32(blob,o+5); entry=u32(blob,o+9)
        print(f"  retType={retT:#x} nameOff={nm:#x}({cstr(nm)}) entry={0x400000+entry:#x}")
        # show candidate localCount at several offsets
        for off in (17,21,25):
            print(f"  u32@+{off}={u32(blob,o+off)}")
        lcount=u32(blob,o+21)
        print(f"  localCount={lcount}")
        for k in range(min(lcount,30)):
            lref=u32(blob,o+25+4*k)
            t0=blob[SB+lref] if SB+lref<len(blob) else -1
            t4=blob[SB+lref+4] if SB+lref+4<len(blob) else -1
            # try var record at lref (tag@+4): typeRef@+5,nameOff@+9,off@+13
            nm=cstr(u32(blob,SB+lref+9)) if SB+lref+13<len(blob) else '?'
            off=i32(blob,SB+lref+13) if SB+lref+13<len(blob) else 0
            raw=' '.join(f'{x:02x}' for x in blob[SB+lref:SB+lref+18])
            print(f"   lref[{k}]={lref:#x} tag@0={t0:#x} tag@4={t4:#x} name={nm!r} off={off:#x}  | {raw}")
        break
    o+=1
else: print("not found")
