"""Inspect module-level manager records being mis-shown as locals."""
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
blob=find(sys.argv[1])
dirv=[u32(blob,8+4*i) for i in range(12)]
NB=dirv[6]; SB=dirv[8]; AM=dirv[11]; nameSz=SB-NB
def cstr(noff):
    try: e=blob.index(0,NB+noff); return blob[NB+noff:e].decode('latin1')
    except: return '?'
# find records whose name contains RELATE:STUDENTS, dump record + scope record
needle=b"RELATE:STUDENTS"
p=SB; shown=0
while p+17<AM and shown<4:
    if blob[p]==0x04:
        nameOff=u32(blob,p+5)
        if 0<nameOff<nameSz:
            nm=cstr(nameOff)
            if needle in nm.encode():
                typeRef=u32(blob,p+1); off=i32(blob,p+9); scope=u32(blob,p+13)
                print(f"\nrec @{p-SB:#x} name={nm!r} off={off} scope={scope:#x} typeRef={typeRef:#x}")
                # dump the scope record (tag at scope+4?)
                s=SB+scope
                print(f"  scope rec bytes @{scope:#x}: {' '.join(f'{x:02x}' for x in blob[s-4:s+40])}")
                # what kind: module records have a ff*8 sentinel; proc records have tag 0x05
                # show tag at scope+0 and scope+4
                print(f"  scope byte@+0={blob[s]:#x} @+4={blob[s+4]:#x}")
                shown+=1
    p+=1
