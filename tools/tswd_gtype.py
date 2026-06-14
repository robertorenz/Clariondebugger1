"""For global var records (tag 0x04 with a data RVA), show the referenced type tag."""
import sys, struct, collections
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def find(path):
    d=open(path,'rb').read(); lfa=u32(d,0x3c); nsec=u16(d,lfa+6); optsz=u16(d,lfa+20); st=lfa+24+optsz
    text=(0x1000,0x50000); data=None
    for i in range(nsec):
        o=st+i*40; nm=d[o:o+8].rstrip(b'\0')
        if nm==b'.text': text=(u32(d,o+12),u32(d,o+8))
        if nm==b'.data': data=(u32(d,o+12),u32(d,o+8))
    for i in range(nsec):
        o=st+i*40
        if d[o:o+8].rstrip(b'\0')==b'.cwdebug':
            rp=u32(d,o+20); loc=d[rp:rp+32]; blob=d[u32(loc,24):u32(loc,24)+u32(loc,16)]
            return blob,data
blob,data=find(sys.argv[1])
dirv=[u32(blob,8+4*i) for i in range(12)]
NB=dirv[6]; SB=dirv[8]; AM=dirv[11]; nameSz=SB-NB
dlo,dhi=data[0],data[0]+data[1]
def cstr(o):
    try: e=blob.index(0,NB+o); return blob[NB+o:e].decode('latin1')
    except: return '?'
tags=collections.Counter(); samples=collections.defaultdict(list)
o=SB
while o+13<AM:
    if blob[o]==0x04:
        typeRef=u32(blob,o+1); nameOff=u32(blob,o+5); rva=u32(blob,o+9)
        if 0<nameOff<nameSz and dlo<=rva<dhi and 0<=typeRef<(AM-SB):
            tt = blob[SB+typeRef+4] if SB+typeRef+4<len(blob) else -1
            nm=cstr(nameOff)
            if nm and nm[0]!='?' and not nm.startswith('VMT'):
                tags[tt]+=1
                if len(samples[tt])<4: samples[tt].append((nm, f"{' '.join(f'{x:02x}' for x in blob[SB+typeRef:SB+typeRef+16])}"))
                o+=13; continue
    o+=1
print("type-tag distribution for global vars (tag at typeRef+4):")
for tt,c in tags.most_common():
    print(f"  typetag={tt:#04x}  count={c}")
    for nm,raw in samples[tt]: print(f"      {nm:24s} typerec={raw}")
