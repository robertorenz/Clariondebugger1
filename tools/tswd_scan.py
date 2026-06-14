"""Scan the whole symbol stream for procedure records (tag 0x05), validated."""
import sys, struct
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def find_blob(path):
    d=open(path,'rb').read(); lfa=u32(d,0x3c); nsec=u16(d,lfa+6); optsz=u16(d,lfa+20); st=lfa+24+optsz
    secs={}
    for i in range(nsec):
        o=st+i*40; nm=d[o:o+8].rstrip(b'\0'); secs[nm]=(u32(d,o+12),u32(d,o+8)) # va,vsize
    o2=None
    for i in range(nsec):
        o=st+i*40
        if d[o:o+8].rstrip(b'\0')==b'.cwdebug':
            rp=u32(d,o+20); loc=d[rp:rp+32]; o2=(u32(loc,24),u32(loc,16))
    text=secs.get(b'.text',(0x1000,0x50000))
    return d[o2[0]:o2[0]+o2[1]], text
def cstr(b,o):
    try: e=b.index(0,o); return b[o:e].decode('latin1')
    except: return '?'
blob,(textVa,textSz)=find_blob(sys.argv[1])
dirv=[u32(blob,8+4*i) for i in range(12)]
NB=dirv[6]; SB=dirv[8]; AM=dirv[11]
nameSz=SB-NB
codeLo,codeHi=textVa,textVa+textSz

procs=[]
o=SB
while o+25 < AM:
    if blob[o]==0x05:
        nameOff=u32(blob,o+5); entry=u32(blob,o+9); lcount=u32(blob,o+21)
        if 0<nameOff<nameSz and codeLo<=entry<codeHi and lcount<2000:
            nm=cstr(blob,NB+nameOff)
            if nm and nm!='?' and all(32<=ord(c)<127 for c in nm):
                procs.append((entry,nm,lcount,o))
                o+=25; continue
    o+=1
print(f"procedure records found by scan: {len(procs)}  (address-map gave 67)")
# show user-ish ones
import re
user=[p for p in procs if not re.search(r'@F\d', p[1]) or 'BROWSE' not in p[1].upper()]
print("\nsample (entry, name, #locals):")
for entry,nm,lc,o in sorted(procs)[:40]:
    print(f"   0x{entry:06X}  {nm:42s} locals={lc}")
