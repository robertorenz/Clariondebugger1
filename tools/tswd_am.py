"""Diagnose the address-map / symbol composition of a TSWD blob."""
import sys, struct, collections
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def i32(b,o): return struct.unpack_from('<i',b,o)[0]
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
print(f"NB={NB:#x} SB={SB:#x} AM={AM:#x} AMC={AMC}")

tags=collections.Counter()
samples=collections.defaultdict(list)
for i in range(AMC):
    e=AM+i*8
    if e+8>len(blob): break
    rva=u32(blob,e); ref=u32(blob,e+4)
    b=SB+ref
    tag = blob[b+4] if 0<=b+4<len(blob) else -1
    tags[tag]+=1
    if len(samples[tag])<6:
        # try to read name at +9 (var/proc layout)
        nameOff = u32(blob,b+9) if b+13<=len(blob) else 0
        nm = cstr(blob, NB+nameOff) if NB+nameOff<len(blob) else '?'
        samples[tag].append((rva, ref, nm))

print("\ntag distribution (tag at SB+ref+4):")
for tag,cnt in tags.most_common():
    print(f"  tag={tag:#04x}  count={cnt}")
    for rva,ref,nm in samples[tag]:
        print(f"      rva={0x400000+rva:#010x} ref={ref:#x} name={nm!r}")
