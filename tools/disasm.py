import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u16(b,o): return struct.unpack_from('<H',b,o)[0]
path=sys.argv[1]; rva=int(sys.argv[2],0); count=int(sys.argv[3]) if len(sys.argv)>3 else 60
d=open(path,'rb').read()
lfa=u32(d,0x3c); nsec=u16(d,lfa+6); optsz=u16(d,lfa+20); st=lfa+24+optsz
text=None
for i in range(nsec):
    o=st+i*40
    if d[o:o+8].rstrip(b'\0')==b'.text': text=(u32(d,o+12),u32(d,o+20))  # va, rawptr
va,rp=text
fo=rp+(rva-va)
code=d[fo:fo+count*8]
md=Cs(CS_ARCH_X86, CS_MODE_32)
md.detail=True
n=0
for insn in md.disasm(code, rva):
    print(f"  {insn.address:#08x}: {insn.mnemonic:<7} {insn.op_str}")
    n+=1
    if n>=count: break
