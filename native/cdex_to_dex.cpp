// darkdex v2 — CompactDex (cdex001) -> standard DEX (dex\n035)
//
// v1 only stamped the magic and left the CompactDex code items in place, so the
// output would not decompile. This does the real work: it expands every compact
// code item back to the standard code_item layout and rewrites the class_data so
// jadx / baksmali / dexdump can read it.
//
// CompactDex CodeItem (art/libdexfile/dex/compact_dex_file.h), 2x uint16 header:
//   fields_                 : registers(4b<<12) ins(4b<<8) outs(4b<<4) tries(4b<<0)
//   insns_count_and_flags_  : insns_size(11b<<5) | preheader_flags(5b)
//   [insns u2...][pad][tries/handlers]
// values too big for their nibble/field live in a "preheader" of uint16s placed
// immediately BEFORE the CodeItem, consumed low-flag-first.
// debug_info_off lives in a separate table in cdex; we set it to 0 (code still
// decompiles; only local-variable names are lost).
//
// Standard code_item:
//   u2 registers,ins,outs,tries; u4 debug_info_off; u4 insns_size; u2 insns[];
//   [pad u2 if tries&&insns odd]; try_item[tries]{u4 start,u2 count,u2 hoff};
//   encoded_catch_handler_list.
//
// Build: g++ -O2 -std=c++17 -DDARKDEX_STANDALONE -o cdex_to_dex cdex_to_dex.cpp
// Use:   ./cdex_to_dex in.cdex out.dex            (code items inside the cdex)
//        ./cdex_to_dex in.cdex out.dex data.bin   (vdex shared-data section)
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

namespace darkdex {

static uint32_t rd_uleb(const uint8_t*& p){
    uint32_t r=*p++; if(r<=0x7f) return r; r&=0x7f;
    uint32_t c=*p++; r|=(c&0x7f)<<7; if(c<=0x7f) return r;
    c=*p++; r|=(c&0x7f)<<14; if(c<=0x7f) return r;
    c=*p++; r|=(c&0x7f)<<21; if(c<=0x7f) return r;
    c=*p++; r|=(c&0x7f)<<28; return r;
}
static void wr_uleb(std::vector<uint8_t>& o, uint32_t v){
    do { uint8_t b=v&0x7f; v>>=7; if(v) b|=0x80; o.push_back(b); } while(v);
}
static int32_t rd_sleb(const uint8_t*& p){
    int32_t r=0; int sh=0; uint8_t b;
    do { b=*p++; r|=(int32_t)(b&0x7f)<<sh; sh+=7; } while(b&0x80);
    if(sh<32 && (b&0x40)) r|=-(1<<sh);
    return r;
}

#pragma pack(push,1)
struct Hdr {
    uint8_t magic[8]; uint32_t checksum; uint8_t sig[20];
    uint32_t file_size, header_size, endian_tag, link_size, link_off, map_off;
    uint32_t sids_sz, sids_off, tids_sz, tids_off, pids_sz, pids_off,
             fids_sz, fids_off, mids_sz, mids_off, cdefs_sz, cdefs_off,
             data_sz, data_off;
};
#pragma pack(pop)

// CompactDex code-item field shifts / preheader flags
enum { kRegShift=12,kInsShift=8,kOutsShift=4,kTriesShift=0,kInsnsShift=5 };
enum { kPreReg=0x1,kPreIns=0x2,kPreOuts=0x4,kPreTries=0x8,kPreInsns=0x10 };

struct Code { uint16_t regs,ins,outs,tries; uint32_t insns; const uint16_t* insns_ptr; };

// Decode a CompactDex code item at `ci`. Returns bytes consumed by insns start.
static bool decode_compact(const uint16_t* ci, const uint16_t* limit, Code& c){
    if(ci+2>limit) return false;
    uint16_t fields = ci[0];
    uint16_t icf    = ci[1];
    uint16_t flags  = icf & 0x1F;
    c.regs  = (fields>>kRegShift)  & 0xF;
    c.ins   = (fields>>kInsShift)  & 0xF;
    c.outs  = (fields>>kOutsShift) & 0xF;
    c.tries = (fields>>kTriesShift)& 0xF;
    c.insns = icf >> kInsnsShift;
    // preheader: uint16s just before ci, consumed low-flag-first
    const uint16_t* pre = ci;
    if(flags & kPreReg)   c.regs  += *--pre;
    if(flags & kPreIns)   c.ins   += *--pre;
    if(flags & kPreOuts)  c.outs  += *--pre;
    if(flags & kPreTries) c.tries += *--pre;
    if(flags & kPreInsns){ uint32_t hi=*--pre; c.insns += hi<<16; }  // insns high bits
    c.insns_ptr = ci+2;
    if(c.insns_ptr + c.insns > limit) return false;
    return true;
}

// length in bytes of an encoded_catch_handler_list starting at p (bounded by end)
static size_t handlers_len(const uint8_t* p, const uint8_t* end){
    const uint8_t* s=p; if(p>=end) return 0;
    uint32_t list_size = rd_uleb(p);
    for(uint32_t i=0;i<list_size && p<end;i++){
        int32_t sz = rd_sleb(p);
        uint32_t n = sz<0 ? (uint32_t)(-sz) : (uint32_t)sz;
        for(uint32_t j=0;j<n && p<end;j++){ rd_uleb(p); rd_uleb(p); }  // type_idx, addr
        if(sz<=0){ rd_uleb(p); }                                       // catch_all addr
    }
    return (size_t)(p-s);
}

// Expand one method's code, append standard code_item to `out`, return new offset.
static uint32_t emit_std_code(std::vector<uint8_t>& out, const uint8_t* codeBase,
                              const uint8_t* codeEnd, uint32_t cdex_off){
    const uint16_t* ci = (const uint16_t*)(codeBase + cdex_off);
    Code c;
    if(!decode_compact(ci,(const uint16_t*)codeEnd,c)) return 0;
    while(out.size() & 3) out.push_back(0);                // 4-byte align
    uint32_t noff = (uint32_t)out.size();
    auto pu2=[&](uint16_t v){ out.push_back(v&0xff); out.push_back(v>>8); };
    auto pu4=[&](uint32_t v){ for(int i=0;i<4;i++) out.push_back((v>>(8*i))&0xff); };
    pu2(c.regs); pu2(c.ins); pu2(c.outs); pu2(c.tries);
    pu4(0);                                                // debug_info_off (dropped)
    pu4(c.insns);
    const uint8_t* ins_b=(const uint8_t*)c.insns_ptr;
    for(uint32_t i=0;i<c.insns*2;i++) out.push_back(ins_b[i]);
    if(c.tries){
        if(c.insns & 1) pu2(0);                            // padding
        const uint8_t* tp = ins_b + c.insns*2;
        const uint8_t* handlers = tp + (size_t)c.tries*8;
        size_t hlen = handlers_len(handlers, codeEnd);
        size_t total = (size_t)c.tries*8 + hlen;
        for(size_t i=0;i<total && (tp+i)<codeEnd;i++) out.push_back(tp[i]);
    }
    return noff;
}

// Full converter. cdex+len is the compact dex; if data!=null it is the shared
// data section (code items resolved from there), else from the cdex itself.
int convert(const uint8_t* cdex, size_t len, std::vector<uint8_t>& dexOut,
            const uint8_t* data=nullptr, size_t data_len=0){
    if(len<sizeof(Hdr)) return -1;
    const Hdr* h=(const Hdr*)cdex;
    if(memcmp(h->magic,"cdex",4)!=0 && memcmp(h->magic,"dex\n",4)!=0) return -2;

    const uint8_t* codeBase = data ? data : cdex;
    const uint8_t* codeEnd  = data ? data+data_len : cdex+len;

    // Copy the fixed tables verbatim; we only rewrite class_data + append code.
    dexOut.assign(cdex, cdex+len);
    std::vector<uint8_t> newClassData;     // appended fresh
    uint32_t base = (uint32_t)dexOut.size();

    uint32_t cdefs = h->cdefs_sz, cdefs_off=h->cdefs_off;
    int methods=0, expanded=0;
    for(uint32_t ci=0; ci<cdefs; ci++){
        uint8_t* cd = dexOut.data() + cdefs_off + (size_t)ci*32;
        uint32_t class_data_off = *(uint32_t*)(cd+24);
        if(!class_data_off || class_data_off>=len) continue;
        const uint8_t* p = cdex + class_data_off;
        const uint8_t* pend = cdex + len;

        uint32_t sf=rd_uleb(p), inf=rd_uleb(p), dm=rd_uleb(p), vm=rd_uleb(p);
        std::vector<uint8_t> nb;                       // new class_data
        wr_uleb(nb,sf); wr_uleb(nb,inf); wr_uleb(nb,dm); wr_uleb(nb,vm);
        // fields copied unchanged
        for(uint32_t i=0;i<sf+inf;i++){ uint32_t d=rd_uleb(p),a=rd_uleb(p); wr_uleb(nb,d); wr_uleb(nb,a); }
        // methods: rewrite code_off
        for(uint32_t i=0;i<dm+vm;i++){
            uint32_t d=rd_uleb(p), a=rd_uleb(p), co=rd_uleb(p);
            uint32_t nco=0;
            if(co){ methods++;
                uint32_t e=emit_std_code(dexOut, codeBase, codeEnd, co);
                if(e){ nco=e; expanded++; } else nco=0; }
            wr_uleb(nb,d); wr_uleb(nb,a); wr_uleb(nb,nco);
        }
        // append new class_data, repoint class_def
        uint32_t off = base + (uint32_t)newClassData.size();
        newClassData.insert(newClassData.end(), nb.begin(), nb.end());
        *(uint32_t*)(dexOut.data()+cdefs_off+(size_t)ci*32+24) = off;
    }
    dexOut.insert(dexOut.end(), newClassData.begin(), newClassData.end());

    Hdr* oh=(Hdr*)dexOut.data();
    memcpy(oh->magic,"dex\n035",8);
    oh->header_size = 0x70;
    oh->file_size   = (uint32_t)dexOut.size();
    oh->map_off     = 0;                    // stale map dropped; header offsets stay valid
    oh->data_off    = base;
    oh->data_sz     = (uint32_t)(dexOut.size()-base);
    // NB: checksum/signature intentionally left; decompilers do not require them.

    fprintf(stderr,"[cdex2dex] classes=%u methods=%u expanded=%u  %zu -> %zu bytes%s\n",
            cdefs, methods, expanded, len, dexOut.size(), data?"  (shared-data)":"");
    return expanded>0 ? 0 : (methods==0 ? 0 : -3);
}

} // namespace darkdex

#ifdef DARKDEX_STANDALONE
static std::vector<uint8_t> slurp(const char* f){ FILE* fp=fopen(f,"rb"); if(!fp) return {};
    fseek(fp,0,SEEK_END); long n=ftell(fp); fseek(fp,0,SEEK_SET); std::vector<uint8_t> b(n);
    size_t r=fread(b.data(),1,n,fp);(void)r; fclose(fp); return b; }
int main(int argc,char**argv){
    if(argc<3){ fprintf(stderr,"cdex_to_dex <in.cdex> <out.dex> [data.bin]\n"); return 1; }
    auto in=slurp(argv[1]); if(in.empty()){ perror("in"); return 1; }
    std::vector<uint8_t> data; if(argc>3) data=slurp(argv[3]);
    std::vector<uint8_t> out;
    int rc=darkdex::convert(in.data(),in.size(),out, data.empty()?nullptr:data.data(), data.size());
    if(rc<=0 && !out.empty()){ FILE* o=fopen(argv[2],"wb"); fwrite(out.data(),1,out.size(),o); fclose(o);
        fprintf(stderr,"[cdex2dex] wrote %s (rc=%d)\n",argv[2],rc); return 0; }
    fprintf(stderr,"[cdex2dex] convert failed rc=%d\n",rc); return rc?rc:0;
}
#endif
