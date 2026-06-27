#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

namespace darkdex {

#pragma pack(push,1)
struct DexHeader {
    uint8_t  magic[8]; uint32_t checksum; uint8_t signature[20];
    uint32_t file_size, header_size, endian_tag, link_size, link_off, map_off;
    uint32_t string_ids_size, string_ids_off, type_ids_size, type_ids_off;
    uint32_t proto_ids_size, proto_ids_off, field_ids_size, field_ids_off;
    uint32_t method_ids_size, method_ids_off, class_defs_size, class_defs_off;
    uint32_t data_size, data_off;
};
struct CdexHeader {
    uint8_t  magic[8]; uint32_t checksum; uint8_t signature[20];
    uint32_t file_size, header_size, endian_tag, link_size, link_off, map_off;
    uint32_t string_ids_size, string_ids_off, type_ids_size, type_ids_off;
    uint32_t proto_ids_size, proto_ids_off, field_ids_size, field_ids_off;
    uint32_t method_ids_size, method_ids_off, class_defs_size, class_defs_off;
    uint32_t data_size, data_off;

    uint32_t feature_flags;
    uint32_t debug_info_offsets_pos, debug_info_offsets_table_offset, debug_info_base;
    uint32_t owned_data_begin, owned_data_end;
};
#pragma pack(pop)

static const uint16_t kRegistersSizeShift=12, kInsSizeShift=8, kOutsSizeShift=4, kTriesSizeShift=0;
static const uint16_t kInsnsSizeShift=5, kInsnsSizeBits=11;
static const uint16_t kFlagPreHeaderRegisterSize=0x1, kFlagPreHeaderInsSize=0x2,
                      kFlagPreHeaderOutsSize=0x4, kFlagPreHeaderTriesSize=0x8,
                      kFlagPreHeaderInsnsSize=0x10;

struct StdCodeItem { uint16_t registers_size, ins_size, outs_size, tries_size; uint32_t debug_info_off, insns_size; };

static bool expand_code_item(const uint8_t* base, const uint8_t* p, StdCodeItem& out) {
    const uint16_t fields = *reinterpret_cast<const uint16_t*>(p);
    const uint16_t* pre = reinterpret_cast<const uint16_t*>(p);
    int back = 0;
    auto take = [&](uint16_t flag)->uint16_t{ return (fields & flag) ? *(pre - (++back)) : 0; };
    out.registers_size = ((fields >> kRegistersSizeShift) & 0xF) + take(kFlagPreHeaderRegisterSize);
    out.ins_size       = ((fields >> kInsSizeShift) & 0xF)       + take(kFlagPreHeaderInsSize);
    out.outs_size      = ((fields >> kOutsSizeShift) & 0xF)      + take(kFlagPreHeaderOutsSize);
    out.tries_size     = ((fields >> kTriesSizeShift) & 0xF)     + take(kFlagPreHeaderTriesSize);
    uint16_t insns     = (fields >> kInsnsSizeShift) & ((1<<kInsnsSizeBits)-1);
    out.insns_size     = (fields & kFlagPreHeaderInsnsSize) ? insns + take(kFlagPreHeaderInsnsSize) : insns;
    out.debug_info_off = 0;
    (void)base; return true;
}

int convert(const uint8_t* cdex, size_t len, std::vector<uint8_t>& dexOut) {
    if (len < sizeof(CdexHeader)) return -1;
    const CdexHeader* ch = reinterpret_cast<const CdexHeader*>(cdex);
    if (memcmp(ch->magic, "cdex", 4) != 0) return -2;
    dexOut.assign(cdex, cdex + len);
    DexHeader* dh = reinterpret_cast<DexHeader*>(dexOut.data());
    memcpy(dh->magic, "dex\n035", 8);
    dh->header_size = 0x70;

    fprintf(stderr,"[cdex2dex] feature_flags=%#x data=[%u..%u] -> standard dex stamped, %zu bytes\n",
            ch->feature_flags, ch->owned_data_begin, ch->owned_data_end, dexOut.size());
    return 0;
}

}

#ifdef DARKDEX_STANDALONE
int main(int argc,char**argv){ if(argc<3){fprintf(stderr,"cdex_to_dex <in.cdex> <out.dex>\n");return 1;}
    FILE*f=fopen(argv[1],"rb"); fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    std::vector<uint8_t> in(n); size_t r=fread(in.data(),1,n,f);(void)r; fclose(f);
    std::vector<uint8_t> out; int rc=darkdex::convert(in.data(),in.size(),out);
    if(rc==0){FILE*o=fopen(argv[2],"wb");fwrite(out.data(),1,out.size(),o);fclose(o);} return rc; }
#endif
