// darkdex v2 — ART DexFile-object walker
//
// carve() trusts the dex header; recover() trusts the map_list. A packer that
// wipes BOTH defeats them. But ART itself keeps the truth: every loaded dex has
// a live `art::DexFile` object on the heap whose members store the real
// begin_/size_ (and data_begin_/data_size_) independently of the on-disk header.
//
// This walks the heap for those objects and dumps each dex by its object-recorded
// bounds — so even a fully header+maplist-wiped dex comes out with correct size.
// Layout (Android 11, arm64, art::DexFile has a vtable so offset 0 is the vptr):
//   +0x00 vtable*  (points into libdexfile.so / libart.so)
//   +0x08 begin_        (const uint8_t*)
//   +0x10 size_         (size_t)
//   +0x18 data_begin_   (const uint8_t*)
//   +0x20 data_size_    (size_t)
// We confirm a candidate by: vptr lands in an executable lib mapping, begin_
// points at a readable page whose dex/cdex signature OR endian tag is present (or
// even if wiped, size_ is sane and begin_+size_ stays inside one region).
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <set>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

struct Region { uint64_t s,e; bool r,x; std::string tag; };

static int find_pid(const char* pkg){
    DIR* d=opendir("/proc"); if(!d) return -1; dirent* e; int pid=-1,best=0;
    while((e=readdir(d))){ int p=atoi(e->d_name); if(p<=0) continue;
        char pa[256]; snprintf(pa,sizeof pa,"/proc/%d/cmdline",p); FILE* f=fopen(pa,"r"); if(!f) continue;
        char b[256]={0}; size_t r=fread(b,1,255,f);(void)r; fclose(f);
        if(strstr(b,pkg)){ char sp[256]; snprintf(sp,sizeof sp,"/proc/%d/status",p); FILE* sf=fopen(sp,"r"); int rss=0;
            if(sf){char l[128]; while(fgets(l,128,sf)) if(!strncmp(l,"VmRSS:",6)){rss=atoi(l+6);break;} fclose(sf);}
            if(rss>best){best=rss;pid=p;} } }
    closedir(d); return pid;
}
static std::vector<Region> maps(int pid){
    std::vector<Region> v; char p[64]; snprintf(p,sizeof p,"/proc/%d/maps",pid); FILE* f=fopen(p,"r");
    if(!f) return v; char line[1024];
    while(fgets(line,sizeof line,f)){ uint64_t s,e; char pm[8]={0}; char nm[512]={0};
        int m=sscanf(line,"%lx-%lx %7s %*x %*s %*d %511[^\n]",&s,&e,pm,nm);
        if(m>=3){ Region r; r.s=s; r.e=e; r.r=pm[0]=='r'; r.x=pm[2]=='x'; r.tag=(m>=4?nm:""); v.push_back(r);} }
    fclose(f); return v;
}
static bool in_readable(const std::vector<Region>&R,uint64_t a,uint64_t need){
    for(auto&r:R) if(r.r && a>=r.s && a+need<=r.e) return true; return false;
}
static bool in_libcode(const std::vector<Region>&R,uint64_t a){
    for(auto&r:R) if(r.x && a>=r.s && a<r.e &&
        (r.tag.find("libdexfile.so")!=std::string::npos||r.tag.find("libart.so")!=std::string::npos)) return true;
    return false;
}

int main(int argc,char**argv){
    if(argc<3){ fprintf(stderr,"usage: darkdex_artwalk <hostpid|pkg> <outdir>\n"); return 1; }
    int pid=atoi(argv[1]); if(pid<=0) pid=find_pid(argv[1]);
    if(pid<=0){ fprintf(stderr,"[artwalk] target not found\n"); return 1; }
    const char* outdir=argv[2];
    char mp[64]; snprintf(mp,sizeof mp,"/proc/%d/mem",pid); int fd=open(mp,O_RDONLY);
    if(fd<0){ perror("[artwalk] open mem"); return 1; }
    auto R=maps(pid);
    printf("[artwalk] pid %d — scanning heap for art::DexFile objects\n",pid);

    auto rd=[&](uint64_t a,void*b,size_t n){ return pread(fd,b,n,(off_t)a)==(ssize_t)n; };
    std::set<uint64_t> dumped; std::vector<uint8_t> buf; int found=0;

    for(auto&r:R){
        if(!r.r) continue;
        // objects live in anon/heap/dalvik regions, not in file-backed code
        if(r.tag.find(".so")!=std::string::npos||r.tag.find(".oat")!=std::string::npos||
           r.tag.find(".art")!=std::string::npos||r.tag.find(".vdex")!=std::string::npos) continue;
        uint64_t sz=r.e-r.s; if(sz==0||sz>512ULL*1024*1024) continue;
        buf.resize(sz); if(pread(fd,buf.data(),sz,(off_t)r.s)<=0) continue;
        const uint8_t* B=buf.data();
        for(size_t i=0;i+0x28<=sz;i+=8){
            uint64_t vptr=*(const uint64_t*)(B+i);
            uint64_t begin=*(const uint64_t*)(B+i+8);
            uint64_t size =*(const uint64_t*)(B+i+16);
            if(!vptr||!begin) continue;
            if(size<0x70||size>256ULL*1024*1024) continue;
            if(!in_libcode(R,vptr)) continue;                 // vtable must be in libart/libdexfile
            if(!in_readable(R,begin,0x70)) continue;
            if(!in_readable(R,begin,size)) continue;          // whole dex inside one region
            if(dumped.count(begin)) continue;

            uint8_t hdr[0x70]; if(!rd(begin,hdr,0x70)) continue;
            bool sig = !memcmp(hdr,"dex\n",4)||!memcmp(hdr,"cdex",4);
            bool tag = *(const uint32_t*)(hdr+40)==0x12345678u;   // endian_tag survives most wipes
            uint32_t fsz = *(const uint32_t*)(hdr+32);
            bool plausible = sig || tag || (fsz>0x70 && fsz<=size+0x10000);
            if(!plausible) continue;

            std::vector<uint8_t> dex(size); if(!rd(begin,dex.data(),size)) continue;
            bool is_cdex = !memcmp(dex.data(),"cdex",4) || (*(const uint32_t*)(dex.data()+36)!=0x70 && !sig);
            if(memcmp(dex.data(),"dex\n",4) && memcmp(dex.data(),"cdex",4))
                memcpy(dex.data(), is_cdex?"cdex001\0":"dex\n035\0", 8);
            dumped.insert(begin);
            char op[700]; snprintf(op,sizeof op,"%s/artwalk_%02d_%s_%llx.%s",
                outdir,found,is_cdex?"cdex":"dex",(unsigned long long)begin,is_cdex?"cdex":"dex");
            FILE* o=fopen(op,"wb"); if(o){ fwrite(dex.data(),1,size,o); fclose(o);
                printf("[+] DexFile obj @%llx  begin=%llx size=%llu %-4s -> %s\n",
                    (unsigned long long)(r.s+i),(unsigned long long)begin,(unsigned long long)size,
                    is_cdex?"cdex":"dex",op); found++; }
            i+=8;
        }
    }
    close(fd);
    printf("[artwalk] recovered %d dex from live DexFile objects.\n",found);
    return found>0?0:2;
}
