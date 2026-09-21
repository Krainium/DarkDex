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
static bool spans_readable(const std::vector<Region>&R,uint64_t a,uint64_t need){
    if(in_readable(R,a,need)) return true;
    uint64_t end=a+need; uint64_t cur=a;
    for(auto&r:R){
        if(!r.r) continue;
        if(r.s>cur) return false;
        if(r.s<=cur && r.e>cur){ cur=r.e; if(cur>=end) return true; }
    }
    return false;
}
static bool in_libcode(const std::vector<Region>&R,uint64_t a){
    for(auto&r:R) if(r.x && a>=r.s && a<r.e &&
        (r.tag.find("libdexfile.so")!=std::string::npos||r.tag.find("libart.so")!=std::string::npos||
         r.tag.find("libdexfile_external.so")!=std::string::npos)) return true;
    return false;
}

static std::vector<std::pair<uint64_t,uint64_t>> load_locs(const char* path){
    std::vector<std::pair<uint64_t,uint64_t>> v;
    FILE* f=fopen(path,"r"); if(!f) return v;
    unsigned long base; size_t size;
    while(fscanf(f,"%lx %zu",&base,&size)==2) v.push_back({(uint64_t)base,(uint64_t)size});
    fclose(f); return v;
}

static int calibrate_begin_offset(int fd, const std::vector<Region>& R,
                                   const std::vector<std::pair<uint64_t,uint64_t>>& locs){
    if(locs.empty()) return -1;
    int hits8=0, hits16=0;
    for(auto& r : R){
        if(!r.r) continue;
        if(r.tag.find(".so")!=std::string::npos||r.tag.find(".oat")!=std::string::npos) continue;
        uint64_t sz=r.e-r.s; if(sz==0||sz>64ULL*1024*1024) continue;
        std::vector<uint8_t> buf(sz);
        if(pread(fd,buf.data(),sz,(off_t)r.s)<=0) continue;
        const uint8_t* B=buf.data();
        for(size_t i=0;i+0x28<=sz;i+=8){
            uint64_t v8 =*(const uint64_t*)(B+i+8);
            uint64_t v16=*(const uint64_t*)(B+i+16);
            for(auto& [base,size]: locs){
                if(v8 ==base) hits8++;
                if(v16==base) hits16++;
            }
        }
        if(hits8>0||hits16>0) break;
    }
    if(hits8>hits16) return 8;
    if(hits16>hits8) return 16;
    return -1;
}

int main(int argc,char**argv){
    if(argc<3){ fprintf(stderr,"usage: darkdex_artwalk <hostpid|pkg> <outdir> [--calibrate <locs.txt>]\n"); return 1; }
    int pid=atoi(argv[1]); if(pid<=0) pid=find_pid(argv[1]);
    if(pid<=0){ fprintf(stderr,"[artwalk] target not found\n"); return 1; }
    const char* outdir=argv[2];

    std::vector<std::pair<uint64_t,uint64_t>> calib_locs;
    for(int i=3;i<argc-1;i++){
        if(!strcmp(argv[i],"--calibrate")) calib_locs=load_locs(argv[i+1]);
    }
    char mp[64]; snprintf(mp,sizeof mp,"/proc/%d/mem",pid); int fd=open(mp,O_RDONLY);
    if(fd<0){ perror("[artwalk] open mem"); return 1; }
    auto R=maps(pid);
    printf("[artwalk] pid %d — scanning heap for art::DexFile objects\n",pid);

    int begin_off = 8;
    if(!calib_locs.empty()){
        int det = calibrate_begin_offset(fd, R, calib_locs);
        if(det > 0){ begin_off = det; printf("[artwalk] calibrated begin_ offset: +%d\n",begin_off); }
        else printf("[artwalk] calibration inconclusive; using default offset +%d\n",begin_off);
    }

    auto rd=[&](uint64_t a,void*b,size_t n){ return pread(fd,b,n,(off_t)a)==(ssize_t)n; };
    std::set<uint64_t> dumped; std::vector<uint8_t> buf; int found=0;

    for(auto&r:R){
        if(!r.r) continue;
        if(r.tag.find(".so")!=std::string::npos||r.tag.find(".oat")!=std::string::npos||
           r.tag.find(".art")!=std::string::npos||r.tag.find(".vdex")!=std::string::npos) continue;
        uint64_t sz=r.e-r.s; if(sz==0||sz>512ULL*1024*1024) continue;
        buf.resize(sz); if(pread(fd,buf.data(),sz,(off_t)r.s)!=(ssize_t)sz) continue;
        const uint8_t* B=buf.data();
        for(size_t i=0;i+0x28<=sz;i+=8){
            uint64_t vptr=*(const uint64_t*)(B+i);
            uint64_t begin=*(const uint64_t*)(B+i+begin_off);
            uint64_t size =*(const uint64_t*)(B+i+begin_off+8);
            if(!vptr||!begin) continue;
            if(size<0x70||size>256ULL*1024*1024) continue;
            if(begin + size <= begin) continue;
            if(!in_libcode(R,vptr)) continue;
            if(!in_readable(R,begin,0x70)) continue;
            if(!spans_readable(R,begin,size)) continue;
            if(dumped.count(begin)) continue;

            uint8_t hdr[0x70]; if(!rd(begin,hdr,0x70)) continue;
            bool sig = !memcmp(hdr,"dex\n",4)||!memcmp(hdr,"cdex",4);
            bool tag = *(const uint32_t*)(hdr+40)==0x12345678u;
            uint32_t fsz = *(const uint32_t*)(hdr+32);
            bool plausible = sig || tag || (fsz>0x70 && fsz<=size+0x10000);
            if(!plausible) continue;

            std::vector<uint8_t> dex(size);
            size_t got=0; uint64_t addr=begin;
            while(got<size){
                ssize_t rd2=pread(fd,dex.data()+got,size-got,(off_t)addr);
                if(rd2<=0) break;
                got+=rd2; addr+=rd2;
            }
            if(got<size) continue;
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
