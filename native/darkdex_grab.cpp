// darkdex v2 — trace grabber
// Reads darkdex_trace.bt events on stdin and, for each, snapshots the dex/cdex
// from /proc/<pid>/mem at (base,size) the moment ART opens it — before anti-scan
// header wiping. Validates, de-dups by content, and writes to <outdir>.
//
//   bpftrace darkdex_trace.bt | darkdex_grab <outdir>
//
// Event lines (from the tracer):
//   DEXOPEN  pid=<d> base=<hex> size=<d>
//   CDEXOPEN pid=<d> base=<hex> size=<d>
//   CLASS    pid=<d> name=<descriptor>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <set>
#include <fcntl.h>
#include <unistd.h>

static uint64_t fnv1a(const uint8_t* p, size_t n){
    uint64_t h=1469598103934665603ULL;
    for(size_t i=0;i<n;i++){ h^=p[i]; h*=1099511628211ULL; }
    return h;
}

// A dex/cdex the packer just handed ART is valid: endian tag + sane sizes.
static uint32_t validate(const uint8_t* p, size_t n, bool& is_cdex){
    if(n<0x70) return 0;
    if(*(const uint32_t*)(p+40)!=0x12345678u) return 0;          // endian_tag
    uint32_t fsize=*(const uint32_t*)(p+32);
    uint32_t hsize=*(const uint32_t*)(p+36);
    if(hsize<0x28||hsize>0x200) return 0;
    if(fsize<hsize||fsize>256u*1024*1024) return 0;
    is_cdex = (!memcmp(p,"cdex",4)) || (hsize!=0x70);
    return fsize;
}

// keep only events from processes whose cmdline contains `pkg` (catches respawns
// and worker threads without a fragile in-kernel comm/pid filter)
static bool pid_matches(long pid, const char* pkg){
    if(!pkg) return true;
    char p[64]; snprintf(p,sizeof p,"/proc/%ld/cmdline",pid);
    FILE* f=fopen(p,"r"); if(!f) return false;
    char b[512]={0}; size_t n=fread(b,1,sizeof b-1,f); fclose(f);
    for(size_t i=0;i+1<n;i++) if(!b[i]) b[i]=' ';   // NUL -> space
    return strstr(b,pkg)!=nullptr;
}

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: darkdex_grab <outdir> [package-substr]\n"); return 1; }
    const char* outdir=argv[1];
    const char* pkg=argc>2?argv[2]:nullptr;
    std::set<uint64_t> seen;                 // content hashes -> de-dup
    std::set<std::string> classes;
    char line[4096]; int saved=0; int nclass=0;
    FILE* clog=nullptr; { char p[600]; snprintf(p,sizeof p,"%s/classes.trace.txt",outdir); clog=fopen(p,"w"); }

    while(fgets(line,sizeof line,stdin)){
        bool cdex_evt = !strncmp(line,"CDEXOPEN",8);
        if(!strncmp(line,"CLASS",5)){
            char* pp=strstr(line,"pid="); long cpid=pp?strtol(pp+4,0,10):0;
            char* nm=strstr(line,"name="); if(nm && pid_matches(cpid,pkg)){ nm+=5; nm[strcspn(nm,"\r\n")]=0;
                if(classes.insert(nm).second){ nclass++; if(clog){ fprintf(clog,"%s\n",nm); fflush(clog);} } }
            continue;
        }
        if(strncmp(line,"DEXOPEN",7) && !cdex_evt) continue;
        long pid=0; unsigned long base=0, size=0;
        char* a=strstr(line,"pid="); char* b=strstr(line,"base="); char* c=strstr(line,"size=");
        if(!a||!b||!c) continue;
        pid=strtol(a+4,0,10); base=strtoul(b+5,0,16); size=strtoul(c+5,0,10);
        if(!pid||!base||size<0x70||size>256u*1024*1024) continue;
        if(!pid_matches(pid,pkg)) continue;

        char mp[64]; snprintf(mp,sizeof mp,"/proc/%ld/mem",pid);
        int fd=open(mp,O_RDONLY); if(fd<0){ perror("[grab] open mem"); continue; }
        std::string buf; buf.resize(size);
        ssize_t n=pread(fd,&buf[0],size,(off_t)base); close(fd);
        if(n<=0){ continue; }
        const uint8_t* p=(const uint8_t*)buf.data();

        bool is_cdex=false; uint32_t fsz=validate(p,(size_t)n,is_cdex);
        if(!fsz){                 // header may already be partially set up; stamp+keep anyway
            is_cdex=cdex_evt;
        } else if(fsz<(uint32_t)n){ buf.resize(fsz); n=fsz; p=(const uint8_t*)buf.data(); }

        uint64_t h=fnv1a(p,(size_t)n);
        if(!seen.insert(h).second) continue;    // already grabbed this exact dex

        // stamp a clean magic if the packer left it blank
        if(memcmp(p,"dex\n",4) && memcmp(p,"cdex",4))
            memcpy(&buf[0], is_cdex?"cdex001\0":"dex\n035\0", 8);

        char op[700]; snprintf(op,sizeof op,"%s/trace_%02d_%s_%lx.%s",
                               outdir, saved, is_cdex?"cdex":"dex", base, is_cdex?"cdex":"dex");
        FILE* o=fopen(op,"wb");
        if(o){ fwrite(buf.data(),1,n,o); fclose(o);
            printf("[grab] %-4s pid=%ld @%lx %zdB -> %s\n", is_cdex?"cdex":"dex", pid, base, (ssize_t)n, op);
            fflush(stdout); saved++; }
    }
    if(clog) fclose(clog);
    fprintf(stderr,"[darkdex_grab] captured %d unique dex/cdex, %d classes\n",saved,nclass);
    return 0;
}
