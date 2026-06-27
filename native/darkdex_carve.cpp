#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <unordered_set>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

static const uint8_t DEX_MAGIC[4]  = {0x64,0x65,0x78,0x0a};
static const uint8_t CDEX_MAGIC[4] = {0x63,0x64,0x65,0x78};

struct Region { uint64_t start, end; bool readable; std::string tag; };

static int find_pid(const char* pkg) {
    DIR* d = opendir("/proc"); if(!d) return -1;
    struct dirent* e; int pid=-1;
    while((e=readdir(d))){
        int p=atoi(e->d_name); if(p<=0) continue;
        char path[256]; snprintf(path,sizeof path,"/proc/%d/cmdline",p);
        FILE* f=fopen(path,"r"); if(!f) continue;
        char buf[256]={0}; size_t r=fread(buf,1,sizeof buf-1,f); (void)r; fclose(f);
        if(strstr(buf,pkg)){ pid=p; break; }
    }
    closedir(d); return pid;
}

static std::vector<Region> read_maps(int pid){
    std::vector<Region> v; char path[256]; snprintf(path,sizeof path,"/proc/%d/maps",pid);
    FILE* f=fopen(path,"r"); if(!f) return v; char line[1024];
    while(fgets(line,sizeof line,f)){
        uint64_t s,e; char perms[8]={0}; char name[512]={0};
        int m=sscanf(line,"%lx-%lx %7s %*x %*s %*d %511[^\n]",&s,&e,perms,name);
        if(m>=3){ Region r; r.start=s; r.end=e; r.readable=(perms[0]=='r'); r.tag=(m>=4?name:""); v.push_back(r);}
    }
    fclose(f); return v;
}

static uint32_t blob_size(const uint8_t* p, size_t avail){
    if(avail<0x70) return 0;
    if(*(const uint32_t*)(p+40)!=0x12345678u) return 0;
    uint32_t fsize=*(const uint32_t*)(p+32);
    uint32_t hsize=*(const uint32_t*)(p+36);
    if(hsize<0x28||hsize>0x200) return 0;
    if(fsize<hsize||fsize>96u*1024*1024) return 0;
    return fsize;
}

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: darkdex_carve <hostpid|pkgname> [outdir]\n"); return 1; }
    int pid=atoi(argv[1]); if(pid<=0) pid=find_pid(argv[1]);
    if(pid<=0){ fprintf(stderr,"[darkdex] target not found\n"); return 1; }
    const char* outdir=argc>2?argv[2]:".";
    printf("[darkdex] target host pid %d  outdir %s\n",pid,outdir);

    char mempath[256]; snprintf(mempath,sizeof mempath,"/proc/%d/mem",pid);
    int memfd=open(mempath,O_RDONLY);
    if(memfd<0){ perror("[darkdex] open mem (need same-uid/root + host visibility)"); return 1; }

    auto regions=read_maps(pid);
    printf("[darkdex] scanning %zu mapped regions...\n",regions.size());

    std::unordered_set<std::string> seen; int found=0; uint64_t scanned=0;
    std::vector<uint8_t> buf;
    for(auto&r:regions){
        if(!r.readable) continue;
        uint64_t size=r.end-r.start;
        if(size==0||size>1024ULL*1024*1024) continue;
        buf.resize(size);
        ssize_t n=pread(memfd,buf.data(),size,r.start);
        if(n<=0) continue; scanned+=n;
        for(size_t i=0;i+0x70<=(size_t)n;i+=4){
            if(*(uint32_t*)(buf.data()+i+40)!=0x12345678u) continue;
            uint32_t dsz=blob_size(buf.data()+i,n-i);
            if(!dsz||i+dsz>(size_t)n) continue;
            uint8_t* blob=buf.data()+i;
            bool is_cdex=(memcmp(blob,CDEX_MAGIC,4)==0)||(*(uint32_t*)(blob+36)!=0x70);

            std::string key=std::to_string(dsz)+":"; key.append((char*)blob+12,16);
            if(seen.count(key)){ i+=dsz-4; continue; } seen.insert(key);

            if(memcmp(blob,DEX_MAGIC,4)!=0 && memcmp(blob,CDEX_MAGIC,4)!=0){
                if(is_cdex) memcpy(blob,"cdex001",7); else memcpy(blob,"dex\n035",7);
            }
            char op[640]; snprintf(op,sizeof op,"%s/carve_%02d_%llx_%s.dex",outdir,found,
                (unsigned long long)(r.start+i),is_cdex?"cdex":"dex");
            FILE* o=fopen(op,"wb"); if(o){ fwrite(blob,1,dsz,o); fclose(o);
                printf("[+] %-4s @ %012llx  size %8u  region[%s]  -> %s\n",is_cdex?"cdex":"dex",
                    (unsigned long long)(r.start+i),dsz,r.tag.c_str(),op); found++; }
            i+=dsz-4;
        }
    }
    close(memfd);
    printf("[darkdex] scanned %.1f MB, carved %d dex/cdex blob(s).\n",scanned/1048576.0,found);
    return found>0?0:2;
}
