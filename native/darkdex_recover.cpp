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

#pragma pack(push,1)
struct MapItem { uint16_t type; uint16_t unused; uint32_t size; uint32_t offset; };
#pragma pack(pop)
enum { kHeader=0x0000,kStringId=0x0001,kTypeId=0x0002,kProtoId=0x0003,kFieldId=0x0004,
       kMethodId=0x0005,kClassDef=0x0006,kMapList=0x1000 };

static int find_pid(const char* pkg){ DIR* d=opendir("/proc"); if(!d)return -1; dirent* e; int pid=-1,best=0;
 while((e=readdir(d))){int p=atoi(e->d_name); if(p<=0)continue; char pa[256]; snprintf(pa,256,"/proc/%d/cmdline",p);
  FILE* f=fopen(pa,"r"); if(!f)continue; char b[256]={0}; size_t r=fread(b,1,255,f);(void)r; fclose(f);
  if(strstr(b,pkg)){char sp[256];snprintf(sp,256,"/proc/%d/status",p);FILE* sf=fopen(sp,"r");int rss=0;
   if(sf){char l[128];while(fgets(l,128,sf))if(!strncmp(l,"VmRSS:",6)){rss=atoi(l+6);break;}fclose(sf);} if(rss>best){best=rss;pid=p;}}}
 closedir(d); return pid; }

int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: darkdex_recover <hostpid|pkg> <outdir> [class-substr]\n");return 1;}
    int pid=atoi(argv[1]); if(pid<=0)pid=find_pid(argv[1]); if(pid<=0){fprintf(stderr,"target not found\n");return 1;}
    const char* outdir=argv[2]; const char* want=argc>3?argv[3]:nullptr;
    char mp[256]; snprintf(mp,256,"/proc/%d/mem",pid); int fd=open(mp,O_RDONLY); if(fd<0){perror("mem");return 1;}
    char mpath[256]; snprintf(mpath,256,"/proc/%d/maps",pid); FILE* mf=fopen(mpath,"r"); if(!mf)return 1;
    printf("[darkdex_recover] pid %d  — anchoring on dex map_list (header-agnostic)\n",pid);
    std::vector<uint8_t> buf; char line[1024]; int found=0; std::set<uint32_t> seen;
    while(fgets(line,sizeof line,mf)){
        uint64_t s,e; char perms[8]={0}; if(sscanf(line,"%lx-%lx %7s",&s,&e,perms)!=3)continue;
        if(perms[0]!='r')continue; uint64_t sz=e-s; if(sz==0||sz>700ULL*1024*1024)continue;
        buf.resize(sz); ssize_t n=pread(fd,buf.data(),sz,s); if(n<=0)continue; const uint8_t* B=buf.data();
        for(size_t i=4;i+64<(size_t)n;i+=4){

            const MapItem* m0=(const MapItem*)(B+i);
            const MapItem* m1=(const MapItem*)(B+i+12);
            if(m0->type!=kHeader||m0->size!=1||m0->offset!=0||m1->type!=kStringId||m1->size==0||m1->size>2000000) continue;
            uint32_t count=*(const uint32_t*)(B+i-4); if(count<5||count>40) continue;
            if(i-4 + 4 + (size_t)count*12 > (size_t)n) continue;

            uint32_t sid_s=0,sid_o=0,tid_s=0,tid_o=0,pid_s=0,pid_o=0,fid_s=0,fid_o=0,mid_s=0,mid_o=0,cd_s=0,cd_o=0,map_off=0; bool ok=true;
            for(uint32_t k=0;k<count;k++){ const MapItem* it=(const MapItem*)(B+i+(size_t)k*12);
                switch(it->type){case kStringId:sid_s=it->size;sid_o=it->offset;break;case kTypeId:tid_s=it->size;tid_o=it->offset;break;
                    case kProtoId:pid_s=it->size;pid_o=it->offset;break;case kFieldId:fid_s=it->size;fid_o=it->offset;break;
                    case kMethodId:mid_s=it->size;mid_o=it->offset;break;case kClassDef:cd_s=it->size;cd_o=it->offset;break;
                    case kMapList:map_off=it->offset;break;} }
            if(!map_off||!cd_s||!sid_s){ continue; }
            uint64_t mlist_addr = s + (i-4);
            uint64_t dex_start  = mlist_addr - map_off;
            uint32_t file_size  = map_off + 4 + count*12;
            if(dex_start < s || dex_start+file_size > e || file_size<0x70 || file_size>96u*1024*1024) continue;
            if(seen.count((uint32_t)(dex_start - s + (s&0xffffffff)))) continue;
            std::vector<uint8_t> dex(file_size);
            if(pread(fd,dex.data(),file_size,dex_start)!=(ssize_t)file_size) continue;

            if(want){ bool hit=false; for(size_t z=0;z+strlen(want)<file_size;z++) if(!memcmp(dex.data()+z,want,strlen(want))){hit=true;break;} if(!hit) continue; }

            uint8_t* H=dex.data();
            memcpy(H,"dex\n035\0",8);
            *(uint32_t*)(H+32)=file_size; *(uint32_t*)(H+36)=0x70; *(uint32_t*)(H+40)=0x12345678;
            *(uint32_t*)(H+44)=0; *(uint32_t*)(H+48)=0;
            *(uint32_t*)(H+52)=map_off;
            *(uint32_t*)(H+56)=sid_s; *(uint32_t*)(H+60)=sid_o;
            *(uint32_t*)(H+64)=tid_s; *(uint32_t*)(H+68)=tid_o;
            *(uint32_t*)(H+72)=pid_s; *(uint32_t*)(H+76)=pid_o;
            *(uint32_t*)(H+80)=fid_s; *(uint32_t*)(H+84)=fid_o;
            *(uint32_t*)(H+88)=mid_s; *(uint32_t*)(H+92)=mid_o;
            *(uint32_t*)(H+96)=cd_s;  *(uint32_t*)(H+100)=cd_o;
            uint32_t data_off=cd_o+cd_s*32; if(data_off>file_size)data_off=0x70;
            *(uint32_t*)(H+104)=file_size>data_off?file_size-data_off:0; *(uint32_t*)(H+108)=data_off;
            char op[512]; snprintf(op,512,"%s/recovered_%02d_%llx.dex",outdir,found,(unsigned long long)dex_start);
            FILE* o=fopen(op,"wb"); if(o){fwrite(dex.data(),1,file_size,o);fclose(o);
                printf("[+] RECOVERED dex @ %llx  size %u  classes %u  -> %s\n",(unsigned long long)dex_start,file_size,cd_s,op);
                found++; seen.insert((uint32_t)(dex_start-s+(s&0xffffffff)));}
            i += 12;
        }
    }
    fclose(mf); close(fd);
    printf("[darkdex_recover] recovered %d header-erased dex.\n",found);
    return found>0?0:2;
}
