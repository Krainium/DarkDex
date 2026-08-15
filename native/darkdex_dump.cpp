// darkdex v2 — on-device combined engine (shipped in the APK as lib/<abi>/libdd.so
// and run by the app via `su`). One /proc/<pid>/mem pass does:
//   1. carve     — scan for dex/cdex by header/endian-tag
//   2. recover   — header-agnostic, anchor on map_list (header wiped)
//   3. artwalk   — recover from live art::DexFile heap objects (header AND
//                  map_list wiped) — v2
//   4. intel     — mine urls / hosts / class map / packer fingerprint
//   5. cdex->dex — expand any CompactDex so dumps decompile — v2
// The host-side JIT tracer (darkdex_trace.bt) is a separate, host-only tool
// (needs bpftrace); on-device this engine is the recovery core.
//
// Build (static, so it runs on Android under su):
//   g++ -O2 -std=c++17 -static -o libdd darkdex_dump.cpp cdex_to_dex.cpp
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

namespace darkdex { int convert(const uint8_t*, size_t, std::vector<uint8_t>&, const uint8_t*, size_t); }

static const uint8_t DEXM[4]={0x64,0x65,0x78,0x0a}, CDEXM[4]={0x63,0x64,0x65,0x78};
#pragma pack(push,1)
struct MapItem{uint16_t type;uint16_t un;uint32_t size;uint32_t off;};
#pragma pack(pop)
struct Region{uint64_t s,e;bool r,x;std::string tag;};

static int find_pid(const char*pkg){DIR*d=opendir("/proc");if(!d)return -1;dirent*e;int pid=-1,best=0;
 while((e=readdir(d))){int p=atoi(e->d_name);if(p<=0)continue;char pa[256];snprintf(pa,256,"/proc/%d/cmdline",p);
  FILE*f=fopen(pa,"r");if(!f)continue;char b[256]={0};size_t r=fread(b,1,255,f);(void)r;fclose(f);
  if(!strcmp(b,pkg)){char sp[256];snprintf(sp,256,"/proc/%d/status",p);FILE*sf=fopen(sp,"r");int rss=0;
   if(sf){char l[128];while(fgets(l,128,sf))if(!strncmp(l,"VmRSS:",6)){rss=atoi(l+6);break;}fclose(sf);}if(rss>best){best=rss;pid=p;}}}
 closedir(d);return pid;}
static std::vector<Region> read_maps(int pid){std::vector<Region> v;char p[64];snprintf(p,64,"/proc/%d/maps",pid);
 FILE*f=fopen(p,"r");if(!f)return v;char line[1024];
 while(fgets(line,sizeof line,f)){uint64_t s,e;char pm[8]={0},nm[512]={0};
  int m=sscanf(line,"%lx-%lx %7s %*x %*s %*d %511[^\n]",&s,&e,pm,nm);
  if(m>=3){Region r;r.s=s;r.e=e;r.r=pm[0]=='r';r.x=pm[2]=='x';r.tag=(m>=4?nm:"");v.push_back(r);} }
 fclose(f);return v;}
static bool urlc(uint8_t c){return c>0x20&&c<0x7f&&c!='"'&&c!='\''&&c!='<'&&c!='>'&&c!='\\'&&c!=')'&&c!='(';}
static uint32_t carve_size(const uint8_t*p,size_t a){if(a<0x70)return 0;if(*(uint32_t*)(p+40)!=0x12345678u)return 0;
 uint32_t fs=*(uint32_t*)(p+32),hs=*(uint32_t*)(p+36);if(hs<0x28||hs>0x200)return 0;if(fs<hs||fs>96u*1024*1024)return 0;return fs;}
static bool inreadable(const std::vector<Region>&R,uint64_t a,uint64_t n){for(auto&r:R)if(r.r&&a>=r.s&&a+n<=r.e)return true;return false;}
static bool inlibcode(const std::vector<Region>&R,uint64_t a){for(auto&r:R)if(r.x&&a>=r.s&&a<r.e&&
 (r.tag.find("libdexfile.so")!=std::string::npos||r.tag.find("libart.so")!=std::string::npos))return true;return false;}

int main(int argc,char**argv){
 if(argc<3){fprintf(stderr,"usage: %s <package> <outdir>\n",argv[0]);return 1;}
 const char*pkg=argv[1];const char*out=argv[2];
 int pid=-1; for(int _t=0;_t<30&&pid<=0;_t++){pid=find_pid(pkg); if(pid<=0)sleep(1);} if(pid>0)sleep(8);
 if(pid<=0){printf("DARKDEX_ERR target not running: %s\n",pkg);return 2;}
 printf("DARKDEX target=%s pid=%d out=%s\n",pkg,pid,out);
 char mp[256];snprintf(mp,256,"/proc/%d/mem",pid);int fd=open(mp,O_RDONLY);
 if(fd<0){printf("DARKDEX_ERR open mem failed (need root)\n");return 3;}
 auto R=read_maps(pid);
 std::vector<uint8_t> buf;int dex=0,rec=0,art=0;std::set<std::string> seenC,seenR;std::set<uint64_t> seenA;
 std::set<std::string> urls,hosts,classes,packer,cfgs;

 for(auto&r:R){
  if(!r.r)continue;uint64_t sz=r.e-r.s;if(sz==0||sz>900ULL*1024*1024)continue;
  buf.resize(sz);ssize_t n=pread(fd,buf.data(),sz,r.s);if(n<=0)continue;const uint8_t*B=buf.data();

  // 1. carve
  for(size_t i=0;i+0x70<=(size_t)n;i+=4){
   if(*(uint32_t*)(B+i+40)!=0x12345678u)continue;uint32_t ds=carve_size(B+i,n-i);if(!ds||i+ds>(size_t)n)continue;
   const uint8_t*bl=B+i;bool cd=(!memcmp(bl,CDEXM,4))||(*(uint32_t*)(bl+36)!=0x70);
   std::string k=std::to_string(ds)+":";k.append((char*)bl+12,16);if(seenC.count(k)){i+=ds-4;continue;}seenC.insert(k);
   std::vector<uint8_t> o(bl,bl+ds);if(memcmp(o.data(),DEXM,4)&&memcmp(o.data(),CDEXM,4))memcpy(o.data(),cd?"cdex001":"dex\n035",7);
   char op[640];snprintf(op,640,"%s/carve_%02d_%s.%s",out,dex,cd?"cdex":"dex",cd?"cdex":"dex");FILE*of=fopen(op,"wb");
   if(of){fwrite(o.data(),1,ds,of);fclose(of);dex++;}i+=ds-4;
  }
  // 2. recover (map_list anchored)
  for(size_t i=4;i+64<(size_t)n;i+=4){
   const MapItem*m0=(const MapItem*)(B+i),*m1=(const MapItem*)(B+i+12);
   if(m0->type!=0||m0->size!=1||m0->off!=0||m1->type!=1||m1->size==0||m1->size>2000000)continue;
   uint32_t cnt=*(uint32_t*)(B+i-4);if(cnt<5||cnt>40||i-4+4+(size_t)cnt*12>(size_t)n)continue;
   uint32_t sids=0,sido=0,tids=0,tido=0,pids=0,pido=0,fids=0,fido=0,mids=0,mido=0,cds=0,cdo=0,moff=0;
   for(uint32_t k=0;k<cnt;k++){const MapItem*it=(const MapItem*)(B+i+(size_t)k*12);switch(it->type){
    case 1:sids=it->size;sido=it->off;break;case 2:tids=it->size;tido=it->off;break;case 3:pids=it->size;pido=it->off;break;
    case 4:fids=it->size;fido=it->off;break;case 5:mids=it->size;mido=it->off;break;case 6:cds=it->size;cdo=it->off;break;
    case 0x1000:moff=it->off;break;}}
   if(!moff||!cds||!sids)continue;uint64_t mla=r.s+(i-4),dst=mla-moff;uint32_t fsz=moff+4+cnt*12;
   if(dst<r.s||dst+fsz>r.e||fsz<0x70||fsz>96u*1024*1024)continue;
   std::string rk=std::to_string(dst)+":"+std::to_string(fsz);if(seenR.count(rk)){i+=12;continue;}seenR.insert(rk);
   std::vector<uint8_t> dx(fsz);if(pread(fd,dx.data(),fsz,dst)!=(ssize_t)fsz){i+=12;continue;}
   uint8_t*H=dx.data();memcpy(H,"dex\n035\0",8);*(uint32_t*)(H+32)=fsz;*(uint32_t*)(H+36)=0x70;*(uint32_t*)(H+40)=0x12345678;
   *(uint32_t*)(H+52)=moff;*(uint32_t*)(H+56)=sids;*(uint32_t*)(H+60)=sido;*(uint32_t*)(H+64)=tids;*(uint32_t*)(H+68)=tido;
   *(uint32_t*)(H+72)=pids;*(uint32_t*)(H+76)=pido;*(uint32_t*)(H+80)=fids;*(uint32_t*)(H+84)=fido;*(uint32_t*)(H+88)=mids;
   *(uint32_t*)(H+92)=mido;*(uint32_t*)(H+96)=cds;*(uint32_t*)(H+100)=cdo;uint32_t doff=cdo+cds*32;if(doff>fsz)doff=0x70;
   *(uint32_t*)(H+104)=fsz>doff?fsz-doff:0;*(uint32_t*)(H+108)=doff;
   char op[640];snprintf(op,640,"%s/recovered_%02d.dex",out,rec);FILE*of=fopen(op,"wb");if(of){fwrite(dx.data(),1,fsz,of);fclose(of);rec++;}i+=12;
  }
  // 3. artwalk — live art::DexFile objects (v2): [vptr][begin_][size_] ...
  if(r.tag.find(".so")==std::string::npos&&r.tag.find(".oat")==std::string::npos&&
     r.tag.find(".art")==std::string::npos&&r.tag.find(".vdex")==std::string::npos){
   for(size_t i=0;i+0x28<=(size_t)n;i+=8){
    uint64_t vptr=*(uint64_t*)(B+i),begin=*(uint64_t*)(B+i+8),size=*(uint64_t*)(B+i+16);
    if(!vptr||!begin||size<0x70||size>256ULL*1024*1024)continue;
    if(!inlibcode(R,vptr)||!inreadable(R,begin,size)||seenA.count(begin))continue;
    uint8_t hdr[0x70];if(pread(fd,hdr,0x70,begin)!=0x70)continue;
    bool sig=!memcmp(hdr,"dex\n",4)||!memcmp(hdr,"cdex",4);bool tag=*(uint32_t*)(hdr+40)==0x12345678u;
    uint32_t fs=*(uint32_t*)(hdr+32);if(!(sig||tag||(fs>0x70&&fs<=size+0x10000)))continue;
    std::vector<uint8_t> dx(size);if(pread(fd,dx.data(),size,begin)!=(ssize_t)size)continue;
    bool cd=!memcmp(dx.data(),CDEXM,4)||(*(uint32_t*)(dx.data()+36)!=0x70&&!sig);
    if(memcmp(dx.data(),DEXM,4)&&memcmp(dx.data(),CDEXM,4))memcpy(dx.data(),cd?"cdex001\0":"dex\n035\0",8);
    seenA.insert(begin);
    char op[640];snprintf(op,640,"%s/artwalk_%02d_%s.%s",out,art,cd?"cdex":"dex",cd?"cdex":"dex");
    FILE*of=fopen(op,"wb");if(of){fwrite(dx.data(),1,size,of);fclose(of);art++;}i+=8;
   }
  }
  // 4. intel
  for(size_t i=0;i+8<(size_t)n;i++){
   if(!memcmp(B+i,"http",4)&&(!memcmp(B+i,"http://",7)||!memcmp(B+i,"https://",8))){size_t j=i;std::string u;
    while(j<(size_t)n&&urlc(B[j])&&u.size()<256){u+=(char)B[j];j++;}if(u.size()>10){urls.insert(u);
     size_t h=u.find("//");if(h!=std::string::npos){size_t k=u.find('/',h+2);hosts.insert(u.substr(h+2,(k==std::string::npos?u.size():k)-h-2));}}i=j;}
   else if(B[i]=='L'&&(!memcmp(B+i,"Lcom/",5)||!memcmp(B+i,"Lcn/",4)||!memcmp(B+i,"Lio/",4)||!memcmp(B+i,"Lorg/",5))){
    size_t j=i+1;std::string c;while(j<(size_t)n&&(isalnum(B[j])||B[j]=='/'||B[j]=='_'||B[j]=='$')&&c.size()<120){c+=(char)B[j];j++;}
    if(j<(size_t)n&&B[j]==';'&&c.size()>6){if(c.find("ijiami")!=std::string::npos||c.find("uyumao")!=std::string::npos||c.find("secneo")!=std::string::npos)packer.insert(c);else classes.insert(c);}i=j;}
   else if(!memcmp(B+i,"\"appId\"",7)||!memcmp(B+i,"\"apkVersion\"",12)){size_t j=i;std::string c;while(j<(size_t)n&&B[j]>=0x20&&B[j]<0x7f&&c.size()<160){c+=(char)B[j];j++;}cfgs.insert(c);i=j;}
  }
 }
 close(fd);

 // 5. cdex -> dex so dumps decompile (v2)
 int conv=0;{DIR*d=opendir(out);if(d){dirent*e;while((e=readdir(d))){const char*nm=e->d_name;size_t L=strlen(nm);
  if(L>5&&!strcmp(nm+L-5,".cdex")){char ip[700];snprintf(ip,700,"%s/%s",out,nm);
   FILE*f=fopen(ip,"rb");if(!f)continue;fseek(f,0,SEEK_END);long fl=ftell(f);fseek(f,0,SEEK_SET);
   std::vector<uint8_t> in(fl);size_t rr=fread(in.data(),1,fl,f);(void)rr;fclose(f);std::vector<uint8_t> o;
   if(darkdex::convert(in.data(),in.size(),o,nullptr,0)<=0&&!o.empty()){
    char op[760];snprintf(op,760,"%s/%.*s.fromcdex.dex",out,(int)(L-5),nm);
    FILE*of=fopen(op,"wb");if(of){fwrite(o.data(),1,o.size(),of);fclose(of);conv++;}}}}closedir(d);}}

 char ip[640];snprintf(ip,640,"%s/intel.txt",out);FILE*io=fopen(ip,"w");
 if(io){fprintf(io,"# darkdex intel %s pid %d\n## PACKER\n",pkg,pid);for(auto&x:packer)fprintf(io,"  %s\n",x.c_str());
  fprintf(io,"## HOSTS\n");int z=0;for(auto&x:hosts){if(z++>120)break;fprintf(io,"  %s\n",x.c_str());}
  fprintf(io,"## CONFIG\n");for(auto&x:cfgs)fprintf(io,"  %s\n",x.c_str());
  fprintf(io,"## CLASSES(%zu)\n",classes.size());z=0;for(auto&x:classes){if(z++>400)break;fprintf(io,"  %s\n",x.c_str());}fclose(io);}
 printf("DARKDEX_DONE dex=%d recovered=%d artwalk=%d cdex2dex=%d urls=%zu classes=%zu packer=%zu\n",
        dex,rec,art,conv,urls.size(),classes.size(),packer.size());
 return 0;
}
