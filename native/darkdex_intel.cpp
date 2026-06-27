#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <set>
#include <map>
#include <vector>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

static int find_pid(const char* pkg){
    DIR* d=opendir("/proc"); if(!d) return -1; struct dirent* e; int pid=-1,best=0;
    while((e=readdir(d))){ int p=atoi(e->d_name); if(p<=0) continue;
        char pa[256]; snprintf(pa,sizeof pa,"/proc/%d/cmdline",p); FILE* f=fopen(pa,"r"); if(!f) continue;
        char b[256]={0}; size_t r=fread(b,1,255,f);(void)r; fclose(f);
        if(strstr(b,pkg)){ char sp[256]; snprintf(sp,sizeof sp,"/proc/%d/status",p); FILE* sf=fopen(sp,"r"); int rss=0;
            if(sf){char l[128]; while(fgets(l,128,sf)) if(!strncmp(l,"VmRSS:",6)){rss=atoi(l+6);break;} fclose(sf);}
            if(rss>best){best=rss;pid=p;} } }
    closedir(d); return pid;
}
static bool urlchar(uint8_t c){ return c>0x20 && c<0x7f && c!='"' && c!='\'' && c!='<' && c!='>' && c!='\\' && c!=')' && c!='('; }

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: darkdex_intel <hostpid|pkgname> [outfile]\n"); return 1; }
    int pid=atoi(argv[1]); if(pid<=0) pid=find_pid(argv[1]);
    if(pid<=0){ fprintf(stderr,"[darkdex] target not found\n"); return 1; }
    FILE* out = argc>2 ? fopen(argv[2],"w") : stdout;
    char mp[256]; snprintf(mp,sizeof mp,"/proc/%d/mem",pid);
    int fd=open(mp,O_RDONLY); if(fd<0){ perror("open mem"); return 1; }
    char maps[256]; snprintf(maps,sizeof maps,"/proc/%d/maps",pid); FILE* mf=fopen(maps,"r");
    if(!mf){ perror("maps"); return 1; }

    std::set<std::string> urls, hosts, classes, pkgs, configs, packer;
    std::vector<uint8_t> buf; char line[1024]; uint64_t scanned=0;
    while(fgets(line,sizeof line,mf)){
        uint64_t s,e; char perms[8]={0};
        if(sscanf(line,"%lx-%lx %7s",&s,&e,perms)!=3) continue;
        if(perms[0]!='r') continue; uint64_t sz=e-s;
        if(sz==0||sz>600ULL*1024*1024) continue; buf.resize(sz);
        ssize_t n=pread(fd,buf.data(),sz,s); if(n<=0) continue; scanned+=n;
        const uint8_t* p=buf.data();
        for(size_t i=0;i+8<(size_t)n;i++){

            if(!memcmp(p+i,"http",4) && (!memcmp(p+i,"http://",7)||!memcmp(p+i,"https://",8))){
                size_t j=i; std::string u; while(j<(size_t)n && urlchar(p[j]) && u.size()<256){ u+=(char)p[j]; j++; }
                if(u.size()>10){ urls.insert(u);
                    size_t h=u.find("//"); if(h!=std::string::npos){ size_t k=u.find('/',h+2); hosts.insert(u.substr(h+2,(k==std::string::npos?u.size():k)-h-2)); }
                }
                i=j;
            }

            else if(p[i]=='L' && (!memcmp(p+i,"Lcom/",5)||!memcmp(p+i,"Lcn/",4)||!memcmp(p+i,"Lio/",4)||!memcmp(p+i,"Lorg/",5))){
                size_t j=i+1; std::string c; while(j<(size_t)n && (isalnum(p[j])||p[j]=='/'||p[j]=='_'||p[j]=='$') && c.size()<120){ c+=(char)p[j]; j++; }
                if(j<(size_t)n && p[j]==';' && c.size()>6){
                    if(c.find("ijiami")!=std::string::npos||c.find("secneo")!=std::string::npos||c.find("uyumao")!=std::string::npos) packer.insert(c);
                    else if(c.find("brasiltv")!=std::string::npos||c.find("youcine")!=std::string::npos) classes.insert(c);
                }
                i=j;
            }

            else if(!memcmp(p+i,"\"appId\"",7)||!memcmp(p+i,"\"apkVersion\"",12)||!memcmp(p+i,"\"deviceId\"",10)){
                size_t j=i; std::string c; while(j<(size_t)n && p[j]>=0x20 && p[j]<0x7f && c.size()<160){ c+=(char)p[j]; j++; } configs.insert(c); i=j;
            }
        }
    }
    fclose(mf); close(fd);
    auto dump=[&](const char*t,std::set<std::string>&s,int lim){ fprintf(out,"\n=== %s (%zu) ===\n",t,s.size()); int k=0; for(auto&x:s){ if(k++>=lim)break; fprintf(out,"  %s\n",x.c_str()); } };
    fprintf(out,"# darkdex intel — pid %d — scanned %.0f MB\n",pid,scanned/1048576.0);

    std::set<std::string> backend; for(auto&h:hosts) if(h.find("google")==std::string::npos&&h.find("android")==std::string::npos&&h.find("gstatic")==std::string::npos&&h.find("schemas")==std::string::npos) backend.insert(h);
    dump("BACKEND HOSTS",backend,60);
    dump("URLs",urls,80);
    dump("APP CONFIG",configs,15);
    dump("PACKER FINGERPRINT (iJiami/uyumao)",packer,30);
    dump("APP CLASS MAP (brasiltv/youcine)",classes,60);
    if(out!=stdout) fclose(out);
    fprintf(stderr,"[darkdex] intel: %zu urls, %zu backend hosts, %zu app classes, %zu packer classes\n",urls.size(),backend.size(),classes.size(),packer.size());
    return 0;
}
