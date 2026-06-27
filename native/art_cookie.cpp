#include <jni.h>
#include <android/log.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#define LOG(...) __android_log_print(ANDROID_LOG_INFO,"darkdex",__VA_ARGS__)

extern "C" JNIEXPORT jint JNICALL
Java_com_darkdex_DarkDexDriver_dumpCookie(JNIEnv* env, jobject, jlong cookie, jstring joutdir) {
    const char* outdir = env->GetStringUTFChars(joutdir, nullptr);
    int dumped = 0;

    uintptr_t* slots = reinterpret_cast<uintptr_t*>(cookie);
    for (int i = 0; i < 32; ++i) {
        uintptr_t cand = 0;
        if (__builtin_expect(reinterpret_cast<uintptr_t>(slots) < 0x1000, 0)) break;
        memcpy(&cand, &slots[i], sizeof(cand));
        if (cand < 0x10000) continue;
        const uint8_t* p = reinterpret_cast<const uint8_t*>(cand);
        bool dex  = !memcmp(p, "dex\n", 4);
        bool cdex = !memcmp(p, "cdex", 4);
        if ((dex || cdex) && *reinterpret_cast<const uint32_t*>(p+40) == 0x12345678u) {
            uint32_t fsz = *reinterpret_cast<const uint32_t*>(p+32);
            if (fsz > 0x70 && fsz < 64u*1024*1024) {
                char path[512]; snprintf(path,sizeof path,"%s/cookie_%d_%s.%s",outdir,dumped,
                                         cdex?"cdex":"dex", cdex?"cdex":"dex");
                FILE* o = fopen(path,"wb");
                if (o){ fwrite(p,1,fsz,o); fclose(o); LOG("dumped %s (%u bytes)",path,fsz); dumped++; }
            }
        }
    }
    env->ReleaseStringUTFChars(joutdir, outdir);
    return dumped;
}

namespace darkdex { int convert(const uint8_t*, size_t, std::vector<uint8_t>&); }
extern "C" JNIEXPORT jint JNICALL
Java_com_darkdex_DarkDexDriver_cdexToDex(JNIEnv* env, jobject, jstring jin, jstring jout) {
    const char* in = env->GetStringUTFChars(jin,nullptr); const char* out = env->GetStringUTFChars(jout,nullptr);
    FILE* f=fopen(in,"rb"); int rc=-1;
    if(f){ fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET); std::vector<uint8_t> b(n); size_t r=fread(b.data(),1,n,f);(void)r; fclose(f);
        std::vector<uint8_t> o; rc=darkdex::convert(b.data(),b.size(),o);
        if(rc==0){ FILE* of=fopen(out,"wb"); if(of){fwrite(o.data(),1,o.size(),of);fclose(of);} } }
    env->ReleaseStringUTFChars(jin,in); env->ReleaseStringUTFChars(jout,out); return rc;
}
