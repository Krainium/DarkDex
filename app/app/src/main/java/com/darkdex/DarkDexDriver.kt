package com.darkdex

import java.io.File

/**
 * DarkDex in-process driver (root / self-unpack path).
 *
 * The host tool reads /proc/<pid>/mem from outside the sandbox. When DarkDex runs
 * *inside* a process (self-unpack, or an injected agent), it can go straight to
 * ART's own bookkeeping instead of scanning: every loaded dex is reachable through
 * the class loader's `DexFile.mCookie`, a native array of `art::DexFile*`. This
 * driver walks those cookies and hands each pointer to the native side, which
 * validates the dex/cdex header and dumps it — no header reconstruction needed,
 * because the object-recorded bounds are authoritative.
 *
 * Native side lives in native/art_cookie.cpp (libdarkdex.so):
 *   dumpCookie(cookie, outDir) -> number of dex written
 *   cdexToDex(in, out)         -> 0 on success (native/cdex_to_dex.cpp)
 */
object DarkDexDriver {
    init {
        try { System.loadLibrary("darkdex") } catch (_: Throwable) {}
    }

    external fun dumpCookie(cookie: Long, outDir: String): Int
    external fun cdexToDex(input: String, output: String): Int

    /** Dump every dex loaded by [loader] (default: the caller's own). Returns files written. */
    fun dumpLoadedDexes(outDir: String, loader: ClassLoader = DarkDexDriver::class.java.classLoader!!): Int {
        File(outDir).mkdirs()
        var total = 0
        for (cookie in cookiesOf(loader)) {
            try { total += dumpCookie(cookie, outDir) } catch (_: Throwable) {}
        }
        // convert any CompactDex we dumped so the output decompiles
        File(outDir).listFiles { f -> f.name.endsWith(".cdex") }?.forEach {
            try { cdexToDex(it.absolutePath, it.absolutePath.removeSuffix(".cdex") + ".fromcdex.dex") } catch (_: Throwable) {}
        }
        return total
    }

    /**
     * Reflect BaseDexClassLoader -> pathList -> dexElements[] -> dexFile -> mCookie.
     * mCookie is a long[] whose [0] is the oat file and [1..] are native DexFile*.
     * We return every native pointer we can see; the native side filters non-dex.
     */
    private fun cookiesOf(loader: ClassLoader): List<Long> {
        val out = ArrayList<Long>()
        try {
            val bdcl = Class.forName("dalvik.system.BaseDexClassLoader")
            val fPathList = bdcl.getDeclaredField("pathList").apply { isAccessible = true }
            val pathList = fPathList.get(loader) ?: return out
            val fElements = pathList.javaClass.getDeclaredField("dexElements").apply { isAccessible = true }
            val elements = fElements.get(pathList) as? Array<*> ?: return out
            for (el in elements) {
                el ?: continue
                val fDexFile = el.javaClass.getDeclaredField("dexFile").apply { isAccessible = true }
                val dexFile = fDexFile.get(el) ?: continue
                val fCookie = dexFile.javaClass.getDeclaredField("mCookie").apply { isAccessible = true }
                when (val c = fCookie.get(dexFile)) {
                    is Long -> out.add(c)
                    is LongArray -> c.forEach { if (it != 0L) out.add(it) }
                    is Array<*> -> c.forEach { (it as? Long)?.let { p -> if (p != 0L) out.add(p) } }
                }
            }
        } catch (_: Throwable) {}
        return out
    }
}
