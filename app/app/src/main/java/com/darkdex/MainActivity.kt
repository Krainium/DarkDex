package com.darkdex
import android.app.AlertDialog
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.util.zip.ZipFile
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
    private lateinit var apps: List<ApplicationInfo>
    private var shown = mutableListOf<ApplicationInfo>()
    private lateinit var adapter: ArrayAdapter<String>
    private lateinit var statusTv: TextView
    private var forceNoRoot = false
    private var rootAvailable = false
    private var suCmd: List<String>? = null
    private val pm get() = packageManager

    private val suProviders: List<List<String>> = listOf(
        listOf("su"), listOf("/system/bin/su"), listOf("/system/xbin/su"),
        listOf("/sbin/su"), listOf("/debug_ramdisk/su"), listOf("/su/bin/su"),
        listOf("/sbin/magisk", "su"), listOf("/system/bin/magisk", "su"),
        listOf("/data/adb/magisk/magisk", "su"), listOf("/data/adb/ksu/bin/su")
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        apps = pm.getInstalledApplications(0).filter { it.packageName != packageName }
            .sortedBy { pm.getApplicationLabel(it).toString().lowercase() }
        shown = apps.toMutableList()
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.parseColor("#0A0A0E")) }
        root.addView(TextView(this).apply { text="DarkDex"; textSize=22f; setPadding(34,30,34,2); setTextColor(Color.parseColor("#FFB300")); setTypeface(typeface, Typeface.BOLD) })
        val bar = LinearLayout(this).apply { orientation=LinearLayout.HORIZONTAL; gravity=Gravity.CENTER_VERTICAL; setPadding(34,4,28,12) }
        statusTv = TextView(this).apply { text="root: checking…"; textSize=12f; setTextColor(Color.parseColor("#888888")); layoutParams=LinearLayout.LayoutParams(0,ViewGroup.LayoutParams.WRAP_CONTENT,1f) }
        val sw = Switch(this).apply { text="force no-root"; textSize=12f; setTextColor(Color.parseColor("#CCCCCC")); setOnCheckedChangeListener { _, c -> forceNoRoot=c; updateStatus() } }
        bar.addView(statusTv); bar.addView(sw); root.addView(bar)
        val search = EditText(this).apply { hint="Search apps…"; setHintTextColor(Color.parseColor("#555555")); setTextColor(Color.WHITE); setBackgroundColor(Color.parseColor("#16161D")); setPadding(34,24,34,24) }
        root.addView(search)
        val lv = ListView(this).apply { setBackgroundColor(Color.parseColor("#0A0A0E")); divider=null }
        adapter = object : ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, names(shown)) {
            override fun getView(p:Int, cv:View?, parent:ViewGroup):View { val v=super.getView(p,cv,parent) as TextView; v.setTextColor(Color.parseColor("#E0E0E0")); v.textSize=14f; return v }
        }
        lv.adapter=adapter
        lv.setOnItemClickListener { _,_,pos,_ -> if (pos<shown.size) dump(shown[pos].packageName) }
        search.addTextChangedListener(object: TextWatcher {
            override fun afterTextChanged(s:Editable?) { val q=s.toString().lowercase()
                shown = apps.filter { pm.getApplicationLabel(it).toString().lowercase().contains(q) || it.packageName.lowercase().contains(q) }.toMutableList()
                adapter.clear(); adapter.addAll(names(shown)); adapter.notifyDataSetChanged() }
            override fun beforeTextChanged(s:CharSequence?,a:Int,b:Int,c:Int){}; override fun onTextChanged(s:CharSequence?,a:Int,b:Int,c:Int){}
        })
        root.addView(lv); setContentView(root)
        thread { rootAvailable = (findSu()!=null); runOnUiThread { updateStatus() } }
        intent.getStringExtra("dump_pkg")?.let { dump(it) }
    }

    private fun updateStatus() {
        val noRoot = forceNoRoot || !rootAvailable
        if (noRoot) { statusTv.text = if (forceNoRoot) "mode: NO-ROOT (forced)" else "root: ✗  ·  mode: NO-ROOT"; statusTv.setTextColor(Color.parseColor("#FFB300")) }
        else { val via=suCmd?.joinToString(" ") ?: "su"; statusTv.text = "root: ✓ ($via)  ·  ROOT"; statusTv.setTextColor(Color.parseColor("#7CFC00")) }
    }
    private fun names(list:List<ApplicationInfo>) = list.map { "${pm.getApplicationLabel(it)}\n${it.packageName}" }

    private fun findSu(): List<String>? {
        suCmd?.let { return it }
        for (prov in suProviders) {
            try {
                val p = Runtime.getRuntime().exec((prov + listOf("-c", "id")).toTypedArray())
                val o = p.inputStream.bufferedReader().readText(); p.waitFor()
                if (o.contains("uid=0")) { suCmd = prov; return prov }
            } catch (_: Exception) {}
        }
        return null
    }
    private fun runSu(cmd: String): Process = Runtime.getRuntime().exec(((suCmd ?: listOf("su")) + listOf("-c", cmd)).toTypedArray())

    private fun dump(pkg: String) {
        val useRoot = !forceNoRoot && (rootAvailable || findSu()!=null)
        val badge = if (useRoot) "🔒 ROOT ✓ — full memory dump" else "📂 NO-ROOT — on-disk extraction"
        val prog = AlertDialog.Builder(this).setTitle("DarkDex").setMessage("$badge\n\nUnpacking $pkg…").setCancelable(false).create()
        prog.show()
        thread {
            val out = File(getExternalFilesDir(null), pkg).apply { mkdirs() }
            out.listFiles()?.forEach { it.delete() }
            val log: String
            if (useRoot) {
                runOnUiThread { try { pm.getLaunchIntentForPackage(pkg)?.let { startActivity(it) } } catch(_:Exception){} }
                Thread.sleep(22000)
                val bin = File(applicationInfo.nativeLibraryDir, "libdd.so").absolutePath
                var l=""
                for (a in 1..2) { val p=runSu("$bin $pkg ${out.absolutePath}"); l=(p.inputStream.bufferedReader().readText()+p.errorStream.bufferedReader().readText()).trim(); p.waitFor(); if (l.contains("DARKDEX_DONE")) break; Thread.sleep(10000) }
                log="(via ${suCmd?.joinToString(" ")})\n$l"
            } else log = extractNoRoot(pkg, out)
            val dex = out.listFiles { f -> f.name.endsWith(".dex") }?.size ?: 0
            runOnUiThread {
                try { prog.dismiss() } catch(_:Exception){}
                Toast.makeText(this, "DarkDex: $dex dex ($badge)", Toast.LENGTH_LONG).show()
                try { AlertDialog.Builder(this).setTitle("DarkDex — $pkg").setMessage("$badge\n\n✓ $dex dex → ${out.absolutePath}\n\n$log").setPositiveButton("OK",null).show() } catch(_:Exception){}
            }
        }
    }
    private fun extractNoRoot(pkg: String, out: File): String {
        val ai = pm.getApplicationInfo(pkg, 0); val srcs = mutableListOf(ai.sourceDir); ai.splitSourceDirs?.let { srcs.addAll(it) }
        var n=0
        for (src in srcs) try { ZipFile(src).use { z -> z.entries().asSequence().filter { it.name.endsWith(".dex") }.forEach { e -> File(out, "${File(src).nameWithoutExtension}_${e.name.replace('/','_')}").outputStream().use { o -> z.getInputStream(e).copyTo(o) }; n++ } } } catch(_:Exception){}
        return "Extracted $n on-disk dex from ${srcs.size} APK(s).\nUnpacked apps: real code. Packed (iJiami): on-disk stub — decrypted code needs root."
    }
}
