package com.darkdex
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.*
import android.view.Gravity
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class SplashActivity : AppCompatActivity() {
    override fun onCreate(s: Bundle?) {
        super.onCreate(s)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#0A0A0E"))
        }
        root.addView(TextView(this).apply {
            text = "DarkDex"; textSize = 52f; gravity = Gravity.CENTER
            setTextColor(Color.parseColor("#FFB300")); typeface = Typeface.DEFAULT_BOLD
        })
        root.addView(TextView(this).apply {
            text = "by Krainium"; textSize = 17f; gravity = Gravity.CENTER
            setTextColor(Color.parseColor("#7CFC00")); setPadding(0, 28, 0, 0)
        })
        root.addView(TextView(this).apply {
            text = "iJiami dex unpacker"; textSize = 12f; gravity = Gravity.CENTER
            setTextColor(Color.parseColor("#666666")); setPadding(0, 60, 0, 0)
        })
        setContentView(root)
        Handler(Looper.getMainLooper()).postDelayed({
            startActivity(Intent(this, MainActivity::class.java)); finish()
        }, 2000)
    }
}
