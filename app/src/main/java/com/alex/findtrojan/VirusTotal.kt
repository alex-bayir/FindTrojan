package com.alex.findtrojan

import android.graphics.Color
import android.os.Handler
import android.os.Looper
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.*
import java.security.MessageDigest

class VirusTotal(val file: File, val algorithm:String) {
    constructor(file:File):this(file,"SHA-256")
    val hash=getHash(FileInputStream(file),algorithm).fold(""){str,it->str+"%02x".format(it)}
    fun check(callback: (Any) -> Unit){
        try{
            val response=OkHttpClient().newCall(Request.Builder().url("https://www.virustotal.com/vtapi/v2/file/report?apikey=$apikey&resource=$hash").build()).execute()
            val json=JSONObject(response.body?.string()?:"")
            Handler(Looper.getMainLooper()).post{callback(json)}
        }catch (e:IOException){
            e.printStackTrace()
            Handler(Looper.getMainLooper()).post{callback(StringWriter().apply{e.printStackTrace(PrintWriter(this))}.toString())}
        }
    }
    fun detection(str:SpannableStringBuilder,json:JSONObject){
        val p=json.optInt("positives",-1)
        val t=json.optInt("total",-1)
        str.append("\nDetection: ")
        if(t>0 && p>0){
            str.append("${json.optInt("positives")}/${json.optInt("total")}",ForegroundColorSpan(Color.RED),Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        }else if(p==0){
            str.append("not detected",ForegroundColorSpan(Color.GREEN),Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        }else{
            str.append("not checked",ForegroundColorSpan(Color.YELLOW),Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
    }
    companion object{
        fun getHash(data: InputStream, algorithm:String):ByteArray{
            val digest=MessageDigest.getInstance(algorithm)
            val buffer=ByteArray(1024)
            var read=0
            while(read!=-1){
                digest.update(buffer,0,read)
                read=data.read(buffer)
            }
            data.close()
            return digest.digest()
        }
        const val apikey="e17f95fffa073e77e3a831373199c4208c8df8c6a41b2c1374b55a046316a347"
    }
}