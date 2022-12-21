package com.alex.findtrojan

import android.graphics.Color
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import net.dongliu.apk.parser.ApkFile
import java.io.*

class ApkAnalyze(val apk:ApkFile) {
    constructor(apk:File):this(ApkFile(apk))
    companion object{
        val RED:ForegroundColorSpan
            get()=ForegroundColorSpan(Color.RED)
        val YELLOW:ForegroundColorSpan
            get()=ForegroundColorSpan(Color.YELLOW)
        val GREEN:ForegroundColorSpan
            get()=ForegroundColorSpan(Color.GREEN)
        private fun clip(str:String)=Regex("L(.+?);").find(str.replace("/","."))!!.groupValues[1]
        private fun full(clz:String,packageName:String)=clz.replace(Regex("^\\."), "$packageName.")
    }
    val packageName=apk.apkMeta.packageName
    val manifest=apk.manifestXml
    val amClasses=Regex("(activity|service|receiver).*?name=\"(.*?)\"").findAll(manifest).map{full(it.groupValues[2],packageName)}.toSortedSet()
    val permissions=apk.apkMeta.usesPermissions.toSortedSet()
    val dangerous_permissions=permissions.filter{Regex(".*?(SYSTEM_ALERT_WINDOW|ACTION_MANAGE_OVERLAY_PERMISSION|WRITE_SETTINGS|RECORD_AUDIO|READ_SMS|RECEIVE_SMS)").findAll(it).count()>0}.toSortedSet()
    val dexClasses=apk.dexClasses.map{clip(it.classType)}.toSortedSet()
    val diff=amClasses.minus(dexClasses)
    val canHaveHiddenCode=diff.isNotEmpty()
    val referencesAS=Regex("\"(android.accessibilityservice.*?)\"").findAll(manifest).map{it.value}.toSortedSet()
    val referenceAS=referencesAS.isNotEmpty()
    val classesUsesAccessibility=kotlin.runCatching{Regex("<(activity|service|receiver).*?name=\"(.*?)\"(.|\n)*?(action|meta-data).*?name=\"(android.accessibilityservice.*?)\"(.|\n)*?</(activity|service|receiver)>").findAll(manifest).map{full(it.groupValues[2],packageName)}.toSortedSet()}.getOrDefault(sortedSetOf<String>())
    val isMalware=referenceAS || (canHaveHiddenCode && dangerous_permissions.size>3)
    fun report(str:SpannableStringBuilder){
        str.append("\nApk metadata:")
        str.append("\n\tApp name: ${apk.apkMeta.name}")
        str.append("\n\tApp package name: $packageName")
        str.append("\n\tApp version: ${apk.apkMeta.versionName} (${apk.apkMeta.versionCode})")
        str.append("\n\tApp SDK version: ${apk.apkMeta.compileSdkVersion}")
        str.append("\n\tApp min SDK version: ${apk.apkMeta.minSdkVersion}")
        str.append("\nResult answer: ",YELLOW,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        if(referenceAS || (canHaveHiddenCode && dangerous_permissions.size>3)){
            str.append("Should be deleted",RED,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        }else if(!canHaveHiddenCode || dangerous_permissions.size==0){
            str.append("safe to use",GREEN,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        }else{
            str.append("there are suspicions about the file",YELLOW,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        str.append("\nCan have hidden code:",YELLOW,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE).append("$canHaveHiddenCode",if(isMalware) RED else if (canHaveHiddenCode) YELLOW else GREEN,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        if(dangerous_permissions.isNotEmpty()){
            str.append("\nHave ${dangerous_permissions.size} dangerous permissions:",if(isMalware) RED else YELLOW,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE).append(dangerous_permissions.joinToString("\n\t","\n\t"))
        }
        if(referencesAS.isNotEmpty()){
            str.append("\nCount of AccessibilityService references: ${referencesAS.size}",RED,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        if(classesUsesAccessibility.isNotEmpty()){
            str.append("\nHave ${classesUsesAccessibility.size} classes uses AccessibilityService:",RED,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE).append(classesUsesAccessibility.joinToString("\n\t","\n\t"))
        }
        if(diff.isNotEmpty()){
            str.append("\nHave ${diff.size} ${if(isMalware) "hidden" else "outer"} classes:", if(isMalware) RED else YELLOW,Spannable.SPAN_EXCLUSIVE_EXCLUSIVE).append(diff.joinToString("\n\t","\n\t"))
        }
    }
}