package com.alex.findtrojan


import com.eclipsesource.json.Json
import com.eclipsesource.json.JsonArray
import com.eclipsesource.json.JsonObject
import com.eclipsesource.json.WriterConfig
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Test
import java.io.*
import java.net.SocketTimeoutException
import java.util.SortedSet
class CheckWork {
    val dir=get_dir()
    val apks=dir.plus("\\apks")
    val report=dir.plus("\\report.json")

    companion object{
        fun Double.format(digits: Int) = "%.${digits}f".format(this)
        fun JsonObject.add(name:String, value:Boolean?)=apply{value?.let{add(name, value)}}
        fun get_dir()=System.getProperty("user.dir")?.let{File(it).parent.plus("\\malware")}!!

        fun analyze(file:File,url:String?=null):JsonObject{
            val a=ApkAnalyze(file)
            val v=VirusTotal(file)
            return JsonObject().add("a",a.answer()).add("v",v.answer()).add("hash",v.hash).add("url",url)
        }

        fun saveReport(report:String,array:JsonArray){
            FileWriter(report).apply{write(array.toString(WriterConfig.PRETTY_PRINT))}.close()
        }

        fun ApkAnalyze.answer()=referenceAS || (canHaveHiddenCode && dangerous_permissions.size>3)
        fun VirusTotal.answer():Boolean?{
            val response=OkHttpClient().newCall(Request.Builder().url("https://www.virustotal.com/vtapi/v2/file/report?apikey=${VirusTotal.apikey}&resource=${hash}").build()).execute()
            Json.parse(response.body?.string()?:"{}").asObject().apply {
                val p=getInt("positives",-1)
                val t=getInt("total",-1)
                return if(t>0 && p>0){
                    true
                }else if(p==0){
                    false
                }else{
                    null
                }
            }
        }

        fun download(url:String,file:File,log: Boolean=true)=download(Request.Builder().url(url).build(),file,log)
        fun download(request: Request,file:File,log:Boolean=true):Boolean{
            val response=OkHttpClient().newCall(request).execute()
            val body=response.body
            if(response.isSuccessful && body!=null){
                val size=response.header("content-length",null)?.toInt() ?: -1
                val sizeMb=if(size>0) size/(1024*1024) else -1
                println("size=${sizeMb}Mb ${file.name}   ${size}")
                if(sizeMb<50 && size!=-1){
                    body.byteStream().apply {
                        file.createNewFile()
                        FileOutputStream(file).apply {
                            val buf=ByteArray(1024*1024)
                            var r: Int; var read=0
                            while(true){
                                r=read(buf)
                                if(r<=0){break}else{
                                    write(buf,0,r)
                                    read+=r
                                    if(log)println("$read/$size  ${(read*100.0/size).format(2)}%")
                                }
                            }
                        }.close()
                    }.close()
                    body.close()
                    return true
                }
            }else{
                println(request.url)
                println("body: ${body?.string()?:"null"}")
            }
            return false
        }
    }

    @Test
    fun check_work(){
        println(dir)
        val urls=FileReader(dir.plus("\\urls.txt")).readLines().toSortedSet()
        val array=Json.parse(kotlin.runCatching { FileReader(report).readText() }.getOrDefault("[]")).asArray()
        for(json in array){
            urls.remove(json.asObject().get("url").let{if(it.isString)it.asString() else ""})
        }
        val r=sortedSetOf<String>()
        var last=0
        urls.onEachIndexed { i, url ->
            try{
                val (str,cur)=full_report()
                if(last!=cur){last=cur; println(str)}
                val name=Regex("/([^/]*?)(\\?.*?)?$").find(url)?.groupValues?.get(1)
                val file=File("$apks\\${name?:"tmp"}")
                if(file.exists()){
                    try{
                        saveReport(report,array.add(analyze(file,url)))
                    }catch (e:Exception){
                        file.delete()
                        removeurl(url,urls,r)
                    }
                }else{
                    if(download(url,file,false)){
                        try{
                            saveReport(report,array.add(analyze(file,url)))
                            removeurl(url,urls,r)
                        }catch (e:Exception){
                            file.delete()
                        }
                    }else{
                        removeurl(url,urls,r)
                    }
                }
                println("\r${i+1}/${urls.size}")
            }catch (e:SocketTimeoutException){
                println("Time out")
            }
        }
    }

    fun removeurl(url:String,urls:Set<String>,r:SortedSet<String>){
        r.add(url)
        FileWriter(dir.plus("\\urls.txt")).apply{write(urls.filter{u->!r.contains(u)}.toSortedSet().joinToString("\n"))}.close()
    }


    fun download_malware(hash:String):String?{
        val url="https://mb-api.abuse.ch/api/v1/"
        val file=File("$apks\\${hash}.zip")
        val body="query=get_file&sha256_hash=$hash".toRequestBody("application/x-www-form-urlencoded".toMediaType())
        val request=Request.Builder().url(url).post(body).build()
        download(request,file,false)
        val zip=net.lingala.zip4j.ZipFile(file)
        if(zip.isEncrypted){
            zip.setPassword("infected".toCharArray())
        }
        val name=if(zip.fileHeaders.size>0 ||file.length()>0L)zip.fileHeaders[0].fileName else null
        if(name!=null && !name.endsWith(".exe")){kotlin.runCatching{zip.extractAll(apks)}}
        file.delete()
        return name
    }
    fun get_hashes_malware(tags:String):SortedSet<String>{
        val url="https://mb-api.abuse.ch/api/v1/"
        val body="query=get_taginfo&$tags&file_type=apk&limit=1000".toRequestBody("application/x-www-form-urlencoded".toMediaType())
        val request=Request.Builder().url(url).post(body).build()
        val response=OkHttpClient().newCall(request).execute()
        val answer=response.body?.string()
        kotlin.runCatching {
            val data=Json.parse(answer).asObject().get("data").asArray()
            val hashes=data.map{json->json.asObject().getString("sha256_hash",null)}.toSortedSet()
            //println(hashes.joinToString("\n"))
            //println(data.toString(WriterConfig.PRETTY_PRINT))
            return hashes
        }.onFailure {
            println(answer)
        }
        return sortedSetOf()
    }
    @Test
    fun checkWorkMalware(){
        val hashes=sortedSetOf<String>()
        hashes.addAll(get_hashes_malware("tag=Cerberus"))
        hashes.addAll(get_hashes_malware("tag=Hydra"))
        hashes.addAll(get_hashes_malware("tag=Alien"))
        hashes.addAll(get_hashes_malware("tag=SharkBot"))
        hashes.addAll(get_hashes_malware("tag=TeaBot"))
        hashes.addAll(get_hashes_malware("tag=BankBot"))
        hashes.addAll(get_hashes_malware("tag=AbereBot"))
        hashes.addAll(get_hashes_malware("tag=Ermac"))
        while (hashes.size>0){
            val array=Json.parse(kotlin.runCatching { FileReader(report).readText() }.getOrDefault("[]")).asArray()
            for(json in array){
                hashes.remove(json.asObject().getString("hash",null))
            }
            val r=sortedSetOf<String>()
            var last=0
            hashes.onEachIndexed { i, hash ->
                val start=System.currentTimeMillis()
                try{
                    val (str,cur)=full_report()
                    if(last!=cur){last=cur; println(str)}

                    var file=File("$apks\\${hash}.apk")
                    if(file.exists()){
                        try{saveReport(report,array.add(analyze(file)))}catch(e:Exception){file.delete(); r.add(hash)}
                    }else{
                        val name=download_malware(hash)
                        if(name==null || name.endsWith(".exe")){
                            r.add(hash)
                        }else{
                            file=File("$apks\\${name}")
                            Thread{
                                try{saveReport(report,array.add(analyze(file)))}catch(e:Exception){file.delete(); r.add(hash)}
                            }.start()
                        }
                    }
                    println("\r${i+1}/${hashes.size}")
                }catch (e:SocketTimeoutException){
                    println("Time out")
                }
                Thread.sleep((15 * 1000 - (System.currentTimeMillis() - start)).coerceAtLeast(100))
            }
            r.forEach { h->hashes.remove(h) }
        }
    }


    fun analyze(array: JsonArray,filter:(JsonObject)->Boolean):Array<Int>{
        var tt=0; var tf=0
        var ft=0; var ff=0
        for(json in array.filter{json->filter(json.asObject())}){
            val a=json.asObject().getBoolean("a",false)
            val v=json.asObject().getBoolean("v",false)
            if(a && v){tt++}else if(!a && v){ft++}else if(a && !v){tf++}else{ff++}
        }
        return arrayOf(tt,tf,ft,ff,tt+tf+ft+ff)
    }
    fun full_report():Pair<String,Int>{
        val array=Json.parse(kotlin.runCatching { FileReader(report).readText() }.getOrDefault("[]")).asArray()
        val all=analyze(array){ _ ->true}
        val els=analyze(array){json->json.get("url").isString}
        val baz=analyze(array){json->!json.get("url").isString}
        var str=
             "    all               https://bazaar.abuse.ch     https://d.apkpure.com\n"
        str+="   T V F                      T V F                     T V F          \n"
        str+=" +---+---+                  +---+---+                 +---+---+        \n"
        str+="T|%3d|%3d| %3d             T|%3d|%3d| %3d            T|%3d|%3d| %3d    \n".format(all[0],all[1],all[0]+all[1],baz[0],baz[1],baz[0]+baz[1],els[0],els[1],els[0]+els[1])
        str+="A+---+---+                 A+---+---+                A+---+---+        \n"
        str+="F|%3d|%3d| %3d             F|%3d|%3d| %3d            F|%3d|%3d| %3d    \n".format(all[2],all[3],all[2]+all[3],baz[2],baz[3],baz[2]+baz[3],els[2],els[3],els[2]+els[3])
        str+=" +-------+                  +-------+                 +-------+        \n"
        str+="  %3d %3d %4d               %3d %3d % 4d              %3d %3d % 4d    \n".format(all[0]+all[2],all[1]+all[3],all[4],baz[0]+baz[2],baz[1]+baz[3],baz[4],els[0]+els[2],els[1]+els[3],els[4])
            str+="%s %.1f%%             %3d/%3d  %.1f%%            %3d/%3d  %.1f%%    \n".format("${all[0]+all[3]}/${all[4]}".padEnd(8),(all[0]+all[3])*100.0/all[4],baz[0]+baz[3],baz[4],(baz[0]+baz[3])*100.0/baz[4],els[0]+els[3],els[4],(els[0]+els[3])*100.0/els[4])
        str+="E1:%4d  %4.1f%%             E1:%4d  %4.1f%%            E1:%4d  %4.1f%%    \n".format(all[2],all[2]*100.0/all[4],baz[2],baz[2]*100.0/baz[4],els[2],els[2]*100.0/els[4])
        str+="E2:%4d  %4.1f%%             E2:%4d  %4.1f%%            E2:%4d  %4.1f%%    \n".format(all[1],all[1]*100.0/all[4],baz[1],baz[1]*100.0/baz[4],els[1],els[1]*100.0/els[4])
        str+="  all apks                  malware apks               normal apks     \n"
        return Pair(str,all[4])
    }
    @Test
    fun test(){
        println(full_report().first)
    }
    @Test
    fun count_modifications(){
        val keys=arrayOf("Cerberus","Hydra","Alien","SharkBot","TeaBot","BankBot","AbereBot","Ermac","SpyNote","XLoader","Harly","Sova","Joker","Octo","PixStealer","GodFather","Dracarys","Wroba","BrasDex","IRATA","AgentSmith","Metasploit")
        val modifications=keys.associateWith { key -> get_hashes_malware("tag=$key") }
        val analyze=JsonObject()
        val json=Json.parse(kotlin.runCatching { FileReader(report).readText() }.getOrDefault("[]")).asArray()
        modifications.forEach { (k, v) ->
            val r=JsonObject()
            var al=0
            var vt=0
            var count=0
            json.filter { json->v.contains(json.asObject()["hash"].asString()) }.forEach { json->
                al+=if(json.asObject()["a"].asBoolean()) 1 else 0
                vt+=if(json.asObject()["v"].asBoolean()) 1 else 0
                count++
            }
            r.add("a",al).add("v",vt).add("count",count).add("percent","${(if(count>0) al*100/count.toDouble() else 0.0).format(2)}%")
            analyze.add(k,r)
        }
        println(analyze.toString(WriterConfig.PRETTY_PRINT))
    }
    /*
    @Test
    fun parseUrls(){
        val dir=get_dir()
        val urls=LinkedHashSet<String>()
        try{urls.addAll(FileReader(dir.plus("\\urls.txt")).readLines())}catch (_:Exception){}
        File(dir)
            .listFiles { _ , name -> name.endsWith(".html") }
            ?.forEach {
                when(it.name){
                    "2.html"->urls.addAll(Jsoup.parse(it).select("a[title~=.* APK]").map{e->"https://d.apkpure.com/b/APK/${e.attr("href").substringAfterLast("/")}?version=latest"})
                }
            }
        val w=PrintWriter(dir.plus("\\urls.txt"))
        w.println(urls.joinToString("\n"))
        w.close()
        println(urls.size)
    }
     */
}