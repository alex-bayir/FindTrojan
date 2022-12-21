## About
An application for testing a heuristic algorithm for detecting malicious Android applications.  
Screenshots:
<table>
<tbody>
    <tr>
        <td valign="top"><img src="https://user-images.githubusercontent.com/103780136/208158548-bcb5ddad-f6ca-477d-8c63-c8979dc5f347.jpg" /></td>
        <td valign="top"><img src="https://user-images.githubusercontent.com/103780136/208158560-6599f1ea-4b1e-4aaf-91d8-4b43b34d357f.jpg" /></td>
    </tr>
</tbody>
</table>

## Algorithm
< ENG >  
Most malware uses dangerous permissions and accessibility services, and hides malicious load. Therefore, the algorithm correlates between the classes stated in AndroidManifest.xml , and the classes that are in classes.dex and the number of potentially dangerous permissions. Thereby hypothesizing whether there is a hidden code. And also the algorithm makes a correlation between whether AccessibilityService is mentioned in AndroidManifest.xml and the assumption is whether there is a hidden code here. Based on the above, the algorithm determines whether the apk file is potentially dangerous.  
< RU >  
Большинство вредоносных программ использует опасные разрешения и службы доступности, а также прячет вредоносную нагрузку. Поэтому алгоритм проводит корреляцию между классами, заявленных в AndroidManifest.xml, и классами которые находятся в classes.dex и количеством потенциально опасных разрешений. Тем самым выдвигая гипотезу о том есть ли скрытый код. А также алгоритм проводит корреляция между тем упоминается ли AccessibilityService в AndroidManifest.xml и предположением есть ли тут скрытый код. На основании вышеизложенного алгоритм определяет является ли apk файл потенциально опасным.

```kotlin
companion object{
    private fun clip(str:String)=Regex("L(.+?);").find(str.replace("/","."))!!.groupValues[1]
    private fun full(clz:String,packageName:String)=clz.replace(Regex("^\\."), "$packageName.")
}
    val manifest=apk.manifestXml
    val amClasses=Regex("(activity|service|receiver).*?name=\"(.*?)\"")
        .findAll(manifest).map{full(it.groupValues[2],packageName)}.toSortedSet()
    val permissions=apk.apkMeta.usesPermissions.toSortedSet()
    val dangerous_permissions=permissions.filter{
        Regex(".*?(SYSTEM_ALERT_WINDOW|ACTION_MANAGE_OVERLAY_PERMISSION|WRITE_SETTINGS|RECORD_AUDIO|READ_SMS|RECEIVE_SMS)")
            .findAll(it).count()>0
    }.toSortedSet()
    val dexClasses=apk.dexClasses.map{clip(it.classType)}.toSortedSet()
    val diff=amClasses.minus(dexClasses)
    val canHaveHiddenCode=diff.isNotEmpty()
    val referencesAS=Regex("\"(android.accessibilityservice.*?)\"")
        .findAll(manifest).map{it.value}.toSortedSet()
    val referenceAS=referencesAS.isNotEmpty()
    val isMalware=if(referenceAS || (canHaveHiddenCode && dangerous_permissions.size>3)){
                      true //dangerous, should be deleted
                  }else if(!canHaveHiddenCode || dangerous_permissions.size==0){
                      false //safe to use
                  }else{
                      false //passed the test, but there are some suspicions
                  }
```
## Results
V-VirusTotal  
A-heuristic Algorithm  
T-True F-False  
E1-type I Errors  
E2-type II Errors  
Error matrix of analysis 1000 apks: [hashes](https://github.com/alex-bayir/FindTrojan/blob/master/malware/report.json)
```kotlin
    all               https://bazaar.abuse.ch     https://d.apkpure.com
   T V F                      T V F                     T V F          
 +---+---+                  +---+---+                 +---+---+        
T|598|  9| 607             T|591|  0| 591            T|  7|  9|  16    
A+---+---+                 A+---+---+                A+---+---+        
F|211|182| 393             F|204|  5| 209            F|  7|177| 184    
 +-------+                  +-------+                 +-------+        
  809 191 1000               795   5  800               14 186  200    
780/1000 78,0%             596/800  74,5%            184/200  92,0%    
E1: 211  21,1%             E1: 204  25,5%            E1:   7   3,5%    
E2:   9   0,9%             E2:   0   0,0%            E2:   9   4,5%    
  all apks                  malware apks               normal apks     
```
