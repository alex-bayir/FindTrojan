package com.alex.findtrojan

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.*
import android.provider.Settings
import android.text.SpannableStringBuilder
import android.text.method.ScrollingMovementMethod
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.databinding.DataBindingUtil
import com.alex.findtrojan.databinding.ActivityMainBinding
import com.github.angads25.filepicker.model.DialogProperties
import com.github.angads25.filepicker.view.FilePickerDialog
import org.json.JSONObject
import java.io.File


class MainActivity : AppCompatActivity() {
    lateinit var binding: ActivityMainBinding
    private lateinit var dialog:FilePickerDialog
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding=DataBindingUtil.setContentView(this,R.layout.activity_main)
        binding.text.movementMethod=ScrollingMovementMethod()
        binding.text.setHorizontallyScrolling(true)
        val p=DialogProperties()
        p.root=Environment.getExternalStorageDirectory()
        p.extensions = arrayOf("apk","zip")
        dialog=FilePickerDialog(this,p)
        dialog.setTitle("Select apk")
        dialog.setDialogSelectionListener {
            binding.text.text="Wait a few seconds..."
            Thread{
                val apk=File(it[0])
                val str=SpannableStringBuilder("File folder: ${apk.parent}").append("\nFile name: ${apk.name}")
                if(apk.exists()){
                    val vt=VirusTotal(apk,"SHA-256")
                    val analyze=ApkAnalyze(apk)
                    str.append("\n${vt.algorithm}: ${vt.hash}")
                    analyze.report(str)
                    str.append("\n\nVirusTotal answer:")
                    vt.check{json:Any->
                        if(json is JSONObject){
                            vt.detection(str,json)
                            str.append("\n"+json.toString(2))
                        }else if (json is String){
                            str.append("\n$json")
                        }
                        Handler(Looper.getMainLooper()).post{binding.text.text=str}
                    }
                }else{
                    str.append("\nNot checked because not exists or wrong file path")
                }
                Handler(Looper.getMainLooper()).post{binding.text.text=str}
            }.start()
        }
        binding.start.setOnClickListener {if(callPermissionManageStorage(this))dialog.show()}
        binding.nestedScrollView.setOnScrollChangeListener { _, _, scrollY, _, oldScrollY ->
            if(scrollY-oldScrollY>0){
                binding.start.shrink()
            }else{
                binding.start.extend()
            }
        }
    }
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String?>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            FilePickerDialog.EXTERNAL_READ_PERMISSION_GRANT -> {
                if (checkPermissionManageStorage(this)) {
                    dialog.show()
                }else {
                    Toast.makeText(this,"Permission is Required for getting list of files",Toast.LENGTH_SHORT).show();
                }
            }
        }
    }

    fun checkPermissionManageStorage(context: Context)=(ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED || ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED) && (Build.VERSION.SDK_INT < Build.VERSION_CODES.R || Environment.isExternalStorageManager())

    fun callPermissionManageStorage(activity: Activity):Boolean {
        return if (!checkPermissionManageStorage(activity)) {
            ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE), 2478276)
            ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.MANAGE_EXTERNAL_STORAGE), 1)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
                activity.startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).setData(Uri.fromParts("package",activity.packageName,null)))
            }
            false
        }else{
            true
        }
    }
}