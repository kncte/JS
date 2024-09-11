

//"x1=2f970a417a6e091ff1f8f24482b52552;x2=0|0|0|1|0|0|1|0|0|0|1|0|0|0|0|1|0|0|0;x3=191b053fe94zrxevly90ez0s5tnl9beakcijqigoi50000370261;x4=1725240180382;" 
const crypto = require('crypto');
function get_code(text){
    aaa = []
    for (let i = 0; i < text.length; i++) {
        let charCode = text.charCodeAt(i);
        aaa.push(charCode)
    }
    while(aaa.length <208){
        aaa.push(8)
    }
    return aaa
}

function calc(src, iv) {
    let res = [];
    for (let i = 0; i < iv.length; i++) {
        res.push(src[i] ^ iv[i]);
    }
    return res;
}
function uint32FromBytesBigEndian(bytes) {
    return (bytes[3] | (bytes[2] << 8) | (bytes[1] << 16) | (bytes[0] << 24)) >>> 0;
}

function intToBytes(int) {
    // 将整数转换为4个字节的数组
    let bytes = [];
    for (let i = 3; i >= 0; i--) {
        bytes.push((int >> (i * 8)) & 0xFF);
    }
    return bytes;
}

function combineToAesKey(int1, int2, int3, int4) {
    // 获取每个整数的字节数组
    let keyBytes = [
        ...intToBytes(int1),
        ...intToBytes(int2),
        ...intToBytes(int3),
        ...intToBytes(int4)
    ];

    return keyBytes;
}


function aes_encrypt(key_,iv_,text_){


    // 定义16字节的密钥 (128位)    此处为key
    const key = Buffer.from(key_);

    // 定义16字节的IV (128位)
    const iv = Buffer.from(iv_);

    // 要加密的文本  初始化的 base64
    const text = text_;

    // 创建加密器
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);

    // 加密文本
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    // console.log('加密后的文本:', encrypted);
    return encrypted
}



xhs_iv = [52, 104, 114, 105, 118, 103, 119, 53, 115, 51, 52, 50, 102, 57, 98, 50]


function get_xs(url_md5,a1,time_){
    // 0|0|0|1|0|0|1|0|0|0|1|0|0|0|0|1|0|0|0
    // var text = "x1="+url_md5+";x2=0|0|0|1|0|0|1|0|0|0|1|0|0|0|0|1|0|0|0;x3="+a1+";x4="+time_+";"
    var text = "x1="+url_md5+";x2=0|0|0|1|0|0|1|0|0|0|1|0|0|0|0;x3="+a1+";x4="+time_+";"
    const base_64_ = btoa(text)
    key = [
        103, 108, 116,  54, 104,
         54,  49, 116,  97,  55,
        107, 105, 115, 111, 119,
         55
      ]
    // console.log('AES 密钥字节数组:', key);
    var aes_data = aes_encrypt(key,xhs_iv,base_64_)
    text = '{"signSvn":"55","signType":"x2","appId":"xhs-pc-web","signVersion":"1","payload":"'+aes_data+'"}'
    return "XYW_"+btoa(text)
}

console.log(get_xs("191b0db28f8rwiyv02mbdzn754ed3ize8makakl1d50000102446","cabb58357049653fbfd8921727e949a8","1725249359371"))

// text = '{"signSvn":"55","signType":"x2","appId":"xhs-pc-web","signVersion":"1","payload":"'+a+'"}'
// console.log(text)

// console.log("XYW_"+btoa(text))




