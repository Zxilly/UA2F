<?php
$userAgent = $_SERVER['HTTP_USER_AGENT'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User-Agent Display</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            padding: 20px;
            background-color: #f0f0f0;
        }

        .user-agent {
            background-color: #fff;
            border: 1px solid #ddd;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .title {
            color: #333;
        }

        @media (min-width: 1200px) {
            .user-agent {
                max-width: 800px;
                margin: 20px auto;
            }

            .title {
                font-size: 24px;
            }
        }
    </style>
</head>
<body>
<div class="user-agent" id="php-user-agent">
    <h2 class="title">服务器端 User-Agent:</h2>
    <p><?php echo htmlspecialchars($userAgent); ?></p>
</div>
<div class="user-agent" id="js-user-agent">
    <h2 class="title">用户端 User-Agent:</h2>
    <p></p>
</div>
<div class="user-agent" id="ua2f-status">
    <h2 class="title"><a href="https://github.com/Zxilly/UA2F" target="_blank">UA2F</a> 状态:</h2>
    <p></p>
</div>
<script>
    document.getElementById('js-user-agent').querySelector('p').textContent = navigator.userAgent;

    // Compare server-side and client-side User-Agents
    const serverUA = document.getElementById('php-user-agent').querySelector('p').textContent;
    const clientUA = navigator.userAgent;
    const ua2fStatusText = serverUA === clientUA ? "未工作" : "正常工作";
    document.getElementById('ua2f-status').querySelector('p').textContent = ua2fStatusText;

    if (window.location.protocol === 'https:') {
        document.querySelectorAll('.user-agent').forEach(function(element) {
            element.style.display = 'none';
        });

        // 创建并显示消息
        var messageDiv = document.createElement('div');
        messageDiv.textContent = '此网页无法在 https 下正常工作';
        messageDiv.style.padding = '20px';
        messageDiv.style.marginTop = '20px';
        messageDiv.style.backgroundColor = '#ffcccc';
        messageDiv.style.textAlign = 'center';
        messageDiv.style.border = '1px solid #ffaaaa';
        document.body.appendChild(messageDiv);
    }
</script>
</body>
</html>