<?php
if (isset($_COOKIE['visits']))
	$value = (int)$_COOKIE['visits'] + 1;
else
	$value = 1;

setcookie('visits', "$value");
?>
<pre><?php echo print_r(get_defined_vars(), true); ?></pre>
