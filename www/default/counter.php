<?php
$db_hostname = '172.29.0.1';
$db_user = 'counter';
$db_pass = 'teller';
$db_db = 'myip';

if (isset($_COOKIE['visits']))
	$count = (int)$_COOKIE['visits'] + 1;
else
	$count = 1;

setcookie('visits', "$count");

if (isset($_COOKIE['uuid']))
	$uuid = $_COOKIE['uuid'];
else {
	$uuid = uniqid();

	setcookie('uuid', $uuid);
}

mysqli_report(MYSQLI_REPORT_ERROR);
$connection = new mysqli($db_hostname, $db_user, $db_pass, $db_db);
$q = 'INSERT INTO hits(cookie, count) VALUES (?, ?) ON DUPLICATE KEY UPDATE count = ?';
$stmt = $connection->prepare($q);
$stmt->bind_param('sii', $uuid, $count, $count);

$stmt->execute();

print($count); ?>
