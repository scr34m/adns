<?php
setcookie('asd', 'asd');
$db = new mysqli('localhost', 'root', '', 'adns');

if ( !$_REQUEST['password'] || !$_REQUEST['user'] )
{
    die('ERROR: unauthorized');
}

$salt = 'wukyetGhoIkmyRopFaWeekcip!';
$password = $db->escape_string(sha1($_REQUEST['password'] . $salt));
$sql = sprintf('SELECT id FROM users WHERE name = "%s" AND password = "%s" AND blocked = 0', $db->escape_string($_REQUEST['user']), $password);
$result = $db->query($sql);
if ( !$result )
{
    die('ERROR: unauthorized');
}
$user_id = $result->fetch_object()->id;

$domain = $db->escape_string($_REQUEST['domain']);
$result = $db->query(sprintf('SELECT domain FROM records WHERE user_id = "%s" AND domain = "%s"', $user_id, $domain));
if ( !$result )
{
    die('ERROR: unknow domain');
}

if (!filter_var($_REQUEST['ip'], FILTER_VALIDATE_IP))
{
    die('ERROR: not a valid ip');
}

$sql = sprintf('UPDATE domains SET ip = %s, updated = NOW() WHERE user = "%s" AND domain = "%s"', $db->escape_string($_REQUEST['ip']), $user_id, $domain);
$db->query($sql);

$memcache = new Memcache();
$memcache->connect('localhost', 11211);
$memcache->set($_REQUEST['domain'], $_REQUEST['ip']);

die('OK');
