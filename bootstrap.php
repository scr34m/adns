<?php
$db = new mysqli('localhost', 'root', '', 'adns');

$memcache = new Memcache();
$memcache->connect('localhost', 11211);

$result = $db->query('SELECT * FROM records');
if($result)
{
    while ($row = $result->fetch_object())
    {
        $memcache->set($row->domain, $row->ip);
    }
}
