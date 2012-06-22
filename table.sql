CREATE TABLE `users` (
  `id` bigint(20) NOT NULL auto_increment,
  `name` varchar(64) NOT NULL,
  `password` varchar(64) NOT NULL,
  `blocked` int(11) NOT NULL default '0',
  PRIMARY KEY  (`id`),
  KEY `user` (`name`(8),`password`(8),`blocked`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `records` (
  `user_id` bigint(20) NOT NULL,
  `domain` varchar(128) NOT NULL,
  `ip` varchar(16) NOT NULL,
  `updated` datetime NOT NULL,
  PRIMARY KEY  (`user_id`,`domain`),
  KEY `domain` (`user_id`,`domain`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

