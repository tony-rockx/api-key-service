
create database api_service;


create table api_keys (id int(50) not null auto_increment primary key, `date` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, user varchar(100), email varchar(255), api_key_prefix varchar(10), api_key_postfix varchar(10), api_key_hash varchar(255), api_secret varchar(255), permission varchar(255));


INSERT INTO api_keys (user, email, api_key_prefix, api_key_postfix, api_key_hash, api_secret, permission) VALUES("tony", "tony@rock.com", "123", "123", "321berbrebeberbebebeberrebrrb", "123", "low");


SELECT * FROM api_keys;


SELECT * FROM api_keys WHERE api_key_prefix="20c6b" AND api_key_postfix="d1311";
