
create database api_service;


create table api_keys (id int(50) not null auto_increment primary key, `date` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, user varchar(100), email varchar(255), api_key_prefix varchar(10), api_key_postfix varchar(10), api_key_hash varchar(255), api_secret varchar(255), admin_rights boolean, permission_wallet varchar(1000), permission_coin varchar(1000), permission_feature varchar(1000), permission_network varchar(1000), expiration_epoch(1000));


INSERT INTO api_keys (user, email, api_key_prefix, api_key_postfix, api_key_hash, api_secret, admin_rights, permission_wallet, permission_coin, permission_feature, permission_network, expiration_epoch) VALUES("tony", "tony@rock.com", "123", "123", "321berbrebeberbebebeberrebrrb", "123", true, "hot,warm", "btc,eth,atom,iotex", "", "main,test", "1583213606");

SELECT * FROM api_keys;


SELECT * FROM api_keys WHERE api_key_prefix="20c6b" AND api_key_postfix="d1311";

ALTER TABLE api_keys ADD COLUMN permission_wallet varchar(1000);

ALTER TABLE api_keys ADD COLUMN permission_coin varchar(1000);

ALTER TABLE api_keys ADD COLUMN permission_feature varchar(1000);

ALTER TABLE api_keys ADD COLUMN permission_network varchar(1000);

ALTER TABLE api_keys ADD COLUMN expiration_epoch varchar(1000);

ALTER TABLE api_keys ADD COLUMN admin_rights boolean;

ALTER TABLE api_keys DROP permission;

UPDATE `api_keys` SET `expiration_epoch` = '9583214241348' WHERE `id`=‘8’;
