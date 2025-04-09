/***********************************************
 * Remove first_name, last_name, with full_name *
 ************************************************/
-- ALTER TABLE registered_user ADD COLUMN full_name TEXT;
-- DO $$
-- DECLARE
-- 	temp_user_row record;
-- BEGIN
--  for temp_user_row IN SELECT * FROM registered_user LOOP
--  UPDATE registered_user SET full_name = concat(temp_user_row.first_name, ' ' ,temp_user_row.last_name) WHERE registered_user_id = temp_user_row.registered_user_id;
--  END LOOP;
-- END; $$;
-- ALTER TABLE registered_user ALTER column full_name SET NOT NULL;
-- ALTER TABLE registered_user DROP column first_name;
-- ALTER TABLE registered_user DROP column last_name;
/***********************************************************
 * Alter hourly_bandwidth table to remove redundant columns *
 ***********************************************************/
-- ALTER TABLE
-- 	hourly_bandwidth DROP COLUMN message_date;

-- ALTER TABLE
-- 	hourly_bandwidth DROP COLUMN message_hour;

-- CREATE UNIQUE INDEX on hourly_bandwidth(
-- 	extract(
-- 		year
-- 		FROM
-- 			(timestamp AT TIME ZONE 'UTC')
-- 	),
-- 	extract(
-- 		month
-- 		FROM
-- 			(timestamp AT TIME ZONE 'UTC')
-- 	),
-- 	extract(
-- 		day
-- 		FROM
-- 			(timestamp AT TIME ZONE 'UTC')
-- 	),
-- 	extract(
-- 		hour
-- 		FROM
-- 			(timestamp AT TIME ZONE 'UTC')
-- 	),
-- 	device_id,
-- 	is_pi,
-- 	is_counted
-- );

\echo "device_password password_hash NOT NULL"
ALTER TABLE device_password
ALTER COLUMN password_hash SET NOT NULL;

\echo "device max_clients NOT NULL"
ALTER TABLE device
ALTER COLUMN max_clients SET NOT NULL;

\echo "device structured_data NOT NULL"
ALTER TABLE device
ALTER COLUMN structured_data SET NOT NULL;


\echo "contact_message email_address_id NOT NULL"
ALTER TABLE contact_message
ALTER COLUMN email_address_id SET NOT NULL;

