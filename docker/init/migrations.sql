
\echo "device_password password_hash NOT NULL"
ALTER TABLE device_password ALTER COLUMN password_hash SET NOT NULL;

\echo "device max_clients NOT NULL"
ALTER TABLE device ALTER COLUMN max_clients SET NOT NULL;

\echo "device structured_data NOT NULL"
ALTER TABLE device ALTER COLUMN structured_data SET NOT NULL;

\echo "contact_message email_address_id NOT NULL"
ALTER TABLE contact_message ALTER COLUMN email_address_id SET NOT NULL;