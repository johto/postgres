--
-- PGP sign
--
-- ensure consistent test output regardless of the default bytea format
SET bytea_output TO escape;

-- decrypt without verifying the signature
select pgp_sym_decrypt_bytea(pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(seckey)), 'key')
from keytbl where keytbl.name = 'rsa2048';

-- decrypt and verify the signature
select pgp_sym_decrypt_verify_bytea(pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(seckey)), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

-- decrypt and verify the signature, wrong key
select pgp_sym_decrypt_verify_bytea(pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(keytbl1.seckey)), 'key', dearmor(keytbl2.pubkey))
from keytbl keytbl1, keytbl keytbl2 where keytbl1.name = 'rsa2048' and keytbl2.name = 'rsaenc2048';


-- decrypt without verifying the signature, pub
select pgp_pub_decrypt_bytea(pgp_pub_encrypt_sign_bytea('Secret.', dearmor(pubkey), dearmor(seckey)), dearmor(seckey))
from keytbl where keytbl.name = 'rsaenc2048';

-- decrypt and verify the signature, pub
select pgp_pub_decrypt_verify_bytea(pgp_pub_encrypt_sign_bytea('Secret.', dearmor(pubkey), dearmor(seckey)), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

-- decrypt and verify the signature, pub, wrong key
select pgp_pub_decrypt_verify_bytea(pgp_pub_encrypt_sign_bytea('Secret.', dearmor(keytbl2.pubkey), dearmor(keytbl1.seckey)), dearmor(keytbl2.seckey), dearmor(keytbl2.pubkey))
from keytbl keytbl1, keytbl keytbl2 where keytbl1.name = 'rsa2048' and keytbl2.name = 'rsaenc2048';
