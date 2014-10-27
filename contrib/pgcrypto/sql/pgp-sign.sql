--
-- PGP sign
--
-- ensure consistent test output regardless of the default bytea format
SET bytea_output TO escape;

-- list keys
select pgp_sym_signatures.* from
    (select pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(seckey)) as ciphertext
    from keytbl where keytbl.name = 'rsa2048') encrypted,
    lateral pgp_sym_signatures(encrypted.ciphertext, 'key')
    ;
select pgp_pub_signatures.* from
    (select seckey, pgp_pub_encrypt_sign_bytea('Secret.', dearmor(pubkey), dearmor(seckey)) as ciphertext
    from keytbl where keytbl.name = 'rsaenc2048') encrypted,
    lateral pgp_pub_signatures(encrypted.ciphertext, dearmor(encrypted.seckey))
    ;

-- test debug mode
select pgp_pub_signatures.* from
    (select pgp_pub_encrypt_sign_bytea('Secret.', dearmor(pubkey), dearmor(seckey)) as ciphertext
    from keytbl where keytbl.name = 'rsaenc2048') encrypted,
    lateral pgp_pub_signatures(encrypted.ciphertext, (select dearmor(seckey) from keytbl where keytbl.name='elg2048'), '', false, 'debug=1')
    ;

-- decrypt without verifying the signature
select pgp_sym_decrypt_bytea(pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(seckey)), 'key')
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_bytea(pgp_pub_encrypt_sign_bytea('Secret.', dearmor(pubkey), dearmor(seckey)), dearmor(seckey))
from keytbl where keytbl.name = 'rsaenc2048';

-- decrypt and verify the signature
select pgp_sym_decrypt_verify_bytea(pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(seckey)), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify_bytea(pgp_pub_encrypt_sign_bytea('Secret.', dearmor(pubkey), dearmor(seckey)), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

-- decrypt and verify the signature, wrong key
select pgp_sym_decrypt_verify_bytea(pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(keytbl1.seckey)), 'key', dearmor(keytbl2.pubkey))
from keytbl keytbl1, keytbl keytbl2 where keytbl1.name = 'rsa2048' and keytbl2.name = 'rsaenc2048';

select pgp_pub_decrypt_verify_bytea(pgp_pub_encrypt_sign_bytea('Secret.', dearmor(keytbl2.pubkey), dearmor(keytbl1.seckey)), dearmor(keytbl2.seckey), dearmor(keytbl2.pubkey))
from keytbl keytbl1, keytbl keytbl2 where keytbl1.name = 'rsa2048' and keytbl2.name = 'rsaenc2048';

-- complain if no signature is present
select pgp_sym_decrypt_verify_bytea(pgp_sym_encrypt_bytea('Secret.', 'key'), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify_bytea(pgp_pub_encrypt_bytea('Secret.', dearmor(pubkey)), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

-- multiple signers
insert into encdata(id, data) values (5, '
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.19 (Darwin)

jA0ECQMCA7SEJlWfWYjUyekWNxFzQ/NFijc61eLTtHEqtxZ36f0XvgV2ZjIgUVq5
jSaGcly7rTfy6P9bCNMN+p1B86N+v6P+7zkzhtg4abM7RTbnXfj9VupQE+bTu++A
9xTAOrM79cFlyVzVykkQUOcvw7kNRk2woepREbguRpqLytDwVf8tJKn2Yd00X/Lp
IsU5HfT+TcNngx8NFqhKedfAPcyQd0cS7NA0dcUyXcN/fO+PsPavp7iPGt0Q+/JN
exkjx4LmJPObkrgN7RYiOlA3vRUt4SuzJAIN6+GkKxveYrpQuaGr1t1M0HfPXw9n
gilqUtlwX36tHGfCOYYwlG64LaNsyuTRmXIvV0o8kYaaJtoVKeMGkZCPd6XZoAf9
Elluzf7Mxe+T44XRQ/VlO8P9aT0immSdOwGL6wywmV+kITpcVUcthCR3a2Yb2R4M
NE0efRop4arfdOGpLdysF32ymwAZgdqNCDHKLTuAKfDlnXl2Tm1QdOhXytILIe64
kkzt5YNjrAvw5qmn0ze3xZuUCTuEUbBh3T19o5jrF1oiZ4hqd6o3iUEPnYxWaHl0
r7W9BxHpVJexY7K3MGtAnnHKn8f+MmopGe4HDSHTRf+qDjZi7yg9psWChlii4PPs
YqmfxGBicnoHQy+GSauoDgVPNy4PPrH5yY4bAByt3op28/vkQ7bQH0tuc6x6J0Rm
GYG7s8HPpWFSzS7o25tALBmXIi+DZfdgQ8tQ4MLx5wZPJ1H68A3MTvinuQKiY5yE
YezsNH92tGilzM5E0iRA8UTluqhQIkX4apMJnnRT8RJ0by5pUbkYKokbmH4rKTCv
nOIu5RYb/9a4Nd4ijZOWM8AmNKVNsLP3cB7jJqupykWNpos=
=1JXB
-----END PGP MESSAGE-----
');
insert into encdata(id, data) values (6, '
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.19 (Darwin)

hQEMA/0CBsQJt0h1AQf/bAFXphI0ecP5Ba2gKnC9TXz7BWhHn07QBEBoWJ4CHMpp
ULwBJ4CgG6ED9QdtIPeteazrn490ORS8ut4mymf+ERolZGI7U4p2lJJIkvpS7Qyq
wAEjsZgl48mT6P8JQyp7Xf2MDrONVNS+rsp1+C5Fem8PGprlIu7RRUBYi1eg3lZO
Kjl8poBqU28PHT/HaZakccO/cOFKaXBAlq3wZGHgEwNa2LXwNlUOG66u2GrMKcAm
R2N68ve5clIa5cUWPB8uvvWkbCjBnf+re4L7hddRCAVNs98WC7ty1876xJLh5OyH
cGh8xa03LMOOnBseuOUx/dKVTjc5vFgsfTDJgf6SS9LpAeKts5nMscaVzqU2jgtd
YOyhocXn8+kA43iUX0YZvMzfep8vSoHqigV2VQ6OtxQBT1SA7inE/7l3t3xPaSRz
HeeXBDSg1BSwLr2p+l/PTvR158MZ4MQX5PvmPJ3M6f/1nDflHGR1pp8Qjv7BGiOz
XnjGSK+pRrzT4S2XSOIglcSNqEKa0B0iodv/R593E08/zZMeyGZQL7esJq9CWp4n
jT30ATpvIrZ6UvBpxj21G64/JfFSZa8a+v2biC/eOws3Dch/fCa0IU0RNlZaTXoN
888am3HEKlObzst+7PvkRc4TgK91cfF46w311iD3bDi8lsv1LqDmBMqhIEWrg1Sc
ntAe+afUzHdUKg/StlMOSloTwU0oP+drj3h30UaR/t0/ykMDfCjW6peEmEB64vDx
3FQk8phKket2EmKhC1pHWZpZsEgITficWwy42l43xAsLNp6cwuhZ5Sz874di73iE
oDhIqB5Mftvc1zUiZv/15KsIX9DwxGHWbaUIRro+xYmKj36ljJguTA74NwKljxbE
xQ6gLjMs81MCBkPbPjM4iNuF5AqVu78BSUqd7nOKauLm5/a2COr/5fh6Zigph57y
FTe54GqFzxlpP4JOqUiS2gd9lRlXujCWpVa8Cexxh99jpG1mF/xuHpnjJvCOPp4h
g0IBsNq67xYHubsX+goGnH2edeJsH5eXYwETFqYnUt5kQmKQKPZn4vH01TAidHco
Qv9O1DIyvwiwmgaoPT6JCuGfd8lFqmR6W4u+3NM6pbW19AguYIFXRcgzLIOX5t4K
E3JVgW8pkQcxBsycFxrwjf66hfaLTu39SsZrWkkaPRMo8kCt08K2jgf4alz/MyhH
uRScuAbB94gSEf/VmzTnilt2219be1w5zl35h1fjCbo=
=snSk
-----END PGP MESSAGE-----
');

-- multiple signers without verifying the signature
select * from pgp_pub_decrypt_bytea((select dearmor(data) from encdata where id=6), (select dearmor(seckey) from keytbl where keytbl.name = 'rsaenc2048'));

-- no details
select * from pgp_sym_signatures((select dearmor(data) from encdata where id=5), 'key');
select * from pgp_pub_signatures((select dearmor(data) from encdata where id=6), (select dearmor(seckey) from keytbl where keytbl.name = 'rsaenc2048'));

-- with details; the signatures will appear in reverse order
select * from pgp_sym_signatures((select dearmor(data) from encdata where id=5), 'key', true);
select * from pgp_pub_signatures((select dearmor(data) from encdata where id=6), (select dearmor(seckey) from keytbl where keytbl.name = 'rsaenc2048'), '', true);

-- verify both signatures
select * from pgp_pub_decrypt_verify_bytea((select dearmor(data) from encdata where id=6), (select dearmor(seckey) from keytbl where keytbl.name = 'rsaenc2048'), (select dearmor(pubkey) from keytbl where keytbl.name = 'rsa2048'));
select * from pgp_pub_decrypt_verify_bytea((select dearmor(data) from encdata where id=6), (select dearmor(seckey) from keytbl where keytbl.name = 'rsaenc2048'), (select dearmor(pubkey) from keytbl where keytbl.name = 'rsaenc2048'));

-- test v3 signature headers
insert into encdata(id, data) values (7, '
-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.19 (Darwin)
Comment: GPGTools - http://gpgtools.org

hQEMA/0CBsQJt0h1AQf/TbgfgQgH8QxP6THfNFKOW39TvV+v9Sb2p5Q7JRF6/YxG
n2N2ADkO0S63wE9HRH2xHAbxvaxO9nCHX48mTTi6sj/6fRdg3nDn9yvQcE994JaS
Wumn3d+7Pe8AqpwAyk6Tn2YSrdv8K3AKB0DuQI0FsXvjET8x7uBvD272c665od4k
FhgOzJrgtin6DKCUSVc8UZgDw4ZI/TAHrbf6pxiIX2rLdn1EAcjuPALiQKGvQIyH
I/B+Yq7j8sLhL60k3DEKHSjFqHR16LG4wsCKnNjzBM+Dto3nkklTcuy1Qu6D8B38
b1yVWO6IoUPf1aKahrzdFfv3J9jnmt7CMbxIfjqeqdLAsAG2e+dtdDu/own6lI6T
AM8TqvSCyKpjz8IN6FELe4rJq2LgS+FKJPcuFJV2JJs+eOo4O2PzVfdv8yJklysH
epU5tfrpYdkbsrR9pLhsbKGDINDmqENydAhFLUII2xdichVkYvk+gye+GS3E2EPp
aniMP/CuetL6qDIht9ADBCstBih8VFE7d7bNB//ldKc8cXKMJ/h1CHJ788sV2QBO
RHgHdWFE02JoK8WsDf/Wg5422Yca1JXhfr3wvHUwAvmnnIGzOUBaHbMSTlrgqNsR
nerdZxLfaxUQ8CjJ2yobn9OIAj4TAuITipssUsEVypT8m1lwsW2CaTuWUBcE9oC7
ULIfPPt+McDf1EYNtp+0UxZASFLETVYsLIfhNQxf8YnXFuVcLzvhdVRQKZ7oMC17
+0non8pele5HURJO7e3ULQihtb1i9GPtPXRjhyuR5K3n35NoZJHt4SCQPuRxRJIB
I4toPKPYCrND+X25oKaTrTMC
=WWPD
-----END PGP MESSAGE-----
');
select * from pgp_pub_decrypt_verify_bytea((select dearmor(data) from encdata where id=7), (select dearmor(seckey) from keytbl where keytbl.name = 'rsaenc2048'), (select dearmor(pubkey) from keytbl where keytbl.name = 'rsa2048'));

-- pgp_main_key_id() should fail, even on signed data
select pgp_main_key_id(pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(seckey)))
from keytbl where keytbl.name = 'rsa2048';

-- text mode
select pgp_sym_decrypt_verify(pgp_sym_encrypt_sign('Secret.', 'key', dearmor(seckey)), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify(pgp_pub_encrypt_sign('Secret.', dearmor(pubkey), dearmor(seckey)), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

-- encrypt in binary, verify signature in text (doesn't work)
select pgp_sym_decrypt_verify(pgp_sym_encrypt_sign_bytea('Secret.', 'key', dearmor(seckey)), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify(pgp_pub_encrypt_sign_bytea('Secret.', dearmor(pubkey), dearmor(seckey)), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

-- encrypt in text, verify signature in binary (works)

select pgp_sym_decrypt_verify_bytea(pgp_sym_encrypt_sign('Secret.', 'key', dearmor(seckey)), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify_bytea(pgp_pub_encrypt_sign('Secret.', dearmor(pubkey), dearmor(seckey)), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

-- encrypt in text with convert-crlf, verify signature in binary (works)

select pgp_sym_decrypt_verify_bytea(pgp_sym_encrypt_sign('Secret.', 'key', dearmor(seckey), '', 'convert-crlf=1'), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify_bytea(pgp_pub_encrypt_sign('Secret.', dearmor(pubkey), dearmor(seckey), '', 'convert-crlf=1'), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

select pgp_sym_decrypt_verify_bytea(pgp_sym_encrypt_sign(E'Secret.\n', 'key', dearmor(seckey), '', 'convert-crlf=1'), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify_bytea(pgp_pub_encrypt_sign(E'Secret.\n', dearmor(pubkey), dearmor(seckey), '', 'convert-crlf=1'), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

-- encrypt in text with convert-crlf, verify with same (works)

select pgp_sym_decrypt_verify(pgp_sym_encrypt_sign('Secret.', 'key', dearmor(seckey), '', 'convert-crlf=1'), 'key', dearmor(pubkey), '', 'convert-crlf=1')
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify(pgp_pub_encrypt_sign('Secret.', dearmor(pubkey), dearmor(seckey), '', 'convert-crlf=1'), dearmor(seckey), dearmor(pubkey), '', 'convert-crlf=1')
from keytbl where keytbl.name = 'rsaenc2048';

select pgp_sym_decrypt_verify(pgp_sym_encrypt_sign(E'Secret.\n', 'key', dearmor(seckey), '', 'convert-crlf=1'), 'key', dearmor(pubkey), '', 'convert-crlf=1')
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify(pgp_pub_encrypt_sign(E'Secret.\n', dearmor(pubkey), dearmor(seckey), '', 'convert-crlf=1'), dearmor(seckey), dearmor(pubkey), '', 'convert-crlf=1')
from keytbl where keytbl.name = 'rsaenc2048';

-- encrypt in text with convert-crlf, verify in text without conversion (works)

select pgp_sym_decrypt_verify(pgp_sym_encrypt_sign('Secret.', 'key', dearmor(seckey), '', 'convert-crlf=1'), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify(pgp_pub_encrypt_sign('Secret.', dearmor(pubkey), dearmor(seckey), '', 'convert-crlf=1'), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

select pgp_sym_decrypt_verify(pgp_sym_encrypt_sign(E'Secret.\n', 'key', dearmor(seckey), '', 'convert-crlf=1'), 'key', dearmor(pubkey))
from keytbl where keytbl.name = 'rsa2048';

select pgp_pub_decrypt_verify(pgp_pub_encrypt_sign(E'Secret.\n', dearmor(pubkey), dearmor(seckey), '', 'convert-crlf=1'), dearmor(seckey), dearmor(pubkey))
from keytbl where keytbl.name = 'rsaenc2048';

