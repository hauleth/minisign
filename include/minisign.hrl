-define(COMMENT_PREFIX, <<"untrusted comment: ">>).
-define(TRUSTED_COMMENT_PREFIX, <<"trusted comment: ">>).

-define(SIGALG, <<"Ed">>).
-define(SIGALG_HASHED, <<"ED">>).

-define(DEFAULT_COMMENT, <<"signature from minisign secret key">>).
-define(PUBLICKEY_DEFAULT_COMMENT(Id),
       <<"minisign public key ", (binary:encode_hex(Id))/binary>>).
-define(SECRETKEY_DEFAULT_COMMENT, <<"minisign encrypted secret key">>).
