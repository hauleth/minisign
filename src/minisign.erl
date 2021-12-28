-module(minisign).

%% Keys management
-export([gen_key/0, to_public/1]).
-export([export_key/1, export_key/2]).
-export([import_key/1]).
%% Signature and verification
-export([sign/2, sign/3]).
-export([verify/3]).

-export_type([priv_key/0, public_key/0]).

-include_lib("minisign.hrl").

-record(priv_key, {signature_algorithm = <<"Ed">>, key_id, secret_key, public_key}).
-record(public_key, {signature_algorithm = <<"Ed">>, key_id, public_key}).

%% Private key used for signing
%%
%% Additionally can be used for checking signatures, however that behaviour is
%% meant only for testing, as using private key for checking signatures is
%% pointless (if you have private key, then you can forge any message you want).
-opaque priv_key() :: #priv_key{}.
-opaque public_key() :: #public_key{}.

%% @doc Generate key for signing.
%%
%% Returned value can be used as public and private key. It can be converted to
%% be just private key via {@link to_public/1. `to_public/1'}.
%% @end
-spec gen_key() -> priv_key().
gen_key() ->
        {RawPublicKey, RawPrivKey} = crypto:generate_key(eddsa, ed25519),
        KeyId = crypto:strong_rand_bytes(8),
        PrivKey = #priv_key{key_id = KeyId,
                            public_key = RawPublicKey,
                            secret_key = RawPrivKey},
        PrivKey.

%% @doc Convert private key into public key that is safe for sharing.
%% @end
-spec to_public(priv_key()) -> public_key().
to_public(#priv_key{signature_algorithm = Algo,
                    key_id = KeyId,
                    public_key = Key}) ->
        #public_key{signature_algorithm = Algo,
                    key_id = KeyId,
                    public_key = Key}.

%% @equiv export_key(Key, #{})
-spec export_key(public_key() | priv_key()) -> binary().
export_key(Key) ->
        export_key(Key, #{}).

%% @doc Export <b>public key</b> from the passed key.
%%
%% Currently this library do not support exporting private keys.
%% @end
-spec export_key(public_key() | priv_key(), Opts) -> binary()
        when Opts :: #{untrusted_comment := binary()}.
export_key(#priv_key{signature_algorithm = Algo,
                     key_id = KeyId,
                     public_key = Key},
           Opts) ->
        UntrustedComment = maps:get(untrusted_comment, Opts, ?PUBLICKEY_DEFAULT_COMMENT(KeyId)),
        Encoded = base64:encode(<<Algo/binary, KeyId/binary, Key/binary>>),
        <<?COMMENT_PREFIX/binary, UntrustedComment/binary, $\n, Encoded/binary, $\n>>;
export_key(#public_key{signature_algorithm = Algo,
                       key_id = KeyId,
                       public_key = Key},
           Opts) ->
        UntrustedComment = maps:get(untrusted_comment, Opts, ?PUBLICKEY_DEFAULT_COMMENT(KeyId)),
        Encoded = base64:encode(<<Algo/binary, KeyId/binary, Key/binary>>),
        <<?COMMENT_PREFIX/binary, UntrustedComment/binary, $\n, Encoded/binary, $\n>>.

%% @doc Import public key.
%%
%% Importing private keys is currently unsupported.
%% @end
-spec import_key(binary()) -> {ok, public_key(), binary()} | {error, term()}.
import_key(Data) ->
        {RawKey, Comment} =
                case string:split(Data, "\n", all) of
                        [Raw] ->
                                {Raw, <<>>};
                        [C, Raw] ->
                                {Raw, C};
                        [C, Raw, <<>>] ->
                                {Raw, C}
                end,
        try base64:decode(RawKey) of
                <<"Ed", KeyId:8/binary, Key/binary>> ->
                        {ok,
                         #public_key{signature_algorithm = <<"Ed">>,
                                     key_id = KeyId,
                                     public_key = Key},
                         Comment}
        catch
                _ ->
                        {error, invalid_data}
        end.

%% @equiv sign(Message, Key, #{type => hash})
-spec sign(binary(), priv_key()) -> binary().
sign(Message, Key) ->
        sign(Message, Key, #{type => hash}).

%% @doc Sign given data using private key.
%% @end
-spec sign(binary, priv_key(), Opts) -> binary()
        when Opts ::
                     #{type := plain | hash,
                       untrusted_comment := binary(),
                       trusted_comment := binary()}.
sign(Message, Key, #{type := Type} = Opts) when Type =:= hash; Type =:= plain ->
        {Alg, Data} = prehash(Message, Type =:= hash),
        do_sign(Alg, Data, Key, Opts).

-define(comment,
        iolist_to_binary(io_lib:format("timestamp:~B", [erlang:system_time(second)]))).

do_sign(Type, Message, #priv_key{key_id = Id, secret_key = Key}, Opts) ->
        UntrustedComment = maps:get(untrusted_comment, Opts, ?DEFAULT_COMMENT),
        TrustedComment = maps:get(comment, Opts, ?comment),
        Signature = crypto:sign(eddsa, none, Message, [Key, ed25519]),
        EncSign = base64:encode(<<Type/binary, Id/binary, Signature/binary>>),
        GlobSignature =
                crypto:sign(eddsa,
                            none,
                            <<Signature/binary, TrustedComment/binary>>,
                            [Key, ed25519]),
        EncGlobSign = base64:encode(GlobSignature),
        <<?COMMENT_PREFIX/binary,
          UntrustedComment/binary,
          $\n,
          EncSign/binary,
          $\n,
          ?TRUSTED_COMMENT_PREFIX/binary,
          TrustedComment/binary,
          $\n,
          EncGlobSign/binary,
          $\n>>.

%% @doc Verify signature for given key and data.
%% @end
-spec verify(binary(), binary(), priv_key() | public_key()) ->
                    {ok, Comment, TrustedComment} | error
        when Comment :: binary(),
             TrustedComment :: binary().
verify(Data, Signature, Key) when is_binary(Signature) ->
        Lines = string:split(Signature, "\n", all),
        try
                do_verify(Data, Lines, Key)
        catch
                _ ->
                        error
        end.

do_verify(DataRaw, [UntrustedComment, EncSign, TrustedComment, EncGlobSign, <<>>], Key) ->
        KeyId = key_id(Key),
        PublicKey = public_key(Key),
        Signature = base64:decode(EncSign),
        GlobSign = base64:decode(EncGlobSign),

        case {Signature, string:prefix(TrustedComment, ?TRUSTED_COMMENT_PREFIX)} of
                {_, nomatch} ->
                        error;
                {<<Alg:2/binary, SKeyId:8/binary, Sig/binary>>, Comment}
                        when Alg =:= ?SIGALG orelse Alg =:= ?SIGALG_HASHED, SKeyId =:= KeyId ->
                        {_, Data} = prehash(DataRaw, Alg =:= ?SIGALG_HASHED),
                        case crypto:verify(eddsa, none, Data, Sig, [PublicKey, ed25519])
                             and crypto:verify(eddsa,
                                               none,
                                               <<Sig/binary, Comment/binary>>,
                                               GlobSign,
                                               [PublicKey, ed25519])
                        of
                                true ->
                                        {ok, UntrustedComment, Comment};
                                false ->
                                        error
                        end;
                _ ->
                        error
        end.

key_id(#public_key{key_id = KeyId}) ->
        KeyId;
key_id(#priv_key{key_id = KeyId}) ->
        KeyId.

public_key(#public_key{public_key = KeyId}) ->
        KeyId;
public_key(#priv_key{public_key = KeyId}) ->
        KeyId.

prehash(Data, false) ->
        {?SIGALG, Data};
prehash(Data, true) ->
        {?SIGALG_HASHED, crypto:hash(blake2b, Data)}.
