%% Argument checking for Erlang's public_key application.

-module(dbg_public_key).

-export([
    format_sign_key/1,
    format_verify_key/1,
    sign/3,
    sign/4,
    verify/4,
    verify/5
    ]).

-record('ECPoint', {
	point
	}).

-record('ECPrivateKey', {
    version,
    privateKey,
    parameters,
    publicKey,
    attributes
    }).

namedCurves({1, 3, 101, 112}) -> ed25519.

ec_curve_spec({namedCurve, OID}) when is_tuple(OID), is_integer(element(1,OID)) ->
    ec_curve_spec({namedCurve, namedCurves(OID)});
ec_curve_spec({namedCurve, ed25519 = Name}) ->
    Name;
ec_curve_spec({namedCurve, Name}) when is_atom(Name) ->
    crypto:ec_curve(Name);
ec_curve_spec(_) ->
    whatever.

format_sign_key(#'ECPrivateKey'{privateKey = PrivKey, parameters = {namedCurve, Curve} = Param})
  when (Curve == {1, 3, 101, 112}) orelse (Curve == {1, 3, 101, 112}) ->
    ECCurve = ec_curve_spec(Param),
    {eddsa, [PrivKey, ECCurve]};
format_sign_key(#'ECPrivateKey'{privateKey = PrivKey, parameters = Param}) ->
    ECCurve = ec_curve_spec(Param),
    {ecdsa, [PrivKey, ECCurve]};
format_sign_key({ed_pri, Curve, _Pub, Priv}) ->
    {eddsa, [Priv,Curve]};
format_sign_key(_) ->
    badarg.

format_verify_key({#'ECPoint'{point = Point}, {namedCurve, Curve} = Param}) when (Curve == {1, 3, 101, 112}) orelse
                                                                                 (Curve == {1, 3, 101, 112}) ->
    ECCurve = ec_curve_spec(Param),
    {eddsa, [Point, ECCurve]};
format_verify_key({#'ECPoint'{point = Point}, Param}) ->
    ECCurve = ec_curve_spec(Param),
    {ecdsa, [Point, ECCurve]};
format_verify_key({ed_pub, Curve, Key}) ->
    {eddsa, [Key,Curve]};
format_verify_key(#'ECPrivateKey'{parameters = Param, publicKey = {_, Point}}) ->
    format_verify_key({#'ECPoint'{point = Point}, Param});
format_verify_key(#'ECPrivateKey'{parameters = Param, publicKey = Point}) ->
    format_verify_key({#'ECPoint'{point = Point}, Param});
format_verify_key(_) ->
    badarg.

%%--------------------------------------------------------------------
%% Description: Create digital signature.
%%--------------------------------------------------------------------
sign(DigestOrPlainText, DigestType, Key) ->
    sign(DigestOrPlainText, DigestType, Key, []).

sign(DigestOrPlainText, DigestType, Key, Options) ->
    case format_sign_key(Key) of
        badarg ->
            erlang:error(badarg, [DigestOrPlainText, DigestType, Key, Options]);
        {Algorithm, CryptoKey} ->
            try crypto:sign(Algorithm, DigestType, DigestOrPlainText, CryptoKey, Options)
            catch %% Compatible with old error schema
                error:{notsup,_,_} -> error(notsup);
                error:{error,_,_} -> error(error);
                error:{badarg,_,_} ->
                    erlang:error(cryptoSignBadarg, [Algorithm, DigestType, DigestOrPlainText, CryptoKey, Options])
            end
    end.

%%--------------------------------------------------------------------
%% Description: Verifies a digital signature.
%%--------------------------------------------------------------------
verify(DigestOrPlainText, DigestType, Signature, Key) ->
    verify(DigestOrPlainText, DigestType, Signature, Key, []).

verify(DigestOrPlainText, DigestType, Signature, Key, Options) when is_binary(Signature) ->
    case format_verify_key(Key) of
        badarg ->
            erlang:error(badarg, [DigestOrPlainText, DigestType, Signature, Key, Options]);
        {Algorithm, CryptoKey} ->
            try crypto:verify(Algorithm, DigestType, DigestOrPlainText, Signature, CryptoKey, Options)
            catch %% Compatible with old error schema
                error:{notsup,_,_} -> error(notsup);
                error:{error,_,_} -> error(error);
                error:{badarg,_,_} ->
                    erlang:error(cryptoVerifyBadarg, [Algorithm, DigestType, DigestOrPlainText, Signature, CryptoKey, Options])
            end
    end;
verify(_,_,_,_,_) ->
    %% If Signature is a bitstring and not a binary we know already at this
    %% point that the signature is invalid.
    false.
