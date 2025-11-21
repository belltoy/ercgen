-module(ercgen).

-export([
    default_certificate_params/0,
    generate_rsa_private_key/0,
    check_certificate_params/1,
    rsa_public_key_to_pem/1,
    rsa_private_key_to_der/1,
    signed_by/4
]).

-export_type([
    gen_error/0,
    cert_params/0,
    san_type/0,
    dn/0,
    key_usage/0,
    ext_key_usage/0,
    custom_extension/0,
    name_constraints/0,
    general_subtree/0,
    crl_distribution_point/0,
    uri/0
]).

-include_lib("public_key/include/public_key.hrl").
-include("cargo.hrl").
-on_load(init/0).
-define(NOT_LOADED, not_loaded(?LINE)).

-type cert_params() :: #{
    not_before => {Year :: integer(), Month :: pos_integer(), Day :: pos_integer()},
    not_after => {Year :: integer(), Month :: pos_integer(), Day :: pos_integer()},
    serial_number => undefined | [integer()],
    subject_alt_names => [san_type()],
    distinguished_name => dn(),
    is_ca => no_ca | explicit_no_ca | {ca, {constrained, integer()} | unconstrained},
    key_usages => [key_usage()],
    extended_key_usages => [ext_key_usage()],
    name_constraints => undefined | name_constraints(),
    crl_distribution_points => [crl_distribution_point()],
    custom_extensions => [custom_extension()],
    use_authority_key_identifier_extension => boolean(),
    key_identifier_method => sha256 | sha384 | sha512 | {pre_specified, [integer()]}
}.

-type name_constraints() :: #{
    permitted_subtrees => [general_subtree()],
    excluded_subtrees => [general_subtree()]
}.

-type general_subtree() ::
    {dns_name, binary()} |
    {rfc822_name, binary()} |
    {ip_address, binary()} |
    {directory_name, dn()}.

-type crl_distribution_point() :: [uri()].

-type uri() :: binary().

-type dn() :: #{
    organizational_unit_name => binary(),
    organization_name => binary(),
    common_name => binary(),
    country_name => binary(),
    locality_name => binary(),
    state_or_province_name => binary(),
    {custom_dn_type, Oid :: [integer()]} => binary()
}.

-type san_type() ::
    {dns_name, binary()} |
    {ip_address, binary()} |
    {other_name, #{value := binary(), oid := [integer()]}}.

-type key_usage() ::
    digital_signature |
    content_commitment |
    key_encipherment |
    data_encipherment |
    key_agreement |
    key_cert_sign |
    crl_sign |
    encipher_only |
    decipher_only.

-type ext_key_usage() ::
    any |
    server_auth |
    client_auth |
    code_signing |
    email_protection |
    time_stamping |
    ocsp_signing |
    {other, [non_neg_integer()]}.

-type custom_extension() :: #{
    critical := boolean(),
    oid := [integer()],
    content := [integer()]
}.

-type gen_error() ::
    could_not_parse_certificate |
    could_not_parse_certification_request |
    could_not_parse_key_pair |
    invalid_name_type |
    invalid_asn1_string |
    invalid_ip_address_octet_length |
    key_generation_unavailable |
    unsupported_extension |
    unsupported_signature_algorithm |
    ring_unspecified |
    ring_key_rejected |
    time |
    pem_error |
    remote_key_error |
    unsupported_in_csr |
    invalid_crl_next_update |
    issuer_not_crl_signer |
    x509 |
    invalid_cidr |
    invalid_ip_address |
    pem_missing_section_end |
    pem_illegal_section_start |
    pem_base64_decode |
    pem_io |
    pem_no_items_found |
    unknown.

%%%===================================================================
%%% API
%%%===================================================================

-spec generate_rsa_private_key() -> {#'RSAPublicKey'{}, #'RSAPrivateKey'{}}.
generate_rsa_private_key() ->
    #'RSAPrivateKey'{
        modulus = Modulus,
        publicExponent = PublicExponent
    } = RSAPrivateKey = public_key:generate_key({rsa, 2048, 65537}),

    RSAPublicKey = #'RSAPublicKey'{modulus = Modulus, publicExponent = PublicExponent},
    {RSAPublicKey, RSAPrivateKey}.

-spec rsa_public_key_to_pem(#'RSAPublicKey'{}) -> Pem :: binary().
rsa_public_key_to_pem(#'RSAPublicKey'{} = RSAPublicKey) ->
    Entry = public_key:pem_entry_encode('SubjectPublicKeyInfo', RSAPublicKey),
    public_key:pem_encode([Entry]).

-spec rsa_private_key_to_der(#'RSAPrivateKey'{}) -> Der :: binary().
rsa_private_key_to_der(#'RSAPrivateKey'{} = RSAPrivateKey) ->
    public_key:der_encode('RSAPrivateKey', RSAPrivateKey).

-spec default_certificate_params() -> cert_params().
default_certificate_params() ->
    ?NOT_LOADED.

-spec check_certificate_params(cert_params() | any()) -> {ok, cert_params()} | {error, term()}.
check_certificate_params(Params) ->
    try
        Params1 = certificate_params_echo(Params),
        {ok, Params1}
    catch
        _:Reason -> {error, Reason}
    end.

-spec certificate_params_echo(cert_params() | any()) -> cert_params().
certificate_params_echo(_Params) ->
    ?NOT_LOADED.

-spec signed_by(cert_params(), PublicKeyPem, IssuerCertPem, IssuerPrivateKeyPem) -> Result when
    PublicKeyPem :: binary(),
    IssuerCertPem :: binary(),
    IssuerPrivateKeyPem :: binary(),
    SignedCertPem :: binary(),
    Result :: {ok, SignedCertPem} | {error, gen_error()}.
signed_by(_CertParams, _PublicKeyPem, _IssuerCertPem, _IssuerPrivateKeyPem) ->
    ?NOT_LOADED.

%%%===================================================================
%%% NIF
%%%===================================================================

init() ->
    ?load_nif_from_crate(ercgen, 0).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).
