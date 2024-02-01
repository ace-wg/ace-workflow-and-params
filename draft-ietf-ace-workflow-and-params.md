---
v: 3

title: Alternative Workflow and OAuth Parameters for the Authentication and Authorization for Constrained Environments (ACE) Framework
abbrev: Alternative ACE Workflow and Parameters
docname: draft-ietf-ace-workflow-and-params-latest

# stand_alone: true

ipr: trust200902
area: Security
wg: ACE Working Group
kw: Internet-Draft
cat: std
submissiontype: IETF
updates: 9200

coding: utf-8
pi:    # can use array (if all yes) or hash here

  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
      -
        ins: M. Tiloca
        name: Marco Tiloca
        org: RISE AB
        street: Isafjordsgatan 22
        city: Kista
        code: SE-16440
        country: Sweden
        email: marco.tiloca@ri.se
      -
        ins: G. Selander
        name: Göran Selander
        org: Ericsson AB
        street: Torshamnsgatan 23
        city: Kista
        code: SE-16440 Stockholm
        country: Sweden
        email: goran.selander@ericsson.com

normative:
  RFC2119:
  RFC6749:
  RFC7252:
  RFC7800:
  RFC8174:
  RFC8392:
  RFC8446:
  RFC8747:
  RFC8949:
  RFC9052:
  RFC9053:
  RFC9200:
  RFC9201:
  RFC9430:
  I-D.ietf-ace-edhoc-oscore-profile:

informative:
  RFC9202:
  RFC9203:
  RFC9431:
  I-D.ietf-ace-revoked-token-notification:
  I-D.ietf-ace-group-oscore-profile:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document updates the Authentication and Authorization for Constrained Environments Framework (ACE, RFC 9200) as follows. First, it defines a new, alternative workflow that the Authorization Server can use for uploading an access token to a Resource Server on behalf of the Client. Second, it defines new parameters and encodings for the OAuth 2.0 token endpoint at the Authorization Server. Third, it amends two of the requirements on profiles of the framework.

--- middle

# Introduction # {#intro}

The Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}} defines an architecture to enforce access control for constrained devices. A Client (C) requests an assertion of granted permissions from an Authorization Server (AS) in the form of an access token, then uploads the access token to the target Resource Server (RS), and finally accesses protected resources at the RS according to the permissions specified in the access token.

The framework has as main building blocks the OAuth 2.0 framework {{RFC6749}}, the Constrained Application Protocol (CoAP) {{RFC7252}} for message transfer, CBOR {{RFC8949}} for compact encoding, and COSE {{RFC9052}}{{RFC9053}} for self-contained protection of access tokens. In addition, separate profile documents define in detail how the participants in the ACE architecture communicate, especially as to the security protocols that they use.

This document updates {{RFC9200}} as follows.

* It defines a new, alternative protocol workflow for the ACE framework (see {{sec-workflow}}), according to which the AS uploads the access token to the RS on behalf of C, and then informs C about the outcome. The new workflow is especially convenient in deployments where the communication leg between C and the RS is constrained, but the communication leg between the AS and the RS is not.

   The new workflow has no ambition to replace the original workflow. The AS can use one workflow or the other depending, for example, on the specific RS for which an access token has been issued and the nature of the communication leg with that RS.

* It defines additional parameters and encodings for the OAuth 2.0 token endpoint at the AS (see {{sec-parameters}}). These include:

   - "token_upload", used by C to inform the AS that it opts in to use the new ACE workflow, and by the AS to inform C about the outcome of the token uploading to the RS per the new workflow.

   - "rs_cnf2", used by the AS to provide C with the public keys of the RSs in the group-audience for which the access token is issued (see {{Section 6.9 of RFC9200}}).

   - "aud2", used by the AS to provide C with the identifiers of the RSs in the group-audience for which the access token is issued.

   - "anchor_cnf", used by the AS to provide C with the public keys of trust anchors, which C can use to validate the public key of an RS (e.g., as provided in the parameter "rs_cnf" defined in {{RFC9201}} or in the parameter "rs_cnf2" defined in this document).

* It amends two of the requirements on profiles of the ACE framework (see {{sec-updated-requirements}}).

## Terminology ## {#terminology}

{::boilerplate bcp14}

Readers are expected to be familiar with the terms and concepts described in the ACE framework for Authentication and Authorization {{RFC9200}}{{RFC9201}}, as well as with terms and concepts related to CBOR Web Tokens (CWTs) {{RFC8392}} and CWT Confirmation Methods {{RFC8747}}.

The terminology for entities in the considered architecture is defined in OAuth 2.0 {{RFC6749}}. In particular, this includes Client (C), Resource Server (RS), and Authorization Server (AS).

Readers are also expected to be familiar with the terms and concepts related to the CoAP protocol {{RFC7252}}, CBOR {{RFC8949}}, and COSE {{RFC9052}}{{RFC9053}}.

Note that, unless otherwise indicated, the term "endpoint" is used here following its OAuth definition, aimed at denoting resources such as /token and /introspect at the AS, and /authz-info at the RS. This document does not use the CoAP definition of "endpoint", which is "An entity participating in the CoAP protocol."

Furthermore, this document uses the following term.

* Token series: the set comprising all the access tokens issued by the same AS for the same pair (Client, Resource Server).

   Profiles of ACE can provide their extended and specialized definition, e.g., by further taking into account the public authentication credentials of C and the RS.

Examples throughout this document are expressed in CBOR diagnostic notation without the tag and value abbreviations.

# New ACE Workflow # {#sec-workflow}

As defined in {{Section 4 of RFC9200}}, the ACE framework considers what is shown in {{fig-old-workflow}} as its basic protocol workflow.

That is, the Client first sends an access token request to the token endpoint at the AS (step A), specifying permissions that it seeks to obtain for accessing protected resources at the RS, possibly together with information on its own public authentication credentials.

Then, if the request has been successfully verified, authenticated, and authorized, the AS replies to the Client (step B), providing an access token and possibly additional parameters as access information including the actually granted permissions.

Finally, the Client uploads the access token to the RS and, consistently with the permissions granted according to the access token, accesses a resource at the RS (step C), which replies with the result of the resource access (step F). Details about what protocol the Client and the RS use to establish a secure association, mutually authenticate, and secure their communications are defined in the specifically used profile of ACE, e.g., {{RFC9202}}{{RFC9203}}{{RFC9431}}{{I-D.ietf-ace-edhoc-oscore-profile}}{{I-D.ietf-ace-group-oscore-profile}}{{RFC9431}}.

Further interactions are possible between the AS and the RS, i.e., the exchange of an introspection request and response where the AS validates a previously issued access token for the RS (steps D and E).

~~~~~~~~~~~
+--------+                               +---------------+
|        |---(A)-- Token Request ------->|               |
|        |                               | Authorization |
|        |<--(B)-- Access Token ---------|    Server     |
|        |    + Access Information       |               |
|        |    + Refresh Token (optional) +---------------+
|        |                                      ^ |
|        |            Introspection Request  (D)| |
| Client |                         Response     | |(E)
|        |            (optional exchange)       | |
|        |                                      | v
|        |                               +--------------+
|        |---(C)-- Token + Request ----->|              |
|        |                               |   Resource   |
|        |<--(F)-- Protected Resource ---|    Server    |
|        |                               |              |
+--------+                               +--------------+
~~~~~~~~~~~
{: #fig-old-workflow title="ACE Basic Protocol Workflow"}

This section defines a new, alternative protocol workflow shown in {{fig-new-workflow}}, which MAY be supported by the AS. Unlike in the original protocol workflow, the AS uploads the access token to the RS on behalf of the Client, and then informs the Client about the outcome.

If the token uploading has been successfully completed, the AS does not provide the access token to the Client altogether. Instead, the Client simply establishes a secure association with the RS (if that has not happened already), and then accesses protected resources at the RS according to the permissions granted per the access token and specified by the AS as access information.

~~~~~~~~~~~
+--------+                               +----------------------------+
|        |---(A)-- Token Request ------->|                            |
|        |                               |       Authorization        |
|        |<--(B)-- Token Response -------|           Server           |
|        |    + Access Information       |                            |
|        |    + Access Token (optional)  +----------------------------+
|        |    + Refresh Token (optional)   ^ |         | ^
|        |                                 | |         | | Token-Upload
|        |        Introspection Request (D)| |     (A1)| |      Request
| Client |                     Response    | |(E)      | |(A2) Response
|        |        (optional exchange)      | |         | |
|        |                                 | v         v |
|        |                               +----------------------------+
|        |---(C1)-- Token (Optional) --->|                            |
|        |                               |                            |
|        |---(C2)-- Protected Request -->|          Resource          |
|        |                               |           Server           |
|        |<--(F)--- Protected Resource --|                            |
|        |                               |                            |
+--------+                               +----------------------------+
~~~~~~~~~~~
{: #fig-new-workflow title="ACE Alternative Protocol Workflow"}

More specifically, the new workflow consists of the following steps.

* Step A - Like in the original workflow, the Client sends an Access Token Request to the token endpoint at the AS, with the additional indication that it opts in to use the alternative workflow.

   As defined in {{sec-token_upload}}, this information is conveyed to the AS by means of the "token_upload" parameter.

* Step A1 - This new step consists of the AS uploading the access token to the RS, typically at the authz-info endpoint, just like the Client does in the original workflow.

* Step A2 - This new step consists of the RS replying to the AS, following the uploading of the access token at step A1.

* Step B - In the Access Token Response, the AS tells the Client that it has attempted to upload the access token to the RS, specifying the outcome of the token uploading based on the reply received from the RS at step A2.

   As defined in {{sec-token_upload}}, this information is conveyed to the Client by means of the "token_upload" parameter. If the token uploading has succeeded, the AS does not provide the Client with the access token. Otherwise, the AS provides the Client with the access token.

* Step C1 - This step occurs only if the token uploading from the AS has failed, and the AS has provided the Client with the access token at step B. In such a case, the Client uploads the access token to the RS just like at step C of the original workflow.

* Step C2 - The Client attempts to access a protected resource at the RS, according to the permissions granted per the access token and specified by the AS as access information at step B.

* Steps D, E, and F are as in the original workflow.

The new workflow has no ambition to replace the original workflow defined in {{RFC9200}}. The AS can use one workflow or the other depending, for example, on the specific RS for which the access token has been issued and the nature of the communication leg with that RS.

# New ACE Parameters # {#sec-parameters}

The rest of this section defines a number of additional parameters and encodings for the OAuth 2.0 token endpoint at the AS.

## token_upload {#sec-token_upload}

This section defines the additional parameter "token_upload". The parameter can be used in an Access Token Request sent by C to the token endpoint at the AS, as well as in the successful Access Token Response sent as reply by the AS.

* In an Access Token Request

   The parameter "token_upload" is OPTIONAL in an Access Token Request. If present, this parameter MUST encode the CBOR simple value "true" (0xf5). The presence of the parameter indicates that C opts in to use the new, alternative ACE workflow defined in {{sec-workflow}}, whose actual use for uploading the issued access token to the RS is an exclusive prerogative of the AS.

   If the AS supports the new ACE workflow and the Access Token Request includes the parameter "token_upload" with value the CBOR simple value "true" (0xf5), then the AS MAY use the new ACE workflow to upload the access token to the RS on behalf of C. Otherwise, the AS MUST NOT use the new ACE workflow.

* In an Access Token Response

   The parameter "token_upload" is REQUIRED in a successful Access Token Response with response code 2.01 (Created), if both the following conditions apply. Otherwise, the parameter "token_upload" MUST NOT be present.

   - The corresponding Access Token Request included the parameter "token_upload", with value the CBOR simple value "true" (0xf5).

   - The AS has attempted to upload the issued access token at the RS as per the new ACE workflow, irrespective of the result of the token upload.

   When the parameter "token_upload" is present in the Access Token Response, the following applies.

   - If the token upload at the RS was successful, then the parameter "token_upload" MUST encode the CBOR simple value "true" (0xf5), and the access token MUST NOT be included in the Access Token Response.

   - If the token upload at the RS was not successful, then the parameter "token_upload" MUST encode the CBOR simple value "false" (0xf4), and the access token MUST be included in the Access Token Response.

### Examples

{{fig-example-AS-to-C-token-upload}} shows an example with first an Access Token Request from C to the AS, and then an Access Token Response from the AS to C, following the issue of an access token bound to a symmetric PoP key.

The Access Token Response specifies the parameter "token_upload" with value "true", which indicates that the AS has successfully uploaded the access token to the RS on behalf of C.

Consistently, the Access Token Response does not include the access token, while it still includes the parameter "cnf" specifying the symmetric PoP key bound to the access token.

~~~~~~~~~~~
   / Access Token Request /

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: application/ace+cbor
   Payload:
   {
            "audience" : "tempSensor4711",
               "scope" : "read",
        "token_upload" : true
   }


   / Access Token Response /

   Header: Created (Code=2.01)
   Content-Format: application/ace+cbor
   Max-Age: 3560
   Payload:
   {
     "token_upload" : true,
       "expires_in" : 3600,
              "cnf" : {
                "COSE_Key" : {
                  "kty" : 1,
                  "kid" : h'3d027833fc6267ce',
                    "k" : h'73657373696f6e6b6579'
                }
              }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-token-upload title="Example of Access Token Request-Response Exchange. The Access Token Response includes the parameter \"token_upload\" but not the access token, which is bound to a symmetric key and was uploaded to the RS by the AS"}

{{fig-example-AS-to-C-token-upload-failed}} shows another example with first an Access Token Request from C to the AS, and then an Access Token Response from the AS to C, also following the issue of an access token bound to a symmetric PoP key.

In this example, the Access Token Response includes the parameter "token_upload" with value "false", which indicates that the AS has failed to upload the access token to the RS on behalf of C. The Access Token Response also includes the access token and the parameter "cnf" specifying the symmetric PoP key bound to the access token.

Note that, even though the AS has failed to upload the access token to the RS, the response code 2.01 (Created) is used when replying to C, since the Access Token Request as such has been successfully processed at the AS, with the following issue of the access token.

~~~~~~~~~~~
   / Access Token Request /

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: application/ace+cbor
   Payload:
   {
            "audience" : "tempSensor4711",
               "scope" : "read",
        "token_upload" : true
   }


   / Access Token Response /

   Header: Created (Code=2.01)
   Content-Format: application/ace+cbor
   Max-Age: 3560
   Payload:
   {
       "access_token" : h'd08343a1'/...
        (remainder of CWT omitted for brevity;
        CWT contains the symmetric PoP key in the "cnf" claim)/,
       "token_upload" : false,
         "expires_in" : 3600,
                "cnf" : {
                  "COSE_Key" : {
                    "kty" : 1,
                    "kid" : h'3d027833fc6267ce',
                      "k" : h'73657373696f6e6b6579'
                  }
                }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-token-upload-failed title="Example of Access Token Request-Response Exchange. The Access Token Response includes the parameter \"token_upload\" together with the access token, which is bound to a symmetric key and which the AS failed to upload to the RS"}

## rs_cnf2 and aud2 {#sec-rs_cnf2-aud2}

This section defines the additional parameters "rs_cnf2" and "aud2" for an Access Token Response, sent by the AS in reply to a request to the token endpoint from C.

* The parameter "rs_cnf2" is OPTIONAL if the token type is "pop", asymmetric keys are used, and the access token is issued for an audience that includes multiple RSs (i.e., a group-audience, see {{Section 6.9 of RFC9200}}). Otherwise, the parameter "rs_cnf2" MUST NOT be present.

   This parameter specifies information about the public keys used by the RSs of a group-audience for authenticating themselves to C, and is used in case the binding between the public keys and the corresponding RS identities are not established through other means. If this parameter is absent, either the RSs in the group-audience do not use a public key, or the AS knows that the RSs can authenticate themselves to C without additional information.

   If present, this parameter MUST encode a non-empty CBOR array of N elements, where N is the number of RSs in the group-audience for which the access token is issued. Each element of the CBOR array specifies the public key of one RS in the group-audience, and MUST follow the syntax and semantics of the "cnf" claim either from {{Section 3.1 of RFC8747}} for CBOR-based interactions, or from {{Section 3.1 of RFC7800}} for JSON-based interactions. It is not required that all the elements of the CBOR array rely on the same confirmation method.

   Each of the public keys may contain parameters specifying information such as the public key algorithm and use (e.g., by means of the parameters "alg" or "key_ops" in a COSE_Key structure). If such information is specified, a Client MUST NOT use a public key that is incompatible with the profile or PoP algorithm according to that information. An RS MUST reject a proof of possession using such a key with a response code equivalent to the CoAP code 4.00 (Bad Request).

* The parameter "aud2" is OPTIONAL and specifies the identifiers of the RSs in the group-audience for which the access token is issued.

   If present, this parameter MUST encode a non-empty CBOR array of N elements, where N is the number of RSs in the group-audience for which the access token is issued. Each element of the CBOR array in the "aud2" parameter MUST be a CBOR text string, with value the identifier of one RS in the group-audience.

   The element of the CBOR array referring to an RS in the group-audience SHOULD have the same value that would be used to identify that RS through the parameter "aud" of an Access Token Request to the AS (see {{Section 5.8.2 of RFC9200}}) and of an Access Token Response from the AS (see {{Section 5.8.2 of RFC9200}}), when requesting and issuing an access token for that individual RS.

   The parameter "aud2" is REQUIRED if the parameter "rs_cnf2" is present. In such a case, the i-th element of the CBOR array in the "aud2" parameter MUST be the identifier of the RS whose public key is specified as the i-th element of the CBOR array in the "rs_cnf2" parameter.

### Example

{{fig-example-AS-to-C-rs_cnf2}} shows an example of Access Token Response from the AS to C, following the issue of an access token for a group-audience composed of two RSs "rs1" and "rs2", and bound to C's public key as asymmetric PoP key. The Access Token Response includes the access token, as well as the parameters "rs_cnf2" and "aud2". These specify the public key of the two RSs as intended recipients of the access token and the identifiers of those two RSs, respectively.

~~~~~~~~~~~
   2.01 Created
   Content-Format: application/ace+cbor
   Max-Age: 3600
   Payload:
   {
     "access_token" : b64'SlAV32hk'/...
      (remainder of CWT omitted for brevity;
      CWT contains the client's RPK in the "cnf" claim)/,
     "expires_in" : 3600,
     "rs_cnf2" : [
       {
         "COSE_Key" : {
           "kty" : 2,
           "crv" : 1,
           "x" : h'bbc34960526ea4d32e940cad2a234148
                   ddc21791a12afbcbac93622046dd44f0',
           "y" : h'4519e257236b2a0ce2023f0931f1f386
                   ca7afda64fcde0108c224c51eabf6072'
         }
       },
       {
         "COSE_Key" : {
           "kty" : 2,
           "crv" : 1,
           "x" : h'ac75e9ece3e50bfc8ed6039988952240
                   5c47bf16df96660a41298cb4307f7eb6',
           "y" : h'6e5de611388a4b8a8211334ac7d37ecb
                   52a387d257e6db3c2a93df21ff3affc8'
         }
       }
     ],
     "aud2" : ["rs1", "rs2"]
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-rs_cnf2 title="Example of Access Token Response with an access token bound to an asymmetric key, using the parameters \"rs_cnf2\" and \"aud2\""}

## anchor_cnf {#sec-anchor_cnf}

This section defines the additional parameter "anchor_cnf" for an Access Token Response, sent by the AS in reply to a request to the token endpoint from C.

The parameter "anchor_cnf" is OPTIONAL if the token type is "pop" and asymmetric keys are used. Otherwise, the parameter "anchor_cnf" MUST NOT be present.

This parameter specifies information about the public keys of trust anchors, which C can use to validate the public key of the RS/RSs included in the audience for which the access token is issued. This parameter can be used when the access token is issued for an audience including one RS or multiple RSs.

If this parameter is absent, either the RS/RSs in the audience do not use a public key, or the AS knows that C can validate the public key of such RS/RSs without additional information (e.g., C has already obtained the required public keys of the involved trust anchors from the AS or through other means).

If present, this parameter MUST encode a non-empty CBOR array that MUST be treated as a set, i.e., the order of its elements has no meaning. Each element of the CBOR array specifies the public key of one trust anchor, which can be used to validate the public key of at least one RS included in the audience for which the access token is issued. Each element of the CBOR array MUST follow the syntax and semantics of the "cnf" claim either from {{Section 3.1 of RFC8747}} for CBOR-based interactions, or from {{Section 3.1 of RFC7800}} for JSON-based interactions. It is not required that all the elements of the CBOR array rely on the same confirmation method.

Each of the public keys specified in the parameter "anchor_cnf" may contain parameters specifying information such as the public key algorithm and use (e.g., by means of the parameters "alg" or "key_ops" in a COSE_Key structure). If such information is specified, a Client MUST NOT use a public key that is incompatible with the profile, or with the public keys to validate and the way to validate those.

The presence of this parameter does not require that the Access Token Response also includes the parameter "rs_cnf" defined in {{RFC9201}} or the parameter "rs_cnf2" defined in {{sec-rs_cnf2-aud2}} of this document. That is, C may be able to obtain the public keys of the RS/RSs for which the access token is issued through other means.

When the Access Token Response includes both the parameter "anchor_cnf" and the parameter "aud2" defined in {{sec-rs_cnf2-aud2}}, then C MUST make sure that a public key PK_RS is associated with an RS identified by an element of "aud2", before using any of the public keys specified in "anchor_cnf" to validate PK_RS.

When the Access Token Response includes the parameter "anchor_cnf" but not the parameter "aud2", then C can use any of the public keys specified in "anchor_cnf" to validate the public key PK_RS of any RS in the targeted audience. This allows C to use the access token with an RS that is deployed later on as part of the same audience, which is particularly useful in the case of a group-audience.

### Example

{{fig-example-AS-to-C-anchor_cnf}} shows an example of Access Token Response from the AS to C, following the issue of an access token for a group-audience, and bound to C's public key as asymmetric PoP key.

The identifier of the group-audience was specified by the "aud" parameter of the Access Token Request to the AS and is specified by the "aud" claim of the issued access token, and is not repeated in the Access Token Response from the AS.

The Access Token Response includes the parameter "anchor_cnf". This specifies the public key of a trust anchor that C can use to validate the public keys of any RS with which the access token is going to be used. The public key of the trust anchor is here conveyed within an X.509 certificate used as public authentication credential for that trust anchor, by means of the CWT confirmation method "x5chain" defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

~~~~~~~~~~~
   2.01 Created
   Content-Format: application/ace+cbor
   Max-Age: 3600
   Payload:
   {
     "access_token" : b64'SlAV32hk'/...
      (remainder of CWT omitted for brevity;
      CWT contains the client's RPK in the "cnf" claim)/,
     "expires_in" : 3600,
     "anchor_cnf" : [
       {
         "x5chain" : h'308201363081dea003020102020301f50d30
                       0a06082a8648ce3d04030230163114301206
                       035504030c0b524643207465737420434130
                       1e170d3230303130313030303030305a170d
                       3231303230323030303030305a3022312030
                       1e06035504030c1730312d32332d34352d46
                       462d46452d36372d38392d41423059301306
                       072a8648ce3d020106082a8648ce3d030107
                       03420004b1216ab96e5b3b3340f5bdf02e69
                       3f16213a04525ed44450b1019c2dfd3838ab
                       ac4e14d86c0983ed5e9eef2448c6861cc406
                       547177e6026030d051f7792ac206a30f300d
                       300b0603551d0f040403020780300a06082a
                       8648ce3d04030203470030440220445d798c
                       90e7f500dc747a654cec6cfa6f037276e14e
                       52ed07fc16294c84660d02205a33985dfbd4
                       bfdd6d4acf3804c3d46ebf3b7fa62640674f
                       c0354fa056dbaea6'
       }
     ]
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-anchor_cnf title="Example of Access Token Response with an access token bound to an asymmetric key, using the parameter \"anchor_cnf\""}

# Updated Requirements on Profiles # {#sec-updated-requirements}

{{Section C of RFC9200}} compiles a list of requirements on the profiles of ACE. This document amends two of those requirements as follows.

The text of the fifth requirement

{:quote}
> Specify the security protocol the client and RS must use to protect their communication (e.g., OSCORE or DTLS). This must provide encryption and integrity and replay protection (Section 5.8.4.3).

is replaced by the following text:

{:quote}
> Specify the security protocol the client and RS must use to protect their communication (e.g., OSCORE or DTLS). In combination with the used communication protocol, this must provide encryption, integrity and replay protection, and a binding between requests and responses (Section 5.8.4.3 and Section 6.5).

The text of the tenth requirement

{:quote}
> Specify the communication and security protocol for interactions between the client and AS. This must provide encryption, integrity protection, replay protection, and a binding between requests and responses (Sections 5 and 5.8).

is replaced by the following text:

{:quote}
> Specify the communication and security protocol for interactions between the client and AS. The combined use of those protocols must provide encryption, integrity protection, replay protection, and a binding between requests and responses (Sections 5 and 5.8).

At the time of writing, all the profiles of ACE that are published as RFC (i.e., {{RFC9202}}{{RFC9203}}{{RFC9431}}) already comply with the two updated requirements as formulated above.

# Security Considerations

The same security considerations from the ACE framework for Authentication and Authorization {{RFC9200}} apply to this document, together with those from the specifically used transport profile of ACE, e.g., {{RFC9202}}{{RFC9203}}{{RFC9431}}{{I-D.ietf-ace-edhoc-oscore-profile}}{{I-D.ietf-ace-group-oscore-profile}}{{RFC9431}}.

Editor's note: add more security considerations.

# IANA Considerations

This document has the following actions for IANA.

## OAuth Parameters Registry ## {#iana-oauth-params}

IANA is asked to add the following entries to the "OAuth Parameters" registry.

* Name: "token_upload"
* Parameter Usage Location: token request and token response
* Change Controller: IESG
* Reference: {{&SELF}}

&nbsp;

* Name: "rs_cnf2"
* Parameter Usage Location: token response
* Change Controller: IESG
* Reference: {{&SELF}}

&nbsp;

* Name: "aud2"
* Parameter Usage Location: token response
* Change Controller: IESG
* Reference: {{&SELF}}

&nbsp;

* Name: "anchor_cnf"
* Parameter Usage Location: token response
* Change Controller: IESG
* Reference: {{&SELF}}

## OAuth Parameters CBOR Mappings Registry ## {#iana-oauth-cbor-mappings}

IANA is asked to add the following entries to the "OAuth Parameters CBOR Mappings" following the procedure specified in {{RFC9200}}.

* Name: "token_upload"
* CBOR Key: TBD
* Value Type: simple value "true" / simple value "false"
* Reference: {{&SELF}}

&nbsp;

* Name: "rs_cnf2"
* CBOR Key: TBD
* Value Type: array
* Reference: {{&SELF}}

&nbsp;

* Name: "aud2"
* CBOR Key: TBD
* Value Type: array
* Reference: {{&SELF}}

&nbsp;

* Name: "anchor_cnf"
* CBOR Key: TBD
* Value Type: array
* Reference: {{&SELF}}

--- back

# Benefits for ACE Transport Profiles # {#sec-benefits-for-profiles}

For any transport profile of ACE, the following holds.

* The new ACE workflow defined in {{sec-workflow}} is effectively possible to use. This is beneficial for deployments where the communication leg between C and the RS is constrained, but the communication leg between the AS and RS is not.

* When the new ACE workflow is used, the parameter "token_upload" defined in {{sec-token_upload}} is used:

   - To inform the AS that C opts in to use the new ACE workflow; and

   - To inform C that the AS has attempted to upload the issued access token to the RS, specifying whether the uploading has succeeded or failed.

## DTLS Profile

When the RPK mode of the DTLS profile is used (see {{Section 3.2 of RFC9202}}), it becomes possible for the AS to effectively issue an access token intended to an audience that includes multiple RSs. This is enabled by the parameters "rs_cnf2" and "aud2" defined in {{sec-rs_cnf2-aud2}}, as well as by the parameter "anchor_cnf" defined in {{sec-anchor_cnf}}. This seamlessly applies also if the profile uses Transport Layer Security (TLS) {{RFC8446}}, as defined in {{RFC9430}}.

## EDHOC and OSCORE Profile

When the EDHOC and OSCORE profile is used {{I-D.ietf-ace-edhoc-oscore-profile}}, it becomes possible for the AS to effectively issue an access token intended to an audience that includes multiple RSs. This is enabled by the parameters "rs_cnf2" and "aud2" defined in {{sec-rs_cnf2-aud2}}, as well as by the parameter "anchor_cnf" defined in {{sec-anchor_cnf}}.

# Open Points # {#sec-open-points}

## New Workflow # {#sec-open-points-workflow}

The following discusses open points related to the use of the new ACE workflow defined in {{sec-workflow}}.

### Allow the Dynamic Update of Access Rights # {#sec-open-points-workflow-dynamic-access-rights}

In some profiles of ACE, C can request a new access token to update its access rights, while preserving the same secure association with the RS. The new access token supersedes the current one stored at the RS, as they are both part of the same token series.

When using the original ACE workflow, C uploads the new access token to the RS by protecting the message exchange through the secure association with the RS. This allows the RS to determine that the upload of such access token is for updating the access rights of C.

When using the new ACE workflow, the AS uploads the new access token to the RS also when an update of access rights for C is to be performed. This message exchange would be protected through the secure association between the AS and the RS. However, this secure association does not help the RS retrieve the stored access token to supersede, as that is rather bound to the secure association with C.

In order for the new ACE workflow to also allow the dynamic update of access rights, it is required that the new access token updating the access rights of C includes an explicit indication for the RS. Such an indication can point the RS to the token series in question (hence to the current access token to supersede), irrespective of the secure association used to protect the token uploading.

In some profiles of ACE, such an indication is in fact already present in issued access tokens:

* In the PSK mode of the DTLS profile {{RFC9202}}, the token series is indicated by the parameter "kid" within the claim "cnf" of the new access token. This has the same value of the parameter "kid" in the COSE_Key within the claim "cnf" from the first access token of the token series.

* In the OSCORE profile {{RFC9203}}, the token series is indicated by the parameter "kid" within the claim "cnf" of the new access token. This has the same value of the parameter "id" in the OSCORE_Input_Material object within the claim "cnf" from the first access token of the token series.

* In the EDHOC and OSCORE profile {{I-D.ietf-ace-edhoc-oscore-profile}}, the token series is indicated by the parameter "kid" within the claim "cnf" of the new access token. This has the same value of the parameter "id" in the EDHOC_Information object within the claim "cnf" from the first access token of the token series.

In the three cases above, the update of access rights is possible because there is a value used as de facto "token series ID". This value does not change throughout the lifetime of a token series, and it is used to associate the new access token with the previous one in the same series to be superseded.

Such a token series ID is required to have a unique value from a namespace/pool that the AS exclusively controls. This is in fact what happens in the profiles of ACE above, where the AS is the entity creating the mentioned objects or COSE Key included in the first access token of a token series.

However, this may generally not hold and it is not what happens in other known cases, i.e., the DTLS profile in RPK mode {{RFC9203}} and the Group OSCORE profile {{I-D.ietf-ace-group-oscore-profile}}. At the moment, the dynamic update of access rights is not possible for those, _neither in the original nor in the new ACE workflow_.

In order to make the update of access rights possible also for such cases, as well as both in the original and in the new ACE workflow, those cases can rely on a new parameter and claim "token_series_id" (see {{sec-more-parameters}}), which specifies a unique identifier of the token series which an access token belongs to.

As to existing profiles of ACE, the above has no intention to change the current behavior when the update of access rights occurs, irrespective of the used ACE workflow and especially when using the original workflow.

If future profiles rely on a construction where the AS creates the object or the key included in the claim "cnf" of the first access token in a token series, and a unique ID generated by the AS is included in such object or key, then that ID must be used as de facto "token series ID", rather than the new parameter "token_series_id".

### Allow the Re-uploading of the Access Token # {#sec-open-points-workflow-token-re-uploading}

After the AS has successfully uploaded the access token to the RS when using the new ACE workflow, C does not obtain the access token altogether. It follows that C cannot re-upload the Access Token to the RS by itself, e.g., in order to perform a key update like defined for the OSCORE profile {{RFC9203}}.

Even in such a case, the token re-uploading can be allowed by relying on a new parameter "token_hash", which the AS provides to C and specifies the hash of the access token (see {{sec-more-parameters}}).

Then, C can practically "re-upload" the access token to the RS, by sending a request to the authz-info endpoint that includes the parameter "token_hash" instead of the parameter "access_token". Such a request may include further parameters, depending on what is defined for the used transport profile.

If the RS still stores the access token in question, then the RS can identify it by means of the received token hash, and take the same actions that would have been taken in case the full access token was re-uploaded to the authz-info endpoint.

### Ensure Applicability to Any ACE Profile # {#sec-open-points-workflow-applicability}

Some profiles of ACE require that C and the RS generate information to be exchanged when uploading the access token.

For example, in the OSCORE profile {{RFC9203}}, C and the RS exchange the nonces N1 and N2 together with their OSCORE Recipient IDs ID1 and ID2, when uploading to the RS the first access token of a token series, as well as when re-uploading any access token (e.g., in order to perform a key update).

Evidently, using the new ACE workflow prevents C and the RS from directly performing the required exchanges above, since the uploading of the access token does not rely on a direct interaction between C and the RS like in the original ACE workflow. For some profiles of ACE, this may prevent the use of the new ACE workflow altogether.

This issue can be solved by having the AS acting as intermediary also for the exchange of C- and RS-generated information, by relying on two new parameters "to_rs" and "from_rs" (see {{sec-more-parameters}}). In particular, C can use "to_rs" for providing the AS with C-generated information, to be relayed to the RS when uploading the access token. Also, the RS can use "from_rs" for providing the AS with RS-generated information when replying to the token uploading, and to be relayed to C.

With reference to the two cases mentioned above, "to_rs" can specify the nonce N1 generated by C, while "from_rs" can specify the nonce N2 generated by the RS.

## Further New Parameters to Consider # {#sec-more-parameters}

The following discusses possible, further new parameters that can be defined for addressing the open points raised earlier in {{sec-open-points}}.

* "token_series_id" - This parameter specifies the unique identifier of a token series, thus ensuring that C can dynamically update its access rights, irrespective of the used ACE workflow (see {{sec-open-points-workflow-dynamic-access-rights}}).

   When issuing the first access token of a token series, the AS specifies this parameter in the Access Token Response to C, with value TS_ID. Also, the AS includes a claim "token_series_id" with the same value in the access token.

   When C requests a new access token in the same tokes series for dynamically updating its access rights, C specifies TS_ID as value of the parameter "token_series_id" of the Access Token Request, which MUST omit the parameter "req_cnf" (see {{Section 3.1 of RFC9201}}). The AS specifies the same value within the claim "token_series_id" of the new access token.

   When this parameter is used, the information about the token series in question has to be specified in that parameter and in the corresponding token claim. Instead, the "req_cnf" parameter and the "cnf" claim are used for their main purpose, i.e., for specifying the public authentication credential of the Client, by value or by reference.

   If a profile of ACE can use or is already using a different parameter/claim as de-facto identifier of the token series, then that profile will continue to do so, and will not use this new parameter "token_series_id".

* "token_hash" - This parameter specifies the hash of an access token that the AS has successfully issued and uploaded to the RS as per the new ACE workflow, and thus that the AS does not provide to C (see {{sec-open-points-workflow-dynamic-access-rights}}).

   The AS specifies this parameter in a successful Access Token Response, in case the parameter "token_upload" is also specified as encoding the CBOR simple value "true" (see {{sec-token_upload}}). The parameter value is the hash computed over the value that the parameter "access_token" would have had in that same response message, if it was included therein specifying the access token.

   C specifies this parameter in the request sent to the authz-info endpoint at the RS for "re-uploading" the same access token, e.g., in order to perform a key update (see {{sec-open-points-workflow-token-re-uploading}}).

   This parameter also allows C to seamlessly use the method defined in {{I-D.ietf-ace-revoked-token-notification}} for learning of revoked access tokens, even when the new ACE workflow is used and C does not obtain the access token, which makes it impossible for C to compute the token hash by itself.

* "to_rs" - When using the new ACE workflow, this parameter specifies C-generated information that, according to the used profile of ACE, C has to provide to the RS together with the access token if using the original ACE workflow. This allows the AS to relay such information to the RS upon uploading the access token on behalf of C (see {{sec-open-points-workflow-applicability}}).

   First, C specifies this parameter in the Access Token Request sent to the AS. Then, the AS specifies this parameter in the request to the RS sent for uploading the access token on behalf of C, by simply relaying the value received from C. The used profile of ACE has to define the detailed content and semantics of the information specified in the parameter value.

* "from_rs" - When using the new ACE workflow, this parameter specifies RS-generated information that, according to the used profile of ACE, the RS has to provide to C after the uploading of an access token if using the original ACE workflow. This allows the AS to relay such information to C after having uploaded the access token on behalf of C (see {{sec-open-points-workflow-applicability}}).

   First, the RS specifies this parameter in the response sent to the AS, after the upload of an access token through a request from the AS. Then, the AS specifies this parameter in the Access Token Response to C, by simply relaying the value received from the RS. The used profile of ACE has to define the detailed content and semantics of the information specified in the parameter value.

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -00 to -01 ## {#sec-00-01}

* Definition of the "token series" moved to the "Terminology" section.

* Clarifications and fixes on using parameters in messages.

* Amendeded two of the requirements on profiles of the framework.

* The Client has to opt-in for using the alternative workflow.

* Parameter "token_uploaded" renamed to "token_upload".

* Security considerations inherited from other documents.

* Editorial fixes and improvements.

# Acknowledgments # {#acknowledgments}
{: numbered="no"}

The authors sincerely thank {{{Christian Amsüss}}}, {{{Rikard Höglund}}}, and {{{Dave Robin}}} for their comments and feedback. The work on this document has been partly supported by the H2020 project SIFIS-Home (Grant agreement 952652).

