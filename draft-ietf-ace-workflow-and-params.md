---
v: 3

title: Short Distribution Chain (SDC) Workflow and New OAuth Parameters for the Authentication and Authorization for Constrained Environments (ACE) Framework
abbrev: New ACE Workflow and Parameters
docname: draft-ietf-ace-workflow-and-params-latest

# stand_alone: true

ipr: trust200902
area: Security
wg: ACE Working Group
kw: Internet-Draft
cat: std
submissiontype: IETF
updates: 9200, 9202, 9203, 9431

venue:
  group: Authentication and Authorization for Constrained Environments (ace)
  mail: ace@ietf.org
  github: ace-wg/ace-workflow-and-params

coding: utf-8

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
  RFC3629:
  RFC4648:
  RFC6749:
  RFC6920:
  RFC7252:
  RFC7519:
  RFC7800:
  RFC8259:
  RFC8392:
  RFC8446:
  RFC8610:
  RFC8747:
  RFC8949:
  RFC9052:
  RFC9053:
  RFC9200:
  RFC9201:
  RFC9202:
  RFC9203:
  RFC9290:
  RFC9430:
  RFC9431:
  I-D.ietf-ace-edhoc-oscore-profile:
  I-D.ietf-ace-revoked-token-notification:
  ACE.OAuth.Error.Code.CBOR.Mappings:
    author:
      org: IANA
    date: false
    title: OAuth Error Code CBOR Mappings
    target: https://www.iana.org/assignments/ace/ace.xhtml#oauth-error-code-cbor-mappings
  Named.Information.Hash.Algorithm:
    author:
      org: IANA
    date: false
    title: Named Information Hash Algorithm
    target: https://www.iana.org/assignments/named-information/named-information.xhtml
  SHA-256:
    author:
      org: NIST
    title: Secure Hash Standard
    seriesinfo: FIPS 180-3
    date: 2008-10
    target: http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf

informative:
  I-D.ietf-ace-group-oscore-profile:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document updates the Authentication and Authorization for Constrained Environments Framework (ACE, RFC 9200) as follows. First, it defines the Short Distribution Chain (SDC) workflow that the authorization server can use for uploading an access token to a resource server on behalf of the client. Second, it defines new parameters and their encodings for the OAuth 2.0 token endpoint at the authorization server. Third, it extends the semantics of the "ace_profile" parameter for the OAuth 2.0 token endpoint at the authorization server. Fourth, it amends two of the requirements on profiles of the framework. Finally, it deprecates the original payload format of error responses that convey an error code, when CBOR is used to encode message payloads. For such error responses, it defines a new payload format aligned with RFC 9290, thus updating in this respect also the profiles of ACE defined in RFC 9202, RFC 9203, and RFC 9431.

--- middle

# Introduction # {#intro}

The Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}} defines an architecture to enforce access control for constrained devices. A client (C) requests an assertion of granted permissions from an authorization server (AS) in the form of an access token, then uploads the access token to the target resource server (RS), and finally accesses protected resources at the RS according to the permissions specified in the access token.

The framework has as main building blocks the OAuth 2.0 framework {{RFC6749}}, the Constrained Application Protocol (CoAP) {{RFC7252}} for message transfer, Concise Binary Object Representation (CBOR) {{RFC8949}} for compact encoding, and CBOR Object Signing and Encryption (COSE) {{RFC9052}}{{RFC9053}} for self-contained protection of access tokens. In addition, separate profile documents define in detail how the participants in the ACE architecture communicate, especially as to the security protocols that they use.

This document updates {{RFC9200}} as follows.

* It defines the Short Distribution Chain (SDC) workflow for the ACE framework (see {{sec-workflow}}), according to which the AS uploads the access token to the RS on behalf of C, and then informs C about the outcome. The SDC workflow is especially convenient in deployments where the communication leg between C and the RS is constrained, but the communication leg between the AS and the RS is not.

  The SDC workflow has no ambition to replace the original workflow defined in {{RFC9200}}. The AS can use one workflow or the other depending, for example, on the specific RS for which an access token has been issued and the nature of the communication leg with that RS.

* It defines new parameters and their encodings for the OAuth 2.0 token endpoint at the AS (see {{sec-parameters}}). These include:

  - "token_upload", used by C to inform the AS that it opts in to use the SDC workflow, and by the AS to inform C about the outcome of the token uploading to the RS per the SDC workflow.

  - "token_hash", used by the AS to provide C with a token hash, corresponding to an access token that the AS has issued for C and has successfully uploaded to the RS on behalf of C per the SDC workflow.

  - "to_rs", used by C to provide the AS with information to relay to the RS, upon asking the AS to upload the access token to the RS per the SDC workflow. Its specific use with the OSCORE profile {{RFC9203}} is also defined, thereby effectively enabling the use of the SDC workflow for that profile.

  - "from_rs", used by the AS to provide C with information to relay from the RS, after the AS has successfully uploaded the access token to the RS per the SDC workflow. Its specific use with the OSCORE profile {{RFC9203}} is also defined, thereby effectively enabling the use of SDC workflow for that profile.

  - "rs_cnf2", used by the AS to provide C with the public keys of the RSs in the group-audience for which the access token is issued (see {{Section 6.9 of RFC9200}}).

  - "audience2", used by the AS to provide C with the identifiers of the RSs in the group-audience for which the access token is issued.

  - "anchor_cnf", used by the AS to provide C with the public keys of trust anchors, which C can use to validate the public key of an RS (e.g., as provided in the "rs_cnf" parameter defined in {{RFC9201}} or in the "rs_cnf2" parameter defined in this document).

  - "token_series_id", used by the AS to provide C with the identifier of a token series, and by C to ask the AS for a new access token in the same token series that dynamically updates access rights. A corresponding access token claim, namely "token_series_id", is also defined.

* It extends the semantics of the "ace_profile" parameter for the OAuth 2.0 token endpoint at the authorization server defined in {{RFC9200}} (see {{sec-updated-ace-profile-parameter}}).

* It amends two of the requirements on profiles of the ACE framework (see {{sec-updated-requirements}}).

* It deprecates the original payload format of error responses that convey an error code, when CBOR is used to encode message payloads in the ACE framework. For such error responses, it defines a new payload format according to the problem-details format specified in {{RFC9290}} (see {{sec-updated-error-responses}}).

  In this respect, it also updates the profiles of the ACE framework defined in {{RFC9202}}, {{RFC9203}}, and {{RFC9431}}.


## Terminology ## {#terminology}

{::boilerplate bcp14-tagged}

Readers are expected to be familiar with the terms and concepts described in the ACE framework for Authentication and Authorization {{RFC9200}}{{RFC9201}}, as well as with terms and concepts related to CBOR Web Tokens (CWTs) {{RFC8392}} and CWT Confirmation Methods {{RFC8747}}.

The terminology for entities in the considered architecture is defined in OAuth 2.0 {{RFC6749}}. In particular, this includes client (C), resource server (RS), and authorization server (AS).

Readers are also expected to be familiar with the terms and concepts related to CoAP {{RFC7252}}, Concise Data Definition Language (CDDL) {{RFC8610}}, CBOR {{RFC8949}}, JavaScript Object Notation (JSON) {{RFC8259}}, and COSE {{RFC9052}}{{RFC9053}}.

Note that the term "endpoint" is used here following its OAuth definition {{RFC6749}}, aimed at denoting resources such as /token and /introspect at the AS, and /authz-info at the RS. This document does not use the CoAP definition of "endpoint", which is "An entity participating in the CoAP protocol."

Furthermore, this document uses the following terms.

* Token series: a set of access tokens, all of which are bound to the same proof-of-possession (PoP) key and are sequentially issued by the same AS for the same pair (client, audience) per the same profile of ACE. A token series ends when the latest access token of that token series becomes invalid (e.g., when it expires or gets revoked).

  Profiles of ACE can provide their extended and specialized definition, e.g., by further taking into account the public authentication credentials of C and the RS.

* Token hash: identifier of an access token, in binary format encoding. The token hash has no relation to other possibly used token identifiers, such as the 'cti' (CWT ID) claim of CBOR Web Tokens (CWTs) {{RFC8392}}.

CBOR {{RFC8949}} and CDDL {{RFC8610}} are used in this document. CDDL predefined type names, especially bstr for CBOR byte strings and tstr for CBOR text strings, are used extensively in this document.

Examples throughout this document are expressed in CBOR diagnostic notation as defined in {{Section 8 of RFC8949}} and {{Appendix G of RFC8610}}. Diagnostic notation comments are often used to provide a textual representation of the parameters' keys and values.

In the CBOR diagnostic notation used in this document, constructs of the form e'SOME_NAME' are replaced by the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. For example, {e'audience2' : \["rs1", "rs2"\]} stands for {53 : \["rs1", "rs2"\]}.

Note to RFC Editor: Please delete the paragraph immediately preceding this note. Also, in the CBOR diagnostic notation used in this document, please replace the constructs of the form e'SOME_NAME' with the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. Finally, please delete this note.

# The Short Distribution Chain (SDC) Workflow # {#sec-workflow}

As defined in {{Section 4 of RFC9200}}, the ACE framework relies on its basic protocol workflow shown in {{fig-old-workflow}}.

That is, the client first sends an access token request to the token endpoint at the AS (Step A), specifying permissions that it seeks to obtain for accessing protected resources at the RS, possibly together with information on its own public authentication credential.

Then, if the request has been successfully verified, authenticated, and authorized, the AS replies to the client (Step B), providing an access token and possibly additional parameters as access information including the actually granted permissions.

Finally, the client uploads the access token to the RS and, consistently with the permissions granted according to the access token, accesses a resource at the RS (Step C), which replies with the result of the resource access (Step F). Details about what protocol the client and the RS use to establish a secure association, mutually authenticate, and secure their communications are defined in the specific profile of ACE used, e.g., {{RFC9202}}{{RFC9203}}{{RFC9431}}{{I-D.ietf-ace-edhoc-oscore-profile}}{{I-D.ietf-ace-group-oscore-profile}}{{RFC9431}}.

Further interactions are possible between the AS and the RS, i.e., the exchange of an introspection request and response where the AS validates a previously issued access token for the RS (Steps D and E).

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
{: #fig-old-workflow title="ACE Basic Protocol Workflow."}

This section defines the alternative Short Distribution Chain (SDC) workflow shown in {{fig-new-workflow}}, which MAY be supported by the AS. Unlike in the original workflow defined in {{RFC9200}}, the AS uploads the access token to the RS on behalf of the client, and then informs the client about the outcome.

If the token uploading has been successfully completed, the client typically does not need to obtain the access token from the AS altogether. Instead, the client simply establishes a secure association with the RS (if that has not happened already), and then accesses protected resources at the RS according to the permissions granted per the access token and specified by the AS as access information.

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
{: #fig-new-workflow title="ACE Short Distribution Chain (SDC) Workflow."}

More specifically, the SDC workflow consists of the following steps.

* Step A - Like in the original workflow, the client sends an access token request to the token endpoint at the AS, with the additional indication that it opts in to use the SDC workflow.

  As defined in {{sec-token_upload}}, this information is conveyed to the AS by means of the "token_upload" parameter. The parameter also specifies what the AS has to return in the access token response at Step B, following a successful uploading of the access token from the AS to the RS.

* Step A1 - This new step consists of the AS uploading the access token to the RS, typically at the authz-info endpoint, just like the client does in the original workflow.

* Step A2 - This new step consists of the RS replying to the AS, following the uploading of the access token at Step A1.

* Step B - In the access token response, the AS tells the client that it has attempted to upload the access token to the RS, specifying the outcome of the token uploading based on the reply received from the RS at Step A2.

  As defined in {{sec-token_upload}}, this information is conveyed to the client by means of the "token_upload" parameter included in the access token response. If the token uploading has failed, the access token response also includes the access token. Otherwise, the access token response includes information consistent with what was specified by the "token_upload" parameter of the access token request at Step A.

* Step C1 - This step occurs only if the token uploading from the AS has failed, and the AS has provided the client with the access token at Step B. In such a case, the client uploads the access token to the RS just like at Step C of the original workflow.

* Step C2 - The client attempts to access a protected resource at the RS, according to the permissions granted per the access token and specified by the AS as access information at Step B.

* Steps D, E, and F are as in the original workflow.

The SDC workflow has no ambition to replace the original workflow defined in {{RFC9200}}. The AS can use one workflow or the other depending, for example, on the specific RS for which the access token has been issued and the nature of the communication leg with that RS.

When using the SDC workflow, all the communications between the AS and the RS MUST be protected, consistent with {{Sections 5.8.4.3 and 6.5 of RFC9200}}. Unlike in the original workflow, this results in protecting also the uploading of the first access token in a token series, i.e., in addition to the uploading of the following access tokens in the token series for dynamically updating the access rights of the client.

Note that the SDC workflow is also suitable for deployments where devices meant to access protected resources at the RS are not required or expected to be actual ACE clients. That is, consistent with the intended access policies, the AS can be configured to automatically issue access tokens for such devices and upload those access tokens to the RS. This means that those devices do not have to request for an access token to be issued in the first place, and instead can immediately send requests to the RS for accessing its protected resources, in accordance with the access tokens already issued and uploaded by the AS.

# New Parameters # {#sec-parameters}

The rest of this section defines a number of additional parameters and their encodings for the OAuth 2.0 token endpoint at the AS.

## token_upload {#sec-token_upload}

This section defines the additional "token_upload" parameter. The parameter can be used in an access token request sent by C to the token endpoint at the AS, as well as in the successful access token response sent as reply by the AS.

* The "token_upload" parameter is OPTIONAL in an access token request. The presence of this parameter indicates that C opts in to use the SDC workflow defined in {{sec-workflow}}, whose actual use for uploading the issued access token to the RS is an exclusive prerogative of the AS.

  This parameter can take one of the following integer values. When the access token request is encoded in CBOR, those values are encoded as CBOR unsigned integers. The value of the parameter determines whether the follow-up successful access token response will have to include certain information, in case the AS has successfully uploaded the access token to the RS.

  - 0: The access token response will have to include neither the access token nor its corresponding token hash.

  - 1: The access token response will have to include the token hash corresponding to the access token, but not the access token.

  - 2: The access token response will have to include the access token, but not the corresponding token hash.

  If the AS supports the SDC workflow and the access token request includes the "token_upload" parameter with value 0, 1, or 2, then the AS MAY use the SDC workflow to upload the access token to the RS on behalf of C. Otherwise, following that access token request, the AS MUST NOT use the SDC workflow.

* The "token_upload" parameter is REQUIRED in a successful access token response with response code 2.01 (Created), if both the following conditions apply. Otherwise, the "token_upload" parameter MUST NOT be present.

  - The corresponding access token request included the "token_upload" parameter, with value 0, 1, or 2.

  - The AS has attempted to upload the issued access token to the RS as per the SDC workflow, irrespective of the result of the token upload.

  When the "token_upload" parameter is present in the access token response, it can take one of the following integer values. When the access token response is encoded in CBOR, those values are encoded as CBOR unsigned integers.

  - If the token upload to the RS was not successful, then the "token_upload" parameter MUST specify the value 1.

    In this case, the access token response MUST include the "access_token" parameter specifying the issued access token.

  - If the token upload at the RS was successful, then the "token_upload" parameter MUST specify the value 0.

    In this case, the access token response can include additional parameters as defined below, depending on the value of the "token_upload" parameter in the corresponding access token request.

    - If the "token_upload" parameter in the access token request specified the value 0, then the access token response MUST NOT include the "access_token" parameter and MUST NOT include the "token_hash" parameter defined in {{sec-token_hash}}.

    - If the "token_upload" parameter in the access token request specified the value 1, then the access token response MUST NOT include the "access_token" parameter and MUST include the "token_hash" parameter defined in {{sec-token_hash}}, specifying the hash corresponding to the issued access token and computed as defined in {{sec-token_hash}}.

    - If the "token_upload" parameter in the access token request specified the value 2, then the access token response MUST include the "access_token" parameter specifying the issued access token and MUST NOT include the "token_hash" parameter defined in {{sec-token_hash}}.

### Examples

{{fig-example-AS-to-C-token-upload}} shows an example with first an access token request from C to the AS, and then an access token response from the AS to C, following the issue of an access token bound to a symmetric PoP key.

The access token request specifies the "token_upload" parameter with value 0. That is, C indicates that it requires neither the access token nor the corresponding token hash from the AS, in case the AS successfully uploads the access token to the RS.

The access token response specifies the "token_upload" parameter with value 0, which indicates that the AS has successfully uploaded the access token to the RS on behalf of C.

Consistent with the value of the "token_upload" parameter in the access token request, the access token response includes neither the access token nor its corresponding token hash. The access token response also includes the "cnf" parameter specifying the symmetric PoP key bound to the access token.

~~~~~~~~~~~
   Access token request

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 0
   }


   Access token response

   Header: Created (Code=2.01)
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
     e'token_upload' : 0,
     / expires_in / 2 : 3600,
     / cnf /        8 : {
       / COSE_Key / 1 : {
         / kty / 1 : 4 / Symmetric /,
         / kid / 2 : h'3d027833fc6267ce',
         / k /  -1 : h'73657373696f6e6b6579'
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-token-upload title="Example of Access Token Request-Response Exchange. Following a successful uploading of the access token from the AS to the RS, the access token response includes the \"token_upload\" parameter but not the access token, which is bound to a symmetric key and was uploaded to the RS by the AS."}

{{fig-example-AS-to-C-token-upload-success-ret-token}} shows another example with first an access token request from C to the AS, and then an access token response from the AS to C, following the issue of an access token bound to a symmetric PoP key.

The access token request specifies the "token_upload" parameter with value 2. That is, C indicates that it requires the access token from the AS, even in case the AS successfully uploads the access token to the RS.

The access token response specifies the "token_upload" parameter with value 0, which indicates that the AS has successfully uploaded the access token to the RS on behalf of C.

Consistent with the value of the "token_upload" parameter in the access token request, the access token response includes the "access_token" parameter specifying the issued access token. The access token response also includes the "cnf" parameter specifying the symmetric PoP key bound to the access token.

~~~~~~~~~~~
   Access token request

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 2
   }


   Access token response

   Header: Created (Code=2.01)
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
        e'token_upload' : 0,
     / access_token / 1 : h'd08343a1...4819',
       / (full CWT elided for brevity;
          CWT contains the symmetric PoP key in the "cnf" claim) /
     / expires_in /   2 : 3600,
     / cnf /          8 : {
       / COSE_Key / 1 : {
         / kty / 1 : 4 / Symmetric /,
         / kid / 2 : h'3d027833fc6267ce',
         / k /  -1 : h'73657373696f6e6b6579'
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-token-upload-success-ret-token title="Example of Access Token Request-Response Exchange. Following a successful uploading of the access token from the AS to the RS, the access token response includes the \"token_upload\" parameter as well as the \"access_token\" parameter conveying the access token, which is bound to a symmetric key and was uploaded to the RS by the AS."}

{{fig-example-AS-to-C-token-upload-failed}} shows another example with first an access token request from C to the AS, and then an access token response from the AS to C, also following the issue of an access token bound to a symmetric PoP key.

The access token request specifies the "token_upload" parameter with value 0. That is, C indicates that it requires neither the access token nor the corresponding token hash from the AS, in case the AS successfully uploads the access token to the RS.

In this example, the access token response includes the "token_upload" parameter with value 1, which indicates that the AS has attempted and failed to upload the access token to the RS on behalf of C. The access token response also includes the "access_token" parameter specifying the issued access token, together with the "cnf" parameter specifying the symmetric PoP key bound to the access token.

Note that, even though the AS has failed to upload the access token to the RS, the response code 2.01 (Created) is used when replying to C, since the access token request as such has been successfully processed at the AS, with the following issue of the access token.

~~~~~~~~~~~
   Access token request

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 0
   }


   Access token response

   Header: Created (Code=2.01)
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
        e'token_upload' : 1,
     / access_token / 1 : h'd08343a1...4819',
       / (full CWT elided for brevity;
          CWT contains the symmetric PoP key in the "cnf" claim) /
     / expires_in /   2 : 3600,
     / cnf /          8 : {
       / COSE_Key / 1 : {
         / kty / 1 : 4 / Symmetric /,
         / kid / 2 : h'3d027833fc6267ce',
         / k /  -1 : h'73657373696f6e6b6579'
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-token-upload-failed title="Example of Access Token Request-Response Exchange. Following a failed uploading of the access token from the AS to the RS, the access token response includes the \"token_upload\" parameter with value 1 as well the \"access_token\" parameter conveying the access token bound to a symmetric key."}

## token_hash {#sec-token_hash}

This section defines the additional "token_hash" parameter. The parameter can be used in a successful access token response sent as reply by the AS to C.

The following refers to the base64url encoding without padding (see {{Section 5 of RFC4648}}), and denotes as "binary representation" of a text string the corresponding UTF-8 encoding {{RFC3629}}, which is the implied charset used in JSON (see {{Section 8.1 of RFC8259}}).

The "token_hash" parameter is REQUIRED in a successful access token response with response code 2.01 (Created), if both the following conditions apply. Otherwise, the "token_hash" parameter MUST NOT be present.

* The corresponding access token request included the "token_upload" parameter with value 1.

* The access token response includes the "token_upload" parameter with value 0. That is, the AS has successfully uploaded the issued access token to the RS, as per the SDC workflow.

This parameter specifies the token hash corresponding to the access token issued by the AS and successfully uploaded to the RS on behalf of C. In particular:

* If the access token response is encoded in CBOR, then the "token_hash" parameter is a CBOR byte string, with value the token hash.

* If the access token response is encoded in JSON, then the "token_hash" parameter has as value the base64url-encoded text string that encodes the token hash.

The AS computes the token hash as defined in {{sec-token-hash-output}}.

### Computing the Token Hash # {#sec-token-hash-output}

The AS computes the token hash over the value that the "access_token" parameter would have had in the same access token response, if it was included therein and specifying the access token.

In particular, the input HASH_INPUT over which the token hash is computed is determined as follows.

* If the access token response is encoded in CBOR, then:

  - BYTES denotes the value of the CBOR byte string that would be conveyed by the "access_token" parameter, if this was included in the access token response.

  - HASH_INPUT_TEXT is the base64url-encoded text string that encodes BYTES.

  - HASH_INPUT is the binary representation of HASH_INPUT_TEXT.

* If the access token response is encoded in JSON, then HASH_INPUT is the binary representation of the text string conveyed by the "access_token" parameter, if this was included in the access token response.

Once determined HASH_INPUT as defined above, a hash value of HASH_INPUT is generated as per {{Section 6 of RFC6920}}. The resulting output in binary format is used as the token hash. Note that the used binary format embeds the identifier of the used hash function, in the first byte of the computed token hash.

The specifically used hash function MUST be collision-resistant on byte-strings, and MUST be selected from the "Named Information Hash Algorithm" Registry {{Named.Information.Hash.Algorithm}}. Consistent with the compliance requirements in {{Section 2 of RFC6920}}, the hash function sha-256 as specified in {{SHA-256}} is mandatory to implement.

The computation of token hashes defined above is aligned with that specified for the computation of token hashes in {{I-D.ietf-ace-revoked-token-notification}}, where they are used as identifiers of revoked access tokens. Therefore, given a hash algorithm and an access token, the AS computes the same corresponding token hash in either case.

If the AS supports the method specified in {{I-D.ietf-ace-revoked-token-notification}}, then the AS MUST use the same hash algorithm for computing both the token hashes to include in the "token_hash" parameter and the token hashes computed per such a method to identify revoked access tokens.

### Example

{{fig-example-AS-to-C-token-hash}} shows an example with first an access token request from C to the AS, and then an access token response from the AS to C, following the issue of an access token bound to a symmetric PoP key.

The access token request specifies the "token_upload" parameter with value 1. That is, C indicates that it requires the token hash corresponding to the access token from the AS, in case the AS successfully uploads the access token to the RS.

The access token response specifies the "token_upload" parameter with value 0, which indicates that the AS has successfully uploaded the access token to the RS on behalf of C.

Consistent with the value of the "token_upload" parameter in the access token request, the access token response includes the "token_hash" parameter, which specifies the token hash corresponding to the issued access token. The access token response also includes the "cnf" parameter specifying the symmetric PoP key bound to the access token.

~~~~~~~~~~~
   Access token request

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 1
   }


   Access token response

   Header: Created (Code=2.01)
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
      e'token_upload' : 0,
        e'token_hash' : h'0153269057e12fe2b74ba07c892560a2d7
                          53877eb62ff44d5a19002530ed97ffe4',
     / expires_in / 2 : 3600,
     / cnf /        8 : {
       / COSE_Key / 1 : {
         / kty / 1 : 4 / Symmetric /,
         / kid / 2 : h'3d027833fc6267ce',
         / k /  -1 : h'73657373696f6e6b6579'
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-token-hash title="Example of Access Token Request-Response Exchange. Following a successful uploading of the access token from the AS to the RS, the access token response includes the \"token_upload\" parameter as well as the \"token_hash\" parameter. The \"token_hash\" parameter conveys the token hash corresponding to the issued access token, which is bound to a symmetric key and was uploaded to the RS by the AS."}

## to_rs and from_rs {#sec-to_rs-from_rs}

This section defines the additional parameters "to_rs" and "from_rs". The "to_rs" parameter can be used in an access token request sent by C to the token endpoint at the AS. The "from_rs" parameter can be used in an access token response, sent by the AS in reply to a request to the token endpoint from C.

* The "to_rs" parameter is OPTIONAL in an access token request. The presence of this parameter indicates that C wishes the AS to relay the information specified therein to the RS, when the AS uploads the issued access token to the RS per the SDC workflow defined in {{sec-workflow}}. This parameter MUST NOT be present if the "token_upload" parameter defined in {{sec-token_upload}} is not present in the access token request.

  If present, this parameter specifies the information that C wishes the AS to relay to the RS, when uploading the access token to the RS on behalf of C. If considered together with the access token, this information is expected to consist in what C would have uploaded to the authz-info endpoint at the RS, if uploading the access token per the original workflow. When the access token request is encoded in CBOR, the value of this parameter is encoded as a CBOR byte string.

  The semantics and encoding of the information specified in this parameter depend on the specific profile of ACE used. {{sec-to_rs-from_rs-oscore-profile}} defines those for when this parameter is used with the OSCORE profile {{RFC9203}}.

* The "from_rs" parameter is OPTIONAL in an access token response. The presence of this parameter indicates that the AS has to relay the information specified therein to C, which the AS has received from the RS after having successfully uploaded the access token to the RS per the SDC workflow defined in {{sec-workflow}}. This parameter MUST NOT be present if the "token_upload" parameter defined in {{sec-token_upload}} is not present with value 0 in the access token response.

  If present, this parameter specifies the information that the AS has to relay to C from the RS, following the successful upload of the access token to the RS on behalf of C. This information is expected to consist in what C would have received in a successful response from the authz-info endpoint at the RS, if uploading the access token per the original workflow. When the access token response is encoded in CBOR, the value of this parameter is encoded as a CBOR byte string.

  The semantics and encoding of the information specified in this parameter depend on the specific profile of ACE used. {{sec-to_rs-from_rs-oscore-profile}} defines those for when this parameter is used with the OSCORE profile {{RFC9203}}.

### Use with the OSCORE Profile {#sec-to_rs-from_rs-oscore-profile}

This section defines the semantics and encoding of the information specified in the parameters "to_rs" and "from_rs" when used with the OSCORE profile {{RFC9203}}, thereby effectively enabling the use of the SDC workflow for that profile.

The value of the "to_rs" parameter is the binary representation of a CBOR map C_MAP composed of two fields:

* A field with the CBOR unsigned integer 40 as map key, and with value the nonce N1 generated by C encoded a CBOR byte string (see {{Section 4.1 of RFC9203}}).

* A field with the CBOR unsigned integer 43 as map key, and with value the Recipient ID ID1 generated by C and encoded as a CBOR byte string (see {{Section 4.1 of RFC9203}}).

When building the POST request for uploading the access token to the authz-info endpoint at the RS, the AS composes the request payload as specified in {{Section 4.1 of RFC9203}}. In particular, the CBOR map specified as payload includes:

* The "access_token" field, with value the access token to upload encoded as a CBOR byte string.

* The "nonce1" field, with value the same CBOR byte string specified by the field of C_MAP that has the CBOR unsigned integer 40 as map key.

* The "ace_client_recipientid" field, with value the same CBOR byte string specified by the field of C_MAP that has the CBOR unsigned integer 43 as map key.

In case the upload of the access token to the RS from the AS is successful, the RS replies to the AS with a 2.01 (Created) response, whose payload is a CBOR map RS_MAP that includes:

* The "nonce2" field, with value the nonce N2 generated by the RS encoded a CBOR byte string (see {{Section 4.2 of RFC9203}}).

* The "ace_server_recipientid" field, with value the Recipient ID ID2 generated by the RS and encoded as a CBOR byte string (see {{Section 4.2 of RFC9203}}).

The value of the "from_rs" parameter is the binary representation of a CBOR map composed of two elements:

* A field with the CBOR unsigned integer 42 as map key, and with value the same CBOR byte string specified by the "nonce2" field of RS_MAP.

* A field with the CBOR unsigned integer 44 as map key, and with value the same CBOR byte string specified by the "ace_server_recipientid" field of RS_MAP.

When C receives from the AS the successful access token response specifying the "token_upload" parameter with value 0, C can retrieve the nonce N2 and the Recipient ID ID2 from the "from_rs" parameter, just like when retrieving those from a 2.01 (Created) response received from the RS when using the original workflow.

{{fig-example-AS-to-C-token-upload-oscore-profile}} shows an example where the OSCORE profile is used, with first an access token request from C to the AS, and then an access token response from the AS to C, following the issue of an access token bound to a symmetric PoP key.

The access token request specifies the "token_upload" parameter with value 0. That is, C indicates that it requires neither the access token nor the corresponding token hash from the AS, in case the AS successfully uploads the access token to the RS. Also, the access token request includes the "to_rs" parameter, specifying the values of N1 = 0x018a278f7faab55a and ID1 = 0x1645 intended to the RS.

The access token response specifies the "token_upload" parameter with value 0, which indicates that the AS has successfully uploaded the access token to the RS on behalf of C.

Consistent with the value of the "token_upload" parameter in the access token request, the access token response includes neither the access token nor its corresponding token hash. The access token response also includes the "cnf" parameter specifying the symmetric PoP key bound to the access token, as an OSCORE_Input_Material object. Also, the access token response includes the "from_rs" parameter, specifying the values of N2 = 0x25a8991cd700ac01 and ID2 = 0x0000 received from the RS and intended to C.

~~~~~~~~~~~
   Access token request

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 0,
            e'to_rs' : h'a2182848018a278f7faab55a182b421645'
   }


   Access token response

   Header: Created (Code=2.01)
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
        e'token_upload' : 0,
             e'from_rs' : h'a2182a4825a8991cd700ac01182c420000',
     / ace_profile / 38 : / coap_oscore / 2,
       / expires_in / 2 : 3600,
       / cnf /        8 : {
         / osc / 4 : {
           / id / 0 : h'01',
           / ms / 2 : h'f9af838368e353e78888e1426bd94e6f'
         }
       }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-token-upload-oscore-profile title="Example of Access Token Request-Response Exchange where the OSCORE Profile is Used. Following a successful uploading of the access token from the AS to the RS, the access token response includes the \"token_upload\" parameter but not the access token, which is bound to a symmetric key and was uploaded to the RS by the AS. C and the RS exchange N1, ID1, N2, and ID2 via the AS by means of the parameters \"to_rs\" and \"from_rs\""}

## rs_cnf2 and audience2 {#sec-rs_cnf2-audience2}

This section defines the additional parameters "rs_cnf2" and "audience2" for an access token response, sent by the AS in reply to a request to the token endpoint from C.

* The "rs_cnf2" parameter is OPTIONAL if the token type is "pop", asymmetric keys are used, and the access token is issued for an audience that includes multiple RSs (i.e., a group-audience, see {{Section 6.9 of RFC9200}}). Otherwise, the "rs_cnf2" parameter MUST NOT be present.

  This parameter specifies information about the public keys used by the RSs of a group-audience for authenticating themselves to C, and is used in case the binding between the public keys and the corresponding RS identities are not established through other means. If this parameter is absent, either the RSs in the group-audience do not use a public key, or the AS knows that the RSs can authenticate themselves to C without additional information.

  If present, this parameter MUST encode a non-empty CBOR array of N elements, where N is the number of RSs in the group-audience for which the access token is issued. Each element of the CBOR array specifies the public key of one RS in the group-audience, and MUST follow the syntax and semantics of the "cnf" claim either from {{Section 3.1 of RFC8747}} for CBOR-based interactions, or from {{Section 3.1 of RFC7800}} for JSON-based interactions. It is not required that all the elements of the CBOR array rely on the same confirmation method.

  Each of the public keys may contain parameters specifying information such as the public key algorithm and use (e.g., by means of the parameters "alg" or "key_ops" in a COSE_Key structure). If such information is specified, a client MUST NOT use a public key that is incompatible with the profile of ACE used or with the PoP algorithm according to that information. An RS MUST reject a proof-of-possession that relies on such a key, and reply with a response code equivalent to the CoAP code 4.00 (Bad Request).

* The "audience2" parameter is OPTIONAL and specifies the identifiers of the RSs in the group-audience for which the access token is issued.

  If present, this parameter MUST encode a non-empty CBOR array of N elements, where N is the number of RSs in the group-audience for which the access token is issued. Each element of the CBOR array in the "audience2" parameter MUST be a CBOR text string, with value the identifier of one RS in the group-audience.

  The element of the CBOR array referring to an RS in the group-audience SHOULD have the same value that would be used to identify that RS through the "audience" parameter of an access token request to the AS (see {{Section 5.8.1 of RFC9200}}) and of an access token response from the AS (see {{Section 5.8.2 of RFC9200}}), when requesting and issuing an access token for that individual RS.

  The "audience2" parameter is REQUIRED if the "rs_cnf2" parameter is present. In such a case, the i-th element of the CBOR array in the "audience2" parameter MUST be the identifier of the RS whose public key is specified as the i-th element of the CBOR array in the "rs_cnf2" parameter.

### Example

{{fig-example-AS-to-C-rs_cnf2}} shows an example of access token response from the AS to C, following the issue of an access token for a group-audience composed of two RSs "rs1" and "rs2", and bound to C's public key as asymmetric PoP key. The access token response includes the access token, as well as the parameters "audience2" and "rs_cnf2". These specify the public key of the two RSs as intended recipients of the access token and the identifiers of those two RSs, respectively.

~~~~~~~~~~~
   Access token response

   Header: Created (Code=2.01)
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3600
   Payload:
   {
     / access_token / 1 : b64'SlAV32hk...12',
       / (full CWT elided for brevity;
          CWT contains the client's RPK in the "cnf" claim) /
     / expires_in /   2 : 3600,
           e'audience2' : ["rs1", "rs2"],
             e'rs_cnf2' : [
               {
                 / COSE_Key / 1 : {
                   / kty /  1 : 2 / EC2 /,
                   / crv / -1 : 1 / P-256 /,
                   / x /   -2 : h'bbc34960526ea4d32e940cad2a234148
                                  ddc21791a12afbcbac93622046dd44f0',
                   / y /   -3 : h'4519e257236b2a0ce2023f0931f1f386
                                  ca7afda64fcde0108c224c51eabf6072'
                 }
               },
               {
                 / COSE_Key / 1 : {
                   / kty /  1 : 2 / EC2 /,
                   / crv / -1 : 1 / P-256 /,
                   / x /   -2 : h'ac75e9ece3e50bfc8ed6039988952240
                                  5c47bf16df96660a41298cb4307f7eb6',
                   / y /   -3 : h'6e5de611388a4b8a8211334ac7d37ecb
                                  52a387d257e6db3c2a93df21ff3affc8'
                 }
               }
             ]
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-rs_cnf2 title="Example of access token response with an access token bound to an asymmetric key, using the parameters \"audience2\" and \"rs_cnf2\"."}

## anchor_cnf {#sec-anchor_cnf}

This section defines the additional "anchor_cnf" parameter for an access token response, sent by the AS in reply to a request to the token endpoint from C.

The "anchor_cnf" parameter is OPTIONAL if the token type is "pop" and asymmetric keys are used. Otherwise, the "anchor_cnf" parameter MUST NOT be present.

This parameter specifies information about the public keys of trust anchors, which C can use to validate the public key of the RS/RSs included in the audience for which the access token is issued. This parameter can be used when the access token is issued for an audience including one RS or multiple RSs.

If this parameter is absent, either the RS/RSs in the audience do not use a public key, or the AS knows that C can validate the public key of such RS/RSs without additional information (e.g., C has already obtained the required public keys of the involved trust anchors from the AS or through other means).

If present, this parameter MUST encode a non-empty CBOR array that MUST be treated as a set, i.e., the order of its elements has no meaning. Each element of the CBOR array specifies the public key of one trust anchor, which can be used to validate the public key of at least one RS included in the audience for which the access token is issued. Each element of the CBOR array MUST follow the syntax and semantics of the "cnf" claim either from {{Section 3.1 of RFC8747}} for CBOR-based interactions, or from {{Section 3.1 of RFC7800}} for JSON-based interactions. It is not required that all the elements of the CBOR array rely on the same confirmation method.

Each of the public keys specified in the "anchor_cnf" parameter may contain parameters specifying information such as the public key algorithm and use (e.g., by means of the parameters "alg" or "key_ops" in a COSE_Key structure). If such information is specified, a client MUST NOT use a public key that is incompatible with the profile of ACE used, or with the public keys to validate and the way to validate those.

The presence of this parameter does not require that the access token response also includes the "rs_cnf" parameter defined in {{RFC9201}} or the "rs_cnf2" parameter defined in {{sec-rs_cnf2-audience2}} of this document. That is, C may be able to obtain the public keys of the RS/RSs for which the access token is issued through other means.

When the access token response includes both the "anchor_cnf" parameter and the "audience2" parameter defined in {{sec-rs_cnf2-audience2}}, then C MUST make sure that a public key PK_RS is associated with an RS identified by an element of "audience2", before using any of the public keys specified in "anchor_cnf" to validate PK_RS.

When the access token response includes the "anchor_cnf" parameter but not the "audience2" parameter, then C can use any of the public keys specified in "anchor_cnf" to validate the public key PK_RS of any RS in the targeted audience. This allows C to use the access token with an RS that is deployed later on as part of the same audience, which is particularly useful in the case of a group-audience.

### Example

{{fig-example-AS-to-C-anchor_cnf}} shows an example of access token response from the AS to C, following the issue of an access token for a group-audience, and bound to C's public key as asymmetric PoP key.

The identifier of the group-audience was specified by the "audience" parameter of the access token request to the AS, is specified by the "aud" claim of the issued access token, and is not repeated in the access token response from the AS.

The access token response includes the "anchor_cnf" parameter. This specifies the public key of a trust anchor that C can use to validate the public keys of any RS with which the access token is going to be used. The public key of the trust anchor is here conveyed within an X.509 certificate used as public authentication credential for that trust anchor, by means of the CWT confirmation method "x5chain" defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

~~~~~~~~~~~
   Access token response

   Header: Created (Code=2.01)
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3600
   Payload:
   {
     / access_token / 1 : b64'SlAV32hk...12',
       / (full CWT elided for brevity;
          CWT contains the client's RPK in the "cnf" claim) /
     / expires_in /   2 : 3600,
          e'anchor_cnf' : [
            {
              e'x5chain' : h'308201363081dea003020102020301f50d30
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
{: #fig-example-AS-to-C-anchor_cnf title="Example of Access Token Response with an access token bound to an asymmetric key, using the \"anchor_cnf\" parameter."}

## token_series_id {#sec-token_series_id}

This section defines the additional "token_series_id" parameter. The parameter can be used in an access token request sent by C to the token endpoint at the AS, as well as in the successful access token response sent as reply by the AS.

* The "token_series_id" parameter is OPTIONAL in an access token request. The presence of this parameter indicates that C wishes to obtain a new access token for dynamically updating its access rights. That is, the new access token is intended to be the next one in an active token series and to supersede the latest access token in that token series. This parameter MUST NOT be present if the requested access token is the first one of a new token series.

  If present, this parameter specifies the identifier of the token series that the new access token is intended to extend. The identifier does not change throughout the lifetime of the token series, and was provided to C in the successful access token response that the AS sent when issuing the first access token in that token series. When the access token request is encoded in CBOR, the value of this parameter is encoded as a CBOR byte string.

* The "token_series_id" parameter is OPTIONAL in an access token response. This parameter MUST NOT be present if the issued access token is not the first one of the token series it belongs to.

  If present, this parameter specifies the identifier of the token series to which the issued access token belongs. When the access token response is encoded in CBOR, the value of this parameter is encoded as a CBOR byte string.

If the AS relies on the "token_series_id" parameter to exchange the identifier of token series with clients, then the following applies.

* The value assigned to the identifier of a token series MUST be associated with all the access tokens issued by the AS for that token series, and MUST be selected from a pool that the AS exclusively controls.

  In particular, the triple (TS_ID, C, AUD) MUST uniquely identify a token series and its corresponding access tokens, where TS_ID is the identifier of the token series, while C and AUD are the client and the audience for which the access token is issued, respectively. The AS MUST take into account both ongoing and ended token series for selecting a new TS_ID that complies with the above requirements.

  Note that the ACE profile is not part of the triple, hence the requirement spans across all the ACE profiles that the AS and its registered clients/RSs support.

* An issued access token that belongs to a token series MUST include the identifier of that token series. This allows the RS to identify the latest access token in the token series to be superseded by the issued access token.

  In particular, each of such access tokens MUST include a claim specifying the identifier of the token series to which the access token belongs. When CWTs are used as access tokens, this information MUST be transported in the "token_series_id" claim registered in {{iana-token-cwt-claims}}.

If a profile of ACE relies on a construct that uses different parameters/claims to transport the identifier of a token series, then the new "token_series_id" parameter and "token_series_id" claim MUST NOT be used when using that profile.

For example, a number of parameters/claims are already used to transport information that acts de facto as identifier of token series, in the PSK mode of the DTLS profile {{RFC9202}}, in the OSCORE profile {{RFC9203}}, and in the EDHOC and OSCORE profile {{I-D.ietf-ace-edhoc-oscore-profile}}.

# Updated "ace_profile" Parameter # {#sec-updated-ace-profile-parameter}

This section extends the semantics of the "ace_profile" parameter defined in {{RFC9200}} for the OAuth 2.0 token endpoint at the authorization server.

In addition to what is specified in {{Sections 5.8.1, 5.8.2, and 5.8.4.3 of RFC9200}}, the following applies.

* When sending an access token request to the token endpoint at the AS (see {{Section 5.8.1 of RFC9200}}), C MAY include the "ace_profile" parameter, specifying the identifier of the profile that C wishes to use towards the RS.

* If the AS receives an access token request that includes the "ace_profile" parameter specifying the identifier of a profile, then the AS proceeds as follows.

  In case the AS does not issue access tokens per the profile specified in the access token request, or C and the RS do not share that profile, then the AS MUST reject the request and reply with an error response (see {{Section 5.8.3 of RFC9200}}). The error response MUST have a response code equivalent to the CoAP code 4.00 (Bad Request) and MUST include the error code "incompatible_ace_profiles".

  In case the AS issues an access token to C, the access token MUST be per the profile whose identifier was specified by the "ace_profile" parameter in the access token request.

  In case the AS replies to C with a successful access token response (see {{Section 5.8.2 of RFC9200}}), then the response MAY include the "ace_profile" parameter. If it is included in the access token response, the "ace_profile" parameter MUST specify the same profile identifier that was specified by the "ace_profile" parameter of the corresponding access token request.

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

# Updated Payload Format of Error Responses # {#sec-updated-error-responses}

This section deprecates the original payload format of error responses conveying an error code, when CBOR is used to encode message payloads in the ACE framework. That format is referred to, e.g., when defining the error responses of {{Sections 5.8.3 and 5.9.3 of RFC9200}}.

Also, this section defines a new payload format that allows such error responses to convey an error code together with further error-specific information, according to the problem-details format specified in {{RFC9290}}.

Such error responses MUST have Content-Format set to application/concise-problem-details+cbor. The payload of these error responses MUST be a CBOR map specifying a Concise Problem Details data item (see {{Section 2 of RFC9290}}). The CBOR map is formatted as follows.

* It MUST include the Custom Problem Detail entry "ace-error" registered in {{iana-problem-details}} of this document.

  This entry is formatted as a CBOR map including only one field, namely "error-code". The map key for "error-code" is the CBOR unsigned integer with value 0. The value of "error-code" is a CBOR integer specifying the error code associated with the occurred error. This value is taken from the "CBOR Value" column of the "OAuth Error Code CBOR Mappings" registry {{ACE.OAuth.Error.Code.CBOR.Mappings}}.

  The new payload format MUST use the field "error-code" in order to convey the same information that the original payload format conveys through the "error" parameter (see, e.g., {{Sections 5.8.3 and 5.9.3 of RFC9200}}).

  The CDDL notation {{RFC8610}} of the "ace-error" entry is given below.

~~~~~~~~~~~ CDDL
   ace-error = {
     &(error-code: 0) => int
   }
~~~~~~~~~~~

* It MAY include further Standard Problem Detail entries or Custom Problem Detail entries (see {{RFC9290}}). The following Standard Problem Detail entries are of particular relevance for the ACE framework.

  * "detail" (map key -2): its value is a CBOR text string that specifies a human-readable, diagnostic description of the occurred error (see {{Section 2 of RFC9290}}).

    The diagnostic text is intended for software engineers as well as for device and network operators, in order to aid debugging and provide context for possible intervention. The diagnostic message SHOULD be logged by the sender of the error response. The entry "detail" is unlikely relevant in an unattended setup where human intervention is not expected.

    The new payload format MUST use the Standard Problem Detail entry "detail" in order to convey the same information that the original payload format conveys through the "error_description" parameter (see, e.g., {{Sections 5.8.3 and 5.9.3 of RFC9200}}).

   * "instance" (map key -3): its value is a URI reference identifying the specific occurrence of the error (see {{Section 2 of RFC9290}}).

     The new payload format MUST use the Standard Problem Detail entry "instance" in order to convey the same information that the original payload format conveys through the "error_uri" parameter (see, e.g., {{Sections 5.8.3 and 5.9.3 of RFC9200}}).

An example of error response using the problem-details format is shown in {{fig-example-error-response}}.

~~~~~~~~~~~
Header: Bad Request (Code=4.00)
Content-Format: 257 (application/concise-problem-details+cbor)
Payload:
{
  / title /  -1 : "Incompatible ACE profile",
  / detail / -2 : "The RS supports only the OSCORE profile",
    e'ace-error': {
      / error_code / 0: 8 / incompatible_ace_profiles /
    }
}
~~~~~~~~~~~
{: #fig-example-error-response title="Example of Error Response with Problem Details."}

When the ACE framework is used with CBOR for encoding message payloads, the following applies.

* It is RECOMMENDED that authorization servers, clients, and resource servers support the payload format defined in this section.

* Authorization servers, clients, and resource servers that support the payload format defined in this section MUST use it when composing an outgoing error response that conveys an error code.

# Security Considerations

The same security considerations from the ACE framework for Authentication and Authorization {{RFC9200}} apply to this document, together with those from the specific profile of ACE used, e.g., {{RFC9202}}{{RFC9203}}{{RFC9431}}{{I-D.ietf-ace-edhoc-oscore-profile}}{{I-D.ietf-ace-group-oscore-profile}}{{RFC9431}}.

When using the problem-details format defined in {{RFC9290}} for error responses, then the privacy and security considerations from {{Sections 4 and 5 of RFC9290}} also apply.

Editor's note: add more security considerations.

# IANA Considerations

This document has the following actions for IANA.

Note to RFC Editor: Please replace all occurrences of "{{&SELF}}" with the RFC number of this specification and delete this paragraph.

## OAuth Parameters Registry ## {#iana-oauth-params}

IANA is asked to add the following entries to the "OAuth Parameters" registry.

* Name: token_upload
* Parameter Usage Location: token request and token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: token_hash
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: to_rs
* Parameter Usage Location: token request
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: from_rs
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: rs_cnf2
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: audience2
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: anchor_cnf
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: token_series_id
* Parameter Usage Location: token request and token response
* Change Controller: IETF
* Reference: {{&SELF}}

## OAuth Parameters CBOR Mappings Registry ## {#iana-oauth-cbor-mappings}

IANA is asked to add the following entries to the "OAuth Parameters CBOR Mappings" registry, following the procedure specified in {{RFC9200}}.

* Name: token_upload
* CBOR Key: TBD (value between 1 and 255)
* Value Type: unsigned integer
* Reference: {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: token_hash
* CBOR Key: TBD (value between 1 and 255)
* Value Type: unsigned integer
* Reference: {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: to_rs
* CBOR Key: TBD (value between 1 and 255)
* Value Type: byte string
* Reference: {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: from_rs
* CBOR Key: TBD (value between 1 and 255)
* Value Type: byte string
* Reference: {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: rs_cnf2
* CBOR Key: TBD (value between 1 and 255)
* Value Type: array
* Reference: {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: audience2
* CBOR Key: TBD (value between 1 and 255)
* Value Type: array
* Reference: {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: anchor_cnf
* CBOR Key: TBD (value between 1 and 255)
* Value Type: array
* Reference: {{&SELF}}
* Original Specification: {{&SELF}}

<br>

* Name: token_series_id
* CBOR Key: TBD (value between 1 and 255)
* Value Type: byte string
* Reference: {{&SELF}}
* Original Specification: {{&SELF}}

## JSON Web Token Claims Registry ## {#iana-token-json-claims}

IANA is asked to add the following entries to the "JSON Web Token Claims" registry, following the procedure specified in {{RFC7519}}.

*  Claim Name: token_series_id
*  Claim Description: The identifier of a token series
*  Change Controller: IETF
*  Reference: {{&SELF}}

## CBOR Web Token (CWT) Claims Registry ## {#iana-token-cwt-claims}

IANA is asked to add the following entries to the "CBOR Web Token (CWT) Claims" registry, following the procedure specified in {{RFC8392}}.

* Claim Name: token_series_id
* Claim Description: The identifier of a token series
* JWT Claim Name: token_series_id
* Claim Key: TBD (value between 1 and 255)
* Claim Value Type: byte string
* Change Controller: IETF
* Reference: {{sec-token_series_id}} of {{&SELF}}

## Custom Problem Detail Keys Registry  ## {#iana-problem-details}

IANA is asked to register the following entry in the "Custom Problem Detail Keys" registry within the "Constrained RESTful Environments (CoRE) Parameters" registry group.

* Key Value: TBD (value between 0 and 23)
* Name: ace-error
* Brief Description: Carry ACE {{RFC9200}} problem details in a Concise Problem Details data item.
* Change Controller: IETF
* Reference: {{sec-updated-error-responses}} of {{&SELF}}


--- back

# Benefits for ACE Profiles # {#sec-benefits-for-profiles}

For any profile of ACE, the following holds.

* The SDC workflow defined in {{sec-workflow}} is effectively possible to use. This is beneficial for deployments where the communication leg between C and the RS is constrained, but the communication leg between the AS and RS is not.

* When the SDC workflow is used, the "token_upload" parameter defined in {{sec-token_upload}} is used:

  - To inform the AS about C opting in to use the SDC workflow.

  - To request the AS that the follow-up successful access token response will have to include certain information, in case the AS has successfully uploaded the access token to the RS.

  - To inform C that the AS has attempted to upload the issued access token to the RS, specifying whether the uploading has succeeded or failed.

* When the SDC workflow is used, it remains possible for C to always obtain the issued access token from the AS.

  That is, by specifying the value 2 for the "token_upload" parameter in the access token request, C will ensure to receive the access token from the AS, even in case the AS successfully uploads the access token to the RS on behalf of C.

  This is useful in profiles of ACE where C can re-upload the same access token to the RS by itself, e.g., in order to perform a key update like defined for the OSCORE profile {{RFC9203}}.

## DTLS Profile

When the RPK mode of the DTLS profile is used (see {{Section 3.2 of RFC9202}}), it becomes possible for the AS to effectively issue an access token intended to an audience that includes multiple RSs. This is enabled by the parameters "rs_cnf2" and "audience2" defined in {{sec-rs_cnf2-audience2}}, as well as by the "anchor_cnf" parameter defined in {{sec-anchor_cnf}}. This seamlessly applies also if the profile uses Transport Layer Security (TLS) {{RFC8446}}, as defined in {{RFC9430}}.

## EDHOC and OSCORE Profile

When the EDHOC and OSCORE profile is used {{I-D.ietf-ace-edhoc-oscore-profile}}, it becomes possible for the AS to effectively issue an access token intended to an audience that includes multiple RSs. This is enabled by the parameters "rs_cnf2" and "audience2" defined in {{sec-rs_cnf2-audience2}}, as well as by the "anchor_cnf" parameter defined in {{sec-anchor_cnf}}.

# Open Points # {#sec-open-points}

## SDC Workflow # {#sec-open-points-workflow}

The following discusses open points related to the use of the SDC workflow defined in {{sec-workflow}}.

### Prevent Ambiguities in the Dynamic Update of Access Rights # {#sec-open-points-workflow-dynamic-access-rights}

In some profiles of ACE, C can request a new access token to update its access rights, while preserving the same secure association with the RS. The new access token supersedes the current one stored at the RS, as they are both part of the same token series.

When using the original workflow, C uploads the new access token to the RS by protecting the message exchange through the secure association with the RS. This allows the RS to determine that the upload of such access token is for updating the access rights of C.

When using the SDC workflow, the AS uploads the new access token to the RS also when an update of access rights for C is to be performed. This message exchange is protected through the secure association between the AS and the RS.

In this latter case, even though the access token claim "token_series_id" defined in {{sec-token_series_id}} provides the RS with an explicit indication for recognizing a stored access token as belonging to an ongoing token series, such a process might still lead to ambiguities.

For example, the RS might have deleted a stored access token due to memory limitations. This effectively terminates the corresponding token series, which is however impractical for the RS to remember indefinitely. Consequently, if the AS uploads to the RS a new access token belonging to the same token series, the RS would erroneously interpret it to be the first access token of a new series.

This can be avoided by relying on a new "updated_rights" parameter, which the AS can include in a POST request to the authz-info endpoint when uploading to the RS an access token for dynamically updating the access rights of C (see {{sec-more-parameters}}).

## Further New Parameters to Consider # {#sec-more-parameters}

The following discusses possible, further new parameters that can be defined for addressing the open points raised earlier in {{sec-open-points}}.

* "updated_rights" - When using the SDC workflow and issuing an access token for dynamically updating the access rights of C, the AS specifies this parameter in the request sent to the RS for uploading the access token on behalf of C (see {{sec-open-points-workflow-dynamic-access-rights}}). This parameter encodes the CBOR simple value `true` (0xf5).

# CDDL Model # {#sec-cddl-model}
{:removeinrfc}

~~~~~~~~~~~~~~~~~~~~ CDDL
; OAuth Parameters CBOR Mappings
token_upload = 48
token_hash = 49
to_rs = 50
from_rs = 51
rs_cnf2 = 52
audience2 = 53
anchor_cnf = 54
token_series_id_param = 55

; CBOR Web Token (CWT) Claims
token_series_id_claim = 42

; CWT Confirmation Methods
x5chain = 24

; Custom Problem Detail Keys Registry
ace-error = 2
~~~~~~~~~~~~~~~~~~~~
{: #fig-cddl-model title="CDDL model" artwork-align="left"}

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -03 to -04 ## {#sec-03-04}

* Updated document title.

* Defined name for the new workflow.

* Improved definition of "token series".

* Revised criterion for the AS to choose a token series identifier.

* Updated semantics of the "ace_profile" parameter.

* Removed content on bidirectional access control.

* Suggested value ranges for codepoints to register.

* Editorial fixes and improvements.

## Version -02 to -03 ## {#sec-02-03}

* Defined parameter and claim "token_series_id".

* Defined parameters "to_rs" and "from_rs".

* Defined use of "to_rs" and "from_rs" in the OSCORE profile.

* Lowercase use of "client", "resource server", and "authorization server".

* Fixed naming of parameters/claims for audience.

* Split elision and comments in the examples in CBOR Diagnostic Notation.

* SHA-256 is mandatory to implement for computing token hashes.

* Fixes in the IANA considerations.

* Removed (parts of) appendices that are not needed anymore.

* Clarifications and editorial improvements.

## Version -01 to -02 ## {#sec-01-02}

* CBOR diagnostic notation uses placeholders from a CDDL model.

* Note on the new workflow supporting also non-ACE clients.

* Revised semantics of the "token_upload" parameter.

* Defined the new "token_hash" parameter.

* First definition of bidirectional access control through a single access token.

* Revised and extended considerations and next steps in appendices.

* Clarifications and editorial improvements.

## Version -00 to -01 ## {#sec-00-01}

* Definition of the "token series" moved to the "Terminology" section.

* Clarifications and fixes on using parameters in messages.

* Amended two of the requirements on profiles of the framework.

* The client has to opt-in for using the new workflow.

* Parameter "token_uploaded" renamed to "token_upload".

* Updated format of error response payload to use RFC 9290.

* Security considerations inherited from other documents.

* Editorial fixes and improvements.

# Acknowledgments # {#acknowledgments}
{:numbered="false"}

The authors sincerely thank {{{Christian Amsüss}}}, {{{Rikard Höglund}}}, and {{{Dave Robin}}} for their comments and feedback.

This work was supported by the Sweden's Innovation Agency VINNOVA within the EUREKA CELTIC-NEXT project CYPRESS; and by the H2020 project SIFIS-Home (Grant agreement 952652).
