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
  RFC2119:
  RFC3629:
  RFC4648:
  RFC6749:
  RFC6920:
  RFC7252:
  RFC7519:
  RFC7800:
  RFC8174:
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

informative:
  I-D.ietf-ace-group-oscore-profile:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document updates the Authentication and Authorization for Constrained Environments Framework (ACE, RFC 9200) as follows. First, it defines a new, alternative workflow that the authorization server can use for uploading an access token to a resource server on behalf of the client. Second, it defines new parameters and encodings for the OAuth 2.0 token endpoint at the authorization server. Third, it defines a method for the ACE framework to enforce bidirectional access control by means of a single access token. Fourth, it amends two of the requirements on profiles of the framework. Finally, it deprecates the original payload format of error responses that convey an error code, when CBOR is used to encode message payloads. For such error responses, it defines a new payload format aligned with RFC 9290, thus updating in this respect also the profiles of ACE defined in RFC 9202, RFC 9203, and RFC 9431.

--- middle

# Introduction # {#intro}

The Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}} defines an architecture to enforce access control for constrained devices. A client (C) requests an assertion of granted permissions from an authorization server (AS) in the form of an access token, then uploads the access token to the target resource server (RS), and finally accesses protected resources at the RS according to the permissions specified in the access token.

The framework has as main building blocks the OAuth 2.0 framework {{RFC6749}}, the Constrained Application Protocol (CoAP) {{RFC7252}} for message transfer, CBOR {{RFC8949}} for compact encoding, and COSE {{RFC9052}}{{RFC9053}} for self-contained protection of access tokens. In addition, separate profile documents define in detail how the participants in the ACE architecture communicate, especially as to the security protocols that they use.

This document updates {{RFC9200}} as follows.

* It defines a new, alternative protocol workflow for the ACE framework (see {{sec-workflow}}), according to which the AS uploads the access token to the RS on behalf of C, and then informs C about the outcome. The new workflow is especially convenient in deployments where the communication leg between C and the RS is constrained, but the communication leg between the AS and the RS is not.

  The new workflow has no ambition to replace the original workflow. The AS can use one workflow or the other depending, for example, on the specific RS for which an access token has been issued and the nature of the communication leg with that RS.

* It defines additional parameters and encodings for the OAuth 2.0 token endpoint at the AS (see {{sec-parameters}}). These include:

  - "token_upload", used by C to inform the AS that it opts in to use the new ACE workflow, and by the AS to inform C about the outcome of the token uploading to the RS per the new workflow.

  - "token_hash", used by the AS to provide C with a token hash, corresponding to an access token that the AS has issued for C and has successfully uploaded to the RS on behalf of C per the new ACE workflow.

  - "rs_cnf2", used by the AS to provide C with the public keys of the RSs in the group-audience for which the access token is issued (see {{Section 6.9 of RFC9200}}).

  - "aud2", used by the AS to provide C with the identifiers of the RSs in the group-audience for which the access token is issued.

  - "anchor_cnf", used by the AS to provide C with the public keys of trust anchors, which C can use to validate the public key of an RS (e.g., as provided in the "rs_cnf" parameter defined in {{RFC9201}} or in the "rs_cnf2" parameter defined in this document).

  - "rev_aud", used by C to provide the AS with an identifier of itself as a reverse audience, and by the AS to possibly confirm that identifier in a response to C. A corresponding access token claim, namely "rev_aud", is also defined.

  - "rev_scope", used by C to ask the AS that the requested access token specifies additional access rights as a reverse scope, allowing the access token's audience to accordingly access protected resources at C. This parameter is also used by the AS to provide C with the access rights that are actually granted as reverse scope to the access token's audience. A corresponding access token claim, namely "rev_scope", is also defined.

* It defines a method for the ACE framework to enforce bidirectional access control by means of a single access token (see {{sec-bidirectional-access-control}}), building on the two new parameters "rev_aud" and "rev_scope" as well as on the corresponding access token claims.

* It amends two of the requirements on profiles of the ACE framework (see {{sec-updated-requirements}}).

* It deprecates the original payload format of error responses that convey an error code, when CBOR is used to encode message payloads in the ACE framework. For such error responses, it defines a new payload format according to the problem-details format specified in {{RFC9290}} (see {{sec-updated-error-responses}}).

  In this respect, it also updates the profiles of the ACE framework defined in {{RFC9202}}, {{RFC9203}}, and {{RFC9431}}.


## Terminology ## {#terminology}

{::boilerplate bcp14-tagged}

Readers are expected to be familiar with the terms and concepts described in the ACE framework for Authentication and Authorization {{RFC9200}}{{RFC9201}}, as well as with terms and concepts related to CBOR Web Tokens (CWTs) {{RFC8392}} and CWT Confirmation Methods {{RFC8747}}.

The terminology for entities in the considered architecture is defined in OAuth 2.0 {{RFC6749}}. In particular, this includes client (C), resource server (RS), and authorization server (AS).

Readers are also expected to be familiar with the terms and concepts related to CoAP {{RFC7252}}, CDDL {{RFC8610}}, CBOR {{RFC8949}}, JSON {{RFC8259}}, and COSE {{RFC9052}}{{RFC9053}}.

Note that the term "endpoint" is used here following its OAuth definition {{RFC6749}}, aimed at denoting resources such as /token and /introspect at the AS, and /authz-info at the RS. This document does not use the CoAP definition of "endpoint", which is "An entity participating in the CoAP protocol."

Furthermore, this document uses the following term.

* Token series: the set comprising all the access tokens issued by the same AS for the same pair (client, resource server).

  Profiles of ACE can provide their extended and specialized definition, e.g., by further taking into account the public authentication credentials of C and the RS.

* Token hash: identifier of an access token, in binary format encoding. The token hash has no relation to other possibly used token identifiers, such as the 'cti' (CWT ID) claim of CBOR Web Tokens (CWTs) {{RFC8392}}.

Concise Binary Object Representation (CBOR) {{RFC8949}} and Concise Data Definition Language (CDDL) {{RFC8610}} are used in this document. CDDL predefined type names, especially bstr for CBOR byte strings and tstr for CBOR text strings, are used extensively in this document.

Examples throughout this document are expressed in CBOR diagnostic notation as defined in {{Section 8 of RFC8949}} and {{Appendix G of RFC8610}}. Diagnostic notation comments are often used to provide a textual representation of the numeric parameter names and values.

In the CBOR diagnostic notation used in this document, constructs of the form e'SOME_NAME' are replaced by the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. For example, {e'aud_2' : \["rs1", "rs2"\]} stands for {49 : \["rs1", "rs2"\]}.

Note to RFC Editor: Please delete the paragraph immediately preceding this note. Also, in the CBOR diagnostic notation used in this document, please replace the constructs of the form e'SOME_NAME' with the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. Finally, please delete this note.

# New ACE Workflow # {#sec-workflow}

As defined in {{Section 4 of RFC9200}}, the ACE framework considers what is shown in {{fig-old-workflow}} as its basic protocol workflow.

That is, the client first sends an Access Token Request to the token endpoint at the AS (step A), specifying permissions that it seeks to obtain for accessing protected resources at the RS, possibly together with information on its own public authentication credentials.

Then, if the request has been successfully verified, authenticated, and authorized, the AS replies to the client (step B), providing an access token and possibly additional parameters as access information including the actually granted permissions.

Finally, the client uploads the access token to the RS and, consistently with the permissions granted according to the access token, accesses a resource at the RS (step C), which replies with the result of the resource access (step F). Details about what protocol the client and the RS use to establish a secure association, mutually authenticate, and secure their communications are defined in the specifically used profile of ACE, e.g., {{RFC9202}}{{RFC9203}}{{RFC9431}}{{I-D.ietf-ace-edhoc-oscore-profile}}{{I-D.ietf-ace-group-oscore-profile}}{{RFC9431}}.

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
{: #fig-old-workflow title="ACE Basic Protocol Workflow."}

This section defines a new, alternative protocol workflow shown in {{fig-new-workflow}}, which MAY be supported by the AS. Unlike in the original protocol workflow, the AS uploads the access token to the RS on behalf of the client, and then informs the client about the outcome.

If the token uploading has been successfully completed, the AS does not provide the access token to the client altogether. Instead, the client simply establishes a secure association with the RS (if that has not happened already), and then accesses protected resources at the RS according to the permissions granted per the access token and specified by the AS as access information.

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
{: #fig-new-workflow title="ACE Alternative Protocol Workflow."}

More specifically, the new workflow consists of the following steps.

* Step A - Like in the original workflow, the client sends an Access Token Request to the token endpoint at the AS, with the additional indication that it opts in to use the alternative workflow.

  As defined in {{sec-token_upload}}, this information is conveyed to the AS by means of the "token_upload" parameter. The parameter also specifies what the AS has to return in the Token Response at step B, following a successful uploading of the access token from the AS to the RS.

* Step A1 - This new step consists of the AS uploading the access token to the RS, typically at the authz-info endpoint, just like the client does in the original workflow.

* Step A2 - This new step consists of the RS replying to the AS, following the uploading of the access token at step A1.

* Step B - In the Access Token Response, the AS tells the client that it has attempted to upload the access token to the RS, specifying the outcome of the token uploading based on the reply received from the RS at step A2.

  As defined in {{sec-token_upload}}, this information is conveyed to the client by means of the "token_upload" parameter included in the Access Token Response. If the token uploading has failed, the Access Token Response also includes the access token. Otherwise, the Access Token Response includes information consistent with what was specified by the "token_upload" parameter of the Access Token Request at Step A.

* Step C1 - This step occurs only if the token uploading from the AS has failed, and the AS has provided the client with the access token at step B. In such a case, the client uploads the access token to the RS just like at step C of the original workflow.

* Step C2 - The client attempts to access a protected resource at the RS, according to the permissions granted per the access token and specified by the AS as access information at step B.

* Steps D, E, and F are as in the original workflow.

The new workflow has no ambition to replace the original workflow defined in {{RFC9200}}. The AS can use one workflow or the other depending, for example, on the specific RS for which the access token has been issued and the nature of the communication leg with that RS.

When using the new workflow, all the communications between the AS and the RS MUST be protected, consistent with {{Sections 5.8.4.3 and 6.5 of RFC9200}}. Unlike in the original workflow, this results in protecting also the uploading of the first access token in a token series, i.e., in addition to the uploading of the following access tokens in the token series for dynamically updating the access rights of the client.

Note that the new workflow is also suitable for deployments where devices meant to access protected resources at the RS are not required to be actual ACE clients. That is, consistent with intended access policies, the AS can be configured to automatically issue access tokens for such devices and upload those access tokens to the RS. This means that those devices do not have to request for an access token to be issued in the first place, and instead can immediately send requests to the RS for accessing its protected resources, in accordance to the access tokens already issued and uploaded by the AS.

# New ACE Parameters # {#sec-parameters}

The rest of this section defines a number of additional parameters and encodings for the OAuth 2.0 token endpoint at the AS.

## token_upload {#sec-token_upload}

This section defines the additional "token_upload" parameter. The parameter can be used in an Access Token Request sent by C to the token endpoint at the AS, as well as in the successful Access Token Response sent as reply by the AS.

* The "token_upload" parameter is OPTIONAL in an Access Token Request. The presence of this parameter indicates that C opts in to use the new, alternative ACE workflow defined in {{sec-workflow}}, whose actual use for uploading the issued access token to the RS is an exclusive prerogative of the AS.

  This parameter can take one of the following integer values. When the Access Token Request is encoded in CBOR, those values are encoded as CBOR unsigned integers. The value of the parameter determines whether the follow-up successful Access Token Response will have to include certain information, in case the AS has successfully uploaded the access token to the RS.

  - 0: The Access Token Response will have to include neither the access token nor its corresponding token hash.

  - 1: The Access Token Response will have to include the token hash corresponding to the access token, but not the access token.

  - 2: The Access Token Response will have to include the access token, but not the corresponding token hash.

  If the AS supports the new ACE workflow and the Access Token Request includes the "token_upload" parameter with value 0, 1, or 2, then the AS MAY use the new ACE workflow to upload the access token to the RS on behalf of C. Otherwise, the AS MUST NOT use the new ACE workflow.

* The "token_upload" parameter is REQUIRED in a successful Access Token Response with response code 2.01 (Created), if both the following conditions apply. Otherwise, the "token_upload" parameter MUST NOT be present.

  - The corresponding Access Token Request included the "token_upload" parameter, with value 0, 1, or 2.

  - The AS has attempted to upload the issued access token to the RS as per the new ACE workflow, irrespective of the result of the token upload.

  When the "token_upload" parameter is present in the Access Token Response, it can take one of the following integer values. When the Access Token Response is encoded in CBOR, those values are encoded as CBOR unsigned integers.

  - If the token upload to the RS was not successful, then the "token_upload" parameter MUST specify the value 1.

    In this case, the Access Token Response MUST include the "access_token" parameter specifying the issued access token.

  - If the token upload at the RS was successful, then the "token_upload" parameter MUST specify the value 0.

    In this case, the Access Token Response can include additional parameters as defined below, depending on the value of the "token_upload" parameter in the corresponding Access Token Request.

    - If the "token_upload" parameter in the Access Token Request specified the value 0, then the Access Token Response MUST NOT include the "access_token" parameter and MUST NOT include the "token_hash" parameter defined in {{sec-token_hash}}.

    - If the "token_upload" parameter in the Access Token Request specified the value 1, then the Access Token Response MUST NOT include the "access_token" parameter and MUST include the "token_hash" parameter defined in {{sec-token_hash}}, specifying the hash corresponding to the issued access token and computed as defined in {{sec-token_hash}}.

    - If the "token_upload" parameter in the Access Token Request specified the value 2, then the Access Token Response MUST include the "access_token" parameter specifying the issued access token and MUST NOT include the "token_hash" parameter defined in {{sec-token_hash}}.

### Examples

{{fig-example-AS-to-C-token-upload}} shows an example with first an Access Token Request from C to the AS, and then an Access Token Response from the AS to C, following the issue of an access token bound to a symmetric PoP key.

The Access Token Request specifies the "token_upload" parameter with value 0. That is, C indicates that it requires neither the access token nor the corresponding token hash from the AS, in case the AS successfully uploads the access token to the RS.

The Access Token Response specifies the "token_upload" parameter with value 0, which indicates that the AS has successfully uploaded the access token to the RS on behalf of C.

Consistent with the value of the "token_upload" parameter in the Access Token Request, the Access Token Response includes neither the access token nor its corresponding token hash. The Access Token Response also includes the "cnf" parameter specifying the symmetric PoP key bound to the access token.

~~~~~~~~~~~
   / Access Token Request /

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: application/ace+cbor
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 0
   }


   / Access Token Response /

   Header: Created (Code=2.01)
   Content-Format: application/ace+cbor
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
{: #fig-example-AS-to-C-token-upload title="Example of Access Token Request-Response Exchange. Following a successful uploading of the access token from the AS to the RS, the Access Token Response includes the \"token_upload\" parameter but not the access token, which is bound to a symmetric key and was uploaded to the RS by the AS."}

{{fig-example-AS-to-C-token-upload-success-ret-token}} shows another example with first an Access Token Request from C to the AS, and then an Access Token Response from the AS to C, following the issue of an access token bound to a symmetric PoP key.

The Access Token Request specifies the "token_upload" parameter with value 2. That is, C indicates that it requires the access token from the AS, even in case the AS successfully uploads the access token to the RS.

The Access Token Response specifies the "token_upload" parameter with value 0, which indicates that the AS has successfully uploaded the access token to the RS on behalf of C.

Consistent with the value of the "token_upload" parameter in the Access Token Request, the Access Token Response includes the "access_token" parameter specifying the issued access token. The Access Token Response also includes the "cnf" parameter specifying the symmetric PoP key bound to the access token.

~~~~~~~~~~~
   / Access Token Request /

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: application/ace+cbor
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 2
   }


   / Access Token Response /

   Header: Created (Code=2.01)
   Content-Format: application/ace+cbor
   Max-Age: 3560
   Payload:
   {
        e'token_upload' : 0,
     / access_token / 1 : h'd08343a1'/...
      (remainder of CWT omitted for brevity;
      CWT contains the symmetric PoP key in the "cnf" claim)/,
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
{: #fig-example-AS-to-C-token-upload-success-ret-token title="Example of Access Token Request-Response Exchange. Following a successful uploading of the access token from the AS to the RS, the Access Token Response includes the \"token_upload\" parameter as well as the \"access_token\" parameter conveying the access token, which is bound to a symmetric key and was uploaded to the RS by the AS."}

{{fig-example-AS-to-C-token-upload-failed}} shows another example with first an Access Token Request from C to the AS, and then an Access Token Response from the AS to C, also following the issue of an access token bound to a symmetric PoP key.

The Access Token Request specifies the "token_upload" parameter with value 0. That is, C indicates that it requires neither the access token nor the corresponding token hash from the AS, in case the AS successfully uploads the access token to the RS.

In this example, the Access Token Response includes the "token_upload" parameter with value 1, which indicates that the AS has attempted and failed to upload the access token to the RS on behalf of C. The Access Token Response also includes the "access_token" parameter specifying the issued access token, together with the "cnf" parameter specifying the symmetric PoP key bound to the access token.

Note that, even though the AS has failed to upload the access token to the RS, the response code 2.01 (Created) is used when replying to C, since the Access Token Request as such has been successfully processed at the AS, with the following issue of the access token.

~~~~~~~~~~~
   / Access Token Request /

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: application/ace+cbor
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 0
   }


   / Access Token Response /

   Header: Created (Code=2.01)
   Content-Format: application/ace+cbor
   Max-Age: 3560
   Payload:
   {
        e'token_upload' : 1,
     / access_token / 1 : h'd08343a1'/...
      (remainder of CWT omitted for brevity;
      CWT contains the symmetric PoP key in the "cnf" claim)/,
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
{: #fig-example-AS-to-C-token-upload-failed title="Example of Access Token Request-Response Exchange. Following a failed uploading of the access token from the AS to the RS, the Access Token Response includes the \"token_upload\" parameter with value 1 as well the \"access_token\" parameter conveying the access token bound to a symmetric key."}

## token_hash {#sec-token_hash}

This section defines the additional "token_hash" parameter. The parameter can be used in a successful Access Token Response sent as reply by the AS to C.

The following refers to the base64url encoding without padding (see {{Section 5 of RFC4648}}), and denotes as "binary representation" of a text string the corresponding UTF-8 encoding {{RFC3629}}, which is the implied charset used in JSON (see {{Section 8.1 of RFC8259}}).

The "token_hash" parameter is REQUIRED in a successful Access Token Response with response code 2.01 (Created), if both the following conditions apply. Otherwise, the "token_hash" parameter MUST NOT be present.

* The corresponding Access Token Request included the "token_upload" parameter with value 1.

* The Access Token Response includes the "token_upload" parameter with value 0. That is, the AS has successfully uploaded the issued access token to the RS, as per the new ACE workflow.

This parameter specifies the token hash corresponding to the access token issued by the AS and successfully uploaded to the RS on behalf of C. In particular:

* If the Access Token Response is encoded in CBOR, then the "token_hash" parameter is a CBOR byte string, with value the token hash.

* If the Access Token Response is encoded in JSON, then the "token_hash" parameter has as value the binary representation of the base64url-encoded text string that encodes the token hash.

The AS computes the token hash as defined in {{sec-token-hash-output}}.

### Computing the Token Hash # {#sec-token-hash-output}

The AS computes the token hash over the value that the "access_token" parameter would have had in the same Access Token Response, if it was included therein and specifying the access token.

In particular, the input HASH_INPUT over which the token hash is computed is determined as follows.

* If the Access Token Response is encoded in CBOR, then:

  - BYTES denotes the value of the CBOR byte string that would be conveyed by the "access_token" parameter, if this was included in the Access Token Response.

  - HASH_INPUT_TEXT is the base64url-encoded text string that encodes BYTES.

  - HASH_INPUT is the binary representation of HASH_INPUT_TEXT.

* If the Access Token Response is encoded in JSON, then HASH_INPUT is the binary representation of the text string conveyed by the "access_token" parameter, if this was included in the Access Token Response.

Once determined HASH_INPUT as defined above, a hash value of HASH_INPUT is generated as per {{Section 6 of RFC6920}}. The resulting output in binary format is used as the token hash. Note that the used binary format embeds the identifier of the used hash function, in the first byte of the computed token hash.

The specifically used hash function MUST be collision-resistant on byte-strings, and MUST be selected from the "Named Information Hash Algorithm" Registry {{Named.Information.Hash.Algorithm}}.

The computation of token hashes defined above is aligned with that specified for the computation of token hashes in {{I-D.ietf-ace-revoked-token-notification}}, where they are used as identifiers of revoked access tokens. Therefore, given a hash algorithm and an access token, the AS computes the same corresponding token hash in either case.

If the AS supports the method specified in {{I-D.ietf-ace-revoked-token-notification}}, then the AS MUST use the same hash algorithm for computing both the token hashes to include in the "token_hash" parameter and the token hashes computed per such a method to identify revoked access tokens.

### Example

{{fig-example-AS-to-C-token-hash}} shows an example with first an Access Token Request from C to the AS, and then an Access Token Response from the AS to C, following the issue of an access token bound to a symmetric PoP key.

The Access Token Request specifies the "token_upload" parameter with value 1. That is, C indicates that it requires the token hash corresponding to the access token from the AS, in case the AS successfully uploads the access token to the RS.

The Access Token Response specifies the "token_upload" parameter with value 0, which indicates that the AS has successfully uploaded the access token to the RS on behalf of C.

Consistent with the value of the "token_upload" parameter in the Access Token Request, the Access Token Response includes the "token_hash" parameter, which specifies the token hash corresponding to the issued access token. The Access Token Response also includes the "cnf" parameter specifying the symmetric PoP key bound to the access token.

~~~~~~~~~~~
   / Access Token Request /

   Header: POST (Code=0.02)
   Uri-Host: "as.example.com"
   Uri-Path: "token"
   Content-Format: application/ace+cbor
   Payload:
   {
     / audience /  5 : "tempSensor4711",
     / scope /     9 : "read",
     e'token_upload' : 1
   }


   / Access Token Response /

   Header: Created (Code=2.01)
   Content-Format: application/ace+cbor
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
{: #fig-example-AS-to-C-token-hash title="Example of Access Token Request-Response Exchange. Following a successful uploading of the access token from the AS to the RS, the Access Token Response includes the \"token_upload\" parameter as well as the \"token_hash\" parameter. The \"token_hash\" parameter conveys the token hash corresponding to the issued access token, which is bound to a symmetric key and was uploaded to the RS by the AS."}

## rs_cnf2 and aud2 {#sec-rs_cnf2-aud2}

This section defines the additional parameters "rs_cnf2" and "aud2" for an Access Token Response, sent by the AS in reply to a request to the token endpoint from C.

* The "rs_cnf2" parameter is OPTIONAL if the token type is "pop", asymmetric keys are used, and the access token is issued for an audience that includes multiple RSs (i.e., a group-audience, see {{Section 6.9 of RFC9200}}). Otherwise, the "rs_cnf2" parameter MUST NOT be present.

  This parameter specifies information about the public keys used by the RSs of a group-audience for authenticating themselves to C, and is used in case the binding between the public keys and the corresponding RS identities are not established through other means. If this parameter is absent, either the RSs in the group-audience do not use a public key, or the AS knows that the RSs can authenticate themselves to C without additional information.

  If present, this parameter MUST encode a non-empty CBOR array of N elements, where N is the number of RSs in the group-audience for which the access token is issued. Each element of the CBOR array specifies the public key of one RS in the group-audience, and MUST follow the syntax and semantics of the "cnf" claim either from {{Section 3.1 of RFC8747}} for CBOR-based interactions, or from {{Section 3.1 of RFC7800}} for JSON-based interactions. It is not required that all the elements of the CBOR array rely on the same confirmation method.

  Each of the public keys may contain parameters specifying information such as the public key algorithm and use (e.g., by means of the parameters "alg" or "key_ops" in a COSE_Key structure). If such information is specified, a client MUST NOT use a public key that is incompatible with the profile or PoP algorithm according to that information. An RS MUST reject a proof of possession using such a key with a response code equivalent to the CoAP code 4.00 (Bad Request).

* The "aud2" parameter is OPTIONAL and specifies the identifiers of the RSs in the group-audience for which the access token is issued.

  If present, this parameter MUST encode a non-empty CBOR array of N elements, where N is the number of RSs in the group-audience for which the access token is issued. Each element of the CBOR array in the "aud2" parameter MUST be a CBOR text string, with value the identifier of one RS in the group-audience.

  The element of the CBOR array referring to an RS in the group-audience SHOULD have the same value that would be used to identify that RS through the "aud" parameter of an Access Token Request to the AS (see {{Section 5.8.2 of RFC9200}}) and of an Access Token Response from the AS (see {{Section 5.8.2 of RFC9200}}), when requesting and issuing an access token for that individual RS.

  The "aud2" parameter is REQUIRED if the "rs_cnf2" parameter is present. In such a case, the i-th element of the CBOR array in the "aud2" parameter MUST be the identifier of the RS whose public key is specified as the i-th element of the CBOR array in the "rs_cnf2" parameter.

### Example

{{fig-example-AS-to-C-rs_cnf2}} shows an example of Access Token Response from the AS to C, following the issue of an access token for a group-audience composed of two RSs "rs1" and "rs2", and bound to C's public key as asymmetric PoP key. The Access Token Response includes the access token, as well as the parameters "aud2" and "rs_cnf2". These specify the public key of the two RSs as intended recipients of the access token and the identifiers of those two RSs, respectively.

~~~~~~~~~~~
   Header: Created (Code=2.01)
   Content-Format: application/ace+cbor
   Max-Age: 3600
   Payload:
   {
     / access_token / 1 : b64'SlAV32hk'/...
      (remainder of CWT omitted for brevity;
      CWT contains the client's RPK in the "cnf" claim)/,
     / expires_in /   2 : 3600,
                e'aud2' : ["rs1", "rs2"],
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
{: #fig-example-AS-to-C-rs_cnf2 title="Example of Access Token Response with an access token bound to an asymmetric key, using the parameters \"aud2\" and \"rs_cnf2\"."}

## anchor_cnf {#sec-anchor_cnf}

This section defines the additional "anchor_cnf" parameter for an Access Token Response, sent by the AS in reply to a request to the token endpoint from C.

The "anchor_cnf" parameter is OPTIONAL if the token type is "pop" and asymmetric keys are used. Otherwise, the "anchor_cnf" parameter MUST NOT be present.

This parameter specifies information about the public keys of trust anchors, which C can use to validate the public key of the RS/RSs included in the audience for which the access token is issued. This parameter can be used when the access token is issued for an audience including one RS or multiple RSs.

If this parameter is absent, either the RS/RSs in the audience do not use a public key, or the AS knows that C can validate the public key of such RS/RSs without additional information (e.g., C has already obtained the required public keys of the involved trust anchors from the AS or through other means).

If present, this parameter MUST encode a non-empty CBOR array that MUST be treated as a set, i.e., the order of its elements has no meaning. Each element of the CBOR array specifies the public key of one trust anchor, which can be used to validate the public key of at least one RS included in the audience for which the access token is issued. Each element of the CBOR array MUST follow the syntax and semantics of the "cnf" claim either from {{Section 3.1 of RFC8747}} for CBOR-based interactions, or from {{Section 3.1 of RFC7800}} for JSON-based interactions. It is not required that all the elements of the CBOR array rely on the same confirmation method.

Each of the public keys specified in the "anchor_cnf" parameter may contain parameters specifying information such as the public key algorithm and use (e.g., by means of the parameters "alg" or "key_ops" in a COSE_Key structure). If such information is specified, a client MUST NOT use a public key that is incompatible with the profile, or with the public keys to validate and the way to validate those.

The presence of this parameter does not require that the Access Token Response also includes the "rs_cnf" parameter defined in {{RFC9201}} or the "rs_cnf2" parameter defined in {{sec-rs_cnf2-aud2}} of this document. That is, C may be able to obtain the public keys of the RS/RSs for which the access token is issued through other means.

When the Access Token Response includes both the "anchor_cnf" parameter and the "aud2" parameter defined in {{sec-rs_cnf2-aud2}}, then C MUST make sure that a public key PK_RS is associated with an RS identified by an element of "aud2", before using any of the public keys specified in "anchor_cnf" to validate PK_RS.

When the Access Token Response includes the "anchor_cnf" parameter but not the "aud2" parameter, then C can use any of the public keys specified in "anchor_cnf" to validate the public key PK_RS of any RS in the targeted audience. This allows C to use the access token with an RS that is deployed later on as part of the same audience, which is particularly useful in the case of a group-audience.

### Example

{{fig-example-AS-to-C-anchor_cnf}} shows an example of Access Token Response from the AS to C, following the issue of an access token for a group-audience, and bound to C's public key as asymmetric PoP key.

The identifier of the group-audience was specified by the "aud" parameter of the Access Token Request to the AS and is specified by the "aud" claim of the issued access token, and is not repeated in the Access Token Response from the AS.

The Access Token Response includes the "anchor_cnf" parameter. This specifies the public key of a trust anchor that C can use to validate the public keys of any RS with which the access token is going to be used. The public key of the trust anchor is here conveyed within an X.509 certificate used as public authentication credential for that trust anchor, by means of the CWT confirmation method "x5chain" defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

~~~~~~~~~~~
   Header: Created (Code=2.01)
   Content-Format: application/ace+cbor
   Max-Age: 3600
   Payload:
   {
     / access_token / 1 : b64'SlAV32hk'/...
      (remainder of CWT omitted for brevity;
      CWT contains the client's RPK in the "cnf" claim)/,
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

## rev_aud {#sec-rev_aud}

This section defines the additional "rev_aud" parameter. The parameter can be used in an Access Token Request sent by C to the token endpoint at the AS, as well as in the successful Access Token Response sent as reply by the AS.

* The "rev_aud" parameter is OPTIONAL in an Access Token Request. The presence of this parameter indicates that C wishes the requested access token to specify additional access rights. These are intended for the access token's audience to access protected resources at C as the access token's reverse audience.

  This parameter specifies such a reverse audience as a text string identifier of C. When the Access Token Request is encoded in CBOR, the value of this parameter is encoded as a CBOR text string.

* The "rev_aud" parameter is OPTIONAL in an Access Token Response. If present, it has the same meaning and encoding that it has in the Access Token Request.

Fundamentally, this parameter has the same semantics of the "aud" parameter used in the ACE framework, with the difference that it conveys an identifier of C as a host of protected resources to access, according to the access rights granted as reverse scope to the audience of the access token issued by the AS.

The use of this parameter is further detailed in {{sec-bidirectional-access-control}}.

## rev_scope {#sec-rev_scope}

This section defines the additional "rev_scope" parameter. The parameter can be used in an Access Token Request sent by C to the token endpoint at the AS, as well as in the successful Access Token Response sent as reply by the AS.

* The "rev_scope" parameter is OPTIONAL in an Access Token Request. The presence of this parameter indicates that C wishes the requested access token to specify additional access rights. These are intended for the access token's audience to access protected resources at C as the access token's reverse audience.

  This parameter specifies such access rights as a reverse scope. When the Access Token Request is encoded in CBOR, the value of this parameter is encoded as a CBOR text string or a CBOR byte string.

* The "rev_scope" parameter is OPTIONAL in an Access Token Response. If present, this parameter specifies the access rights that the AS has actually granted as a reverse scope to the access token's audience, for accessing protected resources at C as the access token's reverse audience.

Fundamentally, this parameter has the same semantics of the "scope" parameter used in ACE framework, with the difference that it conveys an identifier of C as a host of protected resources to access, according to the access rights granted as reverse scope to the audience of the access token issued by the AS.

The use of this parameter is further detailed in {{sec-bidirectional-access-control}}.

# Bidirectional Access Control # {#sec-bidirectional-access-control}

In some deployments, two devices DEV1 and DEV2 might wish to access each other's protected resources. This can clearly be achieved by means of two separate access tokens, each of which is used to enforce access control in one direction. That is:

* A first access token is requested by and issued to DEV1, for accessing protected resources at DEV2. With respect to this access token, DEV1 is an ACE client, while DEV2 is an ACE RS.

* A second access token is requested by and issued to DEV2, for accessing protected resources at DEV1. With respect to this access token, DEV2 is an ACE client, while DEV1 is an ACE RS.

This section defines how to enforce such a bidirectional access control by means of a single access token, which is requested by and issued to a device DEV1 acting as ACE client. In particular:

* The access token expresses access rights according to which the requesting ACE client DEV1 can access protected resources hosted at the ACE RS DEV2.

  For this first direction of access control, the target DEV2 is specified by means of the "aud" parameter and the corresponding access token claim, while the access rights are specified by means of the "scope" parameter and the corresponding access token claim.

  This is the original, primary direction of access control, where the ACE client DEV1 that requests the access token wishes access rights to access protected resources at the ACE RS DEV2.

* The same access token additionally expresses access rights according to which the ACE RS DEV2 can access protected resources hosted at the ACE client DEV1.

  For this second direction of access control, the target DEV1 is specified by means of the "rev_aud" parameter defined in {{sec-rev_aud}} and the corresponding access token claim defined in this section, while the access rights are specified by means of the "rev_scope" parameter defined in {{sec-rev_scope}} and the corresponding access token claim defined in this section.

  This is the new, secondary direction of access control, where the ACE client DEV1 that requests the access token also wishes access rights for the ACE RS DEV2 to access resources at DEV1.

  Clearly, this requires the ACE client DEV1 to also act as CoAP server, and the ACE RS DEV2 to also act as CoAP client.

Like for the original case with a single access control direction, the access token is uploaded to the ACE RS DEV2, which processes the access token as per {{Section 5.10 of RFC9200}} and according to the transport profile of ACE used by DEV1 and DEV2.

The protocol workflow is detailed in the following {{sec-bidirectional-access-control-one-as}} and {{sec-bidirectional-access-control-two-as}}, in case only one authorization server or two authorization servers are involved, respectively.

## Scenario with One Authorization Server # {#sec-bidirectional-access-control-one-as}

As shown in {{fig-bidirectional-one-as}}, this section considers a scenario with a single authorization server AS. Both devices DEV1 and DEV2 are registered at AS, and each of them with permissions to access protected resources at the other device. In the following, DEV1 acts as ACE client by requesting an access token from AS.

~~~~~~~~~~~ aasvg
- DEV1 is registered as:                       +----+
  - Device authorized to access DEV2; and      |    |
  - Device that can be accessed by DEV2        |    |
                                               |    |
- DEV2 is registered as:                       | AS |
  - Device that can be accessed by DEV1; and   |    |
  - Device authorized to access DEV1           |    |
                                               |    |
                                               +----+

                                                  ^
                                                  |
                                                  |
                                                  |
                                                  v

 DEV2                                           DEV1
+----+                                          +---+
| RS | <--------------------------------------> | C |
+----+                                          +---+
~~~~~~~~~~~
{: #fig-bidirectional-one-as title="Bidirectional access control with one Authorization Server."}

### Access Token Request # {#sec-bidirectional-access-control-one-as-req}

As to the Access Token Request that DEV1 sends to AS, the following applies.

* The "aud" and "scope" parameters are used as defined in {{RFC9200}}, and according to the transport profile of ACE used by DEV1 and DEV2.

  In particular, "aud" specifies an identifier of DEV2, while "scope" specifies access rights that DEV1 wishes to obtain for accessing protecting resources at DEV2.

  That is, the two parameters pertain to the primary direction of access control.

* The "req_cnf" parameter defined in {{RFC9201}} can be included. When present, it specifies the key that DEV1 wishes to bind to the requested access token.

* The "rev_aud" and "rev_scope" parameters defined in {{sec-rev_aud}} and {{sec-rev_scope}} can be included.

  In particular, "rev_aud" specifies an identifier of DEV1, while "rev_scope" specifies access rights that DEV1 wishes for DEV2 to obtain for accessing protecting resources at DEV1.

  That is, the two parameters pertain to the secondary direction of access control.

If DEV1 wishes that the requested access token also provides DEV2 with access rights pertaining to the secondary direction of access control, then the Access Token Request has to include at least one of the two parameters "rev_aud" and "rev_scope".

### Access Token Response # {#sec-bidirectional-access-control-one-as-resp}

When receiving an Access Token Request that includes at least one of the two parameters "rev_aud" and "rev_scope", AS processes it as defined in {{Section 5.2 of RFC9200}}, with the following additions:

* If the Access Token Request includes the "rev_scope" parameter but not the "rev_aud" parameter, then AS assumes the identifier of DEV1 to be the default one, if any is defined.

* If the Access Token Request includes the "rev_aud" parameter but not the "rev_scope" parameter, then AS assumes the access rights requested for DEV2 to access DEV1 to be the default ones, if any are defined.

* AS checks whether the access rights requested for DEV2 as reverse scope can be at least partially granted, in accordance with the installed access policies pertaining to the access to protected resources at DEV1 from DEV2.

  That is, AS performs the same evaluation that it would perform if DEV2 sent an Access Token Request as an ACE client, with the intent to access protected resources at DEV1 as an ACE RS.

  It is REQUIRED that such evaluation succeeds, in order for AS to issue an access token and reply to DEV1 with a successful Access Token Response.

As to the successful Access Token Response that AS sends to DEV1, the following applies.

* The "aud" and "scope" parameters are used as defined in {{RFC9200}}, and according to the transport profile of ACE used by DEV1 and DEV2.

  In particular, "aud" specifies an identifier of DEV2, while "scope" specifies the access rights that AS has granted to DEV1 for accessing protecting resources at DEV2.

  The "scope" parameter has to be present if: i) it was present in the Access Token Request, and the access rights granted to DEV1 are different from the requested ones; or ii) it was not present in the Access Token Request, and the access rights granted to DEV1 are different from the default ones.

  If the "scope" parameter is not present, then the granted access rights are the same as those requested by the "scope" parameter in the Access Token Request if present therein, or the default access rights otherwise.

* The "rs_cnf" parameter defined in {{RFC9201}} can be included. When present, it specifies information about the public key that DEV2 uses to authenticate.

* The "rev_aud" parameter defined in {{sec-rev_aud}} can be included, and specifies an identifier of DEV1.

  If the "rev_aud" parameter is present in the Access Token Response and it was also present in the Access Token Request, then the parameter in the Access Token Response MUST have the same value specified by the parameter in the Access Token Request.

* The "rev_scope" parameter defined in {{sec-rev_scope}} can be included, and specifies access rights that AS has granted to DEV2 for accessing protecting resources at DEV1.

  The "rev_scope" parameter MUST be present if: i) it was present in the Access Token Request, and the access rights granted to DEV2 are different from the requested ones; or ii) it was not present in the Access Token Request, and the access rights granted to DEV2 are different from the default ones.

  If the "rev_scope" parameter is not present, then the access rights granted to DEV2 are the same as those requested by the "rev_scope" parameter in the Access Token Request if present therein, or the default access rights otherwise.

The issued access token MUST include information about the reverse audience and reverse scope pertaining to the secondary access control direction. In particular:

* The access token MUST contain a claim specifying the identifier of DEV1.

  If the Access Token Response includes the "rev_aud" parameter, then the claim specifies the same information conveyed by that parameter.

  If this is not the case, then the claim specifies the same information conveyed by the "rev_aud" parameter of the Access Token Request, if included therein, or the default identifier of DEV1 otherwise.

  When CWTs are used as access tokens, this information MUST be transported in the "rev_aud" claim defined in {{iana-token-cwt-claims}}.

* The access token MUST contain a claim specifying the access rights that AS has granted to DEV2 for accessing protecting resources at DEV1.

  If the Access Token Response includes the "rev_scope" parameter, then the claim specifies the same information conveyed by that parameter.

  If this is not the case, then the claim specifies the same information conveyed by the "rev_scope" parameter of the Access Token Request, if included therein, or the default access rights for DEV2 to access DEV1 otherwise.

  When CWTs are used as access tokens, this information MUST be transported in the "rev_scope" claim, defined in {{iana-token-cwt-claims}}.

### Access to Protected Resources # {#sec-bidirectional-access-control-one-as-comm}

As to the secure communication association between DEV1 and DEV2, its establishment and maintenance does not deviate from what is defined in the transport profile of ACE used by DEV1 and DEV2.

Furthermore, communications between DEV1 and DEV2 MUST rely on such secure communication association for both directions of access control, i.e., when DEV1 accesses protected resources at DEV2 and vice versa.

After having received a successful Access Token Response from AS, DEV1 MUST maintain and enforce the information about the access rights granted to DEV2 and pertaining the secondary access control direction.

In particular, DEV1 MUST prevent DEV2 from accessing protected resources at DEV1, in case access requests from DEV2 are not authorized as per the reverse scope specified by the issued access token, or after having purged the issued access token (e.g., following its expiration of revocation).

## Scenario with Two Authorization Servers # {#sec-bidirectional-access-control-two-as}

TBD

## Practical Considerations

When enforcing bidirectional access control by means of a single access token, the following considerations hold.

* The access token can be uploaded to the ACE RS DEV2 by the ACE client per the original ACE workflow, or by the AS that has issued the access token per the new ACE workflow defined in {{sec-workflow}}.

* Since the access token is requested by the ACE client DEV1, only DEV1 can request for a new access token in the same token series, in order to dynamically update the access rights concerning its own access to protected resources hosted by DEV2 (on the primary access control direction) and/or the access rights concerning the access of DEV2 to access protected resources hosted by DEV1 (on the secondary access control direction).

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
Content-Format: application/concise-problem-details+cbor
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

Note to RFC Editor: In the figure above, please replace "TBD" with the unsigned integer assigned as key value to the Custom Problem Detail entry "ace-error" (see {{iana-problem-details}}). Then, please delete this paragraph.

When the ACE framework is used with CBOR for encoding message payloads, the following applies.

* It is RECOMMENDED that authorization servers, clients, and resource servers support the payload format defined in this section.

* Authorization servers, clients, and resource servers that support the payload format defined in this section MUST use it when composing an outgoing error response that conveys an error code.

# Security Considerations

The same security considerations from the ACE framework for Authentication and Authorization {{RFC9200}} apply to this document, together with those from the specifically used transport profile of ACE, e.g., {{RFC9202}}{{RFC9203}}{{RFC9431}}{{I-D.ietf-ace-edhoc-oscore-profile}}{{I-D.ietf-ace-group-oscore-profile}}{{RFC9431}}.

When using the problem-details format defined in {{RFC9290}} for error responses, then the privacy and security considerations from {{Sections 4 and 5 of RFC9290}} also apply.

Editor's note: add more security considerations.

# IANA Considerations

This document has the following actions for IANA.

Note to RFC Editor: Please replace all occurrences of "{{&SELF}}" with the RFC number of this specification and delete this paragraph.

## OAuth Parameters Registry ## {#iana-oauth-params}

IANA is asked to add the following entries to the "OAuth Parameters" registry.

* Name: "token_upload"
* Parameter Usage Location: token request and token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: "token_hash"
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: "rs_cnf2"
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: "aud2"
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: "anchor_cnf"
* Parameter Usage Location: token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: "rev_aud"
* Parameter Usage Location: token request and token response
* Change Controller: IETF
* Reference: {{&SELF}}

<br>

* Name: "rev_scope"
* Parameter Usage Location: token request and token response
* Change Controller: IETF
* Reference: {{&SELF}}

## OAuth Parameters CBOR Mappings Registry ## {#iana-oauth-cbor-mappings}

IANA is asked to add the following entries to the "OAuth Parameters CBOR Mappings" registry, following the procedure specified in {{RFC9200}}.

* Name: "token_upload"
* CBOR Key: TBD
* Value Type: unsigned integer
* Reference: {{&SELF}}

<br>

* Name: "token_hash"
* CBOR Key: TBD
* Value Type: unsigned integer
* Reference: {{&SELF}}

<br>

* Name: "rs_cnf2"
* CBOR Key: TBD
* Value Type: array
* Reference: {{&SELF}}

<br>

* Name: "aud2"
* CBOR Key: TBD
* Value Type: array
* Reference: {{&SELF}}

<br>

* Name: "anchor_cnf"
* CBOR Key: TBD
* Value Type: array
* Reference: {{&SELF}}

<br>

* Name: "rev_aud"
* CBOR Key: TBD
* Value Type: text string
* Reference: {{&SELF}}

<br>

* Name: "rev_scope"
* CBOR Key: TBD
* Value Type: text string or byte string
* Reference: {{&SELF}}

## JSON Web Token Claims Registry ## {#iana-token-json-claims}

IANA is asked to add the following entries to the "JSON Web Token Claims" registry, following the procedure specified in {{RFC7519}}.

*  Claim Name: "rev_aud"
*  Claim Description: The reverse audience of an access token
*  Change Controller: IETF
*  Reference: {{&SELF}}

<br>

*  Claim Name: "rev_scope"
*  Claim Description: The reverse scope of an access token
*  Change Controller: IETF
*  Reference: {{&SELF}}

## CBOR Web Token (CWT) Claims Registry ## {#iana-token-cwt-claims}

IANA is asked to add the following entries to the "CBOR Web Token (CWT) Claims" registry, following the procedure specified in {{RFC8392}}.

* Claim Name: "rev_aud"
* Claim Description: The reverse audience of an access token
* JWT Claim Name: "rev_aud"
* Claim Key: TBD
* Claim Value Type: text string
* Change Controller: IETF
* Reference: {{sec-bidirectional-access-control}} of {{&SELF}}

<br>

* Claim Name: "rev_scope"
* Claim Description: The reverse scope of an access token
* JWT Claim Name: "rev_scope"
* Claim Key: TBD
* Claim Value Type: text string or byte string
* Change Controller: IETF
* Reference: {{sec-bidirectional-access-control}} of {{&SELF}}

## Custom Problem Detail Keys Registry  ## {#iana-problem-details}

IANA is asked to register the following entry in the "Custom Problem Detail Keys" registry within the "Constrained RESTful Environments (CoRE) Parameters" registry group.

* Key Value: TBD
* Name: ace-error
* Brief Description: Carry ACE {{RFC9200}} problem details in a Concise Problem Details data item.
* Change Controller: IETF
* Reference: {{sec-updated-error-responses}} of {{&SELF}}


--- back

# Benefits for ACE Transport Profiles # {#sec-benefits-for-profiles}

For any transport profile of ACE, the following holds.

* The new ACE workflow defined in {{sec-workflow}} is effectively possible to use. This is beneficial for deployments where the communication leg between C and the RS is constrained, but the communication leg between the AS and RS is not.

* When the new ACE workflow is used, the "token_upload" parameter defined in {{sec-token_upload}} is used:

  - To inform the AS about C opting in to use the new ACE workflow.

  - To request the AS that the follow-up successful Access Token Response will have to include certain information, in case the AS has successfully uploaded the access token to the RS.

  - To inform C that the AS has attempted to upload the issued access token to the RS, specifying whether the uploading has succeeded or failed.

* When the new ACE workflow is used, it remains possible for C to always obtain the issued access token from the AS.

  That is, by specifying the value 2 for the "token_upload" parameter in the Access Token Request, C will ensure to receive the access token from the AS, even in case the AS successfully uploads the access token to the RS on behalf of C.

  This is useful in transport profiles of ACE where C can re-upload the same Access Token to the RS by itself, e.g., in order to perform a key update like defined for the OSCORE profile {{RFC9203}}.

## DTLS Profile

When the RPK mode of the DTLS profile is used (see {{Section 3.2 of RFC9202}}), it becomes possible for the AS to effectively issue an access token intended to an audience that includes multiple RSs. This is enabled by the parameters "rs_cnf2" and "aud2" defined in {{sec-rs_cnf2-aud2}}, as well as by the "anchor_cnf" parameter defined in {{sec-anchor_cnf}}. This seamlessly applies also if the profile uses Transport Layer Security (TLS) {{RFC8446}}, as defined in {{RFC9430}}.

## EDHOC and OSCORE Profile

When the EDHOC and OSCORE profile is used {{I-D.ietf-ace-edhoc-oscore-profile}}, it becomes possible for the AS to effectively issue an access token intended to an audience that includes multiple RSs. This is enabled by the parameters "rs_cnf2" and "aud2" defined in {{sec-rs_cnf2-aud2}}, as well as by the "anchor_cnf" parameter defined in {{sec-anchor_cnf}}.

# Open Points # {#sec-open-points}

## New Workflow # {#sec-open-points-workflow}

The following discusses open points related to the use of the new ACE workflow defined in {{sec-workflow}}.

### Allow the Dynamic Update of Access Rights # {#sec-open-points-workflow-dynamic-access-rights}

In some profiles of ACE, C can request a new access token to update its access rights, while preserving the same secure association with the RS. The new access token supersedes the current one stored at the RS, as they are both part of the same token series.

When using the original ACE workflow, C uploads the new access token to the RS by protecting the message exchange through the secure association with the RS. This allows the RS to determine that the upload of such access token is for updating the access rights of C.

When using the new ACE workflow, the AS uploads the new access token to the RS also when an update of access rights for C is to be performed. This message exchange would be protected through the secure association between the AS and the RS. However, this secure association does not help the RS retrieve the stored access token to supersede, as that is rather bound to the secure association with C.

In order for the new ACE workflow to also allow the dynamic update of access rights, it is required that the new access token updating the access rights of C includes an explicit indication for the RS. Such an indication can point the RS to the token series in question (hence to the current access token to supersede), irrespective of the secure association used to protect the token uploading.

In some profiles of ACE, such an indication is in fact already present in issued access tokens:

* In the PSK mode of the DTLS profile {{RFC9202}}, the token series is indicated by the "kid" parameter within the "cnf" claim of the new access token. This has the same value of the "kid" parameter in the COSE_Key within the "cnf" claim from the first access token of the token series.

* In the OSCORE profile {{RFC9203}}, the token series is indicated by the "kid" parameter within the "cnf" claim of the new access token. This has the same value of the "id" parameter in the OSCORE_Input_Material object within the "cnf" claim from the first access token of the token series.

* In the EDHOC and OSCORE profile {{I-D.ietf-ace-edhoc-oscore-profile}}, the token series is indicated by the "kid" parameter within the "cnf" claim of the new access token. This has the same value of the "id" parameter in the EDHOC_Information object within the "cnf" claim from the first access token of the token series.

In the three cases above, the update of access rights is possible because there is a value used as de facto "token series ID". This value does not change throughout the lifetime of a token series, and it is used to associate the new access token with the previous one in the same series to be superseded.

Such a token series ID is required to have a unique value from a namespace/pool that the AS exclusively controls. This is in fact what happens in the profiles of ACE above, where the AS is the entity creating the mentioned objects or COSE Key included in the first access token of a token series.

However, this may generally not hold and it is not what happens in other known cases, i.e., the DTLS profile in RPK mode {{RFC9203}} and the Group OSCORE profile {{I-D.ietf-ace-group-oscore-profile}}. At the moment, the dynamic update of access rights is not possible for those, _neither in the original nor in the new ACE workflow_.

In order to make the update of access rights possible also for such cases, as well as both in the original and in the new ACE workflow, those cases can rely on a new "token_series_id" parameter and corresponding "token_series_id" claim (see {{sec-more-parameters}}), which specify a unique identifier of the token series which an access token belongs to.

As to existing profiles of ACE, the above has no intention to change the current behavior when the update of access rights occurs, irrespective of the used ACE workflow and especially when using the original workflow.

If future profiles rely on a construction where the AS creates the object or the key included in the "cnf" claim of the first access token in a token series, and a unique ID generated by the AS is included in such object or key, then that ID must be used as de facto "token series ID", rather than the new "token_series_id" parameter.

Even though a "token series ID" provides an explicit indication for recognizing a stored access token as belonging to an ongoing token series, such a process might still be prone to ambiguities. For example, the RS might have deleted a stored access token due to memory limitations. This effectively terminates the corresponding token series, which is however impractical for the RS to remember indefinitely. Consequently, if the AS uploads to the RS a new access token belonging to the same token series, the RS would erroneously interpret it to be the first access token of a new series. This can be avoided by relying on a new "updated_rights" parameter, which the AS can include in a POST request to the /authz-info endpoint when uploading to the RS an access token for dynamically updating the access rights of C (see {{sec-more-parameters}}).

### Ensure Applicability to Any ACE Profile # {#sec-open-points-workflow-applicability}

Some profiles of ACE require that C and the RS generate information to be exchanged when uploading the access token.

For example, in the OSCORE profile {{RFC9203}}, C and the RS exchange the nonces N1 and N2 together with their OSCORE Recipient IDs ID1 and ID2, when uploading to the RS the first access token of a token series, as well as when re-uploading any access token (e.g., in order to perform a key update).

Evidently, using the new ACE workflow prevents C and the RS from directly performing the required exchanges above, since the uploading of the access token does not rely on a direct interaction between C and the RS like in the original ACE workflow. For some profiles of ACE, this may prevent the use of the new ACE workflow altogether.

This issue can be solved by having the AS acting as intermediary also for the exchange of C- and RS-generated information, by relying on two new parameters "to_rs" and "from_rs" (see {{sec-more-parameters}}). In particular, C can use "to_rs" for providing the AS with C-generated information, to be relayed to the RS when uploading the access token. Also, the RS can use "from_rs" for providing the AS with RS-generated information when replying to the token uploading, and to be relayed to C.

With reference to the two cases mentioned above, "to_rs" can specify the nonce N1 generated by C, while "from_rs" can specify the nonce N2 generated by the RS.

## Further New Parameters to Consider # {#sec-more-parameters}

The following discusses possible, further new parameters that can be defined for addressing the open points raised earlier in {{sec-open-points}}.

* "token_series_id" - This parameter specifies the unique identifier of a token series, thus ensuring that C can dynamically update its access rights, irrespective of the used ACE workflow (see {{sec-open-points-workflow-dynamic-access-rights}}).

  When issuing the first access token of a token series, the AS specifies this parameter in the Access Token Response to C, with value TS_ID. Also, the AS includes a "token_series_id" claim with the same value in the access token.

  When C requests a new access token in the same tokes series for dynamically updating its access rights, C specifies TS_ID as value of the "token_series_id" parameter of the Access Token Request, which MUST omit the "req_cnf" parameter (see {{Section 3.1 of RFC9201}}). The AS specifies the same value within the "token_series_id" claim of the new access token.

  When this parameter is used, the information about the token series in question has to be specified in that parameter and in the corresponding token claim. Instead, the "req_cnf" parameter and the "cnf" claim are used for their main purpose, i.e., for specifying the public authentication credential of the client, by value or by reference.

  If a profile of ACE can use or is already using a different parameter/claim as de-facto identifier of the token series, then that profile will continue to do so, and will not use this new "token_series_id" parameter.

* "updated_rights" - When using the new ACE workflow and issuing an access token for dynamically updating the access rights of C, the AS specifies this parameter in the request sent to the RS for uploading the access token on behalf of C (see {{sec-open-points-workflow-dynamic-access-rights}}). This parameter encodes the CBOR simple value `true` (0xf5).

* "to_rs" - When using the new ACE workflow, this parameter specifies C-generated information that, according to the used profile of ACE, C has to provide to the RS together with the access token if using the original ACE workflow. This allows the AS to relay such information to the RS upon uploading the access token on behalf of C (see {{sec-open-points-workflow-applicability}}).

  First, C specifies this parameter in the Access Token Request sent to the AS. Then, the AS specifies this parameter in the request to the RS sent for uploading the access token on behalf of C, by simply relaying the value received from C. The used profile of ACE has to define the detailed content and semantics of the information specified in the parameter value.

* "from_rs" - When using the new ACE workflow, this parameter specifies RS-generated information that, according to the used profile of ACE, the RS has to provide to C after the uploading of an access token if using the original ACE workflow. This allows the AS to relay such information to C after having uploaded the access token on behalf of C (see {{sec-open-points-workflow-applicability}}).

  First, the RS specifies this parameter in the response sent to the AS, after the upload of an access token through a request from the AS. Then, the AS specifies this parameter in the Access Token Response to C, by simply relaying the value received from the RS. The used profile of ACE has to define the detailed content and semantics of the information specified in the parameter value.

# CDDL Model # {#sec-cddl-model}
{:removeinrfc}

~~~~~~~~~~~~~~~~~~~~ CDDL
; OAuth Parameters CBOR Mappings
token_upload = 48
token_hash = 49
aud_2 = 50
rs_cnf_2 = 51
anchor_cnf = 52
rev_aud_param = 53
rev_scope_param = 54

; CBOR Web Token (CWT) Claims
rev_aud_claim = 42
rev_scope_claim = 43

; CWT Confirmation Methods
x5chain = 5

; Custom Problem Detail Keys Registry
ace-error = 2
~~~~~~~~~~~~~~~~~~~~
{: #fig-cddl-model title="CDDL model" artwork-align="left"}

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -02 to -03 ## {#sec-02-03}

* Lowercase use of "client", "resource server", and "authorization server".

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

* The client has to opt-in for using the alternative workflow.

* Parameter "token_uploaded" renamed to "token_upload".

* Updated format of error response payload to use RFC 9290.

* Security considerations inherited from other documents.

* Editorial fixes and improvements.

# Acknowledgments # {#acknowledgments}
{:numbered="false"}

The authors sincerely thank {{{Christian Amsüss}}}, {{{Rikard Höglund}}}, and {{{Dave Robin}}} for their comments and feedback.

This work was supported by the Sweden's Innovation Agency VINNOVA within the EUREKA CELTIC-NEXT project CYPRESS; and by the H2020 project SIFIS-Home (Grant agreement 952652).
