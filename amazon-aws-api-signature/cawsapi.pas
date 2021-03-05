unit cawsapi;
{ this unit contains the methods used to create AWS v4 signature }

interface

uses
  cawsglobal,
  classes;

type
  {$REGION ' TAwsAuthentication  }
  TAwsAuthentication = class(TObject)
  private
    FAccessKey : string;
    FSecretKey : string;

    // used to build the canonical request for the Authorization header
    FHTTPMethod : string;
    FAPIHostFull : string;
    FRequestHeaders : TStringList;
    FPayload : string;

    // used to build the string to sign scope
    FSigningDate : TDateTime;
    FAwsRegion : string;
    FAwsServiceType : TAwsServiceTypes;

    function GetHashedPayload : string;
    function GetSignedHeaders : string;
    function GetCanonicalRequest : string;
    function GetStringToSign : string;
    function GetSigningKey : string;
    function GetSigningKeyHex : string;
    function GetSignature : string;
    function GetCredential : string;
    function GetAuthorization : string;

  public
    constructor Create; overload;
    constructor Create(AAccessKey,ASecretKey : string); overload;
    destructor Destroy; override;
    procedure LoadRequestHeaders(Source : TStringList);

  published
    property AccessKey : string read FAccessKey write FAccessKey;
    property SecretKey : string read FSecretKey write FSecretKey;

    property HTTPMethod : string read FHTTPMethod write FHTTPMethod;
    property APIHostFull : string read FAPIHostFull write FAPIHostFull;
    property Payload : string read FPayload write FPayload;

    property SigningDate : TDateTime read FSigningDate write FSigningDate;
    property AwsRegion : string read FAwsRegion write FAwsRegion;
    property AwsServiceType : TAwsServiceTypes read FAwsServiceType write FAwsServiceType;

    property HashedPayload : string read GetHashedPayload;
    property SignedHeaders : string read GetSignedHeaders;
    property CanonicalRequest : string read GetCanonicalRequest;
    property StringToSign : string read GetStringToSign;
    property SigningKey : string read GetSigningKey;
    property SigningKeyHex : string read GetSigningKeyHex;
    property Signature : string read GetSignature;
    property Credential : string read GetCredential;

    property Authorization : string read GetAuthorization;
  end; // TAwsAuthentication
  {$ENDREGION}


procedure TestSigningKey;

procedure TestCalculateSignature;

implementation

uses
  dialogs,
  encryptutil,
  sysutils;
  
const
  LINEFEED=#10;


{$REGION ' TAwsAuthentication  }
{$REGION ' GetHashedPayload  }
function TAwsAuthentication.GetHashedPayload : string;
begin
  Result:= trim(FPayload);
  if AnsiCompareText(UNSIGNED_PAYLOAD,Result) = 0 then
     EXIT;

  Result:= SHA256Hash(Result);
end; // GetHashedPayload
{$ENDREGION}

{$REGION ' GetSignedHeaders  }
function TAwsAuthentication.GetSignedHeaders : string;
var j : integer;
begin
(*
  SignedHeaders is an alphabetically sorted, semicolon-separated list of
  lowercase request header names. The request headers in the list are the
  same headers that you included in the CanonicalHeaders string.
  For example, for the following canonicalheaders example,

  host:s3.amazonaws.com
  x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  x-amz-date:20130708T220855Z

  the value of SignedHeaders would be as follows:

  host;x-amz-content-sha256;x-amz-date
*)

  Result:= '';

  if not Assigned(FRequestHeaders) then
     EXIT;
  if FRequestHeaders.Count <= 0 then
     EXIT;

  // sort
  FRequestHeaders.Sort;

  for j:= 0 to FRequestHeaders.Count-1 do
    if trim(FRequestHeaders.Names[j]) <> '' then
       Result:= AppendStrIfNotNull(Result, ';')+
                TSL(FRequestHeaders.Names[j]);

end; // GetSignedHeaders
{$ENDREGION}

{$REGION ' GetCanonicalRequest  }
function TAwsAuthentication.GetCanonicalRequest : string;

  {$REGION ' CanonicalURI  }
  function CanonicalURI : string;
  var
    jj : integer;
    TempAbsolutePath : string;
  begin
  (*
    CanonicalURI is the URI-encoded version of the absolute path component
    of the URI —- everything starting with the "/" that follows the domain name
    and up to the end of the string or to the question mark character ('?')
    if you have query string parameters. The URI in the following example,
    /examplebucket/myphoto.jpg, is the absolute path and you don't encode
    the "/" in the absolute path:

    http://s3.amazonaws.com/examplebucket/myphoto.jpg

    If the absolute path is empty, use a forward slash (/), i.e., if nothing follows
    the host in the URI, the absolute path is empty.


    // TODO: this is only for S3. We need to implement the URI encoding twice for non-S3                                                                                
  *)

    try
      Result:= '';

      TempAbsolutePath:= trim(FAPIHostFull);
      if TempAbsolutePath = '' then
         EXIT;

      // remove http / https
      TempAbsolutePath:= trim(StringReplace(TempAbsolutePath,'http://', '',[rfIgnoreCase,rfReplaceAll]));
      TempAbsolutePath:= trim(StringReplace(TempAbsolutePath,'https://','',[rfIgnoreCase,rfReplaceAll]));
      if TempAbsolutePath = '' then
         EXIT;

      // remove query string
      jj:= pos('?',TempAbsolutePath);
      if jj > 0 then
         TempAbsolutePath:= trim(copy(TempAbsolutePath,1,jj-1));
      if TempAbsolutePath = '' then
         EXIT;

      // remove domain
      jj:= pos('/',TempAbsolutePath);
      if jj <= 0 then
         EXIT;
      TempAbsolutePath:= trim(copy(TempAbsolutePath,jj+1));
      if TempAbsolutePath = '' then
         EXIT;

      Result:= trim(EncodeURIComponent(TempAbsolutePath,true));

    finally
      Result:= '/'+Result;
    end;
  end; // CanonicalURI
  {$ENDREGION}

  {$REGION ' CanonicalQueryString  }
  function CanonicalQueryString : string;
  var
    jj : integer;
    TempParamsStr : string;
    TempParamsList : TStringList;
    ParamName : string;
    ParamValue : string;
  begin
  (*
    CanonicalQueryString specifies the URI-encoded query string parameters.
    You URI-encode name and values individually. You must also sort the
    parameters in the canonical query string alphabetically by key name.
    The sorting occurs after encoding.
  *)

    Result:= '';
    TempParamsList:= nil;

    try
      // extract query string from host
      jj:= pos('?',trim(APIHostFull));
      if jj <= 0 then
         EXIT;
      TempParamsStr:= trim(copy(trim(APIHostFull),jj+1));
      if TempParamsStr = '' then
         EXIT;

      // parse query string
      TempParamsList:= TStringList.Create;
      TempParamsList.StrictDelimiter:= true;
      TempParamsList.Delimiter:= '&';
      TempParamsList.DelimitedText:= TempParamsStr;
      if TempParamsList.Count <= 0 then
         EXIT;

      // URI-encode
      {for jj:= 0 to TempParamsList.Count-1 do
        TempParamsList[jj]:= TempParamsList.Names[jj]
                             +'='+
                             TempParamsList.ValueFromIndex[jj];}

      // sort after URI-encoding
      TempParamsList.Sort;

      // form string
      for jj:= 0 to TempParamsList.Count-1 do
        begin
          ParamName:= trim(TempParamsList.Names[jj]);
          ParamValue:= trim(TempParamsList.ValueFromIndex[jj]);

          if ParamName = '' then
             begin
               ParamName:= trim(TempParamsList[jj]);
               ParamValue:= '';
             end;

          Result:= AppendStrIfNotNull(Result,'&')+
                   Format('%s=%s', [ParamName,ParamValue]);

          SessionLogAdd([IntToStr(jj)+' '+ParamName+' '+ParamValue],false,true,false);
        end;

    finally
      if Assigned(TempParamsList) then
         FreeAndNil(TempParamsList);
    end;
  end; // CanonicalQueryString
  {$ENDREGION}

  {$REGION ' CanonicalHeaders  }
  function CanonicalHeaders : string;
  var jj : integer;
  begin
  (*
    CanonicalHeaders is a list of request headers with their values.
    Individual header name and value pairs are separated by the newline character
    ("\n"). Header names must be in lowercase. You must sort the header names
    alphabetically to construct the string, as shown in the following example:

    Lowercase(<HeaderName1>)+":"+Trim(<value>)+"\n"
    Lowercase(<HeaderName2>)+":"+Trim(<value>)+"\n"
    ...
    Lowercase(<HeaderNameN>)+":"+Trim(<value>)+"\n"
  *)

    Result:= '';

    if not Assigned(FRequestHeaders) then
       EXIT;
    if FRequestHeaders.Count <= 0 then
       EXIT;

    // sort
    FRequestHeaders.Sort;

    for jj:= 0 to FRequestHeaders.Count-1 do
      if trim(FRequestHeaders.Names[jj]) <> '' then
         Result:= AppendStrIfNotNull(Result, LINEFEED)+
                  Format('%s:%s',
                    [TSL(FRequestHeaders.Names[jj]),
                     trim(FRequestHeaders.ValueFromIndex[jj])] );
  end; // CanonicalHeaders
  {$ENDREGION}

begin
(*
  Create CanonicalRequest - task 1 in calculating the signature
                            for the authorization header
*)

  Result:= TSU(FHTTPMethod)
             +LINEFEED+
           CanonicalURI
             +LINEFEED+
           CanonicalQueryString
             +LINEFEED+
           CanonicalHeaders
             +LINEFEED+LINEFEED+
           SignedHeaders
             +LINEFEED+
           HashedPayload;

  SessionLogAdd(['CanonicalRequest: ',Result],false,true,false);
end; // GetCanonicalRequest
{$ENDREGION}

{$REGION ' GetStringToSign  }
function TAwsAuthentication.GetStringToSign : string;

  {$REGION ' Scope  }
  function Scope : string;
  const
    SCOPE_DELIMITER = '/';
  begin
  (*
    Create StringToSignScope - part of Create StringToSign task (#2)

    Scope binds the resulting signature to a specific date, an AWS Region,
          and a service. Thus, your resulting signature will work only
          in the specific Region and for a specific service.
          The signature is valid for seven days after the specified date.
  *)

    Result:= FormatDateTime('yyyyMMdd',FSigningDate)
               +SCOPE_DELIMITER+
             TSL(FAwsRegion)
               +SCOPE_DELIMITER+
             TSL(AwsServiceNames[FAwsServiceType])
               +SCOPE_DELIMITER+
             TSL(AWS4_REQUEST);

    //SessionLogAdd(['StringToSignScope: ',Result],false,true,false);
  end; // Scope
  {$ENDREGION}

begin
(*
  Create StringToSign" - task 2 in calculating the signature
                         for the authorization header

  To form the string to sign, we concatenate the following strings,
     using \n as delimiter :
     (1) AWS4-HMAC-SHA256 (literal, specifies the hash algorithm used)
     (2) Time stamp in ISO8601 format (e.g., 20210114T051800Z)
     (3) Scope (see GetStringToSignScope function)
     (4) Hex of the SHA256 of the canonical request (from task 1)
*)

  Result:= AWS4_HMAC_SHA256
             +LINEFEED+
           GiveUTCDateTimeISO8601NoSymbols(FSigningDate)
             +LINEFEED+
           Scope()
             +LINEFEED+
           SHA256Hash(Self.CanonicalRequest);
end; // GetStringToSign
{$ENDREGION}

{$REGION ' GetSigningKey  }
function TAwsAuthentication.GetSigningKey : string;
begin
(*
  Create SigningKey - task 3 in calculating the signature
                      for the authorization header

  Pseudocode
    kSecret = secret access key
    kDate = HMAC("AWS4" + kSecret, Date)
    kRegion = HMAC(kDate, Region)
    kService = HMAC(kRegion, Service)
    kSigning = HMAC(kService, "aws4_request")

    Finally, return hex of kSigning
*)

  // SecretKey
  Result:= TSU(AWS4) + FSecretKey;

  // DateKey
  Result:= HMAC_SHA256(Result, FormatDateTime('yyyyMMdd',FSigningDate));

  // DateRegionKey
  Result:= HMAC_SHA256(Result, TSL(FAwsRegion));

  // DateRegionServiceKey
  Result:= HMAC_SHA256(Result, TSL(AwsServiceNames[FAwsServiceType]));

  // SigningKey
  Result:= HMAC_SHA256(Result, TSL(AWS4_REQUEST));
end; // GetSigningKey

function TAwsAuthentication.GetSigningKeyHex : string;
begin
  // only for testing/verification purposes
  
  // SecretKey
  Result:= TSU(AWS4) + FSecretKey;

  // DateKey
  Result:= HMAC_SHA256(Result, FormatDateTime('yyyyMMdd',FSigningDate));

  // DateRegionKey
  Result:= HMAC_SHA256(Result, TSL(FAwsRegion));

  // DateRegionServiceKey
  Result:= HMAC_SHA256(Result, TSL(AwsServiceNames[FAwsServiceType]));

  // SigningKey
  Result:= HMAC_SHA256Hex(Result, TSL(AWS4_REQUEST));
end; // GetSigningKeyHex
{$ENDREGION}

{$REGION ' GetSignature  }
function TAwsAuthentication.GetSignature : string;
begin
(*
  Calculate Signature

  Use the SigningKey and StringToSign as inputs to the keyed hash function

  THREE steps involved
  (1) Create CanonicalRequest
  (2) Create StringToSign
  (3) Create SigningKey
*)

  Result:= HMAC_SHA256Hex(SigningKey,StringToSign);
end; // GetSignature
{$ENDREGION}

{$REGION ' GetCredential  }
function TAwsAuthentication.GetCredential : string;
begin
  Result:= FAccessKey
             +'/'+
           FormatDateTime('yyyyMMdd',FSigningDate)
             +'/'+
           FAwsRegion
             +'/'+
           TSL(AwsServiceNames[FAwsServiceType])
             +'/'+
           TSL(AWS4_REQUEST);
end; // Credential
{$ENDREGION}

{$REGION ' GetAuthorization  }
function TAwsAuthentication.GetAuthorization : string;
begin

  Result:= AWS4_HMAC_SHA256
             +' '+
           'Credential='+Credential
             +','+
           'SignedHeaders='+SignedHeaders
             +','+
           'Signature='+Signature;
end; // GetAuthorization
{$ENDREGION}

{$REGION ' Create  }
constructor TAwsAuthentication.Create;
begin
  inherited Create;

  FAccessKey:= '';
  FSecretKey:= '';

  // used to build the canonical request for the Authorization header
  FHTTPMethod:= '';
  FAPIHostFull:= '';
  FRequestHeaders:= TStringList.Create;
  FPayload:= UNSIGNED_PAYLOAD;

  // used to build the string to sign scope
  FAwsRegion:= '';
  FSigningDate:= Now;
  FAwsServiceType:= astUnknown;
end; // Create

constructor TAwsAuthentication.Create(AAccessKey,ASecretKey : string);
begin
  Create;

  FAccessKey:= trim(AAccessKey);
  FSecretKey:= trim(ASecretKey);
end; // Create
{$ENDREGION}

{$REGION ' Destroy  }
destructor TAwsAuthentication.Destroy;
begin
  if Assigned(FRequestHeaders) then
     FreeAndNil(FRequestHeaders);

  inherited Destroy;
end; // Destroy
{$ENDREGION}

{$REGION ' LoadRequestHeaders  }
procedure TAwsAuthentication.LoadRequestHeaders(Source : TStringList);
begin
  FRequestHeaders.Clear;

  if not Assigned(Source) then
     EXIT;

  FRequestHeaders.Assign(Source);
end; // LoadHeaders
{$ENDREGION}
{$ENDREGION}

{$REGION ' TestSigningKey  }
procedure TestSigningKey;
const EXPECTED_SIGNING_KEY = 'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9';
var AwsAuthObj : TAwsAuthentication;
begin
  AwsAuthObj:= nil;
  try
    with AwsAuthObj do
      begin
        AwsAuthObj:= TAwsAuthentication.Create('','wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY');

        SigningDate:= EncodeDate(2015,8,30);
        AwsRegion:= 'us-west-1';
        AwsServiceType:= astIAM;

        showmessage(
          Format('Signing keys%s match',
            [IFString(AnsiCompareText(EXPECTED_SIGNING_KEY, SigningKeyHex) <> 0, ' don''t') ]));
      end;
  finally
    if Assigned(AwsAuthObj) then
       FreeAndNil(AwsAuthObj);
  end;
end; // TestSigningKey
{$ENDREGION}

{$REGION ' TestCalculateSignature  }
procedure TestCalculateSignature;
var
  AwsAuthObj : TAwsAuthentication;
  RqstHdrs : TStringList;
begin
  AwsAuthObj:= nil;
  RqstHdrs:= nil;

  try
    with AwsAuthObj do
      begin
        AwsAuthObj:= TAwsAuthentication.Create(
                   'AKIAIOSFODNN7EXAMPLE',
                   'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

        HTTPMethod:= 'GET';
        APIHostFull:= 'https://examplebucket.s3.amazonaws.com/test.txt';

        RqstHdrs:= TStringList.Create;
        RqstHdrs.Add(GiveRequestHeader(arhtHost,'examplebucket.s3.amazonaws.com'));
        RqstHdrs.Add(GiveRequestHeader(arhtContentSHA256,SHA256Hash('')));
        RqstHdrs.Add(GiveRequestHeader(arhtDate,GiveUTCDateTimeISO8601NoSymbols(SigningDate)));
        RqstHdrs.Add('Range=bytes=0-9');
        LoadRequestHeaders(RqstHdrs);

        Payload:= '';
        SigningDate:= EncodeDate(2013,5,24);
        AwsRegion:= 'us-west-1';
        AwsServiceType:= astS3;

        showmessage(Authorization);
      end;

  finally
    if Assigned(AwsAuthObj) then
       FreeAndNil(AwsAuthObj);
    if Assigned(RqstHdrs) then
       FreeAndNil(RqstHdrs);
  end;
end; // TestCalculateSignature
{$ENDREGION}

begin
end.
