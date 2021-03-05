unit cawsglobal;

interface

type
  TAwsServiceTypes =
    ( astUnknown,
      astS3,
      astIAM );

  {$REGION ' TAwsRequestHeaderTypes  }
  { AWS request header types }
  TAwsRequestHeaderTypes =
    ( arhtUnknown,
      arhtCustom,
      arhtHost,

      arhtContentEncoding,
      arhtContentType,
      arhtContentLength,
      arhtContentMD5,

      arhtContentSHA256,
      arhtDate,
      arhtAcl,
      arhtGrantFullControl,
      arhtGrantRead,
      arhtGrantReadACP,
      arhtGrantWrite,
      arhtGrantWriteACP,
      arhtBucketObjectLockEnabled,
      arhtMetaAuthor );
  {$ENDREGION}

  {$REGION ' TAwsRequestParamTypes  }
  TAwsRequestParamTypes =
    ( arptUnknown,
      arptCustom,

      arptContinuationToken,
      arptDelimiter,
      arptEncodingType,
      arptFetchOwner,
      arptMaxKeys,
      arptPrefix,
      arptStartAfter,

      arptAlgorithm,
      arptCredential,
      arptDate,
      arptExpires,
      arptSignedHeaders,
      arptSignature );
  {$ENDREGION}

const
  AWS4 = 'AWS4';
  AWS4_REQUEST = 'aws4_request';
  AWS4_HMAC_SHA256 = 'AWS4-HMAC-SHA256';
  UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';
  AWS_MOD2_REGION = 'us-west-1';

  AwsServiceNames : array[TAwsServiceTypes] of string
    = ('','s3','iam');

  {$REGION ' AwsRequestHeaderName  }
  AwsRequestHeaderName : array[TAwsRequestHeaderTypes] of string
    = ( '',
        'custom',
        'Host',

        'Content-Encoding',
        'Content-Type',
        'Content-Length',
        'Content-MD5',

        'x-amz-content-sha256',
        'x-amz-date',
        'x-amz-acl',
        'x-amz-grant-full-control',
        'x-amz-grant-read',
        'x-amz-grant-read-acp',
        'x-amz-grant-write',
        'x-amz-grant-write-acp',
        'x-amz-bucket-object-lock-enabled',
        'x-amz-meta-author'
      );
  {$ENDREGION}

  {$REGION ' TAwsRequestParamTypes  }
  AwsRequestParamName : array[TAwsRequestParamTypes] of string
    = ( '',
        'custom',

        'continuation-token',
        'delimiter',
        'encoding-type',
        'fetch-owner',
        'max-keys',
        'prefix',
        'start-after',

        'X-Amz-Algorithm',
        'X-Amz-Credential',
        'X-Amz-Date',
        'X-Amz-Expires',
        'X-Amz-SignedHeaders',
        'X-Amz-Signature' );
  {$ENDREGION}

  
function GiveRequestHeader(ThisType : TAwsRequestHeaderTypes; ThisValue : string) : string; overload;
{ returns the request header for the given type and value in <ThisTypeName>=<ThisValue> format
  where ThisTypeName is derived from AwsRequestHeaderName[ThisType] }

function GiveRequestHeader(ThisName,ThisValue : string) : string; overload;
{ returns the request header for the given type and value in <ThisName>=<ThisValue> format }

function GiveRequestParam(ThisType : TAwsRequestParamTypes; ThisValue : string) : string; overload;
{ returns the request parameter for the given type and value in <ThisTypeName>=<ThisValue> format
  where ThisTypeName is derived from AwsRequestParamName[ThisType] }

function GiveRequestParam(ThisName,ThisValue : string) : string; overload;
{ returns the request header for the given type and value in <ThisName>=<ThisValue> format }


implementation

uses
  sysutils;

{$REGION ' GiveRequestHeader  }
function GiveRequestHeader(ThisType : TAwsRequestHeaderTypes; ThisValue : string) : string;
begin
  Result:= GiveRequestHeader(AwsRequestHeaderName[ThisType],ThisValue);
end; // GiveRequestHeader(type)

function GiveRequestHeader(ThisName,ThisValue : string) : string;
begin
  Result:= trim(ThisName) + '=' + trim(ThisValue);
end; // GiveRequestHeader(name)
{$ENDREGION}

{$REGION ' GiveRequestParam  }
function GiveRequestParam(ThisType : TAwsRequestParamTypes; ThisValue : string) : string;
begin
  Result:= GiveRequestParam(AwsRequestParamName[ThisType],ThisValue);
end; // GiveRequestParam

function GiveRequestParam(ThisName,ThisValue : string) : string;
begin
  Result:= trim(ThisName) + '=' + trim(ThisValue);
end; // GiveRequestParam
{$ENDREGION}

end.
