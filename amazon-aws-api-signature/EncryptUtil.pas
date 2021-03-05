unit EncryptUtil;

interface

function SHA256Hash(ThisString : string) : string;
{ Secure Hash Algorithm cryptographic hash function
  returns the hex version hashed string }

function HMAC_SHA256(SigningKey,StringToSign : string) : string;
{ computes HMAC by using the SHA256 algorithm with the signing key provided
             : returns the signed string }

function HMAC_SHA256Hex(SigningKey,StringToSign : string) : string;
{ computes HMAC by using the SHA256 algorithm with the signing key provided
  returns the hex version of the signed string }


implementation

uses
  chash;

function SHA256Hash(ThisString : string) : string;
begin

  Result:= SHA256DigestToHex(CalcSHA256(ThisString));

end; // SHA256Hash

function HMAC_SHA256(SigningKey,StringToSign : string) : string;
begin

  Result:= SHA256DigestAsString(CalcHMAC_SHA256(SigningKey,StringToSign));

end; // HMAC_SHA256

function HMAC_SHA256Hex(SigningKey,StringToSign : string) : string;
begin

  Result:= SHA256DigestToHex(CalcHMAC_SHA256(SigningKey,StringToSign));

end; // HMAC_SHA256Hex


begin

end.
