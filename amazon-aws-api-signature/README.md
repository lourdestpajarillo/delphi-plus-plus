# amazon-aws-api-signature

I've recently had to build a project that involves accessing and storing objects to an Amazon AWS S3 Bucket. We are slowly transitioning our "old" application to be fully cloud-based. Our servers are already running in Amazon EC2 servers but the need to fully utilize AWS services came up. We wanted to be able to store all our file-based images and attachments to an AWS S3 bucket and access them live from there whenever our application needs to display any of them. This includes both images and document files, e.g., doc, xls, and pdf.

Thus, we needed to make our application "communicate" with Amazon AWS via APIs. A common hurdle I find whenever I need to implement this kind of interaction is the lack of SDKs because, well, Delphi 2006, is a bit old. Although recent version of Delphi like XE7 already have built-in objects for this, we wanted to build our own, especially that Amazon frequently updates its signature implementation.

The snippets in this collection are the building blocks for producing the AWS4-HMAC-SHA256 Signature. Details of implmentation mandated by Amazon can be found here: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
