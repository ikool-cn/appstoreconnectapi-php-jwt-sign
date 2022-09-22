#  App Store Connect API JWT ES256  Signature For PHP

### Usage
```php
require './ECSign.php';

$key = <<<EOF
-----BEGIN PRIVATE KEY-----
YOUR p8 KEY File Content
-----END PRIVATE KEY-----
EOF;

$header = [
    'alg' => 'ES256',
    'kid' => '<Your Kid>',
    'typ' => 'JWT',
];

$payload = [
    'iss' => '<YOUR Issuer ID>',
    'exp' => time() + 600,
    'aud' => 'appstoreconnect-v1'
];

$token =  ECSign::sign($payload, $header, $key);
echo $token;
```


### Run Test
```shell
curl -v -H 'Authorization: Bearer <YOUR TOKEN>' "https://api.appstoreconnect.apple.com/v1/apps"
```
