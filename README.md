# s3-policy-v4
Amazon AWS S3 Policy Generator with Signature Version 4

Thanks to https://github.com/benjreinhart/react-native-aws3

### Install
```
npm install --save s3-policy-v4
```


### Usage
```javascript
import S3Policy from 's3-policy-v4';

```javascript
const policy = S3Policy.generate({
  key: 'S3_OBJECT_KEY',
  bucket: 'S3_BUCKET_NAME',
  contentType: 'OBJECT_CONTENT_TYPE',
  region: 'S3_BUCKET_REGION',
  accessKey: 'S3_ACCESS_KEY',
  secretKey: 'S3_SECRET_KEY',
  acl: 'ACL',                                  // e.g. 'public-read'
  conditions: [                                // all the fiddly conditions to
    ['content-length-range', 0, 1048579],      // your heart's desire!
    ['starts-with', '$Content-Type', 'image/'],
    {bucket: 'mr-bucket'}
  ]
});
```

### TODO


### Dependencies
 - Encoding Base64: https://github.com/feross/buffer
 - Encrypting Policy: https://github.com/brix/crypto-js


### License
```
The MIT License (MIT)

Copyright (c) 2016 Joon Ho Cho

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
