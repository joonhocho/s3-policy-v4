/**
 * S3Policy
 */

const CryptoJS = require('crypto-js');
const Buffer = global.Buffer || require('buffer').Buffer;

const assert = (object, message) => {
  if (object == null) throw new Error(message);
};

const FIVE_MINUTES = 5 * 60 * 1000;

const AWS_ACL = 'public-read';
const AWS_SERVICE_NAME = 's3';
const AWS_REQUEST_POLICY_VERSION = 'aws4_request';
const AWS_ALGORITHM = 'AWS4-HMAC-SHA256';

const DEFAULT_SUCCESS_ACTION_STATUS = '201';


const getDate = () => {
  const date = new Date();
  const yymmdd = date.toISOString().slice(0, 10).replace(/-/g, '');
  const amzDate = `${yymmdd}T000000Z`;
  return {yymmdd, amzDate};
};


/*
 * Expires in 5 minutes. Amazon will reject request
 * if it arrives after the expiration date.
 *
 * returns string in ISO8601 GMT format, i.e.
 *
 *     2016-03-24T20:43:47.314Z
 */
const getExpirationDate = () => new Date(Date.now() + FIVE_MINUTES).toISOString();


const getPolicyParams = (options) => {
  const date = getDate();
  const expiration = getExpirationDate();

  return {
    acl: AWS_ACL,
    algorithm: AWS_ALGORITHM,
    bucket: options.bucket,
    contentType: options.contentType,
    credential: `${options.accessKey}/${date.yymmdd}/${options.region}/${AWS_SERVICE_NAME}/${AWS_REQUEST_POLICY_VERSION}`,
    date,
    expiration,
    key: options.key,
    region: options.region,
    secretKey: options.secretKey,
    successActionStatus: String(options.successActionStatus || DEFAULT_SUCCESS_ACTION_STATUS),
    metadata: (options.metadata || {})
  };
};


const formatPolicyForEncoding = (policy) => {
  let policyForEncoding = {
    expiration: policy.expiration,
    conditions: [
     {bucket: policy.bucket},
     {key: policy.key},
     {acl: policy.acl},
     {success_action_status: policy.successActionStatus},
     {'Content-Type': policy.contentType},
     {'x-amz-credential': policy.credential},
     {'x-amz-algorithm': policy.algorithm},
     {'x-amz-date': policy.date.amzDate},
    ],
  };

  Object.keys(policy.metadata).forEach((k) => {
    let metadata = String(policy.metadata[k])
    policyForEncoding.conditions.push({[k]: metadata});
  });

  return policyForEncoding;
};


const getEncodedPolicy = (policy) =>
  new Buffer(JSON.stringify(policy), 'utf-8').toString('base64');


const getSignatureKey = (options) => {
  const kDate = CryptoJS.HmacSHA256(options.date.yymmdd, `AWS4${options.secretKey}`);
  const kRegion = CryptoJS.HmacSHA256(options.region, kDate);
  const kService = CryptoJS.HmacSHA256(AWS_SERVICE_NAME, kRegion);
  const kSigning = CryptoJS.HmacSHA256(AWS_REQUEST_POLICY_VERSION, kService);

  return kSigning;
};


const getSignature = (base64EncodedPolicy, options) =>
  CryptoJS.HmacSHA256(
    base64EncodedPolicy,
    getSignatureKey(options)
  ).toString(CryptoJS.enc.Hex);


const formatPolicyForRequestBody = (base64EncodedPolicy, signature, options) => ({
  key: options.key,
  acl: options.acl,
  success_action_status: options.successActionStatus,
  'Content-Type': options.contentType,
  'X-Amz-Credential': options.credential,
  'X-Amz-Algorithm': options.algorithm,
  'X-Amz-Date': options.date.amzDate,
  Policy: base64EncodedPolicy,
  'X-Amz-Signature': signature,
});


export class S3Policy {
  static generate(options) {
    assert(options, 'Must provide options');
    assert(options.key, 'Must provide `key` option with the object key');
    assert(options.bucket, 'Must provide `bucket` option with your AWS bucket name');
    assert(options.contentType, 'Must provide `contentType` option with the object content type');
    assert(options.region, 'Must provide `region` option with your AWS region');
    assert(options.accessKey, 'Must provide `accessKey` option with your AWSAccessKeyId');
    assert(options.secretKey, 'Must provide `secretKey` option with your AWSSecretKey');

    const policyParams = getPolicyParams(options);
    const policy = formatPolicyForEncoding(policyParams);
    const base64EncodedPolicy = getEncodedPolicy(policy);
    const signature = getSignature(base64EncodedPolicy, policyParams);

    return formatPolicyForRequestBody(base64EncodedPolicy, signature, policyParams);
  }
}

export default S3Policy;
