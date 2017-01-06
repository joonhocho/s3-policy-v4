/**
 * S3Policy
 */

const CryptoJS = require('crypto-js');
const Buffer = global.Buffer || require('buffer').Buffer;

const validate = (object, test, message) => {
  if (!test(object)) throw new Error(message);
};
const isNonNullString = (v) => typeof v === 'string' && v !== null;
const isLengthyList = (v) => typeof v === 'object' && v !== null && v.length !== undefined;
const isNonZeroNumber = (v) => typeof v === 'number' && v > 0;
const isThreeDigitString = (v) => typeof v === 'string' && v.match(/[0-9]{3}/);

const FIVE_MINUTES = 5 * 60;

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
const getExpirationDate = (secs) => new Date(Date.now() + secs * 1000).toISOString();

const encodeConditions = (conditions) => {
  return conditions.map((c) => {
    const keys = Object.keys(c);
    if (keys.length === 1) {
      return { [keys[0]]: `${c[keys[0]]}` };
    } else {
      return keys.map((k) => `${c[keys[k]]}`);
    }
  });
}

const formatPolicyForEncoding = (options) => ({
  expiration: options.expiration,
  conditions: [
    {bucket: options.bucket},
    {key: options.key},
    {acl: options.acl},
    {success_action_status: options.successActionStatus},
    {'x-amz-credential': options.credential},
    {'x-amz-algorithm': options.algorithm},
    {'x-amz-date': options.date.amzDate},
    ...encodeConditions(options.conditions)
  ],
});


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
static generate({
  // required:
  bucket = null,
  key = null,
  region = null,
  accessKey = null,
  secretKey = null,
  // optional:
  acl = AWS_ACL,
  conditions = {},
  expirationSec = FIVE_MINUTES,
  successActionStatus = DEFAULT_SUCCESS_ACTION_STATUS
} = {}) {
    validate(bucket, isNonNullString, 'Must provide `bucket` option with your AWS bucket name');
    validate(key, isNonNullString, 'Must provide `key` option with the object key');
    validate(region, isNonNullString, 'Must provide `region` option with your AWS region');
    validate(accessKey, isNonNullString, 'Must provide `accessKey` option with your AWSAccessKeyId');
    validate(secretKey, isNonNullString, 'Must provide `secretKey` option with your AWSSecretKey');
    validate(acl, isNonNullString, 'Must provide `acl` as string value');
    validate(conditions, isLengthyList, 'Conditions must be a list');
    validate(expirationSec, isNonZeroNumber, 'Expiration seconds must be > 0');
    validate(successActionStatus, isThreeDigitString, 'successActionStatus seconds must be > 0');

    const date = getDate();

    const options = {
      // from parameters
      region,
      accessKey,
      secretKey,
      acl,
      conditions,
      successActionStatus,
      // calculated options
      algorithm: AWS_ALGORITHM,
      credential: `${accessKey}/${date.yymmdd}/${region}/${AWS_SERVICE_NAME}/${AWS_REQUEST_POLICY_VERSION}`,
      date,
      expiration: getExpirationDate(expirationSec)
    };

    const policy = formatPolicyForEncoding(options);
    const base64EncodedPolicy = getEncodedPolicy(policy);
    const signature = getSignature(base64EncodedPolicy, options);

    return formatPolicyForRequestBody(base64EncodedPolicy, signature, options);
  }
}

export default S3Policy;
