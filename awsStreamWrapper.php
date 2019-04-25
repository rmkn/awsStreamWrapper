<?php
// vim: set et ts=4 sw=4 sts=4:

/*

利用方法
    stream_wrapper_register("aws", "AwsStreamWrapper");
    $opts = array('aws' => array(...), 'http' => array(...));
    $context = stream_context_create($opts);
    $url = 'aws://route53.amazonaws.com/2012-12-12/hostedzone';
    $res = file_get_contents($url, false, $context);

awsコンテキストオプション
    accesskey string
    secretkey string
    region string
        デフォルト us-east-1
    version int
        2, 3, 4
        デフォルト 4
    format string
        xml, json, array
        デフォルト xml

*/

class AwsStreamWrapper
{
    // resource
    public $context;

    private $path;
    private $buf;
    private $pt;

    /**
     * @return void
     */
    public function __construct()
    {
        $this->path = null;
        $this->buf  = null;
        $this->pt   = null;
    }

    /**
     * @return void
     */
    public function __destruct()
    {
    }

    /**
     * @return void
     */
    public function stream_close()
    {
    }

    /**
     * @return bool
     */
    public function stream_eof()
    {
        return strlen($this->buf) == $this->pt;
    }

    /**
     * @return bool
     */
    public function stream_flush()
    {
        return true;
    }

    /**
     * @param string $path
     * @param string $mode
     * @param int    $options
     * @param string &$opened_path
     *
     * @return bool
     */
    public function stream_open($path, $mode, $options, &$opened_path)
    {
        $this->path = preg_replace('/^aws/', 'https', $path);
        $this->buf  = null;
        $this->pt   = null;
        return true;
    }

    /**
     * @param int $count
     *
     * @return string
     */
    public function stream_read($count)
    {
        if ($this->buf === null) {
            $opt = stream_context_get_options($this->context);
            $this->buf = null;
            if (isset($opt['aws']['accesskey']) && isset($opt['aws']['secretkey'])) {
                $awsapi = new AwsApi($opt['aws']['accesskey'], $opt['aws']['secretkey']);
                if (isset($opt['aws']['version'])) {
                    $awsapi->setSignatureVersion($opt['aws']['version']);
                }
                if (isset($opt['aws']['region'])) {
                    $awsapi->setRegion($opt['aws']['region']);
                }
                if (isset($opt['aws']['cloud'])) {
                    $awsapi->setCloud($opt['aws']['cloud']);
                }
                $this->buf = $awsapi->call($this->path, $opt);
                if (isset($opt['aws']['format'])) {
                    switch ($opt['aws']['format']) {
                    case 'json':
                        $this->buf = $awsapi->asJson();
                        break;
                    case 'array':
                        $this->buf = serialize($awsapi->asArray());
                        break;
                    }
                }
            }
            $this->pt = 0;
        }
        $res = substr($this->buf, $this->pt, $count);
        $this->pt += strlen($res);
        return $res;
    }

    /**
     * @return array
     */
    public function stream_stat()
    {
        return array();
    }

}

class AwsApi
{
    const SIGNATURE_V2 = 'V2';
    const SIGNATURE_V3 = 'V3';
    const SIGNATURE_V4 = 'V4';

    private $signatureVer = self::SIGNATURE_V4;

    private $cloud = 'aws';

    private $accessKey;
    private $secretKey;

    private $region = 'us-east-1';
    private $service;
    private $credentialScope;
    private $signedHeaders;

    private $requestDate;
    private $res;
    private $url;
    private $option;
    private $headers;


    public function __construct($accessKey, $secretAccessKey)
    {
        $this->accessKey   = $accessKey;
        $this->secretKey   = $secretAccessKey;
        $this->requestDate = time();

        $this->service         = null;
        $this->credentialScope = null;
        $this->signedHeaders   = null;
        $this->res             = null;
        $this->url             = null;
        $this->option          = null;
        $this->headers         = array();
    }

    public function setCloud($cloud)
    {
        $this->cloud = strtolower($cloud);
    }

    public function setRegion($region)
    {
        $this->region = $region;
    }

    public function setSignatureVersion($version)
    {
        $def = array(
            2 => self::SIGNATURE_V2,
            3 => self::SIGNATURE_V3,
            4 => self::SIGNATURE_V4,
        );
        $this->signatureVer = isset($def[$version]) ? $def[$version] : self::SIGNATURE_V4;
    }

    function headerToArray($option)
    {
        if (isset($option['http']['header'])) {
            $header = array();
            if (is_array($option['http']['header'])) {
                foreach ($option['http']['header'] as $k => $v) {
                    if (is_numeric($k)) {
                        $b = explode(':', $v, 2);
                        if (count($b) == 2) {
                            $header[$b[0]] = trim($b[1]);
                        }
                    } else {
                        $header[$k] = $v;
                    }
                }
            } else {
                foreach (explode("\n", $option['http']['header']) as $l) {
                    $b = explode(':', $l, 2);
                    if (count($b) == 2) {
                        $header[$b[0]] = trim($b[1]);
                    }
                }
            }
            $option['http']['header'] = $header;
        }
        return $option;
    }

    public function call($url, $option = array())
    {
        $this->url    = $url;
        $this->option = $this->headerToArray($option);
        switch ($this->signatureVer) {
        case self::SIGNATURE_V2:
            $this->setAuthHeaderV2();
            break;
        case self::SIGNATURE_V3:        // route53.amazonaws.com/2012-12-12
            $this->setAuthHeaderV3();
            break;
        case self::SIGNATURE_V4:        // cloudfront.amazonaws.com/2013-05-12
        default:
            $this->setAuthHeaderV4();
        }

        $method = isset($this->option['http']['method']) ? strtoupper($this->option['http']['method']) : 'GET';
        switch ($method) {
        case 'POST':
        case 'PUT':
            $buf = array(
                'Content-Length' => strlen($this->option['http']['content']),
                'Content-Type'   => 'application/x-www-form-urlencoded',
            );
            $this->headers += $buf;
        }

        if (!empty($this->headers)) {
            $buf = array();
            foreach ($this->headers as $k => $v) {
                $buf[] = "{$k}: {$v}";
            }
            $this->option['http']['header'] = implode("\r\n", $buf);
        }

        $this->option['http']['ignore_errors'] = true;
        $context = stream_context_create($this->option);
        $this->res = @file_get_contents($this->url, false, $context);
//var_dump(__FUNCTION__, $this->url, $this->option, $http_response_header);
        return $this->res;
    }

    private function setAuthHeaderV2()
    {
        $url = parse_url($this->url);
        $qs  = sprintf('AccessKeyId=%s&Timestamp=%s&SignatureVersion=2&SignatureMethod=HmacSHA256',
                    $this->accessKey,
                    urlencode(gmdate('Y-m-d\TH:i:s\Z', $this->requestDate))
               );
        $ss = implode("\n", array(
            empty($this->option['method']) ? 'GET' : $this->option['method'],
            $url['host'],
            $url['path'],
            $this->createCanonicalQueryString("{$url['query']}&{$qs}"),
        ));
        $signature = base64_encode(hash_hmac('sha256', $ss, $this->secretKey, true));
        $this->url .= "&{$qs}&Signature=" . urlencode($signature);
    }

    private function setAuthHeaderV3()
    {
        $fmt = 'D, d M Y H:i:s T';
        $this->setRequestHeaders($fmt);
        $ss = gmdate($fmt, $this->requestDate);
        $signature = base64_encode(hash_hmac('sha256', $ss, $this->secretKey, true));
        $key = sprintf('X-%s-Authorization',
            $this->getAuthHeaderStr()
        );
        $auth = sprintf('%s3-HTTPS %sAccessKeyId=%s,Algorithm=HmacSHA256,Signature=%s',
            strtoupper($this->cloud),
            strtoupper($this->cloud),
            $this->accessKey,
            $signature
        );
        $this->headers[$key] = $auth;
    }

    private function getAuthHeaderStr()
    {
        switch ($this->cloud) {
        case 'aws':
            return 'Amzn';
        default:
            return ucfirst($this->cloud);
        }
    }

    private function setAuthHeaderV4()
    {
        $this->setRequestHeaders('Ymd\THis\Z');
        $cr = $this->createCanonicalRequest();
        $ss = $this->createStringToSign($cr);
        $sg = $this->calclulateSignature();
        $signature = hash_hmac('sha256', $ss, $sg, false);
        $auth = sprintf('%s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            strtoupper($this->cloud),
            $this->accessKey,
            $this->credentialScope,
            $this->signedHeaders,
            $signature
        );
        $this->headers['Authorization'] = $auth;
    }

    private function setRequestHeaders($dateType = 'r')
    {
        $host = parse_url($this->url,  PHP_URL_HOST);
        $buf  = explode('.', $host);
        $this->service = $buf[0];

        $this->headers = array();
        if (isset($this->option['http']['header'])) {
            foreach ($this->option['http']['header'] as $k => $v) {
                if (strcasecmp($k, 'host') !== 0) {
                    $this->headers[$k] = $v;
                }
            }
        }
        $this->headers['Host'] = $host;
        $key = sprintf('X-%s-Date', $this->getDateHeaderStr());
        $this->headers[$key] = gmdate($dateType, $this->requestDate);
        $this->option['http']['header'] = $this->headers;
//var_dump(__FUNCTION__, $this->option);
    }

    private function getDateHeaderStr()
    {
        switch ($this->cloud) {
        case 'aws':
            return 'Amz';
        default:
            return ucfirst($this->cloud);
        }
    }

    /**
     * Task 1: Create a Canonical Request For Signature Version 4
     * http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
     */
    private function createCanonicalRequest()
    {
        $url = array_merge(
            array(
                'query' => '',
            ),
            parse_url($this->url)
        );
        $option = array_merge(
            array(
                'method' => 'GET',
                'content' => '',
            ),
            (array)$this->option['http']
        );

        $this->setCredentialScope();

        $res = array(
            $option['method'],
            $url['path'],
            $this->createCanonicalQueryString($url['query']),
            $this->createCanonicalHeaders(),
            $this->signedHeaders,
            hash('sha256', $option['content'], false),
        );
//var_dump(__FUNCTION__, implode("\n", $res), $option);
        return implode("\n", $res);
    }

    private function setCredentialScope()
    {
        $this->credentialScope = sprintf('%s/%s/%s/%s4_request',
            gmdate('Ymd', $this->requestDate),
            $this->region,
            $this->service,
            strtolower($this->cloud)
        );
//var_dump(__FUNCTION__, $this->credentialScope);
    }

    private function createCanonicalQueryString($query)
    {
        $res = explode('&', $query);
        sort($res);
//var_dump(__FUNCTION__, $res);
        return implode('&', $res);
    }

    private function createCanonicalHeaders()
    {
        $res = array();
        $sh  = array();
        foreach ($this->headers as $k => $v) {
            $vv = preg_replace(array('/^\s*/', '/\s{2,}/', '/\s*$/'), array('', ' ', ''), $v);
            $res[] = strtolower($k) . ':' . $vv;
            $sh[]  = strtolower($k);
        }
        sort($res);
        sort($sh);

        $this->signedHeaders = implode(';', $sh);
//var_dump(__FUNCTION__, $res);
        return implode("\n", $res) . "\n";
    }

    /**
     * Task 2: Create a String to Sign for Signature Version 4
     * http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
     */
    private function createStringToSign($s)
    {
        $res = array(
            strtoupper($this->cloud) . '4-HMAC-SHA256',
            gmdate('Ymd\THis\Z', $this->requestDate),
            $this->credentialScope,
            hash('sha256', $s, false),
        );
//var_dump(__FUNCTION__, implode("\n", $res));
        return implode("\n", $res);
    }

    /**
     * Task 3: Calculate the AWS Signature Version 4
     * http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
     */
    private function calclulateSignature()
    {
        $kSecret  = $this->secretKey;
        $kDate    = hash_hmac('sha256', gmdate('Ymd', $this->requestDate), strtoupper($this->cloud) . "4{$kSecret}", true);
        $kRegion  = hash_hmac('sha256', $this->region,  $kDate, true);
        $kService = hash_hmac('sha256', $this->service, $kRegion, true);
        $kSigning = hash_hmac('sha256', strtolower($this->cloud) . '4_request',  $kService, true);
//var_dump(__FUNCTION__, strtoupper($this->cloud) . "4{$kSecret}", $this->region, $this->service, strtolower($this->cloud) . '4_request');
        return $kSigning;
    }

    public function asSimpleXml()
    {
        $sx = @simplexml_load_string($this->res, 'SX');
        return $sx !== false ? $sx : false;
    }

    public function asArray()
    {
        $sx = $this->asSimpleXml();
        return $sx !== false ? $sx->asArray() : false;
    }

    public function asJson()
    {
        $sx = $this->asSimpleXml();
        return $sx !== false ? $sx->asJson() : false;
    }
}

class SX extends SimpleXMLElement
{
    public function asJson()
    {
        return json_encode($this);
    }

    public function asArray()
    {
        return json_decode($this->asJson(), true);
    }
}
