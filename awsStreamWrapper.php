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

    public function debug($s)
    {
        var_dump($s);
    }

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

    private $accessKey;
    private $secretKey;

    private $region = 'us-east-1';
    private $service;
    private $credentialScope;
    private $signedHeaders;

    private $_requestDate;
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

    public function setRegion($region)
    {
        $this->region = $region;
        $this->setCredentialScope();
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

    public function call($url, $option = array())
    {
        $this->url    = $url;
        $this->option = $option;
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
        if (!empty($this->headers)) {
            $this->option['http']['header'] = implode("\r\n", $this->headers);
        }
        $this->option['http']['ignore_errors'] = true;
        $context = stream_context_create($this->option);
        $this->res = @file_get_contents($this->url, false, $context);
        return $this->res;
    }

    private function setAuthHeaderV2()
    {
        $url = parse_url($this->url);
        $ss = implode("\n", array(
            empty($this->option['method']) ? 'GET' : $this->option['method'],
            $url['host'],
            $url['path'],
            $this->createCanonicalQueryString($url['query']),
        ));
        $signature = base64_encode(hash_hmac('sha256', $ss, $this->secretKey, true));
        $this->url .= "&Signature=" . urlencode($signature);
    }

    private function setAuthHeaderV3()
    {
        $fmt = 'D, d M Y H:i:s T';
        $this->setRequestHeaders($fmt);
        $ss = gmdate($fmt, $this->requestDate);
        $signature = base64_encode(hash_hmac('sha256', $ss, $this->secretKey, true));
        $auth = sprintf('X-Amzn-Authorization: AWS3-HTTPS AWSAccessKeyId=%s,Algorithm=HmacSHA256,Signature=%s',
            $this->accessKey,
            $signature
        );
        $this->headers[] = $auth;
    }

    private function setAuthHeaderV4()
    {
        $this->setRequestHeaders('c');
        $cr = $this->createCanonicalRequest();
        $ss = $this->createStringToSign($cr);
        $sg = $this->calclulateSignature();
        $signature = hash_hmac('sha256', $ss, $sg, false);
        $auth = sprintf('Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            $this->accessKey,
            $this->credentialScope,
            $this->signedHeaders,
            $signature
        );
        $this->headers[] = $auth;
    }

    private function setRequestHeaders($dateType = 'r')
    {
        $host  = parse_url($this->url,  PHP_URL_HOST);
        $_host = explode('.', $host);
        $this->service = $_host[0];

        $this->requestDate = time();
        $this->headers = array();
        $h = isset($this->option['http']['header']) ? str_replace("\r", '', $this->option['http']['header']) : '';
        foreach (explode("\n", $h) as $line) {
            if (empty($line)) {
                continue;
            }
            if (stripos($line, 'date:') !== false) {
                $this->requestDate = strtotime(substr($line, strpos($line, ':') + 1));
            } else if (stripos($line, 'host:') === false) {
                $this->headers[] = $line;
            }
        }
        $this->headers[] = "Host: {$host}";
        $this->headers[] = 'x-amz-date: ' . gmdate($dateType);
        $this->option['http']['header'] = implode("\r\n", $this->headers);
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
        return implode("\n", $res);
    }

    private function setCredentialScope()
    {
        $this->credentialScope = sprintf('%s/%s/%s/aws4_request',
            gmdate('Ymd', $this->requestDate),
            $this->region,
            $this->service
        );
    }

    private function createCanonicalQueryString($query)
    {
        $res = explode('&', $query);
        sort($res);
        return implode('&', $res);
    }

    private function createCanonicalHeaders()
    {
        $res = array();
        $sh  = array();
        foreach ($this->headers as $line) {
            $h = explode(':', $line, 2);
            if (count($h) >= 2) {
                $res[] = strtolower($h[0]) . ':' . trim($h[1]);
                $sh[]  = strtolower($h[0]);
            }
        }
        sort($res);
        sort($sh);

        $this->signedHeaders = implode(';', $sh);
        return implode("\n", $res) . "\n";
    }

    /**
     * Task 2: Create a String to Sign for Signature Version 4
     * http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
     */
    private function createStringToSign($s)
    {
        $res = array(
            'AWS4-HMAC-SHA256',
            gmdate('Ymd\THis\Z', $this->requestDate),
            $this->credentialScope,
            hash('sha256', $s, false),
        );
        return implode("\n", $res);
    }

    /**
     * Task 3: Calculate the AWS Signature Version 4
     * http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
     */
    private function calclulateSignature()
    {
        $kSecret  = $this->secretKey;
        $kDate    = hash_hmac('sha256', gmdate('Ymd', $this->requestDate), "AWS4{$kSecret}", true);
        $kRegion  = hash_hmac('sha256', $this->region,  $kDate, true);
        $kService = hash_hmac('sha256', $this->service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request',  $kService, true);
        return $kSigning;
    }

    public function asSimpleXml()
    {
        $sx = simplexml_load_string($this->res, 'SX');
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
