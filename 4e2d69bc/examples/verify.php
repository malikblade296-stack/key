<?php
declare(strict_types=1);

/**
 * KeyGate verify client for PHP.
 *
 * Supports every authentication mode the server offers, in any combination:
 *   - API key      (X-API-Key header, or Authorization: Bearer)
 *   - HMAC-SHA256  (X-Timestamp / X-Nonce / X-Signature over "timestamp.nonce.body")
 *   - HTTP Basic   (Authorization: Basic)
 *
 * These credentials belong on the server. Never ship them inside a distributed
 * app or expose them in client-side JavaScript.
 *
 * Server-side usage:
 *
 *   require __DIR__ . '/verify.php';
 *
 *   $client = new KeyGateClient('https://licenses.example.com/api/verify', [
 *       'api_key'      => '...',   // optional
 *       'hmac_secret'  => '...',   // optional
 *       'basic_user'   => '...',   // optional
 *       'basic_password' => '...',
 *       'timeout'      => 10,
 *       'verify_ssl'   => true,
 *   ]);
 *
 *   $result = $client->verify($licenseKey, $hwid);
 *   if (($result['valid'] ?? false) === true) {
 *       // licensed until $result['expires_at'] (ms) or forever when null
 *   } else {
 *       // $result['reason']: invalid_key, expired, suspended, revoked,
 *       // device_required, device_mismatch, invalid_hwid
 *   }
 *
 * Command line:
 *
 *   KEYGATE_URL=http://localhost:3000/api/verify \
 *   KEYGATE_KEY=XXXX-XXXX-XXXX-XXXX-XXXX \
 *   KEYGATE_HWID=my-server \
 *   php examples/verify.php
 */

final class KeyGateException extends RuntimeException
{
}

final class KeyGateClient
{
    private string $endpoint;

    /** @var array<string, mixed> */
    private array $options;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(string $endpoint, array $options = [])
    {
        if (!preg_match('#^https?://#i', $endpoint)) {
            throw new KeyGateException('Endpoint must be an http(s) URL.');
        }
        if (!function_exists('curl_init')) {
            throw new KeyGateException('The PHP cURL extension is required.');
        }
        $this->endpoint = $endpoint;
        $this->options = $options;
    }

    /**
     * Build a client from KEYGATE_* environment variables.
     */
    public static function fromEnvironment(): self
    {
        $options = [];
        foreach ([
            'api_key' => 'KEYGATE_API_KEY',
            'hmac_secret' => 'KEYGATE_HMAC_SECRET',
            'basic_user' => 'KEYGATE_BASIC_USER',
            'basic_password' => 'KEYGATE_BASIC_PASSWORD',
        ] as $option => $variable) {
            $value = getenv($variable);
            if ($value !== false && $value !== '') {
                $options[$option] = $value;
            }
        }
        $endpoint = getenv('KEYGATE_URL') ?: 'http://localhost:3000/api/verify';
        return new self($endpoint, $options);
    }

    /**
     * Verify a license key. Returns the decoded JSON response, including
     * "http_status" (0 when the request never reached the server).
     *
     * @return array<string, mixed>
     */
    public function verify(string $key, ?string $hwid = null): array
    {
        $payload = ['key' => trim($key)];
        if ($hwid !== null && $hwid !== '') {
            $payload['hwid'] = $hwid;
        }
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($body === false) {
            throw new KeyGateException('Could not encode the request body.');
        }

        $headers = ['Content-Type: application/json', 'Accept: application/json'];

        $apiKey = $this->stringOption('api_key');
        if ($apiKey !== '') {
            $bearer = ($this->options['api_key_header'] ?? 'x-api-key') === 'bearer';
            $headers[] = $bearer
                ? 'Authorization: Bearer ' . $apiKey
                : 'X-API-Key: ' . $apiKey;
        }

        $secret = $this->stringOption('hmac_secret');
        if ($secret !== '') {
            $timestamp = (string) (int) floor(microtime(true) * 1000);
            $nonce = bin2hex(random_bytes(16));
            $signature = hash_hmac('sha256', $timestamp . '.' . $nonce . '.' . $body, $secret);
            $headers[] = 'X-Timestamp: ' . $timestamp;
            $headers[] = 'X-Nonce: ' . $nonce;
            $headers[] = 'X-Signature: ' . $signature;
        }

        $basicUser = $this->stringOption('basic_user');
        if ($basicUser !== '') {
            $headers[] = 'Authorization: Basic ' . base64_encode(
                $basicUser . ':' . $this->stringOption('basic_password')
            );
        }

        $ch = curl_init($this->endpoint);
        if ($ch === false) {
            throw new KeyGateException('Could not initialize cURL.');
        }
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => max(1, (int) ($this->options['timeout'] ?? 10)),
            CURLOPT_SSL_VERIFYPEER => ($this->options['verify_ssl'] ?? true) !== false,
            CURLOPT_SSL_VERIFYHOST => ($this->options['verify_ssl'] ?? true) !== false ? 2 : 0,
        ]);
        $raw = curl_exec($ch);
        if ($raw === false) {
            $error = curl_error($ch);
            if (PHP_VERSION_ID < 80000) {
                curl_close($ch);
            }
            throw new KeyGateException('KeyGate request failed: ' . $error);
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if (PHP_VERSION_ID < 80000) {
            // curl_close() is deprecated (and a no-op) since PHP 8.
            curl_close($ch);
        }

        $data = json_decode((string) $raw, true);
        if (!is_array($data)) {
            throw new KeyGateException('KeyGate returned an invalid response (HTTP ' . $status . ').');
        }
        $data['http_status'] = $status;
        return $data;
    }

    private function stringOption(string $name): string
    {
        $value = $this->options[$name] ?? '';
        return is_string($value) ? trim($value) : '';
    }
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    $key = getenv('KEYGATE_KEY') ?: ($argv[1] ?? '');
    if ($key === '') {
        fwrite(STDERR, "Usage: KEYGATE_KEY=... [KEYGATE_HWID=...] php verify.php\n");
        exit(2);
    }
    $hwid = getenv('KEYGATE_HWID');
    if ($hwid === false || $hwid === '') {
        $hwid = gethostname() ?: null;
    }
    try {
        $result = KeyGateClient::fromEnvironment()->verify($key, $hwid);
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
        exit(($result['valid'] ?? false) === true ? 0 : 1);
    } catch (KeyGateException $error) {
        fwrite(STDERR, $error->getMessage() . PHP_EOL);
        exit(2);
    }
}
