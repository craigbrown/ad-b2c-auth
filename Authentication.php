<?php

namespace AD_B2C_Auth;

use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Algorithm\RS256;

use Exception;

class Authentication {

    private const TOKEN_POST_NAME = 'id_token';
    private const TOKEN_COOKIE_NAME = 'auth_id_token';

    private static $instance;

    // TODO: fix this to get params from settings
    public static function getInstance(Settings $settings) {
        if (!isset(self::$instance)) {
            self::$instance = new Authentication($settings->getTenantName(), $settings->getPolicyName(), $settings->getClientId());
        }
        return self::$instance;
    }

    private $tenant;
    private $policy_name;
    private $client_id;
    private $token;

    /**
     * Initializes the object
     *
     * @param string $tenant
     * @param string $policy_name
     */
    public function __construct(string $tenant, string $policy_name, string $client_id) {
        $this->tenant = $tenant;
        $this->policy_name = $policy_name;
        $this->client_id = $client_id;
    }

    public function getProviderMetadata() {
        $metadata_url = 'https://login.microsoftonline.com/' . 
                        $this->tenant . 
                        '/v2.0/.well-known/openid-configuration?p=' .
                        $this->policy_name;
        $response = wp_remote_get($metadata_url);
        $decoded_response = json_decode( $response['body'], true );
        if (count($decoded_response) == 0 ) {
            throw new Exception('Unable to retrieve metadata from ' . $metadata_url);
        }
        return $decoded_response;
    }

    public function getToken() {
        if ( !isset($this->token) ) {
            $token_str = $this->getTokenString();
            if ( isset($token_str) ) {
                // Parse the token string into an object
                $this->token = (new Parser())->parse($token_str);
            }
        }
        return $this->token;
    }

    private function getTokenString() {
        if ( $this->isTokenPosted() ) {
            // Parse the token string into an object
            return $_POST[self::TOKEN_POST_NAME];
        }
        if ( $this->isTokenSaved() ) {
            return $_COOKIE[self::TOKEN_COOKIE_NAME];
        }
        return null;
    }

    public function isTokenPosted() {
        return isset($_POST[self::TOKEN_POST_NAME]);
    }
    public function isTokenSaved() {
        return isset($_COOKIE[self::TOKEN_COOKIE_NAME]);
    }

    public function isTokenValid( ) {
        // Parse the token string into an object
        $token = $this->getToken();
        if ( !isset($token) ) {
            return false;
        }
        // Get the OpenID Provider Metadata document
        $metadata = $this->getProviderMetadata( $this->tenant, $this->policy_name );

        // Get the JWKSet
        $jwks = $this->getJWKSet( $metadata );
        $kid = $token->getHeader('kid');
        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] == $kid) {
                $jwk = $key;
                break;
            }
        }

        if ( !isset($jwk) ) {
            throw new Exception("Could not find the correct key.");
        }

        $jwk = JWK::create($jwk);

        if (!$jwk->has('kty') || $jwk->get('kty') !== 'RSA') {
            throw new Exception("Could not find a key with the correct encryption type.");
        }

        // Convert the token string to an object
        $serializer = new CompactSerializer(new StandardConverter());
        $jws = $serializer->unserialize($this->getTokenString());
        

        // Get the signature
        $algorithm_key = 'RS256';

        // Get the signature verifier class
        $algorithm_manager_factory = new AlgorithmManagerFactory();
        $algorithm_manager_factory->add($algorithm_key, new Algorithm\RS256());
        $algorithm_manager = $algorithm_manager_factory->create( [$algorithm_key] );
        $verifier = new JWSVerifier( $algorithm_manager );

        // Verify the token's signature
        try {
            $is_verified = $verifier->verifyWithKey($jws, $jwk, 0);
        } catch (\Throwable $e) {
            throw new Exception("B2C Error: An error occurred while verifying the key. Ensure the GMP extension for PHP is active.");
        }

        if (!$is_verified) {
            throw new Exception("Invalid response from the authentication server.");
        }

        // Set up the validation data to check the token's claims against
        $validation_data = new ValidationData();
        $validation_data->setIssuer( $metadata['issuer'] );
        $validation_data->setAudience( $this->client_id );
        $validation_data->setId( NONCE_SECRET );

        // Validate the token
        return $token->validate($validation_data);
    }

    private function getJWKSet( $metadata ) {
        $jwks_uri = $metadata['jwks_uri'];
        $response = wp_remote_get($jwks_uri);
        $decoded_response = json_decode( $response['body'], true );
        if (count($decoded_response) == 0 ) {
            throw new Exception('Unable to retrieve JWKS.');
        }
        return $decoded_response;
    }

    public function saveToken() {
        if (!$this->isTokenPosted()) {
            throw new Exception('Unable to get token string.');
        }
        // TODO: THIS NEEDS TO BE MORE SECURE!!!
        setcookie('auth_id_token', $_POST[self::TOKEN_POST_NAME], 0, COOKIEPATH, COOKIE_DOMAIN, false, true);
    }

    public function unsaveToken() {
        if (!$this->isTokenSaved()) {
            throw new Exception('Unable to get token string.');
        }
        // TODO: THIS NEEDS TO BE MORE SECURE!!!
        setcookie('auth_id_token', '', time() - DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, false, true);
    }
}