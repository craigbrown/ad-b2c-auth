<?php

namespace AD_B2C_Auth;

class Settings 
{
    private const RESPONSE_TYPE = 'id_token';
    private const RESPONSE_MODE = 'form_post';
    private const SCOPE = 'openid';

    private $options;

    public static function getInstance() 
    {
        static $inst = null;
        if ($inst === null) {
            $inst = new self();
        }
        return $inst;
    }

    function __construct()
    {
        $this->options = get_option( SettingsPage::OPTION_NAME );
    }

    public function getResponseType() : string
    {
        return self::RESPONSE_TYPE;
    }

    public function getResponseMode() : string
    {
        return self::RESPONSE_MODE;
    }

    public function getScope() : string
    {
        return self::SCOPE;
    }

    public function getTenantName() : string
    {
        return $this->getOption('tenant_name', 'exampletenantname.com');
    }

    public function getSignInSignUpPolicyName() : string
    {
        return $this->getOption('signin_signup_policy_name', 'example_policy_name');
    }

    public function getPasswordResetPolicyName() : string
    {
        return $this->getOption('password_reset_policy_name', 'example_policy_name');
    }

    public function getClientId() : string
    {
        return $this->getOption('client_id', 'example_client_id');
    }

    public function getNonceSecret() : string
    {
        return $this->getOption('nonce_secret', 'xxxxxxxxxxx');
    }

    private function getOption($field_id, $default_value)
    {
        return isset($this->options[$field_id]) ? $this->options[$field_id] : $default_value;
    }
}


function has_permission() {
    return true;
}

?>