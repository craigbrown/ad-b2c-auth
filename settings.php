<?php
define('TENANT', 'example.onmicrosoft.com');
define('POLICY_NAME', 'b2c_policy_name');
define('CLIENT_ID', 'client id string goes here');

define('RESPONSE_TYPE', 'id_token');
define('RESPONSE_MODE', 'form_post');
define('SCOPE', 'openid');
define('NONCE_SECRET', 'secret string goes here');


function has_permission() {
    return true;
}
?>