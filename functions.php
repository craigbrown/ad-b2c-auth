<?php

/**
 * Plugin Name: Azure Active Directory B2C Authentication
 * Plugin URI: https://github.com/Frakur/ad-b2c-auth
 * Description: A plugin that allows users to log in using B2C policies
 * Version: 1.2.1
 */

use AD_B2C_Auth\Authentication;
use AD_B2C_Auth\Settings;
use AD_B2C_Auth\NonceUtil;

//======================================
/**
 * HOW LOGIN WORKS
 * 1. The WP Theme should use the oid_login_url() function to present a login button or link to the user.
 * 2. When this URL is followed, the request_login() function is called which calculates the Azure AD B2C login URL, and redirects to it.
 * 3. Azure AD B2C handles the login, and redirects the user back to WP.
 * 4. When WP loads, the verify_token() function is called. If a token has been provided (as it will have been after a login), it is verified for authenticity here.
 * 5. If successful, user is redirected to the page they were trying to get to (this can be specified in step 2). Themes can use the 'adb2c_will_redirect' filter to amend this URL prior to redirection.
 */
//======================================
 /**
  * HOW LOGOUT WORKS
  * 1. The WP Theme should use the oid_logout_url() function to present a logout button or link to the user.
  * 2. When this URL is followed, the request_logout() function is called which calculates the Azure AD B2C logout URL, and redirects to it.
  * 3. Azure AD B2C handles the logout, then redirects the user back to the home page of the WP site.
  */
  //======================================

/**
 * ACTIONS (CALLED BY WORDPRESS)
 */

/** 
 * Requires the autoloaders.
 */
require 'vendor/autoload.php';

// If the login or logout pages are being loaded, call the necessary functions which will do the redirect.
function login_logout_redirect() {
    $cur_page = $_SERVER['REQUEST_URI'];
    if (substr($cur_page, 0, 10) == '/oid-login') {
        request_login();
    }
    elseif (substr($cur_page, 0, 11) == '/oid-logout') {
        request_logout();
    }
}
add_action( 'template_redirect', 'login_logout_redirect' );

// Called when logging out of AD B2C
function request_logout() {
    try {
        // Get the OpenID Provider Metadata document
        $auth = Authentication::getSignInSignUpInstance();
        $metadata = $auth->getProviderMetadata();
        // Build up the URL for logout
        $logout_url = $metadata['end_session_endpoint'] . 
                                '&post_logout_redirect_uri=' . urlencode(site_url().'/');
        // Remove the saved token
        $auth->unsaveToken();
        // Redirect to this URL
        wp_redirect($logout_url);
        exit;
    } catch (Exception $e) {
		echo $e->getMessage();
		exit;
	}
}

// Called when logging in
function request_login( $redirect = null ) {
    $redirect_uri = urlencode(site_url() . '/');
    $state = array( 'redirect' => $redirect );
    $state = urlencode( base64_encode( json_encode($state) ) );
    try {
        // Get the Authorization URL for login
        $auth = Authentication::getSignInSignUpInstance();
        $authorization_url = $auth->getAuthorizationUrl( $redirect_uri, $state );
        // Redirect to this URL
        wp_redirect($authorization_url);
        exit;
    } catch (Exception $e) {
		echo $e->getMessage();
		exit;
	}

}

// Called when a page is loaded
// If the token has been posted, it is processed and verified.
function verify_token() {
    try {
        check_for_password_change();

        check_for_user_cancel();

        check_for_error();
        
        $auth = Authentication::getSignInSignUpInstance();

        if ( $auth->isTokenPosted() ) {

            // Validate the token
            if ( !$auth->isTokenValid() ) {
                return;
            }

            // Send the email if necessary
            if ( get_claim('newUser') ) {
                do_action( 'adb2c_new_user' );
            }

            // Remember the ID
            $auth->saveToken();
        } 
        elseif ( $auth->isTokenSaved() && !$auth->isTokenValid() ) {
            $auth->unsaveToken();
        }
    } catch (Exception $e) {
		echo $e->getMessage();
		exit;
	}
    if ( !empty($_POST['state']) ) {
        $state = json_decode( base64_decode( urldecode($_POST['state']) ) );
        if (isset($state) && isset($state->redirect)) {
            // Allow amending of redirect URL (or setting to false/null to cancel the redirect)
            $redirect = apply_filters( 'adb2c_will_redirect', $state->redirect );
            if (!empty($redirect)) {
                wp_safe_redirect( $redirect );
                exit;
            }
        }
        
    }
    
}
add_action('wp_loaded', 'verify_token');

function check_for_password_change() {
    if (isset($_POST['error_description']) && strpos($_POST['error_description'], 'AADB2C90118') !== false) {
        try {
            $redirect_uri = urlencode(site_url() . '/');
            $state = isset($_POST['state']) ? $_POST['state'] : null;
            // Get the Authorization URL for login
            $auth = Authentication::getPasswordResetInstance();
            $authorization_url = $auth->getAuthorizationUrl( $redirect_uri, $state );
            // Redirect to this URL
            wp_redirect($authorization_url);
            exit;
        } catch (Exception $e) {
            echo $e->getMessage();
            exit;
        }
    }
}

/**
 * Check for user cancelling a password reset or a sign-up.
 */
function check_for_user_cancel()
{
    if (isset($_POST['error_description']) && strpos($_POST['error_description'], 'AADB2C90091') !== false) {
        // Redirect to the address we saved in 'state' if it exists
        if ( !empty($_POST['state']) ) {
            $state = json_decode( base64_decode( urldecode($_POST['state']) ) );
            if (isset($state) && isset($state->redirect)) {
                wp_redirect( $state->redirect );
                exit;   
            }
        }
        // Otherwise just redirect home
        wp_redirect( site_url() . '/' );
        exit;
    }
}

function page_access_gatekeeper() {
    // If the page is not protected, do nothing
    if ( !get_is_protected() ) return;
    // If the user isn't logged in, make them log in
    if ( !is_oid_user_logged_in() ) {
        global $wp;
        request_login( home_url( $wp->request ) );
    }
    // If the user is logged in, check they have permission to view the page
    if (!adb2c_has_permission()) {
        // If not, set the status to 403
        status_header(403);
    }
}
add_action('template_redirect', 'page_access_gatekeeper');

function show_403_if_forbidden( $template ) {
    // If the page is not protected, do nothing
    if ( !get_is_protected() ) return $template;
    // If the user is logged in, and they have permission to view the page, continue
    if ( is_oid_user_logged_in() && adb2c_has_permission() ) return $template;
    // Otherwise, show the forbidden page (fallback to 404 then index)
    return locate_template( array( '403.php', '404.php', 'index.php' ) );
}
add_action('template_include', 'show_403_if_forbidden');

/**
 * ADDING METADATA FIELD TO POSTS/PAGES
 */

function oid_add_meta_box() {
	add_meta_box(
		'oid_protected', // $id
		'Azure Active Directory B2C Auth', // $title
		'oid_show_meta_box', // $callback
		array('post', 'page'), // $screen
		'side', // $context
		'high' // $priority
	);
}
add_action( 'add_meta_boxes', 'oid_add_meta_box' );


function oid_show_meta_box() {
    global $post;
	$is_protected = get_post_meta( $post->ID, "oid_is_protected", true );
?>
	<input type="hidden" name="oid_meta_box_nonce" value="<?php echo wp_create_nonce( basename(__FILE__) ); ?>">

    <!-- All fields will go here -->
    <p>
        <label for="oid_is_protected">Hidden unless logged in</label>
        <input type="checkbox" name="oid_is_protected" <?php checked( $is_protected ); ?>>
    </p>
<?php
}

function oid_save_meta_box( $post_id ) {   
    if ( !isset($_POST['oid_meta_box_nonce']) ) {
        return;
    }
	// verify nonce
	if ( !wp_verify_nonce( $_POST['oid_meta_box_nonce'], basename(__FILE__) ) ) {
		return $post_id; 
	}
	// check autosave
	if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
		return $post_id;
	}
	// check permissions
	if ( 'page' === $_POST['post_type'] ) {
		if ( !current_user_can( 'edit_page', $post_id ) ) {
			return $post_id;
		} elseif ( !current_user_can( 'edit_post', $post_id ) ) {
			return $post_id;
		}  
	}
	
	$is_protected_old = get_post_meta( $post_id, 'oid_is_protected', true );
	$is_protected_new = isset( $_POST['oid_is_protected'] ) && $_POST['oid_is_protected'];

	if ( $is_protected_new && $is_protected_new != $is_protected_old ) {
		update_post_meta( $post_id, 'oid_is_protected', $is_protected_new );
	} elseif ( !$is_protected_new && $is_protected_new != $is_protected_old ) {
		delete_post_meta( $post_id, 'oid_is_protected', $is_protected_old );
	}
}
add_action( 'save_post', 'oid_save_meta_box' );


/**
 * HELPERS
 */

function check_for_error() {
    if (isset($_POST['error'])) {
        echo 'Unable to log in';
        echo '<br/>error:' . $_POST['error'];
        echo '<br/>error_description:' . $_POST['error_description'];
        exit;
    }
}

// Checks whether a logged-in user has permission to view the page. Returns true by default. Other plugins/themes can amend the value by hooking into this filter.
function adb2c_has_permission() {
    return apply_filters( 'adb2c_has_permission', true );
}

/**
 * CALLABLE FUNCTIONS
 */

// Returns the URL for logging in with AD.
// NOTE: redirect parameter not yet working
function oid_login_url( $redirect = '' ) {
    $url = '/oid-login';
    if (empty($redirect)) {
        return $url;
    }
    $r = urlencode($redirect);
    return $url . '?r=' . $r;
}

// Returns the URL for logging out from AD.
// NOTE: redirect parameter not yet working
function oid_logout_url( $redirect = '' ) {
    $url = '/oid-logout';
    if (empty($redirect)) {
        return $url;
    }
    $r = urlencode($redirect);
    return $url . '?r=' . $r;
}

// Returns true if the user is logged in with AD, false otherwise.
function is_oid_user_logged_in() {
    $auth = Authentication::getSignInSignUpInstance();
    return $auth->isTokenValid();
}

// Returns true if the post or page is marked as protected
function get_is_protected() {
    global $post;
    if (is_null($post)) {
        return false;
    }
    return get_post_meta( $post->ID, "oid_is_protected", true );
}

// Returns the claim or null if it doesn't exist
function get_claim($name, $default = null) {
    $auth = Authentication::getSignInSignUpInstance();
    $token = $auth->getToken();

    if (is_null($token)) {
        return null;
    }

    if (!$token->hasClaim($name)) { 
        return null;
    }

    return $token->getClaim($name, $default);
}

?>