# Azure AD B2C Auth / WordPress Plugin

A WordPress plugin that allows you to protect certain posts so they can only be accessed by users in an Azure Active Directory (B2C).

## Description

This plugin keeps the WordPress login separate from the AD, so you log in with WordPress as usual to access the WP Admin, but you log in using an AD B2C policy to view your site's protected pages.

It has been designed for use with Azure AD B2C, but with some tweaking you may be able to get it to work with another OpenID Connect authentication service.

Please note this plugin is VERY BETA. It works, but it may not be completely secure or bug-free. DO NOT use on production systems unless you've thoroughly reviewed the code first. If you can help us improve the code, please submit a pull request! It'll be hugely appreciated.

## Requirements

You must have the GMP module enabled in your PHP installation.

## How to use

1. (Optional) Edit the `has_permission()` function in `permission.php` to put extra conditions on whether a logged in user has access to protected pages (e.g. ensuring a claim has a specific value).
2. Compress the source code into a zip, and manually upload this to your WordPress site as a new plugin.
3. In the WordPress admin area, go to Settings > AD B2C Settings, and fill in the details of your active directory. The 'Number-Used-Once Secret' should just be a random string.
4. (Optional) Use the functions `oid_login_url()`, `oid_logout_url()`, and `is_oid_user_logged_in()` in your theme to allow users to log in and out.
5. (Optional) Add a `403.php` template to your theme - this will be shown to users without permission to view a protected page.
6. In the WP admin area, for any posts/pages you want protected check the "Hidden unless logged in" box on the Edit page. (If you can't see the box, make sure that "Azure Active Directory B2C Auth" is checked under "Screen Options").

## Behavior

- If the user is logged out, and the post is protected, the user will be redirected to the login page.
- If the user is logged in, the post is protected, and the user doesn't pass the `has_permission()` function check, the user will see the `403.php` or `404.php` template.
- If the user is logged in, the post is protected, and the user passes the `has_permission()` function check, the user will see the page.

## License

This project is licensed under the GNU General Public License v3 - see the [LICENSE.md](LICENSE.md) file for details.
