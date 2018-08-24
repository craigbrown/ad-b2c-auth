<?php
namespace AD_B2C_Auth;
class SettingsPage
{
    private const OPTION_GROUP_NAME = 'adb2c-group';
    public const OPTION_NAME = 'adb2c-option';
    private const MENU_SLUG = 'adb2c-settings';
    private const SETTINGS_SECTION_ID = 'adb2c-settings-section';
    private const SETTINGS_SECTION_TITLE = 'Authentication Settings';
    private const OPTIONS_PAGE_TITLE = 'Azure AD B2C Plugin';


    /**
     * Holds the values to be used in the fields callbacks
     */
    private $options;

    /**
     * Start up
     */
    public function __construct()
    {
        add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );
        add_action( 'admin_init', array( $this, 'page_init' ) );
    }

    /**
     * Add options page
     */
    public function add_plugin_page()
    {
        // This page will be under "Settings"
        add_options_page(
            'AD B2C Settings', 
            'AD B2C Settings', 
            'manage_options', 
            self::MENU_SLUG, 
            array( $this, 'create_settings_page' )
        );
    }

    /**
     * Options page callback
     */
    public function create_settings_page()
    {
        // Set class property
        $this->options = get_option( self::OPTION_NAME );
        ?>
        <div class="wrap">
            <h1><?php echo self::OPTIONS_PAGE_TITLE; ?></h1>
            <form method="post" action="options.php">
            <?php
                // This prints out all hidden setting fields
                settings_fields( self::OPTION_GROUP_NAME );
                do_settings_sections( self::MENU_SLUG );
                submit_button();
            ?>
            </form>
        </div>
        <?php
    }

    /**
     * Register and add settings
     */
    public function page_init()
    {        
        register_setting(
            self::OPTION_GROUP_NAME, // Option group
            self::OPTION_NAME, // Option name
            array( $this, 'sanitize' ) // Sanitize
        );

        add_settings_section(
            self::SETTINGS_SECTION_ID, // ID
            self::SETTINGS_SECTION_TITLE, // Title
            array( $this, 'print_section_info' ), // Callback
            self::MENU_SLUG // Page
        );

        $this->add_settings_field('tenant_name', 'Tenant Name');
        $this->add_settings_field('policy_name', 'Policy Name');
        $this->add_settings_field('client_id', 'Client ID');
        $this->add_settings_field('nonce_secret', 'No-Used-Once Secret');

    }

    /**
     * Sanitize each setting field as needed
     *
     * @param array $input Contains all settings fields as array keys
     */
    public function sanitize( $input )
    {
        return $input;
    }

    /** 
     * Print the Section text
     */
    public function print_section_info()
    {
        print 'Enter your settings below:';
    }

    /**
     * Helper function for easier creation of settings field.
     */
    private function add_settings_field($field_id, $field_name)
    {
        add_settings_field(
            $field_id, 
            $field_name, 
            array( $this, 'field_callback' ), 
            self::MENU_SLUG, 
            self::SETTINGS_SECTION_ID,
            array( 'label_for' => $field_id )
        );
    }

    /** 
     * Get the settings option array and print one of its values
     */
    public function field_callback($args) {
        $field_id = $args['label_for'];
        printf(
            '<input type="text" id="' . $field_id . '" name="' . self::OPTION_NAME . '[' . $field_id . ']" value="%s" />',
            isset( $this->options[$field_id] ) ? esc_attr( $this->options[$field_id]) : ''
        );
    }
}

if( is_admin() )
    $my_settings_page = new SettingsPage();
?>