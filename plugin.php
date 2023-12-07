<?php
/**
 * Plugin Name: Wikimedia WordPress Security Plugin
 * Description: Deploys security related code to Wikimedia Foundation sites hosted on WordPress VIP.
 * Author: The Wikimedia Foundation and Human Made
 * Author URI: https://github.com/wikimedia/wikimedia-wordpress-security-plugin/graphs/contributors
 * Version: 1.0.0
 */

declare( strict_types=1 );

namespace WMF\Security;

require_once __DIR__ . '/inc/security.php';
require_once __DIR__ . '/inc/plugin-integration/jetpack.php';
require_once __DIR__ . '/inc/csp.php';

bootstrap();
Plugin_Integration\Jetpack\bootstrap();
