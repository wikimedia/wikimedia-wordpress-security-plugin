<?php
/**
 * Manage Content-Security-Policy and related HTTP headers.
 */

declare( strict_types=1 );

namespace Wikimedia\Security\CSP;

use WP;

/**
 * Connect namespace methods to actions and filters.
 */
function bootstrap(): void {
	add_filter( 'wp_headers', __NAMESPACE__ . '\\add_csp_headers', 900, 2 );
	add_filter( 'wmf/security/csp/allowed_origins', __NAMESPACE__ . '\\maybe_add_local_dev_origins' );
}

/**
 * Filters the HTTP headers before they're sent to the browser.
 *
 * @param string[] $headers Associative array of headerd to set.
 * @param WP       $wp      Current WordPress environment instance.
 * @return string[] Updated HTTP headers array.
 */
function add_csp_headers( array $headers, WP $wp ) {
	$allowed_origins = [
		"'self'",
		'*.wikimedia.org',
	];

	if ( is_admin() ) {
		// Permit phoning home to host for update information.
		$allowed_origins[] = '*.wp.com';
	}

	/**
	 * Permit customizations to CSP allowed origins on a per-site basis.
	 *
	 * @param string[] $allowed_origins List of origins to allow in CSP directives.
	 */
	$allowed_origins = apply_filters( 'wmf/security/csp/allowed_origins', $allowed_origins );

	$allowed_origins = implode( ' ', $allowed_origins );

	$csp_directives = [
		"default-src {$allowed_origins}",
		"base-uri 'self'",
		"font-src data: {$allowed_origins}",
		"img-src data: https://phab.wmfusercontent.org {$allowed_origins}",
		"script-src 'unsafe-inline' {$allowed_origins}",
		"style-src 'unsafe-inline' {$allowed_origins}",
		"form-action 'self'",
		"frame-ancestors 'none'",
		'block-all-mixed-content',
	];

	$csp_headers = [
		'Content-Security-Policy' => implode( '; ', $csp_directives ),
		'X-Frame-Options'         => 'deny',
		'X-XSS-Protection'        => '1; mode=block',
		'X-Content-Type-Options'  => 'nosniff',
		'X-DNS-Prefetch-Control'  => 'off',
		'Referrer-Policy'         => 'strict-origin-when-cross-origin',
	];

	/**
	 * Permit customization of CSP-related headers on a per-site basis.
	 */
	$csp_headers = apply_filters( 'wmf/security/csp/headers', $headers );

	return array_merge( $headers, $csp_headers );
}

/**
 * When the environment type is "local", add localhost origins to CSP headers.
 *
 * @param string[] $allowed_origins List of origins to allow in CSP directives.
 * @return string[]
 */
function maybe_add_local_dev_origins( array $allowed_origins ) : array {
	if ( wp_get_environment_type() !== 'local' ) {
		return $allowed_origins;
	}

	foreach ( [
		'http://localhost',
		'https://localhost',
		'http://localhost:8080',
		'https://localhost:8080',
		'http://localhost:9090',
		'https://localhost:9090',
	] as $local_dev_origin ) {
		$allowed_origins[] = $local_dev_origin;
	}

	return $allowed_origins;
}
