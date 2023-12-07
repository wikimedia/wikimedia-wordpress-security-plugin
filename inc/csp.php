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

	// Per-directive customizations.
	add_filter( 'wmf/security/csp/allowed_origins', __NAMESPACE__ . '\\allow_vip_origin', 10, 2 );
	add_filter( 'wmf/security/csp/allowed_origins', __NAMESPACE__ . '\\allow_video_service_origins', 10, 2 );
	add_filter( 'wmf/security/csp/allowed_origins', __NAMESPACE__ . '\\maybe_add_local_dev_origins', 10, 2 );
	add_filter( 'wmf/security/csp/allowed_origins', __NAMESPACE__ . '\\allow_wikimedia_origins', 10, 2 );
	add_filter( 'wmf/security/csp/allow_unsafe_inline', __NAMESPACE__ . '\\allow_unsafe_inline_scripts_styles', 10, 2 );
	add_filter( 'wmf/security/csp/allow_data_uris', __NAMESPACE__ . '\\allow_data_uri_inline_assets', 10, 2 );
}

/**
 * Apply filters to each CSP directive type and render the fully-formed directive.
 *
 * @param string $policy_type Type of directive being rendered, e.g. 'default-src' or 'script-src'.
 * @return string Fully-formed CSP `...-src` directive string.
 */
function render_filtered_csp_directive( string $policy_type ): string {
	/**
	 * Customize allowed origins for a ...-src CSP directive.
	 *
	 * @param string[] $allowed_origins List of origins to allow in this CSP directive.
	 * @param string   $policy_type  CSP directive type.
	 */
	$allowed_origins = apply_filters( 'wmf/security/csp/allowed_origins', [], $policy_type );

	// Strip out entries that the validator returned as empty.
	$allowed_origins = array_filter(
		array_map( __NAMESPACE__ . '\\validate_and_sanitize_csp_origin', $allowed_origins ),
		/** Strip out entries that the validator returned as empty. */
		fn( string $origin ): bool => ( $origin !== '' )
	);

	/**
	 * Filter whether 'unsafe-inline' should be permitted in this directive (false by default).
	 *
	 * @param bool   $allow_unsafe_inline Whether to include 'unsafe-inline' in the directive.
	 * @param string $policy_type      CSP directive type.
	 */
	if ( apply_filters( 'wmf/security/csp/allow_unsafe_inline', false, $policy_type ) ) {
		array_unshift( $allowed_origins, "'unsafe-inline'" );
	}

	/**
	 * Filter whether data: URIs should be permitted in this directive (false by default).
	 *
	 * @param bool   $allow_data_uris Whether to include data: in the directive.
	 * @param string $policy_type  CSP directive type.
	 */
	if ( apply_filters( 'wmf/security/csp/allow_data_uris', false, $policy_type ) ) {
		array_unshift( $allowed_origins, 'data:' );
	}

	// Always allow 'self'.
	array_unshift( $allowed_origins, "'self'" );

	// Prefix with directive type, and return complete directive.
	return "$policy_type " . implode( $allowed_origins );
}


/**
 * Validate and sanitize the provided URL.
 *
 * @param string $url CSP origin URL.
 * @return string Filtered and sanitized URL, or '' if not permitted/not valid.
 */
function validate_and_sanitize_csp_origin( string $url ): string {
	$components = parse_url( esc_url( $url ) );

	$host   = $components['host'] ?? '';
	$scheme = $components['scheme'] ?? '';

	if ( strlen( $host ) <= 3 ) {
		// A hostname with <= 3 characters *probably* means a non-URL string was passed in.
		return '';
	}

	if ( ! in_array( $scheme, [ 'http', 'https', 'wss' ], true ) ) {
		// Only support http:, https:, and wss: schemes at this time.
		return '';
	}

	$port = ! empty( $components['port'] ) ? ( '' . $components['port'] ) : '';
	return sprintf( '%s://%s%s', $scheme, $host, $port );
}


/**
 * Add *.wp.com origin to relevant directives.
 *
 * @param string[] $allowed_origins List of origins to allow in this CSP directive.
 * @param string   $policy_type  CSP directive type.
 * @return string[] Filtered directive array.
 */
function allow_vip_origin( array $allowed_origins, string $policy_type ): array {
	if ( in_array( $policy_type, [ 'frame-src', 'img-src', 'font-src', 'script-src', 'style-src' ], true ) ) {
		$allowed_origins[] = 'https://*.wp.com';
	}
	return $allowed_origins;
}


/**
 * Add YouTube and Vimeo origins to script-src and frame-src directives.
 *
 * @param string[] $allowed_origins List of origins to allow in this CSP directive.
 * @param string   $policy_type  CSP directive type.
 * @return string[] Filtered directive array.
 */
function allow_video_service_origins( array $allowed_origins, string $policy_type ): array {
	if ( in_array( $policy_type, [ 'frame-src', 'script-src' ], true ) ) {
		$allowed_origins[] = 'https://www.youtube.com';
		$allowed_origins[] = 'https://player.vimeo.com';
	}
	return $allowed_origins;
}

/**
 * Permit certain resources from *.wikimedia.org necessary for Matomo tracking.
 *
 * @param string[] $allowed_origins List of origins to allow in this CSP directive.
 * @param string   $policy_type  CSP directive type.
 * @return string[] Filtered directive array.
 */
function allow_wikimedia_origins( array $allowed_origins, string $policy_type ): array {
	if ( in_array( $policy_type, [ 'script-src', 'style-src', 'img-src' ], true ) ) {
		$allowed_origins[] = 'https://*.wikimedia.org';
	}
	return $allowed_origins;
}

/**
 * Define the 'connect-src' origins list.
 *
 * @param string[] $allowed_origins List of origins to allow in this CSP directive.
 * @param string   $policy_type  CSP directive type.
 * @return string[] Filtered directive array.
 */
function set_connect_src_origins( array $allowed_origins, string $policy_type ): array {
	if ( $policy_type === 'connect-src' ) {
		return [ 'https://*.wikipedia.org', 'wss://*.wordpress.com' ];
	}
	return $allowed_origins;
}

/**
 * When the environment type is "local", add localhost origins to CSP headers
 * and permit proxying media requests through to deployed environment.
 *
 * @param string[] $allowed_origins List of origins to allow in this CSP directive.
 * @param string   $policy_type  CSP directive type.
 * @return string[] Filtered directive array.
 */
function maybe_add_local_dev_origins( array $allowed_origins, string $policy_type ): array {
	if ( wp_get_environment_type() !== 'local' ) {
		return $allowed_origins;
	}

	if ( $policy_type === 'script-src' ) {
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
	}

	if ( $policy_type === 'img-src' ) {
		/**
		 * Permit proxying images through to production or to preprod.
		 *
		 * @see https://docs.wpvip.com/how-tos/dev-env-add-media/#h-proxy-media-files
		 */
		$allowed_origins[] = 'https://wikimediafoundation.org';
		$allowed_origins[] = 'https://wikimediafoundation-org-preprod.go-vip.net';
	}

	return $allowed_origins;
}

/**
 * We need to set 'unsafe-inline' on scripts and styles for now.
 *
 * IMPORTANT NOTICE
 *
 * Because of many errors being watched in the Wikimedia Foundation site, the current
 * implementation of our Content-Security-Policy (CSP) is having the 'unsafe-inline'
 * directive for script and style tags. This, even resolving the errors, allows the
 * potential for some Cross-Site Scripting (XSS) attacks.
 *
 * TODO:
 *
 * 1. Removal of 'unsafe-inline' directive for scripts and styles: This directive
 *    is making less the efficiency of the CSP against attacks of XSS.
 *
 * 2. Alternatives being proposed:
 *
 *    a. Using a nonce: This would need adding a nonce unique to each inline script/style tag.
 *
 *    b. Using a hash: This involves mapping and making hashes for all inline scripts/styles
 *       and including these hashes in the CSP as exceptions.
 *
 * Please make a note that both strategies will demand substantial effort and testing to make
 * sure that functionality of site remains not affected.
 *
 * @param bool   $allow_unsafe_inline Whether to include 'unsafe-inline' in the directive.
 * @param string $policy_type      CSP directive type.
 * @return bool Filtered permission flag.
 */
function allow_unsafe_inline_scripts_styles( bool $allow_unsafe_inline, string $policy_type ): bool {
	return $allow_unsafe_inline || in_array( $policy_type, [ 'script-src', 'style-src' ], true );
}


/**
 * Permit inlined data: URIs in image tags and font references.
 *
 * @param bool   $allow_data_uris Whether to include data: in the directive.
 * @param string $policy_type  CSP directive type.
 * @return bool Filtered permission flag.
 */
function allow_data_uri_inline_assets( bool $allow_data_uris, string $policy_type ): bool {
	return $allow_data_uris || in_array( $policy_type, [ 'script-src', 'style-src' ], true );
}

/**
 * Filters the HTTP headers before they're sent to the browser.
 *
 * @param string[] $headers Associative array of headerd to set.
 * @param WP       $wp      Current WordPress environment instance.
 * @return string[] Updated HTTP headers array.
 */
function add_csp_headers( array $headers, WP $wp ) {
	// For each directive type, pass it through several filters to customize
	// the origins and instructions each specific type of directive permits.
	$csp_src_directives = array_map(
		__NAMESPACE__ . '\\render_filtered_csp_directive',
		[
			'default-src',
			'connect-src',
			'font-src',
			'frame-src',
			'img-src',
			'script-src',
			'style-src',
		]
	);

	// These directives cannot be filtered.
	$csp_invariate_directives = [
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
		'block-all-mixed-content',
	];

	$csp_headers = [
		'Content-Security-Policy' => implode( '; ', array_merge( $csp_src_directives, $csp_invariate_directives ) ),
		'X-Frame-Options'         => 'deny',
		'X-XSS-Protection'        => '1; mode=block',
		'X-Content-Type-Options'  => 'nosniff',
		'X-DNS-Prefetch-Control'  => 'off',
		'Referrer-Policy'         => 'strict-origin-when-cross-origin',
	];

	return array_merge( $headers, $csp_headers );
}
