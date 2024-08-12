<?php
/**
 * Manage Content-Security-Policy and related HTTP headers.
 */

declare( strict_types=1 );

namespace WMF\Security\REST_API;

use WP_REST_Response;
use WP_Error;
use WP_REST_Request;

/**
 * Connect namespace functions to actions and filters.
 */
function bootstrap() {
	add_action( 'rest_request_before_callbacks', __NAMESPACE__ . '\\restrict_anonymous_rest_api_access', 10, 3 );
	add_filter( 'wmf/security/rest_api/public_endpoint', __NAMESPACE__ . '\\permit_2fa_endpoint_access', 10, 2 );
}

/**
 * Restrict public REST API access.
 *
 * Used to pass a WP_Error back to the API when request is not authenticated.
 *
 * @param \WP_REST_Response|WP_Error|mixed $response Result to send to the client.
 * @param array                            $handler  Route handler used for the request.
 * @param WP_REST_Request                  $request  Request used to generate the response.
 *
 * @return WP_Error|null|true
 */
function restrict_anonymous_rest_api_access( $response, array $handler, WP_REST_Request $request ) {
	// Check if a previous authentication was applied and pass that result
	// without modification.
	if ( is_wp_error( $response ) ) {
		return $response;
	}

	// Return an unauthorized response error if user does not have editing capabilities.
	if ( ! current_user_can( 'edit_posts' ) ) {
		/**
		 * Filter which API endpoint requests can be fulfilled without authentication.
		 *
		 * This enables specific routes to be made publicly accessible if they
		 * are required for frontend site functionality, such as vega-lite CSV
		 * dataset endpoints.
		 *
		 * @param bool            $is_allowed Whether the endpoint is publicly accessible, false by default.
		 * @param WP_REST_Request $request    Active REST Request object.
		 */
		$is_allowed_request = apply_filters( 'wmf/security/rest_api/public_endpoint', false, $request );

		if ( ! $is_allowed_request ) {
			return new WP_Error(
				'rest_disabled',
				__( 'You do not have permission to access the REST API.', 'wmf-rest-api' ),
				[ 'status' => rest_authorization_required_code() ]
			);
		}
	}

	return $response;
}

/**
 * Enable Two Factor plugin routes to be accessed without elevated authentication.
 *
 * 2FA endpoint has to be accessible to subscriber users in order for them to
 * gain elevated permissions elsewhere. Without this 2FA credentials cannot
 * be set or updated.
 *
 * @param bool            $is_allowed Whether the endpoint is publicly accessible, false by default.
 * @param WP_REST_Request $request    Active REST Request object.
 * @return bool Whether the anonymous request should be permitted.
 */
function permit_2fa_endpoint_access( bool $is_allowed, WP_REST_Request $request ): bool {
	if ( strpos( $request->get_route(), '/two-factor/1.0' ) === 0 ) {
		return true;
	}
	return $is_allowed;
}
