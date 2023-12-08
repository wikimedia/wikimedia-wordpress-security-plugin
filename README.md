# wikimedia-wordpress-security-plugin

Plugin for use implementing security enhancements to the Wikimedia Foundation's sites hosted on WordPress VIP.

## Available filters

`wmf/security/csp/allowed_origins`

Some values, such as allowed script origins, may need to be customized on a per-site basis: for example, perhaps one site in the network needs to be able to use a different video provider than YouTube or Vimeo, but most do not.

Filter on the custom `allowed_origins` hook to register any necessary site-specific origins.

```php
add_filter( 'wmf/security/csp/allowed_origins', __NAMESPACE__ . '\\permit_custom_video_provider', 10, 2 );

/**
 * Customize CSP origin allow-list for this site.
 *
 * @param string[] $allowed_origins List of origins to allow in this CSP.
 * @param string   $policy_type     CSP type.
 * @return string[] Filtered list of permitted origins.
 */
function permit_custom_video_provider( array $allowed_origins, string $policy_type ) : array {
	if ( in_array( $policy_type, [ 'script-src', 'frame-src' ], true ) {
		$allowed_origins[] = 'https://player.necessary-video-service.com';
	}
	return $allowed_origins;
}
```
