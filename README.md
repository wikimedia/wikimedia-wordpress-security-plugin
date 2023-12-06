# wikimedia-wordpress-security-plugin
Plugin for use implementing security enhancements to the Wikimedia Foundation's sites hosted on WordPress VIP.

## Available filters

`wmf/security/csp/allowed_origins`

Some values, such as allowed script origins, may need to be customized on a per-site basis: for example, perhaps one site in the network needs to be able to use a Vimeo embed but most should not permit that editorially.

Filter on the custom `allowed_origins` hook to register site-specific origins that should be permitted.

```php
add_filter( 'wmf/security/csp/allowed_origins', __NAMESPACE__ . '\\customize_allowed_csp_origins' );

/**
 * Customize CSP origin allow-list for this site.
 *
 * @param string[] $allowed_origins
 * @return string[] Filtered list
 */
function customize_allowed_csp_origins( array $allowed_origins ) : array {
  $allowed_origins[] = 'https://player.vimeo.com';
  return $allowed_origins;
}
```
