<?php
/** Plugin Name: Fixture XSS (vulnerable) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_shortcode( 'fx_search', 'fx_xss_render' );

function fx_xss_render( $atts ) {
	echo '<p>Results for ' . $_GET['q'] . '</p>'; // VULN
	printf( '<input value="%s">', $_GET['v'] ); // VULN
	return '';
}
