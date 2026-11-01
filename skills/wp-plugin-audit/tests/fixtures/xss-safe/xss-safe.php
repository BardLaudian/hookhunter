<?php
/** Plugin Name: Fixture XSS (safe twin) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_shortcode( 'fx_search', 'fx_xss_render' );

function fx_xss_render( $atts ) {
	echo '<p>Results for ' . esc_html( $_GET['q'] ) . '</p>'; // SAFE
	printf( '<input value="%s">', esc_attr( $_GET['v'] ) ); // SAFE
	return '';
}
