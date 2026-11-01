<?php
/** Plugin Name: Fixture object injection (vulnerable) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'init', 'fx_prefs' );

function fx_prefs() {
	$prefs = unserialize( base64_decode( $_COOKIE['fx_prefs'] ) ); // VULN
	$data  = maybe_unserialize( $_POST['data'] ); // VULN
	return array( $prefs, $data );
}
