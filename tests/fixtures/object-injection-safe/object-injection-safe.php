<?php
/** Plugin Name: Fixture object injection (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'init', 'fx_prefs' );

function fx_prefs() {
	$raw   = base64_decode( $_COOKIE['fx_prefs'] );
	$prefs = unserialize( $raw, array( 'allowed_classes' => false ) ); // SAFE
	$data  = json_decode( wp_unslash( $_POST['data'] ), true );
	return array( $prefs, $data );
}
