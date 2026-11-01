<?php
/** Plugin Name: Fixture open redirect (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'template_redirect', 'fx_go' );

function fx_go() {
	if ( isset( $_GET['next'] ) ) {
		wp_safe_redirect( $_GET['next'] ); // SAFE
		exit;
	}
	if ( isset( $_GET['to'] ) ) {
		wp_redirect( wp_validate_redirect( $_GET['to'], home_url() ) ); // SAFE
		exit;
	}
}
