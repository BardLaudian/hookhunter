<?php
/** Plugin Name: Fixture open redirect (vulnerable) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'template_redirect', 'fx_go' );

function fx_go() {
	if ( isset( $_GET['next'] ) ) {
		wp_redirect( $_GET['next'] ); // VULN
		exit;
	}
	if ( isset( $_GET['to'] ) ) {
		header( 'Location: ' . $_GET['to'] ); // VULN
		exit;
	}
}
