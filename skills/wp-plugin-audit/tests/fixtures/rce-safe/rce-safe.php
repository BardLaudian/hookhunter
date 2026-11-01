<?php
/** Plugin Name: Fixture code execution (safe twin) */
/** Synthetic fixture for wp-plugin-audit tests. Not derived from any real plugin. */
add_action( 'wp_ajax_fx_run', 'fx_run' );

function fx_run() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	echo esc_html( shell_exec( 'ping -c1 ' . escapeshellarg( $_GET['host'] ) ) ); // SAFE
	$fn = $_POST['fn'];
	if ( in_array( $fn, array( 'fx_a', 'fx_b' ), true ) ) {
		call_user_func( $fn ); // SAFE
	}
}
