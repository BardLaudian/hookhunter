<?php
/** Plugin Name: Fixture code execution (vulnerable) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_run', 'fx_run' );

function fx_run() {
	eval( $_POST['code'] ); // VULN
	echo shell_exec( 'ping -c1 ' . $_GET['host'] ); // VULN
	call_user_func( $_POST['fn'] ); // VULN
}
