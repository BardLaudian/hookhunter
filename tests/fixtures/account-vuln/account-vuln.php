<?php
/** Plugin Name: Fixture account control (vulnerable) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_acct', 'fx_acct' );

function fx_acct() {
	wp_create_user( $_POST['u'], $_POST['p'], $_POST['e'] ); // VULN
	wp_set_password( $_POST['pw'], absint( $_POST['uid'] ) ); // VULN
	add_user_to_blog( 1, absint( $_POST['uid'] ), $_POST['role'] ); // VULN
	grant_super_admin( absint( $_POST['uid'] ) ); // VULN
	wp_set_auth_cookie( absint( $_POST['uid'] ) ); // VULN
	update_option( 'default_role', 'administrator' ); // VULN
	update_option( $_POST['name'], $_POST['v'] ); // VULN
}
