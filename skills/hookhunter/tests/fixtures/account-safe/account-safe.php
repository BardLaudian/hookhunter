<?php
/** Plugin Name: Fixture account control (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_fx_acct', 'fx_acct' );

function fx_acct() {
	if ( ! current_user_can( 'promote_users' ) ) {
		wp_send_json_error( null, 403 );
	}
	wp_set_password( wp_generate_password(), absint( $_POST['uid'] ) ); // SAFE
	add_user_to_blog( 1, absint( $_POST['uid'] ), 'subscriber' ); // SAFE
	update_option( 'default_role', 'subscriber' ); // SAFE
	update_option( 'fx_label', sanitize_text_field( $_POST['v'] ) ); // SAFE
}
