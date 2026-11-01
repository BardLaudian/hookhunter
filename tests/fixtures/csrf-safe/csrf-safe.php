<?php
/** Plugin Name: Fixture missing nonce (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'admin_init', 'fx_handle_form' );

function fx_handle_form() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	if ( isset( $_POST['fx_opt'] ) ) {
		check_admin_referer( 'fx_form' );
		update_option( 'fx_opt', sanitize_text_field( $_POST['fx_opt'] ) );
	}
}
