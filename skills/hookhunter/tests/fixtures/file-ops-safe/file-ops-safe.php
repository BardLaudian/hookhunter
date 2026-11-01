<?php
/** Plugin Name: Fixture file operations (safe twin) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_fx_files', 'fx_files' );

function fx_files() {
	if ( ! current_user_can( 'upload_files' ) ) {
		return;
	}
	$name  = sanitize_file_name( $_FILES['f']['name'] );
	$check = wp_check_filetype( $name );
	if ( empty( $check['ext'] ) ) {
		return;
	}
	$dest = wp_upload_dir()['path'] . '/' . $name;
	move_uploaded_file( $_FILES['f']['tmp_name'], $dest ); // SAFE
	$tpl = $_GET['tpl'];
	if ( in_array( $tpl, array( 'a', 'b' ), true ) ) {
		include __DIR__ . '/tpl/' . $tpl . '.php'; // SAFE
	}
	unlink( WP_CONTENT_DIR . '/' . basename( $_POST['file'] ) ); // SAFE
}
