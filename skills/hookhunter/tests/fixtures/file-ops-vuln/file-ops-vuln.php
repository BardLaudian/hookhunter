<?php
/** Plugin Name: Fixture file operations (vulnerable) */
/** Synthetic fixture for hookhunter tests. Not derived from any real plugin. */
add_action( 'wp_ajax_nopriv_fx_files', 'fx_files' );

function fx_files() {
	$dest = WP_CONTENT_DIR . '/uploads/' . $_FILES['f']['name'];
	move_uploaded_file( $_FILES['f']['tmp_name'], $dest ); // VULN
	include $_GET['tpl']; // VULN
	unlink( WP_CONTENT_DIR . '/' . $_POST['file'] ); // VULN
}
